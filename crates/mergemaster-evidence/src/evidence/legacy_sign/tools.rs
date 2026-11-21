//! The legacy signer's tool-file and process-environment trust boundary.
use anyhow::{Context, Result, bail};
use std::{
    collections::BTreeMap,
    ffi::{CString, OsStr, OsString},
    fs,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use crate::evidence::legacy_verify::{python_repr::Repr, value_inputs::TextRef};
use crate::gate::git::deadline::GitChild;

const TRUSTED_PATH: &str =
    "/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/local/bin:/usr/bin:/bin";
const REFUSED_ENVIRONMENT: [&str; 8] = [
    "LD_PRELOAD",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "GCONV_PATH",
    "NLSPATH",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
];
type Environment = BTreeMap<OsString, OsString>;

pub(super) fn refuse_loader() -> Result<()> {
    refuse_loader_environment(&std::env::vars_os().collect())
}

fn refuse_loader_environment(environ: &Environment) -> Result<()> {
    let mut found: Vec<_> = REFUSED_ENVIRONMENT
        .into_iter()
        .filter(|name| environ.contains_key(OsStr::new(name)))
        .collect();
    found.sort_unstable();
    if !found.is_empty() {
        bail!(
            "refusing to run with {} set: the launcher must scrub the environment (this script cannot undo what the loader or interpreter already did)",
            found.join(", ")
        );
    }
    Ok(())
}

pub(super) struct Tools {
    git: PathBuf,
    ssh_keygen: PathBuf,
    path: String,
}

impl Tools {
    pub(super) fn load(configured: Option<&str>) -> Result<Self> {
        let context = DirectoryContext::load()?;
        let configured = configured.filter(|path| !path.is_empty());
        trusted_tools(
            configured.unwrap_or(TRUSTED_PATH),
            configured.is_some(),
            |directory| unsafe_directory(directory, &context),
            unsafe_file,
        )
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.git);
        command.env_clear().envs(child_environment(
            &self.path,
            &std::env::vars_os().collect(),
            None,
        ));
        command
    }

    pub(super) fn git(&self, repo: &Path, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut command = self.command();
        command
            .args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.pager=cat",
                "-c",
            ])
            .arg(format!("gpg.ssh.program={}", self.ssh_keygen.display()))
            .arg("-C")
            .arg(repo)
            .args(args);
        // With no input Python inherits stdin; with input the collector closes its pipe at EOF.
        command.stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });
        let output = GitChild::capture(&mut command, input, Duration::from_secs(300))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim_matches(python_whitespace);
            let start = stderr.char_indices().rev().nth(499).map_or(0, |(at, _)| at);
            bail!(
                "git {} failed: {}",
                args.first().copied().unwrap_or(""),
                &stderr[start..]
            );
        }
        Ok(output.stdout)
    }

    pub(super) fn initialize(&self, repo: &Path) -> Result<()> {
        let mut command = self.command();
        command.args(["init", "--quiet", "--bare"]).arg(repo);
        // Python's initialization inherits both streams, unlike its plumbing calls.
        let status = GitChild::with_stdio(
            &mut command,
            Duration::from_secs(300),
            Stdio::inherit(),
            Stdio::inherit(),
        )?
        .wait()?;
        if !status.success() {
            bail!("git init failed: {status}");
        }
        Ok(())
    }
}

fn python_whitespace(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

fn child_environment(
    path: &str,
    environ: &Environment,
    extra: Option<&Environment>,
) -> Environment {
    let mut child = Environment::new();
    for name in ["HOME", "TMPDIR"] {
        if let Some(value) = environ.get(OsStr::new(name)) {
            child.insert(name.into(), value.clone());
        }
    }
    for (name, value) in [
        ("PATH", path),
        ("LC_ALL", "C"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_NO_LAZY_FETCH", "1"),
    ] {
        child.insert(name.into(), value.into());
    }
    if let Some(extra) = extra {
        child.extend(
            extra
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
    }
    child
}

struct DirectoryContext {
    roots: Vec<PathBuf>,
}

impl DirectoryContext {
    fn load() -> Result<Self> {
        let cwd = std::env::current_dir()?;
        let home = if let Some(home) = std::env::var_os("HOME") {
            // posixpath.expanduser strips trailing slashes and maps an empty HOME to /.
            let bytes = home.as_os_str().as_bytes();
            let end = bytes
                .iter()
                .rposition(|byte| *byte != b'/')
                .map_or(0, |at| at + 1);
            if end == 0 {
                PathBuf::from("/")
            } else {
                PathBuf::from(OsStr::from_bytes(&bytes[..end]))
            }
        } else {
            #[allow(deprecated)]
            std::env::home_dir().context("Could not determine home directory.")?
        };
        // tempfile.gettempdir checks these candidates by actually creating a file.
        let mut candidates: Vec<PathBuf> = ["TMPDIR", "TEMP", "TMP"]
            .into_iter()
            .filter_map(std::env::var_os)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .collect();
        candidates.extend([
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
            PathBuf::from("/usr/tmp"),
            cwd.clone(),
        ]);
        let temp = candidates
            .into_iter()
            .find(|candidate| tempfile::tempfile_in(candidate).is_ok())
            .context("No usable temporary directory found")?;
        let mut roots = vec![
            cwd,
            home,
            absolute(&temp)?,
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
        ];
        for name in ["RUNNER_TEMP", "GITHUB_WORKSPACE"] {
            roots.push(
                std::env::var_os(name)
                    .filter(|value| !value.is_empty())
                    .map_or_else(|| PathBuf::from("/nonexistent"), PathBuf::from),
            );
        }
        Ok(Self { roots })
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}

// Python's realpath/Path.resolve are non-strict: a nonexistent suffix is retained.
fn realpath(path: &Path) -> Result<PathBuf> {
    let absolute = absolute(path)?;
    if let Ok(real) = fs::canonicalize(&absolute) {
        return Ok(real);
    }
    let mut real = PathBuf::from("/");
    for part in absolute.components() {
        use std::path::Component;
        match part {
            Component::ParentDir => {
                real.pop();
            }
            Component::Normal(name) => {
                real.push(name);
                if let Ok(resolved) = fs::canonicalize(&real) {
                    real = resolved;
                }
            }
            _ => {}
        }
    }
    Ok(real)
}

fn unsafe_directory(directory: &str, context: &DirectoryContext) -> Result<Option<String>> {
    if !directory.starts_with('/') {
        return Ok(Some("not an absolute path".into()));
    }
    let mut segments: Vec<_> = directory[1..].split('/').collect();
    if segments.last() == Some(&"") {
        segments.pop();
    }
    if segments.iter().any(|part| matches!(*part, "" | "." | "..")) {
        return Ok(Some("has an empty, . or .. segment".into()));
    }
    let real = realpath(Path::new(directory))?;
    if !real.is_dir() {
        return Ok(Some("is not a directory".into()));
    }
    let real_text = real.as_os_str().as_bytes();
    for root in &context.roots {
        let resolved = realpath(root)?;
        // Keep the original root too: a symlink alias must not bypass this boundary.
        for base in [root, &resolved] {
            let bytes = base.as_os_str().as_bytes();
            let prefix = bytes.strip_suffix(b"/").unwrap_or(bytes);
            let under =
                |path: &[u8]| path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/');
            if real_text == bytes || under(real_text) || under(directory.as_bytes()) {
                return Ok(Some(format!(
                    "is under {}, where code under test can write",
                    base.display()
                )));
            }
        }
    }
    if real_text.starts_with(b"/nix/store/") {
        return Ok((fs::metadata(&real)?.mode() & 0o222 != 0)
            .then(|| "has a write bit in the Nix store".into()));
    }
    let mut current = real.as_path();
    loop {
        let status = fs::metadata(current)?;
        if status.uid() != 0 {
            return Ok(Some(format!(
                "or its parent {} is not owned by root",
                current.display()
            )));
        }
        if status.mode() & 0o022 != 0 {
            return Ok(Some(format!(
                "or its parent {} is writable by group or others",
                current.display()
            )));
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return Ok(None),
        }
    }
}

fn unsafe_file_mode(real: &Path, mode: u32, uid: u32) -> Option<&'static str> {
    if mode & libc::S_IFMT != libc::S_IFREG {
        return Some("is not a regular file");
    }
    if real.as_os_str().as_bytes().starts_with(b"/nix/store/") {
        if mode & 0o222 != 0 {
            return Some("has a write bit in the Nix store");
        }
    } else {
        if uid != 0 {
            return Some("is not owned by root");
        }
        if mode & 0o022 != 0 {
            return Some("is writable by group or others");
        }
    }
    if mode & 0o100 == 0 {
        return Some("is not executable by its owner");
    }
    None
}

fn unsafe_file(real: &Path) -> Result<Option<String>> {
    let status = fs::metadata(real)?;
    Ok(unsafe_file_mode(real, status.mode(), status.uid()).map(str::to_owned))
}

fn checked_path(
    path: &str,
    strict: bool,
    directory_check: &impl Fn(&str) -> Result<Option<String>>,
) -> Result<String> {
    let mut kept = Vec::new();
    for directory in path.split(':') {
        match directory_check(directory)? {
            None => kept.push(directory),
            Some(reason) if strict => bail!(
                "tool path directory {} {reason}",
                Repr(TextRef::Str(directory))
            ),
            Some(_) => {}
        }
    }
    if kept.is_empty() {
        bail!("no usable directory in the signer's own path");
    }
    Ok(kept.join(":"))
}

fn executable(path: &Path) -> bool {
    if path.is_dir() {
        return false;
    }
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: path is a live NUL-terminated string; access only reads it. Like
    // shutil.which/os.access this checks executable access for the real user.
    unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 }
}

fn trusted_tools(
    path: &str,
    strict: bool,
    directory_check: impl Fn(&str) -> Result<Option<String>>,
    file_check: impl Fn(&Path) -> Result<Option<String>>,
) -> Result<Tools> {
    let path = checked_path(path, strict, &directory_check)?;
    let resolve = |name| -> Result<PathBuf> {
        let found = path
            .split(':')
            .map(|directory| Path::new(directory).join(name))
            .find(|candidate| executable(candidate))
            .with_context(|| format!("{name} is not in the signer's own path ({path})"))?;
        let real = realpath(&found)?;
        let parent = real.parent().context("resolved tool has no directory")?;
        if let Some(reason) = directory_check(&parent.to_string_lossy())? {
            bail!(
                "{name} resolves to {}, whose directory {reason}",
                real.display()
            );
        }
        if let Some(reason) = file_check(&real)? {
            bail!("{name} resolves to {}, which {reason}", real.display());
        }
        Ok(real)
    };
    let git = resolve("git")?;
    let ssh_keygen = resolve("ssh-keygen")?;
    Ok(Tools {
        git,
        ssh_keygen,
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn env(pairs: &[(&str, &str)]) -> Environment {
        pairs
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    #[test]
    fn group_1_tool_file_mode_owner_and_store_rules() {
        let file = Path::new("x");
        let store = Path::new("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-git-1/bin/git");
        for (path, mode, uid, expected) in [
            (file, libc::S_IFREG | 0o755, 0, None),
            (file, libc::S_IFREG | 0o555, 0, None),
            (
                file,
                libc::S_IFREG | 0o755,
                1000,
                Some("is not owned by root"),
            ),
            (
                file,
                libc::S_IFREG | 0o775,
                0,
                Some("is writable by group or others"),
            ),
            (
                file,
                libc::S_IFREG | 0o757,
                0,
                Some("is writable by group or others"),
            ),
            (
                file,
                libc::S_IFREG | 0o777,
                1000,
                Some("is not owned by root"),
            ),
            (store, libc::S_IFREG | 0o555, 65534, None),
            (store, libc::S_IFREG | 0o555, 0, None),
            (
                store,
                libc::S_IFREG | 0o755,
                0,
                Some("has a write bit in the Nix store"),
            ),
            (
                store,
                libc::S_IFREG | 0o775,
                65534,
                Some("has a write bit in the Nix store"),
            ),
            (
                store,
                libc::S_IFREG | 0o444,
                0,
                Some("is not executable by its owner"),
            ),
            (
                Path::new("/nix/store-lookalike/git"),
                libc::S_IFREG | 0o555,
                65534,
                Some("is not owned by root"),
            ),
            (
                file,
                libc::S_IFDIR | 0o755,
                0,
                Some("is not a regular file"),
            ),
            (
                file,
                libc::S_IFLNK | 0o777,
                0,
                Some("is not a regular file"),
            ),
            (
                file,
                libc::S_IFREG | 0o644,
                0,
                Some("is not executable by its owner"),
            ),
        ] {
            assert_eq!(
                unsafe_file_mode(path, mode, uid),
                expected,
                "{path:?} {mode:o} {uid}"
            );
        }
    }

    fn fixture_tool(path: &Path, mode: u32) -> Result<()> {
        fs::write(path, "#!/bin/sh\n")?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    #[test]
    fn group_2_real_files_links_and_host_git() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let tool = directory.path().join("tool");
        fixture_tool(&tool, 0o755)?;
        if fs::metadata(&tool)?.uid() != 0 {
            assert_eq!(unsafe_file(&tool)?.as_deref(), Some("is not owned by root"));
        }
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o777))?;
        let expected = if fs::metadata(&tool)?.uid() == 0 {
            "is writable by group or others"
        } else {
            "is not owned by root"
        };
        assert_eq!(unsafe_file(&tool)?.as_deref(), Some(expected));
        let link = directory.path().join("link");
        symlink(&tool, &link)?;
        assert_eq!(unsafe_file(&fs::canonicalize(link)?)?, unsafe_file(&tool)?);
        let host_git = std::env::split_paths(&std::env::var_os("PATH").context("PATH missing")?)
            .filter(|path| !path.to_string_lossy().contains("recorder"))
            .map(|path| path.join("git"))
            .find(|path| path.exists())
            .context("test needs git on PATH")?;
        let host_git = fs::canonicalize(host_git)?;
        let status = fs::metadata(&host_git)?;
        let store = host_git.as_os_str().as_bytes().starts_with(b"/nix/store/");
        let acceptable = status.is_file()
            && status.mode() & 0o100 != 0
            && if store {
                status.mode() & 0o222 == 0
            } else {
                status.uid() == 0 && status.mode() & 0o022 == 0
            };
        assert_eq!(unsafe_file(&host_git)?.is_none(), acceptable);
        Ok(())
    }

    #[test]
    fn group_3_clean_directory_does_not_make_unsafe_file_trusted() -> Result<()> {
        let directory = tempfile::tempdir()?;
        for name in ["git", "ssh-keygen"] {
            fixture_tool(&directory.path().join(name), 0o777)?;
        }
        let error = trusted_tools(
            directory
                .path()
                .to_str()
                .context("fixture path is not UTF-8")?,
            true,
            |_| Ok(None),
            unsafe_file,
        )
        .err()
        .context("unsafe tool accepted")?
        .to_string();
        let expected = if fs::metadata(directory.path().join("git"))?.uid() == 0 {
            "is writable by group or others"
        } else {
            "is not owned by root"
        };
        assert!(
            error.contains("git resolves to") && error.contains(expected),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn group_4_resolved_checked_files_are_executed() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let real_dir = directory.path().join("real");
        fs::create_dir(&real_dir)?;
        for name in ["git", "ssh-keygen"] {
            let real = real_dir.join(format!("{name}-real"));
            fixture_tool(&real, 0o755)?;
            symlink(real, directory.path().join(name))?;
        }
        let tools = trusted_tools(
            directory
                .path()
                .to_str()
                .context("fixture path is not UTF-8")?,
            true,
            |_| Ok(None),
            |_| Ok(None),
        )?;
        assert_eq!(tools.git, fs::canonicalize(real_dir.join("git-real"))?);
        assert_eq!(
            tools.ssh_keygen,
            fs::canonicalize(real_dir.join("ssh-keygen-real"))?
        );
        assert_eq!(tools.command().get_program(), tools.git.as_os_str());
        Ok(())
    }

    #[test]
    fn group_5_children_get_only_explicit_environment() {
        let hostile = env(&[
            ("LD_LIBRARY_PATH", "/evil"),
            ("LD_PRELOAD", "/evil.so"),
            ("SSH_AUTH_SOCK", "/agent"),
            ("GIT_DIR", "/evil"),
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_SSH_COMMAND", "evil"),
            ("PYTHONUNBUFFERED", "1"),
            ("PERL5OPT", "-Mevil"),
            ("HTTPS_PROXY", "http://evil"),
            ("PATH", "/evil/bin"),
            ("LC_ALL", "evil"),
            ("HOME", "/srv/example-home"),
            ("TMPDIR", "/var/tmp/x"),
            ("FOO", "bar"),
        ]);
        let expected = env(&[
            ("HOME", "/srv/example-home"),
            ("TMPDIR", "/var/tmp/x"),
            ("PATH", "/usr/bin:/bin"),
            ("LC_ALL", "C"),
            ("GIT_NO_REPLACE_OBJECTS", "1"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_NO_LAZY_FETCH", "1"),
        ]);
        assert_eq!(child_environment("/usr/bin:/bin", &hostile, None), expected);
        let extra = env(&[("GIT_AUTHOR_NAME", "Evidence signer")]);
        let mut with_extra = expected;
        with_extra.extend(extra.clone());
        assert_eq!(
            child_environment("/usr/bin:/bin", &hostile, Some(&extra)),
            with_extra
        );
        assert_eq!(
            child_environment("/bin", &Environment::new(), None).len(),
            7
        );
    }

    #[test]
    fn group_6_loader_variables_refuse_even_empty_values_and_sort_names() -> Result<()> {
        for name in REFUSED_ENVIRONMENT {
            for value in ["x", ""] {
                let error = refuse_loader_environment(&env(&[(name, value)]))
                    .err()
                    .context("loader accepted")?
                    .to_string();
                assert_eq!(
                    error,
                    format!(
                        "refusing to run with {name} set: the launcher must scrub the environment (this script cannot undo what the loader or interpreter already did)"
                    )
                );
            }
        }
        refuse_loader_environment(&env(&[
            ("LD_LIBRARY_PATH", "/x"),
            ("PYTHONUNBUFFERED", "1"),
            ("PATH", "/bin"),
        ]))?;
        let error = refuse_loader_environment(&env(&[
            ("PYTHONPATH", ""),
            ("LD_PRELOAD", ""),
            ("LD_AUDIT", ""),
        ]))
        .err()
        .context("loader accepted")?
        .to_string();
        assert_eq!(
            error,
            "refusing to run with LD_AUDIT, LD_PRELOAD, PYTHONPATH set: the launcher must scrub the environment (this script cannot undo what the loader or interpreter already did)"
        );
        Ok(())
    }

    #[test]
    fn directory_and_checked_path_refusal_messages() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let context = DirectoryContext {
            roots: vec![directory.path().to_path_buf()],
        };
        for (path, reason) in [
            ("relative", "not an absolute path"),
            ("/usr//bin", "has an empty, . or .. segment"),
            ("/usr/./bin", "has an empty, . or .. segment"),
            ("/usr/../bin", "has an empty, . or .. segment"),
        ] {
            assert_eq!(unsafe_directory(path, &context)?.as_deref(), Some(reason));
        }
        let text = directory
            .path()
            .to_str()
            .context("fixture path is not UTF-8")?;
        assert_eq!(
            unsafe_directory(text, &context)?,
            Some(format!("is under {text}, where code under test can write"))
        );
        let check =
            |directory: &str| Ok((directory != "/good").then(|| "is not a directory".into()));
        assert_eq!(checked_path("/missing:/good", false, &check)?, "/good");
        assert_eq!(
            checked_path("/missing", false, &check)
                .err()
                .context("empty path accepted")?
                .to_string(),
            "no usable directory in the signer's own path"
        );
        assert_eq!(
            checked_path("/missing:/good", true, &check)
                .err()
                .context("bad path accepted")?
                .to_string(),
            "tool path directory '/missing' is not a directory"
        );
        Ok(())
    }
}
