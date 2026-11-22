//! Git measurement isolation and the legacy wrapper's publication-only transport.
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use indexmap::IndexMap;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    os::unix::{ffi::OsStringExt, fs::OpenOptionsExt},
    process::{Command, Output, Stdio},
    time::Duration,
};

use crate::gate::git::deadline::GitChild;

type Environment = BTreeMap<OsString, OsString>;
const GIT_TIMEOUT: Duration = Duration::from_secs(600);
const PUSH_TRIES: usize = 3;

pub(super) struct Redactor {
    token: String,
    header: String,
}

impl Redactor {
    pub(super) fn new(token: String) -> Self {
        let header = if token.is_empty() {
            String::new()
        } else {
            STANDARD.encode(format!("x-access-token:{token}"))
        };
        Self { token, header }
    }

    pub(super) fn from_env() -> Self {
        Self::new(std::env::var("EVIDENCE_PUSH_TOKEN").unwrap_or_default())
    }

    pub(super) fn text<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        if self.token.is_empty() {
            return std::borrow::Cow::Borrowed(text);
        }
        let next = |text: &str| {
            [
                (text.find(&self.header), self.header.len()),
                (text.find(&self.token), self.token.len()),
            ]
            .into_iter()
            .filter_map(|(at, length)| at.map(|at| (at, length)))
            .min_by_key(|(at, _)| *at)
        };
        let Some((mut at, mut length)) = next(text) else {
            return std::borrow::Cow::Borrowed(text);
        };
        let mut redacted = String::with_capacity(text.len());
        let mut remaining = text;
        loop {
            redacted.push_str(&remaining[..at]);
            redacted.push_str("***");
            remaining = &remaining[at + length..];
            match next(remaining) {
                Some(found) => (at, length) = found,
                None => break,
            }
        }
        redacted.push_str(remaining);
        std::borrow::Cow::Owned(redacted)
    }
}

pub(super) fn git(args: &[&str], input: Option<&[u8]>) -> Result<Output> {
    let done = git_status(args, input, &[], false)?;
    if !done.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            diagnostic_tail(&done.stderr, &Redactor::from_env())
        );
    }
    Ok(done)
}

pub(super) fn git_status(
    args: &[&str],
    input: Option<&[u8]>,
    extra: &[(String, String)],
    publication: bool,
) -> Result<Output> {
    let mut command = git_command(args, &std::env::vars_os().collect(), extra, publication);
    capture(&mut command, input)
}

fn git_command(
    args: &[&str],
    environ: &Environment,
    extra: &[(String, String)],
    publication: bool,
) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    for (name, value) in environ {
        if !name.as_encoded_bytes().starts_with(b"GIT_")
            && name != OsStr::new("EVIDENCE_PUSH_TOKEN")
            && name != OsStr::new("EVIDENCE_SIGNER")
        {
            command.env(name, value);
        }
    }
    if publication {
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_ALLOW_PROTOCOL", "https:ssh:file");
        command.args([
            "-c",
            "http.followRedirects=false",
            "-c",
            "core.commitGraph=false",
            "-c",
            "core.multiPackIndex=false",
            "-c",
            "pack.useBitmaps=false",
            "-c",
            "pack.useBitmapBoundaryTraversal=false",
        ]);
    }
    command
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .envs(extra.iter().map(|(key, value)| (key, value)))
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.pager=cat",
        ])
        .args(args);
    command
}

fn capture(command: &mut Command, input: Option<&[u8]>) -> Result<Output> {
    // subprocess.run inherits stdin unless an input buffer was supplied.
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    GitChild::capture(command, input, GIT_TIMEOUT).map_err(|error| {
        anyhow::anyhow!(
            "{}",
            crate::evidence::legacy_verify::projection_process_error::diagnostic(
                command,
                &error,
                false,
                GIT_TIMEOUT
            )
        )
    })
}

fn whitespace(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

fn diagnostic_tail(bytes: &[u8], secrets: &Redactor) -> String {
    let decoded = String::from_utf8_lossy(bytes);
    let text = secrets.text(&decoded);
    let text = text.trim_matches(whitespace);
    let start = text.char_indices().rev().nth(499).map_or(0, |(at, _)| at);
    text[start..].to_owned()
}

fn token_environment(token: &str, url: &str) -> Vec<(String, String)> {
    if token.is_empty() {
        return Vec::new();
    }
    let header = STANDARD.encode(format!("x-access-token:{token}"));
    vec![
        ("GIT_CONFIG_COUNT".into(), "1".into()),
        ("GIT_CONFIG_KEY_0".into(), format!("http.{url}.extraheader")),
        (
            "GIT_CONFIG_VALUE_0".into(),
            format!("Authorization: Basic {header}"),
        ),
    ]
}

#[derive(Debug, PartialEq, Eq)]
enum PublicationUrlError {
    UnsupportedTransport,
    InvalidRepository,
    CheckoutLocalDestination,
}

impl std::fmt::Display for PublicationUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedTransport => "publication URL must target github.com over HTTPS or Git SSH (absolute local paths require no token)",
            Self::InvalidRepository => "publication URL must name one GitHub owner/repository without userinfo, port, escapes, query or fragment",
            Self::CheckoutLocalDestination => "checkout-configured local publication destination is refused; pass a trusted absolute path explicitly with --push",
        })
    }
}

impl std::error::Error for PublicationUrlError {}

fn trusted_url(
    url: &str,
    authenticated: bool,
    caller_explicit: bool,
) -> std::result::Result<String, PublicationUrlError> {
    // No userinfo, ports, escapes, query, fragment, options or remote-helper syntax.
    let (path, ssh) = if let Some(path) = url.strip_prefix("https://github.com/") {
        (path, false)
    } else if let Some(path) = url.strip_prefix("git@github.com:") {
        (path, true)
    } else if let Some(path) = url.strip_prefix("ssh://git@github.com/") {
        (path, true)
    } else {
        // Offline, credential-free publication remains useful for local callers.
        if std::path::Path::new(url).is_absolute() && !caller_explicit {
            return Err(PublicationUrlError::CheckoutLocalDestination);
        }
        if !authenticated && caller_explicit && std::path::Path::new(url).is_absolute() {
            return Ok(url.to_owned());
        }
        return Err(PublicationUrlError::UnsupportedTransport);
    };
    let Some((owner, repository)) = path.split_once('/') else {
        return Err(PublicationUrlError::InvalidRepository);
    };
    if [owner, repository].iter().any(|part| {
        part.is_empty()
            || matches!(*part, "." | "..")
            || !part
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    }) {
        return Err(PublicationUrlError::InvalidRepository);
    }
    if ssh && !authenticated {
        Ok(format!("ssh://git@github.com/{path}"))
    } else {
        Ok(format!("https://github.com/{path}"))
    }
}

fn publication_url(remote: &str, authenticated: bool) -> Result<String> {
    let caller_explicit = remote.contains('/') || remote.contains(':');
    let url = if caller_explicit {
        remote.to_owned()
    } else {
        // Read the literal URL once, not get-url (which applies insteadOf).
        // Includes and pushurl are deliberately not publication authorities.
        let done = git(
            &[
                "config",
                "--local",
                "--no-includes",
                "--get",
                &format!("remote.{remote}.url"),
            ],
            None,
        )?;
        String::from_utf8(done.stdout)?
            .trim_end_matches('\n')
            .to_owned()
    };
    Ok(trusted_url(&url, authenticated, caller_explicit)?)
}

#[derive(Debug)]
enum PublicationObjectsError {
    InvalidDirectory(std::path::PathBuf),
    InvalidPackOrMissingObjects(String),
    MissingHistory(String),
    InvalidShallowBoundary,
    ShallowBoundaryRead(io::Error),
    ShallowBoundaryTooLarge,
}

impl std::fmt::Display for PublicationObjectsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDirectory(path) => write!(
                f,
                "checkout object directory is not a directory: {}",
                path.display()
            ),
            Self::InvalidPackOrMissingObjects(detail) => write!(
                f,
                "publication pack is invalid or required checkout objects are missing (automatic fetching is disabled): {detail}"
            ),
            Self::MissingHistory(detail) => write!(
                f,
                "publication requires complete checkout history (automatic fetching is disabled): {detail}"
            ),
            Self::InvalidShallowBoundary => {
                f.write_str("checkout shallow boundary must contain only 40- or 64-hex object IDs")
            }
            Self::ShallowBoundaryRead(error) => write!(
                f,
                "reading checkout shallow boundary without following symlinks failed: {error}"
            ),
            Self::ShallowBoundaryTooLarge => {
                f.write_str("checkout shallow boundary exceeds the 1 MiB limit")
            }
        }
    }
}

impl std::error::Error for PublicationObjectsError {}

#[derive(Debug)]
struct PublicationRefMismatch {
    name: String,
    expected: String,
    actual: String,
}

impl std::fmt::Display for PublicationRefMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "checkout publication ref {} points at {}, not signed record {}",
            self.name, self.actual, self.expected
        )
    }
}

impl std::error::Error for PublicationRefMismatch {}

fn alternate_path(objects: &std::path::Path) -> String {
    use std::fmt::Write as _;
    let mut path = String::with_capacity(objects.as_os_str().len() + 3);
    path.push('"');
    for byte in objects.as_os_str().as_encoded_bytes() {
        match *byte {
            b'"' | b'\\' => {
                path.push('\\');
                path.push(char::from(*byte));
            }
            0x20..=0x7e => path.push(char::from(*byte)),
            _ => {
                let _ = write!(path, "\\{byte:03o}");
            }
        }
    }
    path.push_str("\"\n");
    path
}

fn publication_repository(
    directory: &std::path::Path,
    pack: &[u8],
    objects: &std::path::Path,
    refs: &[String],
    record: &str,
    environ: &Environment,
) -> Result<()> {
    if !objects.is_absolute() || !objects.is_dir() {
        return Err(PublicationObjectsError::InvalidDirectory(objects.to_owned()).into());
    }
    let mut init = git_command(&["init", "--bare", "--template=", "."], environ, &[], true);
    init.current_dir(directory);
    let done = capture(&mut init, None)?;
    if !done.status.success() {
        bail!("initializing isolated publication repository failed");
    }
    // Objects are read through the alternate; traversal metadata is disabled
    // for publication. Quote the path using Git's C-style alternate-path syntax.
    std::fs::write(
        directory.join("objects/info/alternates"),
        alternate_path(objects),
    )?;
    const MAX_SHALLOW_BYTES: u64 = 1024 * 1024;
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(objects.with_file_name("shallow"))
    {
        Ok(file) => {
            let metadata = file
                .metadata()
                .map_err(PublicationObjectsError::ShallowBoundaryRead)?;
            if !metadata.is_file() {
                return Err(PublicationObjectsError::ShallowBoundaryRead(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a regular file",
                ))
                .into());
            }
            if metadata.len() > MAX_SHALLOW_BYTES {
                return Err(PublicationObjectsError::ShallowBoundaryTooLarge.into());
            }
            let mut shallow = Vec::with_capacity(metadata.len() as usize);
            file.take(MAX_SHALLOW_BYTES + 1)
                .read_to_end(&mut shallow)
                .map_err(PublicationObjectsError::ShallowBoundaryRead)?;
            if shallow.len() as u64 > MAX_SHALLOW_BYTES {
                return Err(PublicationObjectsError::ShallowBoundaryTooLarge.into());
            }
            if !shallow.split_inclusive(|byte| *byte == b'\n').all(|line| {
                let oid = line.strip_suffix(b"\n").unwrap_or(line);
                matches!(oid.len(), 40 | 64) && oid.iter().all(u8::is_ascii_hexdigit)
            }) {
                return Err(PublicationObjectsError::InvalidShallowBoundary.into());
            }
            std::fs::write(directory.join("shallow"), shallow)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(PublicationObjectsError::ShallowBoundaryRead(error).into()),
    }
    let mut import = git_command(&["index-pack", "--strict", "--stdin"], environ, &[], true);
    import.current_dir(directory);
    let imported = capture(&mut import, Some(pack))?;
    if !imported.status.success() {
        return Err(PublicationObjectsError::InvalidPackOrMissingObjects(
            String::from_utf8_lossy(&imported.stderr).trim().to_owned(),
        )
        .into());
    }
    for name in refs {
        let mut update = git_command(&["update-ref", name, record], environ, &[], true);
        update.current_dir(directory);
        if !capture(&mut update, None)?.status.success() {
            bail!("preparing isolated publication ref failed");
        }
    }
    Ok(())
}

pub(super) fn push_refs(
    remote: &str,
    refs: &[String],
    record: &str,
    pack: &[u8],
    secrets: &Redactor,
) -> Result<()> {
    let result = (|| {
        let url = publication_url(remote, !secrets.token.is_empty())?;
        for name in refs {
            let done = git(
                &["for-each-ref", "--format=%(refname) %(objectname)", name],
                None,
            )?;
            for line in String::from_utf8(done.stdout)?.lines() {
                if let Some((found, actual)) = line.split_once(' ')
                    && found == name
                    && actual != record
                {
                    return Err(PublicationRefMismatch {
                        name: name.clone(),
                        expected: record.to_owned(),
                        actual: actual.to_owned(),
                    }
                    .into());
                }
            }
        }
        let mut common = git(
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
            None,
        )?
        .stdout;
        if common.last() == Some(&b'\n') {
            common.pop();
        }
        let objects = std::path::PathBuf::from(OsString::from_vec(common)).join("objects");
        let environ = std::env::vars_os().collect();
        let repository = tempfile::Builder::new()
            .prefix("evidence-push-")
            .tempdir()?;
        publication_repository(repository.path(), pack, &objects, refs, record, &environ)?;
        let extra = token_environment(&secrets.token, &url);
        push_with(
            &url,
            refs,
            |args| {
                let mut command = git_command(args, &environ, &extra, true);
                command.current_dir(repository.path());
                capture(&mut command, None)
            },
            std::thread::sleep,
            &mut io::stderr().lock(),
            secrets,
        )
    })();
    result.map_err(|error: anyhow::Error| {
        let detail = error.to_string();
        match secrets.text(&detail) {
            std::borrow::Cow::Borrowed(_) => error,
            std::borrow::Cow::Owned(redacted) => anyhow::anyhow!("{redacted}"),
        }
    })
}

fn push_with(
    remote: &str,
    refs: &[String],
    mut run: impl FnMut(&[&str]) -> Result<Output>,
    mut sleep: impl FnMut(Duration),
    diagnostics: &mut impl Write,
    secrets: &Redactor,
) -> Result<()> {
    let mut pending = refs.to_vec();
    for attempt in 1..=PUSH_TRIES {
        let specs: Vec<String> = pending
            .iter()
            .map(|name| format!("{name}:{name}"))
            .collect();
        let mut args = vec!["push", "--porcelain", remote];
        args.extend(specs.iter().map(String::as_str));
        let done = run(&args)?;
        if done.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&done.stderr);
        let stdout = String::from_utf8_lossy(&done.stdout);
        if [
            "Could not read ",
            "unable to read ",
            "unable to find ",
            "bad object ",
            "Failed to traverse parents",
            "did not receive expected object",
            "missing necessary objects",
            "missing blob ",
            "missing tree ",
            "missing commit ",
            "unresolved deltas",
            "shallow update not allowed",
        ]
        .iter()
        .any(|message| stderr.contains(message) || stdout.contains(message))
        {
            return Err(PublicationObjectsError::MissingHistory(format!(
                "{}\n{}",
                diagnostic_tail(&done.stderr, secrets),
                diagnostic_tail(&done.stdout, secrets),
            ))
            .into());
        }
        // Like Python's dict, preserve the first insertion order and the last reason.
        let mut refused = IndexMap::new();
        for line in stdout.split([
            '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
            '\u{2029}',
        ]) {
            let mut fields = line.split('\t');
            if !line.starts_with('!') {
                continue;
            }
            if let (Some(_), Some(names), Some(reason)) =
                (fields.next(), fields.next(), fields.next())
            {
                refused.insert(
                    names.split(':').next().unwrap_or("").to_owned(),
                    reason.trim_matches(whitespace),
                );
            }
        }
        if refused.is_empty() {
            bail!("push failed: {}", diagnostic_tail(&done.stderr, secrets));
        }
        if refused
            .values()
            .any(|reason| *reason != "[remote rejected] (failed)")
            || attempt == PUSH_TRIES
        {
            let shown = refused
                .iter()
                .map(|(name, reason)| format!("{name} {reason}"))
                .collect::<Vec<_>>()
                .join("; ");
            bail!("push failed (try {attempt} of {PUSH_TRIES}): {shown}");
        }
        writeln!(
            diagnostics,
            "evidence-wrap: {} answered {} ref(s) with a bare (failed); pushing them again ({} of {PUSH_TRIES})",
            secrets.text(remote),
            refused.len(),
            attempt + 1
        )?;
        diagnostics.flush()?;
        sleep(Duration::from_secs(2 * attempt as u64));
        pending = refused.into_keys().collect();
    }
    bail!("push failed after {PUSH_TRIES} attempts")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn diagnostic_redaction_covers_basic_auth_before_tail_truncation() {
        let token = "sensitive".repeat(100);
        let secrets = Redactor::new(token.clone());
        let text = format!(
            "raw={token} header={}",
            STANDARD.encode(format!("x-access-token:{token}"))
        );
        assert_eq!(
            diagnostic_tail(text.as_bytes(), &secrets),
            "raw=*** header=***"
        );
        assert_eq!(secrets.text("ordinary diagnostic"), "ordinary diagnostic");
    }

    #[test]
    fn git_capture_spawn_errors_use_python_command_diagnostics() {
        let mut command = Command::new("/definitely-missing-legacy-wrap-git");
        let error = capture(&mut command, None).unwrap_err().to_string();
        assert_eq!(
            error,
            "[Errno 2] No such file or directory: '/definitely-missing-legacy-wrap-git'"
        );
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "collector deadline");
        assert_eq!(
            crate::evidence::legacy_verify::projection_process_error::diagnostic(
                &command,
                &timeout,
                true,
                GIT_TIMEOUT
            ),
            "Command '['/definitely-missing-legacy-wrap-git']' timed out after 600 seconds"
        );
    }

    fn environment(values: &[(&str, &str)]) -> Environment {
        values
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    fn output(success: bool, stdout: &str, stderr: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(if success { 0 } else { 256 }),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn all_git_overrides_are_scrubbed_before_publication_configuration() {
        let env = environment(&[
            ("PATH", "/bin"),
            ("GIT_CONFIG_COUNT", "999"),
            ("GIT_CONFIG_KEY_0", "http.extraheader"),
            ("GIT_CONFIG_VALUE_0", "caller-secret"),
            ("GIT_CONFIG_GLOBAL", "/hostile"),
            ("GIT_DIR", "/wrong"),
            ("GIT_SSH_COMMAND", "/evil"),
            ("GIT_ASKPASS", "/evil"),
            ("EVIDENCE_PUSH_TOKEN", "secret"),
        ]);
        for publication in [false, true] {
            let command = git_command(&["status"], &env, &[], publication);
            let actual: Environment = command
                .get_envs()
                .map(|(key, value)| (key.to_owned(), value.unwrap().to_owned()))
                .collect();
            for name in [
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0",
                "GIT_DIR",
                "GIT_SSH_COMMAND",
                "GIT_ASKPASS",
                "EVIDENCE_PUSH_TOKEN",
            ] {
                assert!(!actual.contains_key(OsStr::new(name)), "{name}");
            }
            if publication {
                assert_eq!(actual[OsStr::new("GIT_CONFIG_GLOBAL")], "/dev/null");
                assert_eq!(actual[OsStr::new("GIT_CONFIG_NOSYSTEM")], "1");
                let args: Vec<_> = command.get_args().collect();
                for setting in [
                    "core.commitGraph=false",
                    "core.multiPackIndex=false",
                    "pack.useBitmaps=false",
                    "pack.useBitmapBoundaryTraversal=false",
                ] {
                    assert!(
                        args.windows(2)
                            .any(|pair| pair[0] == "-c" && pair[1] == setting)
                    );
                }
            } else {
                assert!(!actual.contains_key(OsStr::new("GIT_CONFIG_GLOBAL")));
            }
        }
    }

    #[test]
    fn retries_only_bare_failed_refs_with_exact_backoff_and_diagnostics() {
        let refs = vec!["refs/tags/a".into(), "refs/notes/b".into()];
        let mut calls = Vec::new();
        let mut sleeps = Vec::new();
        let mut diagnostics = Vec::new();
        push_with("origin", &refs, |args| {
            calls.push(args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>());
            Ok(match calls.len() {
                1 => output(false, "=\trefs/tags/a:refs/tags/a\t[up to date]\n!\trefs/notes/b:refs/notes/b\t[remote rejected] (failed)\n", ""),
                2 => output(false, "!\trefs/notes/b:refs/notes/b\t[remote rejected] (failed)\n", ""),
                _ => output(true, "", ""),
            })
        }, |duration| sleeps.push(duration), &mut diagnostics, &Redactor::new(String::new())).unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[0],
            [
                "push",
                "--porcelain",
                "origin",
                "refs/tags/a:refs/tags/a",
                "refs/notes/b:refs/notes/b"
            ]
        );
        for call in &calls[1..] {
            assert_eq!(
                call,
                &["push", "--porcelain", "origin", "refs/notes/b:refs/notes/b"]
            );
        }
        assert_eq!(sleeps, [Duration::from_secs(2), Duration::from_secs(4)]);
        assert_eq!(
            String::from_utf8(diagnostics).unwrap(),
            concat!(
                "evidence-wrap: origin answered 1 ref(s) with a bare (failed); pushing them again (2 of 3)\n",
                "evidence-wrap: origin answered 1 ref(s) with a bare (failed); pushing them again (3 of 3)\n",
            )
        );
    }

    #[test]
    fn reasoned_refusals_and_transport_errors_never_retry() {
        for (stdout, stderr, expected) in [
            (
                "!\ta:a\t[remote rejected] (failed)\n!\tb:b\t[remote rejected] (pre-receive hook declined)\n",
                "",
                "push failed (try 1 of 3): a [remote rejected] (failed); b [remote rejected] (pre-receive hook declined)",
            ),
            ("", " network error \n", "push failed: network error"),
        ] {
            let mut calls = 0;
            let mut diagnostics = Vec::new();
            let error = push_with(
                "origin",
                &["a".into(), "b".into()],
                |_| {
                    calls += 1;
                    Ok(output(false, stdout, stderr))
                },
                |_| panic!("must not back off"),
                &mut diagnostics,
                &Redactor::new(String::new()),
            )
            .unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert_eq!(calls, 1);
            assert!(diagnostics.is_empty());
        }
    }

    #[test]
    fn bare_failures_stop_at_three_and_preserve_refusal_order() {
        let mut calls = 0;
        let error = push_with(
            "origin",
            &["z".into(), "a".into()],
            |_| {
                calls += 1;
                Ok(output(
                    false,
                    "!\tz:z\t[remote rejected] (failed)\n!\ta:a\t[remote rejected] (failed)\n",
                    "",
                ))
            },
            |_| {},
            &mut Vec::new(),
            &Redactor::new(String::new()),
        )
        .unwrap_err();
        assert_eq!(calls, 3);
        assert_eq!(
            error.to_string(),
            "push failed (try 3 of 3): z [remote rejected] (failed); a [remote rejected] (failed)"
        );
    }

    fn run_in(
        repo: &std::path::Path,
        env: &Environment,
        args: &[&str],
        input: Option<&[u8]>,
        extra: &[(String, String)],
    ) -> Output {
        let mut command = git_command(args, env, extra, true);
        command.current_dir(repo);
        let done = capture(&mut command, input).unwrap();
        assert!(
            done.status.success(),
            "{}",
            String::from_utf8_lossy(&done.stderr)
        );
        done
    }

    #[test]
    fn isolated_bare_publication_ignores_hostile_checkout_and_caller_config() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let sink = tmp.path().join("sink.git");
        let isolated = tmp.path().join("publication.git");
        let marker = tmp.path().join("executed");
        let env: Environment = std::env::vars_os().collect();
        for directory in [&repo, &isolated] {
            std::fs::create_dir(directory).unwrap();
        }
        run_in(&repo, &env, &["init", "-q"], None, &[]);
        run_in(
            &repo,
            &env,
            &["init", "-q", "--bare", sink.to_str().unwrap()],
            None,
            &[],
        );
        let oid = run_in(
            &repo,
            &env,
            &["hash-object", "-w", "--stdin"],
            Some(b"record"),
            &[],
        );
        let oid = std::str::from_utf8(&oid.stdout).unwrap().trim();
        let pack = run_in(
            &repo,
            &env,
            &["pack-objects", "--stdout", "--revs"],
            Some(format!("{oid}\n").as_bytes()),
            &[],
        );
        let sink_url = sink.to_str().unwrap();
        let evil = format!("!touch {}", marker.display());
        let included = tmp.path().join("included.config");
        std::fs::write(
            &included,
            format!(
                "[url \"ext::sh -c 'touch {}'\"]\n insteadOf = {sink_url}\n",
                marker.display()
            ),
        )
        .unwrap();
        let config = format!(
            "[core]\n repositoryformatversion = 0\n bare = false\n sshCommand = touch {marker}\n\
             [remote \"origin\"]\n url = {sink_url}\n pushurl = ext::touch {marker}\n\
             [url \"ext::touch {marker}\"]\n insteadOf = {sink_url}\n pushInsteadOf = {sink_url}\n\
             [include]\n path = {included}\n\
             [includeIf \"gitdir:{repo}/\"]\n path = {included}\n\
             [credential]\n helper = {evil}\n\
             [http]\n extraheader = caller-secret\n\
             [http \"https://github.com/owner/repo.git\"]\n extraheader = checkout-secret\n",
            marker = marker.display(),
            included = included.display(),
            repo = repo.display()
        );
        std::fs::write(repo.join(".git/config"), &config).unwrap();
        let mut hostile_env = env.clone();
        hostile_env.insert(
            "GIT_CONFIG_GLOBAL".into(),
            repo.join(".git/config").into_os_string(),
        );
        hostile_env.insert("GIT_CONFIG_COUNT".into(), "1".into());
        hostile_env.insert("GIT_CONFIG_KEY_0".into(), "url.ext::evil.insteadOf".into());
        hostile_env.insert("GIT_CONFIG_VALUE_0".into(), sink_url.into());
        publication_repository(
            &isolated,
            &pack.stdout,
            &repo.join(".git/objects"),
            &["refs/tags/evidence/test".into()],
            oid,
            &hostile_env,
        )
        .unwrap();
        let url = "https://github.com/owner/repo.git";
        let extra = token_environment("secret-token-xyz", url);
        assert_eq!(extra[1].1, format!("http.{url}.extraheader"));
        let mut command = git_command(&["config", "--list"], &hostile_env, &extra, true);
        command.current_dir(&isolated);
        let done = capture(&mut command, None).unwrap();
        assert!(done.status.success());
        let config = String::from_utf8(done.stdout).unwrap();
        assert!(config.contains(&format!("http.{url}.extraheader=Authorization: Basic ")));
        for forbidden in [
            "caller-secret",
            "checkout-secret",
            "insteadof",
            "pushurl",
            "credential.helper",
            "sshcommand",
            "include",
            "http.extraheader",
        ] {
            assert!(!config.contains(forbidden), "{config}");
        }
        let mut command = git_command(
            &[
                "push",
                "--porcelain",
                sink_url,
                "refs/tags/evidence/test:refs/tags/evidence/test",
            ],
            &hostile_env,
            &extra,
            true,
        );
        assert!(!format!("{:?}", command.get_args().collect::<Vec<_>>()).contains("secret-token"));
        command.current_dir(&isolated);
        let done = capture(&mut command, None).unwrap();
        assert!(
            done.status.success(),
            "{}",
            String::from_utf8_lossy(&done.stderr)
        );
        assert!(!marker.exists());
        let actual = run_in(
            &sink,
            &env,
            &["rev-parse", "refs/tags/evidence/test"],
            None,
            &[],
        );
        assert_eq!(String::from_utf8(actual.stdout).unwrap().trim(), oid);
        assert!(isolated.join("objects/info/alternates").is_file());
    }

    #[test]
    fn shallow_porcelain_refusal_has_typed_redacted_history_detail() {
        let error = push_with(
            "/trusted/sink.git",
            &["refs/notes/evidence/test".into()],
            |_| {
                Ok(output(
                    false,
                    "!\ta:a\t[remote rejected] (shallow update not allowed) secret-token\n",
                    "Git transport refused secret-token",
                ))
            },
            |_| panic!("shallow rejection must not retry"),
            &mut Vec::new(),
            &Redactor::new("secret-token".into()),
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<PublicationObjectsError>(),
            Some(PublicationObjectsError::MissingHistory(_))
        ));
        assert!(error.to_string().contains("shallow update not allowed"));
        assert!(error.to_string().contains("Git transport refused ***"));
        assert!(!error.to_string().contains("secret-token"));
    }

    #[test]
    fn malformed_shallow_boundary_is_refused_before_import() {
        let tmp = tempfile::tempdir().unwrap();
        let common = tmp.path().join("source.git");
        let objects = common.join("objects");
        let isolated = tmp.path().join("isolated.git");
        std::fs::create_dir_all(&objects).unwrap();
        std::fs::create_dir(&isolated).unwrap();
        std::fs::write(common.join("shallow"), b"not-an-object-id\n").unwrap();
        let error = publication_repository(
            &isolated,
            b"",
            &objects,
            &[],
            "",
            &std::env::vars_os().collect(),
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<PublicationObjectsError>(),
            Some(PublicationObjectsError::InvalidShallowBoundary)
        ));
    }

    #[test]
    fn shallow_boundary_symlinks_and_oversized_files_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let common = tmp.path().join("source.git");
        let objects = common.join("objects");
        std::fs::create_dir_all(&objects).unwrap();
        let real = tmp.path().join("boundary");
        std::fs::write(&real, format!("{}\n", "a".repeat(40))).unwrap();
        let shallow = common.join("shallow");
        std::os::unix::fs::symlink(&real, &shallow).unwrap();
        for oversized in [false, true] {
            if oversized {
                std::fs::remove_file(&shallow).unwrap();
                std::fs::File::create(&shallow)
                    .unwrap()
                    .set_len(1024 * 1024 + 1)
                    .unwrap();
            }
            let isolated = tmp.path().join(if oversized {
                "large.git"
            } else {
                "symlink.git"
            });
            std::fs::create_dir(&isolated).unwrap();
            let error = publication_repository(
                &isolated,
                b"",
                &objects,
                &[],
                "",
                &std::env::vars_os().collect(),
            )
            .unwrap_err();
            if oversized {
                assert!(matches!(
                    error.downcast_ref::<PublicationObjectsError>(),
                    Some(PublicationObjectsError::ShallowBoundaryTooLarge)
                ));
            } else {
                assert!(matches!(
                    error.downcast_ref::<PublicationObjectsError>(),
                    Some(PublicationObjectsError::ShallowBoundaryRead(_))
                ));
            }
            assert!(!isolated.join("shallow").exists());
        }
    }

    #[test]
    fn missing_promisor_history_fails_closed_with_typed_publication_error() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source.git");
        let isolated = tmp.path().join("isolated.git");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&isolated).unwrap();
        let env: Environment = std::env::vars_os().collect();
        run_in(
            &source,
            &env,
            &["init", "--bare", "--template=", "."],
            None,
            &[],
        );
        run_in(&source, &env, &["config", "user.name", "Test"], None, &[]);
        run_in(
            &source,
            &env,
            &["config", "user.email", "test@example.invalid"],
            None,
            &[],
        );
        let tree = run_in(&source, &env, &["mktree"], Some(b""), &[]);
        let tree = std::str::from_utf8(&tree.stdout).unwrap().trim();
        let root = run_in(&source, &env, &["commit-tree", tree], Some(b"root\n"), &[]);
        let root = std::str::from_utf8(&root.stdout).unwrap().trim();
        let middle = run_in(
            &source,
            &env,
            &["commit-tree", tree, "-p", root],
            Some(b"middle\n"),
            &[],
        );
        let middle = std::str::from_utf8(&middle.stdout).unwrap().trim();
        let subject = run_in(
            &source,
            &env,
            &["commit-tree", tree, "-p", middle],
            Some(b"subject\n"),
            &[],
        );
        let subject = std::str::from_utf8(&subject.stdout).unwrap().trim();
        let record = run_in(
            &source,
            &env,
            &["commit-tree", tree, "-p", subject],
            Some(b"record\n"),
            &[],
        );
        let record = std::str::from_utf8(&record.stdout).unwrap().trim();
        let pack = run_in(
            &source,
            &env,
            &["pack-objects", "--stdout"],
            Some(format!("{record}\n{subject}\n{tree}\n").as_bytes()),
            &[],
        );
        run_in(
            &source,
            &env,
            &["config", "remote.origin.promisor", "true"],
            None,
            &[],
        );
        run_in(
            &source,
            &env,
            &["config", "remote.origin.url", "ext::must-not-fetch"],
            None,
            &[],
        );
        std::fs::remove_file(source.join("objects").join(&root[..2]).join(&root[2..])).unwrap();
        publication_repository(
            &isolated,
            &pack.stdout,
            &source.join("objects"),
            &["refs/notes/evidence/test".into()],
            record,
            &env,
        )
        .unwrap();
        let sink = tmp.path().join("sink.git");
        run_in(
            &source,
            &env,
            &["init", "--bare", "--template=", sink.to_str().unwrap()],
            None,
            &[],
        );
        let error = push_with(
            sink.to_str().unwrap(),
            &["refs/notes/evidence/test".into()],
            |args| {
                let mut command = git_command(args, &env, &[], true);
                command.current_dir(&isolated);
                capture(&mut command, None)
            },
            |_| panic!("missing history must not retry"),
            &mut Vec::new(),
            &Redactor::new(String::new()),
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<PublicationObjectsError>(),
            Some(PublicationObjectsError::MissingHistory(_))
        ));
        assert!(error.to_string().contains("automatic fetching is disabled"));
        let command = git_command(&["push"], &env, &[], true);
        assert!(
            command
                .get_envs()
                .any(|(key, value)| key == "GIT_NO_LAZY_FETCH" && value == Some(OsStr::new("1")))
        );
    }

    #[test]
    fn diagnostic_tail_matches_python_character_slicing() {
        let text = format!("\u{1c}{}end\u{1f}", "é".repeat(600));
        assert_eq!(
            diagnostic_tail(text.as_bytes(), &Redactor::new(String::new())),
            format!("{}end", "é".repeat(497))
        );
        assert!(token_environment("", "https://github.com/owner/repo").is_empty());
    }

    #[test]
    fn trusted_urls_reject_transport_ambiguity_and_scope_tokens() {
        for url in [
            "https://github.com.evil/owner/repo",
            "https://evil@github.com/owner/repo",
            "https://github.com:443/owner/repo",
            "https://github.com/owner/repo?x",
            "https://github.com/owner/repo#x",
            "https://github.com/owner/%72epo",
            "https://GITHUB.COM/owner/repo",
            "https://ɡithub.com/owner/repo",
            "git@evil:owner/repo",
            "ext::evil",
            "-evil",
            "/local/repo",
        ] {
            assert!(trusted_url(url, true, true).is_err(), "{url}");
        }
        for url in [
            "https://github.com/owner/repo.git",
            "git@github.com:owner/repo.git",
            "ssh://git@github.com/owner/repo.git",
        ] {
            assert_eq!(
                trusted_url(url, true, false).unwrap(),
                "https://github.com/owner/repo.git"
            );
        }
        assert_eq!(
            trusted_url("git@github.com:owner/repo", false, false).unwrap(),
            "ssh://git@github.com/owner/repo"
        );
        assert_eq!(
            trusted_url("/local/repo", false, true).unwrap(),
            "/local/repo"
        );
        assert_eq!(
            trusted_url("/local/repo", false, false),
            Err(PublicationUrlError::CheckoutLocalDestination)
        );
        assert!(trusted_url("file:///local/repo", false, true).is_err());
        let extra = token_environment("secret", "https://github.com/owner/repo");
        assert_eq!(extra[0].1, "1");
        assert_eq!(extra[1].1, "http.https://github.com/owner/repo.extraheader");
    }
}
