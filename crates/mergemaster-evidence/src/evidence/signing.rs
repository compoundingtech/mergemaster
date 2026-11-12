//! Cooperative wrapper signer: account-owned configuration, independent object binding,
//! and an isolated Git repository. No consumer code executes with signing authority.
use super::{
    Check, Fact, Observation, PREDICATE_TYPE, STATEMENT_TYPE, Statement, Subject, TrustTier,
};
use crate::gate::{config, git};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[derive(Args)]
pub struct SignArgs {
    /// Explicit operator-owned configuration outside the consumer checkout.
    #[arg(long)]
    pub config: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub repo: PathBuf,
    pub base: String,
    pub head: String,
    pub check: String,
    pub command: Vec<String>,
    pub exit_code: i32,
    pub output: String,
    pub inputs: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub record: String,
    pub bundle: String,
    pub note_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignConfig {
    version: u32,
    signer: String,
    ssh_key: PathBuf,
    path: Option<String>,
    toolchain: Measurements,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Measurements {
    runtime: PathBuf,
    dependencies: BTreeMap<String, PathBuf>,
}

fn refuse_loader() -> Result<()> {
    ensure!(
        !std::env::vars_os().any(|(key, _)| {
            let key = key.to_string_lossy();
            key.starts_with("LD_")
                || key.starts_with("DYLD_")
                || matches!(
                    key.as_ref(),
                    "GCONV_PATH" | "NLSPATH" | "PYTHONPATH" | "PYTHONSTARTUP" | "PYTHONHOME"
                )
        }),
        "signer refuses loader/interpreter overrides; scrub them in the launcher"
    );
    Ok(())
}

fn configuration(path: &Path, repo: &Path) -> Result<SignConfig> {
    ensure!(path.is_absolute(), "signer configuration must be absolute");
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "configuration must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let home = std::env::var_os("HOME").context("signer requires account HOME")?;
        ensure!(
            metadata.mode() & 0o077 == 0 && metadata.uid() == std::fs::metadata(home)?.uid(),
            "configuration must be account-owned and private (0600)"
        );
    }
    ensure!(
        !std::fs::canonicalize(path)?.starts_with(std::fs::canonicalize(repo)?),
        "configuration must be outside consumer repository"
    );
    let config: SignConfig = serde_json::from_slice(&std::fs::read(path)?)?;
    ensure!(
        config.version == 1
            && config
                .signer
                .split_once('/')
                .is_some_and(|(level, name)| matches!(level, "agent" | "host")
                    && !name.is_empty()
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))),
        "invalid signer configuration"
    );
    ensure!(config.ssh_key.is_absolute(), "signing key must be absolute");
    if let Some(path) = config.path.as_deref() {
        ensure!(
            std::env::split_paths(path).all(|dir| dir.is_absolute()),
            "trusted executable search path must be absolute-only"
        );
    }
    let key = std::fs::symlink_metadata(&config.ssh_key)?;
    ensure!(
        key.is_file() && !key.file_type().is_symlink(),
        "signing key must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            key.mode() & 0o077 == 0 && key.uid() == metadata.uid(),
            "signing key must be account-owned and private"
        );
    }
    ensure!(
        !std::fs::canonicalize(&config.ssh_key)?.starts_with(std::fs::canonicalize(repo)?),
        "key must be outside consumer repository"
    );
    Ok(config)
}

pub(super) fn hash_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn measure(
    path: &Path,
    expected: &config::Artifact,
    nix: Option<&Path>,
) -> Result<Option<BTreeMap<String, String>>> {
    ensure!(
        path.is_absolute(),
        "toolchain measurement paths must be absolute"
    );
    if let Some(hash) = expected.identity.strip_prefix("sha256:") {
        ensure!(
            std::fs::metadata(path)?.is_file() && hash_file(path)? == hash,
            "toolchain file identity mismatch"
        );
    } else if let Some(commit) = expected.identity.strip_prefix("git:") {
        ensure!(
            git::text(path, &["rev-parse", "HEAD"])? == commit && clean(path)?,
            "toolchain repository identity mismatch or dirty dependency"
        );
    } else if let Some(root) = expected.identity.strip_prefix("nix:") {
        ensure!(
            path == Path::new(root),
            "configured Nix artifact differs from BASE"
        );
        return Ok(Some(super::nix::measure(
            nix.context("trusted nix missing")?,
            root,
        )?));
    } else {
        anyhow::bail!("unsupported toolchain identity");
    }
    Ok(None)
}

/// Resolve a lane `argv[0]` to a canonical executable path. Absolute paths
/// keep the historic strict behavior. Relative names resolve against the
/// caller's PATH first (matching execution), then the account's trusted
/// search path (the isolated signer worker's PATH carries only
/// git/ssh-keygen). The caller must check closure membership, so a hostile
/// PATH cannot smuggle in an unmeasured binary.
fn resolve_lane_executable(config: &SignConfig, argv0: &str) -> Result<PathBuf> {
    resolve_lane_executable_with_search_path(config, argv0, std::env::var_os("PATH").as_deref())
}

fn resolve_lane_executable_with_search_path(
    config: &SignConfig,
    argv0: &str,
    caller_path: Option<&std::ffi::OsStr>,
) -> Result<PathBuf> {
    ensure!(
        !Path::new(argv0)
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir)),
        "Nix lanes require argv[0] without parent-directory escapes"
    );
    let resolved = if Path::new(argv0).is_absolute() {
        PathBuf::from(argv0)
    } else {
        let mut directories = caller_path
            .map(|path| std::env::split_paths(path).collect::<Vec<_>>())
            .unwrap_or_default();
        if let Some(path) = config.path.as_deref() {
            directories.extend(std::env::split_paths(path));
        }
        directories
            .into_iter()
            .map(|directory| directory.join(argv0))
            .find(|candidate| candidate.is_file())
            .context("lane executable not found on trusted search path")?
    };
    ensure!(
        !resolved
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir)),
        "Nix lanes require argv[0] without parent-directory escapes"
    );
    std::fs::canonicalize(&resolved)
        .with_context(|| format!("lane executable is not a resolvable file: {argv0}"))
}

/// Independently measure provisioned artifacts and bind execution to Nix closure bytes.
pub fn measure_toolchain(
    repo: &Path,
    environment: &config::Environment,
    path: &Path,
    command: &[String],
    bind_execution: bool,
) -> Result<BTreeMap<String, String>> {
    let config = configuration(path, repo)?;
    let system = config::current_system();
    let toolchain = environment
        .systems
        .get(&system)
        .with_context(|| format!("committed environment has no toolchain for {system}"))?;
    ensure!(
        config.toolchain.dependencies.len() == toolchain.dependencies.len(),
        "dependency measurement set differs"
    );
    let artifacts = std::iter::once((
        "runtime",
        &toolchain.runtime,
        Some(&config.toolchain.runtime),
    ))
    .chain(toolchain.dependencies.iter().map(|(name, artifact)| {
        (
            name.as_str(),
            artifact,
            config.toolchain.dependencies.get(name),
        )
    }));
    let needs_nix = toolchain.runtime.identity.starts_with("nix:")
        || toolchain
            .dependencies
            .values()
            .any(|a| a.identity.starts_with("nix:"));
    let nix = needs_nix.then(|| find_tool(&config, "nix")).transpose()?;
    let mut claims = BTreeMap::new();
    let mut executable_bound = false;
    let executable = if needs_nix && bind_execution {
        let argv0 = command.first().context("missing lane executable")?;
        Some(resolve_lane_executable(&config, argv0)?)
    } else {
        None
    };
    for (_name, artifact, provisioned) in artifacts {
        let provisioned = provisioned.context("missing dependency measurement")?;
        if let Some(closure) = measure(provisioned, artifact, nix.as_deref())? {
            claims.insert(
                format!("nix_closure_sha256:{}", artifact.identity),
                super::nix::digest(&closure)?,
            );
            executable_bound |= executable
                .as_ref()
                .is_some_and(|exe| closure.keys().any(|root| exe.starts_with(root)));
        }
    }
    ensure!(
        !needs_nix || !bind_execution || executable_bound,
        "lane executable is outside measured Nix closures"
    );
    Ok(claims)
}

pub fn clean(repo: &Path) -> Result<bool> {
    Ok(tracked_clean(repo)? && super::workspace::declared_only(repo, &[])?)
}

pub(super) fn tracked_clean(repo: &Path) -> Result<bool> {
    // Status alone trusts index flags and stat caches; execution uses filesystem bytes.
    let entries = git::git(repo, &["ls-files", "-v", "-z"])?;
    if entries
        .split(|b| *b == 0)
        .filter(|entry| !entry.is_empty())
        .any(|entry| entry[0] != b'H')
    {
        return Ok(false);
    }
    // Collect every tracked blob first so one `cat-file --batch` session serves
    // all comparisons; the previous code spawned one Git process per file.
    let tree = git::git(repo, &["ls-tree", "-r", "-z", "HEAD"])?;
    let mut requests: Vec<(String, String, Vec<u8>)> = Vec::new();
    for entry in tree.split(|b| *b == 0).filter(|entry| !entry.is_empty()) {
        let (metadata, path) = entry.split_at(
            entry
                .iter()
                .position(|b| *b == b'\t')
                .context("invalid tree entry")?,
        );
        let mut fields = std::str::from_utf8(metadata)?.split(' ');
        let mode = fields.next().context("missing tree mode")?;
        ensure!(
            fields.next() == Some("blob"),
            "workspace inputs must be tracked blobs"
        );
        let object = fields.next().context("missing tree object")?;
        requests.push((mode.to_owned(), object.to_owned(), path[1..].to_vec()));
    }
    let ids: Vec<String> = requests
        .iter()
        .map(|(_, object, _)| object.clone())
        .collect();
    let committed = git::blob_contents(repo, &ids)?;
    for ((mode, _, raw_path), body) in requests.into_iter().zip(committed) {
        let path = repo.join(std::str::from_utf8(&raw_path)?);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let actual = if mode == "120000" {
            if !metadata.file_type().is_symlink() {
                return Ok(false);
            }
            hex::encode(Sha256::digest(
                std::fs::read_link(&path)?.as_os_str().as_encoded_bytes(),
            ))
        } else {
            if !metadata.is_file() {
                return Ok(false);
            }
            hash_file(&path)?
        };
        if actual != hex::encode(Sha256::digest(body)) {
            return Ok(false);
        }
    }
    // Staged changes are forbidden even when working bytes match HEAD.
    Ok(git::git(
        repo,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
            "--ignore-submodules=none",
        ],
    )?
    .is_empty())
}

/// File-level trust rules match the legacy signer. Directory validation remains
/// separate: a safe parent does not make a writable tool safe.
fn trusted_file_mode(path: &Path, mode: u32, uid: u32) -> Result<()> {
    ensure!(
        mode & 0o170000 == 0o100000,
        "trusted tool is not a regular file"
    );
    if path.starts_with("/nix/store") {
        ensure!(mode & 0o222 == 0, "tool has a write bit in the Nix store");
    } else {
        ensure!(uid == 0, "tool is not owned by root");
        ensure!(mode & 0o022 == 0, "tool is writable by group or others");
    }
    ensure!(mode & 0o100 != 0, "tool is not executable by its owner");
    Ok(())
}

fn trusted_file(path: &Path) -> Result<PathBuf> {
    let path = std::fs::canonicalize(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(&path)?;
        trusted_file_mode(&path, metadata.mode(), metadata.uid())?;
        let mut parent = path.parent();
        while let Some(directory) = parent {
            let metadata = std::fs::metadata(directory)?;
            if directory.starts_with("/nix/store/") {
                ensure!(metadata.mode() & 0o222 == 0, "mutable Nix tool directory");
                break;
            }
            ensure!(
                metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                "unsafe trusted tool directory"
            );
            parent = directory.parent();
        }
    }
    Ok(path)
}

pub(super) fn trusted_tool(path: &str, name: &str) -> Result<PathBuf> {
    for directory in path.split(':') {
        ensure!(
            Path::new(directory).is_absolute(),
            "trusted PATH must contain only absolute directories"
        );
        let candidate = Path::new(directory).join(name);
        if candidate.exists() {
            return trusted_file(&candidate);
        }
    }
    anyhow::bail!("trusted tool missing: {name}")
}

fn find_tool(config: &SignConfig, name: &str) -> Result<PathBuf> {
    trusted_tool(
        config.path.as_deref().unwrap_or(
            "/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/bin:/bin",
        ),
        name,
    )
}

fn tools(config: &SignConfig) -> Result<(PathBuf, PathBuf)> {
    Ok((find_tool(config, "git")?, find_tool(config, "ssh-keygen")?))
}

pub(super) fn derivation(
    repo: &Path,
    head: &str,
    lane: &config::Lane,
    environment: &config::Environment,
    path: &Path,
) -> Result<Option<(super::derivation::Derivation, PathBuf, PathBuf)>> {
    let Some(check) = &lane.nix_check else {
        return Ok(None);
    };
    let config = configuration(path, repo)?;
    let nix = find_tool(&config, "nix")?;
    ensure!(
        Path::new(&lane.argv[0]) == nix,
        "BASE must pin the configured trusted nix executable"
    );
    let root = nix
        .ancestors()
        .find_map(|path| path.to_str().filter(|path| config::nix_store_path(path)))
        .context("Nix executable must reside in a store artifact")?;
    ensure!(
        environment
            .systems
            .values()
            .flat_map(|toolchain| {
                std::iter::once(&toolchain.runtime).chain(toolchain.dependencies.values())
            })
            .any(|artifact| artifact.identity == format!("nix:{root}")),
        "declare the Nix executable's store root as a nix: artifact"
    );
    let git = find_tool(&config, "git")?;
    Ok(Some((
        super::derivation::Derivation::evaluate(&nix, &git, repo, head, check)?,
        nix,
        git,
    )))
}

/// Re-exec with a closed environment before invoking the shared immutable-record writer.
pub fn run_sign(args: SignArgs) -> Result<()> {
    refuse_loader()?;
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes)?;
    let request: Request = serde_json::from_slice(&bytes)?;
    let config = configuration(&args.config, &request.repo)?;
    let (git, ssh) = tools(&config)?;
    let tools_dir = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(git, tools_dir.path().join("git"))?;
        std::os::unix::fs::symlink(ssh, tools_dir.path().join("ssh-keygen"))?;
    }
    let mut worker = Command::new(std::env::current_exe()?);
    worker
        .env_clear()
        .env("PATH", tools_dir.path())
        .env("LC_ALL", "C")
        .env("HOME", std::env::var_os("HOME").context("HOME required")?);
    git::sanitize(&mut worker);
    let mut child = worker
        .arg("evidence")
        .arg("sign-worker")
        .arg("--config")
        .arg(args.config)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    child
        .stdin
        .take()
        .context("sign worker stdin")?
        .write_all(&bytes)?;
    ensure!(
        child.wait()?.success(),
        "isolated signer refused observation"
    );
    Ok(())
}

pub fn run_worker(args: SignArgs) -> Result<()> {
    refuse_loader()?;
    let request: Request = serde_json::from_reader(std::io::stdin())?;
    ensure!(
        request.version == 1
            && request.repo.is_absolute()
            && config::full_commit(&request.head)
            && config::full_commit(&request.base),
        "invalid signing request"
    );
    let local = configuration(&args.config, &request.repo)?;
    let (trusted_git, trusted_ssh) = tools(&local)?;
    // This hidden entry point is not an escape hatch around the closed launcher:
    // both executables actually selected by PATH must be the configured trusted files.
    for (name, expected) in [("git", trusted_git), ("ssh-keygen", trusted_ssh)] {
        let selected = std::env::split_paths(&std::env::var_os("PATH").context("worker PATH")?)
            .map(|directory| directory.join(name))
            .find(|path| path.is_file())
            .context("worker tool missing")?;
        ensure!(
            std::fs::canonicalize(selected)? == expected,
            "worker must use trusted tools"
        );
    }
    ensure!(
        git::text(&request.repo, &["rev-parse", "HEAD"])? == request.head,
        "signer requires exact HEAD"
    );
    let policy = config::load(&request.repo, &request.base)?;
    let lane = policy
        .policy
        .lanes
        .get(&request.check)
        .context("unknown lane")?;
    super::workspace::verify(&request.repo, &request.head, lane, false)?;
    let nix_check = derivation(
        &request.repo,
        &request.head,
        lane,
        &policy.environment,
        &args.config,
    )?;
    if let Some((derivation, nix, _)) = &nix_check {
        let execution = request
            .inputs
            .get("nix_execution")
            .context("missing Nix execution mode")?;
        let command_mode = request
            .inputs
            .get("nix_command_mode")
            .context("missing Nix command mode")?;
        ensure!(
            (execution == "failed") == (request.exit_code != 0),
            "Nix execution claim contradicts exit status"
        );
        ensure!(
            execution != "failed" || !request.inputs.contains_key("nix_outputs_sha256"),
            "failed execution must not assert realized outputs"
        );
        ensure!(
            request.command
                == super::derivation::argv(&lane.argv[0], &derivation.path, command_mode)?,
            "command differs from derived BASE lane"
        );
        let claims = derivation.claims(nix, execution, command_mode)?;
        ensure!(
            claims
                .iter()
                .all(|(key, value)| request.inputs.get(key) == Some(value)),
            "independent derivation digest mismatch"
        );
    } else {
        ensure!(
            lane.argv == request.command,
            "command differs from BASE lane"
        );
    }
    let closures = measure_toolchain(
        &request.repo,
        &policy.environment,
        &args.config,
        &request.command,
        nix_check.is_none(),
    )?;
    ensure!(
        closures
            .iter()
            .all(|(key, value)| request.inputs.get(key) == Some(value)),
        "independent Nix closure digest mismatch"
    );
    let expected = config::expected_inputs(
        &request.repo,
        &request.head,
        &request.check,
        lane,
        &policy.environment,
        &policy.environment_bytes,
    )?;
    ensure!(
        expected
            .iter()
            .all(|(key, value)| request.inputs.get(key) == Some(value)),
        "independent input digest mismatch"
    );
    ensure!(
        request.inputs.get("workspace_clean").map(String::as_str) == Some("true")
            && request.inputs.get("untracked_files").map(String::as_str) == Some("false")
            && request
                .inputs
                .get("attempt")
                .is_some_and(|n| n.parse::<u64>().is_ok_and(|n| n > 0))
            && request
                .inputs
                .get("wrapper_sha256")
                .is_some_and(|h| h.len() == 64
                    && h.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
        "invalid wrapper measurements"
    );
    let output = STANDARD.decode(&request.output)?;
    let scratch = tempfile::tempdir()?;
    git::git(scratch.path(), &["init", "--bare", "."])?;
    let mut pack = git::command(&request.repo)
        .args(["pack-objects", "--stdout", "--revs"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    pack.stdin
        .take()
        .context("pack stdin")?
        .write_all(format!("{}\n{}\n", request.head, request.base).as_bytes())?;
    let packed = pack.wait_with_output()?;
    ensure!(packed.status.success(), "source object export failed");
    let mut import = git::command(scratch.path())
        .args(["index-pack", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    import
        .stdin
        .take()
        .context("import stdin")?
        .write_all(&packed.stdout)?;
    ensure!(import.wait()?.success(), "source object import failed");
    let tree = git::text(
        scratch.path(),
        &["rev-parse", &format!("{}^{{tree}}", request.head)],
    )?;
    let statement = Statement {
        statement_type: STATEMENT_TYPE.into(),
        predicate_type: PREDICATE_TYPE.into(),
        subject: vec![Subject {
            name: request.head.clone(),
            digest: BTreeMap::from([("gitTree".into(), tree.clone())]),
        }],
        predicate: Observation {
            schema_version: 1,
            change_id: request.head.clone(),
            signer: Some(local.signer),
            tier: TrustTier::Full,
            re_attests: None,
            producer_sha256: super::producer_digest()?.into(),
            observed_at: chrono::Utc::now().to_rfc3339(),
            fact: Fact::Tests {
                runner: "wrapper".into(),
                checks: BTreeMap::from([(
                    request.check,
                    Check {
                        command: request.command,
                        exit_code: request.exit_code,
                        output_sha256: hex::encode(Sha256::digest(output)),
                    },
                )]),
                inputs: request.inputs,
            },
        },
    };
    let record = super::sign_observation(scratch.path(), &statement, &local.ssh_key)?;
    let note_ref = format!("refs/notes/evidence/{tree}/{record}");
    git::git(scratch.path(), &["update-ref", &note_ref, &record])?;
    let bundle = scratch.path().join("record.bundle");
    git::git(
        scratch.path(),
        &[
            "bundle",
            "create",
            bundle.to_str().context("bundle path")?,
            &note_ref,
        ],
    )?;
    super::workspace::verify(&request.repo, &request.head, lane, false)?;
    println!(
        "{}",
        serde_json::to_string(&Response {
            record,
            bundle: STANDARD.encode(std::fs::read(bundle)?),
            note_ref
        })?
    );
    Ok(())
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[test]
    fn tool_file_hardening_matches_legacy_oracle() {
        let python = PathBuf::from(
            std::env::var_os("MERGEMASTER_PYTHON_ORACLE")
                .expect("MERGEMASTER_PYTHON_ORACLE must be set; run tests in nix develop"),
        )
        .join("scripts/evidence-sign");
        let cases = [
            ("x", 0o100755, 0),
            ("x", 0o100555, 0),
            ("x", 0o100755, 1000),
            ("x", 0o100775, 0),
            ("x", 0o100757, 0),
            ("x", 0o100777, 1000),
            (
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-git/bin/git",
                0o100555,
                65534,
            ),
            (
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-git/bin/git",
                0o100555,
                0,
            ),
            (
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-git/bin/git",
                0o100755,
                0,
            ),
            (
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-git/bin/git",
                0o100775,
                65534,
            ),
            (
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-git/bin/git",
                0o100444,
                0,
            ),
            ("/nix/store-lookalike/git", 0o100555, 65534),
            ("x", 0o040755, 0),
            ("x", 0o120777, 0),
            ("x", 0o100644, 0),
        ];
        let mut child = Command::new("python3")
            .args([
                "-I",
                "-B",
                "-c",
                r#"
import importlib.machinery, importlib.util, json, sys, types
loader = importlib.machinery.SourceFileLoader('oracle', sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
signer = importlib.util.module_from_spec(spec)
loader.exec_module(signer)
cases = json.load(sys.stdin)
json.dump([signer.unsafe_file(p, types.SimpleNamespace(st_mode=m, st_uid=u)) is None
           for p, m, u in cases], sys.stdout)
"#,
            ])
            .arg(python)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        serde_json::to_writer(child.stdin.take().unwrap(), &cases).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let accepted: Vec<bool> = serde_json::from_slice(&output.stdout).unwrap();
        for ((path, mode, uid), expected) in cases.into_iter().zip(accepted) {
            assert_eq!(
                trusted_file_mode(Path::new(path), mode, uid).is_ok(),
                expected,
                "{path} mode={mode:o} uid={uid}"
            );
        }
    }

    #[test]
    fn relative_argv0_resolves_via_caller_path_first() {
        let caller = tempfile::tempdir().unwrap();
        let trusted = tempfile::tempdir().unwrap();
        let name = "lane-tool";
        std::fs::write(caller.path().join(name), "caller").unwrap();
        std::fs::write(trusted.path().join(name), "trusted").unwrap();
        let config = sign_config(Some(trusted.path().to_string_lossy().into_owned()));
        let resolved = resolve_lane_executable_with_search_path(
            &config,
            name,
            Some(caller.path().as_os_str()),
        )
        .unwrap();
        assert_eq!(resolved, caller.path().join(name).canonicalize().unwrap());
    }

    #[test]
    fn relative_argv0_falls_back_to_trusted_search_path() {
        let trusted = tempfile::tempdir().unwrap();
        let name = "fallback-tool";
        std::fs::write(trusted.path().join(name), "trusted").unwrap();
        let config = sign_config(Some(trusted.path().to_string_lossy().into_owned()));
        let resolved = resolve_lane_executable_with_search_path(
            &config,
            name,
            Some(std::ffi::OsStr::new("/nonexistent-lane-dir")),
        )
        .unwrap();
        assert_eq!(resolved, trusted.path().join(name).canonicalize().unwrap());
    }

    #[test]
    fn parent_directory_escapes_are_refused() {
        let config = sign_config(None);
        let error = resolve_lane_executable(&config, "../escape").unwrap_err();
        assert!(error.to_string().contains("parent-directory escapes"));
        // `Path::components` lexically hides `..` after an absolute prefix
        // in a single literal like `/bin/../escape` (it reports RootDir +
        // ParentDir, which *is* caught) — but a traversal that survives
        // joining, e.g. `sub/../../escape` through a relative PATH entry,
        // must also be refused after the join.
        let joined = std::path::Path::new("sub").join("../../escape");
        assert!(
            joined
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        );
        assert!(
            resolve_lane_executable(&config, "/../escape")
                .unwrap_err()
                .to_string()
                .contains("parent-directory escapes")
        );
    }

    fn sign_config(path: Option<String>) -> SignConfig {
        SignConfig {
            version: 1,
            signer: "agent/fixture".into(),
            ssh_key: PathBuf::from("/tmp/signing-key"),
            path,
            toolchain: Measurements {
                runtime: PathBuf::from("/tmp/runtime"),
                dependencies: BTreeMap::new(),
            },
        }
    }
}
