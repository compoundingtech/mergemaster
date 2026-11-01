//! Cooperative wrapper signer: account-owned configuration, independent object binding,
//! and an isolated Git repository. No consumer code executes with signing authority.
use std::{collections::BTreeMap, io::{Read, Write}, path::{Path, PathBuf}, process::{Command, Stdio}};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::gate::{config, git};
use super::{Check, Fact, Observation, Statement, Subject, TrustTier, STATEMENT_TYPE, PREDICATE_TYPE};

#[derive(Args)]
pub struct SignArgs {
    /// Explicit operator-owned configuration outside the consumer checkout.
    #[arg(long)] pub config: PathBuf,
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
pub struct Response { pub record: String, pub bundle: String, pub note_ref: String }

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
struct Measurements { runtime: PathBuf, dependencies: BTreeMap<String, PathBuf> }

fn refuse_loader() -> Result<()> {
    ensure!(!std::env::vars_os().any(|(key, _)| {
        let key = key.to_string_lossy();
        key.starts_with("LD_") || key.starts_with("DYLD_") || matches!(key.as_ref(),
            "GCONV_PATH" | "NLSPATH" | "PYTHONPATH" | "PYTHONSTARTUP" | "PYTHONHOME")
    }), "signer refuses loader/interpreter overrides; scrub them in the launcher");
    Ok(())
}

fn configuration(path: &Path, repo: &Path) -> Result<SignConfig> {
    ensure!(path.is_absolute(), "signer configuration must be absolute");
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(metadata.is_file() && !metadata.file_type().is_symlink(), "configuration must be a regular file");
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        let home = std::env::var_os("HOME").context("signer requires account HOME")?;
        ensure!(metadata.mode() & 0o077 == 0 && metadata.uid() == std::fs::metadata(home)?.uid(),
            "configuration must be account-owned and private (0600)");
    }
    ensure!(!std::fs::canonicalize(path)?.starts_with(std::fs::canonicalize(repo)?), "configuration must be outside consumer repository");
    let config: SignConfig = serde_json::from_slice(&std::fs::read(path)?)?;
    ensure!(config.version == 1 && config.signer.split_once('/').is_some_and(|(level, name)|
        matches!(level, "agent" | "host") && !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))), "invalid signer configuration");
    ensure!(config.ssh_key.is_absolute(), "signing key must be absolute");
    let key = std::fs::symlink_metadata(&config.ssh_key)?;
    ensure!(key.is_file() && !key.file_type().is_symlink(), "signing key must be a regular file");
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        ensure!(key.mode() & 0o077 == 0 && key.uid() == metadata.uid(), "signing key must be account-owned and private");
    }
    ensure!(!std::fs::canonicalize(&config.ssh_key)?.starts_with(std::fs::canonicalize(repo)?), "key must be outside consumer repository");
    Ok(config)
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn measure(path: &Path, expected: &config::Artifact, nix: Option<&Path>) -> Result<Option<BTreeMap<String, String>>> {
    ensure!(path.is_absolute(), "toolchain measurement paths must be absolute");
    if let Some(hash) = expected.identity.strip_prefix("sha256:") {
        ensure!(std::fs::metadata(path)?.is_file() && hash_file(path)? == hash, "toolchain file identity mismatch");
    } else if let Some(commit) = expected.identity.strip_prefix("git:") {
        ensure!(git::text(path, &["rev-parse", "HEAD"])? == commit && clean(path)?, "toolchain repository identity mismatch or dirty dependency");
    } else if let Some(root) = expected.identity.strip_prefix("nix:") {
        ensure!(path == Path::new(root), "configured Nix artifact differs from BASE");
        return Ok(Some(super::nix::measure(nix.context("trusted nix missing")?, root)?));
    } else { anyhow::bail!("unsupported toolchain identity"); }
    Ok(None)
}

/// Independently measure provisioned artifacts and bind execution to Nix closure bytes.
pub fn measure_toolchain(repo: &Path, environment: &config::Environment, path: &Path,
    command: &[String], bind_execution: bool) -> Result<BTreeMap<String, String>> {
    let config = configuration(path, repo)?;
    let system = format!("{}-{}", std::env::consts::ARCH, if cfg!(target_os = "macos") { "darwin" } else { std::env::consts::OS });
    ensure!(environment.system == system, "runtime platform does not match committed environment");
    ensure!(config.toolchain.dependencies.len() == environment.toolchain.dependencies.len(), "dependency measurement set differs");
    let artifacts = std::iter::once(("runtime", &environment.toolchain.runtime, Some(&config.toolchain.runtime)))
        .chain(environment.toolchain.dependencies.iter().map(|(name, artifact)|
            (name.as_str(), artifact, config.toolchain.dependencies.get(name))));
    let needs_nix = environment.toolchain.runtime.identity.starts_with("nix:")
        || environment.toolchain.dependencies.values().any(|a| a.identity.starts_with("nix:"));
    let nix = needs_nix.then(|| find_tool(&config, "nix")).transpose()?;
    let mut claims = BTreeMap::new();
    let mut executable_bound = false;
    let executable = if needs_nix && bind_execution {
        let argv0 = Path::new(command.first().context("missing lane executable")?);
        ensure!(argv0.is_absolute(), "Nix lanes require absolute argv[0] from the measured closure");
        Some(std::fs::canonicalize(argv0)?)
    } else { None };
    for (_name, artifact, provisioned) in artifacts {
        let provisioned = provisioned.context("missing dependency measurement")?;
        if let Some(closure) = measure(provisioned, artifact, nix.as_deref())? {
            claims.insert(format!("nix_closure_sha256:{}", artifact.identity), super::nix::digest(&closure)?);
            executable_bound |= executable.as_ref().is_some_and(|exe|
                closure.keys().any(|root| exe.starts_with(root)));
        }
    }
    ensure!(!needs_nix || !bind_execution || executable_bound, "lane executable is outside measured Nix closures");
    Ok(claims)
}

pub fn clean(repo: &Path) -> Result<bool> {
    // Status alone trusts index flags and stat caches; execution uses filesystem bytes.
    let entries = git::git(repo, &["ls-files", "-v", "-z"])?;
    if entries.split(|b| *b == 0).filter(|entry| !entry.is_empty())
        .any(|entry| entry[0] != b'H') { return Ok(false); }
    let tree = git::git(repo, &["ls-tree", "-r", "-z", "HEAD"])?;
    for entry in tree.split(|b| *b == 0).filter(|entry| !entry.is_empty()) {
        let (metadata, path) = entry.split_at(entry.iter().position(|b| *b == b'\t').context("invalid tree entry")?);
        let mut fields = std::str::from_utf8(metadata)?.split(' ');
        let mode = fields.next().context("missing tree mode")?;
        ensure!(fields.next() == Some("blob"), "workspace inputs must be tracked blobs");
        let object = fields.next().context("missing tree object")?;
        let path = repo.join(std::str::from_utf8(&path[1..])?);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let actual = if mode == "120000" {
            if !metadata.file_type().is_symlink() { return Ok(false); }
            hex::encode(Sha256::digest(std::fs::read_link(&path)?.as_os_str().as_encoded_bytes()))
        } else {
            if !metadata.is_file() { return Ok(false); }
            hash_file(&path)?
        };
        let committed = git::git(repo, &["cat-file", "blob", object])?;
        if actual != hex::encode(Sha256::digest(committed)) { return Ok(false); }
    }
    // Ignored/untracked files are inputs too, and staged changes must also refuse.
    Ok(git::git(repo, &["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=none"])?.is_empty())
}

fn trusted_file(path: &Path) -> Result<PathBuf> {
    let path = std::fs::canonicalize(path)?;
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(&path)?;
        ensure!(metadata.is_file() && metadata.mode() & 0o100 != 0, "trusted tool must be executable");
        if path.starts_with("/nix/store") {
            ensure!(metadata.mode() & 0o222 == 0, "mutable Nix tool");
        } else {
            ensure!(metadata.uid() == 0 && metadata.mode() & 0o022 == 0, "tool must be root-owned and closed to other writers");
        }
        let mut parent = path.parent();
        while let Some(directory) = parent {
            let metadata = std::fs::metadata(directory)?;
            if directory.starts_with("/nix/store/") {
                ensure!(metadata.mode() & 0o222 == 0, "mutable Nix tool directory");
                break;
            }
            ensure!(metadata.uid() == 0 && metadata.mode() & 0o022 == 0, "unsafe trusted tool directory");
            parent = directory.parent();
        }
    }
    Ok(path)
}

fn find_tool(config: &SignConfig, name: &str) -> Result<PathBuf> {
    let path = config.path.as_deref().unwrap_or("/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/bin:/bin");
    for directory in path.split(':') {
        ensure!(Path::new(directory).is_absolute(), "trusted PATH must contain only absolute directories");
        let candidate = Path::new(directory).join(name);
        if candidate.exists() { return trusted_file(&candidate); }
    }
    anyhow::bail!("trusted tool missing: {name}")
}

fn tools(config: &SignConfig) -> Result<(PathBuf, PathBuf)> {
    Ok((find_tool(config, "git")?, find_tool(config, "ssh-keygen")?))
}

pub(super) fn derivation(repo: &Path, head: &str, lane: &config::Lane, environment: &config::Environment, path: &Path)
    -> Result<Option<(super::derivation::Derivation, PathBuf, PathBuf)>> {
    let Some(check) = &lane.nix_check else { return Ok(None) };
    let config = configuration(path, repo)?;
    let nix = find_tool(&config, "nix")?;
    ensure!(Path::new(&lane.argv[0]) == nix, "BASE must pin the configured trusted nix executable");
    let root = nix.ancestors().find_map(|path| path.to_str().filter(|path| config::nix_store_path(path)))
        .context("Nix executable must reside in a store artifact")?;
    ensure!(std::iter::once(&environment.toolchain.runtime).chain(environment.toolchain.dependencies.values())
        .any(|artifact| artifact.identity == format!("nix:{root}")), "declare the Nix executable's store root as a nix: artifact");
    let git = find_tool(&config, "git")?;
    Ok(Some((super::derivation::Derivation::evaluate(&nix, &git, repo, head, check)?, nix, git)))
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
    #[cfg(unix)] {
        std::os::unix::fs::symlink(git, tools_dir.path().join("git"))?;
        std::os::unix::fs::symlink(ssh, tools_dir.path().join("ssh-keygen"))?;
    }
    let mut worker = Command::new(std::env::current_exe()?);
    worker.env_clear().env("PATH", tools_dir.path()).env("LC_ALL", "C")
        .env("HOME", std::env::var_os("HOME").context("HOME required")?);
    git::sanitize(&mut worker);
    let mut child = worker.arg("evidence").arg("sign-worker").arg("--config").arg(args.config)
        .stdin(Stdio::piped()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn()?;
    child.stdin.take().context("sign worker stdin")?.write_all(&bytes)?;
    ensure!(child.wait()?.success(), "isolated signer refused observation");
    Ok(())
}

pub fn run_worker(args: SignArgs) -> Result<()> {
    refuse_loader()?;
    let request: Request = serde_json::from_reader(std::io::stdin())?;
    ensure!(request.version == 1 && request.repo.is_absolute() && config::full_commit(&request.head)
        && config::full_commit(&request.base), "invalid signing request");
    let local = configuration(&args.config, &request.repo)?;
    let (trusted_git, trusted_ssh) = tools(&local)?;
    // This hidden entry point is not an escape hatch around the closed launcher:
    // both executables actually selected by PATH must be the configured trusted files.
    for (name, expected) in [("git", trusted_git), ("ssh-keygen", trusted_ssh)] {
        let selected = std::env::split_paths(&std::env::var_os("PATH").context("worker PATH")?)
            .map(|directory| directory.join(name)).find(|path| path.is_file()).context("worker tool missing")?;
        ensure!(std::fs::canonicalize(selected)? == expected, "worker must use trusted tools");
    }
    ensure!(git::text(&request.repo, &["rev-parse", "HEAD"])? == request.head && clean(&request.repo)?, "signer requires exact clean HEAD");
    let policy = config::load(&request.repo, &request.base)?;
    let lane = policy.policy.lanes.get(&request.check).context("unknown lane")?;
    let nix_check = derivation(&request.repo, &request.head, lane, &policy.environment, &args.config)?;
    if let Some((derivation, nix, _)) = &nix_check {
        let execution = request.inputs.get("nix_execution").context("missing Nix execution mode")?;
        let command_mode = request.inputs.get("nix_command_mode").context("missing Nix command mode")?;
        ensure!((execution == "failed") == (request.exit_code != 0), "Nix execution claim contradicts exit status");
        ensure!(execution != "failed" || !request.inputs.contains_key("nix_outputs_sha256"), "failed execution must not assert realized outputs");
        ensure!(request.command == super::derivation::argv(&lane.argv[0], &derivation.path, command_mode)?, "command differs from derived BASE lane");
        let claims = derivation.claims(nix, execution, command_mode)?;
        ensure!(claims.iter().all(|(key, value)| request.inputs.get(key) == Some(value)), "independent derivation digest mismatch");
    } else { ensure!(lane.argv == request.command, "command differs from BASE lane"); }
    let closures = measure_toolchain(&request.repo, &policy.environment, &args.config, &request.command, nix_check.is_none())?;
    ensure!(closures.iter().all(|(key, value)| request.inputs.get(key) == Some(value)), "independent Nix closure digest mismatch");
    let expected = config::expected_inputs(&request.repo, &request.head, &request.check, lane, &policy.environment, &policy.environment_bytes)?;
    ensure!(expected.iter().all(|(key, value)| request.inputs.get(key) == Some(value)), "independent input digest mismatch");
    ensure!(request.inputs.get("workspace_clean").map(String::as_str) == Some("true")
        && request.inputs.get("untracked_files").map(String::as_str) == Some("false")
        && request.inputs.get("attempt").is_some_and(|n| n.parse::<u64>().is_ok_and(|n| n > 0))
        && request.inputs.get("wrapper_sha256").is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())), "invalid wrapper measurements");
    let output = STANDARD.decode(&request.output)?;
    let scratch = tempfile::tempdir()?;
    git::git(scratch.path(), &["init", "--bare", "."])?;
    let mut pack = git::command(&request.repo).args(["pack-objects", "--stdout", "--revs"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    pack.stdin.take().context("pack stdin")?.write_all(format!("{}\n{}\n", request.head, request.base).as_bytes())?;
    let packed = pack.wait_with_output()?;
    ensure!(packed.status.success(), "source object export failed");
    let mut import = git::command(scratch.path()).args(["index-pack", "--stdin"])
        .stdin(Stdio::piped()).stdout(Stdio::null()).spawn()?;
    import.stdin.take().context("import stdin")?.write_all(&packed.stdout)?;
    ensure!(import.wait()?.success(), "source object import failed");
    let tree = git::text(scratch.path(), &["rev-parse", &format!("{}^{{tree}}", request.head)])?;
    let statement = Statement {
        statement_type: STATEMENT_TYPE.into(), predicate_type: PREDICATE_TYPE.into(),
        subject: vec![Subject { name: request.head.clone(), digest: BTreeMap::from([("gitTree".into(), tree.clone())]) }],
        predicate: Observation { schema_version: 1, change_id: request.head.clone(), signer: Some(local.signer),
            tier: TrustTier::Full, re_attests: None, producer_sha256: super::producer_digest()?.into(),
            observed_at: chrono::Utc::now().to_rfc3339(), fact: Fact::Tests { runner: "wrapper".into(),
                checks: BTreeMap::from([(request.check, Check {command: request.command, exit_code: request.exit_code,
                    output_sha256: hex::encode(Sha256::digest(output))})]), inputs: request.inputs } },
    };
    let record = super::sign_observation(scratch.path(), &statement, &local.ssh_key)?;
    let note_ref = format!("refs/notes/evidence/{tree}/{record}");
    git::git(scratch.path(), &["update-ref", &note_ref, &record])?;
    let bundle = scratch.path().join("record.bundle");
    git::git(scratch.path(), &["bundle", "create", bundle.to_str().context("bundle path")?, &note_ref])?;
    ensure!(git::text(&request.repo, &["rev-parse", "HEAD"])? == request.head && clean(&request.repo)?, "HEAD/workspace changed during signing");
    println!("{}", serde_json::to_string(&Response { record, bundle: STANDARD.encode(std::fs::read(bundle)?), note_ref })?);
    Ok(())
}
