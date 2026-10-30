//! Cooperative wrapper signer: account-owned configuration, independent object binding,
//! and an isolated Git repository. No consumer code executes with signing authority.
use std::{collections::BTreeMap, io::{Read, Write}, path::{Path, PathBuf}, process::{Command, Stdio}};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::gate::{config, git};
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

fn measure(path: &Path, expected: &config::Artifact) -> Result<()> {
    ensure!(path.is_absolute(), "toolchain measurement paths must be absolute");
    if let Some(hash) = expected.identity.strip_prefix("sha256:") {
        ensure!(std::fs::metadata(path)?.is_file() && hash_file(path)? == hash, "toolchain file identity mismatch");
    } else if let Some(commit) = expected.identity.strip_prefix("git:") {
        ensure!(git::text(path, &["rev-parse", "HEAD"])? == commit && clean(path)?, "toolchain repository identity mismatch or dirty dependency");
    } else { anyhow::bail!("unsupported toolchain identity"); }
    Ok(())
}

/// Measure actual provisioned runtime/dependency artifacts, not caller-supplied digests.
pub fn measure_toolchain(repo: &Path, environment: &config::Environment, path: &Path) -> Result<()> {
    let config = configuration(path, repo)?;
    let system = format!("{}-{}", std::env::consts::ARCH, if cfg!(target_os = "macos") { "darwin" } else { std::env::consts::OS });
    ensure!(environment.system == system, "runtime platform does not match committed environment");
    measure(&config.toolchain.runtime, &environment.toolchain.runtime)?;
    ensure!(config.toolchain.dependencies.len() == environment.toolchain.dependencies.len(), "dependency measurement set differs");
    for (name, artifact) in &environment.toolchain.dependencies {
        measure(config.toolchain.dependencies.get(name).context("missing dependency measurement")?, artifact)?;
    }
    Ok(())
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

