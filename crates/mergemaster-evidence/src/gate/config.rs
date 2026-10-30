//! Version-one, BASE-owned policy and object-only input binding.
use std::{collections::BTreeMap, path::Path};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use super::git::{git, text};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolPin {
    version: u32,
    repository: String,
    revision: String,
    #[serde(default)]
    release: Option<ReleasePin>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasePin { version: String, sha256: String }

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub pull_request: PullRequestPolicy,
    pub protected_paths: Vec<String>,
    #[serde(default)]
    pub bootstrap_paths: Vec<String>,
    pub lanes: BTreeMap<String, Lane>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestPolicy {
    pub same_repository: bool,
    pub authors: Authors,
    pub base_relation: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authors {
    None,
    Allowlist { logins: Vec<String>, git_authors: Vec<String>, git_committers: Vec<String> },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lane {
    pub argv: Vec<String>,
    pub definition_paths: Vec<String>,
    pub trust_levels: Vec<String>,
    pub mode: String,
    pub events: Vec<String>,
    pub environment: EnvironmentDeclaration,
    pub protected_edits: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require_hosted: Vec<HostedCheck>,
    pub remediation_argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostedCheck {
    pub name: String,
    pub workflow_id: u64,
    pub workflow_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentDeclaration { pub manifest: String, pub paths: Vec<String> }

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub version: u32,
    pub system: String,
    pub toolchain: Toolchain,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    pub runtime: Artifact,
    pub dependencies: BTreeMap<String, Artifact>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact { pub name: String, pub identity: String }

#[derive(Debug)]
pub struct Config {
    pub policy: Policy,
    pub environment: Environment,
    pub environment_bytes: Vec<u8>,
    pub keys: Vec<u8>,
}

pub fn full_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

fn nonempty(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

/// Repository-relative literal paths, never pathspec patterns or filesystem paths.
pub fn validate_path(path: &str) -> Result<()> {
    let path = path.strip_suffix('/').unwrap_or(path);
    ensure!(!path.is_empty() && !path.starts_with('/') && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path.split('/').all(|part| !part.is_empty() && part != "." && part != ".." && part != ".git"),
        "invalid repository path");
    Ok(())
}

fn blob(repo: &Path, commit: &str, path: &str) -> Result<Vec<u8>> {
    validate_path(path)?;
    let object = format!("{commit}:{path}");
    ensure!(text(repo, &["cat-file", "-t", &object])?.trim() == "blob", "expected committed regular file");
    // A blob may still be a symbolic link. Inspect its tree mode separately.
    let entries = entries(repo, commit, &[path.to_owned()])?;
    ensure!(entries.len() == 1 && entries[0].0 == path && entries[0].1 != "120000", "expected regular file");
    git(repo, &["cat-file", "blob", &object])
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], name: &str) -> Result<T> {
    serde_json::from_slice(bytes).with_context(|| format!("invalid {name}"))
}

pub fn load(repo: &Path, base: &str) -> Result<Config> {
    ensure!(full_commit(base), "BASE must be a full commit ID");
    ensure!(text(repo, &["cat-file", "-t", base])?.trim() == "commit", "BASE is not a commit");
    let pin: ToolPin = decode(&blob(repo, base, ".mergemaster/tool-pin.json")?, "tool pin")?;
    ensure!(pin.version == 1 && pin.repository == "compoundingtech/mergemaster" && full_commit(&pin.revision), "unsupported tool pin");
    if let Some(release) = &pin.release {
        let version = release.version.strip_prefix('v').context("release version must start with v")?;
        ensure!(version.split('.').count() == 3
            && version.split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            && release.sha256.len() == 64
            && release.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid release pin");
    }
    let mut policy: Policy = decode(&blob(repo, base, ".mergemaster/lanes.json")?, "lanes policy")?;
    let environment_bytes = blob(repo, base, ".mergemaster/environment.json")?;
    let environment: Environment = decode(&environment_bytes, "environment")?;
    validate_environment(&environment)?;
    ensure!(policy.version == 1 && policy.pull_request.same_repository
        && policy.pull_request.base_relation == "ancestor" && !policy.lanes.is_empty(), "unsupported pull request policy");
    if let Authors::Allowlist { logins, git_authors, git_committers } = &policy.pull_request.authors {
        ensure!(!logins.is_empty() && !git_authors.is_empty() && !git_committers.is_empty()
            && logins.iter().all(|login| nonempty(login) && login.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
            && git_authors.iter().chain(git_committers).all(|identity| nonempty(identity) && identity.ends_with('>') && identity.contains(" <")),
            "invalid author allowlist");
    }
    for path in policy.protected_paths.iter().chain(&policy.bootstrap_paths) { validate_path(path)?; }
    for path in &policy.bootstrap_paths { entries(repo, base, std::slice::from_ref(path))?; }
    for required in [".mergemaster/", ".github/workflows/", ".github/actions/"] {
        if !policy.protected_paths.iter().any(|path| path == required) { policy.protected_paths.push(required.to_owned()); }
    }
    for path in &policy.bootstrap_paths {
        if !policy.protected_paths.contains(path) { policy.protected_paths.push(path.clone()); }
    }
    for (check, lane) in &policy.lanes {
        ensure!(nonempty(check) && !lane.argv.is_empty() && lane.argv.iter().all(|arg| !arg.contains('\0'))
            && nonempty(&lane.argv[0]) && !lane.remediation_argv.is_empty()
            && lane.remediation_argv.iter().all(|arg| !arg.contains('\0')), "invalid lane argv");
        ensure!(matches!(lane.mode.as_str(), "required_evidence" | "optional_fallback")
            && matches!(lane.protected_edits.as_str(), "reject" | "human_approval") && lane.events == ["pull_request"]
            && !lane.trust_levels.is_empty() && lane.trust_levels.iter().all(|level| matches!(level.as_str(), "agent" | "host"))
            && lane.max_age_seconds != Some(0), "unsupported lane policy");
        if lane.protected_edits == "human_approval" {
            ensure!(!lane.approvers.is_empty() && lane.approvers.iter().all(|login|
                nonempty(login) && login.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
                && !lane.require_hosted.is_empty(), "human approval requires approvers and hosted checks");
            let mut names = std::collections::BTreeSet::new();
            for hosted in &lane.require_hosted {
                validate_path(&hosted.workflow_path)?;
                ensure!(nonempty(&hosted.name) && names.insert(&hosted.name) && hosted.workflow_id > 0
                    && hosted.workflow_path.starts_with(".github/workflows/")
                    && (hosted.workflow_path.ends_with(".yml") || hosted.workflow_path.ends_with(".yaml")),
                    "invalid required hosted check");
                blob(repo, base, &hosted.workflow_path)?;
            }
        } else {
            ensure!(lane.approvers.is_empty() && lane.require_hosted.is_empty(),
                "approval configuration requires human_approval policy");
        }
        ensure!(lane.environment.manifest == ".mergemaster/environment.json", "unsupported environment manifest");
        entries(repo, base, &lane.definition_paths)?;
        entries(repo, base, &lane.environment.paths)?;
    }
    let keys = blob(repo, base, ".mergemaster/evidence-keys")?;
    validate_keys(&keys)?;
    Ok(Config { policy, environment, environment_bytes, keys })
}

fn validate_keys(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("evidence keys are not UTF-8")?;
    let mut count = 0;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let mut fields = line.split_whitespace();
        let principals = fields.next().context("missing signer principal")?;
        ensure!(principals.split(',').all(|principal| {
            principal.split_once('/').is_some_and(|(level, name)| {
                matches!(level, "agent" | "host") && !name.is_empty()
                    && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
            })
        }), "unsupported signer principal");
        let mut kind = fields.next().context("missing signer key")?;
        if kind == "namespaces=\"git\"" { kind = fields.next().context("missing signer key")?; }
        ensure!(kind == "ssh-ed25519", "unsupported signer key type or options");
        let encoded = fields.next().context("missing signer key data")?;
        let decoded = STANDARD.decode(encoded).context("invalid signer key encoding")?;
        // SSH wire strings: uint32(11), \"ssh-ed25519\", uint32(32), public key.
        ensure!(decoded.len() == 51 && decoded[..4] == [0, 0, 0, 11]
            && &decoded[4..15] == b"ssh-ed25519" && decoded[15..19] == [0, 0, 0, 32],
            "invalid Ed25519 public key");
        count += 1;
    }
    ensure!(count > 0, "evidence keys contain no supported signers");
    Ok(())
}

fn validate_environment(environment: &Environment) -> Result<()> {
    ensure!(environment.version == 1 && matches!(environment.system.as_str(),
        "x86_64-linux" | "aarch64-linux" | "x86_64-darwin" | "aarch64-darwin"), "unsupported environment");
    for (name, artifact) in std::iter::once(("runtime", &environment.toolchain.runtime))
        .chain(environment.toolchain.dependencies.iter().map(|(name, artifact)| (name.as_str(), artifact))) {
        ensure!(nonempty(name) && nonempty(&artifact.name), "invalid toolchain artifact");
        let valid = artifact.identity.strip_prefix("sha256:").is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()))
            || artifact.identity.strip_prefix("git:").is_some_and(full_commit);
        ensure!(valid, "toolchain artifacts require immutable sha256 or git identities");
    }
    Ok(())
}

// Sorted by raw UTF-8 path bytes (the accepted path encoding); no checkout,
// symlink following, submodule traversal, filters, shell or glob expansion.
fn entries(repo: &Path, commit: &str, paths: &[String]) -> Result<Vec<(String, String, String)>> {
    ensure!(!paths.is_empty(), "input paths must not be empty");
    let mut files = BTreeMap::new();
    for path in paths {
        validate_path(path)?;
        let path = path.trim_end_matches('/');
        let literal = format!(":(literal){path}");
        let output = git(repo, &["ls-tree", "-r", "-z", "--full-tree", commit, "--", &literal])?;
        let mut found = false;
        for entry in output.split(|byte| *byte == 0).filter(|entry| !entry.is_empty()) {
            let entry = std::str::from_utf8(entry).context("input path is not UTF-8")?;
            let (metadata, name) = entry.split_once('\t').context("invalid Git tree entry")?;
            let parts: Vec<_> = metadata.split(' ').collect();
            ensure!(parts.len() == 3 && parts[1] == "blob" && matches!(parts[0], "100644" | "100755"), "unsupported input type (symlink or submodule)");
            ensure!(name == path || name.strip_prefix(path).is_some_and(|suffix| suffix.starts_with('/')), "input path escaped declaration");
            files.insert(name.to_owned(), (parts[0].to_owned(), parts[2].to_owned()));
            found = true;
        }
        ensure!(found, "missing committed input path: {path}");
    }
    Ok(files.into_iter().map(|(path, (mode, id))| (path, mode, id)).collect())
}

fn manifest(repo: &Path, head: &str, paths: &[String]) -> Result<Vec<(String, String, String)>> {
    entries(repo, head, paths)?.into_iter().map(|(path, mode, id)| {
        let bytes = git(repo, &["cat-file", "blob", &id])?;
        Ok((path, mode, hex::encode(Sha256::digest(bytes))))
    }).collect()
}

fn hash(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

/// Shared signer/verifier contract. Hashes are SHA-256 of compact JSON tuples:
/// environment [version, BASE bytes, declared paths, sorted [path,mode,sha256]],
/// toolchain [version, resolved toolchain], lane [version,check,lane,files].
/// Array ordering and struct field ordering are normative; dependency maps and
/// expanded paths use byte-sorted keys. No runtime or candidate code is executed.
pub fn expected_inputs(repo: &Path, head: &str, check: &str, lane: &Lane,
    environment: &Environment, environment_bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    ensure!(full_commit(head), "HEAD must be a full commit ID");
    ensure!(text(repo, &["cat-file", "-t", head])?.trim() == "commit", "HEAD is not a commit");
    validate_environment(environment)?;
    let declared: Environment = decode(environment_bytes, "environment")?;
    ensure!(serde_json::to_vec(&declared)? == serde_json::to_vec(environment)?, "environment bytes differ from declaration");
    let environment_files = manifest(repo, head, &lane.environment.paths)?;
    let definition_files = manifest(repo, head, &lane.definition_paths)?;
    let environment_sha = hash(&(1, environment_bytes, &lane.environment.paths, environment_files))?;
    let toolchain_sha = hash(&(1, &environment.toolchain))?;
    let lane_sha = hash(&(1, check, lane, definition_files))?;
    Ok(BTreeMap::from([
        ("environment_sha256".to_owned(), environment_sha),
        ("toolchain_sha256".to_owned(), toolchain_sha),
        ("lane_definition_sha256".to_owned(), lane_sha),
        ("system".to_owned(), environment.system.clone()),
    ]))
}
