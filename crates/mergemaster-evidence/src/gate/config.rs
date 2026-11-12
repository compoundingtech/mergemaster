//! Version-one, BASE-owned policy and object-only input binding.
use super::git::{blob_digests, git, text, validate_blobs};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

/// The signing or verifying host's platform, matching the keys of
/// `Environment::systems`.
pub fn current_system() -> String {
    format!(
        "{}-{}",
        std::env::consts::ARCH,
        if cfg!(target_os = "macos") {
            "darwin"
        } else {
            std::env::consts::OS
        }
    )
}

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
struct ReleasePin {
    version: String,
    sha256: String,
}

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
    Allowlist {
        logins: Vec<String>,
        git_authors: Vec<String>,
        git_committers: Vec<String>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lane {
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub direct_exec: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nix_check: Option<NixCheck>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inputs: BTreeMap<String, Artifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scratch: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NixCheck {
    pub attribute: String,
    #[serde(default = "fresh")]
    pub required: String,
}
fn fresh() -> String {
    "fresh".into()
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
pub struct EnvironmentDeclaration {
    pub manifest: String,
    pub paths: Vec<String>,
}

/// Committed environments are keyed by host platform (`systems`). The
/// pre-multisystem shape (`system` + `toolchain`) is accepted on read and
/// folds into a single-entry systems map, so existing consumer checkouts
/// keep verifying without a flag day. Serialization always emits `systems`.
#[derive(Debug, Serialize)]
pub struct Environment {
    pub version: u32,
    pub systems: BTreeMap<String, Toolchain>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentCurrent {
    version: u32,
    systems: BTreeMap<String, Toolchain>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentLegacy {
    version: u32,
    system: String,
    toolchain: Toolchain,
}

impl<'de> Deserialize<'de> for Environment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = serde_json::Value::deserialize(deserializer)?;
        if raw.get("systems").is_some() {
            let current: EnvironmentCurrent =
                serde_json::from_value(raw).map_err(serde::de::Error::custom)?;
            Ok(Self {
                version: current.version,
                systems: current.systems,
            })
        } else {
            let legacy: EnvironmentLegacy =
                serde_json::from_value(raw).map_err(serde::de::Error::custom)?;
            Ok(Self {
                version: legacy.version,
                systems: BTreeMap::from([(legacy.system, legacy.toolchain)]),
            })
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    pub runtime: Artifact,
    pub dependencies: BTreeMap<String, Artifact>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub identity: String,
}

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

/// A literal top-level store output, never a flake expression or subpath.
pub fn nix_store_path(path: &str) -> bool {
    path.strip_prefix("/nix/store/").is_some_and(|name| {
        name.len() > 33
            && name.as_bytes()[32] == b'-'
            && name.as_bytes()[..32]
                .iter()
                .all(|c| b"0123456789abcdfghijklmnpqrsvwxyz".contains(c))
            && name[33..]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"+-._?=".contains(&c))
    })
}

fn nonempty(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

/// Repository-relative literal paths, never pathspec patterns or filesystem paths.
pub fn validate_path(path: &str) -> Result<()> {
    let path = path.strip_suffix('/').unwrap_or(path);
    ensure!(
        !path.is_empty()
            && !path.starts_with('/')
            && !path.contains('\\')
            && !path.chars().any(char::is_control)
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".." && part != ".git"),
        "invalid repository path"
    );
    Ok(())
}

/// Explicit direct execution is limited to a single tracked Bun script.
pub fn validate_direct_exec(repo: &Path, commit: &str, lane: &Lane) -> Result<()> {
    if !lane.direct_exec {
        return Ok(());
    }
    ensure!(
        lane.nix_check.is_none() && lane.argv.len() == 2 && lane.argv[0] == "bun",
        "direct_exec requires exactly bun and a tracked relative script"
    );
    let script = &lane.argv[1];
    validate_path(script)?;
    ensure!(
        !script.starts_with('-')
            && [".ts", ".tsx", ".js", ".mjs", ".cjs"]
                .iter()
                .any(|suffix| script.ends_with(suffix)),
        "direct_exec requires a tracked relative script"
    );
    blob(repo, commit, script)?;
    Ok(())
}

fn blob(repo: &Path, commit: &str, path: &str) -> Result<Vec<u8>> {
    validate_path(path)?;
    let object = format!("{commit}:{path}");
    ensure!(
        text(repo, &["cat-file", "-t", &object])?.trim() == "blob",
        "expected committed regular file"
    );
    // A blob may still be a symbolic link. Inspect its tree mode separately.
    let literal = format!(":(literal){path}");
    let tree = parse_tree(&git(
        repo,
        &["ls-tree", "-z", "--full-tree", commit, "--", &literal],
    )?)?;
    let entries = entries_from(&tree, &[path.to_owned()])?;
    ensure!(
        entries.len() == 1 && entries[0].0 == path && entries[0].1 != "120000",
        "expected regular file"
    );
    git(repo, &["cat-file", "blob", &object])
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], name: &str) -> Result<T> {
    serde_json::from_slice(bytes).with_context(|| format!("invalid {name}"))
}

/// A required BASE declaration is absent, not malformed or unreadable.
#[derive(Debug)]
pub struct MissingConfig(pub &'static str);

impl std::fmt::Display for MissingConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BASE configuration missing: {}", self.0)
    }
}

impl std::error::Error for MissingConfig {}

#[cfg(test)]
mod missing_config_tests {
    #[test]
    fn missing_config_keeps_a_distinct_error_type_and_path() {
        let error = anyhow::Error::new(super::MissingConfig(".mergemaster/lanes.json"));
        assert!(error.is::<super::MissingConfig>());
        assert_eq!(
            error.to_string(),
            "BASE configuration missing: .mergemaster/lanes.json"
        );
        assert!(!anyhow::anyhow!("invalid lanes policy").is::<super::MissingConfig>());
    }
}

#[cfg(test)]
mod environment_compat_tests {
    use super::{Environment, current_system};
    use std::collections::BTreeMap;

    fn toolchain(identity: &str) -> super::Toolchain {
        super::Toolchain {
            runtime: super::Artifact {
                name: "runtime".into(),
                identity: identity.into(),
            },
            dependencies: BTreeMap::new(),
        }
    }

    #[test]
    fn legacy_shape_folds_into_single_entry_systems_map() {
        let system = current_system();
        let raw = serde_json::json!({
            "version": 1,
            "system": system,
            "toolchain": {
                "runtime": {"name": "runtime", "identity": "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
                "dependencies": {}
            }
        });
        let environment: Environment = serde_json::from_value(raw).unwrap();
        assert_eq!(environment.version, 1);
        assert_eq!(environment.systems.len(), 1);
        assert!(environment.systems.contains_key(&system));
        super::validate_environment(&environment).unwrap();
        let reserialized = serde_json::to_value(&environment).unwrap();
        assert!(reserialized.get("systems").is_some());
        assert!(reserialized.get("system").is_none());
        assert!(reserialized.get("toolchain").is_none());
    }

    #[test]
    fn mixed_old_and_new_fields_are_rejected() {
        let system = current_system();
        let bad = serde_json::json!({
            "version": 1,
            "systems": {},
            "system": system,
            "toolchain": {
                "runtime": {"name": "runtime", "identity": "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
                "dependencies": {}
            }
        });
        assert!(serde_json::from_value::<Environment>(bad).is_err());
    }

    #[test]
    fn system_mismatch_refuses_lookup() {
        let other = if current_system().starts_with("x86_64") {
            "aarch64-linux"
        } else {
            "x86_64-linux"
        };
        let environment = Environment {
            version: 1,
            systems: BTreeMap::from([(
                other.to_owned(),
                toolchain(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                ),
            )]),
        };
        assert!(!environment.systems.contains_key(&current_system()));
    }
}

fn config_blob(repo: &Path, base: &str, path: &'static str) -> Result<Vec<u8>> {
    let literal = format!(":(literal){path}");
    // A successful empty tree lookup is absence. Git failures, wrong object
    // types, symlinks and malformed contents retain their original errors.
    if git(
        repo,
        &["ls-tree", "-z", "--full-tree", base, "--", &literal],
    )?
    .is_empty()
    {
        return Err(MissingConfig(path).into());
    }
    blob(repo, base, path)
}

pub fn load(repo: &Path, base: &str) -> Result<Config> {
    ensure!(full_commit(base), "BASE must be a full commit ID");
    ensure!(
        text(repo, &["cat-file", "-t", base])?.trim() == "commit",
        "BASE is not a commit"
    );
    let pin: ToolPin = decode(
        &config_blob(repo, base, ".mergemaster/tool-pin.json")?,
        "tool pin",
    )?;
    ensure!(
        pin.version == 1
            && pin.repository == "compoundingtech/mergemaster"
            && full_commit(&pin.revision),
        "unsupported tool pin"
    );
    if let Some(release) = &pin.release {
        let version = release
            .version
            .strip_prefix('v')
            .context("release version must start with v")?;
        ensure!(
            version.split('.').count() == 3
                && version
                    .split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                && release.sha256.len() == 64
                && release
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid release pin"
        );
    }
    let mut policy: Policy = decode(
        &config_blob(repo, base, ".mergemaster/lanes.json")?,
        "lanes policy",
    )?;
    let environment_bytes = config_blob(repo, base, ".mergemaster/environment.json")?;
    let environment: Environment = decode(&environment_bytes, "environment")?;
    validate_environment(&environment)?;
    let keys = config_blob(repo, base, ".mergemaster/evidence-keys")?;
    validate_keys(&keys)?;
    ensure!(
        policy.version == 1
            && policy.pull_request.same_repository
            && policy.pull_request.base_relation == "ancestor"
            && !policy.lanes.is_empty(),
        "unsupported pull request policy"
    );
    if let Authors::Allowlist {
        logins,
        git_authors,
        git_committers,
    } = &policy.pull_request.authors
    {
        ensure!(
            !logins.is_empty()
                && !git_authors.is_empty()
                && !git_committers.is_empty()
                && logins.iter().all(|login| nonempty(login)
                    && login
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-'))
                && git_authors
                    .iter()
                    .chain(git_committers)
                    .all(|identity| nonempty(identity)
                        && identity.ends_with('>')
                        && identity.contains(" <")),
            "invalid author allowlist"
        );
    }
    for path in policy.protected_paths.iter().chain(&policy.bootstrap_paths) {
        validate_path(path)?;
    }
    let tree = read_tree(repo, base)?;
    for path in &policy.bootstrap_paths {
        entries_from(&tree, std::slice::from_ref(path))?;
    }
    for required in [".mergemaster/", ".github/workflows/", ".github/actions/"] {
        if !policy.protected_paths.iter().any(|path| path == required) {
            policy.protected_paths.push(required.to_owned());
        }
    }
    for path in &policy.bootstrap_paths {
        if !policy.protected_paths.contains(path) {
            policy.protected_paths.push(path.clone());
        }
    }
    for (check, lane) in &policy.lanes {
        ensure!(
            nonempty(check)
                && !lane.argv.is_empty()
                && lane.argv.iter().all(|arg| !arg.contains('\0'))
                && nonempty(&lane.argv[0])
                && !lane.remediation_argv.is_empty()
                && lane.remediation_argv.iter().all(|arg| !arg.contains('\0')),
            "invalid lane argv"
        );
        validate_direct_exec(repo, base, lane)?;
        ensure!(
            !lane.direct_exec
                || environment
                    .systems
                    .values()
                    .all(|toolchain| toolchain.runtime.identity.starts_with("nix:")),
            "direct_exec requires a declared Nix runtime"
        );
        ensure!(
            matches!(
                lane.mode.as_str(),
                "required_evidence" | "optional_fallback"
            ) && matches!(lane.protected_edits.as_str(), "reject" | "human_approval")
                && !lane.events.is_empty()
                && lane.events.iter().all(|event| matches!(
                    event.as_str(),
                    "pull_request" | "push" | "merge_group" | "queue"
                ))
                && lane
                    .events
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == lane.events.len()
                && !lane.trust_levels.is_empty()
                && lane
                    .trust_levels
                    .iter()
                    .all(|level| matches!(level.as_str(), "agent" | "host"))
                && lane.max_age_seconds != Some(0),
            "unsupported lane policy"
        );
        if lane.protected_edits == "human_approval" {
            ensure!(
                !lane.approvers.is_empty()
                    && lane.approvers.iter().all(|login| nonempty(login)
                        && login
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
                    && !lane.require_hosted.is_empty(),
                "human approval requires approvers and hosted checks"
            );
            let mut names = std::collections::BTreeSet::new();
            for hosted in &lane.require_hosted {
                validate_path(&hosted.workflow_path)?;
                ensure!(
                    nonempty(&hosted.name)
                        && names.insert(&hosted.name)
                        && hosted.workflow_id > 0
                        && hosted.workflow_path.starts_with(".github/workflows/")
                        && (hosted.workflow_path.ends_with(".yml")
                            || hosted.workflow_path.ends_with(".yaml")),
                    "invalid required hosted check"
                );
                blob(repo, base, &hosted.workflow_path)?;
            }
        } else {
            ensure!(
                lane.approvers.is_empty() && lane.require_hosted.is_empty(),
                "approval configuration requires human_approval policy"
            );
        }
        if let Some(check) = &lane.nix_check {
            let parts: Vec<_> = check.attribute.split('.').collect();
            ensure!(
                parts.len() == 3
                    && parts[0] == "checks"
                    && parts.iter().all(|part| !part.is_empty()
                        && part
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)))
                    && matches!(check.required.as_str(), "fresh" | "any"),
                "invalid Nix check declaration"
            );
            ensure!(
                lane.argv.len() == 1 && Path::new(&lane.argv[0]).is_absolute(),
                "Nix check argv declares the absolute trusted nix executable only"
            );
        }
        ensure!(
            lane.environment.manifest == ".mergemaster/environment.json",
            "unsupported environment manifest"
        );
        entries_from(&tree, &lane.definition_paths)?;
        entries_from(&tree, &lane.environment.paths)?;
    }
    Ok(Config {
        policy,
        environment,
        environment_bytes,
        keys,
    })
}

fn validate_keys(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("evidence keys are not UTF-8")?;
    let mut count = 0;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let mut fields = line.split_whitespace();
        let principals = fields.next().context("missing signer principal")?;
        ensure!(
            principals.split(',').all(|principal| {
                principal.split_once('/').is_some_and(|(level, name)| {
                    matches!(level, "agent" | "host")
                        && !name.is_empty()
                        && name
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
                })
            }),
            "unsupported signer principal"
        );
        let mut kind = fields.next().context("missing signer key")?;
        if kind == "namespaces=\"git\"" {
            kind = fields.next().context("missing signer key")?;
        }
        ensure!(
            kind == "ssh-ed25519",
            "unsupported signer key type or options"
        );
        let encoded = fields.next().context("missing signer key data")?;
        let decoded = STANDARD
            .decode(encoded)
            .context("invalid signer key encoding")?;
        // SSH wire strings: uint32(11), \"ssh-ed25519\", uint32(32), public key.
        ensure!(
            decoded.len() == 51
                && decoded[..4] == [0, 0, 0, 11]
                && &decoded[4..15] == b"ssh-ed25519"
                && decoded[15..19] == [0, 0, 0, 32],
            "invalid Ed25519 public key"
        );
        count += 1;
    }
    ensure!(count > 0, "evidence keys contain no supported signers");
    Ok(())
}

fn validate_environment(environment: &Environment) -> Result<()> {
    ensure!(
        environment.version == 1
            && !environment.systems.is_empty()
            && environment.systems.keys().all(|system| matches!(
                system.as_str(),
                "x86_64-linux" | "aarch64-linux" | "x86_64-darwin" | "aarch64-darwin"
            )),
        "unsupported environment"
    );
    for toolchain in environment.systems.values() {
        for (name, artifact) in std::iter::once(("runtime", &toolchain.runtime)).chain(
            toolchain
                .dependencies
                .iter()
                .map(|(name, artifact)| (name.as_str(), artifact)),
        ) {
            ensure!(
                nonempty(name) && nonempty(&artifact.name),
                "invalid toolchain artifact"
            );
            let valid = artifact
                .identity
                .strip_prefix("sha256:")
                .is_some_and(|hash| {
                    hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit())
                })
                || artifact
                    .identity
                    .strip_prefix("git:")
                    .is_some_and(full_commit)
                || artifact
                    .identity
                    .strip_prefix("nix:")
                    .is_some_and(nix_store_path);
            ensure!(
                valid,
                "toolchain artifacts require immutable sha256, git or nix identities"
            );
        }
    }
    Ok(())
}

// Sorted by raw UTF-8 path bytes (the accepted path encoding); no checkout,
// symlink following, submodule traversal, filters, shell or glob expansion.
type Tree = BTreeMap<Vec<u8>, Vec<u8>>;

fn parse_tree(output: &[u8]) -> Result<Tree> {
    output
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let tab = entry
                .iter()
                .position(|byte| *byte == b'\t')
                .context("invalid Git tree entry")?;
            Ok((entry[tab + 1..].to_vec(), entry[..tab].to_vec()))
        })
        .collect()
}

fn read_tree(repo: &Path, commit: &str) -> Result<Tree> {
    parse_tree(&git(repo, &["ls-tree", "-r", "-z", "--full-tree", commit])?)
}

fn entries_from(tree: &Tree, paths: &[String]) -> Result<Vec<(String, String, String)>> {
    ensure!(!paths.is_empty(), "input paths must not be empty");
    let mut files = BTreeMap::new();
    for path in paths {
        validate_path(path)?;
        let path = path.trim_end_matches('/');
        let mut found = false;
        for (name, metadata) in tree.range(path.as_bytes().to_vec()..) {
            if !name.starts_with(path.as_bytes()) {
                break;
            }
            if name != path.as_bytes() && name.get(path.len()) != Some(&b'/') {
                continue;
            }
            let name = std::str::from_utf8(name).context("input path is not UTF-8")?;
            let metadata = std::str::from_utf8(metadata).context("invalid Git tree entry")?;
            let parts: Vec<_> = metadata.split(' ').collect();
            ensure!(
                parts.len() == 3 && parts[1] == "blob" && matches!(parts[0], "100644" | "100755"),
                "unsupported input type (symlink or submodule)"
            );
            ensure!(
                name == path
                    || name
                        .strip_prefix(path)
                        .is_some_and(|suffix| suffix.starts_with('/')),
                "input path escaped declaration"
            );
            files.insert(name.to_owned(), (parts[0].to_owned(), parts[2].to_owned()));
            found = true;
        }
        ensure!(found, "missing committed input path: {path}");
    }
    Ok(files
        .into_iter()
        .map(|(path, (mode, id))| (path, mode, id))
        .collect())
}

#[cfg(test)]
mod tree_tests {
    use super::{entries_from, parse_tree};

    #[test]
    fn expansion_preserves_boundaries_modes_and_selected_path_encoding() {
        let tree = parse_tree(
            b"100644 blob a\ttools/a\0\
            100755 blob b\ttools/b\0\
            120000 blob c\ttools-link\0\
            100644 blob d\tother/\xff\0",
        )
        .unwrap();
        let files = entries_from(&tree, &["tools/".into(), "tools/a".into()]).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[1], ("tools/b".into(), "100755".into(), "b".into()));
        assert!(entries_from(&tree, &["tool".into()]).is_err());
        assert!(entries_from(&tree, &["tools-link".into()]).is_err());
        assert!(
            entries_from(&tree, &["other".into()])
                .unwrap_err()
                .to_string()
                .contains("UTF-8")
        );
    }
}

fn manifest(
    files: Vec<(String, String, String)>,
    digests: &BTreeMap<String, String>,
) -> Vec<(String, String, String)> {
    files
        .into_iter()
        .map(|(path, mode, id)| (path, mode, digests[&id].clone()))
        .collect()
}

fn hash(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

/// Keep candidate declaration/type checks fail-closed even without a record.
pub fn validate_candidate(repo: &Path, head: &str, lane: &Lane) -> Result<()> {
    let tree = read_tree(repo, head)?;
    let environment_files = entries_from(&tree, &lane.environment.paths)?;
    let definition_files = entries_from(&tree, &lane.definition_paths)?;
    let ids = environment_files
        .iter()
        .chain(&definition_files)
        .map(|(_, _, id)| id.as_str())
        .collect();
    validate_blobs(repo, &ids)?;
    if !lane.inputs.is_empty() || !lane.scratch.is_empty() {
        crate::evidence::workspace::validate(repo, head, lane)?;
    }
    Ok(())
}

/// Shared signer/verifier contract. Hashes are SHA-256 of compact JSON tuples:
/// environment [version, BASE bytes, declared paths, sorted [path,mode,sha256]],
/// toolchain [version, resolved toolchain], lane [version,check,lane,files].
/// Array ordering and struct field ordering are normative; dependency maps and
/// expanded paths use byte-sorted keys. No runtime or candidate code is executed.
pub fn expected_inputs(
    repo: &Path,
    head: &str,
    check: &str,
    lane: &Lane,
    environment: &Environment,
    environment_bytes: &[u8],
) -> Result<BTreeMap<String, String>> {
    ensure!(full_commit(head), "HEAD must be a full commit ID");
    ensure!(
        text(repo, &["cat-file", "-t", head])?.trim() == "commit",
        "HEAD is not a commit"
    );
    validate_environment(environment)?;
    validate_direct_exec(repo, head, lane)?;
    let declared: Environment = decode(environment_bytes, "environment")?;
    ensure!(
        serde_json::to_vec(&declared)? == serde_json::to_vec(environment)?,
        "environment bytes differ from declaration"
    );
    let tree = read_tree(repo, head)?;
    let environment_files = entries_from(&tree, &lane.environment.paths)?;
    let definition_files = entries_from(&tree, &lane.definition_paths)?;
    let ids = environment_files
        .iter()
        .chain(&definition_files)
        .map(|(_, _, id)| id.as_str())
        .collect();
    let digests = blob_digests(repo, &ids)?;
    let environment_files = manifest(environment_files, &digests);
    let definition_files = manifest(definition_files, &digests);
    let environment_sha = hash(&(
        1,
        environment_bytes,
        &lane.environment.paths,
        environment_files,
    ))?;
    let toolchain_sha = hash(&(1, &environment.systems))?;
    let lane_sha = hash(&(1, check, lane, definition_files))?;
    let mut inputs = BTreeMap::from([
        ("environment_sha256".to_owned(), environment_sha),
        ("toolchain_sha256".to_owned(), toolchain_sha),
        ("lane_definition_sha256".to_owned(), lane_sha),
        ("system".to_owned(), current_system()),
    ]);
    if !lane.inputs.is_empty() || !lane.scratch.is_empty() {
        crate::evidence::workspace::validate(repo, head, lane)?;
        inputs.insert("workspace_binding".into(), "v2".into());
        inputs.insert(
            "workspace_declaration_sha256".into(),
            hash(&(2, &lane.inputs, &lane.scratch))?,
        );
    }
    Ok(inputs)
}
