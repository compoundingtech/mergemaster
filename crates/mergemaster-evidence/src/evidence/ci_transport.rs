//! Selector-only CI entry point for a protected profile. Configuration is in its private HOME.
//! The profile's PATH supplies installed Git, gh and timeout; never checkout tools.
use super::{observers::*, *};
use base64::Engine as _;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    repository: String,
    scratch_repo: PathBuf,
    recipe_sha256: String,
    accepted_base: String,
    workflow_sha256: String,
    required_checks: BTreeSet<String>,
    /// Configured by the profile operator. The seat's CLI selectors cannot change it.
    tier: TrustTier,
    signer: Option<String>,
    ssh_key: Option<PathBuf>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

struct Github {
    repository: String,
}

impl Github {
    fn command(&self, suffix: &str) -> Command {
        let mut command = Command::new("timeout");
        command.args([
            "--kill-after=2s",
            "30s",
            "gh",
            "api",
            "--hostname",
            "github.com",
            &format!("repos/{}/{suffix}", self.repository),
        ]);
        command
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .env_remove("GH_DEBUG");
        command
    }

    fn json(&self, suffix: &str) -> Result<Value> {
        let output = self.command(suffix).output().context("contact GitHub")?;
        ensure!(output.status.success(), "GitHub observation unavailable");
        ensure!(
            output.stdout.len() <= 4 * 1024 * 1024,
            "GitHub metadata size bound"
        );
        serde_json::from_slice(&output.stdout).context("GitHub observation JSON")
    }

    fn jobs(&self, run: u64, attempt: u64) -> Result<Vec<Value>> {
        let mut jobs = Vec::new();
        for page in 1..=10 {
            let response = self.json(&format!(
                "actions/runs/{run}/attempts/{attempt}/jobs?per_page=100&page={page}"
            ))?;
            let batch = response["jobs"].as_array().context("GitHub jobs list")?;
            jobs.extend(batch.iter().cloned());
            if batch.len() < 100 {
                return Ok(jobs);
            }
        }
        bail!("CI jobs exceed observer pagination bound")
    }
}

// Authenticate the complete ZIP before parsing, then write only fixed names into a new,
// private directory. Validate every member before creating any extracted file.
fn extract_source(archive: &Path, destination: &Path, size: u64, expected: &str) -> Result<()> {
    use std::io::{Read, Seek};
    use std::os::unix::fs::DirBuilderExt;
    let mut source = std::fs::File::open(archive)?;
    ensure!(source.metadata()?.len() == size, "source ZIP byte length mismatch");
    let mut digest = sha2::Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    ensure!(hex::encode(digest.finalize()) == expected, "source ZIP digest mismatch");
    source.rewind()?;
    let mut zipped = zip::ZipArchive::new(source)?;
    ensure!(
        zipped.len() == 2 && !zipped.has_duplicate_names(),
        "source ZIP member set mismatch"
    );
    for index in 0..zipped.len() {
        let entry = zipped.by_index_raw(index)?;
        let limit = match entry.name_raw() {
            b"receipt.json" => 65536,
            b"source.pack" => 128 * 1024 * 1024,
            _ => bail!("source ZIP member set mismatch"),
        };
        let kind = (entry.external_attributes() >> 16) & 0o170000;
        ensure!(
            !entry.is_dir() && matches!(kind, 0 | 0o100000) && !entry.encrypted(),
            "source ZIP member type mismatch"
        );
        ensure!(entry.size() <= limit, "source ZIP member exceeds bound");
    }
    std::fs::DirBuilder::new().mode(0o700).create(destination)?;
    for name in ["receipt.json", "source.pack"] {
        let mut entry = zipped.by_name(name)?;
        let declared = entry.size();
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(name))?;
        // A forged central-directory size cannot make decompression exceed its bound.
        let copied = std::io::copy(&mut entry.by_ref().take(declared + 1), &mut target)?;
        ensure!(copied == declared, "source ZIP member byte length mismatch");
    }
    Ok(())
}

/// Numeric selectors only. No caller-provided repository, path, verdict, statement or key.
pub fn observe_ci(run: u64, attempt: u64, artifact: u64, predecessors: &[String]) -> Result<Value> {
    for id in predecessors {
        oid(id)?;
    }
    let home = PathBuf::from(std::env::var_os("HOME").context("protected profile HOME")?);
    let directory = crate::product_dirs::resolve(
        home.join(".config/st"),
        home.join(".config/fractal"),
    );
    let configuration: Configuration = serde_json::from_slice(&std::fs::read(
        directory.join("evidence-ci.json"),
    )?)
    .context("private CI observer configuration")?;
    ensure!(
        configuration.scratch_repo.is_absolute(),
        "private scratch path must be absolute"
    );
    if let Some(key) = &configuration.ssh_key {
        ensure!(key.is_absolute(), "private key path must be absolute");
    }
    let signer = match configuration.tier {
        TrustTier::Full => {
            ensure!(
                configuration.expires_at.is_none(),
                "production signer cannot be a test service"
            );
            ObserverSigner::Full {
                principal: configuration
                    .signer
                    .as_deref()
                    .context("configured signing principal")?,
                key: configuration
                    .ssh_key
                    .as_deref()
                    .context("configured signing key")?,
            }
        }
        TrustTier::Test => ObserverSigner::Test {
            principal: configuration
                .signer
                .as_deref()
                .context("configured test principal")?,
            key: configuration
                .ssh_key
                .as_deref()
                .context("configured throwaway key")?,
            expires_at: configuration
                .expires_at
                .context("throwaway service expiration")?,
        },
        TrustTier::Degraded => {
            ensure!(
                configuration.signer.is_none()
                    && configuration.ssh_key.is_none()
                    && configuration.expires_at.is_none(),
                "degraded profile has no signer or key"
            );
            ObserverSigner::Unavailable
        }
    };
    if let ObserverSigner::Full { principal, .. } | ObserverSigner::Test { principal, .. } = &signer
    {
        ensure!(
            !principal.is_empty() && !principal.chars().any(char::is_whitespace),
            "invalid configured signer principal"
        );
    }
    let binding = CiBinding {
        repository: configuration.repository.clone(),
        run,
        attempt,
        recipe_sha256: configuration.recipe_sha256,
        accepted_base: configuration.accepted_base,
        workflow_sha256: configuration.workflow_sha256,
        required_checks: configuration.required_checks,
    };
    binding.validate()?;
    ensure!(
        predecessors.len() <= binding.required_checks.len(),
        "too many predecessor selectors"
    );
    let repo = &configuration.scratch_repo;
    ensure!(
        git_text(repo, &["rev-parse", "--is-bare-repository"], None)? == "true",
        "observer requires its private bare repository"
    );
    let github = Github {
        repository: binding.repository.clone(),
    };
    // Attempt-specific metadata stays authoritative even after another rerun begins.
    let observed_run = github.json(&format!("actions/runs/{run}/attempts/{attempt}"))?;
    binding.validate_run(&observed_run)?;
    let jobs = github.jobs(run, attempt)?;
    binding.validate_jobs(&jobs)?;
    let metadata = github.json(&format!("actions/artifacts/{artifact}"))?;
    let (size, hash) = binding.validate_artifact(&metadata, artifact)?;
    let scratch = tempfile::tempdir_in(repo).context("private source transfer directory")?;
    let archive = scratch.path().join("source.zip");
    let stream = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&archive)?;
    let status = github
        .command(&format!("actions/artifacts/{artifact}/zip"))
        .stdout(Stdio::from(stream))
        .status()?;
    ensure!(status.success(), "source artifact transfer unavailable");
    let destination = scratch.path().join("verified");
    extract_source(&archive, &destination, size, &hash)?;
    let receipt: SourceReceipt =
        serde_json::from_slice(&std::fs::read(destination.join("receipt.json"))?)?;
    let pack = std::fs::read(destination.join("source.pack"))?;
    ensure!(
        receipt.pack_bytes == pack.len() as u64
            && receipt.pack_sha256 == hex::encode(sha2::Sha256::digest(&pack)),
        "retained pack byte length/digest mismatch"
    );
    // Acquire the accepted baseline and platform head with their parents before strict
    // import. Source retention packs intentionally contain no history. For PR merge
    // artifacts the fixed main branch supplies the base history; they remain degraded.
    let platform_head = observed_run["head_sha"]
        .as_str()
        .context("platform run head")?;
    oid(platform_head)?;
    fetch_source(
        repo,
        &binding.repository,
        &[&binding.accepted_base, platform_head, "main"],
    )?;
    git(
        repo,
        &[
            "-c",
            "transfer.fsckObjects=true",
            "index-pack",
            "--strict",
            "--stdin",
        ],
        Some(&pack),
    )?;
    receipt.validate(repo, &binding, &observed_run)?;
    let full_eligible = binding.full_eligible(repo, &receipt, &observed_run)?;
    let effective_signer = if matches!(signer, ObserverSigner::Full { .. }) && !full_eligible {
        &ObserverSigner::Unavailable
    } else {
        &signer
    };
    let mut old_jobs = Vec::new();
    if !predecessors.is_empty() {
        let refs = predecessors
            .iter()
            .map(|id| format!("{NOTES_PREFIX}{id}"))
            .collect::<Vec<_>>();
        fetch_source(
            repo,
            &binding.repository,
            &refs.iter().map(String::as_str).collect::<Vec<_>>(),
        )?;
        let mut attempts = BTreeMap::<(u64, u64), Vec<(String, u64)>>::new();
        for id in predecessors {
            let old = ci_reattest::prior(repo, &binding.repository, id)?;
            let Fact::Tests { runner, .. } = old.predicate.fact else {
                unreachable!()
            };
            let (run, attempt, job) = ci_reattest::identity(&binding.repository, &runner)?;
            attempts
                .entry((run, attempt))
                .or_default()
                .push((id.clone(), job));
        }
        // One immutable provider read per distinct old attempt, shared by its selected jobs.
        for ((run, attempt), selected) in attempts {
            let old_run = github.json(&format!("actions/runs/{run}/attempts/{attempt}"))?;
            let mut old_binding = binding.clone();
            old_binding.run = run;
            old_binding.attempt = attempt;
            old_binding.validate_run(&old_run)?;
            let fetched = github.jobs(run, attempt)?;
            for (id, job) in selected {
                let matching = fetched
                    .iter()
                    .filter(|value| value["id"].as_u64() == Some(job))
                    .collect::<Vec<_>>();
                ensure!(matching.len() == 1, "missing or ambiguous predecessor job");
                old_jobs.push((id, old_run.clone(), matching[0].clone()));
            }
        }
    }
    let current = ci_statements(repo, &binding, &observed_run, &receipt, &jobs)?;
    let links = ci_reattest::prepare(repo, &binding.repository, &current, &jobs, &old_jobs)?;
    let produced = produce_ci_linked(
        repo,
        &binding,
        &observed_run,
        &receipt,
        &jobs,
        effective_signer,
        &links,
    )?;
    let re_attestations = ci_reattest::measurements(repo, &produced)?;
    let re_attestation_elapsed_ms = re_attestations
        .iter()
        .filter_map(|value| value["elapsed_ms"].as_u64())
        .max();
    // Export data only. The caller imports it with index-pack and verifies/puts each record;
    // the private profile need not write the caller's read-only checkout or expose its key.
    let mut objects = format!("{}\n", receipt.source).into_bytes();
    objects.extend(git(
        repo,
        &["rev-list", "--objects", "--no-object-names", &receipt.tree],
        None,
    )?);
    let mut exported_records = produced
        .iter()
        .map(|observation| observation.record.clone())
        .collect::<BTreeSet<_>>();
    for observation in &produced {
        if let Some(prior) = show(repo, &observation.record)?.predicate.re_attests {
            exported_records.insert(prior);
        }
    }
    for record in exported_records {
        let statement = show(repo, &record)?;
        objects.extend(format!("{}\n", statement.subject[0].name).as_bytes());
        objects.extend(format!("{record}\n").as_bytes());
        objects.extend(git(
            repo,
            &[
                "rev-list",
                "--objects",
                "--no-object-names",
                &format!("{record}^{{tree}}"),
            ],
            None,
        )?);
    }
    let object_pack = git(repo, &["pack-objects", "--stdout"], Some(&objects))?;
    let fresh = produced
        .iter()
        .filter(|result| result.newly_recorded)
        .collect::<Vec<_>>();
    let full = fresh
        .iter()
        .filter(|result| result.tier == TrustTier::Full)
        .count();
    let signing_latency_ms = fresh
        .iter()
        .map(|result| result.signing_latency_ms)
        .sum::<u128>();
    Ok(serde_json::json!({
        "repository":binding.repository, "run":run, "attempt":attempt,
        "source":receipt.source, "tree":receipt.tree,
        "full_trust_eligible":full_eligible,
        "trust_limitation":(!full_eligible).then_some("PR source is self-reported or retained workflow differs from accepted pin"),
        "records":produced, "re_attestations":re_attestations,
        "object_pack_base64":base64::engine::general_purpose::STANDARD.encode(object_pack),
        "metrics":{
            "fresh_records":fresh.len(), "full_records":full,
            "full_trust_share":(!fresh.is_empty()).then(|| full as f64 / fresh.len() as f64),
            "signing_latency_ms":signing_latency_ms,
            "original_ci_signing_latency_ms":0,
            "re_attested_records":re_attestations.len(),
            "re_attestation_elapsed_ms":re_attestation_elapsed_ms
        }
    }))
}

use sha2::Digest as _;

/// Fixed public repository and validated revisions only, under the installed profile PATH.
fn fetch_source(repo: &Path, repository: &str, revisions: &[&str]) -> Result<()> {
    let status = Command::new("timeout")
        .args(["--kill-after=2s", "30s", "git", "-C"])
        .arg(repo)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "transfer.fsckObjects=true",
            "fetch",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--",
        ])
        .arg(format!("https://github.com/{repository}.git"))
        .args(revisions)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    ensure!(
        status.success(),
        "accepted baseline/platform source unavailable"
    );
    Ok(())
}

#[cfg(test)]
mod archive_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn archive(root: &Path, case: &str) -> PathBuf {
        let path = root.join("source.zip");
        let status = Command::new("python3").args(["-c", r#"
import pathlib, stat, struct, sys, warnings, zipfile
path, case = pathlib.Path(sys.argv[1]), sys.argv[2]
names = ['receipt.json', 'source.pack']
if case in ('../escape', '/absolute', 'nested/receipt.json', 'receipt.json/'):
    names[0] = case
if case == 'duplicate':
    names[1] = names[0]
with warnings.catch_warnings(), zipfile.ZipFile(path, 'w') as archive:
    warnings.simplefilter('ignore')
    for name in names + (['extra'] if case == 'extra' else ['receipt.json'] if case == 'duplicate_extra' else []):
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        kind = {'symlink': stat.S_IFLNK, 'fifo': stat.S_IFIFO,
                'device': stat.S_IFCHR, 'directory': stat.S_IFDIR}.get(case, stat.S_IFREG)
        info.external_attr = (kind | 0o600) << 16
        info.compress_type = {'deflate': zipfile.ZIP_DEFLATED, 'bzip2': zipfile.ZIP_BZIP2,
                              'lzma': zipfile.ZIP_LZMA}.get(case, zipfile.ZIP_STORED)
        archive.writestr(info, b'\x00\xff\r\npayload' if name == 'source.pack' else b'{}\n')
data = bytearray(path.read_bytes())
central = data.index(b'PK\x01\x02')
if case == 'encrypted':
    struct.pack_into('<H', data, 6, 1)
    struct.pack_into('<H', data, central + 8, 1)
if case in ('receipt_limit', 'pack_limit', 'forged_size'):
    if case == 'pack_limit':
        central = data.index(b'PK\x01\x02', central + 4)
    size = {'receipt_limit': 65537, 'pack_limit': 128*1024*1024+1, 'forged_size': 1}[case]
    struct.pack_into('<I', data, central + 24, size)
if case == 'crc':
    data[30 + len(names[0])] ^= 1
if case == 'truncated':
    del data[-12:]
path.write_bytes(data)
"#]).arg(&path).arg(case).status().unwrap();
        assert!(status.success());
        path
    }

    fn extract(path: &Path, destination: &Path) -> Result<()> {
        let bytes = std::fs::read(path)?;
        extract_source(path, destination, bytes.len() as u64, &hex::encode(sha2::Sha256::digest(&bytes)))
    }

    #[test]
    fn archive_bytes_match_python_for_all_legacy_compression_methods() {
        for case in ["stored", "deflate", "bzip2", "lzma"] {
            let root = tempfile::tempdir().unwrap();
            let path = archive(root.path(), case);
            let destination = root.path().join("verified");
            extract(&path, &destination).unwrap();
            assert_eq!(std::fs::read(destination.join("receipt.json")).unwrap(), b"{}\n");
            assert_eq!(std::fs::read(destination.join("source.pack")).unwrap(), b"\x00\xff\r\npayload");
            assert_eq!(destination.metadata().unwrap().permissions().mode() & 0o777, 0o700);
            assert!(extract(&path, &destination).is_err(), "never reuse a destination");
        }
    }

    #[test]
    fn archive_rejects_adversarial_members_and_corruption() {
        for case in ["../escape", "/absolute", "nested/receipt.json", "receipt.json/",
            "duplicate", "duplicate_extra", "extra", "symlink", "fifo", "device", "directory", "encrypted",
            "receipt_limit", "pack_limit", "forged_size", "crc", "truncated"] {
            let root = tempfile::tempdir().unwrap();
            let path = archive(root.path(), case);
            let destination = root.path().join("verified");
            assert!(extract(&path, &destination).is_err(), "accepted {case}");
            assert!(!root.path().join("escape").exists());
        }
    }

    #[test]
    fn archive_authentication_precedes_parsing_or_writes() {
        let root = tempfile::tempdir().unwrap();
        let path = archive(root.path(), "stored");
        let destination = root.path().join("verified");
        let bytes = std::fs::read(&path).unwrap();
        let hash = hex::encode(sha2::Sha256::digest(&bytes));
        assert!(extract_source(&path, &destination, bytes.len() as u64 + 1, &hash).is_err());
        assert!(extract_source(&path, &destination, bytes.len() as u64, &"0".repeat(64)).is_err());
        assert!(!destination.exists());
    }
}
