//! BASE-authorized, read-only single-lane evidence decisions.
pub mod config;
pub mod git;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};
use clap::Args as ClapArgs;
use serde::Serialize;
use std::{collections::BTreeSet, io::Write, path::{Path, PathBuf}, process::Command};
use crate::evidence::{self, Fact, Statement, TrustTier};
use config::{Authors, Config, Lane};
use unicode_normalization::UnicodeNormalization;

#[derive(ClapArgs)]
pub struct Args {
    #[arg(long)] pub check: String,
    #[arg(long)] pub base: String,
    #[arg(long)] pub head: String,
    #[arg(long)] pub event_file: Option<PathBuf>,
    #[arg(long, value_parser = ["json"])] pub format: String,
    #[arg(long)] pub github_output: Option<PathBuf>,
}

// Signature verification runs in a sanitized child because the unchanged evidence
// module inherits Git configuration from its process. Never mutate process env.
#[derive(ClapArgs)]
pub struct VerifyArgs {
    #[arg(long)] pub repo: PathBuf,
    #[arg(long)] pub record: String,
    #[arg(long)] pub keys: PathBuf,
}

pub fn verify_worker(args: VerifyArgs) -> Result<()> {
    let statement = evidence::verify_record(&args.repo, &args.record, &args.keys)?;
    println!("{}", serde_json::to_string(&statement)?);
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Decision {
    pub version: u32,
    pub check: String,
    pub base: String,
    pub head: String,
    pub tree: String,
    pub decision: &'static str,
    pub outcome: &'static str,
    pub reason: &'static str,
    pub record: Option<String>,
    pub protected_paths: Vec<String>,
}

pub fn run(args: Args) -> Result<()> {
    let repo = std::env::current_dir()?;
    let live = Live::read(&repo, &args.base, &args.head, args.event_file.as_deref())?;
    let decision = compute(&repo, &args.check, &args.base, &args.head, args.event_file.as_deref())?;
    let json = serde_json::to_string(&decision)?;
    let mut output = args.github_output.map(|path|
        std::fs::OpenOptions::new().append(true).create(true).open(path)).transpose()?;
    live.recheck(&repo, &args.base, &args.head)?;
    if let Some(output) = output.as_mut() {
        // No decision outputs are written until the mutable authorities are rechecked.
        writeln!(output, "skip={}\nrecord={}\noutcome={}\nrefuse={}\nrefusal={}",
            decision.decision == "skip", decision.record.as_deref().unwrap_or(""),
            decision.outcome, decision.decision == "refuse",
            if decision.decision == "refuse" { decision.reason } else { "" })?;
    }
    println!("{json}");
    Ok(())
}

fn oid(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn commit(repo: &Path, value: &str) -> Result<()> {
    ensure!(oid(value), "commit must be a full lowercase 40-hex SHA");
    ensure!(git::text(repo, &["cat-file", "-t", value])? == "commit", "object must be a commit");
    Ok(())
}

// Explicit object IDs are not a live authority. Locally require a matching HEAD
// and a named base ref, then watch their mutable ref namespace. In Actions only
// authenticated GitHub metadata is authoritative, not the checkout's refs.
enum Live {
    Local { head: String, head_ref: String, refs: String },
    Github { repository: String, number: u64, base_ref: String },
}

impl Live {
    fn read(repo: &Path, base: &str, head: &str, event: Option<&Path>) -> Result<Self> {
        if let Some(path) = event {
            let event: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
            let repository = std::env::var("GITHUB_REPOSITORY").context("trusted repository required")?;
            ensure!(repository.split('/').count() == 2 && repository.split('/').all(|part|
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))),
                "invalid trusted repository");
            let number = event.pointer("/pull_request/number").or_else(|| event.get("number"))
                .and_then(serde_json::Value::as_u64).filter(|n| *n > 0).context("PR number required")?;
            let base_ref = event.pointer("/pull_request/base/ref")
                .and_then(serde_json::Value::as_str).context("base branch required")?.to_owned();
            return Ok(Self::Github { repository, number, base_ref });
        }
        let current = git::text(repo, &["rev-parse", "HEAD"])?;
        ensure!(current == head, "local HEAD does not match requested head");
        let refs = Self::refs(repo)?;
        ensure!(refs.lines().any(|line| line.split_once(' ').is_some_and(|(_, id)| id == base)),
            "local base requires a matching branch or remote-tracking ref");
        let head_ref = git::text(repo, &["rev-parse", "--symbolic-full-name", "HEAD"])?;
        Ok(Self::Local { head: current, head_ref, refs })
    }

    fn refs(repo: &Path) -> Result<String> {
        git::text(repo, &["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads/", "refs/remotes/"])
    }

    fn recheck(&self, repo: &Path, base: &str, head: &str) -> Result<()> {
        match self {
            Self::Local { head: initial, head_ref, refs } => {
                ensure!(git::text(repo, &["rev-parse", "HEAD"])? == *initial &&
                    git::text(repo, &["rev-parse", "--symbolic-full-name", "HEAD"])? == *head_ref &&
                    Self::refs(repo)? == *refs, "local head or base refs changed during verification");
            }
            Self::Github { repository, number, base_ref } => {
                let pull = Self::api(repo, &format!("repos/{repository}/pulls/{number}"))?;
                ensure!(pull.pointer("/head/sha").and_then(serde_json::Value::as_str) == Some(head) &&
                    pull.pointer("/head/repo/full_name").and_then(serde_json::Value::as_str) == Some(repository.as_str()) &&
                    pull.pointer("/base/repo/full_name").and_then(serde_json::Value::as_str) == Some(repository.as_str()) &&
                    pull.pointer("/base/ref").and_then(serde_json::Value::as_str) == Some(base_ref.as_str()),
                    "live PR metadata changed");
                let encoded: String = base_ref.bytes().map(|b| format!("%{b:02X}")).collect();
                let branch = Self::api(repo, &format!("repos/{repository}/git/ref/heads/{encoded}"))?;
                ensure!(branch.pointer("/object/sha").and_then(serde_json::Value::as_str) == Some(base),
                    "live base tip changed");
            }
        }
        Ok(())
    }

    fn api(repo: &Path, endpoint: &str) -> Result<serde_json::Value> {
        let token = std::env::var("GITHUB_TOKEN").context("authenticated live recheck requires GITHUB_TOKEN")?;
        ensure!(!token.is_empty(), "authenticated live recheck requires GITHUB_TOKEN");
        // PATH is trusted job context, but never execute a relative entry or a
        // tool supplied by candidate source (including symlinks into it).
        let repo = std::fs::canonicalize(repo)?;
        let executable = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .filter(|directory| directory.is_absolute())
            .filter_map(|directory| std::fs::canonicalize(directory.join("gh")).ok())
            .find(|path| !path.starts_with(&repo) && path.is_file())
            .context("trusted gh executable outside candidate repository required")?;
        let config = tempfile::tempdir()?;
        let mut command = Command::new(executable);
        git::sanitize(&mut command);
        let output = command.args(["api", "--hostname", "github.com", endpoint])
            .env("GH_TOKEN", token).env("GH_PROMPT_DISABLED", "1").env("GH_CONFIG_DIR", config.path())
            .env_remove("GH_HOST").stdin(std::process::Stdio::null()).output()
            .context("querying live GitHub metadata")?;
        ensure!(output.status.success(), "authenticated live GitHub recheck failed");
        serde_json::from_slice(&output.stdout).context("invalid live GitHub metadata")
    }
}

pub fn decide(repo: &Path, check: &str, base: &str, head: &str, event: Option<&Path>) -> Result<Decision> {
    let live = Live::read(repo, base, head, event)?;
    let decision = compute(repo, check, base, head, event)?;
    live.recheck(repo, base, head)?;
    Ok(decision)
}

fn compute(repo: &Path, check: &str, base: &str, head: &str, event: Option<&Path>) -> Result<Decision> {
    commit(repo, base)?;
    commit(repo, head)?;
    let config = config::load(repo, base)?;
    let lane = config.policy.lanes.get(check).context("unknown check")?;
    let tree = git::text(repo, &["rev-parse", &format!("{head}^{{tree}}")])?;
    let mut decision = Decision { version: 1, check: check.into(), base: base.into(), head: head.into(), tree,
        decision: if lane.mode == "required_evidence" { "refuse" } else { "run" },
        outcome: "rejected", reason: "base_not_ancestor", record: None, protected_paths: Vec::new() };
    let relation = git::command(repo).args(["merge-base", "--is-ancestor", base, head]).output()?;
    match relation.status.code() {
        Some(0) => {},
        Some(1) => return Ok(decision),
        _ => anyhow::bail!("ancestry unavailable: {}", String::from_utf8_lossy(&relation.stderr)),
    }
    let paths = git::git(repo, &["diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z", base, head, "--"])?;
    let mandatory = [".mergemaster/", ".github/workflows/", ".github/actions/"];
    for path in paths.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        let path = std::str::from_utf8(path).context("non-UTF8 changed path")?;
        if mandatory.iter().copied().chain(config.policy.protected_paths.iter().map(String::as_str))
            .chain(config.policy.bootstrap_paths.iter().map(String::as_str)).any(|prefix| matches_path(path, prefix)) {
            decision.protected_paths.push(path.to_owned());
        }
    }
    if !git::text(repo, &["rev-list", "--min-parents=2", &format!("{base}..{head}")])?.is_empty() {
        decision.decision = "refuse";
        decision.reason = "merge_history";
        return Ok(decision);
    }
    if !decision.protected_paths.is_empty() {
        decision.decision = "refuse";
        decision.reason = "protected_paths";
        return Ok(decision);
    }
    if !eligible(repo, base, head, event, &config, lane)? {
        decision.reason = "ineligible_event";
        return Ok(decision);
    }
    let expected = config::expected_inputs(repo, head, check, lane, &config.environment, &config.environment_bytes)?;
    let mut keys = tempfile::NamedTempFile::new()?;
    keys.write_all(&config.keys)?;
    keys.flush()?;
    let (records, malformed) = records(repo, &decision.tree)?;
    let mut candidates = Vec::new();
    decision.outcome = "no_note";
    decision.reason = if malformed { "invalid_record" } else { "no_record" };
    if malformed { decision.outcome = "rejected"; }
    for id in records {
        let mut command = Command::new(std::env::current_exe()?);
        git::sanitize(&mut command);
        let output = command.arg("gate-verify-record").arg("--repo").arg(repo)
            .arg("--record").arg(&id).arg("--keys").arg(keys.path()).output()?;
        if !output.status.success() {
            decision.reason = "untrusted_signer";
            decision.outcome = "rejected";
            continue;
        }
        let statement: Statement = serde_json::from_slice(&output.stdout).context("signature worker output")?;
        if statement.subject[0].digest.get("gitTree") != Some(&decision.tree) {
            decision.reason = "stale_tree";
            decision.outcome = "rejected";
            continue;
        }
        let Fact::Tests { ref checks, .. } = statement.predicate.fact else { continue };
        if !checks.contains_key(check) { decision.reason = "wrong_check"; continue; }
        let at = DateTime::parse_from_rfc3339(&statement.predicate.observed_at)?;
        candidates.push((id, statement, at));
    }
    // Python evidence-verify selects newest trusted observation first, biased toward
    // failures within two minutes. A later invalid command cannot expose an old pass.
    candidates.sort_by(|a, b| (a.2, failed(&a.1, check), &a.0).cmp(&(b.2, failed(&b.1, check), &b.0)));
    let Some(mut chosen) = candidates.pop() else { return Ok(decision) };
    if !failed(&chosen.1, check) {
        if let Some(index) = candidates.iter().rposition(|c| failed(&c.1, check) && c.2 >= chosen.2 - Duration::seconds(120)) {
            chosen = candidates.remove(index);
        }
    }
    decision.record = Some(chosen.0);
    decision.outcome = "rejected";
    let statement = chosen.1;
    decision.reason = satisfy(&statement, check, head, &decision.tree, lane, &expected);
    if decision.reason == "satisfied" {
        decision.decision = "skip";
        decision.outcome = "satisfied";
    } else if decision.reason == "degraded" { decision.outcome = "degraded"; }
    Ok(decision)
}

fn matches_path(path: &str, prefix: &str) -> bool {
    // NFKC closes compatibility-spelling aliases (including fullwidth dots and
    // separators); lowercase also covers case-insensitive checkout filesystems.
    let path = path.nfkc().flat_map(char::to_lowercase).collect::<String>();
    let prefix = prefix.nfkc().flat_map(char::to_lowercase).collect::<String>();
    let prefix = prefix.trim_end_matches('/');
    path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/')) ||
        prefix.strip_prefix(path.as_str()).is_some_and(|rest| rest.starts_with('/'))
}

fn failed(statement: &Statement, check: &str) -> bool {
    matches!(&statement.predicate.fact, Fact::Tests {checks, ..} if checks[check].exit_code != 0)
}

fn satisfy(statement: &Statement, check: &str, head: &str, tree: &str, lane: &Lane,
    expected: &std::collections::BTreeMap<String, String>) -> &'static str {
    let predicate = &statement.predicate;
    if predicate.tier == TrustTier::Degraded { return "degraded"; }
    if predicate.tier != TrustTier::Full { return "untrusted_tier"; }
    if statement.subject[0].name != head { return "wrong_commit"; }
    if statement.subject[0].digest.get("gitTree").map(String::as_str) != Some(tree) { return "stale_tree"; }
    let principal = predicate.signer.as_deref().unwrap_or("");
    if !lane.trust_levels.iter().any(|level| level == principal.split('/').next().unwrap_or("")) { return "untrusted_level"; }
    let at = DateTime::parse_from_rfc3339(&predicate.observed_at).expect("verified timestamp");
    let now = Utc::now();
    if at > now + Duration::seconds(120) { return "future_dated"; }
    if lane.max_age_seconds.is_some_and(|seconds| (now - at.with_timezone(&Utc)).num_seconds() > i64::try_from(seconds).unwrap_or(i64::MAX)) { return "too_old"; }
    let Fact::Tests { checks, inputs, .. } = &predicate.fact else { return "wrong_check" };
    let result = &checks[check];
    if result.exit_code != 0 { return "check_failed"; }
    if result.command != lane.argv { return "wrong_command"; }
    if !inputs.get("wrapper_sha256").is_some_and(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())) ||
        !inputs.get("attempt").is_some_and(|value| value.parse::<u64>().is_ok_and(|n| n > 0)) { return "wrong_input"; }
    if inputs.get("workspace_clean").map(String::as_str) != Some("true") ||
        inputs.get("untracked_files").map(String::as_str) != Some("false") { return "workspace_dirty"; }
    if expected.iter().any(|(key, value)| inputs.get(key) != Some(value)) { return "wrong_input"; }
    "satisfied"
}

fn records(repo: &Path, tree: &str) -> Result<(BTreeSet<String>, bool)> {
    let refs = git::text(repo, &["for-each-ref", "--format=%(refname) %(objectname)", "refs/notes/evidence/", "refs/tags/evidence/"])?;
    let mut found = BTreeSet::new();
    let mut malformed = false;
    for line in refs.lines() {
        let (name, value) = line.split_once(' ').context("evidence ref listing")?;
        let suffix = name.strip_prefix("refs/notes/evidence/").or_else(|| name.strip_prefix("refs/tags/evidence/")).context("evidence namespace")?;
        let parts: Vec<_> = suffix.split('/').collect();
        let id = match parts.as_slice() {
            [id] if name.starts_with("refs/notes/") => *id,
            [scope, id] if *scope == tree => *id,
            _ => continue,
        };
        if !oid(id) || id != value { malformed = true; continue; }
        found.insert(id.to_owned());
    }
    Ok((found, malformed))
}

fn eligible(repo: &Path, base: &str, head: &str, event: Option<&Path>, config: &Config, lane: &Lane) -> Result<bool> {
    let mut identities = Vec::new();
    if let Some(path) = event {
        let event: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
        let string = |pointer| event.pointer(pointer).and_then(serde_json::Value::as_str);
        let repository = std::env::var("GITHUB_REPOSITORY").context("event verification requires trusted GITHUB_REPOSITORY")?;
        if string("/pull_request/head/sha") != Some(head) || string("/repository/full_name") != Some(repository.as_str()) ||
            string("/pull_request/head/repo/full_name") != Some(repository.as_str()) ||
            string("/pull_request/base/repo/full_name") != Some(repository.as_str()) { return Ok(false); }
        let Some(event_base) = string("/pull_request/base/sha") else { return Ok(false) };
        if !oid(event_base) || git::text(repo, &["merge-base", event_base, base]).ok().as_deref() != Some(event_base) { return Ok(false); }
        identities.push(string("/pull_request/user/login").unwrap_or("").to_owned());
        identities.push(std::env::var("GITHUB_ACTOR").unwrap_or_default());
        identities.push(std::env::var("GITHUB_TRIGGERING_ACTOR").unwrap_or_default());
    }
    if !lane.events.iter().any(|event| event == "pull_request") { return Ok(false); }
    if let Authors::Allowlist { logins, git_authors, git_committers } = &config.policy.pull_request.authors {
        if event.is_none() || identities.iter().any(|login| login.is_empty() || !logins.contains(login)) { return Ok(false); }
        let commits = git::text(repo, &["log", "--format=%an <%ae>%x00%cn <%ce>", &format!("{base}..{head}")])?;
        for line in commits.lines() {
            let Some((author, committer)) = line.split_once('\0') else { return Ok(false) };
            if !git_authors.iter().any(|v| v == author) || !git_committers.iter().any(|v| v == committer) { return Ok(false); }
        }
    }
    Ok(true)
}
