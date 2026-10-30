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
    let decision = decide(&std::env::current_dir()?, &args.check, &args.base, &args.head, args.event_file.as_deref())?;
    let json = serde_json::to_string(&decision)?;
    if let Some(path) = args.github_output {
        let mut output = std::fs::OpenOptions::new().append(true).create(true).open(path)?;
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

pub fn decide(repo: &Path, check: &str, base: &str, head: &str, event: Option<&Path>) -> Result<Decision> {
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
    let prefix = prefix.trim_end_matches('/');
    path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
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
