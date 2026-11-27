//! BASE-authorized, read-only single-lane evidence decisions.
mod approval;
pub mod config;
pub mod git;
pub mod reuse;
pub mod selection;

use crate::evidence::{self, Fact, Statement, TrustTier};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};
use clap::Args as ClapArgs;
use config::{Authors, Config, Lane};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
use unicode_normalization::UnicodeNormalization;

#[derive(ClapArgs)]
pub struct Args {
    #[arg(long)]
    pub check: String,
    #[arg(long)]
    pub base: String,
    #[arg(long)]
    pub head: String,
    #[arg(long, default_value = "pull_request", value_parser = ["pull_request", "push", "merge_group", "queue"])]
    pub event: String,
    /// Exact PR heads in batch merge order (oldest first); queue reports only.
    #[arg(long = "member", value_name = "HEAD_SHA")]
    pub members: Vec<String>,
    #[arg(long)]
    pub event_file: Option<PathBuf>,
    #[arg(long)]
    pub compare_head: Option<String>,
    #[arg(long)]
    pub hosted_evidence: Option<PathBuf>,
    #[arg(long, value_parser = ["json"])]
    pub format: String,
    #[arg(long)]
    pub github_output: Option<PathBuf>,
}

// Signature verification runs in a sanitized child because the unchanged evidence
// module inherits Git configuration from its process. Never mutate process env.
#[derive(ClapArgs)]
pub struct VerifyArgs {
    #[arg(long)]
    pub repo: PathBuf,
    #[arg(long)]
    pub record: String,
    #[arg(long)]
    pub keys: PathBuf,
    /// Current immutable BASE; required for scoped v2 issuer authority.
    #[arg(long)]
    pub base: Option<String>,
    #[arg(long)]
    pub check: Option<String>,
}

pub fn verify_worker(args: VerifyArgs) -> Result<()> {
    if evidence::record_is_v2(&args.repo, &args.record)? {
        #[derive(Serialize)]
        struct Refused<'a> {
            version: u32,
            record: &'a str,
            statement: (),
            verified_signer: (),
            verified_key_id: (),
            selective_reuse: reuse::SelectiveReuse,
        }
        let reply = Refused {
            version: 2,
            record: &args.record,
            statement: (),
            verified_signer: (),
            verified_key_id: (),
            selective_reuse: reuse::worker(&args)?,
        };
        println!("{}", serde_json::to_string(&reply)?);
        return Ok(());
    }
    let statement = evidence::verified::legacy_record::<evidence::v2::DaemonPolicyReceipt>(
        &args.repo,
        &args.record,
        &args.keys,
    )?;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane_selection: Option<selection::Selection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_binding: Option<QueueBinding>,
    pub expectation_source: &'static str,
    pub decision: &'static str,
    pub outcome: &'static str,
    pub reason: &'static str,
    pub record: Option<String>,
    pub report_only: bool,
    pub producer_digest: Option<config::ProducerDigest>,
    pub signer: Option<String>,
    pub observed_at: Option<String>,
    pub age_seconds: Option<i64>,
    pub lane_definition_sha256: Option<String>,
    pub input_key_equal: Option<bool>,
    pub compared_record: Option<ComparedRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selective_reuse: Option<reuse::SelectiveReuse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_refused: Option<usize>,
    pub protected_paths: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct QueueBinding {
    pub base: String,
    pub members: Vec<String>,
    pub tree: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection: Option<QueueProjection>,
}

#[derive(Debug, Serialize)]
pub struct QueueProjection {
    pub commit: String,
    pub parent: String,
    pub paths: Vec<String>,
}

impl Decision {
    fn refuse(&mut self, (reason, summary): (&'static str, String)) {
        self.decision = "refuse";
        self.outcome = "rejected";
        self.reason = reason;
        self.record = None;
        self.selective_reuse = None;
        self.summary = summary;
    }
}

#[derive(Debug, Serialize)]
pub struct ComparedRecord {
    pub tree: String,
    pub signer: Option<String>,
    pub observed_at: String,
    pub age_seconds: i64,
}

pub fn run(args: Args) -> Result<()> {
    let repo = std::env::current_dir()?;
    let merge_group = args.event == "merge_group";
    let queue = args.event == "queue";
    ensure!(
        queue || args.compare_head.is_none(),
        "--compare-head requires --event queue"
    );
    ensure!(
        queue || args.members.is_empty(),
        "--member requires --event queue"
    );
    let live = if merge_group || queue {
        None
    } else {
        Some(Live::read(
            &repo,
            &args.base,
            &args.head,
            args.event_file.as_deref(),
            args.event == "push",
        )?)
    };
    let mut decision = compute(
        &repo,
        &args.check,
        &args.base,
        &args.head,
        args.event_file.as_deref(),
        args.hosted_evidence.as_deref(),
        (&args.event, &args.members),
    )?;
    if queue {
        decision.decision = "refuse";
        decision.report_only = true;
        if let Some(head) = &args.compare_head {
            compare(&repo, &args, head, &mut decision)?;
        }
    }
    if merge_group {
        decision.decision = "refuse";
        if matches!(decision.outcome, "satisfied" | "reused") {
            decision.reason = "report_only_queue_parent";
            decision.outcome = "rejected";
        }
        decision.summary = format!(
            "Report-only merge-group shadow: event base_sha is the queue parent, not the live accepted BASE; caller-supplied candidate, no live queue or protected-target authorization. {}",
            decision.summary
        );
    }
    let mut output = args
        .github_output
        .map(|path| {
            std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
        })
        .transpose()?;
    if let Some(refusal) = live
        .as_ref()
        .map(|live| live.recheck(&repo, &args.base, &args.head))
        .transpose()?
        .flatten()
    {
        decision.refuse(refusal);
    }
    let json = serde_json::to_string(&decision)?;
    if let Some(output) = output.as_mut() {
        // No decision outputs are written until the mutable authorities are rechecked.
        writeln!(
            output,
            "skip={}\nrecord={}\noutcome={}\nrefuse={}\nrefusal={}",
            decision.decision == "skip",
            decision.record.as_deref().unwrap_or(""),
            decision.outcome,
            decision.decision == "refuse",
            if decision.decision == "refuse" {
                decision.reason
            } else {
                ""
            }
        )?;
    }
    println!("{json}");
    Ok(())
}

fn oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn commit(repo: &Path, value: &str) -> Result<()> {
    ensure!(oid(value), "commit must be a full lowercase 40-hex SHA");
    ensure!(
        git::text(repo, &["cat-file", "-t", value])? == "commit",
        "object must be a commit"
    );
    Ok(())
}

// Explicit object IDs are not a live authority. Locally require a matching HEAD
// and a named base ref, then watch their mutable ref namespace. In Actions only
// authenticated GitHub metadata is authoritative, not the checkout's refs.
enum Live {
    Local {
        head: String,
        head_ref: String,
        refs: String,
    },
    Github {
        repository: String,
        number: u64,
        base_ref: String,
    },
    Push {
        repository: String,
        reference: String,
        after: String,
    },
}

impl Live {
    fn read(repo: &Path, base: &str, head: &str, event: Option<&Path>, push: bool) -> Result<Self> {
        if let Some(path) = event {
            let event: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
            let repository =
                std::env::var("GITHUB_REPOSITORY").context("trusted repository required")?;
            ensure!(
                repository.split('/').count() == 2
                    && repository.split('/').all(|part| !part.is_empty()
                        && part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))),
                "invalid trusted repository"
            );
            if push {
                return Ok(Self::Push {
                    repository,
                    reference: event["ref"].as_str().unwrap_or_default().into(),
                    after: event["after"].as_str().unwrap_or_default().into(),
                });
            }
            let number = event
                .pointer("/pull_request/number")
                .or_else(|| event.get("number"))
                .and_then(serde_json::Value::as_u64)
                .filter(|n| *n > 0)
                .context("PR number required")?;
            let base_ref = event
                .pointer("/pull_request/base/ref")
                .and_then(serde_json::Value::as_str)
                .context("base branch required")?
                .to_owned();
            return Ok(Self::Github {
                repository,
                number,
                base_ref,
            });
        }
        let current = git::text(repo, &["rev-parse", "HEAD"])?;
        ensure!(current == head, "local HEAD does not match requested head");
        let refs = Self::refs(repo)?;
        ensure!(
            refs.lines()
                .any(|line| line.split_once(' ').is_some_and(|(_, id)| id == base)),
            "local base requires a matching branch or remote-tracking ref"
        );
        let head_ref = git::text(repo, &["rev-parse", "--symbolic-full-name", "HEAD"])?;
        Ok(Self::Local {
            head: current,
            head_ref,
            refs,
        })
    }

    fn refs(repo: &Path) -> Result<String> {
        git::text(
            repo,
            &[
                "for-each-ref",
                "--format=%(refname) %(objectname)",
                "refs/heads/",
                "refs/remotes/",
            ],
        )
    }

    fn recheck(
        &self,
        repo: &Path,
        base: &str,
        head: &str,
    ) -> Result<Option<(&'static str, String)>> {
        match self {
            Self::Local {
                head: initial,
                head_ref,
                refs,
            } => {
                ensure!(
                    git::text(repo, &["rev-parse", "HEAD"])? == *initial
                        && git::text(repo, &["rev-parse", "--symbolic-full-name", "HEAD"])?
                            == *head_ref
                        && Self::refs(repo)? == *refs,
                    "local head or base refs changed during verification"
                );
            }
            Self::Github {
                repository,
                number,
                base_ref,
            } => {
                let pull = Self::api(repo, &format!("repos/{repository}/pulls/{number}"))?;
                let live_head = pull
                    .pointer("/head/sha")
                    .and_then(serde_json::Value::as_str)
                    .context("live head SHA required")?;
                if live_head != head {
                    return Ok(Some((
                        "stale_head",
                        format!("live head tip moved: event {head} live {live_head}"),
                    )));
                }
                for (field, expected) in [
                    ("/head/repo/full_name", repository.as_str()),
                    ("/base/repo/full_name", repository.as_str()),
                    ("/base/ref", base_ref.as_str()),
                ] {
                    let actual = pull.pointer(field).and_then(serde_json::Value::as_str);
                    if actual != Some(expected) {
                        return Ok(Some((
                            "pr_metadata_changed",
                            format!(
                                "live PR {field} changed: event {expected} live {}; head event {head} live {live_head}; base event {base} live {}",
                                actual.unwrap_or("<missing>"),
                                pull.pointer("/base/sha")
                                    .and_then(serde_json::Value::as_str)
                                    .unwrap_or("<missing>")
                            ),
                        )));
                    }
                }
                let encoded: String = base_ref.bytes().map(|b| format!("%{b:02X}")).collect();
                let branch =
                    Self::api(repo, &format!("repos/{repository}/git/ref/heads/{encoded}"))?;
                let live_base = branch
                    .pointer("/object/sha")
                    .and_then(serde_json::Value::as_str)
                    .context("live base SHA required")?;
                if live_base != base {
                    return Ok(Some((
                        "stale_base",
                        format!("live base tip moved: event {base} live {live_base}"),
                    )));
                }
            }
            Self::Push {
                repository,
                reference,
                after,
            } => {
                let metadata = Self::api(repo, &format!("repos/{repository}"))?;
                let branch = metadata["default_branch"]
                    .as_str()
                    .context("live default branch required")?;
                if reference != &format!("refs/heads/{branch}") {
                    return Ok(Some((
                        "not_default_branch",
                        format!("push ref {reference} is not the live default branch {branch}"),
                    )));
                }
                let encoded: String = branch.bytes().map(|b| format!("%{b:02X}")).collect();
                let tip = Self::api(repo, &format!("repos/{repository}/git/ref/heads/{encoded}"))?;
                if after != head
                    || tip
                        .pointer("/object/sha")
                        .and_then(serde_json::Value::as_str)
                        != Some(head)
                {
                    return Ok(Some((
                        "stale_push",
                        "push does not match the live default branch tip".into(),
                    )));
                }
            }
        }
        Ok(None)
    }

    fn api(repo: &Path, endpoint: &str) -> Result<serde_json::Value> {
        let token = std::env::var("GITHUB_TOKEN")
            .context("authenticated live recheck requires GITHUB_TOKEN")?;
        ensure!(
            !token.is_empty(),
            "authenticated live recheck requires GITHUB_TOKEN"
        );
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
        let output = command
            .args(["api", "--hostname", "github.com", endpoint])
            .env("GH_TOKEN", token)
            .env("GH_PROMPT_DISABLED", "1")
            .env("GH_CONFIG_DIR", config.path())
            .env_remove("GH_HOST")
            .stdin(std::process::Stdio::null())
            .output()
            .context("querying live GitHub metadata")?;
        ensure!(
            output.status.success(),
            "authenticated live GitHub recheck failed"
        );
        serde_json::from_slice(&output.stdout).context("invalid live GitHub metadata")
    }
}

pub fn decide(
    repo: &Path,
    check: &str,
    base: &str,
    head: &str,
    event: Option<&Path>,
) -> Result<Decision> {
    let live = Live::read(repo, base, head, event, false)?;
    let mut decision = compute(repo, check, base, head, event, None, ("pull_request", &[]))?;
    if let Some(refusal) = live.recheck(repo, base, head)? {
        decision.refuse(refusal);
    }
    Ok(decision)
}

// Explicit batches mirror the train's commit-tree tree -p prefix -p admitted.
// The legacy single-PR form also accepts BASE as the second parent.
fn bind_queue(
    repo: &Path,
    base: &str,
    head: &str,
    members: &[String],
    policy: Option<&config::QueuePolicy>,
) -> Result<(Vec<String>, Option<QueueProjection>)> {
    let parents = |head: &str| -> Result<Vec<String>> {
        Ok(
            git::text(repo, &["rev-list", "--parents", "-n", "1", head])?
                .split_whitespace()
                .skip(1)
                .map(str::to_owned)
                .collect(),
        )
    };
    if members.is_empty() {
        let head_parents = parents(head)?;
        let (merge_parents, projection) = if head_parents.len() == 1 {
            let policy =
                policy.context("queue projection requires BASE queue.generated_paths policy")?;
            let parent = &head_parents[0];
            let merge_parents = parents(parent)?;
            ensure!(
                merge_parents.len() != 1,
                "queue head {head} has more than one projection commit"
            );
            ensure!(
                merge_parents.len() == 2 && merge_parents.iter().any(|p| p == base),
                "queue projection parent {parent} must be a two-parent merge with base {base} as a parent"
            );
            let paths = projection_paths(repo, parent, head, &policy.generated_paths)?;
            (
                merge_parents,
                Some(QueueProjection {
                    commit: head.into(),
                    parent: parent.clone(),
                    paths,
                }),
            )
        } else {
            ensure!(
                head_parents.len() == 2 && head_parents.iter().any(|parent| parent == base),
                "queue head {head} must be a two-parent merge with base {base} as a parent; declare ordered --member SHAs for a batch"
            );
            (head_parents, None)
        };
        return Ok((
            merge_parents
                .into_iter()
                .filter(|parent| parent != base)
                .collect(),
            projection,
        ));
    }
    let mut current = head.to_owned();
    for (index, member) in members.iter().enumerate().rev() {
        commit(repo, member).with_context(|| {
            format!(
                "queue member {} must be an existing full lowercase commit SHA",
                index + 1
            )
        })?;
        let mut parents = parents(&current)?;
        ensure!(
            parents.len() == 2,
            "queue step {} at {current} must have exactly two parents, found {}",
            index + 1,
            parents.len()
        );
        ensure!(
            parents[1] == *member,
            "queue step {} at {current} has second parent {}, expected declared member {member}",
            index + 1,
            parents[1]
        );
        current = parents.swap_remove(0);
    }
    ensure!(
        current == base,
        "queue first-parent chain after {} members ends at {current}, expected base {base}",
        members.len()
    );
    Ok((members.to_vec(), None))
}

fn projection_paths(
    repo: &Path,
    parent: &str,
    head: &str,
    generated: &[String],
) -> Result<Vec<String>> {
    // Disabling renames exposes both sides of moves. Raw tree modes include
    // deletes and executable-bit changes, without following checkout symlinks.
    let diff = git::git(
        repo,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--ignore-submodules=none",
            "--raw",
            "-z",
            parent,
            head,
            "--",
        ],
    )?;
    let mut fields = diff.split(|byte| *byte == 0);
    let mut paths = Vec::new();
    while let Some(header) = fields.next().filter(|field| !field.is_empty()) {
        let path = fields.next().context("queue projection diff has no path")?;
        let path = std::str::from_utf8(path).context("non-UTF8 queue projection path")?;
        ensure!(
            generated
                .iter()
                .any(|pattern| generated_matches(path, pattern)),
            "queue projection touches non-generated path {path}"
        );
        let header = std::str::from_utf8(header).context("invalid queue projection diff")?;
        let mut modes = header.trim_start_matches(':').split_whitespace().take(2);
        ensure!(
            modes.all(|mode| matches!(mode, "000000" | "100644")),
            "queue projection path {path} must be a regular non-executable file"
        );
        paths.push(path.to_owned());
    }
    Ok(paths)
}

fn compute(
    repo: &Path,
    check: &str,
    base: &str,
    head: &str,
    event: Option<&Path>,
    hosted: Option<&Path>,
    source: (&str, &[String]),
) -> Result<Decision> {
    let (event_type, members) = source;
    let push = event_type == "push";
    let merge_group = event_type == "merge_group";
    let queue = event_type == "queue";
    if queue && (commit(repo, base).is_err() || commit(repo, head).is_err()) {
        return Ok(Decision {
            version: 1,
            check: check.into(),
            base: base.into(),
            head: head.into(),
            tree: String::new(),
            queue_binding: None,
            lane_selection: None,
            expectation_source: "caller",
            decision: "refuse",
            outcome: "rejected",
            reason: "source_unbound",
            record: None,
            protected_paths: Vec::new(),
            summary: "queue base and head must be existing full lowercase commit SHAs".into(),
            report_only: true,
            producer_digest: None,
            signer: None,
            observed_at: None,
            age_seconds: None,
            lane_definition_sha256: None,
            input_key_equal: None,
            compared_record: None,
            selective_reuse: None,
            repository_refused: None,
        });
    }
    commit(repo, base)?;
    commit(repo, head)?;
    let tree = git::text(repo, &["rev-parse", &format!("{head}^{{tree}}")])?;
    let config = match config::load(repo, base) {
        Ok(config) => config,
        Err(error) if error.is::<config::MissingConfig>() => {
            return Ok(Decision {
                version: 1,
                check: check.into(),
                base: base.into(),
                head: head.into(),
                tree,
                queue_binding: None,
                lane_selection: None,
                expectation_source: "caller",
                decision: "refuse",
                outcome: "rejected",
                reason: "config_missing",
                record: None,
                protected_paths: Vec::new(),
                summary: error.to_string(),
                report_only: queue,
                producer_digest: None,
                signer: None,
                observed_at: None,
                age_seconds: None,
                lane_definition_sha256: None,
                input_key_equal: None,
                compared_record: None,
                selective_reuse: None,
                repository_refused: None,
            });
        }
        Err(error) => return Err(error),
    };
    let lane = config.policy.lanes.get(check).context("unknown check")?;
    let mut decision = Decision {
        version: 1,
        check: check.into(),
        base: base.into(),
        head: head.into(),
        tree,
        lane_selection: None,
        queue_binding: None,
        expectation_source: "caller",
        decision: if lane.mode == "required_evidence" {
            "refuse"
        } else {
            "run"
        },
        outcome: "rejected",
        reason: "base_not_ancestor",
        record: None,
        protected_paths: Vec::new(),
        summary: String::new(),
        report_only: queue,
        producer_digest: None,
        signer: None,
        observed_at: None,
        age_seconds: None,
        lane_definition_sha256: None,
        input_key_equal: None,
        compared_record: None,
        selective_reuse: None,
        repository_refused: None,
    };
    if queue {
        if event.is_some() {
            decision.refuse((
                "source_unbound",
                "queue reports do not accept --event-file".into(),
            ));
            return Ok(decision);
        }
        match bind_queue(repo, base, head, members, config.policy.queue.as_ref()) {
            Ok((members, projection)) => {
                decision.queue_binding = Some(QueueBinding {
                    base: base.into(),
                    members,
                    tree: decision.tree.clone(),
                    projection,
                });
            }
            Err(error) => {
                decision.refuse(("source_unbound", error.to_string()));
                return Ok(decision);
            }
        }
    }
    if !lane.events.iter().any(|event| event == event_type) {
        decision.reason = "event_not_allowed";
        return Ok(decision);
    }
    if merge_group {
        let payload: serde_json::Value = match event {
            Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
            None => {
                decision.reason = "source_unbound";
                return Ok(decision);
            }
        };
        let string = |pointer| payload.pointer(pointer).and_then(serde_json::Value::as_str);
        let branch = string("/merge_group/base_ref")
            .and_then(|reference| reference.strip_prefix("refs/heads/"));
        let bound = branch
            .filter(|branch| !branch.is_empty())
            .is_some_and(|branch| {
                string("/merge_group/head_ref")
                    .and_then(|reference| reference.strip_prefix("refs/heads/"))
                    .is_some_and(|reference| evidence::signer_input::queue_ref(reference, branch))
            });
        if payload["action"] != "checks_requested"
            || !bound
            || string("/merge_group/head_sha") != Some(head)
            || string("/merge_group/base_sha") != Some(base)
            || !std::env::var("GITHUB_REPOSITORY")
                .ok()
                .is_some_and(|repository| {
                    string("/repository/full_name") == Some(repository.as_str())
                })
        {
            decision.reason = "source_unbound";
            decision.summary = "merge_group must bind repository, head_sha to --head, base_sha to --base, and a valid queue head_ref to base_ref".into();
            return Ok(decision);
        }
    }
    if push {
        let parents = git::text(repo, &["rev-list", "--parents", "-n", "1", head])?;
        let Some(parent) = parents.split_whitespace().nth(1) else {
            decision.reason = "no_parent";
            return Ok(decision);
        };
        if parent != base {
            decision.reason = "base_not_parent";
            return Ok(decision);
        }
        let payload: serde_json::Value = match event {
            Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
            None => {
                decision.reason = "event_not_allowed";
                return Ok(decision);
            }
        };
        if payload
            .pointer("/repository/full_name")
            .and_then(serde_json::Value::as_str)
            != std::env::var("GITHUB_REPOSITORY").ok().as_deref()
        {
            decision.reason = "event_not_allowed";
            return Ok(decision);
        }
    }
    let relation = ancestry_status(repo, base, head, std::time::Duration::from_secs(120))?;
    match relation.status.code() {
        Some(0) => {}
        Some(1) => return Ok(decision),
        _ => anyhow::bail!(
            "ancestry unavailable: {}",
            String::from_utf8_lossy(&relation.stderr)
        ),
    }
    let paths = git::git(
        repo,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            base,
            head,
            "--",
        ],
    )?;
    let mandatory = [".mergemaster/", ".github/workflows/", ".github/actions/"];
    for path in paths.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        let path = std::str::from_utf8(path).context("non-UTF8 changed path")?;
        if mandatory
            .iter()
            .copied()
            .chain(config.policy.protected_paths.iter().map(String::as_str))
            .chain(config.policy.bootstrap_paths.iter().map(String::as_str))
            .any(|prefix| matches_path(path, prefix))
        {
            decision.protected_paths.push(path.to_owned());
        }
    }
    if !push && !merge_group && !queue {
        let merges = git::text(
            repo,
            &[
                "rev-list",
                "--min-parents=2",
                "--parents",
                &format!("{base}..{head}"),
            ],
        )?;
        for merge in merges.lines() {
            for parent in merge.split_whitespace().skip(2) {
                if parent == base {
                    continue;
                }
                let relation =
                    ancestry_status(repo, parent, base, std::time::Duration::from_secs(120))?;
                match relation.status.code() {
                    Some(0) => {}
                    Some(1) => {
                        decision.decision = "refuse";
                        decision.reason = "foreign_merge";
                        return Ok(decision);
                    }
                    _ => anyhow::bail!(
                        "merge parent ancestry unavailable: {}",
                        String::from_utf8_lossy(&relation.stderr)
                    ),
                }
            }
        }
    }
    if !decision.protected_paths.is_empty() && (push || lane.protected_edits == "reject") {
        decision.decision = "refuse";
        decision.reason = "protected_paths";
        return Ok(decision);
    }
    if !push && !merge_group && !queue && !eligible(repo, base, head, event, &config, lane)? {
        decision.reason = "ineligible_event";
        return Ok(decision);
    }
    if !decision.protected_paths.is_empty() {
        decision.decision = "refuse";
        decision.reason = "protected_paths";
        if lane.protected_edits == "human_approval" {
            if queue {
                decision.reason = "human_approval_only";
                return Ok(decision);
            }
            if lane
                .require_hosted
                .iter()
                .any(|required| decision.protected_paths.contains(&required.workflow_path))
            {
                decision.summary =
                    "this PR changes the validate workflow; validate ran the changed file".into();
            }
            decision.reason = approval::evaluate(lane, head, hosted)?;
            if decision.reason == "human_approval_satisfied" {
                decision.decision = "skip";
                decision.outcome = "satisfied";
            }
        }
        return Ok(decision);
    }
    decision.lane_selection = selection::select(repo, base, head, &config.policy)?;
    if !push && !merge_group && !queue
        && decision.lane_selection.as_ref().is_some_and(|selection| !selection.lanes.iter().any(|lane| lane == check))
    {
        // A non-applicable App context still needs an exact-head signed review.
        // review-go is mandatory in `always`, so this cannot recurse again.
        let review = compute(repo, "review-go", base, head, event, hosted, source)?;
        decision.record = review.record;
        decision.signer = review.signer;
        decision.observed_at = review.observed_at;
        decision.age_seconds = review.age_seconds;
        if review.decision == "skip" && review.outcome == "satisfied" {
            decision.decision = "skip";
            decision.outcome = "satisfied";
            decision.reason = "path_not_applicable";
            decision.summary = "BASE path policy excludes this lane; exact-head review-go signs the complete selection.".into();
        } else {
            decision.decision = "refuse";
            decision.reason = "selection_review_required";
            decision.summary = "A non-applicable lane requires accepted exact-head review-go with the BASE selection binding.".into();
        }
        return Ok(decision);
    }
    let (records, malformed, other_tree) = records(repo, &decision.tree)?;
    let mut candidates = Vec::new();
    let mut reuse_attempt = None;
    decision.outcome = "no_note";
    decision.reason = if malformed {
        "invalid_record"
    } else if push && other_tree {
        "tree_mismatch"
    } else {
        "no_record"
    };
    if malformed || (push && other_tree) {
        decision.outcome = "rejected";
    }
    if records.is_empty() {
        config::validate_candidate(repo, head, lane)?;
        return Ok(decision);
    }
    let mut expected = config::expected_inputs(
        repo,
        head,
        check,
        lane,
        &config.environment,
        &config.environment_bytes,
    )?;
    expected.extend(selection::inputs(decision.lane_selection.as_ref())?);
    let mut keys = tempfile::NamedTempFile::new()?;
    keys.write_all(&config.keys)?;
    keys.flush()?;
    for (id, discovery) in records {
        let mut command = Command::new(std::env::current_exe()?);
        git::sanitize(&mut command);
        let output = command
            .arg("gate-verify-record")
            .arg("--repo")
            .arg(repo)
            .arg("--record")
            .arg(&id)
            .arg("--keys")
            .arg(keys.path())
            .arg("--base")
            .arg(base)
            .arg("--check")
            .arg(check)
            .output()?;
        if !output.status.success() {
            decision.reason = "untrusted_signer";
            decision.outcome = "rejected";
            continue;
        }
        let statement = match evidence::verified::worker_statement(&output.stdout, &id)? {
            evidence::verified::WorkerStatement::Legacy(statement) => *statement,
            evidence::verified::WorkerStatement::Selective(diagnostic) => {
                // Preserve the legacy worker rejection without admitting a
                // trusted timestamp or failure into candidate selection.
                reuse_attempt.get_or_insert(diagnostic);
                decision.reason = "untrusted_signer";
                decision.outcome = "rejected";
                continue;
            }
        };
        if let Some(reason) = repository_refusal(
            config.policy.repository.as_deref(),
            statement.repository.as_deref(),
        ) {
            decision.reason = reason;
            decision.outcome = "rejected";
            continue;
        }
        if statement.subject[0].digest.get("gitTree") != Some(&decision.tree) {
            decision.reason = if push { "tree_mismatch" } else { "stale_tree" };
            decision.outcome = "rejected";
            continue;
        }
        let Fact::Tests { ref checks, .. } = statement.predicate.fact else {
            continue;
        };
        if !checks.contains_key(check) {
            decision.reason = "wrong_check";
            continue;
        }
        let at = DateTime::parse_from_rfc3339(&statement.predicate.observed_at)?;
        candidates.push((id, statement, at, discovery));
    }
    // Unsigned degraded observations never shadow trusted records in the oracle.
    if !push
        && candidates
            .iter()
            .any(|c| c.1.predicate.tier != TrustTier::Degraded)
    {
        candidates.retain(|c| c.1.predicate.tier != TrustTier::Degraded);
    }
    // Push keeps newest-trusted selection; PR/queue match the pinned oracle.
    candidates
        .sort_by(|a, b| (a.2, failed(&a.1, check), &a.0).cmp(&(b.2, failed(&b.1, check), &b.0)));
    let judge = |statement: &Statement, at: DateTime<chrono::FixedOffset>| {
        if let Fact::Tests { inputs, .. } = &statement.predicate.fact
            && !execution_claims_valid(lane, &config.environment, inputs)
        {
            return (
                "wrong_input",
                config::producer_digest(config.producers.as_ref(), inputs),
            );
        }
        let (reason, producer_digest) = satisfy(
            (
                statement,
                at,
                config.policy.repository.as_deref(),
                config.producers.as_ref(),
            ),
            check,
            head,
            &decision.tree,
            lane,
            expected.iter(),
            push || queue,
        );
        if !push
            && reason == "wrong_input"
            && let Fact::Tests { inputs, .. } = &statement.predicate.fact
            && inputs.get("lane_definition_sha256") != expected.get("lane_definition_sha256")
            && matches!(
                satisfy(
                    (
                        statement,
                        at,
                        config.policy.repository.as_deref(),
                        config.producers.as_ref(),
                    ),
                    check,
                    head,
                    &decision.tree,
                    lane,
                    expected
                        .iter()
                        .filter(|(key, _)| key.as_str() != "lane_definition_sha256"),
                    queue
                )
                .0,
                "satisfied" | "execution_reused"
            )
        {
            ("wrong_definition", producer_digest)
        } else {
            (reason, producer_digest)
        }
    };
    let selected = if push {
        None
    } else {
        candidates
            .iter()
            .enumerate()
            .filter(|(_, (_, statement, at, _))| {
                !failed(statement, check)
                    && lane.trust_levels.iter().any(|level| {
                        Some(level.as_str())
                            == statement
                                .predicate
                                .signer
                                .as_deref()
                                .and_then(|s| s.split('/').next())
                    })
                    && judge(statement, *at).0 != "wrong_definition"
            })
            .max_by(|(_, a), (_, b)| a.2.cmp(&b.2).then_with(|| (b.3, &b.0).cmp(&(a.3, &a.0))))
            .map(|(index, _)| {
                let reason = judge(&candidates[index].1, candidates[index].2);
                if matches!(reason.0, "satisfied" | "execution_reused")
                    && let Some(failure) = candidates.iter().rposition(|c| {
                        failed(&c.1, check) && c.2 >= candidates[index].2 - Duration::seconds(120)
                    })
                {
                    let (_, producer_digest) = judge(&candidates[failure].1, candidates[failure].2);
                    (failure, ("check_failed", producer_digest))
                } else {
                    (index, reason)
                }
            })
    };
    let Some(mut chosen) = (if let Some((index, _)) = selected {
        Some(candidates.remove(index))
    } else {
        candidates.pop()
    }) else {
        decision.selective_reuse = reuse_attempt;
        return Ok(decision);
    };
    if selected.is_none()
        && !failed(&chosen.1, check)
        && let Some(index) = candidates
            .iter()
            .rposition(|c| failed(&c.1, check) && c.2 >= chosen.2 - Duration::seconds(120))
    {
        chosen = candidates.remove(index);
    }
    decision.record = Some(chosen.0);
    decision.outcome = "rejected";
    let statement = chosen.1;
    decision.signer = statement.predicate.signer.clone();
    decision.observed_at = Some(statement.predicate.observed_at.clone());
    decision.age_seconds = Some((Utc::now() - chosen.2.with_timezone(&Utc)).num_seconds());
    if let Fact::Tests { inputs, .. } = &statement.predicate.fact {
        decision.lane_definition_sha256 = inputs.get("lane_definition_sha256").cloned();
    }
    let (reason, producer_digest) =
        selected.map_or_else(|| judge(&statement, chosen.2), |(_, result)| result);
    decision.reason = reason;
    decision.producer_digest = Some(producer_digest);
    if matches!(decision.reason, "satisfied" | "execution_reused") {
        decision.decision = "skip";
        decision.outcome = "satisfied";
        if decision.reason == "execution_reused" {
            decision.outcome = "reused";
            decision.summary =
                "A trusted realization was reused; no fresh test execution is asserted.".into();
        }
    } else if decision.reason == "degraded" {
        decision.outcome = "degraded";
    }
    Ok(decision)
}

fn normalized_changed_path(path: &str) -> String {
    // Diff paths are not policy: preserve compatibility aliases (including
    // fullwidth dots/separators) and case-insensitive checkout protection.
    path.nfkc().flat_map(char::to_lowercase).collect()
}

fn path_within(path: &str, prefix: &str) -> bool {
    component_within(path, prefix.trim_end_matches('/'))
}

fn generated_matches(path: &str, pattern: &str) -> bool {
    if let Some((prefix, suffix)) = pattern.split_once("/*") {
        path.strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|rest| rest.strip_suffix(suffix))
            .is_some_and(|matched| !matched.is_empty())
    } else {
        path_within(path, pattern)
    }
}

fn component_within(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn matches_path(path: &str, prefix: &str) -> bool {
    let path = normalized_changed_path(path);
    let prefix = prefix.to_ascii_lowercase();
    let prefix = prefix.trim_end_matches('/');
    component_within(&path, prefix) || component_within(prefix, &path)
}

fn failed(statement: &Statement, check: &str) -> bool {
    matches!(&statement.predicate.fact, Fact::Tests {checks, ..} if checks[check].exit_code != 0)
}

fn execution_claims_valid(
    lane: &Lane,
    environment: &config::Environment,
    inputs: &BTreeMap<String, String>,
) -> bool {
    if lane.nix_check.is_some()
        || (!lane.direct_exec
            && (!lane
                .argv
                .first()
                .is_some_and(|arg| Path::new(arg).is_absolute())
                || !environment.systems.values().any(|toolchain| {
                    std::iter::once(&toolchain.runtime)
                        .chain(toolchain.dependencies.values())
                        .any(|artifact| artifact.identity.starts_with("nix:"))
                })))
    {
        return true;
    }
    let Some(toolchain) = environment.systems.get(&config::current_system()) else {
        return false;
    };
    let artifacts = || std::iter::once(&toolchain.runtime).chain(toolchain.dependencies.values());
    if !lane.direct_exec && !artifacts().any(|artifact| artifact.identity.starts_with("nix:")) {
        return true;
    }
    inputs.get("executed_executable").is_some_and(|path| {
        Path::new(path).is_absolute()
            && !Path::new(path)
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
    }) && inputs.get("executed_artifact").is_some_and(|identity| {
        identity.starts_with("nix:")
            && artifacts().any(|artifact| &artifact.identity == identity)
            && (!lane.direct_exec || identity == &toolchain.runtime.identity)
            && inputs.contains_key(&format!("nix_closure_sha256:{identity}"))
    })
}

// The accepted-base policy is authoritative; neither the candidate nor ambient
// environment may choose or normalize the identity signed into a record.
fn repository_refusal(repository: Option<&str>, signed: Option<&str>) -> Option<&'static str> {
    let expected = repository?;
    match signed {
        None => Some("repository_unbound"),
        Some(actual) if actual != expected => Some("repository_mismatch"),
        Some(_) => None,
    }
}

fn satisfy<'a>(
    (statement, at, repository, producers): (
        &Statement,
        DateTime<chrono::FixedOffset>,
        Option<&str>,
        Option<&config::ProducerManifest>,
    ),
    check: &str,
    head: &str,
    tree: &str,
    lane: &Lane,
    mut expected: impl Iterator<Item = (&'a String, &'a String)>,
    push: bool,
) -> (&'static str, config::ProducerDigest) {
    let producer_digest = match &statement.predicate.fact {
        Fact::Tests { inputs, .. } => config::producer_digest(producers, inputs),
        _ => config::ProducerDigest::NotApplicable,
    };
    let result = |reason| (reason, producer_digest);
    if let Some(reason) = repository_refusal(repository, statement.repository.as_deref()) {
        return result(reason);
    }
    let predicate = &statement.predicate;
    if predicate.tier == TrustTier::Degraded {
        return result("degraded");
    }
    if predicate.tier != TrustTier::Full {
        return result("untrusted_tier");
    }
    if (!push && statement.subject[0].name != head) || (push && !oid(&statement.subject[0].name)) {
        return result("wrong_commit");
    }
    if statement.subject[0]
        .digest
        .get("gitTree")
        .map(String::as_str)
        != Some(tree)
    {
        return result("stale_tree");
    }
    let principal = predicate.signer.as_deref().unwrap_or("");
    if !lane
        .trust_levels
        .iter()
        .any(|level| level == principal.split('/').next().unwrap_or(""))
    {
        return result("untrusted_level");
    }
    let now = Utc::now();
    if at > now + Duration::seconds(120) {
        return result("future_dated");
    }
    if lane
        .max_age_seconds
        .is_some_and(|seconds| age_exceeds_limit(now - at.with_timezone(&Utc), seconds))
    {
        return result("too_old");
    }
    let Fact::Tests {
        runner,
        checks,
        inputs,
    } = &predicate.fact
    else {
        return result("wrong_check");
    };
    // Match the pinned verifier's producer kinds, without narrowing the record format.
    if !matches!(runner.as_str(), "nix" | "wrapper" | "sekrets") && !runner.starts_with("github:") {
        return result("unsupported_kind");
    }
    let observed = &checks[check];
    if observed.exit_code != 0 {
        return result("check_failed");
    }
    if lane.nix_check.is_some() {
        let Some(drv) = inputs.get("nix_derivation") else {
            return result("wrong_input");
        };
        let Some(execution) = inputs.get("nix_execution") else {
            return result("wrong_input");
        };
        if inputs.get("nix_command_mode") != Some(execution)
            || evidence::derivation::settings_digest().ok().as_ref()
                != inputs.get("nix_settings_sha256")
            || !inputs.get("nix_store").is_some_and(|store| {
                store.starts_with("local")
                    || (store.starts_with("daemon")
                        && inputs.get("nix_daemon_trusted").map(String::as_str) == Some("true"))
            })
        {
            return result("wrong_input");
        }
        let Ok(argv) = evidence::derivation::argv(&lane.argv[0], drv, execution) else {
            return result("wrong_input");
        };
        if observed.command != argv {
            return result("wrong_command");
        }
        if evidence::derivation::command_digest(&argv).ok().as_ref()
            != inputs.get("nix_command_sha256")
            || !inputs
                .get("nix_outputs_sha256")
                .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            return result("wrong_input");
        }
    } else if observed.command != lane.argv {
        return result("wrong_command");
    }
    if !inputs.get("wrapper_sha256").is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }) || !inputs
        .get("attempt")
        .is_some_and(|value| value.parse::<u64>().is_ok_and(|n| n > 0))
    {
        return result("wrong_input");
    }
    if inputs.get("workspace_clean").map(String::as_str) != Some("true")
        || inputs.get("untracked_files").map(String::as_str) != Some("false")
    {
        return result("workspace_dirty");
    }
    if expected.any(|(key, value)| inputs.get(key) != Some(value)) {
        return result("wrong_input");
    }
    if let Some(check) = &lane.nix_check
        && inputs.get("nix_execution").map(String::as_str) == Some("reused")
    {
        return result(if check.required == "any" {
            "execution_reused"
        } else {
            "fresh_execution_required"
        });
    }
    result("satisfied")
}

fn age_exceeds_limit(elapsed: Duration, seconds: u64) -> bool {
    elapsed
        .to_std()
        .is_ok_and(|age| age > std::time::Duration::from_secs(seconds))
}

fn records(repo: &Path, tree: &str) -> Result<(BTreeMap<String, u8>, bool, bool)> {
    let refs = git::text(
        repo,
        &[
            "for-each-ref",
            "--format=%(refname) %(objectname)",
            "refs/notes/evidence/",
            "refs/tags/evidence/",
        ],
    )?;
    let mut found = BTreeMap::<String, u8>::new();
    let mut malformed = false;
    let mut other_tree = false;
    for line in refs.lines() {
        let (name, value) = line.split_once(' ').context("evidence ref listing")?;
        let suffix = name
            .strip_prefix("refs/notes/evidence/")
            .or_else(|| name.strip_prefix("refs/tags/evidence/"))
            .context("evidence namespace")?;
        let parts: Vec<_> = suffix.split('/').collect();
        let id = match parts.as_slice() {
            [id] if name.starts_with("refs/notes/") => *id,
            [scope, id] if *scope == tree => *id,
            // Namespace hints affect only the refusal diagnostic, never authority.
            [scope, _] if oid(scope) => {
                other_tree = true;
                continue;
            }
            _ => continue,
        };
        if !oid(id) || id != value {
            malformed = true;
            continue;
        }
        // Oracle discovery: tree tags, tree notes, then legacy notes; aliases
        // retain their earliest namespace, with ascending IDs within each.
        let discovery = if parts.len() == 1 {
            2
        } else if name.starts_with("refs/tags/") {
            0
        } else {
            1
        };
        found
            .entry(id.to_owned())
            .and_modify(|prior| *prior = (*prior).min(discovery))
            .or_insert(discovery);
    }
    Ok((found, malformed, other_tree))
}

fn eligible(
    repo: &Path,
    base: &str,
    head: &str,
    event: Option<&Path>,
    config: &Config,
    lane: &Lane,
) -> Result<bool> {
    let mut identities = Vec::new();
    if let Some(path) = event {
        let event: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
        let string = |pointer| event.pointer(pointer).and_then(serde_json::Value::as_str);
        let repository = std::env::var("GITHUB_REPOSITORY")
            .context("event verification requires trusted GITHUB_REPOSITORY")?;
        if string("/pull_request/head/sha") != Some(head)
            || string("/repository/full_name") != Some(repository.as_str())
            || string("/pull_request/head/repo/full_name") != Some(repository.as_str())
            || string("/pull_request/base/repo/full_name") != Some(repository.as_str())
        {
            return Ok(false);
        }
        let Some(event_base) = string("/pull_request/base/sha") else {
            return Ok(false);
        };
        if !oid(event_base)
            || git::text(repo, &["merge-base", event_base, base])
                .ok()
                .as_deref()
                != Some(event_base)
        {
            return Ok(false);
        }
        identities.push(string("/pull_request/user/login").unwrap_or("").to_owned());
        identities.push(std::env::var("GITHUB_ACTOR").unwrap_or_default());
        identities.push(std::env::var("GITHUB_TRIGGERING_ACTOR").unwrap_or_default());
    }
    if !lane.events.iter().any(|event| event == "pull_request") {
        return Ok(false);
    }
    if let Authors::Allowlist {
        logins,
        git_authors,
        git_committers,
    } = &config.policy.pull_request.authors
    {
        if event.is_none()
            || identities
                .iter()
                .any(|login| login.is_empty() || !logins.contains(login))
        {
            return Ok(false);
        }
        let commits = git::text(
            repo,
            &[
                "log",
                "--format=%an <%ae>%x00%cn <%ce>",
                &format!("{base}..{head}"),
            ],
        )?;
        for line in commits.lines() {
            let Some((author, committer)) = line.split_once('\0') else {
                return Ok(false);
            };
            if !git_authors.iter().any(|v| v == author)
                || !git_committers.iter().any(|v| v == committer)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn compare(repo: &Path, args: &Args, head: &str, decision: &mut Decision) -> Result<()> {
    commit(repo, head)?;
    if matches!(
        decision.reason,
        "source_unbound" | "config_missing" | "event_not_allowed"
    ) {
        return Ok(());
    }
    let config = config::load(repo, &args.base)?;
    let lane = &config.policy.lanes[&args.check];
    let expected = |head| {
        config::expected_inputs(
            repo,
            head,
            &args.check,
            lane,
            &config.environment,
            &config.environment_bytes,
        )
    };
    decision.input_key_equal = Some(expected(head)? == expected(&args.head)?);
    let tree = git::text(repo, &["rev-parse", &format!("{head}^{{tree}}")])?;
    let mut keys = tempfile::NamedTempFile::new()?;
    keys.write_all(&config.keys)?;
    keys.flush()?;
    let mut newest = None;
    let mut repository_refused = 0;
    for (id, _) in records(repo, &tree)?.0 {
        let mut command = Command::new(std::env::current_exe()?);
        git::sanitize(&mut command);
        let output = command
            .arg("gate-verify-record")
            .arg("--repo")
            .arg(repo)
            .arg("--record")
            .arg(&id)
            .arg("--keys")
            .arg(keys.path())
            .arg("--base")
            .arg(&args.base)
            .arg("--check")
            .arg(&args.check)
            .output()?;
        if !output.status.success() {
            continue;
        }
        let Some(statement) = evidence::verified::legacy_worker_statement(&output.stdout, &id)?
        else {
            continue;
        };
        if repository_refusal(
            config.policy.repository.as_deref(),
            statement.repository.as_deref(),
        )
        .is_some()
        {
            repository_refused += 1;
            continue;
        }
        let predicate = &statement.predicate;
        if statement.subject[0].digest.get("gitTree") != Some(&tree)
            || predicate.tier != TrustTier::Full
            || !lane.trust_levels.iter().any(|level| {
                predicate
                    .signer
                    .as_deref()
                    .unwrap_or("")
                    .starts_with(&format!("{level}/"))
            })
            || !matches!(&predicate.fact, Fact::Tests { checks, .. } if checks.contains_key(&args.check))
        {
            continue;
        }
        let at = DateTime::parse_from_rfc3339(&predicate.observed_at)?;
        if newest
            .as_ref()
            .is_none_or(|(previous, previous_id, _)| (at, &id) > (*previous, previous_id))
        {
            newest = Some((at, id, statement));
        }
    }
    decision.repository_refused = Some(repository_refused);
    decision.compared_record = newest.map(|(at, _, statement)| ComparedRecord {
        tree,
        signer: statement.predicate.signer,
        observed_at: statement.predicate.observed_at,
        age_seconds: (Utc::now() - at.with_timezone(&Utc)).num_seconds(),
    });
    Ok(())
}

#[cfg(test)]
mod repository_tests {
    use super::repository_refusal;

    #[test]
    fn repository_binding_requires_byte_exact_identity_for_every_single_byte_mutation() {
        let expected = "Owner/Name";
        assert_eq!(repository_refusal(Some(expected), Some(expected)), None);
        assert_eq!(
            repository_refusal(Some(expected), None),
            Some("repository_unbound")
        );
        assert_eq!(repository_refusal(None, None), None);
        for index in 0..expected.len() {
            for replacement in b'-'..=b'z' {
                if !replacement.is_ascii_alphanumeric() && !b"-_./".contains(&replacement) {
                    continue;
                }
                let mut changed = expected.as_bytes().to_vec();
                changed[index] = replacement;
                let changed = std::str::from_utf8(&changed).unwrap();
                assert_eq!(
                    repository_refusal(Some(expected), Some(changed)),
                    (changed != expected).then_some("repository_mismatch"),
                    "{changed}"
                );
                assert_eq!(repository_refusal(None, Some(changed)), None);
            }
        }
    }
}

#[cfg(test)]
mod age_tests {
    use super::*;

    #[test]
    fn exact_limit_is_allowed_but_one_microsecond_over_is_expired() {
        let limit = Duration::seconds(60);
        assert!(!age_exceeds_limit(limit, 60));
        assert!(age_exceeds_limit(limit + Duration::microseconds(1), 60));
        assert!(!age_exceeds_limit(limit - Duration::microseconds(1), 60));
        assert!(!age_exceeds_limit(Duration::seconds(-1), 60));
        assert!(!age_exceeds_limit(limit, u64::MAX));
    }
}

fn ancestry_status(
    repo: &Path,
    base: &str,
    head: &str,
    timeout: std::time::Duration,
) -> Result<std::process::Output> {
    Ok(git::deadline::GitChild::capture(
        git::command(repo).args(["merge-base", "--is-ancestor", base, head]),
        None,
        timeout,
    )?)
}

#[cfg(test)]
mod ancestry_tests {
    use super::*;

    #[test]
    fn ancestry_deadline_preserves_status_stderr_and_expiry() {
        let repo = tempfile::tempdir().unwrap();
        git::git(repo.path(), &["init", "-q"]).unwrap();
        let mut commits = Vec::new();
        for message in ["first", "second"] {
            git::git(
                repo.path(),
                &[
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    message,
                ],
            )
            .unwrap();
            commits.push(git::text(repo.path(), &["rev-parse", "HEAD"]).unwrap());
        }
        for (base, head, code) in [
            (commits[0].as_str(), commits[1].as_str(), 0),
            (commits[1].as_str(), commits[0].as_str(), 1),
            ("invalid", commits[0].as_str(), 128),
        ] {
            let output =
                ancestry_status(repo.path(), base, head, std::time::Duration::from_secs(120))
                    .unwrap();
            assert_eq!(output.status.code(), Some(code));
            if code == 128 {
                assert!(!output.stderr.is_empty());
            }
        }
        let error = ancestry_status(
            repo.path(),
            &commits[0],
            &commits[1],
            std::time::Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::TimedOut
        );
    }
}
