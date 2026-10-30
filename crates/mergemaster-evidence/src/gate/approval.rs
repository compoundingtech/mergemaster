//! Offline evaluation of authenticated publisher-fetched GitHub evidence.
use std::{collections::BTreeMap, path::Path};
use anyhow::{Result, ensure};
use serde::Deserialize;
use super::config::Lane;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    version: u32,
    repository: String,
    head: String,
    reviews: Vec<Review>,
    checks: Vec<Check>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    id: u64,
    user: User,
    state: String,
    commit_id: String,
    submitted_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct User { login: String }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    name: String,
    head_sha: String,
    status: String,
    conclusion: Option<String>,
    workflow_run: Run,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    id: u64,
    workflow_id: u64,
    path: String,
    head_sha: String,
    event: String,
}

/// The file is trusted job input, not content from the candidate repository.
/// It never executes or fetches anything. Missing evidence is a refusal.
pub fn evaluate(lane: &Lane, head: &str, file: Option<&Path>) -> Result<&'static str> {
    let Some(file) = file else { return Ok("approval_evidence_missing") };
    let evidence: Evidence = serde_json::from_slice(&std::fs::read(file)?)?;
    let repository = std::env::var("GITHUB_REPOSITORY")?;
    ensure!(evidence.version == 1 && evidence.repository == repository && evidence.head == head,
        "hosted evidence does not match trusted repository and exact head");
    // A dismissed approval or a subsequent change request revokes approval.
    // A comment-only review does not revoke an existing approval.
    let mut latest = BTreeMap::new();
    for review in &evidence.reviews {
        ensure!(review.id > 0 && chrono::DateTime::parse_from_rfc3339(&review.submitted_at).is_ok(),
            "invalid review identity or timestamp");
        if !lane.approvers.iter().any(|login| login.eq_ignore_ascii_case(&review.user.login))
            || matches!(review.state.as_str(), "COMMENTED" | "PENDING") { continue; }
        let login = review.user.login.to_ascii_lowercase();
        let previous = latest.entry(login).or_insert(review);
        if review.id > previous.id { *previous = review; }
    }
    if !latest.values().any(|review| review.state == "APPROVED" && review.commit_id == head) {
        return Ok("human_approval_missing");
    }
    for required in &lane.require_hosted {
        if !evidence.checks.iter().any(|check| check.name == required.name
            && check.head_sha == head && check.status == "completed"
            && check.conclusion.as_deref() == Some("success")
            && check.workflow_run.id > 0 && check.workflow_run.workflow_id == required.workflow_id
            && check.workflow_run.path == required.workflow_path
            && check.workflow_run.head_sha == head && check.workflow_run.event == "pull_request") {
            return Ok("hosted_check_missing");
        }
    }
    Ok("human_approval_satisfied")
}
