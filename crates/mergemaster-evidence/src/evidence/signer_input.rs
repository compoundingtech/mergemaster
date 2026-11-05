//! Pure BASE-only signer boundary: authenticated API data and Git objects, never payload execution.
use super::producer_proof::{self, Bindings, Expected, Receipt};
use anyhow::{Context, Result, ensure};
use jsonwebtoken::jwk::JwkSet;
use serde_json::Value;

/// Read only from the accepted BASE, including the immutable reusable engine pin.
#[derive(Clone, Debug)]
pub struct BasePolicy {
    pub repository: String,
    pub repository_id: u64,
    pub owner_id: u64,
    pub protected_branch: String,
    pub workflow_id: u64,
    pub workflow_path: String,
    pub workflow_sha256: String,
    pub job_workflow_ref: String,
    pub job_workflow_sha: String,
    pub lane: String,
    pub lane_sha256: String,
    pub environment_sha256: String,
    pub recipe_sha256: String,
    pub action_backends: Vec<String>,
}

/// Selectors established by the trusted controller, never by receipt/JWT contents.
#[derive(Clone, Debug)]
pub struct Selection { pub run_id: u64, pub run_attempt: u64, pub check_run_id: u64, pub artifact_id: u64 }

/// API values MUST be authenticated GitHub responses: attempt-specific run, all pages
/// of that attempt's jobs (one combined array/total_count), artifact metadata, and a
/// fresh current-run response to detect racing reruns. Recheck immediately before signing.
/// Candidate commit/tree MUST be resolved together from Git; archive_sha256 is the
/// independently hashed downloaded archive. None of these may originate in a receipt.
pub struct SignerInput<'a> {
    pub run: &'a Value,
    pub current_run: &'a Value,
    pub jobs: &'a Value,
    pub artifact: &'a Value,
    pub accepted_base: &'a str,
    pub candidate_sha: &'a str,
    pub candidate_tree: &'a str,
    pub archive_sha256: &'a str,
}

#[derive(Debug)]
pub struct VerifiedSignerInput {
    pub receipt: Receipt,
    pub job_id: u64,
    /// Independently observed API conclusion, not the receipt's asserted result.
    pub conclusion: String,
}

pub fn derive_expected(p: &BasePolicy, s: &Selection, i: &SignerInput<'_>) -> Result<Expected> {
    ensure!(p.repository_id > 0 && p.owner_id > 0 && s.run_id > 0, "foreign_run: zero selector");
    for run in [i.run, i.current_run] {
        ensure!(run["id"].as_u64() == Some(s.run_id)
            && run["repository"]["id"].as_u64() == Some(p.repository_id)
            && run["repository"]["owner"]["id"].as_u64() == Some(p.owner_id)
            && run["repository"]["full_name"].as_str() == Some(&p.repository), "foreign_run");
        ensure!(s.run_attempt > 0 && run["run_attempt"].as_u64() == Some(s.run_attempt), "wrong_attempt");
    }
    let run = i.run;
    ensure!(p.workflow_id > 0 && run["workflow_id"].as_u64() == Some(p.workflow_id)
        && run["path"].as_str() == Some(&p.workflow_path)
        && git_hash(&p.job_workflow_sha)
        && p.job_workflow_ref.rsplit_once('@').map(|(_, sha)| sha) == Some(p.job_workflow_sha.as_str())
        && run["referenced_workflows"].as_array().is_some_and(|refs| refs.iter().any(|r|
            r["path"].as_str() == Some(&p.job_workflow_ref) && r["sha"].as_str() == Some(&p.job_workflow_sha))), "wrong_recipe");
    let event = run["event"].as_str().context("source_unbound: event")?;
    let mapped = match event {
        // PR head SHA is not its OIDC merge SHA; no inferred equivalence.
        "push" => true,
        "merge_group" => run["head_branch"].as_str().is_some_and(|r|
            queue_ref(r, &p.protected_branch)),
        _ => false,
    };
    ensure!(mapped && run["head_repository"]["id"].as_u64() == Some(p.repository_id)
        && run["head_sha"].as_str() == Some(i.candidate_sha)
        && [i.accepted_base, i.candidate_sha, i.candidate_tree].iter().all(|v| git_hash(v)), "source_unbound");
    let jobs = i.jobs["jobs"].as_array().context("wrong_job: jobs")?;
    ensure!(i.jobs["total_count"].as_u64() == Some(jobs.len() as u64), "wrong_job: incomplete jobs");
    let url = format!("https://api.github.com/repos/{}/check-runs/{}", p.repository, s.check_run_id);
    let mut matching = jobs.iter().filter(|j| j["check_run_url"].as_str() == Some(&url));
    let job = matching.next().context("wrong_job: missing check run")?;
    ensure!(s.check_run_id > 0 && matching.next().is_none() && job["id"].as_u64().is_some_and(|id| id > 0)
        && job["run_id"].as_u64() == Some(s.run_id), "wrong_job");
    ensure!(job["run_attempt"].as_u64() == Some(s.run_attempt), "wrong_attempt: job");
    ensure!(job["status"] == "completed" && job["conclusion"] == "success", "payload_failed");
    let artifact = i.artifact;
    ensure!(s.artifact_id > 0 && artifact["id"].as_u64() == Some(s.artifact_id)
        && artifact["workflow_run"]["id"].as_u64() == Some(s.run_id)
        && artifact["workflow_run"]["repository_id"].as_u64() == Some(p.repository_id)
        && artifact["expired"] == false, "artifact_unbound");
    let digest = artifact["digest"].as_str().context("artifact_unbound: missing digest")?;
    let digest = digest.strip_prefix("sha256:").context("artifact_digest_mismatch: algorithm")?;
    ensure!(digest.len() == 64 && lower_hex(digest) && digest == i.archive_sha256, "artifact_digest_mismatch");
    Ok(Expected {
        bindings: Bindings {
            accepted_base: i.accepted_base.into(), artifact_id: s.artifact_id, artifact_sha256: digest.into(),
            candidate_sha: i.candidate_sha.into(), candidate_tree: i.candidate_tree.into(), check_run_id: s.check_run_id,
            environment_sha256: p.environment_sha256.clone(), job_id: job["id"].as_u64().context("wrong_job")?,
            lane: p.lane.clone(), lane_sha256: p.lane_sha256.clone(), owner_id: p.owner_id,
            recipe_sha256: p.recipe_sha256.clone(), repository: p.repository.clone(), repository_id: p.repository_id,
            run_attempt: s.run_attempt, run_id: s.run_id, workflow_path: p.workflow_path.clone(), workflow_sha256: p.workflow_sha256.clone(),
        },
        job_workflow_ref: p.job_workflow_ref.clone(), job_workflow_sha: p.job_workflow_sha.clone(),
        oidc_sha: i.candidate_sha.into(), event: event.into(), action_backends: p.action_backends.clone(),
    })
}

/// Does not sign, provision keys, execute artifacts, or grant automated gate trust.
pub fn verify_signer_input(bytes: &[u8], jwt: &str, jwks: &JwkSet, policy: &BasePolicy, selection: &Selection, input: &SignerInput<'_>) -> Result<VerifiedSignerInput> {
    let expected = derive_expected(policy, selection, input)?;
    let receipt = producer_proof::verify(bytes, jwt, jwks, &expected)?;
    Ok(VerifiedSignerInput { receipt, job_id: expected.bindings.job_id, conclusion: "success".into() })
}

fn lower_hex(v: &str) -> bool { v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn git_hash(v: &str) -> bool { matches!(v.len(), 40 | 64) && lower_hex(v) }

fn queue_ref(value: &str, branch: &str) -> bool {
    value.strip_prefix("gh-readonly-queue/").and_then(|v| v.strip_prefix(branch))
        .and_then(|v| v.strip_prefix("/pr-")).and_then(|v| v.split_once('-'))
        .is_some_and(|(number, sha)| !number.is_empty() && !number.starts_with('0')
            && number.bytes().all(|b| b.is_ascii_digit()) && git_hash(sha))
}
