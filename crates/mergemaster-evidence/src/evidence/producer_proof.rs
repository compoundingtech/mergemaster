//! Authenticate a canonical producer receipt with GitHub's job-scoped OIDC proof.

use anyhow::{Context, Result, ensure};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header, get_current_timestamp, jwk::JwkSet,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const AUDIENCE: &str = "urn:mergemaster:payload-receipt:v1:sha256:";

// Declaration order is canonical v1's lexicographic key order. Maps are sorted too.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub action_keys: BTreeMap<String, String>,
    pub bindings: Bindings,
    pub log_sha256: String,
    pub manifest_sha256: String,
    pub result: Outcome,
    pub schema_version: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
    pub accepted_base: String,
    pub artifact_id: u64,
    pub artifact_sha256: String,
    pub candidate_sha: String,
    pub candidate_tree: String,
    pub check_run_id: u64,
    pub environment_sha256: String,
    pub job_id: u64,
    pub lane: String,
    pub lane_sha256: String,
    pub owner_id: u64,
    pub recipe_sha256: String,
    pub repository: String,
    pub repository_id: u64,
    pub run_attempt: u64,
    pub run_id: u64,
    pub workflow_path: String,
    pub workflow_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
}

/// Trusted caller inputs: derive from protected policy, Git objects and authenticated
/// attempt-specific run/jobs/artifact APIs, never from the receipt or its JWT.
#[derive(Clone, Debug)]
pub struct Expected {
    pub bindings: Bindings,
    pub job_workflow_ref: String,
    pub job_workflow_sha: String,
    /// Independently established event-to-candidate mapping; not necessarily candidate_sha.
    pub oidc_sha: String,
    pub event: String,
    /// Sorted, unique BASE-declared action-key backend names.
    pub action_backends: Vec<String>,
}

#[derive(Clone, Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    exp: u64,
    nbf: u64,
    iat: u64,
    repository: String,
    repository_id: String,
    repository_owner_id: String,
    run_id: String,
    run_attempt: String,
    check_run_id: String,
    job_workflow_ref: String,
    job_workflow_sha: String,
    event_name: String,
    sha: String,
}

/// Authenticate producer assertions, not their truth or a passing job conclusion.
/// `jwks` MUST come only from JWKS_URL via authenticated HTTPS, never artifact data
/// or token-selected URLs. This function performs no network I/O and grants no gate trust.
pub fn verify(bytes: &[u8], jwt: &str, jwks: &JwkSet, expected: &Expected) -> Result<Receipt> {
    ensure!(
        bytes.len() <= 64 * 1024 && jwt.len() <= 64 * 1024,
        "identity_unbound: proof too large"
    );
    let receipt: Receipt = serde_json::from_slice(bytes).context("identity_unbound: receipt")?;
    ensure!(
        receipt.schema_version == 1 && serde_json::to_vec(&receipt)? == bytes,
        "identity_unbound: noncanonical receipt"
    );
    let audience = format!("{AUDIENCE}{}", hex::encode(Sha256::digest(bytes)));
    let header = decode_header(jwt).context("oidc_invalid")?;
    ensure!(header.alg == Algorithm::RS256, "oidc_invalid: algorithm");
    let kid = header.kid.context("oidc_invalid: missing kid")?;
    let mut keys = jwks
        .keys
        .iter()
        .filter(|key| key.common.key_id.as_deref() == Some(kid.as_str()));
    let key = keys.next().context("oidc_invalid: unknown kid")?;
    ensure!(keys.next().is_none(), "oidc_invalid: ambiguous kid");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 0;
    validation.validate_nbf = true;
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[&audience]);
    let claims = decode::<Claims>(
        jwt,
        &DecodingKey::from_jwk(key).context("oidc_invalid")?,
        &validation,
    )
    .context("oidc_invalid")?
    .claims;
    let now = get_current_timestamp();
    ensure!(
        claims.iss == ISSUER
            && claims.aud == audience
            && claims.iat <= now
            && now < claims.exp
            && claims.nbf <= now
            && claims.nbf <= claims.iat
            && claims.iat < claims.exp,
        "oidc_invalid: claims/time"
    );
    let b = &receipt.bindings;
    ensure!(
        b.artifact_id > 0 && b.job_id > 0,
        "identity_unbound: zero API selector"
    );
    ensure!(
        claims.repository == b.repository
            && id(&claims.repository_id, b.repository_id)
            && id(&claims.repository_owner_id, b.owner_id)
            && id(&claims.run_id, b.run_id),
        "foreign_run"
    );
    ensure!(id(&claims.run_attempt, b.run_attempt), "wrong_attempt");
    ensure!(id(&claims.check_run_id, b.check_run_id), "wrong_job");
    ensure!(
        claims.job_workflow_ref == expected.job_workflow_ref
            && claims.job_workflow_sha == expected.job_workflow_sha
            && expected
                .job_workflow_ref
                .rsplit_once('@')
                .map(|(_, sha)| sha)
                == Some(expected.job_workflow_sha.as_str())
            && git_hash(&expected.job_workflow_sha),
        "wrong_recipe: immutable workflow"
    );
    ensure!(
        claims.event_name == expected.event && claims.sha == expected.oidc_sha,
        "source_unbound"
    );
    let e = &expected.bindings;
    ensure!(
        b.repository == e.repository
            && b.repository_id == e.repository_id
            && b.owner_id == e.owner_id
            && b.run_id == e.run_id,
        "foreign_run"
    );
    ensure!(b.run_attempt == e.run_attempt, "wrong_attempt");
    ensure!(
        b.job_id == e.job_id && b.check_run_id == e.check_run_id,
        "wrong_job"
    );
    ensure!(
        b.candidate_sha == e.candidate_sha && b.candidate_tree == e.candidate_tree,
        "tree_mismatch"
    );
    ensure!(
        b.artifact_id == e.artifact_id && b.artifact_sha256 == e.artifact_sha256,
        "artifact_unbound"
    );
    ensure!(b == e, "wrong_recipe");
    ensure!(
        git_hash(&b.accepted_base)
            && git_hash(&b.candidate_sha)
            && git_hash(&b.candidate_tree)
            && [
                &b.artifact_sha256,
                &b.environment_sha256,
                &b.lane_sha256,
                &b.recipe_sha256,
                &b.workflow_sha256,
                &receipt.log_sha256,
                &receipt.manifest_sha256
            ]
            .iter()
            .all(|hash| hash.len() == 64 && lower_hex(hash)),
        "identity_unbound: malformed digest"
    );
    ensure!(
        !receipt.action_keys.is_empty()
            && receipt
                .action_keys
                .keys()
                .eq(expected.action_backends.iter())
            && receipt
                .action_keys
                .iter()
                .all(|(backend, key)| !backend.is_empty() && !key.is_empty()),
        "action_keys_unbound"
    );
    Ok(receipt)
}

fn id(claim: &str, expected: u64) -> bool {
    expected > 0 && claim.parse::<u64>().ok() == Some(expected)
}
fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn git_hash(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && lower_hex(value)
}

#[cfg(test)]
#[path = "producer_proof_tests.rs"]
mod tests;
