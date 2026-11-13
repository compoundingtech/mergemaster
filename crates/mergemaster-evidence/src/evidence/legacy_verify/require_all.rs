//! Complete require-all aggregation; global errors never return partial results.
use super::{Failure, configured, inputs::SystemClock, lane_git, prefix::Request, statement};
use crate::evidence::legacy_policy::{PolicyDocument, PolicyError, RequireMode, check_names};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Ok,
    WouldReject,
    Reject,
}
pub struct Record {
    pub record: String,
    pub signer: String,
    pub tier: Vec<u32>,
}
pub struct Lane {
    pub require: RequireMode,
    pub outcome: Result<Record, Failure>,
    pub decision: Decision,
}
pub struct All<'a> {
    pub tree: &'a str,
    pub satisfied: bool,
    pub decision: Decision,
    /// Python dictionary insertion order, with lossless code-point keys.
    pub lanes: Vec<(Vec<u32>, Lane)>,
}
/// Validate each policy entry before off-skip; only eager no_lane is per-lane.
/// Explicit verification failures are per-lane, including Git/policy and budget
/// refusals; normalized non-Failure judgment exceptions abort the whole aggregate.
/// Each verification owns a fresh collector and intentionally empty owned
/// revocations, not external revocations. Results retain summaries, not documents.
pub fn require_all<'a>(
    repo: &Path,
    tree: &'a str,
    keys: &str,
    policy_text: &str,
    repository: &str,
    lane_file: Option<(&str, &str)>,
    lane_base: Option<&str>,
) -> Result<All<'a>, PolicyError> {
    let mut all = All {
        tree,
        satisfied: true,
        decision: Decision::Ok,
        lanes: Vec::new(),
    };
    let mut clock = SystemClock;
    for check in check_names::sorted(policy_text)? {
        let rules = PolicyDocument::parse(policy_text, check.as_slice())?.into_rules(repository)?;
        if rules.header.require == RequireMode::Off {
            continue;
        }
        let eager = lane_git::required_lane(repo, tree, lane_file, check.as_slice(), lane_base)?;
        let outcome = match eager {
            lane_git::RequiredLane::Missing(error) => Err(Failure {
                reason: error.reason,
                detail: error.detail,
                attempts: 0,
                exception: false,
            }),
            lane_git::RequiredLane::Ready(lane) => configured::required_git(
                &Request {
                    repo,
                    tree,
                    check: check.as_slice().into(),
                    keys,
                    inputs: None,
                    crate_key: None,
                },
                &rules,
                lane.as_ref(),
                &mut clock,
            )
            .map(|selected| {
                let doc = &selected.candidate.statement;
                let predicate = statement::field(doc, doc.root(), "predicate")?;
                let tier = statement::string(statement::field(doc, predicate, "tier")?)?.to_vec();
                Some(Record {
                    record: selected.candidate.commit,
                    signer: selected.principal,
                    tier,
                })
            }),
        };
        let outcome = match outcome {
            Ok(Some(record)) => Ok(record),
            Ok(None) => {
                return Err(PolicyError {
                    reason: "error",
                    detail: "internal invariant: validated statement lacks a string tier".into(),
                });
            }
            Err(error) if error.exception => {
                return Err(PolicyError {
                    reason: error.reason,
                    detail: error.detail,
                });
            }
            Err(error) => Err(error),
        };
        let mode = rules.header.require;
        let decision = if outcome.is_ok() {
            Decision::Ok
        } else if mode == RequireMode::Reject {
            Decision::Reject
        } else {
            Decision::WouldReject
        };
        all.satisfied &= outcome.is_ok();
        all.decision = all.decision.max(decision);
        all.lanes.push((
            check,
            Lane {
                require: mode,
                outcome,
                decision,
            },
        ));
    }
    Ok(all)
}

#[cfg(all(test, unix))]
#[path = "require_all_tests.rs"]
mod tests;
