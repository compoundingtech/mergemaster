//! Selected-record judgment with lazy accepted-base lane and Git reads.
use super::{
    Failure,
    inputs::{Clock, check_inputs},
    routing::{RecordFacts, Routing, route},
};
use crate::evidence::legacy_policy::{PolicyError, PolicyRules, level_rules::LaneBinding};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Deserialize, Serialize)]
pub struct LaneDefinition {
    pub sha256: String,
    pub changed: Vec<String>,
    pub tree_sha256: String,
}
/// Supply trusted lane context and hashes from the verified tree; never unverified claims.
pub trait Provider {
    fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError>;
    fn blob_sha256(&mut self, path: &str) -> Result<Option<String>, PolicyError>;
}
pub fn judge<'a>(
    policy: &'a PolicyRules,
    record: &RecordFacts<'_>,
    clock: &Clock,
    run_inputs: &BTreeMap<String, String>,
    lane: Option<&LaneDefinition>,
    provider: &mut impl Provider,
    attempts: usize,
) -> Result<Routing<'a>, Failure> {
    let fail = |reason| Failure {
        reason,
        detail: format!("record fails legacy {reason} guard"),
        attempts,
    };
    let error = |e: PolicyError| Failure {
        reason: e.reason,
        detail: e.detail,
        attempts,
    };
    let routing = route(policy, record, attempts)?;
    let mode = routing.level.map(|level| &level.lane);
    let lane = if lane.is_none() && mode.is_some_and(|m| !matches!(m, LaneBinding::None)) {
        Some(
            provider
                .level_lane()
                .map_err(error)?
                .ok_or_else(|| fail("no_lane"))?,
        )
    } else {
        lane
    };
    routing.check_runner(record.runner, attempts)?;
    check_inputs(policy, &routing, record, clock, run_inputs, attempts)?;
    if let Some(lane) = lane {
        let expected = if !lane.changed.is_empty() && matches!(mode, Some(LaneBinding::Tree)) {
            &lane.tree_sha256
        } else {
            if !lane.changed.is_empty() {
                return Err(fail("definition_changed"));
            }
            &lane.sha256
        };
        if record.inputs.get("lane_definition_sha256") != Some(expected) {
            return Err(fail("wrong_definition"));
        }
    }
    for (key, path) in &routing.command_inputs.bind_inputs {
        let actual = provider.blob_sha256(path).map_err(error)?;
        if actual.as_ref().is_none_or(|actual| {
            record
                .inputs
                .get(key)
                .is_none_or(|v| v.is_empty() || v != actual)
        }) {
            return Err(fail("wrong_input"));
        }
    }
    Ok(routing)
}
