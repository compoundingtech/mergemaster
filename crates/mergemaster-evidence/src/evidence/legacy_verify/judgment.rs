//! Lane-definition and ordered file bindings after routing/clock/input guards.
use super::{
    Failure,
    routing::{RecordFacts, Routing},
};
use crate::evidence::legacy_policy::{PolicyError, level_rules::LaneBinding};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct LaneDefinition {
    pub sha256: String,
    pub changed: Vec<String>,
    pub tree_sha256: String,
}
/// Supply trusted lane context and hashes from the verified tree; never unverified claims.
pub trait Provider {
    fn blob_sha256(&mut self, path: &str) -> Result<Option<String>, PolicyError>;
}
pub fn check_bindings(
    routing: &Routing<'_>,
    record: &RecordFacts<'_>,
    lane: Option<&LaneDefinition>,
    provider: &mut impl Provider,
    attempts: usize,
) -> Result<(), Failure> {
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
    let mode = routing.level.map(|level| &level.lane);
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
    Ok(())
}
