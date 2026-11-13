//! Selected-record judgment with lazy accepted-base lane and Git reads.
use super::{
    Failure,
    facts::DocumentFacts,
    inputs::{Clock, check_document_inputs, check_inputs},
    routing::{RecordFacts, Routing, route, route_document},
    value_inputs::InputSource,
};
use crate::evidence::legacy_policy::{PolicyError, PolicyRules, level_rules::LaneBinding};
use std::collections::BTreeMap;
pub struct LaneDefinition {
    pub sha256: String,
    pub changed: Vec<Vec<u8>>,
    pub tree_sha256: String,
}
/// Supply trusted lane context and hashes from the verified tree; never unverified claims.
pub trait Provider {
    fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError>;
    /// Preserve native path bytes, including Unix surrogateescaped argv bytes; never use lossy text.
    fn blob_sha256(&mut self, path: &std::path::Path) -> Result<Option<String>, PolicyError>;
}
enum RecordView<'a> {
    Native(&'a RecordFacts<'a>, &'a Clock),
    Document(&'a DocumentFacts<'a>, i64),
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
    judge_source(
        policy,
        RecordView::Native(record, clock),
        run_inputs,
        lane,
        provider,
        attempts,
    )
}
/// Judge validated document facts using independently verified principal/lane/hash context.
/// Current UTC epoch microseconds have check_document_inputs' datetime contract.
pub fn judge_document<'a>(
    policy: &'a PolicyRules,
    record: &DocumentFacts<'_>,
    now_micros: i64,
    run_inputs: &BTreeMap<String, String>,
    lane: Option<&LaneDefinition>,
    provider: &mut impl Provider,
    attempts: usize,
) -> Result<Routing<'a>, Failure> {
    judge_source(
        policy,
        RecordView::Document(record, now_micros),
        run_inputs,
        lane,
        provider,
        attempts,
    )
}
fn judge_source<'a>(
    policy: &'a PolicyRules,
    record: RecordView<'_>,
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
    let routing = match &record {
        RecordView::Native(record, _) => route(policy, record, attempts),
        RecordView::Document(record, _) => route_document(policy, record, attempts),
    }?;
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
    let inputs = match record {
        RecordView::Native(record, clock) => {
            routing.check_runner(record.runner, attempts)?;
            check_inputs(policy, &routing, record, clock, run_inputs, attempts)?;
            InputSource::Native(record.inputs)
        }
        RecordView::Document(record, now) => {
            routing.check_document_runner(record.runner, attempts)?;
            check_document_inputs(policy, &routing, record, now, run_inputs, attempts)?;
            record.input_source()
        }
    };
    if let Some(lane) = lane {
        let expected = if !lane.changed.is_empty() && matches!(mode, Some(LaneBinding::Tree)) {
            &lane.tree_sha256
        } else {
            if !lane.changed.is_empty() {
                return Err(fail("definition_changed"));
            }
            &lane.sha256
        };
        if inputs
            .get("lane_definition_sha256")
            .is_none_or(|value| !value.equals(expected))
        {
            return Err(fail("wrong_definition"));
        }
    }
    for (key, path) in &routing.command_inputs.bind_inputs {
        let actual = provider
            .blob_sha256(std::path::Path::new(path))
            .map_err(error)?;
        if actual.as_ref().is_none_or(|actual| {
            inputs
                .get(key)
                .is_none_or(|value| value.len() == 0 || !value.equals(actual))
        }) {
            return Err(fail("wrong_input"));
        }
    }
    Ok(routing)
}
