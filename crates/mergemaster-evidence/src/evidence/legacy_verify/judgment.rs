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
/// Caller restrictions for rules-absent judgment; no external policy is synthesized.
pub struct Unconfigured<'a> {
    pub routing: super::routing::Unconfigured<'a>,
    pub command: Option<&'a [Vec<u32>]>,
    pub max_age: Option<super::inputs::AgeLimit>,
    pub bindings: &'a [(Vec<u32>, std::path::PathBuf)],
}
/// Judge validated facts against caller restrictions and independently trusted context.
/// An explicit lane is enforced; no policy-level lazy lane is requested without rules.
pub fn judge_unconfigured(
    options: &Unconfigured<'_>,
    record: &DocumentFacts<'_>,
    now_micros: i64,
    lane: Option<&LaneDefinition>,
    provider: &mut impl Provider,
    attempts: usize,
) -> Result<(), Failure> {
    super::routing::route_unconfigured(options.routing, record, attempts)?;
    super::inputs::check_unconfigured_inputs(
        record,
        now_micros,
        options.max_age,
        options.command,
        attempts,
    )?;
    check_lane(&record.input_source(), lane, None, attempts)?;
    check_bindings(
        record.input_source(),
        options
            .bindings
            .iter()
            .map(|(key, path)| (super::value_inputs::TextRef::Points(key), path.as_path())),
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
    check_lane(&inputs, lane, mode, attempts)?;
    check_bindings(
        inputs,
        routing
            .command_inputs
            .bind_inputs
            .iter()
            .map(|(key, path)| {
                (
                    super::value_inputs::TextRef::Str(key),
                    std::path::Path::new(path),
                )
            }),
        provider,
        attempts,
    )?;
    Ok(routing)
}
fn check_lane(
    inputs: &InputSource<'_>,
    lane: Option<&LaneDefinition>,
    mode: Option<&LaneBinding>,
    attempts: usize,
) -> Result<(), Failure> {
    let fail = |reason| Failure {
        reason,
        detail: format!("record fails legacy {reason} guard"),
        attempts,
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
    Ok(())
}
fn check_bindings<'a>(
    inputs: InputSource<'_>,
    bindings: impl Iterator<Item = (super::value_inputs::TextRef<'a>, &'a std::path::Path)>,
    provider: &mut impl Provider,
    attempts: usize,
) -> Result<(), Failure> {
    let error = |e: PolicyError| Failure {
        reason: e.reason,
        detail: e.detail,
        attempts,
    };
    for (key, path) in bindings {
        let actual = provider.blob_sha256(path).map_err(error)?;
        if actual.as_ref().is_none_or(|actual| {
            inputs
                .get_text(key)
                .is_none_or(|value| value.len() == 0 || !value.equals(actual))
        }) {
            return Err(Failure {
                reason: "wrong_input",
                detail: "record fails legacy wrong_input guard".into(),
                attempts,
            });
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "judgment_tests.rs"]
mod tests;
