//! Policy routing for a signature-verified generic observation with the requested check.
use super::{
    Failure,
    events::{kind_of_text, shard_part_source},
    facts::DocumentFacts,
    value_inputs::{InputSource, TextRef},
};
use crate::evidence::{
    Check, TrustTier,
    legacy_policy::{CommandInputs, PolicyRules, kind_rules::KindRule, level_rules::LevelRule},
};
use std::collections::BTreeMap;

pub struct RecordFacts<'a> {
    pub tier: TrustTier,
    pub runner: &'a str,
    /// Principal obtained from signature verification, not an unverified claim.
    pub principal: &'a str,
    pub check: &'a Check,
    pub inputs: &'a BTreeMap<String, String>,
}
pub struct Routing<'a> {
    pub kind: &'a KindRule,
    pub command_inputs: &'a CommandInputs,
    pub level: Option<&'a LevelRule>,
}
struct RoutingFacts<'a> {
    full: bool,
    failed: bool,
    runner: TextRef<'a>,
    principal: &'a str,
    inputs: InputSource<'a>,
}
pub fn route<'a>(
    policy: &'a PolicyRules,
    record: &RecordFacts<'_>,
    attempts: usize,
) -> Result<Routing<'a>, Failure> {
    route_source(
        policy,
        RoutingFacts {
            full: record.tier == TrustTier::Full,
            failed: record.check.exit_code != 0,
            runner: TextRef::Str(record.runner),
            principal: record.principal,
            inputs: InputSource::Native(record.inputs),
        },
        attempts,
    )
}
/// Route lossless validated facts; callers still independently verify signatures.
pub fn route_document<'a>(
    policy: &'a PolicyRules,
    record: &DocumentFacts<'_>,
    attempts: usize,
) -> Result<Routing<'a>, Failure> {
    route_source(
        policy,
        RoutingFacts {
            full: TextRef::Points(record.tier).equals("full"),
            failed: record.failed(),
            runner: TextRef::Points(record.runner),
            principal: record.principal,
            inputs: record.input_source(),
        },
        attempts,
    )
}
fn route_source<'a>(
    policy: &'a PolicyRules,
    record: RoutingFacts<'_>,
    attempts: usize,
) -> Result<Routing<'a>, Failure> {
    let fail = |reason| Failure {
        reason,
        detail: format!("record from {} fails policy routing", record.runner),
        attempts,
    };
    if record.failed && shard_part_source(Some(policy), record.runner, &record.inputs) {
        return Err(fail("check_failed"));
    }
    if !record.full {
        return Err(fail("untrusted_tier"));
    }
    let kind = kind_of_text(record.runner)
        .and_then(|kind| {
            policy
                .kinds
                .iter()
                .find(|(name, _)| name == kind)
                .map(|(_, rule)| rule)
        })
        .ok_or_else(|| fail("unsupported_kind"))?;
    let level = record.principal.split('/').next().unwrap_or("");
    if !kind
        .trust_levels
        .as_deref()
        .unwrap_or(&policy.header.trust_levels)
        .iter()
        .any(|accepted| accepted == level)
    {
        return Err(fail("untrusted_level"));
    }
    let override_ = kind
        .by_level
        .iter()
        .find(|(name, _)| name == level)
        .map(|(_, rule)| rule);
    let command_inputs = override_.map_or(&kind.inputs, |rule| &rule.inputs);
    Ok(Routing {
        kind,
        command_inputs,
        level: override_,
    })
}
impl Routing<'_> {
    /// Call after any required lazy lane lookup, matching the oracle's reason order.
    pub fn check_runner(&self, runner: &str, attempts: usize) -> Result<(), Failure> {
        self.check_runner_text(TextRef::Str(runner), attempts)
    }
    /// Like check_runner, call only after any required lazy lane lookup.
    pub fn check_document_runner(&self, runner: &[u32], attempts: usize) -> Result<(), Failure> {
        self.check_runner_text(TextRef::Points(runner), attempts)
    }
    fn check_runner_text(&self, runner: TextRef<'_>, attempts: usize) -> Result<(), Failure> {
        if self
            .kind
            .runner_prefix
            .as_ref()
            .is_some_and(|prefix| !runner.starts_with(prefix))
        {
            return Err(Failure {
                reason: "wrong_runner",
                detail: "record is for a different repository or producer".into(),
                attempts,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod tests;
