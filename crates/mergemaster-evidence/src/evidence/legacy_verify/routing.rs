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
/// Rules-absent caller restrictions; strings retain Python codepoints, including surrogates.
#[derive(Clone, Copy)]
pub struct Unconfigured<'a> {
    pub kinds: &'a [Vec<u32>],
    pub trust_levels: Option<&'a [Vec<u32>]>,
    pub runner_prefix: Option<&'a [u32]>,
}
#[derive(Clone, Copy)]
enum Rules<'a> {
    Policy(&'a PolicyRules),
    Unconfigured(Unconfigured<'a>),
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
        Rules::Policy(policy),
        RoutingFacts {
            full: record.tier == TrustTier::Full,
            failed: record.check.exit_code != 0,
            runner: TextRef::Str(record.runner),
            principal: record.principal,
            inputs: InputSource::Native(record.inputs),
        },
        attempts,
    )
    .map(|routing| routing.expect("policy route supplies a rule"))
}
/// Route lossless validated facts; callers still independently verify signatures.
pub fn route_document<'a>(
    policy: &'a PolicyRules,
    record: &DocumentFacts<'_>,
    attempts: usize,
) -> Result<Routing<'a>, Failure> {
    route_source(
        Rules::Policy(policy),
        RoutingFacts {
            full: TextRef::Points(record.tier).equals("full"),
            failed: record.failed(),
            runner: TextRef::Points(record.runner),
            principal: record.principal,
            inputs: record.input_source(),
        },
        attempts,
    )
    .map(|routing| routing.expect("policy route supplies a rule"))
}
/// Route validated facts without policy overrides or implicit shard/lane restrictions.
/// Signatures must be verified independently; later input/lane/binding guards still apply.
pub fn route_unconfigured(
    rules: Unconfigured<'_>,
    record: &DocumentFacts<'_>,
    attempts: usize,
) -> Result<(), Failure> {
    route_source(
        Rules::Unconfigured(rules),
        RoutingFacts {
            full: TextRef::Points(record.tier).equals("full"),
            failed: record.failed(),
            runner: TextRef::Points(record.runner),
            principal: record.principal,
            inputs: record.input_source(),
        },
        attempts,
    )?;
    check_runner(
        TextRef::Points(record.runner),
        rules.runner_prefix.map(TextRef::Points),
        attempts,
    )
}
fn route_source<'a>(
    rules: Rules<'a>,
    record: RoutingFacts<'_>,
    attempts: usize,
) -> Result<Option<Routing<'a>>, Failure> {
    let fail = |reason| Failure {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason,
        detail: format!("record from {} fails policy routing", record.runner).into(),
        attempts: Some(attempts),
    };
    let policy = match rules {
        Rules::Policy(policy) => Some(policy),
        Rules::Unconfigured(_) => None,
    };
    if record.failed && shard_part_source(policy, record.runner, &record.inputs) {
        return Err(fail("check_failed"));
    }
    if !record.full {
        return Err(fail("untrusted_tier"));
    }
    let name = kind_of_text(record.runner).ok_or_else(|| fail("unsupported_kind"))?;
    let kind = match rules {
        Rules::Policy(policy) => Some(
            policy
                .kinds
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, rule)| rule)
                .ok_or_else(|| fail("unsupported_kind"))?,
        ),
        Rules::Unconfigured(rules) => {
            if !rules
                .kinds
                .iter()
                .any(|kind| TextRef::Points(kind).equals(name))
            {
                return Err(fail("unsupported_kind"));
            }
            None
        }
    };
    let level = record.principal.split('/').next().unwrap_or("");
    let accepted = match (rules, kind) {
        (Rules::Policy(policy), Some(kind)) => kind
            .trust_levels
            .as_deref()
            .unwrap_or(&policy.header.trust_levels)
            .iter()
            .any(|accepted| accepted == level),
        (Rules::Unconfigured(rules), _) => rules.trust_levels.is_none_or(|levels| {
            levels
                .iter()
                .any(|accepted| TextRef::Points(accepted).equals(level))
        }),
        _ => unreachable!("policy kind was resolved above"),
    };
    if !accepted {
        return Err(fail("untrusted_level"));
    }
    let Some(kind) = kind else {
        return Ok(None);
    };
    let override_ = kind
        .by_level
        .iter()
        .find(|(name, _)| name == level)
        .map(|(_, rule)| rule);
    let command_inputs = override_.map_or(&kind.inputs, |rule| &rule.inputs);
    Ok(Some(Routing {
        kind,
        command_inputs,
        level: override_,
    }))
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
        check_runner(
            runner,
            self.kind
                .runner_prefix
                .as_ref()
                .map(|prefix| prefix.borrowed()),
            attempts,
        )
    }
}
fn check_runner(
    runner: TextRef<'_>,
    prefix: Option<TextRef<'_>>,
    attempts: usize,
) -> Result<(), Failure> {
    let matches = prefix.is_none_or(|prefix| match prefix {
        TextRef::Str(prefix) => runner.starts_with(prefix),
        TextRef::Points(prefix) => {
            let mut points = runner.points();
            prefix.iter().all(|point| points.next() == Some(*point))
        }
    });
    if !matches {
        return Err(Failure {
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: "wrong_runner",
            detail: "record is for a different repository or producer".into(),
            attempts: Some(attempts),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod tests;
