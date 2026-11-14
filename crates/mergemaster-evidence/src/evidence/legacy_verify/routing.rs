//! Policy routing for a signature-verified generic observation with the requested check.
use super::python_repr::Repr;
use super::{
    Failure,
    events::{kind_of_text, shard_part_source},
    facts::{DocumentFacts, ExitCode},
    value_inputs::{InputSource, TextRef},
};
use crate::evidence::legacy_policy::{check_names::CheckName, normalized_text::NormalizedText};
use crate::evidence::{
    Check, TrustTier,
    legacy_policy::{CommandInputs, PolicyRules, kind_rules::KindRule, level_rules::LevelRule},
};
use std::collections::BTreeMap;

pub struct RecordFacts<'a> {
    pub check_name: crate::evidence::legacy_policy::check_names::CheckName<'a>,
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
    tier: TextRef<'a>,
    check: CheckName<'a>,
    exit_code: ExitCode<'a>,
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
    route_policy(
        policy,
        RoutingFacts {
            tier: TextRef::Str(match record.tier {
                TrustTier::Full => "full",
                TrustTier::Degraded => "degraded",
                TrustTier::Test => "test",
            }),
            check: record.check_name,
            exit_code: ExitCode::Native(record.check.exit_code),
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
    route_policy(
        policy,
        RoutingFacts {
            tier: TextRef::Points(record.tier),
            check: record.check_name.into(),
            exit_code: ExitCode::Decimal(record.exit_code),
            failed: record.failed(),
            runner: TextRef::Points(record.runner),
            principal: record.principal,
            inputs: record.input_source(),
        },
        attempts,
    )
}
/// Route validated facts without policy overrides or implicit shard/lane restrictions.
/// Signatures must be verified independently; later input/lane/binding guards still apply.
pub fn route_unconfigured(
    rules: Unconfigured<'_>,
    record: &DocumentFacts<'_>,
    attempts: usize,
) -> Result<(), Failure> {
    let record = RoutingFacts {
        tier: TextRef::Points(record.tier),
        check: record.check_name.into(),
        exit_code: ExitCode::Decimal(record.exit_code),
        failed: record.failed(),
        runner: TextRef::Points(record.runner),
        principal: record.principal,
        inputs: record.input_source(),
    };
    let name = route_source(Rules::Unconfigured(rules), &record, attempts)?;
    if !rules
        .kinds
        .iter()
        .any(|kind| TextRef::Points(kind).equals(name))
    {
        return Err(unsupported_kind(
            Rules::Unconfigured(rules),
            record.runner,
            attempts,
        ));
    }
    let level = record.principal.split('/').next().unwrap_or("");
    check_level(
        rules.trust_levels.is_none_or(|levels| {
            levels
                .iter()
                .any(|accepted| TextRef::Points(accepted).equals(level))
        }),
        level,
        attempts,
    )?;
    check_runner(
        record.runner,
        rules.runner_prefix.map(TextRef::Points),
        attempts,
    )
}
fn route_policy<'a>(
    policy: &'a PolicyRules,
    record: RoutingFacts<'_>,
    attempts: usize,
) -> Result<Routing<'a>, Failure> {
    let name = route_source(Rules::Policy(policy), &record, attempts)?;
    let kind = policy
        .kinds
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, rule)| rule)
        .ok_or_else(|| unsupported_kind(Rules::Policy(policy), record.runner, attempts))?;
    let level = record.principal.split('/').next().unwrap_or("");
    check_level(
        kind.trust_levels
            .as_deref()
            .unwrap_or(&policy.header.trust_levels)
            .iter()
            .any(|accepted| accepted.borrowed().equals(level)),
        level,
        attempts,
    )?;
    let override_ = kind
        .by_level
        .iter()
        .find(|(name, _)| name.borrowed().equals(level))
        .map(|(_, rule)| rule);
    let command_inputs = override_.map_or(&kind.inputs, |rule| &rule.inputs);
    Ok(Routing {
        kind,
        command_inputs,
        level: override_,
    })
}
fn route_source(
    rules: Rules<'_>,
    record: &RoutingFacts<'_>,
    attempts: usize,
) -> Result<&'static str, Failure> {
    let fail = |reason, detail| Failure {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason,
        detail,
        attempts: Some(attempts),
    };
    let policy = match rules {
        Rules::Policy(policy) => Some(policy),
        Rules::Unconfigured(_) => None,
    };
    if record.failed && shard_part_source(policy, record.runner, &record.inputs) {
        return Err(fail(
            "check_failed",
            NormalizedText::around(
                "a shard of the latest run of check ",
                record.check.text(),
                &format!(" exited {}", record.exit_code),
            ),
        ));
    }
    if !record.tier.equals("full") {
        return Err(fail(
            "untrusted_tier",
            NormalizedText::around("latest record has tier ", record.tier, ", not full"),
        ));
    }
    kind_of_text(record.runner).ok_or_else(|| unsupported_kind(rules, record.runner, attempts))
}
fn unsupported_kind(rules: Rules<'_>, runner: TextRef<'_>, attempts: usize) -> Failure {
    let prefix = format!("runner {} is not one of ", Repr(runner));
    let kinds = match rules {
        Rules::Policy(_) => &[][..],
        Rules::Unconfigured(rules) => rules.kinds,
    };
    Failure {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason: "unsupported_kind",
        detail: NormalizedText::concat(std::iter::once(TextRef::Str(prefix.as_str())).chain(
            kinds.iter().enumerate().flat_map(|(i, name)| {
                (i > 0)
                    .then_some(TextRef::Str(", "))
                    .into_iter()
                    .chain(std::iter::once(TextRef::Points(name)))
            }),
        )),
        attempts: Some(attempts),
    }
}
fn check_level(accepted: bool, level: &str, attempts: usize) -> Result<(), Failure> {
    if !accepted {
        return Err(Failure {
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: "untrusted_level",
            detail: format!(
                "signer trust level {} is not accepted for this check",
                Repr(TextRef::Str(level)),
            )
            .into(),
            attempts: Some(attempts),
        });
    }
    Ok(())
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
