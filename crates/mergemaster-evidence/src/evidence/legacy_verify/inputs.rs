//! Clock and value guards after policy routing and any required lane lookup.
use super::{
    Failure,
    facts::DocumentFacts,
    routing::{RecordFacts, Routing},
    value_checks_source,
    value_inputs::{InputSource, TextRef},
};
use crate::evidence::legacy_policy::{PolicyRules, normalized_text::NormalizedText};
use chrono::{DateTime, FixedOffset, SubsecRound, Utc};
use std::collections::BTreeMap;

pub struct Clock {
    pub observed_at: DateTime<FixedOffset>,
    pub now: DateTime<Utc>,
}
/// A clock failure is always a non-Failure exception with an explicit class.
#[derive(Debug, PartialEq, Eq)]
pub struct ClockException {
    pub class: &'static str,
    pub detail: NormalizedText,
}
/// Sample only when a document judgment reaches its time guards.
/// Sampling errors model non-Failure Python exceptions, not policy refusals.
pub trait CurrentTime {
    fn epoch_micros(&mut self) -> Result<i64, ClockException>;
}
impl CurrentTime for Clock {
    fn epoch_micros(&mut self) -> Result<i64, ClockException> {
        Ok(self.now.timestamp_micros())
    }
}
impl CurrentTime for i64 {
    fn epoch_micros(&mut self) -> Result<i64, ClockException> {
        Ok(*self)
    }
}
pub struct SystemClock;
impl CurrentTime for SystemClock {
    fn epoch_micros(&mut self) -> Result<i64, ClockException> {
        system_epoch_micros(std::time::SystemTime::now())
    }
}
pub(super) fn sample(clock: &mut dyn CurrentTime) -> Result<i64, Failure> {
    clock
        .epoch_micros()
        .map_err(|error| Failure::exception(error.class, error.detail))
}
/// Convert without chrono's panicking SystemTime conversion; Python datetime years are 1..9999.
pub(super) fn system_epoch_micros(now: std::time::SystemTime) -> Result<i64, ClockException> {
    let nanos = match now.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as i128,
        Err(error) => -(error.duration().as_nanos() as i128),
    };
    let micros = nanos.div_euclid(1_000);
    if !(-62_135_596_800_000_000..=253_402_300_799_999_999).contains(&micros) {
        return Err(ClockException {
            class: "OverflowError",
            detail: "system clock outside Python datetime range".into(),
        });
    }
    Ok(micros as i64)
}
/// Validated nonnegative seconds, or a positive integer too large for u64.
/// Overflow remains explicit so future-dated refusal still precedes timedelta overflow.
#[derive(Clone, Copy)]
pub enum AgeLimit {
    Seconds(u64),
    Overflow,
}
enum ExpectedCommand<'a> {
    Text(&'a [crate::evidence::legacy_policy::normalized_text::NormalizedText]),
    Points(&'a [Vec<u32>]),
}
struct Guards<'a> {
    age: Option<AgeLimit>,
    required: &'a [String],
    command: Option<ExpectedCommand<'a>>,
    values: Option<&'a crate::evidence::legacy_policy::kind_rules::KindRule>,
}
impl<'a> Guards<'a> {
    fn policy(policy: &PolicyRules, routing: &Routing<'a>) -> Self {
        Self {
            age: policy.header.max_age_s.map(AgeLimit::Seconds),
            required: &routing.command_inputs.required_inputs,
            command: Some(ExpectedCommand::Text(&routing.command_inputs.command)),
            values: Some(routing.kind),
        }
    }
}
enum CheckSource<'a> {
    Native {
        check: &'a crate::evidence::Check,
        name: crate::evidence::legacy_policy::check_names::CheckName<'a>,
    },
    Document(&'a DocumentFacts<'a>),
}
impl CheckSource<'_> {
    fn name(&self) -> crate::evidence::legacy_policy::check_names::CheckName<'_> {
        match self {
            Self::Native { name, .. } => *name,
            Self::Document(record) => record.check_name.into(),
        }
    }
    fn exit_code(&self) -> super::facts::ExitCode<'_> {
        match self {
            Self::Native { check, .. } => super::facts::ExitCode::Native(check.exit_code),
            Self::Document(record) => super::facts::ExitCode::Decimal(record.exit_code),
        }
    }
    fn failed(&self) -> bool {
        match self {
            Self::Native { check, .. } => check.exit_code != 0,
            Self::Document(record) => record.failed(),
        }
    }
    fn matches_command(&self, expected: ExpectedCommand<'_>) -> bool {
        match (self, expected) {
            (Self::Native { check, .. }, ExpectedCommand::Text(expected)) => {
                check.command.len() == expected.len()
                    && check
                        .command
                        .iter()
                        .zip(expected)
                        .all(|(actual, expected)| expected.borrowed().equals(actual))
            }
            (Self::Native { check, .. }, ExpectedCommand::Points(expected)) => {
                check.command.len() == expected.len()
                    && check
                        .command
                        .iter()
                        .zip(expected)
                        .all(|(actual, expected)| TextRef::Points(expected).equals(actual))
            }
            (Self::Document(record), ExpectedCommand::Text(expected)) => {
                record.command().len() == expected.len()
                    && record.command().zip(expected).all(|(actual, expected)| {
                        actual.iter().copied().eq(expected.borrowed().points())
                    })
            }
            (Self::Document(record), ExpectedCommand::Points(expected)) => {
                record.command().eq(expected.iter().map(Vec::as_slice))
            }
        }
    }
}
enum Moments {
    Native(DateTime<FixedOffset>, DateTime<Utc>),
    Micros(i64, i64),
}
impl Moments {
    fn future(&self) -> Result<bool, ()> {
        match self {
            Self::Native(observed, now) => Ok(*observed > *now + chrono::Duration::seconds(120)),
            Self::Micros(observed, now) => {
                // Python's current is UTC: adding FUTURE_SKEW must fit years 1..9999.
                if !(-62_135_596_800_000_000..=253_402_300_679_999_999).contains(now) {
                    return Err(());
                }
                Ok(i128::from(*observed) > i128::from(*now) + 120_000_000)
            }
        }
    }
    fn older_than(&self, seconds: u64) -> bool {
        match self {
            Self::Native(observed, now) => (*now - observed.with_timezone(&Utc))
                .to_std()
                .is_ok_and(|age| age > std::time::Duration::from_secs(seconds)),
            Self::Micros(observed, now) => {
                i128::from(*now) - i128::from(*observed) > i128::from(seconds) * 1_000_000
            }
        }
    }
}
/// Run after the routing/runner guards; lane and bound-file checks follow this.
pub fn check_inputs(
    policy: &PolicyRules,
    routing: &Routing<'_>,
    record: &RecordFacts<'_>,
    clock: &Clock,
    run_inputs: &BTreeMap<String, String>,
    attempts: usize,
) -> Result<(), Failure> {
    check_inputs_source(
        Guards::policy(policy, routing),
        CheckSource::Native {
            check: record.check,
            name: record.check_name,
        },
        InputSource::Native(record.inputs),
        // Truncate each subsecond field, not the delta, including before the epoch.
        Moments::Native(
            clock.observed_at.trunc_subsecs(6),
            clock.now.trunc_subsecs(6),
        ),
        run_inputs,
        attempts,
    )
}
/// After routing/runner guards. `now_micros` is UTC epoch microseconds, years 1..9999.
/// Python datetime/timedelta overflow refuses with error, never an accepted record.
pub fn check_document_inputs(
    policy: &PolicyRules,
    routing: &Routing<'_>,
    record: &DocumentFacts<'_>,
    now_micros: i64,
    run_inputs: &BTreeMap<String, String>,
    attempts: usize,
) -> Result<(), Failure> {
    check_inputs_source(
        Guards::policy(policy, routing),
        CheckSource::Document(record),
        record.input_source(),
        Moments::Micros(record.moment_micros, now_micros),
        run_inputs,
        attempts,
    )
}
/// Rules-absent post-routing guards over validated facts; None disables command equality.
/// Required/value inputs, runner, lane and binding guards are not part of this helper.
pub fn check_unconfigured_inputs(
    record: &DocumentFacts<'_>,
    now_micros: i64,
    age: Option<AgeLimit>,
    command: Option<&[Vec<u32>]>,
    attempts: usize,
) -> Result<(), Failure> {
    check_inputs_source(
        Guards {
            age,
            required: &[],
            command: command.map(ExpectedCommand::Points),
            values: None,
        },
        CheckSource::Document(record),
        record.input_source(),
        Moments::Micros(record.moment_micros, now_micros),
        &BTreeMap::new(),
        attempts,
    )
}
fn check_inputs_source(
    guards: Guards<'_>,
    check: CheckSource<'_>,
    inputs: InputSource<'_>,
    clock: Moments,
    run_inputs: &BTreeMap<String, String>,
    attempts: usize,
) -> Result<(), Failure> {
    let fail = |reason, detail: &str| Failure {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason,
        detail: detail.into(),
        attempts: Some(attempts),
    };
    if clock
        .future()
        .map_err(|()| Failure::exception("OverflowError", "date value out of range"))?
    {
        return Err(fail(
            "future_dated",
            "record claims to be observed in the future",
        ));
    }
    if let Some(age) = guards.age {
        let AgeLimit::Seconds(seconds) = age else {
            return Err(Failure::exception(
                "OverflowError",
                "Python int too large to convert to C int",
            ));
        };
        // Python timedelta caps its day count; do not accept what its verifier aborts.
        if seconds >= 86_400_000_000_000 {
            let days = seconds / 86_400;
            let detail = if days > i32::MAX as u64 {
                "Python int too large to convert to C int".into()
            } else {
                format!("days={days}; must have magnitude <= 999999999")
            };
            return Err(Failure::exception("OverflowError", detail));
        }
        if clock.older_than(seconds) {
            return Err(fail(
                "too_old",
                &format!("record is older than {seconds} seconds"),
            ));
        }
    }
    for key in guards.required {
        if inputs.get(key).is_none_or(|value| value.len() == 0) {
            return Err(Failure {
                origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
                reason: "missing_input",
                detail: format!("record lacks required input {key}").into(),
                attempts: Some(attempts),
            });
        }
    }
    if check.failed() {
        return Err(Failure {
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: "check_failed",
            detail: NormalizedText::around(
                "latest record for check ",
                check.name().text(),
                &format!(" exited {}", check.exit_code()),
            ),
            attempts: Some(attempts),
        });
    }
    if guards
        .command
        .is_some_and(|command| !check.matches_command(command))
    {
        return Err(Failure {
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: "wrong_command",
            detail: NormalizedText::around(
                "latest record for check ",
                check.name().text(),
                " ran a different command",
            ),
            attempts: Some(attempts),
        });
    }
    match guards.values {
        Some(kind) => value_checks_source(kind, inputs, run_inputs, attempts),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "inputs_tests.rs"]
mod tests;
