//! Clock and value guards after policy routing and any required lane lookup.
use super::{
    Failure,
    routing::{RecordFacts, Routing},
    value_checks,
};
use crate::evidence::legacy_policy::PolicyRules;
use chrono::{DateTime, FixedOffset, SubsecRound, Utc};
use std::collections::BTreeMap;

pub struct Clock {
    pub observed_at: DateTime<FixedOffset>,
    pub now: DateTime<Utc>,
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
    let fail = |reason, detail: &str| Failure {
        reason,
        detail: detail.into(),
        attempts,
    };
    // Python datetime discards fractional digits beyond microseconds, including
    // before the epoch. Truncate each clock's subsecond field, not their delta.
    let observed_at = clock.observed_at.trunc_subsecs(6);
    let now = clock.now.trunc_subsecs(6);
    if observed_at > now + chrono::Duration::seconds(120) {
        return Err(fail(
            "future_dated",
            "record claims to be observed in the future",
        ));
    }
    if let Some(seconds) = policy.header.max_age_s {
        // Python timedelta caps its day count; do not accept what its verifier aborts.
        if seconds >= 86_400_000_000_000 {
            return Err(fail("error", "max_age_s exceeds the legacy duration range"));
        }
        if (now - observed_at.with_timezone(&Utc))
            .to_std()
            .is_ok_and(|age| age > std::time::Duration::from_secs(seconds))
        {
            return Err(fail("too_old", "record is older than max_age_s"));
        }
    }
    for key in &routing.command_inputs.required_inputs {
        if record.inputs.get(key).is_none_or(String::is_empty) {
            return Err(Failure {
                reason: "missing_input",
                detail: format!("record lacks required input {key}"),
                attempts,
            });
        }
    }
    if record.check.exit_code != 0 {
        return Err(fail("check_failed", "latest record for the check failed"));
    }
    if record.check.command != routing.command_inputs.command {
        return Err(fail(
            "wrong_command",
            "latest record ran a different command",
        ));
    }
    value_checks(routing.kind, record.inputs, run_inputs, attempts)
}
