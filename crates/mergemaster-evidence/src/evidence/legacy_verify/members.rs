//! No-log member verification. Shadow-log support is a separate pre-C1 surface.
use super::{
    Failure,
    candidates::Levels,
    collection::CrateBinding,
    configured::{self, Settings},
    crate_bindings::Members,
    judgment::Provider,
    ordering::CheckJudgment,
    prefix::Request,
    result::Retained,
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::ErrorOrigin;
use std::collections::BTreeMap;

#[derive(Debug)]
pub enum Refusal {
    /// Preparation errors and uncaught exceptions retain their original provenance.
    Verification(Failure),
    Uncovered(Uncovered),
}
#[derive(Debug)]
pub struct Uncovered {
    pub failure: Failure,
    pub missing: BTreeMap<String, &'static str>,
    pub members: usize,
}
/// Original selected records in sorted crate order, with each crate's exact key.
pub struct Covered<T = Retained> {
    entries: Vec<(String, String, T)>,
}
impl<T> Covered<T> {
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &str, &T)> {
        self.entries
            .iter()
            .map(|(name, key, note)| (name.as_str(), key.as_str(), note))
    }
}
#[path = "members_aggregate.rs"]
mod aggregate;
pub use aggregate::{Aggregate, View};
/// Keys precede the standalone allowance; one judgment shares its LaneOnce across
/// all members. There is deliberately no log_keys parameter on this no-log API.
pub fn verified<P: Provider>(
    q: &Request<'_>,
    policy_base: Option<&str>,
    settings: Settings<'_>,
    judgment: &mut CheckJudgment<'_, P>,
    prefer: Levels<'_>,
) -> Result<Aggregate, Refusal> {
    let members = Members::read(q.repo, q.tree, policy_base).map_err(|e| {
        Refusal::Verification(Failure {
            reason: e.reason,
            detail: e.detail,
            origin: e.origin,
            attempts: None,
        })
    })?;
    collect(members.into_sorted(), |name, key, needs_tests| {
        configured::retained(
            &Request {
                crate_key: Some(CrateBinding {
                    name: TextRef::Str(name),
                    key,
                    needs_tests,
                }),
                ..*q
            },
            settings,
            judgment,
            prefer,
        )
    })
    .and_then(|covered| {
        let events = match settings {
            Settings::Policy(rules) => rules.header.events.as_deref(),
            Settings::Unconfigured(_) => None,
        };
        covered
            .aggregate(q.check, events)
            .map_err(Refusal::Verification)
    })
}
fn collect<T>(
    members: Vec<(String, Option<String>, bool)>,
    mut judge: impl FnMut(&str, &str, bool) -> Result<T, Failure>,
) -> Result<Covered<T>, Refusal> {
    let count = members.len();
    let mut entries = Vec::with_capacity(count);
    let mut missing = BTreeMap::new();
    for (name, key, needs_tests) in members {
        let Some(key) = key else {
            missing.insert(name, "no_key");
            continue;
        };
        match judge(&name, &key, needs_tests) {
            Ok(note) => entries.push((name, key, note)),
            Err(error) if error.origin == ErrorOrigin::Failure => {
                missing.insert(name, error.reason);
            }
            Err(error) => return Err(Refusal::Verification(error)),
        }
    }
    if missing.is_empty() {
        return Ok(Covered { entries });
    }
    let shown = missing
        .iter()
        .take(12)
        .map(|(name, reason)| format!("{name} ({reason})"))
        .collect::<Vec<_>>()
        .join(", ");
    let detail = format!(
        "{} of {count} crates have no satisfying note for their key: {shown}{}",
        missing.len(),
        if missing.len() > 12 { " ..." } else { "" }
    );
    Err(Refusal::Uncovered(Uncovered {
        failure: Failure {
            reason: "crate_uncovered",
            detail: detail.into(),
            attempts: None,
            origin: ErrorOrigin::Failure,
        },
        missing,
        members: count,
    }))
}

#[cfg(test)]
#[path = "members_tests.rs"]
mod tests;
