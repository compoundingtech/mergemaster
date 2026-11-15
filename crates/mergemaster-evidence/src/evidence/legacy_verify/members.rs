//! Member verification with optional advisory shadow-log metadata.
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
    Uncovered(Box<Uncovered>),
}
#[derive(Debug)]
pub struct Uncovered {
    pub failure: Failure,
    pub missing: BTreeMap<String, &'static str>,
    pub members: usize,
    pub keys: BTreeMap<String, Option<String>>,
    pub log: Option<super::members_log_view::View>,
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
/// Keys precede the standalone allowance; one judgment shares its LaneOnce across members.
pub fn verified<P: Provider>(
    q: &Request<'_>,
    policy_base: Option<TextRef<'_>>,
    settings: Settings<'_>,
    judgment: &mut CheckJudgment<'_, P>,
    prefer: Levels<'_>,
    log: Option<super::log_view::Request<'_>>,
) -> Result<Aggregate, Refusal> {
    verified_with_transport(
        q,
        policy_base,
        settings,
        judgment,
        prefer,
        log,
        configured::Transport::Native,
    )
}

pub fn verified_with_transport<P: Provider>(
    q: &Request<'_>,
    policy_base: Option<TextRef<'_>>,
    settings: Settings<'_>,
    judgment: &mut CheckJudgment<'_, P>,
    prefer: Levels<'_>,
    log: Option<super::log_view::Request<'_>>,
    transport: configured::Transport,
) -> Result<Aggregate, Refusal> {
    let log = log.filter(|log| !log.keys.as_os_str().is_empty());
    let members = Members::read(q.repo, q.tree, policy_base)
        .map_err(|e| Refusal::Verification(policy_failure(e)))?;
    let outcome = collect(members.into_sorted(), |name, key, needs_tests| {
        configured::retained_with_transport(
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
            transport,
        )
        .map_err(|e| e.failure)
    });
    match outcome {
        Ok(covered) => {
            let events = match settings {
                Settings::Policy(rules) => rules.header.events.as_deref(),
                Settings::Unconfigured(_) => None,
            };
            let mut aggregate = covered
                .aggregate(q.check, events)
                .map_err(Refusal::Verification)?;
            if let Some(log) = log {
                aggregate.shadow(q, log).map_err(Refusal::Verification)?;
            }
            Ok(aggregate)
        }
        Err(Refusal::Uncovered(mut e)) => {
            if let Some(log) = log {
                let members = e
                    .keys
                    .iter()
                    .map(|(name, key)| {
                        (
                            name.clone(),
                            super::members_log_view::Member {
                                key: key.as_deref(),
                                chosen: None,
                                observed: None,
                            },
                        )
                    })
                    .collect();
                e.log = Some(
                    super::members_log_view::read_at(
                        q.repo,
                        log.keys,
                        q.tree,
                        q.check.text(),
                        &members,
                        log.now_micros,
                        600,
                    )
                    .map_err(|e| Refusal::Verification(policy_failure(e)))?,
                );
            }
            Err(Refusal::Uncovered(e))
        }
        Err(e) => Err(e),
    }
}
fn policy_failure(e: crate::evidence::legacy_policy::PolicyError) -> Failure {
    Failure {
        reason: e.reason,
        detail: e.detail,
        origin: e.origin,
        attempts: None,
    }
}
fn collect<T>(
    members: Vec<(String, Option<String>, bool)>,
    mut judge: impl FnMut(&str, &str, bool) -> Result<T, Failure>,
) -> Result<Covered<T>, Refusal> {
    let count = members.len();
    let mut entries = Vec::with_capacity(count);
    let mut missing = BTreeMap::new();
    let mut keys = BTreeMap::new();
    for (name, key, needs_tests) in members {
        let Some(key) = key else {
            missing.insert(name.clone(), "no_key");
            keys.insert(name, None);
            continue;
        };
        match judge(&name, &key, needs_tests) {
            Ok(note) => entries.push((name, key, note)),
            Err(error) if error.origin == ErrorOrigin::Failure => {
                missing.insert(name.clone(), error.reason);
                keys.insert(name, Some(key));
            }
            Err(error) => return Err(Refusal::Verification(error)),
        }
    }
    if missing.is_empty() {
        return Ok(Covered { entries });
    }
    keys.extend(entries.into_iter().map(|(name, key, _)| (name, Some(key))));
    let mut detail = format!(
        "{} of {count} crates have no satisfying note for their key: ",
        missing.len(),
    );
    for (index, (name, reason)) in missing.iter().take(12).enumerate() {
        if index != 0 {
            detail.push_str(", ");
        }
        detail.push_str(name);
        detail.push_str(" (");
        detail.push_str(reason);
        detail.push(')');
    }
    if missing.len() > 12 {
        detail.push_str(" ...");
    }
    Err(Refusal::Uncovered(Box::new(Uncovered {
        failure: Failure {
            reason: "crate_uncovered",
            detail: detail.into(),
            attempts: None,
            origin: ErrorOrigin::Failure,
        },
        missing,
        members: count,
        keys,
        log: None,
    })))
}

#[cfg(test)]
#[path = "members_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "members_git_tests.rs"]
mod git_tests;
