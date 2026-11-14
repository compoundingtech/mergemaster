//! Selection prelude for already validated, independently trusted candidate facts.
use super::{
    Failure,
    events::shard_part_source,
    facts::DocumentFacts,
    judgment::{LaneDefinition, Provider},
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{
    PolicyError, PolicyRules, check_names::CheckName, normalized_text::NormalizedText,
};
use std::collections::BTreeSet;

/// Borrowed selection-level membership, not signer verification.
/// Unrestricted represents accepted=None; absent preferences use an empty view instead.
#[derive(Clone, Copy)]
pub enum Levels<'a> {
    Unrestricted,
    Policy(&'a BTreeSet<&'a str>),
    Utf8(&'a [String]),
    Codepoints(&'a [Vec<u32>]),
}
impl Levels<'_> {
    pub fn contains(self, level: &str) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Policy(levels) => levels.contains(level),
            Self::Utf8(levels) => levels.iter().any(|entry| entry == level),
            Self::Codepoints(levels) => levels
                .iter()
                .any(|entry| TextRef::Points(entry).equals(level)),
        }
    }
}

pub struct Candidate<'a> {
    pub commit: &'a str,
    pub facts: DocumentFacts<'a>,
}
pub struct Prepared<'a> {
    pub candidates: Vec<Candidate<'a>>,
    pub(super) rules: Rules<'a>,
}
pub(super) enum Rules<'a> {
    Policy {
        policy: &'a PolicyRules,
        accepted: BTreeSet<&'a str>,
    },
    Unconfigured(&'a super::judgment::Unconfigured<'a>),
}
impl<'a> Prepared<'a> {
    /// Policy-mode prelude only: no sorting, judgment, or trust verification.
    /// Upstream collection must supply a nonempty candidate list for this check.
    pub fn new(
        policy: &'a PolicyRules,
        mut candidates: Vec<Candidate<'a>>,
        check: impl Into<CheckName<'a>>,
    ) -> Result<Self, Failure> {
        let check = check.into();
        let before = candidates.len();
        candidates.retain(|candidate| {
            let facts = &candidate.facts;
            facts.failed()
                || !shard_part_source(
                    Some(policy),
                    TextRef::Points(facts.runner),
                    &facts.input_source(),
                )
        });
        if before != 0 && candidates.is_empty() {
            return Err(Failure {
                origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
                reason: "no_record",
                detail: NormalizedText::around(
                    "check ",
                    check.text(),
                    " has only passing shard parts, no record for the whole run",
                ),
                attempts: Some(before),
            });
        }
        let accepted = policy
            .kinds
            .iter()
            .flat_map(|(_, kind)| {
                kind.trust_levels
                    .as_deref()
                    .unwrap_or(&policy.header.trust_levels)
                    .iter()
                    .map(String::as_str)
            })
            .collect();
        Ok(Self {
            candidates,
            rules: Rules::Policy { policy, accepted },
        })
    }
    /// Preserve every candidate/order/duplicate: shard-part filtering requires policy.
    /// Collection must supply validated, independently trusted candidates for this check.
    pub fn unconfigured(
        options: &'a super::judgment::Unconfigured<'a>,
        candidates: Vec<Candidate<'a>>,
    ) -> Self {
        Self {
            candidates,
            rules: Rules::Unconfigured(options),
        }
    }
    pub fn accepted_levels(&self) -> Levels<'_> {
        match &self.rules {
            Rules::Policy { accepted, .. } => Levels::Policy(accepted),
            Rules::Unconfigured(options) => options
                .routing
                .trust_levels
                .map_or(Levels::Unrestricted, Levels::Codepoints),
        }
    }
    pub fn attempts(&self) -> usize {
        self.candidates.len()
    }
}

/// One check's lazy lane snapshot, shared across candidate judgments.
/// Successful absence is cached; errors are not. Blob reads stay lazy and uncached.
pub struct LaneOnce<P> {
    provider: P,
    lane: Option<Option<LaneDefinition>>,
}
impl<P> LaneOnce<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            lane: None,
        }
    }
}
impl<P: Provider> Provider for LaneOnce<P> {
    fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
        if self.lane.is_none() {
            // Provider lends its result; own a snapshot so later blob reads can borrow it mutably.
            self.lane = Some(self.provider.level_lane()?.map(|lane| LaneDefinition {
                sha256: lane.sha256.clone(),
                changed: lane.changed.clone(),
                tree_sha256: lane.tree_sha256.clone(),
            }));
        }
        Ok(self.lane.as_ref().and_then(Option::as_ref))
    }
    fn blob_sha256(&mut self, path: &std::path::Path) -> Result<Option<String>, PolicyError> {
        self.provider.blob_sha256(path)
    }
}

#[cfg(test)]
#[path = "candidates_tests.rs"]
mod tests;
