//! Candidate diagnostics never participate in legacy evidence selection.
use super::{
    AuthenticatedPrCandidate, ReceiptValidation, Refusal, SubjectObjects, Validation, validate,
};
use crate::{
    evidence::{
        v2,
        verified::{self, VerifiedStatement},
    },
    gate::{
        config::{Config, ReuseAuthority},
        git,
    },
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de};
use std::{fmt, path::Path};

macro_rules! strings {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Debug, Serialize)]
        pub enum $name { $(#[serde(rename = $wire)] $variant),+ }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                match String::deserialize(d)?.as_str() {
                    $($wire => Ok(Self::$variant),)+
                    _ => Err(de::Error::custom("unknown selective reuse value")),
                }
            }
        }
    };
}
strings!(Status { Refused => "refused", Disabled => "disabled" });
strings!(Reason {
    AuthorityInvalid => "reuse_authority_invalid", LaneIneligible => "reuse_lane_ineligible",
    CandidateUnverified => "reuse_candidate_unverified", SourceUnverified => "reuse_source_unverified",
    SourceUnavailable => "reuse_source_unavailable", SourceNotRoot => "reuse_source_not_root",
    CandidateBindingMismatch => "reuse_candidate_binding_mismatch", OriginMismatch => "reuse_origin_mismatch",
    OriginUnavailable => "reuse_origin_unavailable", SignerLevelMismatch => "reuse_signer_level_mismatch",
    ProducerUnauthorized => "reuse_producer_unauthorized", KeyMismatch => "reuse_key_mismatch",
    OutputsMismatch => "reuse_outputs_mismatch", CommandMismatch => "reuse_command_mismatch",
    MeasurementInvalid => "reuse_measurement_invalid", ObservationRenewed => "reuse_observation_renewed",
    TimeInvalid => "reuse_time_invalid", SourceExpired => "reuse_source_expired",
    BrokerUnauthorized => "reuse_broker_unauthorized", ReceiptContractUndefined => "receipt_contract_undefined",
    Disabled => "selective_reuse_disabled",
});
impl From<Refusal> for Reason {
    fn from(reason: Refusal) -> Self {
        match reason {
            Refusal::AuthorityInvalid => Self::AuthorityInvalid,
            Refusal::LaneIneligible => Self::LaneIneligible,
            Refusal::CandidateUnverified => Self::CandidateUnverified,
            Refusal::SourceUnverified => Self::SourceUnverified,
            Refusal::SourceNotRoot => Self::SourceNotRoot,
            Refusal::CandidateBindingMismatch => Self::CandidateBindingMismatch,
            Refusal::OriginMismatch => Self::OriginMismatch,
            Refusal::SignerLevelMismatch => Self::SignerLevelMismatch,
            Refusal::ProducerUnauthorized => Self::ProducerUnauthorized,
            Refusal::KeyMismatch => Self::KeyMismatch,
            Refusal::OutputsMismatch => Self::OutputsMismatch,
            Refusal::CommandMismatch => Self::CommandMismatch,
            Refusal::MeasurementInvalid => Self::MeasurementInvalid,
            Refusal::ObservationRenewed => Self::ObservationRenewed,
            Refusal::TimeInvalid => Self::TimeInvalid,
            Refusal::SourceExpired => Self::SourceExpired,
            Refusal::BrokerUnauthorized => Self::BrokerUnauthorized,
            Refusal::ReceiptContractUndefined => Self::ReceiptContractUndefined,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct SelectiveReuse {
    version: u32,
    status: Status,
    reason: Reason,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_record: Option<String>,
}
impl SelectiveReuse {
    pub(super) fn refusal(reason: Reason) -> Self {
        let status = if matches!(reason, Reason::ReceiptContractUndefined | Reason::Disabled) {
            Status::Disabled
        } else {
            Status::Refused
        };
        Self {
            version: 1,
            status,
            reason,
            root_record: None,
        }
    }
}
// Explicit map-only wrapper; derived struct decoding alone also accepts arrays.
impl<'de> Deserialize<'de> for SelectiveReuse {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            version: u32,
            status: Status,
            reason: Reason,
            #[serde(default, deserialize_with = "root")]
            root_record: Option<String>,
        }
        fn root<'de, D: de::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
            let value = String::deserialize(d)?;
            if !crate::gate::config::full_commit(&value) {
                return Err(de::Error::custom("invalid root ID"));
            }
            Ok(Some(value))
        }
        struct Map;
        impl<'de> de::Visitor<'de> for Map {
            type Value = SelectiveReuse;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("selective reuse object")
            }
            fn visit_map<M: de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                let wire = Wire::deserialize(de::value::MapAccessDeserializer::new(map))?;
                if wire.version != 1 {
                    return Err(de::Error::custom("unsupported selective reuse version"));
                }
                Ok(SelectiveReuse {
                    version: 1,
                    status: wire.status,
                    reason: wire.reason,
                    root_record: wire.root_record,
                })
            }
        }
        d.deserialize_map(Map)
    }
}

pub(super) fn attempt<R: v2::Receipt>(
    repo: &Path,
    input: verified::CandidateNote<'_>,
    current: &Config,
    check: &str,
    context: Option<&AuthenticatedPrCandidate<'_>>,
    receipts: &ReceiptValidation<'_>,
    now: DateTime<Utc>,
) -> SelectiveReuse {
    let ReuseAuthority::Valid(authority) = &current.policy.reuse_authority else {
        return SelectiveReuse::refusal(Reason::AuthorityInvalid);
    };
    if !authority.lanes.contains_key(check) {
        return SelectiveReuse::refusal(Reason::LaneIneligible);
    }
    let candidate =
        match verified::candidate_with_receipt::<R>(repo, input, &current.policy.reuse_authority) {
            Ok(candidate) => candidate,
            Err(error) => {
                // Production retains the sealed decoder's early stop: no signature
                // verification or root lookup occurs for an undefined receipt.
                let reason = if error == verified::Refusal::InvalidStatement
                    && matches!(receipts.result, Err(Refusal::ReceiptContractUndefined))
                {
                    Reason::ReceiptContractUndefined
                } else {
                    Reason::CandidateUnverified
                };
                return SelectiveReuse::refusal(reason);
            }
        };
    let VerifiedStatement::V2(statement) = &candidate.statement else {
        return SelectiveReuse::refusal(Reason::CandidateUnverified);
    };
    let Some(root_id) = statement.predicate.reused_from.as_deref() else {
        return SelectiveReuse::refusal(Reason::SourceNotRoot);
    };
    let root =
        match verified::root_with_receipt::<R>(repo, root_id, &current.policy.reuse_authority) {
            Ok(root) => root,
            Err(error) => {
                return SelectiveReuse::refusal(match error {
                    verified::Refusal::Unavailable | verified::Refusal::Oversized => {
                        Reason::SourceUnavailable
                    }
                    verified::Refusal::NotRoot | verified::Refusal::V1Promotion => {
                        Reason::SourceNotRoot
                    }
                    _ => Reason::SourceUnverified,
                });
            }
        };
    let mut diagnostic = SelectiveReuse::refusal(Reason::Disabled);
    diagnostic.root_record = Some(root.record.clone());
    let evaluate = || -> Result<(), Reason> {
        let VerifiedStatement::V2(root_statement) = &root.statement else {
            return Err(Reason::SourceUnverified);
        };
        let subject = &root_statement.subject[0]; // strict object decoder checks cardinality
        let base = &root_statement.predicate.origin.accepted_base;
        if git::git_bounded(repo, &["cat-file", "-t", base], 32)
            .map_err(|_| Reason::SourceUnavailable)?
            != b"commit\n"
        {
            return Err(Reason::SourceUnverified);
        }
        let parents = git::git_bounded(repo, &["show", "-s", "--format=%P", &subject.name], 4096)
            .map_err(|_| Reason::SourceUnavailable)?;
        let parents: Vec<String> = std::str::from_utf8(&parents)
            .map_err(|_| Reason::SourceUnverified)?
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let objects = SubjectObjects {
            head: &subject.name,
            tree: &subject.digest.git_tree,
            accepted_base: base,
            parents: &parents,
        };
        let lane = current
            .policy
            .lanes
            .get(check)
            .ok_or(Reason::LaneIneligible)?;
        let head = context.map_or(statement.subject[0].name.as_str(), |context| {
            context.objects.head
        });
        let expected = crate::gate::config::expected_inputs(
            repo,
            head,
            check,
            lane,
            &current.environment,
            &current.environment_bytes,
        )
        .map_err(|_| Reason::CandidateBindingMismatch)?;
        validate(&Validation {
            current,
            check,
            expected: &expected,
            context,
            candidate: &candidate,
            root: &root,
            root_objects: &objects,
            receipts,
            now,
        })
        .map_err(|reason| {
            if context.is_none() && reason == Refusal::OriginMismatch {
                Reason::OriginUnavailable
            } else {
                reason.into()
            }
        })?;
        Ok(())
    };
    if let Err(reason) = evaluate() {
        diagnostic = SelectiveReuse {
            root_record: diagnostic.root_record,
            ..SelectiveReuse::refusal(reason)
        };
    }
    // Unconditional production admission stop, also exercised by complete test
    // proofs. No configuration, flag, feature or receipt can turn this into skip.
    diagnostic
}
