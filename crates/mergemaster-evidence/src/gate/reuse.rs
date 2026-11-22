//! Pure selective-reuse validation, composed by disabled worker orchestration.
//! Receipt acceptance and authenticated-context construction have no production
//! implementation until their independently reviewed adapters exist.
use super::config::{self, Config, Lane, ReuseAuthority, ReuseKeyAuthority, ReuseRole};
use crate::evidence::{
    derivation, v2,
    verified::{VerifiedRecord, VerifiedStatement},
};
use chrono::{DateTime, Duration, Utc};
use std::{collections::BTreeMap, fmt};

#[path = "reuse_orchestration.rs"]
mod orchestration;
pub use orchestration::SelectiveReuse;
use orchestration::attempt;

pub(super) fn worker(args: &super::VerifyArgs) -> anyhow::Result<SelectiveReuse> {
    use anyhow::Context;
    let base = args
        .base
        .as_deref()
        .context("v2 requires current BASE authority")?;
    let current = config::load(&args.repo, base)?;
    let check = args.check.as_deref().context("v2 worker requires a lane")?;
    Ok(attempt::<v2::DaemonPolicyReceipt>(
        &args.repo,
        &args.record,
        &current,
        check,
        None,
        &ReceiptValidation::contract_undefined(),
        Utc::now(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    AuthorityInvalid,
    LaneIneligible,
    CandidateUnverified,
    SourceUnverified,
    SourceNotRoot,
    CandidateBindingMismatch,
    OriginMismatch,
    SignerLevelMismatch,
    ProducerUnauthorized,
    KeyMismatch,
    OutputsMismatch,
    CommandMismatch,
    MeasurementInvalid,
    ObservationRenewed,
    TimeInvalid,
    SourceExpired,
    BrokerUnauthorized,
    ReceiptContractUndefined,
}
impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "selective reuse validation refusal: {self:?}")
    }
}
impl std::error::Error for Refusal {}
type Result<T, E = Refusal> = std::result::Result<T, E>;

/// Object adapter facts, including proof that accepted_base is an actual commit.
/// Private fields deliberately provide no caller-JSON or unchecked constructor.
pub struct SubjectObjects<'a> {
    head: &'a str,
    tree: &'a str,
    accepted_base: &'a str,
    parents: &'a [String],
}
pub enum CandidateMapping {
    Direct,
    SinglePrMerge,
}
/// Only a future trusted GitHub/final-recheck adapter may construct this context.
/// No Deserialize implementation or production constructor is provided.
/// ```compile_fail
/// fn from_json<T: serde::de::DeserializeOwned>() {}
/// from_json::<mergemaster_evidence::gate::reuse::AuthenticatedPrCandidate<'static>>();
/// ```
/// Event files, local refs, push, queue and merge-group inputs cannot construct it.
pub struct AuthenticatedPrCandidate<'a> {
    repository: &'a str,
    source_repository: &'a str,
    pull_request: u64,
    pr_head: &'a str,
    base_ref: &'a str,
    objects: SubjectObjects<'a>,
    mapping: CandidateMapping,
}
/// An internal receipt-verifier result, not a receipt wire format. Snapshots are
/// rechecked against current BASE, so a previously verified broker grants no grace.
/// There is deliberately no production constructor for an accepted result.
/// This proof is not deserializable, including from an event file.
/// ```compile_fail
/// fn from_json<T: serde::de::DeserializeOwned>() {}
/// from_json::<mergemaster_evidence::gate::reuse::ReceiptValidation<'static>>();
/// ```
pub struct ReceiptValidation<'a> {
    result: Result<[&'a ReuseKeyAuthority; 2]>,
}
impl ReceiptValidation<'_> {
    pub fn contract_undefined() -> Self {
        Self {
            result: Err(Refusal::ReceiptContractUndefined),
        }
    }
}
pub struct Validation<'a, R: v2::Receipt = v2::DaemonPolicyReceipt> {
    pub current: &'a Config,
    pub check: &'a str,
    /// The entire shared config::expected_inputs result for the candidate.
    pub expected: &'a BTreeMap<String, String>,
    pub context: Option<&'a AuthenticatedPrCandidate<'a>>,
    pub candidate: &'a VerifiedRecord<R>,
    pub root: &'a VerifiedRecord<R>,
    pub root_objects: &'a SubjectObjects<'a>,
    pub receipts: &'a ReceiptValidation<'a>,
    pub now: DateTime<Utc>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedReuse<'a> {
    pub root_record: &'a str,
}

pub fn validate<'a, R: v2::Receipt>(input: &Validation<'a, R>) -> Result<ValidatedReuse<'a>> {
    let policy = &input.current.policy;
    let ReuseAuthority::Valid(authority) = &policy.reuse_authority else {
        return Err(Refusal::AuthorityInvalid);
    };
    let lane = policy
        .lanes
        .get(input.check)
        .ok_or(Refusal::LaneIneligible)?;
    let opt_in = authority
        .lanes
        .get(input.check)
        .ok_or(Refusal::LaneIneligible)?;
    if opt_in.version != 1
        || opt_in.origin_profile != "same_repository_pr"
        || opt_in.platform != "linux"
        || !lane
            .nix_check
            .as_ref()
            .is_some_and(|nix| nix.required == "any")
    {
        return Err(Refusal::LaneIneligible);
    }
    let age = lane
        .max_age_seconds
        .filter(|age| *age > 0)
        .and_then(|age| i64::try_from(age).ok())
        .and_then(Duration::try_seconds)
        .ok_or(Refusal::LaneIneligible)?;
    let candidate = statement(input.candidate).ok_or(Refusal::CandidateUnverified)?;
    let root = statement(input.root).ok_or(Refusal::SourceUnverified)?;
    if root.predicate.reused_from.is_some() || input.candidate.record == input.root.record {
        return Err(Refusal::SourceNotRoot);
    }
    if candidate.predicate.reused_from.as_deref() != Some(input.root.record.as_str()) {
        return Err(Refusal::SourceNotRoot);
    }
    let context = input.context.ok_or(Refusal::OriginMismatch)?;
    if policy.repository.as_deref() != Some(context.repository)
        || context.pull_request == 0
        || context.repository != context.source_repository
    {
        return Err(Refusal::OriginMismatch);
    }
    for note in [candidate, root] {
        let origin = &note.predicate.origin;
        if note.repository != context.repository
            || origin.repository != context.repository
            || origin.source_repository != context.repository
            || origin.class != v2::OriginClass::SameRepositoryPr
            || origin.event_kind != v2::EventKind::PullRequest
            || !origin
                .pull_request
                .as_ref()
                .is_some_and(|pr| pr.number == context.pull_request)
        {
            return Err(Refusal::OriginMismatch);
        }
    }
    subject(candidate, &context.objects).map_err(|_| Refusal::CandidateBindingMismatch)?;
    subject(root, input.root_objects)?;
    let pr = candidate
        .predicate
        .origin
        .pull_request
        .as_ref()
        .ok_or(Refusal::OriginMismatch)?;
    if pr.head != context.pr_head || pr.base_ref != context.base_ref {
        return Err(Refusal::OriginMismatch);
    }
    match context.mapping {
        CandidateMapping::Direct
            if context.objects.head == context.pr_head
                && candidate.predicate.origin.train_mapping.is_none() => {}
        CandidateMapping::SinglePrMerge
            if context.objects.head != context.pr_head
                && candidate.predicate.origin.train_mapping.is_some() => {}
        _ => return Err(Refusal::OriginMismatch),
    }
    let candidate_level =
        issuer(input.candidate, candidate, authority, lane).ok_or(Refusal::CandidateUnverified)?;
    let root_level = issuer(input.root, root, authority, lane).ok_or(Refusal::SourceUnverified)?;
    if root_level != candidate_level {
        return Err(Refusal::SignerLevelMismatch);
    }
    let settings = derivation::settings_digest().map_err(|_| Refusal::MeasurementInvalid)?;
    for (note, mode) in [(root, "rebuild"), (candidate, "reused")] {
        measurements(note, input.check, lane, input.expected, mode, &settings)?;
        let producer = &note.predicate.reuse_key.producer;
        if !matches!(producer.system.as_str(), "x86_64-linux" | "aarch64-linux")
            || !config::reuse_producer_authorized(
                input.current.producers.as_ref(),
                &note.predicate.producer_sha256,
                Some(&producer.system),
            )
        {
            return Err(Refusal::ProducerUnauthorized);
        }
    }
    if root.predicate.reuse_key != candidate.predicate.reuse_key {
        return Err(Refusal::KeyMismatch);
    }
    if root.predicate.observed.inputs.get("nix_outputs_sha256")
        != candidate
            .predicate
            .observed
            .inputs
            .get("nix_outputs_sha256")
    {
        return Err(Refusal::OutputsMismatch);
    }
    lifetime(root, candidate, input.now, age)?;
    let brokers = input.receipts.result.as_ref().map_err(|reason| *reason)?;
    for broker in brokers {
        if broker.role != ReuseRole::DaemonPolicyReceipt
            || broker.repository != context.repository
            || !authority
                .authorities
                .iter()
                .any(|current| same_authority(current, broker))
        {
            return Err(Refusal::BrokerUnauthorized);
        }
    }
    Ok(ValidatedReuse {
        root_record: &input.root.record,
    })
}
fn statement<R: v2::Receipt>(record: &VerifiedRecord<R>) -> Option<&v2::Statement<R>> {
    match &record.statement {
        VerifiedStatement::V2(statement)
            if record.version == 2 && config::full_commit(&record.record) =>
        {
            Some(statement)
        }
        _ => None,
    }
}
fn subject<R: v2::Receipt>(note: &v2::Statement<R>, objects: &SubjectObjects<'_>) -> Result<()> {
    let [subject] = note.subject.as_slice() else {
        return Err(Refusal::OriginMismatch);
    };
    let origin = &note.predicate.origin;
    if subject.name != objects.head
        || subject.digest.git_tree != objects.tree
        || origin.subject_head != objects.head
        || origin.accepted_base != objects.accepted_base
        || ![objects.head, objects.tree, objects.accepted_base]
            .iter()
            .all(|id| config::full_commit(id))
    {
        return Err(Refusal::OriginMismatch);
    }
    let pr = origin
        .pull_request
        .as_ref()
        .ok_or(Refusal::OriginMismatch)?;
    if let Some(mapping) = &origin.train_mapping {
        if mapping.kind != "single_pr_merge"
            || mapping.candidate != objects.head
            || mapping.accepted_base != objects.accepted_base
            || mapping.pull_request != pr.number
            || mapping.pr_head != pr.head
            || objects.head == pr.head
            || objects.parents != [objects.accepted_base, pr.head.as_str()]
        {
            return Err(Refusal::OriginMismatch);
        }
    } else if objects.head != pr.head {
        return Err(Refusal::OriginMismatch);
    }
    Ok(())
}
fn issuer<'a, R: v2::Receipt>(
    record: &VerifiedRecord<R>,
    note: &v2::Statement<R>,
    authority: &'a config::ReusePolicy,
    lane: &Lane,
) -> Option<&'a str> {
    let p = &note.predicate;
    let key = authority.authorities.iter().find(|key| {
        key.role == ReuseRole::V2ServiceIssuer
            && key.key_id == p.issuer.key_id
            && key.repository == note.repository
            && key.endpoint_id == p.issuer.service_id
            && key.principal == p.signer
            && record.verified_signer.as_deref() == Some(key.principal.as_str())
            && record.verified_key_id.as_deref() == Some(key.key_id.as_str())
    })?;
    let (level, _) = key.principal.split_once('/')?;
    lane.trust_levels
        .iter()
        .any(|allowed| allowed == level)
        .then_some(level)
}
fn same_authority(left: &ReuseKeyAuthority, right: &ReuseKeyAuthority) -> bool {
    left.role == right.role
        && left.key_id == right.key_id
        && left.public_key == right.public_key
        && left.principal == right.principal
        && left.repository == right.repository
        && left.endpoint_id == right.endpoint_id
}
fn measurements<R: v2::Receipt>(
    note: &v2::Statement<R>,
    check: &str,
    lane: &Lane,
    expected: &BTreeMap<String, String>,
    mode: &str,
    settings: &str,
) -> Result<()> {
    let p = &note.predicate;
    let key = &p.reuse_key;
    let observed = &p.observed;
    if p.schema_version != 2
        || p.tier != "full"
        || observed.kind != "tests"
        || observed.runner != "nix"
        || observed.checks.len() != 1
    {
        return Err(Refusal::MeasurementInvalid);
    }
    let observation = observed
        .checks
        .get(check)
        .ok_or(Refusal::MeasurementInvalid)?;
    if observation.exit_code != 0 || !digest(&observation.output_sha256) {
        return Err(Refusal::MeasurementInvalid);
    }
    let inputs = &observed.inputs;
    if key.version != 1
        || key.check != check
        || &key.expected_inputs != expected
        || expected
            .iter()
            .any(|(name, value)| inputs.get(name) != Some(value))
        || ["workspace_binding", "workspace_declaration_sha256"]
            .iter()
            .any(|name| inputs.get(*name) != expected.get(*name))
    {
        return Err(Refusal::KeyMismatch);
    }
    if key.producer.executable_sha256 != p.producer_sha256
        || inputs.get("wrapper_sha256") != Some(&p.producer_sha256)
        || inputs.get("system") != Some(&key.producer.system)
    {
        return Err(Refusal::ProducerUnauthorized);
    }
    let required = [
        ("nix_derivation", key.nix_derivation.as_str()),
        ("nix_execution", mode),
        ("nix_command_mode", mode),
        ("nix_settings_sha256", key.nix_settings_sha256.as_str()),
        (
            "nix_daemon_policy_sha256",
            key.nix_daemon_policy_sha256.as_str(),
        ),
        ("workspace_clean", "true"),
        ("untracked_files", "false"),
    ];
    if required
        .iter()
        .any(|(name, value)| inputs.get(*name).map(String::as_str) != Some(*value))
        || !inputs
            .get("attempt")
            .is_some_and(|value| value.parse::<u64>().is_ok_and(|n| n > 0))
        || !inputs
            .get("nix_outputs_sha256")
            .is_some_and(|value| digest(value))
        || !digest(&key.nix_daemon_policy_sha256)
        || key.nix_settings_sha256 != settings
        || !inputs.get("nix_store").is_some_and(|store| {
            store.starts_with("local")
                || (store.starts_with("daemon")
                    && inputs.get("nix_daemon_trusted").map(String::as_str) == Some("true"))
        })
    {
        return Err(Refusal::MeasurementInvalid);
    }
    let executable = lane.argv.first().ok_or(Refusal::CommandMismatch)?;
    let argv = derivation::argv(executable, &key.nix_derivation, mode)
        .map_err(|_| Refusal::CommandMismatch)?;
    if observation.command != argv
        || derivation::command_digest(&argv).ok().as_ref() != inputs.get("nix_command_sha256")
    {
        return Err(Refusal::CommandMismatch);
    }
    Ok(())
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn lifetime<R: v2::Receipt>(
    root: &v2::Statement<R>,
    candidate: &v2::Statement<R>,
    now: DateTime<Utc>,
    age: Duration,
) -> Result<()> {
    let parse = |value: &str| {
        v2::timestamp(value)
            .map(|time| time.with_timezone(&Utc))
            .map_err(|_| Refusal::TimeInvalid)
    };
    let root_observed = parse(&root.predicate.observed_at)?;
    let candidate_observed = parse(&candidate.predicate.observed_at)?;
    if root_observed != candidate_observed {
        return Err(Refusal::ObservationRenewed);
    }
    let ceiling = now
        .checked_add_signed(Duration::seconds(120))
        .ok_or(Refusal::TimeInvalid)?;
    // An underflowing cutoff precedes every representable observation.
    let oldest = now.checked_sub_signed(age);
    for (observed, note) in [(root_observed, root), (candidate_observed, candidate)] {
        let attested = parse(&note.predicate.attested_at)?;
        if observed > attested || observed > ceiling || attested > ceiling {
            return Err(Refusal::TimeInvalid);
        }
        // Compare instants instead of subtracting arbitrarily distant dates.
        if oldest.is_some_and(|cutoff| observed < cutoff) {
            return Err(Refusal::SourceExpired);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "reuse_tests.rs"]
mod tests;
