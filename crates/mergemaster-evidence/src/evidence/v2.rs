//! Structural v2 decoding only. No v2 statement is usable until the broker receipt
//! contract exists; neither this module nor its test-only shape decoder grants trust.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde::{
    Deserialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{collections::BTreeMap, fmt};

pub const PREDICATE_TYPE: &str = "https://compounding.tech/fractal/evidence/gate/v2";
// Conservative admission limits: a single check needs only a small note and argv.
// Apply before typed decoding, including extensible input maps and ignored receipts.
pub const MAX_NOTE_BYTES: usize = 128 * 1024;
pub const MAX_MAP_ENTRIES: usize = 128;
pub const MAX_LIST_ENTRIES: usize = 64;
pub const MAX_DEPTH: usize = 16;
const RECEIPT_REFUSAL: &str = "daemon policy receipt contract not yet defined";
mod sealed {
    pub trait Receipt {}
    impl Receipt for super::DaemonPolicyReceipt {}
}
/// Sealed so the receipt cannot be substituted with an accepting type in production.
pub trait Receipt: sealed::Receipt + serde::de::DeserializeOwned {}
impl Receipt for DaemonPolicyReceipt {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "R: Receipt"))]
pub struct Statement<R: Receipt = DaemonPolicyReceipt> {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub repository: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Predicate<R>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub name: String,
    pub digest: Digest,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Digest {
    #[serde(rename = "gitTree")]
    pub git_tree: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "R: Receipt"))]
pub struct Predicate<R: Receipt> {
    pub schema_version: u32,
    pub change_id: String,
    pub signer: String,
    pub tier: String,
    pub issuer: Issuer,
    pub producer_sha256: String,
    pub observed_at: String,
    pub attested_at: String,
    pub origin: Origin,
    pub reuse_key: ReuseKey,
    pub daemon_policy_receipt: R,
    pub observed: Observed,
    #[serde(default, deserialize_with = "present")]
    pub reused_from: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    pub key_id: String,
    pub service_id: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub class: OriginClass,
    pub repository: String,
    pub source_repository: String,
    pub subject_head: String,
    pub accepted_base: String,
    pub event_kind: EventKind,
    #[serde(default, deserialize_with = "present")]
    pub pull_request: Option<PullRequest>,
    #[serde(default, deserialize_with = "present")]
    pub train_mapping: Option<TrainMapping>,
}
// Deserialize through String rather than serde's externally tagged enum visitor,
// which would also accept singleton objects after the bounded JSON parse.
macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: de::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                match String::deserialize(d)?.as_str() {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(de::Error::custom("invalid v2 enum")),
                }
            }
        }
    };
}
string_enum!(OriginClass {
    SameRepositoryPr => "same_repository_pr",
    ForkPr => "fork_pr",
    Push => "push",
    Local => "local",
});
string_enum!(EventKind {
    PullRequest => "pull_request",
    Push => "push",
    Local => "local",
});
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequest {
    pub number: u64,
    pub head: String,
    pub base_ref: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainMapping {
    pub kind: String,
    pub candidate: String,
    pub accepted_base: String,
    pub pull_request: u64,
    pub pr_head: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseKey {
    pub version: u32,
    pub check: String,
    pub nix_derivation: String,
    pub expected_inputs: BTreeMap<String, String>,
    pub nix_settings_sha256: String,
    pub nix_daemon_policy_sha256: String,
    pub producer: Producer,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    pub executable_sha256: String,
    pub system: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observed {
    pub kind: String,
    pub runner: String,
    pub checks: BTreeMap<String, Check>,
    pub inputs: BTreeMap<String, String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub command: Vec<String>,
    pub exit_code: i32,
    pub output_sha256: String,
}

#[derive(Debug)]
pub struct DaemonPolicyReceipt {
    _private: (),
}
impl<'de> Deserialize<'de> for DaemonPolicyReceipt {
    fn deserialize<D: de::Deserializer<'de>>(_: D) -> std::result::Result<Self, D::Error> {
        Err(de::Error::custom(RECEIPT_REFUSAL))
    }
}
fn present<'de, D: de::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

// A bounded recursive visitor preserves duplicate detection before Value's map can
// overwrite anything. This also covers arbitrary keys in inputs and the receipt.
struct StrictValue(usize);
impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        if self.0 > MAX_DEPTH {
            return Err(de::Error::custom("v2 nesting limit"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for StrictValue {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded duplicate-free JSON")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> std::result::Result<Value, M::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = m.next_key::<String>()? {
            if values.len() >= MAX_MAP_ENTRIES {
                return Err(de::Error::custom("v2 map limit"));
            }
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate v2 member"));
            }
            values.insert(key, m.next_value_seed(StrictValue(self.0 + 1))?);
        }
        Ok(Value::Object(values))
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut s: S) -> std::result::Result<Value, S::Error> {
        let mut values = Vec::new();
        // SeqAccess cannot peek: one excess element is decoded before refusal,
        // still subject to the note-byte and nesting limits. Map limits above
        // apply after decoding a key but before decoding its value.
        while let Some(value) = s.next_element_seed(StrictValue(self.0 + 1))? {
            if values.len() >= MAX_LIST_ENTRIES {
                return Err(de::Error::custom("v2 list limit"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
}
fn parse(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() <= MAX_NOTE_BYTES, "v2 note byte limit");
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue(0).deserialize(&mut decoder)?;
    decoder.end()?;
    check_lists(&value, "root")?;
    Ok(value)
}

// Lists are admitted only at the two schema list positions, never as positional
// encodings of objects. The opaque receipt also gets no list exception: its
// future contract must explicitly define any lists before they can be admitted.
fn check_lists(value: &Value, position: &str) -> Result<()> {
    match value {
        Value::Array(values) => {
            ensure!(
                matches!(position, "subject" | "command"),
                "v2 unexpected list"
            );
            for value in values {
                check_lists(value, "other")?;
            }
        }
        Value::Object(values) => {
            for (name, value) in values {
                let next = match (position, name.as_str()) {
                    ("root", "subject") => "subject",
                    ("root", "predicate") => "predicate",
                    ("predicate", "observed") => "observed",
                    ("observed", "checks") => "checks",
                    ("checks", _) => "check",
                    ("check", "command") => "command",
                    _ => "other",
                };
                check_lists(value, next)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn decode(bytes: &[u8]) -> Result<Statement> {
    let statement: Statement = serde_json::from_value(parse(bytes)?)?;
    validate(&statement)?;
    Ok(statement)
}
fn hex(value: &str, size: usize) -> Result<()> {
    ensure!(
        value.len() == size
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid lowercase hexadecimal identifier"
    );
    Ok(())
}
fn nonempty(value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "empty v2 string");
    Ok(())
}
fn timestamp(value: &str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    let time = chrono::DateTime::parse_from_rfc3339(value)?;
    ensure!(
        time.offset().local_minus_utc() == 0 && !value.ends_with("-00:00"),
        "v2 timestamp must denote UTC"
    );
    Ok(time)
}
fn validate<R: Receipt>(s: &Statement<R>) -> Result<()> {
    ensure!(
        s.statement_type == super::STATEMENT_TYPE && s.predicate_type == PREDICATE_TYPE,
        "unsupported v2 evidence format"
    );
    super::validate_repository(&s.repository)?;
    ensure!(s.subject.len() == 1, "v2 needs one subject");
    let subject = &s.subject[0];
    hex(&subject.name, 40)?;
    hex(&subject.digest.git_tree, 40)?;
    let p = &s.predicate;
    ensure!(
        p.schema_version == 2 && p.tier == "full",
        "unsupported v2 schema or tier"
    );
    nonempty(&p.change_id)?;
    nonempty(&p.signer)?;
    ensure!(!p.signer.chars().any(char::is_whitespace), "invalid signer");
    nonempty(&p.issuer.service_id)?;
    let fingerprint = p
        .issuer
        .key_id
        .strip_prefix("SHA256:")
        .context("invalid issuer fingerprint")?;
    let fingerprint_bytes = STANDARD_NO_PAD.decode(fingerprint)?;
    ensure!(
        fingerprint_bytes.len() == 32 && STANDARD_NO_PAD.encode(&fingerprint_bytes) == fingerprint,
        "invalid issuer fingerprint"
    );
    hex(&p.producer_sha256, 64)?;
    ensure!(
        timestamp(&p.observed_at)? <= timestamp(&p.attested_at)?,
        "observation after attestation"
    );
    let o = &p.origin;
    super::validate_repository(&o.repository)?;
    super::validate_repository(&o.source_repository)?;
    ensure!(
        o.repository == s.repository && o.subject_head == subject.name,
        "origin subject/repository mismatch"
    );
    hex(&o.subject_head, 40)?;
    hex(&o.accepted_base, 40)?;
    match o.class {
        OriginClass::SameRepositoryPr | OriginClass::ForkPr => {
            ensure!(o.event_kind == EventKind::PullRequest, "PR event mismatch");
            ensure!(
                (o.source_repository == s.repository) == (o.class == OriginClass::SameRepositoryPr),
                "PR source mismatch"
            );
            let pr = o.pull_request.as_ref().context("missing PR")?;
            ensure!(pr.number > 0, "invalid PR number");
            hex(&pr.head, 40)?;
            nonempty(&pr.base_ref)?;
            if let Some(t) = &o.train_mapping {
                ensure!(
                    t.kind == "single_pr_merge"
                        && t.candidate == o.subject_head
                        && t.accepted_base == o.accepted_base
                        && t.pull_request == pr.number
                        && t.pr_head == pr.head
                        && o.subject_head != pr.head,
                    "invalid train mapping"
                );
            } else {
                ensure!(o.subject_head == pr.head, "prepared PR needs train mapping");
            }
        }
        OriginClass::Push | OriginClass::Local => {
            let event = if o.class == OriginClass::Push {
                EventKind::Push
            } else {
                EventKind::Local
            };
            ensure!(
                o.event_kind == event
                    && o.source_repository == s.repository
                    && o.pull_request.is_none()
                    && o.train_mapping.is_none(),
                "non-PR origin mismatch"
            );
        }
    }
    let key = &p.reuse_key;
    ensure!(key.version == 1, "unsupported reuse key version");
    nonempty(&key.check)?;
    nonempty(&key.nix_derivation)?;
    nonempty(&key.producer.system)?;
    hex(&key.nix_settings_sha256, 64)?;
    hex(&key.nix_daemon_policy_sha256, 64)?;
    hex(&key.producer.executable_sha256, 64)?;
    ensure!(
        key.producer.executable_sha256 == p.producer_sha256,
        "producer digest mismatch"
    );
    let observed = &p.observed;
    ensure!(
        observed.kind == "tests" && observed.runner == "nix" && observed.checks.len() == 1,
        "v2 needs one Nix check"
    );
    let check = observed
        .checks
        .get(&key.check)
        .context("reuse check mismatch")?;
    ensure!(
        check.exit_code == 0 && !check.command.is_empty() && !check.command[0].is_empty(),
        "invalid successful check"
    );
    hex(&check.output_sha256, 64)?;
    for map in [&key.expected_inputs, &observed.inputs] {
        for (name, value) in map {
            nonempty(name)?;
            nonempty(value)?;
        }
    }
    let inputs = &observed.inputs;
    ensure!(
        inputs.get("wrapper_sha256") == Some(&p.producer_sha256)
            && inputs.get("system") == Some(&key.producer.system),
        "measured producer mismatch"
    );
    let mode = if let Some(root) = &p.reused_from {
        hex(root, 40)?;
        "reused"
    } else {
        "rebuild"
    };
    ensure!(
        inputs.get("nix_execution").map(String::as_str) == Some(mode)
            && inputs.get("nix_command_mode").map(String::as_str) == Some(mode),
        "root/rebind mode mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    impl sealed::Receipt for Value {}
    impl Receipt for Value {}

    #[test]
    fn v2_enums_are_string_only() {
        assert!(shape(&fixture()).is_ok());
        for (path, variant) in [
            ("/predicate/origin/class", "same_repository_pr"),
            ("/predicate/origin/event_kind", "pull_request"),
        ] {
            let mut value = fixture();
            *value.pointer_mut(path).unwrap() = json!({(variant): null});
            assert!(shape(&value).is_err(), "{path}");
            *value.pointer_mut(path).unwrap() = json!(variant);
            assert!(shape(&value).is_ok(), "{path}");
        }
        for name in ["same_repository_pr", "fork_pr", "push", "local"] {
            assert!(serde_json::from_value::<OriginClass>(json!(name)).is_ok());
            assert!(serde_json::from_value::<OriginClass>(json!({(name): null})).is_err());
        }
        for name in ["pull_request", "push", "local"] {
            assert!(serde_json::from_value::<EventKind>(json!(name)).is_ok());
            assert!(serde_json::from_value::<EventKind>(json!({(name): null})).is_err());
        }
    }

    // This entry point exists only in tests and never decodes a broker receipt.
    fn decode_shape(bytes: &[u8]) -> Result<Statement<Value>> {
        let statement = serde_json::from_value(parse(bytes)?)?;
        validate(&statement)?;
        Ok(statement)
    }
    fn fixture() -> Value {
        let commit = "a".repeat(40);
        let digest = "b".repeat(64);
        json!({
            "_type": super::super::STATEMENT_TYPE, "repository": "example/project",
            "subject": [{"name": commit, "digest": {"gitTree": "c".repeat(40)}}],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "schema_version": 2, "change_id": "pr-41", "signer": "agent/service",
                "tier": "full", "issuer": {
                    "key_id": format!("SHA256:{}", STANDARD_NO_PAD.encode([0; 32])),
                    "service_id": "service:linux-v1"
                },
                "producer_sha256": digest,
                "observed_at": "2026-11-22T10:00:00Z",
                "attested_at": "2026-11-22T10:00:00+00:00",
                "origin": {
                    "class": "same_repository_pr", "repository": "example/project",
                    "source_repository": "example/project", "subject_head": commit,
                    "accepted_base": "d".repeat(40), "event_kind": "pull_request",
                    "pull_request": {"number": 41, "head": commit, "base_ref": "main"}
                },
                "reuse_key": {
                    "version": 1, "check": "format", "nix_derivation": "/nix/store/check.drv",
                    "expected_inputs": {"system": "x86_64-linux"},
                    "nix_settings_sha256": digest, "nix_daemon_policy_sha256": digest,
                    "producer": {"executable_sha256": digest, "system": "x86_64-linux"}
                },
                "daemon_policy_receipt": null,
                "observed": {
                    "kind": "tests", "runner": "nix",
                    "checks": {"format": {"command": ["nix", "build"], "exit_code": 0, "output_sha256": digest}},
                    "inputs": {
                        "system": "x86_64-linux", "wrapper_sha256": digest,
                        "nix_execution": "rebuild", "nix_command_mode": "rebuild"
                    }
                }
            }
        })
    }
    fn shape(value: &Value) -> Result<Statement<Value>> {
        decode_shape(&serde_json::to_vec(value)?)
    }
    fn v1_fixture() -> Value {
        json!({
            "_type": super::super::STATEMENT_TYPE,
            "subject": [{"name": "a".repeat(40), "digest": {"gitTree": "b".repeat(40)}}],
            "predicateType": super::super::PREDICATE_TYPE,
            "predicate": {
                "schema_version": 1, "change_id": "legacy", "signer": "agent/legacy",
                "tier": "full", "producer_sha256": "c".repeat(64),
                "observed_at": "2026-11-22T10:00:00Z",
                "observed": {"kind": "tests", "runner": "wrapper",
                    "checks": {"format": {"command": ["true"], "exit_code": 0, "output_sha256": "d".repeat(64)}}}
            }
        })
    }
    #[test]
    fn v2_uri_version_dispatch_is_strict() {
        assert!(shape(&fixture()).is_ok());
        let legacy = v1_fixture();
        assert!(super::super::decode_statement(&serde_json::to_vec(&legacy).unwrap()).is_ok());
        assert!(shape(&legacy).is_err());
        let mut value = fixture();
        value["predicate"]["schema_version"] = json!(1);
        assert!(shape(&value).is_err());
        value = fixture();
        value["predicateType"] = json!(super::super::PREDICATE_TYPE);
        assert!(shape(&value).is_err());
        assert!(super::super::decode_statement(&serde_json::to_vec(&fixture()).unwrap()).is_err());
        let mut legacy = legacy;
        legacy["predicateType"] = json!(PREDICATE_TYPE);
        assert!(super::super::decode_statement(&serde_json::to_vec(&legacy).unwrap()).is_err());
    }
    #[test]
    fn v1_rejects_v2_fields_without_downgrade() {
        for member in [
            "issuer",
            "origin",
            "attested_at",
            "reuse_key",
            "daemon_policy_receipt",
            "reused_from",
        ] {
            let mut value = v1_fixture();
            value["predicate"][member] = Value::Null;
            assert!(
                super::super::decode_statement(&serde_json::to_vec(&value).unwrap()).is_err(),
                "{member}"
            );
        }
    }
    #[test]
    fn v2_missing_unknown_duplicate_fields_refuse() {
        let original = fixture();
        // Every required structured member is tested for absence and each object
        // (including extensible maps) for duplicate keys at the raw JSON boundary.
        fn walk(value: &Value, path: &str, paths: &mut Vec<String>) {
            if let Some(object) = value.as_object() {
                paths.push(path.into());
                for (key, child) in object {
                    walk(child, &format!("{path}/{key}"), paths);
                }
            } else if let Some(array) = value.as_array() {
                for (i, child) in array.iter().enumerate() {
                    walk(child, &format!("{path}/{i}"), paths);
                }
            }
        }
        let mut paths = Vec::new();
        walk(&original, "", &mut paths);
        for path in paths {
            let object = original.pointer(&path).unwrap().as_object().unwrap();
            for key in object.keys() {
                let mut missing = original.clone();
                missing
                    .pointer_mut(&path)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(key);
                // Extensible maps need no particular arbitrary key beyond the
                // explicitly required producer/mode bindings and check identity.
                if !path.ends_with("/inputs") && !path.ends_with("/expected_inputs") {
                    assert!(shape(&missing).is_err(), "missing {path}/{key}");
                }
            }
            let mut duplicate = original.clone();
            let key = object.keys().next().unwrap();
            let encoded = serde_json::to_string(&object[key]).unwrap();
            let marker = "__duplicate_marker__";
            duplicate.pointer_mut(&path).unwrap()[key] = json!(marker);
            let raw = serde_json::to_string(&duplicate).unwrap().replace(
                &format!("\"{key}\":\"{marker}\""),
                &format!("\"{key}\":{encoded},\"{key}\":{encoded}"),
            );
            assert!(decode_shape(raw.as_bytes()).is_err(), "duplicate {path}");
            if !path.ends_with("/inputs")
                && !path.ends_with("/expected_inputs")
                && !path.ends_with("/checks")
            {
                let mut unknown = original.clone();
                unknown.pointer_mut(&path).unwrap()["unknown"] = json!("value");
                assert!(shape(&unknown).is_err(), "unknown {path}");
            }
        }
        for path in [
            "/predicate/re_attests",
            "/predicate/reused_from",
            "/predicate/origin/pull_request",
            "/predicate/origin/train_mapping",
        ] {
            let mut value = original.clone();
            let (parent, key) = path.rsplit_once('/').unwrap();
            value.pointer_mut(parent).unwrap()[key] = Value::Null;
            assert!(shape(&value).is_err(), "null {path}");
        }
        for (path, invalid) in [
            ("/subject/0/name", json!("A".repeat(40))),
            ("/subject/0/digest/gitTree", json!("a".repeat(39))),
            ("/predicate/producer_sha256", json!("B".repeat(64))),
            ("/predicate/issuer/key_id", json!("SHA256:invalid")),
            (
                "/predicate/issuer/key_id",
                json!(format!("SHA256:{}=", STANDARD_NO_PAD.encode([0; 32]))),
            ),
            ("/predicate/schema_version", json!(2.0)),
            ("/predicate/reuse_key/version", json!(2)),
            ("/predicate/observed_at", json!("2026-11-22T11:00:00+01:00")),
            ("/predicate/observed_at", json!("2026-11-22T10:00:00-00:00")),
            ("/predicate/origin/class", json!("unknown")),
            ("/predicate/origin/pull_request/number", json!(0)),
            (
                "/predicate/observed/inputs/wrapper_sha256",
                json!("f".repeat(64)),
            ),
            ("/predicate/observed/inputs/system", json!("other-system")),
            (
                "/predicate/reuse_key/producer/executable_sha256",
                json!("f".repeat(64)),
            ),
        ] {
            let mut value = original.clone();
            *value.pointer_mut(path).unwrap() = invalid;
            assert!(shape(&value).is_err(), "{path}");
        }
    }
    #[test]
    fn v2_root_and_rebind_shapes_are_disjoint() {
        let root = fixture();
        assert!(shape(&root).is_ok());
        let mut rebind = root.clone();
        rebind["predicate"]["reused_from"] = json!("e".repeat(40));
        assert!(shape(&rebind).is_err());
        for key in ["nix_execution", "nix_command_mode"] {
            rebind["predicate"]["observed"]["inputs"][key] = json!("reused");
        }
        assert!(shape(&rebind).is_ok());
        let mut invalid = rebind.clone();
        invalid["predicate"]
            .as_object_mut()
            .unwrap()
            .remove("reused_from");
        assert!(shape(&invalid).is_err());
        invalid = root.clone();
        invalid["predicate"]["observed_at"] = json!("2026-11-22T10:00:01Z");
        assert!(shape(&invalid).is_err());
        for class in ["push", "local"] {
            let mut value = root.clone();
            value["predicate"]["origin"]["class"] = json!(class);
            value["predicate"]["origin"]["event_kind"] = json!(class);
            assert!(shape(&value).is_err());
            value["predicate"]["origin"]
                .as_object_mut()
                .unwrap()
                .remove("pull_request");
            assert!(shape(&value).is_ok());
        }
        let mut prepared = root.clone();
        prepared["predicate"]["origin"]["pull_request"]["head"] = json!("f".repeat(40));
        assert!(shape(&prepared).is_err());
        prepared["predicate"]["origin"]["train_mapping"] = json!({
            "kind": "single_pr_merge", "candidate": "a".repeat(40),
            "accepted_base": "d".repeat(40), "pull_request": 41, "pr_head": "f".repeat(40)
        });
        assert!(shape(&prepared).is_ok());
        prepared["predicate"]["origin"]["train_mapping"]["pull_request"] = json!(42);
        assert!(shape(&prepared).is_err());
    }
    #[test]
    fn v2_decode_bounds_refuse() {
        let mut value = fixture();
        value["predicate"]["change_id"] = json!("x".repeat(MAX_NOTE_BYTES));
        assert!(shape(&value).is_err());
        value = fixture();
        let inputs = value["predicate"]["observed"]["inputs"]
            .as_object_mut()
            .unwrap();
        for i in inputs.len()..MAX_MAP_ENTRIES {
            inputs.insert(format!("key{i}"), json!("value"));
        }
        assert!(shape(&value).is_ok());
        value["predicate"]["observed"]["inputs"]["overflow"] = json!("value");
        assert!(shape(&value).is_err());
        value = fixture();
        value["predicate"]["observed"]["checks"]["format"]["command"] =
            json!(vec!["arg"; MAX_LIST_ENTRIES]);
        assert!(shape(&value).is_ok());
        value["predicate"]["observed"]["checks"]["format"]["command"] =
            json!(vec!["arg"; MAX_LIST_ENTRIES + 1]);
        assert!(shape(&value).is_err());
        let raw = format!(
            "{}0{}",
            "[".repeat(MAX_DEPTH + 1),
            "]".repeat(MAX_DEPTH + 1)
        );
        assert!(parse(raw.as_bytes()).is_err());
    }
    #[test]
    fn v2_positional_struct_arrays_refuse() {
        fn walk(value: &Value, path: &str, paths: &mut Vec<String>) {
            match value {
                Value::Object(values) => {
                    paths.push(path.into());
                    for (key, value) in values {
                        walk(value, &format!("{path}/{key}"), paths);
                    }
                }
                Value::Array(values) => {
                    for (index, value) in values.iter().enumerate() {
                        walk(value, &format!("{path}/{index}"), paths);
                    }
                }
                _ => {}
            }
        }
        let original = fixture();
        let mut paths = Vec::new();
        walk(&original, "", &mut paths);
        for path in paths {
            let mut value = original.clone();
            let positional = value
                .pointer(&path)
                .unwrap()
                .as_object()
                .unwrap()
                .values()
                .cloned()
                .collect();
            *value.pointer_mut(&path).unwrap() = Value::Array(positional);
            assert_eq!(
                shape(&value).unwrap_err().to_string(),
                "v2 unexpected list",
                "{path}"
            );
        }
        let mut value = original;
        value["predicate"]["daemon_policy_receipt"] = json!({"opaque": []});
        assert_eq!(shape(&value).unwrap_err().to_string(), "v2 unexpected list");
    }
    #[test]
    fn v2_floats_refuse() {
        for path in [
            "/predicate/schema_version",
            "/predicate/observed/checks/format/exit_code",
            "/predicate/daemon_policy_receipt",
        ] {
            let mut value = fixture();
            *value.pointer_mut(path).unwrap() = json!(1.5);
            assert!(
                parse(&serde_json::to_vec(&value).unwrap()).is_err(),
                "{path}"
            );
        }
    }
    #[test]
    fn legacy_probe_failures_keep_original_errors() {
        for bytes in [
            b"null".as_slice(),
            b"{}",
            b"[]",
            br#"["https://compounding.tech/fractal/evidence/gate/v2"]"#,
            br#"["https://compounding.tech/fractal/evidence/gate/v2",null]"#,
            br#""https://compounding.tech/fractal/evidence/gate/v2""#,
            br#"{"predicateType":null}"#,
        ] {
            let old = serde_json::from_slice::<super::super::Statement>(bytes)
                .context("decode evidence statement")
                .unwrap_err();
            let current = super::super::decode_statement(bytes).unwrap_err();
            assert_eq!(format!("{current:#}"), format!("{old:#}"));
        }
    }
    #[test]
    fn production_decoder_refuses_undefined_receipt() {
        for receipt in [
            Value::Null,
            json!({}),
            json!({"signed": "receipt"}),
            json!(true),
            json!("receipt"),
            json!(0),
        ] {
            let mut value = fixture();
            value["predicate"]["daemon_policy_receipt"] = receipt;
            assert!(shape(&value).is_ok());
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(
                decode(&bytes)
                    .unwrap_err()
                    .to_string()
                    .contains(RECEIPT_REFUSAL)
            );
            assert!(
                super::super::decode_statement(&bytes)
                    .unwrap_err()
                    .to_string()
                    .contains(RECEIPT_REFUSAL)
            );
        }
        let mut value = fixture();
        value["predicate"]
            .as_object_mut()
            .unwrap()
            .remove("daemon_policy_receipt");
        assert!(shape(&value).is_err());
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn section_9_8_root_and_rebind_golden_vectors() {
        // Section 9.8 templates, independently expanded rather than derived from
        // fixture(). Hash placeholders are concrete lowercase digests, argv
        // hashes cover the full template commands, and receipt null deliberately
        // remains non-validating until the broker contract is defined.
        const ROOT: &str = r#"{
  "_type": "https://in-toto.io/Statement/v1",
  "repository": "example/project",
  "subject": [
    {
      "name": "2a421650faad64bfe7796a8c3584b99cfe1b2732",
      "digest": {
        "gitTree": "abc7198173c93a06e7e13511cc14e87a6f7a7180"
      }
    }
  ],
  "predicateType": "https://compounding.tech/fractal/evidence/gate/v2",
  "predicate": {
    "schema_version": 2,
    "change_id": "pr-41",
    "signer": "agent/test-evidence-service",
    "tier": "full",
    "issuer": {
      "key_id": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "service_id": "service:linux-v1"
    },
    "producer_sha256": "042a1a517bf7126308d0461f8537b7b146617354e21f0dfa74266f343cfc53da",
    "observed_at": "2026-11-22T10:00:00Z",
    "attested_at": "2026-11-22T10:00:00Z",
    "origin": {
      "class": "same_repository_pr",
      "repository": "example/project",
      "source_repository": "example/project",
      "subject_head": "2a421650faad64bfe7796a8c3584b99cfe1b2732",
      "accepted_base": "93624c934226a571324d1be72fbe9d29136b5aa0",
      "event_kind": "pull_request",
      "pull_request": {
        "number": 41,
        "head": "2a421650faad64bfe7796a8c3584b99cfe1b2732",
        "base_ref": "main"
      }
    },
    "reuse_key": {
      "version": 1,
      "check": "format",
      "nix_derivation": "/nix/store/00000000000000000000000000000000-format.drv",
      "expected_inputs": {
        "environment_sha256": "541814ad8abe278017ca2b85ff93bc4b40f386a936dfe640dbdc554a1d015c29",
        "toolchain_sha256": "92e17373c4b34698e4ac2ea5f748cb17763b55224f05d0b6c0c162aeef83922b",
        "lane_definition_sha256": "c0b848127fe1d4f08c041c07b30faef3c9be6a61cb61b982b9915c10e2efdb3d",
        "system": "x86_64-linux"
      },
      "nix_settings_sha256": "8e297dfaaaafc188c770a40769ea5861fae3eb40e64d50bdfb74fb18e740d046",
      "nix_daemon_policy_sha256": "ae5a9f5c2223e61bcb58c0f67839cacae55e30364de21c76950bbb56ff5b4185",
      "producer": {
        "executable_sha256": "042a1a517bf7126308d0461f8537b7b146617354e21f0dfa74266f343cfc53da",
        "system": "x86_64-linux"
      }
    },
    "daemon_policy_receipt": null,
    "observed": {
      "kind": "tests",
      "runner": "nix",
      "checks": {
        "format": {
          "command": [
            "/trusted/nix",
            "--extra-experimental-features",
            "nix-command flakes",
            "--option",
            "accept-flake-config",
            "false",
            "--option",
            "pure-eval",
            "true",
            "--option",
            "allow-import-from-derivation",
            "false",
            "--option",
            "builders",
            "",
            "--option",
            "build-hook",
            "",
            "--option",
            "max-jobs",
            "1",
            "--log-format",
            "internal-json",
            "build",
            "--no-link",
            "--json",
            "--print-build-logs",
            "--option",
            "substitute",
            "false",
            "--rebuild",
            "/nix/store/00000000000000000000000000000000-format.drv^*"
          ],
          "exit_code": 0,
          "output_sha256": "31d166a07280fdd21cbe2df4eba57d1cbf57af9773e41442798ed3a26c47e3fd"
        }
      },
      "inputs": {
        "environment_sha256": "541814ad8abe278017ca2b85ff93bc4b40f386a936dfe640dbdc554a1d015c29",
        "toolchain_sha256": "92e17373c4b34698e4ac2ea5f748cb17763b55224f05d0b6c0c162aeef83922b",
        "lane_definition_sha256": "c0b848127fe1d4f08c041c07b30faef3c9be6a61cb61b982b9915c10e2efdb3d",
        "system": "x86_64-linux",
        "wrapper_sha256": "042a1a517bf7126308d0461f8537b7b146617354e21f0dfa74266f343cfc53da",
        "nix_derivation": "/nix/store/00000000000000000000000000000000-format.drv",
        "nix_execution": "rebuild",
        "nix_command_mode": "rebuild",
        "nix_command_sha256": "341727aa784452e2ef96993c6b06642bc590c336c5c79a80bfec16bc108a9012",
        "nix_settings_sha256": "8e297dfaaaafc188c770a40769ea5861fae3eb40e64d50bdfb74fb18e740d046",
        "nix_daemon_policy_sha256": "ae5a9f5c2223e61bcb58c0f67839cacae55e30364de21c76950bbb56ff5b4185",
        "nix_outputs_sha256": "519ee33ac0aee479d4a9cd544871139c3640752d330815d56295ab653b5e2bf9",
        "nix_store": "daemon",
        "nix_daemon_trusted": "true",
        "workspace_clean": "true",
        "untracked_files": "false",
        "attempt": "1"
      }
    }
  }
}"#;
        const REBIND: &str = r#"{
  "_type": "https://in-toto.io/Statement/v1",
  "repository": "example/project",
  "subject": [
    {
      "name": "158f8ce5975a19312b6c5aec2287781df18ceef5",
      "digest": {
        "gitTree": "738b69d430b052fb3af428fb0c50c9c47dca1f93"
      }
    }
  ],
  "predicateType": "https://compounding.tech/fractal/evidence/gate/v2",
  "predicate": {
    "schema_version": 2,
    "change_id": "pr-41",
    "signer": "agent/test-evidence-service",
    "tier": "full",
    "issuer": {
      "key_id": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "service_id": "service:linux-v1"
    },
    "producer_sha256": "042a1a517bf7126308d0461f8537b7b146617354e21f0dfa74266f343cfc53da",
    "observed_at": "2026-11-22T10:00:00Z",
    "attested_at": "2026-11-22T11:00:00Z",
    "reused_from": "9540f88d2c04f547dd0de6bb79cdf8b7d6a00778",
    "origin": {
      "class": "same_repository_pr",
      "repository": "example/project",
      "source_repository": "example/project",
      "subject_head": "158f8ce5975a19312b6c5aec2287781df18ceef5",
      "accepted_base": "dc247dcda13c9e91176f0ac4ea4ebab94ef8d7cd",
      "event_kind": "pull_request",
      "pull_request": {
        "number": 41,
        "head": "158f8ce5975a19312b6c5aec2287781df18ceef5",
        "base_ref": "main"
      }
    },
    "reuse_key": {
      "version": 1,
      "check": "format",
      "nix_derivation": "/nix/store/00000000000000000000000000000000-format.drv",
      "expected_inputs": {
        "environment_sha256": "541814ad8abe278017ca2b85ff93bc4b40f386a936dfe640dbdc554a1d015c29",
        "toolchain_sha256": "92e17373c4b34698e4ac2ea5f748cb17763b55224f05d0b6c0c162aeef83922b",
        "lane_definition_sha256": "c0b848127fe1d4f08c041c07b30faef3c9be6a61cb61b982b9915c10e2efdb3d",
        "system": "x86_64-linux"
      },
      "nix_settings_sha256": "8e297dfaaaafc188c770a40769ea5861fae3eb40e64d50bdfb74fb18e740d046",
      "nix_daemon_policy_sha256": "ae5a9f5c2223e61bcb58c0f67839cacae55e30364de21c76950bbb56ff5b4185",
      "producer": {
        "executable_sha256": "042a1a517bf7126308d0461f8537b7b146617354e21f0dfa74266f343cfc53da",
        "system": "x86_64-linux"
      }
    },
    "daemon_policy_receipt": null,
    "observed": {
      "kind": "tests",
      "runner": "nix",
      "checks": {
        "format": {
          "command": [
            "/trusted/nix",
            "--extra-experimental-features",
            "nix-command flakes",
            "--option",
            "accept-flake-config",
            "false",
            "--option",
            "pure-eval",
            "true",
            "--option",
            "allow-import-from-derivation",
            "false",
            "--option",
            "builders",
            "",
            "--option",
            "build-hook",
            "",
            "--option",
            "max-jobs",
            "1",
            "--log-format",
            "internal-json",
            "build",
            "--no-link",
            "--json",
            "--print-build-logs",
            "/nix/store/00000000000000000000000000000000-format.drv^*"
          ],
          "exit_code": 0,
          "output_sha256": "6eb028d7bc419ff34dafcbe24597ee38895c6b7303c2bc3ba3ce38c15e8dd1aa"
        }
      },
      "inputs": {
        "environment_sha256": "541814ad8abe278017ca2b85ff93bc4b40f386a936dfe640dbdc554a1d015c29",
        "toolchain_sha256": "92e17373c4b34698e4ac2ea5f748cb17763b55224f05d0b6c0c162aeef83922b",
        "lane_definition_sha256": "c0b848127fe1d4f08c041c07b30faef3c9be6a61cb61b982b9915c10e2efdb3d",
        "system": "x86_64-linux",
        "wrapper_sha256": "042a1a517bf7126308d0461f8537b7b146617354e21f0dfa74266f343cfc53da",
        "nix_derivation": "/nix/store/00000000000000000000000000000000-format.drv",
        "nix_execution": "reused",
        "nix_command_mode": "reused",
        "nix_command_sha256": "8b795b5d31c7b3309d9d822040b2cdf5b53c35f70056216a4b1c8357bc1b5de9",
        "nix_settings_sha256": "8e297dfaaaafc188c770a40769ea5861fae3eb40e64d50bdfb74fb18e740d046",
        "nix_daemon_policy_sha256": "ae5a9f5c2223e61bcb58c0f67839cacae55e30364de21c76950bbb56ff5b4185",
        "nix_outputs_sha256": "519ee33ac0aee479d4a9cd544871139c3640752d330815d56295ab653b5e2bf9",
        "nix_store": "daemon",
        "nix_daemon_trusted": "true",
        "workspace_clean": "true",
        "untracked_files": "false",
        "attempt": "2"
      }
    }
  }
}"#;
        for bytes in [ROOT.as_bytes(), REBIND.as_bytes()] {
            assert!(decode_shape(bytes).is_ok());
            assert!(
                decode(bytes)
                    .unwrap_err()
                    .to_string()
                    .contains(RECEIPT_REFUSAL)
            );
            assert!(
                super::super::decode_statement(bytes)
                    .unwrap_err()
                    .to_string()
                    .contains(RECEIPT_REFUSAL)
            );
        }
        let root = decode_shape(ROOT.as_bytes()).unwrap();
        let rebind = decode_shape(REBIND.as_bytes()).unwrap();
        assert!(root.predicate.reused_from.is_none());
        assert!(rebind.predicate.reused_from.is_some());
        assert_eq!(root.predicate.observed_at, rebind.predicate.observed_at);
    }
}
