//! Every note mutation is signed and verified with real Git/SSH. Only receipt
//! input and authenticated-context construction are test-only proof constructors.
use super::*;
use crate::evidence::verified::{self, tests::Fixture};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

struct FixturePair {
    git: Fixture,
    config: Config,
    expected: BTreeMap<String, String>,
    root: Value,
    candidate: Value,
    base: String,
    head: String,
    tree: String,
    root_parents: Vec<String>,
    parents: Vec<String>,
    pr_head: String,
    prepared: bool,
    key: PathBuf,
    now: DateTime<Utc>,
}
impl FixturePair {
    fn new() -> Self {
        let git = Fixture::new();
        let mut policy: Value = serde_json::from_slice(
            &fs::read(git.root.path().join(".mergemaster/lanes.json")).unwrap(),
        )
        .unwrap();
        policy["lanes"]["format"]["trust_levels"] = json!(["agent", "host"]);
        git.write(".mergemaster/lanes.json", policy.to_string());
        let mut root = git.statement();
        git.write(".mergemaster/producers.json", json!({"version":1,"producers":[{
            "executable_sha256":root["predicate"]["producer_sha256"],"flavor":"v2_service","system":"x86_64-linux",
            "provenance":{"mergemaster_revision":"a".repeat(40),"package":"test-service"}
        }]}).to_string());
        git.write("source", "main moved\n");
        let base = git.commit("current BASE authority and manifest");
        git.write("source", "candidate after main move\n");
        let head = git.commit("candidate");
        let tree = git.git(&["rev-parse", "HEAD^{tree}"], b"");
        let config = config::load(git.root.path(), &base).unwrap();
        let expected = config::expected_inputs(
            git.root.path(),
            &head,
            "format",
            &config.policy.lanes["format"],
            &config.environment,
            &config.environment_bytes,
        )
        .unwrap();
        let now = DateTime::parse_from_rfc3339("2026-11-22T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut candidate = root.clone();
        candidate["subject"][0]["name"] = json!(head);
        candidate["subject"][0]["digest"]["gitTree"] = json!(tree);
        candidate["predicate"]["origin"]["subject_head"] = json!(head);
        candidate["predicate"]["origin"]["accepted_base"] = json!(base);
        candidate["predicate"]["origin"]["pull_request"]["head"] = json!(head);
        candidate["predicate"]["reused_from"] = json!("LINK_ROOT");
        for (note, mode) in [(&mut root, "rebuild"), (&mut candidate, "reused")] {
            let drv = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-format.drv";
            let argv = derivation::argv("/trusted/nix", drv, mode).unwrap();
            let p = &mut note["predicate"];
            p["observed_at"] = json!((now - Duration::seconds(60)).to_rfc3339());
            p["attested_at"] = json!((now - Duration::seconds(5)).to_rfc3339());
            p["reuse_key"]["expected_inputs"] = json!(expected);
            p["reuse_key"]["nix_derivation"] = json!(drv);
            p["reuse_key"]["nix_settings_sha256"] = json!(derivation::settings_digest().unwrap());
            p["observed"]["checks"]["format"]["command"] = json!(argv);
            p["observed"]["inputs"] = json!(expected);
            for (name, value) in [
                (
                    "wrapper_sha256",
                    p["producer_sha256"].as_str().unwrap().to_owned(),
                ),
                ("nix_derivation", drv.into()),
                ("nix_execution", mode.into()),
                ("nix_command_mode", mode.into()),
                (
                    "nix_settings_sha256",
                    derivation::settings_digest().unwrap(),
                ),
                (
                    "nix_daemon_policy_sha256",
                    p["reuse_key"]["nix_daemon_policy_sha256"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                ),
                (
                    "nix_command_sha256",
                    derivation::command_digest(&argv).unwrap(),
                ),
                ("nix_outputs_sha256", "e".repeat(64)),
                ("nix_store", "daemon".into()),
                ("nix_daemon_trusted", "true".into()),
                ("workspace_clean", "true".into()),
                ("untracked_files", "false".into()),
                ("attempt", "1".into()),
            ] {
                p["observed"]["inputs"][name] = json!(value);
            }
        }
        let parents = |id: &str| {
            git.git(&["show", "-s", "--format=%P", id], b"")
                .split_whitespace()
                .map(str::to_owned)
                .collect()
        };
        let root_parents = parents(&git.head);
        let candidate_parents = parents(&head);
        Self {
            key: git.key.clone(),
            git,
            config,
            expected,
            root,
            candidate,
            base,
            pr_head: head.clone(),
            head,
            tree,
            root_parents,
            parents: candidate_parents,
            prepared: false,
            now,
        }
    }
    fn current(&self) -> Config {
        config::load(self.git.root.path(), &self.base).unwrap()
    }
    fn check(&self, root: &Value, candidate: &Value) -> Result<()> {
        self.validate(root, candidate, &self.config, true, self.now, true)
    }
    fn validate(
        &self,
        root: &Value,
        candidate: &Value,
        current: &Config,
        receipt_accepted: bool,
        now: DateTime<Utc>,
        authenticated: bool,
    ) -> Result<()> {
        let root_id = self.git.raw_note(
            &serde_json::to_vec(root).unwrap(),
            &self.git.tree,
            &[&self.git.head],
            &self.git.key,
        );
        let keys = self.git.root.path().join(".mergemaster/evidence-keys");
        let root = verified::verify_with_receipt::<Value>(
            self.git.root.path(),
            &root_id,
            &keys,
            Some(&self.base),
        )
        .map_err(|_| Refusal::SourceUnverified)?;
        let mut candidate = candidate.clone();
        if candidate["predicate"]["reused_from"] == "LINK_ROOT" {
            candidate["predicate"]["reused_from"] = json!(root_id);
        }
        let candidate_id = self.git.raw_note(
            &serde_json::to_vec(&candidate).unwrap(),
            &self.tree,
            &[&self.head],
            &self.key,
        );
        let candidate = verified::verify_with_receipt::<Value>(
            self.git.root.path(),
            &candidate_id,
            &keys,
            Some(&self.base),
        )
        .map_err(|_| Refusal::CandidateUnverified)?;
        let root_objects = SubjectObjects {
            head: &self.git.head,
            tree: &self.git.tree,
            accepted_base: &self.git.base,
            parents: &self.root_parents,
        };
        let context = AuthenticatedPrCandidate {
            repository: "example/project",
            source_repository: "example/project",
            pull_request: self.root["predicate"]["origin"]["pull_request"]["number"]
                .as_u64()
                .unwrap(),
            pr_head: &self.pr_head,
            base_ref: "main",
            objects: SubjectObjects {
                head: &self.head,
                tree: &self.tree,
                accepted_base: &self.base,
                parents: &self.parents,
            },
            mapping: if self.prepared {
                CandidateMapping::SinglePrMerge
            } else {
                CandidateMapping::Direct
            },
        };
        let ReuseAuthority::Valid(baseline) = &self.config.policy.reuse_authority else {
            panic!("fixture authority");
        };
        let broker = baseline
            .authorities
            .iter()
            .find(|key| key.role == ReuseRole::DaemonPolicyReceipt)
            .unwrap();
        let receipts = if receipt_accepted {
            ReceiptValidation {
                result: Ok([broker, broker]),
            }
        } else {
            ReceiptValidation::contract_undefined()
        };
        validate(&Validation {
            current,
            check: "format",
            expected: &self.expected,
            context: authenticated.then_some(&context),
            candidate: &candidate,
            root: &root,
            root_objects: &root_objects,
            receipts: &receipts,
            now,
        })
        .map(|_| ())
    }
    fn enroll_service(&mut self, principal: &str) {
        let key = self.git.root.path().join("rotation-key");
        let output = self
            .git
            .command("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(output.status.success());
        let entry = self
            .git
            .key_entry(&key, "v2_service_issuer", principal, "service:rotated");
        let mut policy: Value = serde_json::from_slice(
            &fs::read(self.git.root.path().join(".mergemaster/lanes.json")).unwrap(),
        )
        .unwrap();
        policy["reuse_authorities"]
            .as_array_mut()
            .unwrap()
            .push(entry.clone());
        self.git
            .write(".mergemaster/lanes.json", policy.to_string());
        self.base = self.git.commit("enroll rotated service key");
        self.config = self.current();
        self.candidate["predicate"]["origin"]["accepted_base"] = json!(self.base);
        self.candidate["predicate"]["signer"] = json!(principal);
        self.candidate["predicate"]["issuer"] =
            json!({"key_id":entry["key_id"],"service_id":"service:rotated"});
        self.key = key;
    }
}

#[test]
fn rebind_requires_direct_successful_full_nix_rebuild_root() {
    let f = FixturePair::new();
    assert_eq!(f.check(&f.root, &f.candidate), Ok(()));
    for (path, value) in [
        ("/predicate/tier", json!("degraded")),
        ("/predicate/observed/runner", json!("wrapper")),
        ("/predicate/observed/checks/format/exit_code", json!(1)),
        ("/predicate/observed/inputs/nix_execution", json!("reused")),
        (
            "/predicate/observed/inputs/nix_command_mode",
            json!("reused"),
        ),
    ] {
        let mut root = f.root.clone();
        *root.pointer_mut(path).unwrap() = value;
        assert_eq!(
            f.check(&root, &f.candidate),
            Err(Refusal::SourceUnverified),
            "{path}"
        );
    }
    let mut root = f.root.clone();
    root["predicate"]["reused_from"] = json!("a".repeat(40));
    root["predicate"]["observed"]["inputs"]["nix_execution"] = json!("reused");
    root["predicate"]["observed"]["inputs"]["nix_command_mode"] = json!("reused");
    assert_eq!(f.check(&root, &f.candidate), Err(Refusal::SourceNotRoot));
    let mut candidate = f.candidate.clone();
    candidate["predicate"]["reused_from"] = json!("a".repeat(40));
    assert_eq!(f.check(&f.root, &candidate), Err(Refusal::SourceNotRoot));
    let mut root = f.root.clone();
    root["predicate"]["re_attests"] = json!("a".repeat(40));
    assert_eq!(f.check(&root, &f.candidate), Err(Refusal::SourceUnverified));
    assert_eq!(
        f.validate(&f.root, &f.candidate, &f.config, false, f.now, true),
        Err(Refusal::ReceiptContractUndefined)
    );
}

#[test]
fn root_and_rebind_levels_are_exactly_equal() {
    let mut f = FixturePair::new();
    f.enroll_service("host/rotated");
    assert_eq!(
        f.check(&f.root, &f.candidate),
        Err(Refusal::SignerLevelMismatch)
    );
    let mut f = FixturePair::new();
    f.enroll_service("agent/rotated");
    assert_eq!(f.check(&f.root, &f.candidate), Ok(()));
    let mut current = f.current();
    current.policy.lanes.get_mut("format").unwrap().trust_levels = vec!["host".into()];
    assert_eq!(
        f.validate(&f.root, &f.candidate, &current, true, f.now, true),
        Err(Refusal::CandidateUnverified)
    );
}

#[test]
fn origin_repository_subject_base_and_class_are_bound() {
    let f = FixturePair::new();
    for (path, value) in [
        ("/repository", json!("other/project")),
        ("/predicate/origin/repository", json!("other/project")),
        ("/predicate/origin/subject_head", json!("a".repeat(40))),
        ("/predicate/origin/accepted_base", json!(f.git.base)),
        ("/predicate/origin/pull_request/number", json!(999)),
        ("/predicate/origin/pull_request/base_ref", json!("other")),
    ] {
        let mut candidate = f.candidate.clone();
        *candidate.pointer_mut(path).unwrap() = value;
        assert!(f.check(&f.root, &candidate).is_err(), "{path}");
    }
    // Root historical BASE/head are intentionally different from the candidate.
    assert_ne!(f.git.base, f.base);
    assert_ne!(f.git.head, f.head);
    assert_eq!(f.check(&f.root, &f.candidate), Ok(()));
    let mut root = f.root.clone();
    root["predicate"]["origin"]["pull_request"]["number"] = json!(999);
    assert_eq!(f.check(&root, &f.candidate), Err(Refusal::OriginMismatch));
    for class in ["fork_pr", "push", "local"] {
        let mut candidate = f.candidate.clone();
        let o = candidate["predicate"]["origin"].as_object_mut().unwrap();
        o.insert("class".into(), json!(class));
        if class == "fork_pr" {
            o.insert("source_repository".into(), json!("fork/project"));
        } else {
            o.insert("event_kind".into(), json!(class));
            o.remove("pull_request");
        }
        assert_eq!(
            f.check(&f.root, &candidate),
            Err(Refusal::OriginMismatch),
            "{class}"
        );
    }
    for event in ["queue", "merge_group", "push", "local"] {
        assert_eq!(
            f.validate(&f.root, &f.candidate, &f.config, true, f.now, false),
            Err(Refusal::OriginMismatch),
            "{event}: no authenticated PR context"
        );
    }
}

#[test]
fn reuse_key_optional_entries_compare_exactly() {
    let f = FixturePair::new();
    for name in ["workspace_binding", "workspace_declaration_sha256", "extra"] {
        let mut candidate = f.candidate.clone();
        candidate["predicate"]["reuse_key"]["expected_inputs"][name] = json!("unexpected");
        assert_eq!(
            f.check(&f.root, &candidate),
            Err(Refusal::KeyMismatch),
            "{name}"
        );
    }
    for name in [
        "environment_sha256",
        "toolchain_sha256",
        "lane_definition_sha256",
        "system",
    ] {
        let mut candidate = f.candidate.clone();
        candidate["predicate"]["reuse_key"]["expected_inputs"]
            .as_object_mut()
            .unwrap()
            .remove(name);
        assert_eq!(
            f.check(&f.root, &candidate),
            Err(Refusal::KeyMismatch),
            "{name}"
        );
    }
    let mut candidate = f.candidate.clone();
    candidate["predicate"]["observed"]["inputs"]["workspace_binding"] = json!("v2");
    assert_eq!(f.check(&f.root, &candidate), Err(Refusal::KeyMismatch));
    let mut f = FixturePair::new();
    for (name, value) in [
        ("workspace_binding", "v2".to_owned()),
        ("workspace_declaration_sha256", "a".repeat(64)),
    ] {
        f.expected.insert(name.into(), value.clone());
        for note in [&mut f.root, &mut f.candidate] {
            note["predicate"]["reuse_key"]["expected_inputs"][name] = json!(value);
            note["predicate"]["observed"]["inputs"][name] = json!(value);
        }
    }
    assert_eq!(f.check(&f.root, &f.candidate), Ok(()));
    let mut candidate = f.candidate.clone();
    candidate["predicate"]["observed"]["inputs"]
        .as_object_mut()
        .unwrap()
        .remove("workspace_declaration_sha256");
    assert_eq!(f.check(&f.root, &candidate), Err(Refusal::KeyMismatch));
    let mut candidate = f.candidate.clone();
    candidate["predicate"]["reuse_key"]["nix_daemon_policy_sha256"] = json!("f".repeat(64));
    candidate["predicate"]["observed"]["inputs"]["nix_daemon_policy_sha256"] =
        json!("f".repeat(64));
    assert_eq!(f.check(&f.root, &candidate), Err(Refusal::KeyMismatch));
}

#[test]
fn producer_and_outputs_must_match_current_base() {
    let f = FixturePair::new();
    let mut candidate = f.candidate.clone();
    candidate["predicate"]["observed"]["inputs"]["nix_outputs_sha256"] = json!("f".repeat(64));
    assert_eq!(f.check(&f.root, &candidate), Err(Refusal::OutputsMismatch));
    for side in [false, true] {
        let mut root = f.root.clone();
        let mut candidate = f.candidate.clone();
        let note = if side { &mut root } else { &mut candidate };
        note["predicate"]["producer_sha256"] = json!("f".repeat(64));
        note["predicate"]["reuse_key"]["producer"]["executable_sha256"] = json!("f".repeat(64));
        note["predicate"]["observed"]["inputs"]["wrapper_sha256"] = json!("f".repeat(64));
        assert_eq!(
            f.check(&root, &candidate),
            Err(Refusal::ProducerUnauthorized)
        );
    }
    let mut current = f.current();
    let extra = serde_json::from_value(json!({
        "executable_sha256":"f".repeat(64),"flavor":"v2_service","system":"x86_64-linux",
        "provenance":{"mergemaster_revision":"a".repeat(40),"package":"other-service"}
    }))
    .unwrap();
    current.producers.as_mut().unwrap().producers.push(extra);
    let mut candidate = f.candidate.clone();
    candidate["predicate"]["producer_sha256"] = json!("f".repeat(64));
    candidate["predicate"]["reuse_key"]["producer"]["executable_sha256"] = json!("f".repeat(64));
    candidate["predicate"]["observed"]["inputs"]["wrapper_sha256"] = json!("f".repeat(64));
    assert_eq!(
        f.validate(&f.root, &candidate, &current, true, f.now, true),
        Err(Refusal::KeyMismatch)
    );
    // Logs, attempts and store instances are operational claims, not reuse-key fields.
    let mut candidate = f.candidate.clone();
    candidate["predicate"]["observed"]["checks"]["format"]["output_sha256"] = json!("f".repeat(64));
    candidate["predicate"]["observed"]["inputs"]["attempt"] = json!("2");
    candidate["predicate"]["observed"]["inputs"]["nix_store"] = json!("daemon:new-instance");
    assert_eq!(f.check(&f.root, &candidate), Ok(()));
}

#[test]
fn observed_time_is_equal_and_not_renewed() {
    let f = FixturePair::new();
    let mut candidate = f.candidate.clone();
    candidate["predicate"]["observed_at"] = json!((f.now - Duration::seconds(1)).to_rfc3339());
    candidate["predicate"]["attested_at"] = json!(f.now.to_rfc3339());
    assert_eq!(
        f.check(&f.root, &candidate),
        Err(Refusal::ObservationRenewed)
    );
    let mut root = f.root.clone();
    let mut candidate = f.candidate.clone();
    root["predicate"]["observed_at"] = json!("2026-11-22T09:59:00Z");
    candidate["predicate"]["observed_at"] = json!("2026-11-22T09:59:00+00:00");
    assert_eq!(f.check(&root, &candidate), Ok(()));
    let mut current = f.current();
    current
        .policy
        .lanes
        .get_mut("format")
        .unwrap()
        .max_age_seconds = Some(10);
    assert_eq!(
        f.validate(&root, &candidate, &current, true, f.now, true),
        Err(Refusal::SourceExpired)
    );
}

#[test]
fn reuse_age_and_skew_boundaries() {
    let f = FixturePair::new();
    let mut current = f.current();
    current
        .policy
        .lanes
        .get_mut("format")
        .unwrap()
        .max_age_seconds = Some(60);
    for (delta_nanos, result) in [(0, Ok(())), (1, Err(Refusal::SourceExpired))] {
        assert_eq!(
            f.validate(
                &f.root,
                &f.candidate,
                &current,
                true,
                f.now + Duration::nanoseconds(delta_nanos),
                true
            ),
            result
        );
    }
    for age in [None, Some(0), Some(u64::MAX), Some(i64::MAX as u64)] {
        current
            .policy
            .lanes
            .get_mut("format")
            .unwrap()
            .max_age_seconds = age;
        assert_eq!(
            f.validate(&f.root, &f.candidate, &current, true, f.now, true),
            Err(Refusal::LaneIneligible)
        );
    }
    for (nanos, result) in [(0, Ok(())), (1, Err(Refusal::TimeInvalid))] {
        let at = f.now + Duration::seconds(120) + Duration::nanoseconds(nanos);
        let mut root = f.root.clone();
        let mut candidate = f.candidate.clone();
        for note in [&mut root, &mut candidate] {
            note["predicate"]["observed_at"] = json!(at.to_rfc3339());
            note["predicate"]["attested_at"] = json!(at.to_rfc3339());
        }
        assert_eq!(f.check(&root, &candidate), result);
    }
    let mut candidate = f.candidate.clone();
    candidate["predicate"]["attested_at"] =
        json!((f.now + Duration::seconds(120) + Duration::nanoseconds(1)).to_rfc3339());
    assert_eq!(f.check(&f.root, &candidate), Err(Refusal::TimeInvalid));
    assert_eq!(
        f.validate(
            &f.root,
            &f.candidate,
            &f.config,
            true,
            DateTime::<Utc>::MAX_UTC,
            true
        ),
        Err(Refusal::TimeInvalid)
    );
}

#[test]
fn root_issuer_broker_or_producer_revocation_is_immediate() {
    let f = FixturePair::new();
    for role in [ReuseRole::V2ServiceIssuer, ReuseRole::DaemonPolicyReceipt] {
        let mut current = f.current();
        let ReuseAuthority::Valid(authority) = &mut current.policy.reuse_authority else {
            panic!("fixture authority");
        };
        // Notes and accepted receipt snapshots predate this current-BASE revocation.
        authority.authorities.retain(|key| key.role != role);
        assert_eq!(
            f.validate(&f.root, &f.candidate, &current, true, f.now, true),
            Err(if role == ReuseRole::V2ServiceIssuer {
                Refusal::CandidateUnverified
            } else {
                Refusal::BrokerUnauthorized
            })
        );
    }
    let mut current = f.current();
    current.producers = None;
    assert_eq!(
        f.validate(&f.root, &f.candidate, &current, true, f.now, true),
        Err(Refusal::ProducerUnauthorized)
    );
    let mut current = f.current();
    current.policy.reuse_authority = ReuseAuthority::Absent;
    assert_eq!(
        f.validate(&f.root, &f.candidate, &current, true, f.now, true),
        Err(Refusal::AuthorityInvalid)
    );
    let mut rotated = FixturePair::new();
    rotated.enroll_service("agent/rotated");
    let mut current = rotated.current();
    let ReuseAuthority::Valid(authority) = &mut current.policy.reuse_authority else {
        panic!("fixture authority");
    };
    authority
        .authorities
        .retain(|key| key.principal != "agent/service");
    assert_eq!(
        rotated.validate(
            &rotated.root,
            &rotated.candidate,
            &current,
            true,
            rotated.now,
            true
        ),
        Err(Refusal::SourceUnverified)
    );
}

#[test]
fn normalized_commands_and_measurement_bindings_are_required() {
    let f = FixturePair::new();
    for (path, value, reason) in [
        (
            "/predicate/observed/checks/format/command",
            json!(["true"]),
            Refusal::CommandMismatch,
        ),
        (
            "/predicate/observed/inputs/nix_command_sha256",
            json!("a".repeat(64)),
            Refusal::CommandMismatch,
        ),
        (
            "/predicate/observed/inputs/nix_settings_sha256",
            json!("a".repeat(64)),
            Refusal::MeasurementInvalid,
        ),
        (
            "/predicate/observed/inputs/nix_daemon_policy_sha256",
            json!("a".repeat(64)),
            Refusal::MeasurementInvalid,
        ),
        (
            "/predicate/observed/inputs/workspace_clean",
            json!("false"),
            Refusal::MeasurementInvalid,
        ),
        (
            "/predicate/observed/inputs/untracked_files",
            json!("true"),
            Refusal::MeasurementInvalid,
        ),
        (
            "/predicate/observed/inputs/nix_daemon_trusted",
            json!("false"),
            Refusal::MeasurementInvalid,
        ),
        (
            "/predicate/observed/inputs/attempt",
            json!("0"),
            Refusal::MeasurementInvalid,
        ),
    ] {
        let mut candidate = f.candidate.clone();
        *candidate.pointer_mut(path).unwrap() = value;
        assert_eq!(f.check(&f.root, &candidate), Err(reason), "{path}");
    }
}

#[test]
fn prepared_single_pr_candidate_requires_exact_ordered_merge_parents() {
    let mut f = FixturePair::new();
    f.prepared = true;
    f.head = f.git.git(
        &["commit-tree", &f.tree, "-p", &f.base, "-p", &f.pr_head],
        b"prepared\n",
    );
    f.parents = vec![f.base.clone(), f.pr_head.clone()];
    f.candidate["subject"][0]["name"] = json!(f.head);
    f.candidate["predicate"]["origin"]["subject_head"] = json!(f.head);
    f.candidate["predicate"]["origin"]["train_mapping"] = json!({"kind":"single_pr_merge", "candidate":f.head,
        "accepted_base":f.base,"pull_request":f.candidate["predicate"]["origin"]["pull_request"]["number"],"pr_head":f.pr_head});
    assert_eq!(f.check(&f.root, &f.candidate), Ok(()));
    f.head = f.git.git(
        &["commit-tree", &f.tree, "-p", &f.pr_head, "-p", &f.base],
        b"wrong-order\n",
    );
    f.parents = vec![f.pr_head.clone(), f.base.clone()];
    f.candidate["subject"][0]["name"] = json!(f.head);
    f.candidate["predicate"]["origin"]["subject_head"] = json!(f.head);
    f.candidate["predicate"]["origin"]["train_mapping"]["candidate"] = json!(f.head);
    assert_eq!(
        f.check(&f.root, &f.candidate),
        Err(Refusal::CandidateBindingMismatch)
    );
}

impl FixturePair {
    fn orchestration(
        &self,
        root: &Value,
        candidate: &Value,
        production: bool,
        authenticated: bool,
    ) -> Value {
        let root_id = self.git.raw_note(
            &serde_json::to_vec(root).unwrap(),
            &self.git.tree,
            &[&self.git.head],
            &self.git.key,
        );
        let mut candidate = candidate.clone();
        if candidate["predicate"]["reused_from"] == "LINK_ROOT" {
            candidate["predicate"]["reused_from"] = json!(root_id);
        }
        let candidate_id = self.git.raw_note(
            &serde_json::to_vec(&candidate).unwrap(),
            &self.tree,
            &[&self.head],
            &self.key,
        );
        let context = AuthenticatedPrCandidate {
            repository: "example/project",
            source_repository: "example/project",
            pull_request: self.root["predicate"]["origin"]["pull_request"]["number"]
                .as_u64()
                .unwrap(),
            pr_head: &self.pr_head,
            base_ref: "main",
            objects: SubjectObjects {
                head: &self.head,
                tree: &self.tree,
                accepted_base: &self.base,
                parents: &self.parents,
            },
            mapping: CandidateMapping::Direct,
        };
        let ReuseAuthority::Valid(authority) = &self.config.policy.reuse_authority else {
            panic!("fixture");
        };
        let broker = authority
            .authorities
            .iter()
            .find(|key| key.role == ReuseRole::DaemonPolicyReceipt)
            .unwrap();
        let receipts = ReceiptValidation {
            result: Ok([broker, broker]),
        };
        let diagnostic = if production {
            attempt::<v2::DaemonPolicyReceipt>(
                self.git.root.path(),
                &candidate_id,
                &self.config,
                "format",
                None,
                &ReceiptValidation::contract_undefined(),
                self.now,
            )
        } else {
            attempt::<Value>(
                self.git.root.path(),
                &candidate_id,
                &self.config,
                "format",
                authenticated.then_some(&context),
                &receipts,
                self.now,
            )
        };
        let value = serde_json::to_value(diagnostic).unwrap();
        if !production && value.get("root_record").is_some() {
            assert_eq!(value["root_record"], root_id);
        }
        value
    }
}

#[test]
fn complete_generic_orchestration_verifies_root_but_never_admits() {
    let f = FixturePair::new();
    assert!(f.git.git(&["for-each-ref", "refs/notes/"], b"").is_empty());
    let value = f.orchestration(&f.root, &f.candidate, false, true);
    assert_eq!(value["status"], "disabled");
    assert_eq!(value["reason"], "selective_reuse_disabled");
    assert!(value["root_record"].as_str().is_some());
    let production = f.orchestration(&f.root, &f.candidate, true, false);
    assert_eq!(
        production,
        json!({"version":1,"status":"disabled","reason":"receipt_contract_undefined"})
    );
    let unavailable = f.orchestration(&f.root, &f.candidate, false, false);
    assert_eq!(unavailable["reason"], "reuse_origin_unavailable");
    let mut candidate = f.candidate.clone();
    candidate["predicate"]["observed"]["inputs"]["attempt"] = json!("0");
    let refused = f.orchestration(&f.root, &candidate, false, true);
    assert_eq!(refused["reason"], "reuse_measurement_invalid");
    assert!(refused.get("root_record").is_some());
    let mut candidate = f.candidate.clone();
    candidate["predicate"]["reused_from"] = json!("0".repeat(40));
    let missing = f.orchestration(&f.root, &candidate, false, true);
    assert_eq!(missing["reason"], "reuse_source_unavailable");
    assert!(missing.get("root_record").is_none());
}

#[test]
fn selective_worker_diagnostics_are_map_only_and_string_enum_only() {
    let valid = json!({"version":1,"status":"disabled","reason":"receipt_contract_undefined"});
    assert!(serde_json::from_value::<SelectiveReuse>(valid.clone()).is_ok());
    for value in [
        json!([1, "disabled", "receipt_contract_undefined"]),
        json!({"version":1,
        "status":{"disabled":null},"reason":"receipt_contract_undefined"}),
        json!({"version":1,"status":"disabled","reason":{"receipt_contract_undefined":null}}),
        json!({"version":1,"status":"validated","reason":"selective_reuse_disabled"}),
        json!({"version":1,"status":"disabled","reason":"receipt_contract_undefined","root_record":null}),
    ] {
        assert!(serde_json::from_value::<SelectiveReuse>(value).is_err());
    }
    assert!(serde_json::from_str::<SelectiveReuse>(
        r#"{"version":1,"status":"disabled","reason":"receipt_contract_undefined","reason":"selective_reuse_disabled"}"#).is_err());
}
