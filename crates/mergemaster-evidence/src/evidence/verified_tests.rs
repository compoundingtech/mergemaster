//! Receipt input is the only substitute: all object and SSH checks are production code.
use super::*;
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
};

struct Fixture {
    root: tempfile::TempDir,
    key: PathBuf,
    stranger: PathBuf,
    base: String,
    head: String,
    tree: String,
    authority: ReuseAuthority,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let key = root.path().join("service");
        let stranger = root.path().join("stranger");
        let mut f = Self {
            root,
            key,
            stranger,
            base: String::new(),
            head: String::new(),
            tree: String::new(),
            authority: ReuseAuthority::Absent,
        };
        f.git(&["init", "-q"], b"");
        for key in [&f.key, &f.stranger] {
            let out = f
                .command("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(key)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let issuer = f.key_entry(
            &f.key,
            "v2_service_issuer",
            "agent/service",
            "service:linux-v1",
        );
        let broker = f.key_entry(
            &f.stranger,
            "daemon_policy_receipt",
            "host/broker",
            "broker:linux-v1",
        );
        f.write(".mergemaster/lanes.json", json!({
            "version": 1, "repository": "example/project",
            "pull_request": {"same_repository": true, "authors": {"mode": "none"}, "base_relation": "ancestor"},
            "protected_paths": [], "reuse_authorities": [issuer, broker],
            "lanes": {"format": {
                "argv": ["/trusted/nix"], "definition_paths": ["tools"], "trust_levels": ["agent"],
                "mode": "required_evidence", "events": ["pull_request"],
                "environment": {"manifest": ".mergemaster/environment.json", "paths": ["tools"]},
                "protected_edits": "reject", "remediation_argv": ["retry"],
                "nix_check": {"attribute": "checks.x86_64-linux.format", "required": "any"},
                "max_age_seconds": 86400,
                "reuse": {"version": 1, "origin_profile": "same_repository_pr", "platform": "linux"}
            }}
        }).to_string());
        f.write(".mergemaster/tool-pin.json", json!({"version":1,"repository":"compoundingtech/mergemaster","revision":"a".repeat(40)}).to_string());
        f.write(".mergemaster/environment.json", json!({"version":1,"systems":{"x86_64-linux":{"runtime":{"name":"nix","identity":format!("sha256:{}", "a".repeat(64))},"dependencies":{}}}}).to_string());
        f.write(
            ".mergemaster/evidence-keys",
            format!(
                "agent/service namespaces=\"git\" {}\n",
                issuer["public_key"].as_str().unwrap()
            ),
        );
        f.write("tools/nix", "fixture only\n");
        f.base = f.commit("base");
        f.write("source", "root subject\n");
        f.head = f.commit("root subject");
        f.tree = f.git(&["rev-parse", "HEAD^{tree}"], b"");
        f.authority = config::load(f.root.path(), &f.base)
            .unwrap()
            .policy
            .reuse_authority;
        assert!(matches!(f.authority, ReuseAuthority::Valid(_)));
        f
    }
    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        git::sanitize(&mut command);
        command
            .env("HOME", self.root.path())
            .current_dir(self.root.path());
        command
    }
    fn git(&self, args: &[&str], input: &[u8]) -> String {
        let mut child = self
            .command("git")
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }
    fn write(&self, path: &str, value: impl AsRef<[u8]>) {
        let path = self.root.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value).unwrap();
    }
    fn commit(&self, message: &str) -> String {
        self.git(&["add", "-A"], b"");
        self.git(&["commit", "-q", "-m", message], b"");
        self.git(&["rev-parse", "HEAD"], b"")
    }
    fn key_entry(&self, key: &Path, role: &str, principal: &str, endpoint: &str) -> Value {
        let public = fs::read_to_string(key.with_extension("pub")).unwrap();
        let parts: Vec<_> = public.split_whitespace().collect();
        let public = format!("{} {}", parts[0], parts[1]);
        let digest = Sha256::digest(STANDARD.decode(parts[1]).unwrap());
        json!({"key_id":format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)), "public_key":public,
            "principal":principal, "role":role, "repository":"example/project", "endpoint_id":endpoint})
    }
    fn statement(&self) -> Value {
        let mut s = v2::tests::fixture();
        s["subject"][0]["name"] = json!(self.head);
        s["subject"][0]["digest"]["gitTree"] = json!(self.tree);
        s["predicate"]["origin"]["subject_head"] = json!(self.head);
        s["predicate"]["origin"]["accepted_base"] = json!(self.base);
        s["predicate"]["origin"]["pull_request"]["head"] = json!(self.head);
        s["predicate"]["signer"] = json!("agent/service");
        s["predicate"]["issuer"] = json!({"key_id":self.key_entry(&self.key,"v2_service_issuer","agent/service","service:linux-v1")["key_id"],"service_id":"service:linux-v1"});
        s
    }
    fn raw_note(&self, bytes: &[u8], path: &str, parents: &[&str], key: &Path) -> String {
        let blob = self.git(&["hash-object", "-w", "--stdin"], bytes);
        let tree = self.git(
            &["mktree"],
            format!("100644 blob {blob}\t{path}\n").as_bytes(),
        );
        let signing_key = format!("user.signingKey={}", key.display());
        let mut args = vec![
            "-c",
            "gpg.format=ssh",
            "-c",
            "gpg.ssh.program=ssh-keygen",
            "-c",
            &signing_key,
            "commit-tree",
            "-S",
            &tree,
        ];
        for parent in parents {
            args.extend(["-p", parent]);
        }
        self.git(&args, b"fixture v2 note\n")
    }
    fn note(&self, s: &Value) -> String {
        self.raw_note(
            &serde_json::to_vec(s).unwrap(),
            &self.tree,
            &[&self.head],
            &self.key,
        )
    }
    fn root(&self, id: &str) -> LoadResult<VerifiedRecord<Value>> {
        root_with_receipt(self.root.path(), id, &self.authority)
    }
    fn refusal(&self, id: &str, refusal: Refusal) {
        assert_eq!(self.root(id).unwrap_err(), refusal);
    }
}

#[test]
fn root_lookup_uses_signed_id_outside_candidate_tree() {
    let f = Fixture::new();
    let root = f.note(&f.statement());
    f.write("source", "candidate on moved main\n");
    let candidate = f.commit("candidate");
    let candidate_tree = f.git(&["rev-parse", &format!("{candidate}^{{tree}}")], b"");
    assert_ne!(candidate_tree, f.tree);
    assert!(f.git(&["for-each-ref", "refs/notes/"], b"").is_empty());
    let loaded = f.root(&root).unwrap();
    assert_eq!(loaded.record, root);
    assert_eq!(loaded.version, 2);
    assert_eq!(loaded.verified_signer.as_deref(), Some("agent/service"));
    assert_eq!(
        loaded.verified_key_id.as_deref(),
        f.statement()["predicate"]["issuer"]["key_id"].as_str()
    );
    assert!(matches!(loaded.statement, VerifiedStatement::V2(s) if s.subject[0].name == f.head));
    // The production decoder remains sealed, even for a real correctly signed root.
    assert_eq!(
        load_root(f.root.path(), &root, &f.authority).unwrap_err(),
        Refusal::InvalidStatement
    );
}

#[test]
fn root_alias_and_noncommit_refuse() {
    let f = Fixture::new();
    let root = f.note(&f.statement());
    f.git(&["update-ref", "refs/notes/root-alias", &root], b"");
    for alias in ["refs/notes/root-alias", "HEAD", &root[..12]] {
        f.refusal(alias, Refusal::InvalidId);
    }
    f.refusal(&f.tree, Refusal::NonCommit);
    let blob = f.git(&["hash-object", "-w", "--stdin"], b"not a commit");
    f.refusal(&blob, Refusal::NonCommit);
    let tag = f.git(&["mktag"], format!("object {root}\ntype commit\ntag root\ntagger Fixture <fixture@example.invalid> 1 +0000\n\nroot\n").as_bytes());
    f.refusal(&tag, Refusal::NonCommit);
}

#[test]
fn root_wrong_subject_tree_or_parent_refuses() {
    let f = Fixture::new();
    let mut s = f.statement();
    s["subject"][0]["name"] = json!(f.tree);
    s["predicate"]["origin"]["subject_head"] = json!(f.tree);
    s["predicate"]["origin"]["pull_request"]["head"] = json!(f.tree);
    f.refusal(&f.note(&s), Refusal::WrongSubject);
    let mut s = f.statement();
    s["subject"][0]["digest"]["gitTree"] =
        json!(f.git(&["rev-parse", &format!("{}^{{tree}}", f.base)], b""));
    f.refusal(&f.note(&s), Refusal::WrongTree);
    let bytes = serde_json::to_vec(&f.statement()).unwrap();
    let wrong_path = f.raw_note(&bytes, &"a".repeat(40), &[&f.head], &f.key);
    f.refusal(&wrong_path, Refusal::WrongTree);
    for parents in [
        vec![],
        vec![f.base.as_str()],
        vec![f.head.as_str(), f.base.as_str()],
    ] {
        f.refusal(
            &f.raw_note(&bytes, &f.tree, &parents, &f.key),
            Refusal::WrongParent,
        );
    }
}

#[test]
fn v2_verified_key_must_match_declared_issuer() {
    let f = Fixture::new();
    let s = f.statement();
    f.refusal(
        &f.raw_note(
            &serde_json::to_vec(&s).unwrap(),
            &f.tree,
            &[&f.head],
            &f.stranger,
        ),
        Refusal::Unverified,
    );
    for signer in ["host/service", "agent/other"] {
        let mut s = f.statement();
        s["predicate"]["signer"] = json!(signer);
        f.refusal(&f.note(&s), Refusal::IssuerMismatch);
    }
    for field in ["key_id", "service_id"] {
        let mut s = f.statement();
        s["predicate"]["issuer"][field] = if field == "key_id" {
            f.key_entry(
                &f.stranger,
                "daemon_policy_receipt",
                "host/broker",
                "broker:linux-v1",
            )["key_id"]
                .clone()
        } else {
            json!("other-endpoint")
        };
        f.refusal(&f.note(&s), Refusal::AuthorityInvalid);
    }
    let root = f.note(&s);
    assert_eq!(
        root_with_receipt::<Value>(f.root.path(), &root, &ReuseAuthority::Absent).unwrap_err(),
        Refusal::AuthorityInvalid
    );
    assert_eq!(
        root_with_receipt::<Value>(
            f.root.path(),
            &root,
            &ReuseAuthority::Invalid("revoked".into())
        )
        .unwrap_err(),
        Refusal::AuthorityInvalid
    );
}

#[test]
fn root_chain_and_v1_promotion_refuse() {
    let f = Fixture::new();
    let root = f.note(&f.statement());
    let mut s = f.statement();
    s["predicate"]["reused_from"] = json!(root);
    for field in ["nix_execution", "nix_command_mode"] {
        s["predicate"]["observed"]["inputs"][field] = json!("reused");
    }
    let rebind = f.note(&s);
    f.refusal(&rebind, Refusal::NotRoot);
    s["predicate"]["reused_from"] = json!(rebind);
    f.refusal(&f.note(&s), Refusal::NotRoot);
    let mut s = f.statement();
    s["predicate"]["re_attests"] = json!(root);
    f.refusal(&f.note(&s), Refusal::InvalidStatement);
    let s = json!({"_type":super::super::STATEMENT_TYPE,"predicateType":super::super::PREDICATE_TYPE,
        "subject":[{"name":f.head,"digest":{"gitTree":f.tree}}],
        "predicate":{"schema_version":1,"change_id":"legacy","signer":"agent/service","tier":"full",
            "producer_sha256":"a".repeat(64),"observed_at":"2026-11-22T10:00:00Z",
            "observed":{"kind":"tests","runner":"wrapper","checks":{"format":{"command":["true"],"exit_code":0,"output_sha256":"b".repeat(64)}}}}});
    f.refusal(&f.note(&s), Refusal::V1Promotion);
}

#[test]
fn root_missing_or_oversized_refuses() {
    let f = Fixture::new();
    f.refusal(&"0".repeat(40), Refusal::Unavailable);
    let large = f.raw_note(
        &vec![b' '; v2::MAX_NOTE_BYTES + 1],
        &f.tree,
        &[&f.head],
        &f.key,
    );
    f.refusal(&large, Refusal::Oversized);
    let blob = f.git(&["hash-object", "-w", "--stdin"], b"note");
    let tree = f.git(
        &["mktree"],
        format!("100644 blob {blob}\t{}\n", f.tree).as_bytes(),
    );
    let large = f.git(
        &["commit-tree", &tree, "-p", &f.head],
        &vec![b'x'; MAX_COMMIT_BYTES + 1],
    );
    f.refusal(&large, Refusal::Oversized);
    let mut s = f.statement();
    s["subject"][0]["name"] = json!("0".repeat(40));
    s["predicate"]["origin"]["subject_head"] = json!("0".repeat(40));
    s["predicate"]["origin"]["pull_request"]["head"] = json!("0".repeat(40));
    f.refusal(&f.note(&s), Refusal::Unavailable);
}

#[test]
fn caller_keys_file_cannot_authorize_v2() {
    let f = Fixture::new();
    let root = f.note(&f.statement());
    let keys = f.root.path().join(".mergemaster/evidence-keys");
    let error = verify_record(f.root.path(), &root, &keys, None).unwrap_err();
    assert!(error.to_string().contains("current BASE authority"));
    // Receipt substitution gets through shape decoding to the authority step.
    assert!(verify_with_receipt::<Value>(f.root.path(), &root, &keys, Some(&f.base)).is_ok());
    let policy_path = f.root.path().join(".mergemaster/lanes.json");
    let mut policy: Value = serde_json::from_slice(&fs::read(policy_path).unwrap()).unwrap();
    policy.as_object_mut().unwrap().remove("reuse_authorities");
    policy["lanes"]["format"]
        .as_object_mut()
        .unwrap()
        .remove("reuse");
    f.write(".mergemaster/lanes.json", policy.to_string());
    let without_authority = f.commit("remove current BASE v2 authority");
    assert!(matches!(
        config::load(f.root.path(), &without_authority)
            .unwrap()
            .policy
            .reuse_authority,
        ReuseAuthority::Absent
    ));
    // The caller file still contains the real signing key, but cannot grant a role.
    let error = verify_with_receipt::<Value>(f.root.path(), &root, &keys, Some(&without_authority))
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<Refusal>(),
        Some(&Refusal::AuthorityInvalid)
    );
}
