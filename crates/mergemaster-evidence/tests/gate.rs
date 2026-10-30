//! Generic single-lane gate contracts, using actual Git objects and SSH signatures.
use mergemaster_evidence::gate::config::{expected_inputs, load};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const CHECK: &str = "graph-full-check";
const PRINCIPAL: &str = "agent/fixture";

// Nix sandboxes have neither /usr/bin/env nor an ambient interpreter path.
fn python_executable() -> String {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .filter(|directory| directory.is_absolute())
        .filter_map(|directory| fs::canonicalize(directory.join("python3")).ok())
        .find(|path| path.is_file()).unwrap().to_str().unwrap().to_owned()
}

struct Fixture {
    root: tempfile::TempDir,
    repo: PathBuf,
    key: PathBuf,
    stranger: PathBuf,
    base: String,
    head: String,
    tree: String,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let key = root.path().join("key");
        let stranger = root.path().join("stranger");
        let mut f = Self { root, repo, key, stranger, base: String::new(), head: String::new(), tree: String::new() };
        f.git(&["init", "-q"], b"");
        for key in [&f.key, &f.stranger] {
            let output = f.command("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(key).output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        }
        let public = fs::read_to_string(f.key.with_extension("pub")).unwrap();
        f.write(".mergemaster/evidence-keys", format!("{PRINCIPAL} namespaces=\"git\" {public}"));
        f.write(".mergemaster/tool-pin.json", json!({"version":1,"repository":"compoundingtech/mergemaster","revision":"a".repeat(40)}).to_string());
        f.write(".mergemaster/environment.json", json!({
            "version":1,"system":"x86_64-linux",
            "toolchain":{"runtime":{"name":"bun","identity":format!("sha256:{}", "a".repeat(64))},"dependencies":{}}
        }).to_string());
        f.write(".mergemaster/lanes.json", Self::policy("required_evidence").to_string());
        f.write("tools/graph", "fixture command, never executed\n");
        f.write("source.txt", "base\n");
        f.write(".github/workflows/evidence.yml", "name: trusted\n");
        f.base = f.commit("base");
        f.git(&["update-ref", "refs/heads/gate-base", &f.base], b"");
        f.write("source.txt", "candidate\n");
        f.refresh_head();
        f
    }

    fn policy(mode: &str) -> Value {
        json!({
            "version":1,
            "pull_request":{"same_repository":true,"authors":{"mode":"none"},"base_relation":"ancestor"},
            "protected_paths":[".mergemaster/", ".github/workflows/", ".github/actions/"],
            "lanes":{CHECK:{
                "argv":["tools/graph","check","--full"],"definition_paths":["tools"],
                "trust_levels":["agent"],"mode":mode,"events":["pull_request"],
                "environment":{"manifest":".mergemaster/environment.json","paths":["tools","source.txt"]},
                "protected_edits":"reject","remediation_argv":["mergemaster","evidence","wrap","--check",CHECK]
            }}
        })
    }

    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(program);
        command.env_clear().env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", self.root.path()).env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1").env("LC_ALL", "C")
            .env("GITHUB_REPOSITORY", "fixture/repo").current_dir(&self.repo);
        command
    }

    fn git(&self, args: &[&str], input: &[u8]) -> String {
        let mut child = self.command("git").args([
            "--no-replace-objects", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "maintenance.auto=false",
            "-c", "gc.auto=0", "-c", "diff.external=", "-c", "core.sshCommand=false",
        ]).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn write(&self, path: &str, bytes: impl AsRef<[u8]>) {
        let path = self.repo.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn commit(&self, message: &str) -> String {
        self.git(&["add", "-A"], b"");
        self.git(&["-c", "commit.gpgsign=false", "commit", "--allow-empty", "-q", "-m", message], b"");
        self.git(&["rev-parse", "HEAD"], b"")
    }

    fn refresh_head(&mut self) {
        self.head = self.commit("candidate");
        self.tree = self.git(&["rev-parse", "HEAD^{tree}"], b"");
    }

    fn statement(&self) -> Value {
        let config = load(&self.repo, &self.base).unwrap();
        let mut inputs = expected_inputs(&self.repo, &self.head, CHECK, &config.policy.lanes[CHECK], &config.environment, &config.environment_bytes).unwrap();
        for (name, value) in [("workspace_clean", "true"), ("untracked_files", "false"), ("attempt", "1")] {
            inputs.insert(name.into(), value.into());
        }
        inputs.insert("wrapper_sha256".into(), "c".repeat(64));
        json!({
            "_type":"https://in-toto.io/Statement/v1",
            "predicateType":"https://smalltalk.dev/evidence/gate/v1",
            "subject":[{"name":self.head,"digest":{"gitTree":self.tree}}],
            "predicate":{
                "schema_version":1,"change_id":"fixture","signer":PRINCIPAL,"tier":"full",
                "re_attests":null,"producer_sha256":"a".repeat(64),"observed_at":chrono::Utc::now().to_rfc3339(),
                "observed":{"kind":"tests","runner":"wrapper","inputs":inputs,
                    "checks":{CHECK:{"command":["tools/graph","check","--full"],"exit_code":0,"output_sha256":"b".repeat(64)}}}
            }
        })
    }

    fn note(&self, statement: &Value, key: &Path, layout: &str) -> String {
        self.raw_note(&serde_json::to_vec(statement).unwrap(), key, layout)
    }

    fn raw_note(&self, body: &[u8], key: &Path, layout: &str) -> String {
        let blob = self.git(&["hash-object", "-w", "--stdin"], body);
        let notes = self.git(&["mktree"], format!("100644 blob {blob}\t{}\n", self.tree).as_bytes());
        let signing_key = format!("user.signingKey={}", key.display());
        let record = self.git(&["-c", "gpg.format=ssh", "-c", "gpg.ssh.program=ssh-keygen", "-c", &signing_key,
            "commit-tree", "-S", &notes, "-p", &self.head, "-m", "st gate observation v1"], b"");
        self.publish(&record, layout);
        record
    }

    fn publish(&self, record: &str, layout: &str) {
        let reference = match layout {
            "legacy" => format!("refs/notes/evidence/{record}"),
            "tag" => format!("refs/tags/evidence/{}/{record}", self.tree),
            _ => format!("refs/notes/evidence/{}/{record}", self.tree),
        };
        self.git(&["update-ref", &reference, record], b"");
    }

    fn live_api(&self, head: &str, base: &str) {
        use std::os::unix::fs::PermissionsExt;
        let bin = self.root.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let script = bin.join("gh");
        fs::write(&script, format!(r#"#!{python}
import json, os, pathlib, sys
root = pathlib.Path(os.environ["HOME"])
assert os.environ["GH_TOKEN"] == "fixture-token"
assert sys.argv[1:4] == ["api", "--hostname", "github.com"]
with (root / "api-calls").open("a") as log:
    log.write(sys.argv[4] + "\n")
name = "live-pull" if "/pulls/" in sys.argv[4] else "live-base"
print((root / name).read_text())
"#, python = python_executable())).unwrap();
        fs::set_permissions(script, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(self.root.path().join("live-pull"), json!({
            "head":{"sha":head,"repo":{"full_name":"fixture/repo"}},
            "base":{"ref":"main","repo":{"full_name":"fixture/repo"}}
        }).to_string()).unwrap();
        fs::write(self.root.path().join("live-base"), json!({"object":{"sha":base}}).to_string()).unwrap();
    }

    fn gate(&self, extra: &[&str]) -> Output {
        self.git(&["update-ref", "refs/heads/gate-base", &self.base], b"");
        let mut command = self.command(env!("CARGO_BIN_EXE_mergemaster"));
        let path = std::env::join_paths(std::iter::once(self.root.path().join("bin"))
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap()))).unwrap();
        command.env("PATH", path).env("GITHUB_TOKEN", "fixture-token").args([
            "gate", "--check", CHECK, "--base", &self.base, "--head", &self.head, "--format", "json",
        ]).args(extra).output().unwrap()
    }

    fn decision(&self, extra: &[&str]) -> Value {
        let output = self.gate(extra);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["check"], CHECK);
        assert_eq!(value["base"], self.base);
        assert_eq!(value["head"], self.head);
        assert_eq!(value["tree"], self.tree);
        assert!(value["protected_paths"].is_array());
        value
    }

    fn python(&self) -> Output {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/evidence-verify");
        let keys = self.root.path().join("trusted-signers");
        fs::write(&keys, self.git(&["show", &format!("{}:.mergemaster/evidence-keys", self.base)], b"")).unwrap();
        self.command("python3").arg(script).args(["--repo"]).arg(&self.repo)
            .args(["--revision", &self.head, "--check", CHECK, "--keys"]).arg(keys)
            .args(["--command", "[\"tools/graph\",\"check\",\"--full\"]", "--trust-levels", "agent"]).output().unwrap()
    }
}


#[test]
fn signed_observations_require_every_lane_binding() {
    for case in ["valid", "wrong_key", "wrong_principal", "wrong_level", "test_tier", "degraded", "wrong_argv", "failed", "wrong_commit", "wrong_tree", "wrong_check", "dirty", "untracked", "environment", "toolchain", "definition", "system", "wrapper", "future", "corrupt"] {
        let mut f = Fixture::new();
        if case == "wrong_level" {
            let keys = fs::read_to_string(f.key.with_extension("pub")).unwrap();
            f.write(".mergemaster/evidence-keys", format!("host/fixture namespaces=\"git\" {keys}"));
            f.base = f.commit("authorize host key only");
            f.refresh_head();
        }
        let mut statement = f.statement();
        let mut key = &f.key;
        match case {
            "wrong_key" => key = &f.stranger,
            "wrong_principal" => statement["predicate"]["signer"] = json!("agent/impostor"),
            "wrong_level" => statement["predicate"]["signer"] = json!("host/fixture"),
            "test_tier" => statement["predicate"]["tier"] = json!("test"),
            "degraded" => { statement["predicate"]["tier"] = json!("degraded"); statement["predicate"]["signer"] = Value::Null; }
            "wrong_argv" => statement["predicate"]["observed"]["checks"][CHECK]["command"] = json!(["true"]),
            "failed" => statement["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1),
            "wrong_commit" => statement["subject"][0]["name"] = json!(f.base),
            "wrong_tree" => statement["subject"][0]["digest"]["gitTree"] = json!("0".repeat(40)),
            "wrong_check" => { let check = statement["predicate"]["observed"]["checks"][CHECK].take(); statement["predicate"]["observed"]["checks"] = json!({"other":check}); }
            "dirty" => statement["predicate"]["observed"]["inputs"]["workspace_clean"] = json!("false"),
            "untracked" => statement["predicate"]["observed"]["inputs"]["untracked_files"] = json!("true"),
            "system" => statement["predicate"]["observed"]["inputs"]["system"] = json!("other-platform"),
            "environment" | "toolchain" | "definition" => {
                let field = match case { "environment" => "environment_sha256", "toolchain" => "toolchain_sha256", _ => "lane_definition_sha256" };
                statement["predicate"]["observed"]["inputs"][field] = json!("0".repeat(64));
            }
            "wrapper" => statement["predicate"]["observed"]["inputs"]["wrapper_sha256"] = json!("invalid"),
            "future" => statement["predicate"]["observed_at"] = json!((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()),
            _ => {}
        }
        if case == "corrupt" { f.raw_note(b"{not JSON", key, "tree"); } else { f.note(&statement, key, "tree"); }
        let decision = f.decision(&[]);
        assert_eq!(decision["decision"], if case == "valid" { "skip" } else { "refuse" }, "{case}: {decision}");
        assert_eq!(decision["outcome"] == "satisfied", case == "valid", "{case}: {decision}");
        assert!(decision["reason"].as_str().is_some_and(|reason| !reason.is_empty()), "{case}: {decision}");
    }
}

#[test]
fn base_keys_and_policy_cannot_be_replaced_by_head() {
    for trusted in [false, true] {
        let mut f = Fixture::new();
        f.write(".mergemaster/evidence-keys", format!("{PRINCIPAL} {}", fs::read_to_string(f.stranger.with_extension("pub")).unwrap()));
        f.write(".mergemaster/lanes.json", Fixture::policy("optional_fallback").to_string());
        f.refresh_head();
        f.note(&f.statement(), if trusted { &f.key } else { &f.stranger }, "tree");
        let decision = f.decision(&[]);
        assert_eq!(decision["decision"], "refuse");
        assert_ne!(decision["outcome"], "satisfied");
        assert_eq!(decision["reason"], "protected_paths");
    }
}

#[test]
fn malformed_or_missing_base_configuration_is_not_a_computed_decision() {
    for case in ["unknown", "missing", "missing_field", "malformed", "version", "escape", "missing_path", "unsupported_adapter", "bad_environment", "bad_pin"] {
        let mut f = Fixture::new();
        let mut policy = Fixture::policy("required_evidence");
        match case {
            "unknown" => policy["unknown"] = json!(true),
            "missing" => { fs::remove_file(f.repo.join(".mergemaster/evidence-keys")).unwrap(); }
            "missing_field" => { policy["lanes"][CHECK].as_object_mut().unwrap().remove("argv"); }
            "malformed" => {}
            "version" => policy["version"] = json!(2),
            "escape" => policy["lanes"][CHECK]["definition_paths"] = json!(["../escape"]),
            "missing_path" => policy["lanes"][CHECK]["environment"]["paths"] = json!(["absent"]),
            "unsupported_adapter" => policy["lanes"][CHECK]["shards"] = json!(2),
            "bad_environment" => f.write(".mergemaster/environment.json", "{}"),
            "bad_pin" => f.write(".mergemaster/tool-pin.json", "{}"),
            _ => unreachable!(),
        }
        f.write(".mergemaster/lanes.json", if case == "malformed" { "{".to_owned() } else { policy.to_string() });
        f.base = f.commit("invalid base");
        f.refresh_head();
        let output_path = f.root.path().join("outputs");
        let output = f.gate(&["--github-output", output_path.to_str().unwrap()]);
        assert!(!output.status.success(), "{case}: {}", String::from_utf8_lossy(&output.stdout));
        assert!(!output_path.exists() || fs::read(&output_path).unwrap().is_empty(), "{case}: failure published outputs");
    }
}

#[test]
fn note_layouts_deduplicate_and_never_transfer_to_another_tree() {
    for layout in ["tree", "tag", "legacy"] {
        let mut f = Fixture::new();
        let record = f.note(&f.statement(), &f.key, layout);
        for duplicate in ["tree", "tag", "legacy"] { f.publish(&record, duplicate); }
        let decision = f.decision(&[]);
        assert_eq!(decision["decision"], "skip", "{layout}: {decision}");
        assert_eq!(decision["record"], record);
        f.write("source.txt", "different tree\n");
        f.refresh_head();
        assert_eq!(f.decision(&[])["decision"], "refuse");
    }
}

#[test]
fn protected_changes_include_both_sides_of_renames() {
    for case in ["add", "edit", "delete", "rename_out", "rename_in", "component_boundary"] {
        let mut f = Fixture::new();
        match case {
            "add" => f.write(".github/actions/new/action.yml", "new\n"),
            "edit" => f.write(".github/workflows/evidence.yml", "changed\n"),
            "delete" => fs::remove_file(f.repo.join(".github/workflows/evidence.yml")).unwrap(),
            "rename_out" => { fs::rename(f.repo.join(".github/workflows/evidence.yml"), f.repo.join("workflow.yml")).unwrap(); }
            "rename_in" => { fs::rename(f.repo.join("source.txt"), f.repo.join(".github/workflows/source.yml")).unwrap(); f.write("source.txt", "replacement\n"); }
            "component_boundary" => f.write(".github/workflows-extra/file", "not a protected component\n"),
            _ => unreachable!(),
        }
        f.refresh_head();
        f.note(&f.statement(), &f.key, "tree");
        let decision = f.decision(&[]);
        assert_eq!(decision["decision"], if case == "component_boundary" { "skip" } else { "refuse" }, "{case}: {decision}");
        if case != "component_boundary" { assert_eq!(decision["reason"], "protected_paths", "{case}: {decision}"); }
    }
}

#[test]
fn divergent_history_and_same_tree_different_commit_are_not_eligible() {
    let mut f = Fixture::new();
    let statement = f.statement();
    f.note(&statement, &f.key, "tree");
    f.refresh_head(); // Empty commit: same tree is insufficient; subject commit must also be exact.
    assert_eq!(f.decision(&[])["decision"], "refuse");
    let unrelated = f.git(&["commit-tree", &f.tree, "-m", "unrelated"], b"");
    f.head = unrelated;
    f.git(&["update-ref", "HEAD", &f.head], b"");
    let decision = f.decision(&[]);
    assert_eq!(decision["decision"], "refuse");
    assert_eq!(decision["reason"], "base_not_ancestor");
}

#[test]
fn computed_refusal_and_satisfaction_publish_compatible_outputs() {
    let f = Fixture::new();
    let outputs = f.root.path().join("outputs");
    let refused = f.decision(&["--github-output", outputs.to_str().unwrap()]);
    assert_eq!(refused["decision"], "refuse");
    assert_eq!(refused["outcome"], "no_note");
    let text = fs::read_to_string(&outputs).unwrap();
    for field in ["skip=false", "refuse=true", "outcome=no_note", "refusal="] { assert!(text.contains(field), "{text}"); }
    fs::remove_file(&outputs).unwrap();
    let record = f.note(&f.statement(), &f.key, "tree");
    let satisfied = f.decision(&["--github-output", outputs.to_str().unwrap()]);
    assert_eq!(satisfied["decision"], "skip");
    let text = fs::read_to_string(outputs).unwrap();
    for field in ["skip=true", "refuse=false", "outcome=satisfied", &format!("record={record}")] { assert!(text.contains(field), "{text}"); }
    let usage = f.command(env!("CARGO_BIN_EXE_mergemaster")).args(["gate", "--check", CHECK]).output().unwrap();
    assert!(!usage.status.success());
}

#[test]
fn python_reference_and_rust_gate_accept_and_reject_the_same_signed_lane() {
    for failed in [false, true] {
        let f = Fixture::new();
        let mut statement = f.statement();
        statement["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(i32::from(failed));
        let record = f.note(&statement, &f.key, "tree");
        let python = f.python();
        let reference: Value = serde_json::from_slice(&python.stdout).unwrap();
        assert_eq!(python.status.success(), !failed, "{reference}");
        let rust = f.decision(&[]);
        assert_eq!(rust["decision"], if failed { "refuse" } else { "skip" });
        if failed { assert_eq!(reference["reason"], "check_failed"); assert_eq!(rust["reason"], "check_failed"); }
        else { assert_eq!(reference["record"], record); assert_eq!(rust["record"], record); }
    }
}

#[test]
fn optional_fallback_runs_instead_of_refusing_missing_or_failed_evidence() {
    let mut f = Fixture::new();
    f.write(".mergemaster/lanes.json", Fixture::policy("optional_fallback").to_string());
    f.base = f.commit("optional base policy");
    f.refresh_head();
    let missing = f.decision(&[]);
    assert_eq!(missing["decision"], "run");
    assert_eq!(missing["outcome"], "no_note");
    let mut statement = f.statement();
    statement["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1);
    f.note(&statement, &f.key, "tree");
    let failed = f.decision(&[]);
    assert_eq!(failed["decision"], "run");
    assert_eq!(failed["reason"], "check_failed");
}

#[test]
fn supplied_event_must_bind_exact_head_base_and_repository() {
    for case in ["valid", "head", "base", "fork", "repository"] {
        let f = Fixture::new();
        f.note(&f.statement(), &f.key, "tree");
        let mut event = json!({
            "repository":{"full_name":"fixture/repo"},
            "number":1,
            "pull_request":{
                "head":{"sha":f.head,"repo":{"full_name":"fixture/repo"}},
                "base":{"sha":f.base,"ref":"main","repo":{"full_name":"fixture/repo"}},
                "user":{"login":"fixture"}
            }
        });
        match case {
            "head" => event["pull_request"]["head"]["sha"] = json!(f.base),
            "base" => event["pull_request"]["base"]["sha"] = json!(f.head),
            "fork" => event["pull_request"]["head"]["repo"]["full_name"] = json!("attacker/repo"),
            "repository" => event["repository"]["full_name"] = json!("attacker/repo"),
            _ => {}
        }
        let path = f.root.path().join("event.json");
        f.live_api(&f.head, &f.base);
        fs::write(&path, event.to_string()).unwrap();
        let decision = f.decision(&["--event-file", path.to_str().unwrap()]);
        assert_eq!(decision["decision"], if case == "valid" { "skip" } else { "refuse" }, "{case}: {decision}");
        if case != "valid" { assert_eq!(decision["reason"], "ineligible_event"); }
    }
}

#[test]
fn latest_failure_is_not_hidden_by_a_nearby_passing_observation() {
    for seconds_after_failure in [0, 119, 120, 121] {
        let f = Fixture::new();
        let mut failure = f.statement();
        let failed_at = chrono::Utc::now() - chrono::Duration::minutes(10);
        failure["predicate"]["observed_at"] = json!(failed_at.to_rfc3339());
        failure["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1);
        f.note(&failure, &f.key, "tree");
        let mut pass = f.statement();
        pass["predicate"]["observed_at"] = json!((failed_at + chrono::Duration::seconds(seconds_after_failure)).to_rfc3339());
        f.note(&pass, &f.key, "tree");
        let decision = f.decision(&[]);
        assert_eq!(decision["decision"], if seconds_after_failure > 120 { "skip" } else { "refuse" }, "{decision}");
        let reference = f.python();
        assert_eq!(reference.status.success(), seconds_after_failure > 120);
    }
}

#[test]
fn record_ref_names_must_match_the_immutable_signed_object() {
    let f = Fixture::new();
    let record = f.note(&f.statement(), &f.key, "tree");
    f.git(&["update-ref", "-d", &format!("refs/notes/evidence/{}/{record}", f.tree)], b"");
    f.git(&["update-ref", &format!("refs/notes/evidence/{}/{}", f.tree, "0".repeat(40)), &record], b"");
    let decision = f.decision(&[]);
    assert_eq!(decision["decision"], "refuse");
    assert_eq!(decision["reason"], "invalid_record");
}

#[test]
fn configured_maximum_age_rejects_old_signed_success() {
    let mut f = Fixture::new();
    let mut policy = Fixture::policy("required_evidence");
    policy["lanes"][CHECK]["max_age_seconds"] = json!(60);
    f.write(".mergemaster/lanes.json", policy.to_string());
    f.base = f.commit("age-limited policy");
    f.refresh_head();
    let mut statement = f.statement();
    statement["predicate"]["observed_at"] = json!((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
    f.note(&statement, &f.key, "tree");
    let decision = f.decision(&[]);
    assert_eq!(decision["decision"], "refuse");
    assert_eq!(decision["reason"], "too_old");
}

#[test]
fn moved_python_signer_produces_a_record_the_generic_gate_accepts() {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let mut f = Fixture::new();
    // Legacy Nix-consumer fixture only: the moved signer independently requires
    // flake.lock. Generic fixtures above deliberately have no Nix contract.
    let lock = b"{\"nodes\":{\"root\":{}},\"root\":\"root\",\"version\":7}\n";
    f.write("flake.lock", lock);
    f.refresh_head();
    let config_dir = f.root.path().join(".config/st");
    fs::create_dir_all(&config_dir).unwrap();
    // Resolve only the two protected signer's tools, not sandbox wrappers or
    // writable build directories from the rest of the test harness's PATH.
    use std::os::unix::fs::PermissionsExt;
    let search_path = std::env::var_os("PATH").unwrap();
    let mut tool_dirs = std::collections::BTreeSet::new();
    for program in ["git", "ssh-keygen"] {
        let executable = std::env::split_paths(&search_path)
            .filter_map(|directory| fs::canonicalize(directory.join(program)).ok())
            .find(|path| fs::metadata(path).is_ok_and(|metadata|
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0))
            .unwrap_or_else(|| panic!("a real {program} must be available"));
        tool_dirs.insert(executable.parent().unwrap().to_path_buf());
    }
    let signer_path = std::env::join_paths(tool_dirs).unwrap();
    fs::write(config_dir.join("evidence-sign.json"), json!({
        "signer":PRINCIPAL,"ssh_key":f.key,
        "scratch_repo":f.root.path().join("signer.git"),
        "path":signer_path.to_str().unwrap()
    }).to_string()).unwrap();
    let statement = f.statement();
    let mut inputs = statement["predicate"]["observed"]["inputs"].clone();
    inputs["flake_lock_sha256"] = json!(hex::encode(Sha256::digest(lock)));
    let request = json!({
        "commit":f.head,"check":CHECK,"command":["tools/graph","check","--full"],
        "exit_code":0,"output_sha256":"b".repeat(64),"change_id":"python-produced",
        "inputs":inputs
    });
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/evidence-sign");
    let mut signer = f.command("python3").arg(script)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    signer.stdin.take().unwrap().write_all(request.to_string().as_bytes()).unwrap();
    let output = signer.wait_with_output().unwrap();
    assert!(output.status.success(), "moved signer: {}", String::from_utf8_lossy(&output.stderr));
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["commit"], f.head);
    assert_eq!(response["tree"], f.tree);
    let pack = base64::engine::general_purpose::STANDARD
        .decode(response["object_pack_base64"].as_str().unwrap()).unwrap();
    f.git(&["unpack-objects", "-q"], &pack);
    let record = response["record"].as_str().unwrap();
    f.publish(record, "tree");
    let decision = f.decision(&[]);
    assert_eq!(decision["decision"], "skip", "{decision}");
    assert_eq!(decision["record"], record);
    let python = f.python();
    assert!(python.status.success(), "{}", String::from_utf8_lossy(&python.stdout));
    let reference: Value = serde_json::from_slice(&python.stdout).unwrap();
    assert_eq!(reference["record"], record);
}

#[test]
fn protected_aliases_and_symlink_replacements_never_skip() {
    for path in [".MERGEMASTER/new", ".GitHub/Workflows/new.yml",
        ".github/ｗｏｒｋｆｌｏｗｓ/new.yml", "．mergemaster/new", ".github/actions/new"] {
        let mut f = Fixture::new();
        f.write(path, "protected alias\n");
        f.refresh_head();
        f.note(&f.statement(), &f.key, "tree");
        assert_eq!(f.decision(&[])["reason"], "protected_paths", "{path}");
    }
    for path in [".github/workflows/evidence.yml", ".github", ".mergemaster"] {
        let mut f = Fixture::new();
        let target = f.repo.join(path);
        if target.is_dir() { fs::remove_dir_all(&target).unwrap(); }
        else { fs::remove_file(&target).unwrap(); }
        std::os::unix::fs::symlink("outside", target).unwrap();
        f.refresh_head();
        // Trust still comes from BASE even when HEAD replaces the entire root.
        assert_eq!(f.decision(&[])["reason"], "protected_paths", "{path}");
    }
}

#[test]
fn merge_commits_anywhere_in_candidate_history_refuse() {
    for at_tip in [true, false] {
        let mut f = Fixture::new();
        let side = f.git(&["commit-tree", &f.tree, "-p", &f.base, "-m", "side"], b"");
        let merge = f.git(&["commit-tree", &f.tree, "-p", &f.head, "-p", &side, "-m", "merge"], b"");
        f.git(&["update-ref", "HEAD", &merge], b"");
        f.head = merge;
        if !at_tip { f.refresh_head(); }
        f.note(&f.statement(), &f.key, "tree");
        assert_eq!(f.decision(&[])["reason"], "merge_history");
    }
}

#[test]
fn live_github_recheck_precedes_all_decision_outputs() {
    for outcome in ["skip", "no_note", "protected"] {
        for moved in ["head", "base", "unavailable", "unchanged"] {
            let mut f = Fixture::new();
            if outcome == "protected" { f.write(".github/actions/new", "changed"); f.refresh_head(); }
            if outcome == "skip" { f.note(&f.statement(), &f.key, "tree"); }
            f.live_api(if moved == "head" { &f.base } else { &f.head },
                if moved == "base" { &f.head } else { &f.base });
            if moved == "unavailable" { fs::remove_file(f.root.path().join("live-pull")).unwrap(); }
            let event = f.root.path().join("event.json");
            fs::write(&event, json!({"number":1, "repository":{"full_name":"fixture/repo"},
                "pull_request":{"head":{"sha":f.head,"repo":{"full_name":"fixture/repo"}},
                    "base":{"sha":f.base,"ref":"main","repo":{"full_name":"fixture/repo"}}}
            }).to_string()).unwrap();
            let outputs = f.root.path().join("outputs");
            let result = f.gate(&["--event-file", event.to_str().unwrap(),
                "--github-output", outputs.to_str().unwrap()]);
            assert_eq!(result.status.success(), moved == "unchanged", "{outcome}/{moved}");
            if moved != "unchanged" {
                assert!(result.stdout.is_empty());
                assert!(!outputs.exists() || fs::read(outputs).unwrap().is_empty());
            }
            assert!(f.root.path().join("api-calls").exists(), "{outcome}/{moved}: no live recheck");
        }
    }
}

#[test]
fn concurrent_local_head_and_base_movements_cannot_publish_decisions() {
    use std::os::unix::fs::PermissionsExt;
    for evidence in [false, true] {
        for reference in ["HEAD", "refs/heads/gate-base"] {
            let f = Fixture::new();
            if evidence { f.note(&f.statement(), &f.key, "tree"); }
            // A Git interposer moves a real ref at evidence discovery, after the
            // initial snapshot. No sleeps or scheduler-dependent timing.
            let real_git = f.command("sh").args(["-c", "command -v git"]).output().unwrap();
            let real_git = String::from_utf8(real_git.stdout).unwrap().trim().to_owned();
            let bin = f.root.path().join("bin");
            fs::create_dir_all(&bin).unwrap();
            let script = bin.join("git");
            fs::write(&script, format!(r#"#!{python}
import subprocess, sys
git = {real_git:?}
args = sys.argv[1:]
if "refs/notes/evidence/" in args:
    subprocess.run([git, "-C", {repo:?}, "update-ref", {reference:?}, {replacement:?}], check=True)
raise SystemExit(subprocess.run([git] + args).returncode)
"#, python = python_executable(), repo = f.repo.to_str().unwrap(), replacement = if reference == "HEAD" { &f.base } else { &f.head })).unwrap();
            fs::set_permissions(script, fs::Permissions::from_mode(0o755)).unwrap();
            let outputs = f.root.path().join("outputs");
            let result = f.gate(&["--github-output", outputs.to_str().unwrap()]);
            assert!(!result.status.success(), "{evidence}/{reference}");
            assert!(String::from_utf8_lossy(&result.stderr).contains("refs changed"));
            assert!(result.stdout.is_empty());
            assert!(!outputs.exists() || fs::read(outputs).unwrap().is_empty());
        }
    }
}

#[test]
fn immutable_ids_alone_are_not_a_local_live_authority() {
    for missing_base_ref in [true, false] {
        let f = Fixture::new();
        if missing_base_ref {
            f.git(&["update-ref", "-d", "refs/heads/gate-base"], b"");
        } else {
            f.git(&["update-ref", "HEAD", &f.base], b"");
        }
        let outputs = f.root.path().join("outputs");
        let result = f.command(env!("CARGO_BIN_EXE_mergemaster")).args([
            "gate", "--check", CHECK, "--base", &f.base, "--head", &f.head,
            "--format", "json", "--github-output", outputs.to_str().unwrap(),
        ]).output().unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!outputs.exists() || fs::read(outputs).unwrap().is_empty());
    }
}
