//! Generic single-lane gate contracts, using actual Git objects and SSH signatures.
use mergemaster_evidence::gate::config::{expected_inputs, load};
use serde_json::{Value, json};
use sha2::Digest;
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
        .find(|path| path.is_file())
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
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
        let mut f = Self {
            root,
            repo,
            key,
            stranger,
            base: String::new(),
            head: String::new(),
            tree: String::new(),
        };
        f.git(&["init", "-q"], b"");
        for key in [&f.key, &f.stranger] {
            let output = f
                .command("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(key)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let public = fs::read_to_string(f.key.with_extension("pub")).unwrap();
        f.write(
            ".mergemaster/evidence-keys",
            format!("{PRINCIPAL} namespaces=\"git\" {public}"),
        );
        f.write(".mergemaster/tool-pin.json", json!({"version":1,"repository":"compoundingtech/mergemaster","revision":"a".repeat(40)}).to_string());
        f.write(".mergemaster/environment.json", json!({
            "version":1,"system":"x86_64-linux",
            "toolchain":{"runtime":{"name":"bun","identity":format!("sha256:{}", "a".repeat(64))},"dependencies":{}}
        }).to_string());
        f.write(
            ".mergemaster/lanes.json",
            Self::policy("required_evidence").to_string(),
        );
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
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", self.root.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("LC_ALL", "C")
            .env("GITHUB_REPOSITORY", "fixture/repo")
            .current_dir(&self.repo);
        command
    }

    fn git(&self, args: &[&str], input: &[u8]) -> String {
        let mut child = self
            .command("git")
            .args([
                "--no-replace-objects",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "maintenance.auto=false",
                "-c",
                "gc.auto=0",
                "-c",
                "diff.external=",
                "-c",
                "core.sshCommand=false",
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn write(&self, path: &str, bytes: impl AsRef<[u8]>) {
        let path = self.repo.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn commit(&self, message: &str) -> String {
        self.git(&["add", "-A"], b"");
        self.git(
            &[
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--allow-empty",
                "-q",
                "-m",
                message,
            ],
            b"",
        );
        self.git(&["rev-parse", "HEAD"], b"")
    }

    fn refresh_head(&mut self) {
        self.head = self.commit("candidate");
        self.tree = self.git(&["rev-parse", "HEAD^{tree}"], b"");
    }

    fn statement(&self) -> Value {
        let config = load(&self.repo, &self.base).unwrap();
        let mut inputs = expected_inputs(
            &self.repo,
            &self.head,
            CHECK,
            &config.policy.lanes[CHECK],
            &config.environment,
            &config.environment_bytes,
        )
        .unwrap();
        for (name, value) in [
            ("workspace_clean", "true"),
            ("untracked_files", "false"),
            ("attempt", "1"),
        ] {
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
        let notes = self.git(
            &["mktree"],
            format!("100644 blob {blob}\t{}\n", self.tree).as_bytes(),
        );
        let signing_key = format!("user.signingKey={}", key.display());
        let record = self.git(
            &[
                "-c",
                "gpg.format=ssh",
                "-c",
                "gpg.ssh.program=ssh-keygen",
                "-c",
                &signing_key,
                "commit-tree",
                "-S",
                &notes,
                "-p",
                &self.head,
                "-m",
                "st gate observation v1",
            ],
            b"",
        );
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
        fs::write(
            &script,
            format!(
                r#"#!{python}
import json, os, pathlib, sys
root = pathlib.Path(os.environ["HOME"])
assert os.environ["GH_TOKEN"] == "fixture-token"
assert sys.argv[1:4] == ["api", "--hostname", "github.com"]
with (root / "api-calls").open("a") as log:
    log.write(sys.argv[4] + "\n")
name = "live-pull" if "/pulls/" in sys.argv[4] else "live-base"
print((root / name).read_text())
"#,
                python = python_executable()
            ),
        )
        .unwrap();
        fs::set_permissions(script, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            self.root.path().join("live-pull"),
            json!({
                "head":{"sha":head,"repo":{"full_name":"fixture/repo"}},
                "base":{"sha":base,"ref":"main","repo":{"full_name":"fixture/repo"}}
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            self.root.path().join("live-base"),
            json!({"default_branch":"main","object":{"sha":base}}).to_string(),
        )
        .unwrap();
    }

    fn gate(&self, extra: &[&str]) -> Output {
        self.git(&["update-ref", "refs/heads/gate-base", &self.base], b"");
        let mut command = self.command(env!("CARGO_BIN_EXE_mergemaster"));
        let path = std::env::join_paths(
            std::iter::once(self.root.path().join("bin"))
                .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        command
            .env("PATH", path)
            .env("GITHUB_TOKEN", "fixture-token")
            .args([
                "gate", "--check", CHECK, "--base", &self.base, "--head", &self.head, "--format",
                "json",
            ])
            .args(extra)
            .output()
            .unwrap()
    }

    fn decision(&self, extra: &[&str]) -> Value {
        let output = self.gate(extra);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["check"], CHECK);
        assert_eq!(value["base"], self.base);
        assert_eq!(value["head"], self.head);
        assert_eq!(value["tree"], self.tree);
        assert_eq!(value["expectation_source"], "caller");
        assert!(value["protected_paths"].is_array());
        value
    }

    fn push(&self, reference: &str, after: &str, live: &str) -> Value {
        self.live_api(&self.head, live);
        let event = self.root.path().join("push.json");
        fs::write(
            &event,
            json!({"ref":reference,"after":after,
            "repository":{"full_name":"fixture/repo"}})
            .to_string(),
        )
        .unwrap();
        self.decision(&["--event", "push", "--event-file", event.to_str().unwrap()])
    }

    fn python(&self) -> Output {
        self.python_with(&[])
    }

    fn python_with(&self, extra: &[&str]) -> Output {
        let script = PathBuf::from(
            std::env::var_os("MERGEMASTER_PYTHON_ORACLE")
                .expect("MERGEMASTER_PYTHON_ORACLE must be set; run tests in nix develop"),
        )
        .join("scripts/evidence-verify");
        let keys = self.root.path().join("trusted-signers");
        fs::write(
            &keys,
            self.git(
                &["show", &format!("{}:.mergemaster/evidence-keys", self.base)],
                b"",
            ),
        )
        .unwrap();
        self.command("python3")
            .arg(script)
            .args(["--repo"])
            .arg(&self.repo)
            .args(["--revision", &self.head, "--check", CHECK, "--keys"])
            .arg(keys)
            .args([
                "--command",
                "[\"tools/graph\",\"check\",\"--full\"]",
                "--trust-levels",
                "agent",
            ])
            .args(extra)
            .output()
            .unwrap()
    }

    fn oracle_selection(&self, definition: &str) -> Value {
        self.oracle_selection_with(definition, None, false, None)
    }

    fn oracle_selection_with(
        &self,
        definition: &str,
        age: Option<u64>,
        bind: bool,
        now: Option<&str>,
    ) -> Value {
        let root = PathBuf::from(std::env::var_os("MERGEMASTER_PYTHON_ORACLE").unwrap());
        let keys = self.root.path().join("selection-keys");
        fs::write(
            &keys,
            self.git(
                &["show", &format!("{}:.mergemaster/evidence-keys", self.base)],
                b"",
            ),
        )
        .unwrap();
        // Isolate selection from digest derivation: Rust's compact-JSON lane
        // digest differs from legacy --lane-from. The oracle code is unchanged.
        let output = self
            .command("python3")
            .args([
                "-c",
                r#"
import json, runpy, sys
v = runpy.run_path(sys.argv[1])
try:
    r = v['verify'](sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],
        ['tools/graph', 'check', '--full'], trust_levels=['agent'],
        lane={'sha256': sys.argv[6], 'changed': []}, max_age=int(sys.argv[7]) or None,
        bind=[('wrapper_sha256', 'tools/graph')] if sys.argv[8] == 'true' else [],
        now=v['parse_time'](sys.argv[9]) if sys.argv[9] else None)
    r['reason'] = 'satisfied'
except v['Failure'] as e:
    r = dict(satisfied=False, reason=e.reason, **e.extra)
print(json.dumps(r))
"#,
            ])
            .arg(root.join("scripts/evidence-verify"))
            .args([
                self.repo.to_str().unwrap(),
                &self.tree,
                CHECK,
                keys.to_str().unwrap(),
                definition,
            ])
            .args([age.unwrap_or(0).to_string(), bind.to_string()])
            .arg(now.unwrap_or_default())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

fn queue_fixture() -> Fixture {
    let mut f = Fixture::new();
    let mut policy = Fixture::policy("required_evidence");
    policy["lanes"][CHECK]["events"] = json!(["queue"]);
    f.write(".mergemaster/lanes.json", policy.to_string());
    f.base = f.commit("queue policy");
    f.write("source.txt", "queue candidate\n");
    f.refresh_head();
    f.head = f.git(
        &[
            "commit-tree",
            &f.tree,
            "-p",
            &f.base,
            "-p",
            &f.head,
            "-m",
            "queue",
        ],
        b"",
    );
    f
}

#[test]
fn queue_exact_tree_is_report_only_in_either_parent_order() {
    let mut f = queue_fixture();
    let mut statement = f.statement();
    statement["predicate"]["observed_at"] =
        json!((chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339());
    let record = f.note(&statement, &f.key, "tree");
    let mut newer = f.statement();
    newer["predicate"]["observed"]["inputs"]["lane_definition_sha256"] = json!("0".repeat(64));
    f.note(&newer, &f.key, "tree");
    let oracle = f.oracle_selection(
        statement["predicate"]["observed"]["inputs"]["lane_definition_sha256"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(oracle["reason"], "satisfied");
    assert_eq!(oracle["decided_by"], record);
    let output = f.root.path().join("github-output");
    for reverse in [false, true] {
        if reverse {
            let other = f.git(&["rev-parse", &format!("{}^2", f.head)], b"");
            f.head = f.git(
                &[
                    "commit-tree",
                    &f.tree,
                    "-p",
                    &other,
                    "-p",
                    &f.base,
                    "-m",
                    "reversed",
                ],
                b"",
            );
        }
        let d = f.decision(&[
            "--event",
            "queue",
            "--github-output",
            output.to_str().unwrap(),
        ]);
        assert_eq!(d["decision"], "refuse");
        assert_eq!(d["reason"], "satisfied");
        assert_eq!(d["outcome"], "satisfied");
        assert_eq!(d["record"], record);
        assert_eq!(d["report_only"], true);
        assert_eq!(d["signer"], PRINCIPAL);
        assert_eq!(d["observed_at"], statement["predicate"]["observed_at"]);
        assert!(d["age_seconds"].is_i64());
        assert_eq!(
            d["lane_definition_sha256"],
            statement["predicate"]["observed"]["inputs"]["lane_definition_sha256"]
        );
    }
    let output = fs::read_to_string(output).unwrap();
    assert!(!output.contains("skip=true"));
    assert!(output.contains("skip=false"));
    assert!(output.contains("refuse=true"));
}

#[test]
fn queue_requires_two_parents_bound_base_and_no_event_file() {
    let mut f = queue_fixture();
    assert_eq!(
        f.decision(&["--event", "queue", "--event-file", "unused"])["reason"],
        "source_unbound"
    );
    let original = f.head.clone();
    f.head = f.git(
        &["commit-tree", &f.tree, "-p", &f.base, "-m", "one parent"],
        b"",
    );
    assert_eq!(
        f.decision(&["--event", "queue"])["reason"],
        "source_unbound"
    );
    let unrelated = f.git(&["commit-tree", &f.tree, "-m", "unrelated"], b"");
    f.head = f.git(
        &[
            "commit-tree",
            &f.tree,
            "-p",
            &original,
            "-p",
            &unrelated,
            "-m",
            "non-parent base",
        ],
        b"",
    );
    assert_eq!(
        f.decision(&["--event", "queue"])["reason"],
        "source_unbound"
    );
}

#[test]
fn queue_requires_base_keys_and_lane_opt_in() {
    let mut f = queue_fixture();
    let mut policy = Fixture::policy("required_evidence");
    f.write(".mergemaster/lanes.json", policy.to_string());
    f.base = f.commit("no queue");
    f.head = f.git(
        &[
            "commit-tree",
            &f.tree,
            "-p",
            &f.base,
            "-p",
            &f.head,
            "-m",
            "queue",
        ],
        b"",
    );
    assert_eq!(
        f.decision(&["--event", "queue"])["reason"],
        "event_not_allowed"
    );
    policy["lanes"][CHECK]["events"] = json!(["queue"]);
    f.write(".mergemaster/lanes.json", policy.to_string());
    fs::remove_file(f.repo.join(".mergemaster/evidence-keys")).unwrap();
    f.base = f.commit("no keys");
    assert_eq!(
        f.decision(&["--event", "queue"])["reason"],
        "config_missing"
    );
}

#[test]
fn missing_keys_precede_lane_expansion_but_no_record_still_validates_inputs() {
    let mut f = queue_fixture();
    let mut policy = Fixture::policy("required_evidence");
    policy["lanes"][CHECK]["events"] = json!(["queue"]);
    policy["lanes"][CHECK]["definition_paths"] = json!(["absent"]);
    f.write(".mergemaster/lanes.json", policy.to_string());
    fs::remove_file(f.repo.join(".mergemaster/evidence-keys")).unwrap();
    f.base = f.commit("missing keys and lane input");
    f.refresh_head();
    assert_eq!(
        f.decision(&["--event", "queue"])["reason"],
        "config_missing"
    );

    let mut f = queue_fixture();
    fs::remove_file(f.repo.join("tools/graph")).unwrap();
    f.refresh_head();
    f.head = f.git(
        &[
            "commit-tree",
            &f.tree,
            "-p",
            &f.base,
            "-p",
            &f.head,
            "-m",
            "queue",
        ],
        b"",
    );
    let output = f.gate(&["--event", "queue"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing committed input path"));
}

#[test]
fn queue_input_comparison_never_satisfies_a_different_tree() {
    let mut f = queue_fixture();
    let compared = f.head.clone();
    let compared_tree = f.tree.clone();
    f.note(&f.statement(), &f.key, "tree");
    f.write("unrelated.txt", "not a lane input\n");
    f.refresh_head();
    f.head = f.git(
        &[
            "commit-tree",
            &f.tree,
            "-p",
            &f.base,
            "-p",
            &f.head,
            "-m",
            "queue",
        ],
        b"",
    );
    let d = f.decision(&["--event", "queue", "--compare-head", &compared]);
    assert_eq!(d["input_key_equal"], true);
    assert_eq!(d["compared_record"]["tree"], compared_tree);
    assert_eq!(d["compared_record"]["signer"], PRINCIPAL);
    assert_eq!(d["reason"], "no_record");
    assert_eq!(d["decision"], "refuse");
    assert!(d["record"].is_null());
    f.write("tools/graph", "changed definition\n");
    f.refresh_head();
    f.head = f.git(
        &[
            "commit-tree",
            &f.tree,
            "-p",
            &f.base,
            "-p",
            &f.head,
            "-m",
            "queue",
        ],
        b"",
    );
    assert_eq!(
        f.decision(&["--event", "queue", "--compare-head", &compared])["input_key_equal"],
        false
    );
    assert!(!f.gate(&["--compare-head", &compared]).status.success());
}

fn merge_group_fixture() -> Fixture {
    let mut f = Fixture::new();
    let mut policy = Fixture::policy("required_evidence");
    policy["lanes"][CHECK]["events"] = json!(["merge_group"]);
    f.write(".mergemaster/lanes.json", policy.to_string());
    f.base = f.commit("opt into merge-group shadow");
    f.write("source.txt", "queue candidate\n");
    f.refresh_head();
    f
}

fn merge_group_event(f: &Fixture) -> Value {
    json!({"action":"checks_requested","repository":{"full_name":"fixture/repo"},
        "merge_group":{"head_sha":f.head,"base_sha":f.base,"base_ref":"refs/heads/main",
            "head_ref":format!("refs/heads/gh-readonly-queue/main/pr-1-{}", f.head)}})
}

fn merge_group_decision(f: &Fixture, event: &Value, extra: &[&str]) -> Value {
    let path = f.root.path().join("merge-group.json");
    fs::write(&path, event.to_string()).unwrap();
    let mut args = vec![
        "--event",
        "merge_group",
        "--event-file",
        path.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    f.decision(&args)
}

#[test]
fn merge_group_is_explicit_and_report_only_even_with_satisfying_evidence() {
    let f = merge_group_fixture();
    f.note(&f.statement(), &f.key, "tree");
    let output = f.root.path().join("github-output");
    let decision = merge_group_decision(
        &f,
        &merge_group_event(&f),
        &["--github-output", output.to_str().unwrap()],
    );
    assert_eq!(decision["decision"], "refuse");
    assert_eq!(decision["outcome"], "rejected");
    assert_eq!(decision["reason"], "report_only_queue_parent");
    assert_eq!(decision["expectation_source"], "caller");
    assert!(
        decision["summary"]
            .as_str()
            .unwrap()
            .contains("queue parent, not the live accepted BASE")
    );
    let output = fs::read_to_string(output).unwrap();
    assert!(output.contains("skip=false\n"));
    assert!(output.contains("refuse=true\n"));
}

#[test]
fn merge_group_requires_lane_opt_in_and_event_file() {
    let f = Fixture::new();
    assert_eq!(
        merge_group_decision(&f, &merge_group_event(&f), &[])["reason"],
        "event_not_allowed"
    );
    let f = merge_group_fixture();
    assert_eq!(
        f.decision(&["--event", "merge_group"])["reason"],
        "source_unbound"
    );
    assert_eq!(
        merge_group_decision(&f, &merge_group_event(&f), &[])["reason"],
        "no_record"
    );
}

#[test]
fn merge_group_refuses_unbound_candidate_parent_or_queue_ref() {
    let f = merge_group_fixture();
    for (field, value) in [
        ("head_sha", f.base.clone()),
        ("base_sha", f.head.clone()),
        (
            "head_ref",
            format!("refs/heads/gh-readonly-queue/main/pr-01-{}", f.head),
        ),
        (
            "head_ref",
            format!("refs/heads/gh-readonly-queue/other/pr-1-{}", f.head),
        ),
        (
            "head_ref",
            "refs/heads/gh-readonly-queue/main/pr-1-not-a-sha".into(),
        ),
    ] {
        let mut event = merge_group_event(&f);
        event["merge_group"][field] = json!(value);
        let decision = merge_group_decision(&f, &event, &[]);
        assert_eq!(decision["decision"], "refuse");
        assert_eq!(decision["reason"], "source_unbound", "{field}: {value}");
    }
}

#[test]
fn merge_group_refuses_wrong_action_repository_or_missing_binding_fields() {
    let f = merge_group_fixture();
    f.note(&f.statement(), &f.key, "tree");
    for case in [
        "action",
        "repository",
        "head_sha",
        "base_sha",
        "base_ref",
        "head_ref",
    ] {
        let mut event = merge_group_event(&f);
        match case {
            "action" => event["action"] = json!("destroyed"),
            "repository" => event["repository"]["full_name"] = json!("other/repo"),
            field => {
                event["merge_group"].as_object_mut().unwrap().remove(field);
            }
        }
        let decision = merge_group_decision(&f, &event, &[]);
        assert_eq!(decision["decision"], "refuse", "{case}: {decision}");
        assert_eq!(decision["outcome"], "rejected", "{case}: {decision}");
        assert_eq!(decision["reason"], "source_unbound", "{case}: {decision}");
    }
}

#[test]
fn merge_group_optional_fallback_never_emits_skip() {
    for case in ["missing", "failed", "satisfied"] {
        let mut f = merge_group_fixture();
        let mut policy = Fixture::policy("optional_fallback");
        policy["lanes"][CHECK]["events"] = json!(["merge_group"]);
        f.write(".mergemaster/lanes.json", policy.to_string());
        f.base = f.commit("optional merge-group policy");
        f.write("source.txt", "optional queue candidate\n");
        f.refresh_head();
        if case != "missing" {
            let mut statement = f.statement();
            if case == "failed" {
                statement["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1);
            }
            f.note(&statement, &f.key, "tree");
        }
        let output = f.root.path().join(format!("optional-output-{case}"));
        let decision = merge_group_decision(
            &f,
            &merge_group_event(&f),
            &["--github-output", output.to_str().unwrap()],
        );
        assert_eq!(decision["decision"], "refuse", "{case}: {decision}");
        assert_eq!(
            decision["reason"],
            match case {
                "missing" => "no_record",
                "failed" => "check_failed",
                _ => "report_only_queue_parent",
            },
            "{case}: {decision}"
        );
        assert_eq!(
            decision["outcome"],
            if case == "missing" {
                "no_note"
            } else {
                "rejected"
            }
        );
        let output = fs::read_to_string(output).unwrap();
        assert!(output.contains("skip=false\n"), "{case}: {output}");
        assert!(output.contains("refuse=true\n"), "{case}: {output}");
    }
}

#[test]
fn merge_group_with_reused_hosted_evidence_is_still_report_only() {
    let f = merge_group_fixture();
    f.note(&f.statement(), &f.key, "tree");
    let hosted = f.root.path().join("hosted.json");
    fs::write(&hosted, approval_evidence(&f).to_string()).unwrap();
    let decision = merge_group_decision(
        &f,
        &merge_group_event(&f),
        &["--hosted-evidence", hosted.to_str().unwrap()],
    );
    assert_eq!(decision["decision"], "refuse");
    assert_eq!(decision["outcome"], "rejected");
    assert_eq!(decision["reason"], "report_only_queue_parent");
}

#[test]
fn merge_group_human_approval_never_yields_satisfied() {
    let mut f = approval_fixture();
    let mut policy = Fixture::policy("required_evidence");
    policy["lanes"][CHECK]["events"] = json!(["pull_request", "merge_group"]);
    policy["lanes"][CHECK]["protected_edits"] = json!("human_approval");
    policy["lanes"][CHECK]["approvers"] = json!(["schickling"]);
    policy["lanes"][CHECK]["require_hosted"] = json!([{
        "name":"validate", "workflow_id":42, "workflow_path":".github/workflows/validate.yml"
    }]);
    f.write(".mergemaster/lanes.json", policy.to_string());
    f.base = f.commit("authorize merge-group human policy");
    f.write(
        ".github/workflows/validate.yml",
        "name: validate\n# queue change\n",
    );
    f.refresh_head();
    let hosted = f.root.path().join("hosted.json");
    fs::write(&hosted, approval_evidence(&f).to_string()).unwrap();
    let output = f.root.path().join("approval-output");
    let decision = merge_group_decision(
        &f,
        &merge_group_event(&f),
        &[
            "--hosted-evidence",
            hosted.to_str().unwrap(),
            "--github-output",
            output.to_str().unwrap(),
        ],
    );
    assert_eq!(decision["decision"], "refuse");
    assert_eq!(decision["outcome"], "rejected");
    assert_eq!(decision["reason"], "report_only_queue_parent");
    assert_eq!(
        decision["protected_paths"],
        json!([".github/workflows/validate.yml"])
    );
    let output = fs::read_to_string(output).unwrap();
    assert!(output.contains("skip=false\n"));
    assert!(output.contains("refuse=true\n"));
}

#[test]
fn queue_protected_edits_cannot_be_satisfied_by_human_approval() {
    let mut f = approval_fixture();
    let mut policy: Value =
        serde_json::from_slice(&fs::read(f.repo.join(".mergemaster/lanes.json")).unwrap()).unwrap();
    policy["lanes"][CHECK]["events"] = json!(["queue"]);
    f.write(".mergemaster/lanes.json", policy.to_string());
    f.base = f.commit("authorize queue human policy");
    f.write(
        ".github/workflows/validate.yml",
        "name: validate\n# queue change\n",
    );
    f.refresh_head();
    f.head = f.git(
        &[
            "commit-tree",
            &f.tree,
            "-p",
            &f.base,
            "-p",
            &f.head,
            "-m",
            "queue",
        ],
        b"",
    );
    let hosted = f.root.path().join("hosted.json");
    fs::write(&hosted, approval_evidence(&f).to_string()).unwrap();
    for signed in [false, true] {
        if signed {
            f.note(&f.statement(), &f.key, "tree");
        }
        let output = f.root.path().join(format!("approval-output-{signed}"));
        let d = f.decision(&[
            "--event",
            "queue",
            "--hosted-evidence",
            hosted.to_str().unwrap(),
            "--github-output",
            output.to_str().unwrap(),
        ]);
        assert_eq!(d["decision"], "refuse");
        assert_eq!(d["outcome"], "rejected");
        assert_eq!(d["reason"], "human_approval_only");
        assert_eq!(d["report_only"], true);
        assert!(d["record"].is_null());
        assert_eq!(
            d["protected_paths"],
            json!([".github/workflows/validate.yml"])
        );
        let output = fs::read_to_string(output).unwrap();
        assert!(output.contains(
            "skip=false\nrecord=\noutcome=rejected\nrefuse=true\nrefusal=human_approval_only\n"
        ));
    }
}

fn approval_fixture() -> Fixture {
    let mut f = Fixture::new();
    let mut policy = Fixture::policy("required_evidence");
    let lane = &mut policy["lanes"][CHECK];
    lane["protected_edits"] = json!("human_approval");
    lane["approvers"] = json!(["schickling"]);
    lane["require_hosted"] = json!([{
        "name":"validate", "workflow_id":42, "workflow_path":".github/workflows/validate.yml"
    }]);
    f.write(".mergemaster/lanes.json", policy.to_string());
    f.write(".github/workflows/validate.yml", "name: validate\n");
    f.base = f.commit("base-authorized human policy");
    f.write(
        ".github/workflows/validate.yml",
        "name: validate\n# candidate change\n",
    );
    f.refresh_head();
    f
}

fn approval_evidence(f: &Fixture) -> Value {
    json!({
        "version":1,"repository":"fixture/repo","head":f.head,
        "reviews":[{"id":100,"user":{"login":"schickling"},"state":"APPROVED",
            "commit_id":f.head,"submitted_at":"2026-10-30T12:00:00Z"}],
        "checks":[{"name":"validate","head_sha":f.head,"status":"completed","conclusion":"success",
            "workflow_run":{"id":7,"workflow_id":42,"path":".github/workflows/validate.yml",
                "head_sha":f.head,"event":"pull_request"}}]
    })
}

#[test]
fn missing_base_config_is_a_structured_refusal_even_if_head_supplies_it() {
    for path in [
        ".mergemaster/tool-pin.json",
        ".mergemaster/lanes.json",
        ".mergemaster/environment.json",
        ".mergemaster/evidence-keys",
    ] {
        let mut f = Fixture::new();
        let original = fs::read(f.repo.join(path)).unwrap();
        f.git(&["rm", path], b"");
        f.base = f.commit("base without configuration");
        f.write(path, original);
        f.refresh_head();
        let output = f.root.path().join("outputs");
        let decision = f.decision(&["--github-output", output.to_str().unwrap()]);
        assert_eq!(decision["reason"], "config_missing");
        assert_eq!(decision["decision"], "refuse");
        assert_eq!(decision["outcome"], "rejected");
        assert!(decision["summary"].as_str().unwrap().contains(path));
        assert!(
            fs::read_to_string(output)
                .unwrap()
                .contains("refusal=config_missing\n")
        );
        let error = load(&f.repo, &f.base).unwrap_err();
        assert!(error.is::<mergemaster_evidence::gate::config::MissingConfig>());
    }
}

#[test]
fn native_status_json_and_github_output_are_a_single_contract() {
    // These are the native protocol, NOT the legacy satisfied/tier/policy
    // document consumed by Fractal's ci-evidence-gate.
    let keys = [
        "version",
        "check",
        "base",
        "head",
        "tree",
        "expectation_source",
        "decision",
        "outcome",
        "reason",
        "record",
        "report_only",
        "signer",
        "observed_at",
        "age_seconds",
        "lane_definition_sha256",
        "input_key_equal",
        "compared_record",
        "protected_paths",
        "summary",
    ];
    for mode in ["required_evidence", "optional_fallback"] {
        for case in ["missing", "satisfied", "failed", "wrong_command"] {
            let mut f = Fixture::new();
            f.write(".mergemaster/lanes.json", Fixture::policy(mode).to_string());
            f.base = f.commit("pin status policy");
            f.refresh_head();
            let mut statement = f.statement();
            if case == "failed" {
                statement["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1);
            } else if case == "wrong_command" {
                statement["predicate"]["observed"]["checks"][CHECK]["command"] = json!(["true"]);
            }
            let record = (case != "missing").then(|| f.note(&statement, &f.key, "tree"));
            let output_path = f.root.path().join("github-output");
            fs::write(&output_path, "previous=value\n").unwrap();
            let output = f.gate(&["--github-output", output_path.to_str().unwrap()]);
            // A structured refusal is still a successfully computed decision.
            assert_eq!(output.status.code(), Some(0));
            assert!(output.stderr.is_empty());
            let raw = String::from_utf8(output.stdout).unwrap();
            assert!(raw.ends_with("}\n"));
            assert_eq!(raw.lines().count(), 1);
            let value: Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(value.as_object().unwrap().len(), keys.len());
            let positions: Vec<_> = keys
                .iter()
                .map(|key| raw.find(&format!("\"{key}\":")).unwrap())
                .collect();
            assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
            let satisfied = case == "satisfied";
            let decision = if satisfied {
                "skip"
            } else if mode == "optional_fallback" {
                "run"
            } else {
                "refuse"
            };
            let outcome = if satisfied {
                "satisfied"
            } else if case == "missing" {
                "no_note"
            } else {
                "rejected"
            };
            let reason = match case {
                "missing" => "no_record",
                "failed" => "check_failed",
                "wrong_command" => "wrong_command",
                _ => "satisfied",
            };
            let present = case != "missing";
            let age = &value["age_seconds"];
            assert!(if present {
                age.as_i64().is_some_and(|age| age >= 0)
            } else {
                age.is_null()
            });
            assert_eq!(
                value,
                json!({
                    "version":1, "check":CHECK, "base":f.base, "head":f.head, "tree":f.tree,
                    "expectation_source":"caller", "decision":decision, "outcome":outcome,
                    "reason":reason, "record":record, "report_only":false,
                    "signer":if present { json!(PRINCIPAL) } else { Value::Null },
                    "observed_at":if present { statement["predicate"]["observed_at"].clone() } else { Value::Null },
                    "age_seconds":age,
                    "lane_definition_sha256":if present {
                        statement["predicate"]["observed"]["inputs"]["lane_definition_sha256"].clone()
                    } else { Value::Null },
                    "input_key_equal":null, "compared_record":null, "protected_paths":[], "summary":""
                })
            );
            // Pin names, order, booleans, null-to-empty record conversion,
            // refusal reason, newline termination and append (not overwrite).
            assert_eq!(
                fs::read_to_string(output_path).unwrap(),
                format!(
                    "previous=value\nskip={}\nrecord={}\noutcome={outcome}\nrefuse={}\nrefusal={}\n",
                    satisfied,
                    record.as_deref().unwrap_or(""),
                    decision == "refuse",
                    if decision == "refuse" { reason } else { "" },
                )
            );
        }
    }
}

#[test]
fn invalid_base_config_is_not_misreported_as_missing() {
    for kind in ["json", "directory", "symlink"] {
        let mut f = Fixture::new();
        let path = ".mergemaster/lanes.json";
        f.git(&["rm", path], b"");
        match kind {
            "json" => f.write(path, "{invalid json"),
            "directory" => f.write(&format!("{path}/child"), "not a blob"),
            _ => std::os::unix::fs::symlink("environment.json", f.repo.join(path)).unwrap(),
        }
        f.base = f.commit("invalid base configuration");
        f.refresh_head();
        let error = load(&f.repo, &f.base).unwrap_err();
        assert!(!error.is::<mergemaster_evidence::gate::config::MissingConfig>());
        let output_path = f.root.path().join("github-output");
        fs::write(&output_path, "previous=value\n").unwrap();
        let result = f.gate(&["--github-output", output_path.to_str().unwrap()]);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!result.stderr.is_empty());
        assert_eq!(fs::read_to_string(output_path).unwrap(), "previous=value\n");
    }
}

#[test]
fn read_only_gate_ignores_materialized_dependencies_and_scratch() {
    let f = Fixture::new();
    let before = f.decision(&[]);
    f.write("node_modules/package/bin/postinstall", "must never execute");
    f.write("scratch/observation.json", "not evidence");
    f.write(".gitignore", "node_modules/\nscratch/\n");
    let after = f.decision(&[]);
    assert_eq!(before, after);
    assert_eq!(
        fs::read_to_string(f.repo.join("scratch/observation.json")).unwrap(),
        "not evidence"
    );
}

#[test]
fn protected_human_approval_requires_exact_review_and_workflow_identity() {
    for case in [
        "valid",
        "missing",
        "stale_review",
        "stranger",
        "changes_requested",
        "dismissed",
        "failed",
        "pending",
        "stale_check",
        "stale_run",
        "renamed_workflow",
        "extra_validate",
        "wrong_event",
        "workflow_changed",
    ] {
        let f = approval_fixture();
        let mut evidence = approval_evidence(&f);
        match case {
            "stale_review" => evidence["reviews"][0]["commit_id"] = json!(f.base),
            "stranger" => evidence["reviews"][0]["user"]["login"] = json!("other"),
            "changes_requested" | "dismissed" => {
                let mut review = evidence["reviews"][0].clone();
                review["id"] = json!(101);
                review["state"] = json!(if case == "dismissed" {
                    "DISMISSED"
                } else {
                    "CHANGES_REQUESTED"
                });
                evidence["reviews"].as_array_mut().unwrap().push(review);
            }
            "failed" => evidence["checks"][0]["conclusion"] = json!("failure"),
            "pending" => evidence["checks"][0]["status"] = json!("in_progress"),
            "stale_check" => evidence["checks"][0]["head_sha"] = json!(f.base),
            "stale_run" => evidence["checks"][0]["workflow_run"]["head_sha"] = json!(f.base),
            "renamed_workflow" => {
                evidence["checks"][0]["workflow_run"]["path"] =
                    json!(".github/workflows/renamed.yml")
            }
            // Same display name and same path are insufficient: workflow ID is BASE policy.
            "extra_validate" => evidence["checks"][0]["workflow_run"]["workflow_id"] = json!(43),
            "wrong_event" => {
                evidence["checks"][0]["workflow_run"]["event"] = json!("pull_request_target")
            }
            _ => {}
        }
        let path = f.root.path().join("hosted.json");
        fs::write(&path, evidence.to_string()).unwrap();
        let arguments = ["--hosted-evidence", path.to_str().unwrap()];
        let decision = f.decision(if case == "missing" { &[] } else { &arguments });
        let satisfied = matches!(case, "valid" | "workflow_changed");
        assert_eq!(
            decision["decision"],
            if satisfied { "skip" } else { "refuse" },
            "{case}: {decision}"
        );
        if satisfied {
            assert_eq!(decision["reason"], "human_approval_satisfied");
            assert!(
                decision["record"].is_null(),
                "human policy is not agent evidence"
            );
        }
        assert_eq!(
            decision["summary"],
            "this PR changes the validate workflow; validate ran the changed file"
        );
    }
}

#[test]
fn human_approval_does_not_transfer_to_a_new_push_or_head_policy() {
    let mut f = approval_fixture();
    let mut evidence = approval_evidence(&f);
    f.write("source.txt", "a new push\n");
    f.refresh_head();
    // Publisher has the new head/check, but the approving review is stale.
    evidence["head"] = json!(f.head);
    evidence["checks"][0]["head_sha"] = json!(f.head);
    evidence["checks"][0]["workflow_run"]["head_sha"] = json!(f.head);
    let path = f.root.path().join("hosted.json");
    fs::write(&path, evidence.to_string()).unwrap();
    assert_eq!(
        f.decision(&["--hosted-evidence", path.to_str().unwrap()])["reason"],
        "human_approval_missing"
    );
    // A PR cannot nominate its own approver.
    let mut policy = Fixture::policy("required_evidence");
    policy["lanes"][CHECK]["protected_edits"] = json!("human_approval");
    policy["lanes"][CHECK]["approvers"] = json!(["other"]);
    f.write(".mergemaster/lanes.json", policy.to_string());
    f.refresh_head();
    let mut evidence = approval_evidence(&f);
    evidence["reviews"][0]["user"]["login"] = json!("other");
    fs::write(&path, evidence.to_string()).unwrap();
    assert_eq!(
        f.decision(&["--hosted-evidence", path.to_str().unwrap()])["reason"],
        "human_approval_missing"
    );
}

#[test]
fn malformed_or_misbound_hosted_evidence_never_writes_success() {
    let f = approval_fixture();
    for case in ["repository", "head", "malformed"] {
        let mut evidence = approval_evidence(&f);
        if case == "repository" {
            evidence["repository"] = json!("other/repo");
        }
        if case == "head" {
            evidence["head"] = json!(f.base);
        }
        let path = f.root.path().join("hosted.json");
        fs::write(
            &path,
            if case == "malformed" {
                "{}".into()
            } else {
                evidence.to_string()
            },
        )
        .unwrap();
        let output = f.root.path().join(format!("output-{case}"));
        assert!(
            !f.gate(&[
                "--hosted-evidence",
                path.to_str().unwrap(),
                "--github-output",
                output.to_str().unwrap()
            ])
            .status
            .success()
        );
        assert!(!output.exists());
    }
}

#[test]
fn signed_observations_require_every_lane_binding() {
    for case in [
        "valid",
        "wrong_key",
        "wrong_principal",
        "wrong_level",
        "test_tier",
        "degraded",
        "wrong_argv",
        "failed",
        "wrong_commit",
        "wrong_tree",
        "wrong_check",
        "dirty",
        "untracked",
        "environment",
        "toolchain",
        "definition",
        "system",
        "wrapper",
        "future",
        "corrupt",
    ] {
        let mut f = Fixture::new();
        if case == "wrong_level" {
            let keys = fs::read_to_string(f.key.with_extension("pub")).unwrap();
            f.write(
                ".mergemaster/evidence-keys",
                format!("host/fixture namespaces=\"git\" {keys}"),
            );
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
            "degraded" => {
                statement["predicate"]["tier"] = json!("degraded");
                statement["predicate"]["signer"] = Value::Null;
            }
            "wrong_argv" => {
                statement["predicate"]["observed"]["checks"][CHECK]["command"] = json!(["true"])
            }
            "failed" => statement["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1),
            "wrong_commit" => statement["subject"][0]["name"] = json!(f.base),
            "wrong_tree" => statement["subject"][0]["digest"]["gitTree"] = json!("0".repeat(40)),
            "wrong_check" => {
                let check = statement["predicate"]["observed"]["checks"][CHECK].take();
                statement["predicate"]["observed"]["checks"] = json!({"other":check});
            }
            "dirty" => {
                statement["predicate"]["observed"]["inputs"]["workspace_clean"] = json!("false")
            }
            "untracked" => {
                statement["predicate"]["observed"]["inputs"]["untracked_files"] = json!("true")
            }
            "system" => {
                statement["predicate"]["observed"]["inputs"]["system"] = json!("other-platform")
            }
            "environment" | "toolchain" | "definition" => {
                let field = match case {
                    "environment" => "environment_sha256",
                    "toolchain" => "toolchain_sha256",
                    _ => "lane_definition_sha256",
                };
                statement["predicate"]["observed"]["inputs"][field] = json!("0".repeat(64));
            }
            "wrapper" => {
                statement["predicate"]["observed"]["inputs"]["wrapper_sha256"] = json!("invalid")
            }
            "future" => {
                statement["predicate"]["observed_at"] =
                    json!((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339())
            }
            _ => {}
        }
        if case == "corrupt" {
            f.raw_note(b"{not JSON", key, "tree");
        } else {
            f.note(&statement, key, "tree");
        }
        let decision = f.decision(&[]);
        assert_eq!(
            decision["decision"],
            if case == "valid" { "skip" } else { "refuse" },
            "{case}: {decision}"
        );
        assert_eq!(
            decision["outcome"] == "satisfied",
            case == "valid",
            "{case}: {decision}"
        );
        assert!(
            decision["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()),
            "{case}: {decision}"
        );
    }
}

#[test]
fn oracle_and_gate_agree_on_single_record_selection_bindings() {
    for case in [
        "wrapper",
        "nix",
        "sekrets",
        "github:fixture/repo/actions/runs/1",
        "github:",
        "GitHub:",
        "GITHUB:",
        " github:",
        "\tgithub:fixture/repo",
        "hand-typed",
        "Wrapper",
        "wrong_check",
        "wrong_argv",
        "missing_input",
        "test_tier",
        "wrong_level",
        "wrong_key",
    ] {
        let f = Fixture::new();
        let mut statement = f.statement();
        let inputs = &mut statement["predicate"]["observed"]["inputs"];
        inputs["wrapper_sha256"] = json!(hex::encode(sha2::Sha256::digest(
            b"fixture command, never executed\n"
        )));
        let mut key = &f.key;
        match case {
            "wrong_check" => {
                let check = statement["predicate"]["observed"]["checks"][CHECK].take();
                statement["predicate"]["observed"]["checks"] = json!({"other":check});
            }
            "wrong_argv" => {
                statement["predicate"]["observed"]["checks"][CHECK]["command"] = json!(["true"])
            }
            "missing_input" => {
                inputs.as_object_mut().unwrap().remove("wrapper_sha256");
            }
            "test_tier" => statement["predicate"]["tier"] = json!("test"),
            "wrong_level" => statement["predicate"]["signer"] = json!("host/fixture"),
            "wrong_key" => key = &f.stranger,
            runner => statement["predicate"]["observed"]["runner"] = json!(runner),
        }
        f.note(&statement, key, "tree");
        let expected = matches!(case, "wrapper" | "nix" | "sekrets") || case.starts_with("github:");
        let python = f.python_with(&["--bind-input", "wrapper_sha256=tools/graph"]);
        assert_eq!(
            python.status.success(),
            expected,
            "{case}: {}",
            String::from_utf8_lossy(&python.stdout)
        );
        let decision = f.decision(&[]);
        assert_eq!(
            decision["decision"] == "skip",
            expected,
            "{case}: {decision}"
        );
        if matches!(case, "hand-typed" | "Wrapper") {
            assert_eq!(decision["reason"], "unsupported_kind");
        }
    }
}

#[test]
fn base_keys_and_policy_cannot_be_replaced_by_head() {
    for trusted in [false, true] {
        let mut f = Fixture::new();
        f.write(
            ".mergemaster/evidence-keys",
            format!(
                "{PRINCIPAL} {}",
                fs::read_to_string(f.stranger.with_extension("pub")).unwrap()
            ),
        );
        f.write(
            ".mergemaster/lanes.json",
            Fixture::policy("optional_fallback").to_string(),
        );
        f.refresh_head();
        f.note(
            &f.statement(),
            if trusted { &f.key } else { &f.stranger },
            "tree",
        );
        let decision = f.decision(&[]);
        assert_eq!(decision["decision"], "refuse");
        assert_ne!(decision["outcome"], "satisfied");
        assert_eq!(decision["reason"], "protected_paths");
    }
}

#[test]
fn malformed_base_configuration_is_not_a_computed_decision() {
    for case in [
        "unknown",
        "missing_field",
        "malformed",
        "version",
        "escape",
        "missing_path",
        "unsupported_adapter",
        "bad_environment",
        "bad_pin",
    ] {
        let mut f = Fixture::new();
        let mut policy = Fixture::policy("required_evidence");
        match case {
            "unknown" => policy["unknown"] = json!(true),
            "missing_field" => {
                policy["lanes"][CHECK]
                    .as_object_mut()
                    .unwrap()
                    .remove("argv");
            }
            "malformed" => {}
            "version" => policy["version"] = json!(2),
            "escape" => policy["lanes"][CHECK]["definition_paths"] = json!(["../escape"]),
            "missing_path" => policy["lanes"][CHECK]["environment"]["paths"] = json!(["absent"]),
            "unsupported_adapter" => policy["lanes"][CHECK]["shards"] = json!(2),
            "bad_environment" => f.write(".mergemaster/environment.json", "{}"),
            "bad_pin" => f.write(".mergemaster/tool-pin.json", "{}"),
            _ => unreachable!(),
        }
        f.write(
            ".mergemaster/lanes.json",
            if case == "malformed" {
                "{".to_owned()
            } else {
                policy.to_string()
            },
        );
        f.base = f.commit("invalid base");
        f.refresh_head();
        let output_path = f.root.path().join("outputs");
        let output = f.gate(&["--github-output", output_path.to_str().unwrap()]);
        assert!(
            !output.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            !output_path.exists() || fs::read(&output_path).unwrap().is_empty(),
            "{case}: failure published outputs"
        );
    }
}

#[test]
fn note_layouts_deduplicate_and_never_transfer_to_another_tree() {
    for layout in ["tree", "tag", "legacy"] {
        let mut f = Fixture::new();
        let record = f.note(&f.statement(), &f.key, layout);
        for duplicate in ["tree", "tag", "legacy"] {
            f.publish(&record, duplicate);
        }
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
    for case in [
        "add",
        "edit",
        "delete",
        "rename_out",
        "rename_in",
        "component_boundary",
    ] {
        let mut f = Fixture::new();
        match case {
            "add" => f.write(".github/actions/new/action.yml", "new\n"),
            "edit" => f.write(".github/workflows/evidence.yml", "changed\n"),
            "delete" => fs::remove_file(f.repo.join(".github/workflows/evidence.yml")).unwrap(),
            "rename_out" => {
                fs::rename(
                    f.repo.join(".github/workflows/evidence.yml"),
                    f.repo.join("workflow.yml"),
                )
                .unwrap();
            }
            "rename_in" => {
                fs::rename(
                    f.repo.join("source.txt"),
                    f.repo.join(".github/workflows/source.yml"),
                )
                .unwrap();
                f.write("source.txt", "replacement\n");
            }
            "component_boundary" => f.write(
                ".github/workflows-extra/file",
                "not a protected component\n",
            ),
            _ => unreachable!(),
        }
        f.refresh_head();
        f.note(&f.statement(), &f.key, "tree");
        let decision = f.decision(&[]);
        assert_eq!(
            decision["decision"],
            if case == "component_boundary" {
                "skip"
            } else {
                "refuse"
            },
            "{case}: {decision}"
        );
        if case != "component_boundary" {
            assert_eq!(decision["reason"], "protected_paths", "{case}: {decision}");
        }
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
    for field in ["skip=false", "refuse=true", "outcome=no_note", "refusal="] {
        assert!(text.contains(field), "{text}");
    }
    fs::remove_file(&outputs).unwrap();
    let record = f.note(&f.statement(), &f.key, "tree");
    let satisfied = f.decision(&["--github-output", outputs.to_str().unwrap()]);
    assert_eq!(satisfied["decision"], "skip");
    let text = fs::read_to_string(outputs).unwrap();
    for field in [
        "skip=true",
        "refuse=false",
        "outcome=satisfied",
        &format!("record={record}"),
    ] {
        assert!(text.contains(field), "{text}");
    }
    let usage = f
        .command(env!("CARGO_BIN_EXE_mergemaster"))
        .args(["gate", "--check", CHECK])
        .output()
        .unwrap();
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
        if failed {
            assert_eq!(reference["reason"], "check_failed");
            assert_eq!(rust["reason"], "check_failed");
        } else {
            assert_eq!(reference["record"], record);
            assert_eq!(rust["record"], record);
        }
    }
}

#[test]
fn optional_fallback_runs_instead_of_refusing_missing_or_failed_evidence() {
    let mut f = Fixture::new();
    f.write(
        ".mergemaster/lanes.json",
        Fixture::policy("optional_fallback").to_string(),
    );
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
        assert_eq!(
            decision["decision"],
            if case == "valid" { "skip" } else { "refuse" },
            "{case}: {decision}"
        );
        if case != "valid" {
            assert_eq!(decision["reason"], "ineligible_event");
        }
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
        let failure_id = f.note(&failure, &f.key, "tree");
        let mut pass = f.statement();
        pass["predicate"]["observed_at"] =
            json!((failed_at + chrono::Duration::seconds(seconds_after_failure)).to_rfc3339());
        let pass_id = f.note(&pass, &f.key, "tree");
        // Aliases must not create additional attempts or change the deciding record.
        f.publish(&failure_id, "legacy");
        f.publish(&pass_id, "tag");
        let decision = f.decision(&[]);
        assert_eq!(
            decision["decision"],
            if seconds_after_failure > 120 {
                "skip"
            } else {
                "refuse"
            },
            "{decision}"
        );
        let reference = f.python();
        assert_eq!(reference.status.success(), seconds_after_failure > 120);
        let oracle: Value = serde_json::from_slice(&reference.stdout).unwrap();
        let deciding = if seconds_after_failure > 120 {
            pass_id
        } else {
            failure_id
        };
        assert_eq!(decision["record"], deciding);
        assert_eq!(oracle["decided_by"], deciding);
        assert_eq!(oracle["attempts"], 2);
    }
}

#[test]
fn newer_invalid_pass_is_not_replaced_by_older_evidence() {
    for mode in ["required_evidence", "optional_fallback"] {
        for case in ["argv", "input", "kind", "tier", "future", "age"] {
            let mut f = Fixture::new();
            let mut policy = Fixture::policy(mode);
            policy["lanes"][CHECK]["max_age_seconds"] = json!(3600);
            f.write(".mergemaster/lanes.json", policy.to_string());
            f.base = f.commit("age and fallback policy");
            f.refresh_head();
            let mut older = f.statement();
            older["predicate"]["observed_at"] = json!(
                (chrono::Utc::now()
                    - chrono::Duration::seconds(if case == "age" { 7200 } else { 600 }))
                .to_rfc3339()
            );
            older["predicate"]["observed"]["inputs"]["wrapper_sha256"] = json!(hex::encode(
                sha2::Sha256::digest(b"fixture command, never executed\n")
            ));
            f.note(&older, &f.key, "tree");
            let mut newer = older.clone();
            newer["predicate"]["observed_at"] = json!(
                (chrono::Utc::now()
                    - chrono::Duration::seconds(if case == "age" { 7000 } else { 300 }))
                .to_rfc3339()
            );
            match case {
                "argv" => {
                    newer["predicate"]["observed"]["checks"][CHECK]["command"] = json!(["true"])
                }
                "input" => {
                    newer["predicate"]["observed"]["inputs"]
                        .as_object_mut()
                        .unwrap()
                        .remove("wrapper_sha256");
                }
                "kind" => newer["predicate"]["observed"]["runner"] = json!("unsupported"),
                "tier" => newer["predicate"]["tier"] = json!("test"),
                "future" => {
                    newer["predicate"]["observed_at"] =
                        json!((chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339())
                }
                _ => {}
            }
            let record = f.note(&newer, &f.key, "tree");
            f.publish(&record, "tag");
            let decision = f.decision(&[]);
            let python = f.python_with(&[
                "--max-age",
                "3600",
                "--bind-input",
                "wrapper_sha256=tools/graph",
            ]);
            assert!(!python.status.success(), "{mode}/{case}");
            let oracle: Value = serde_json::from_slice(&python.stdout).unwrap();
            assert_eq!(
                decision["decision"],
                if mode == "optional_fallback" {
                    "run"
                } else {
                    "refuse"
                },
                "{mode}/{case}: {decision}"
            );
            assert_eq!(decision["record"], record, "{mode}/{case}");
            assert_eq!(oracle["decided_by"], record, "{mode}/{case}: {oracle}");
            assert_eq!(oracle["attempts"], 2);
        }
    }
}

#[test]
fn age_and_future_margins_match_oracle() {
    for (offset, accepted) in [(-90, false), (-30, true), (90, true), (150, false)] {
        let mut f = Fixture::new();
        let mut policy = Fixture::policy("required_evidence");
        policy["lanes"][CHECK]["max_age_seconds"] = json!(60);
        f.write(".mergemaster/lanes.json", policy.to_string());
        f.base = f.commit("age-limited policy");
        f.refresh_head();
        let mut statement = f.statement();
        statement["predicate"]["observed_at"] =
            json!((chrono::Utc::now() + chrono::Duration::seconds(offset)).to_rfc3339());
        let record = f.note(&statement, &f.key, "tree");
        let python = f.python_with(&["--max-age", "60"]);
        assert_eq!(python.status.success(), accepted, "offset={offset}");
        let oracle: Value = serde_json::from_slice(&python.stdout).unwrap();
        let decision = f.decision(&[]);
        assert_eq!(
            decision["decision"] == "skip",
            accepted,
            "{offset}: {decision}"
        );
        assert_eq!(decision["record"], record);
        assert_eq!(oracle["decided_by"], record);
        if !accepted {
            assert_eq!(
                decision["reason"],
                if offset < 0 {
                    "too_old"
                } else {
                    "future_dated"
                }
            );
        }
    }
}

#[test]
fn oracle_fixed_clock_matches_exact_age_boundary_contract() {
    for (stamp, expected) in [
        ("2030-01-01T00:00:00Z", "satisfied"),
        ("2029-12-31T23:59:59.999999Z", "too_old"),
        ("2030-01-01T00:00:00.000001Z", "satisfied"),
    ] {
        let f = Fixture::new();
        let mut statement = f.statement();
        statement["predicate"]["observed_at"] = json!(stamp);
        let record = f.note(&statement, &f.key, "tree");
        let oracle = f.oracle_selection_with(
            statement["predicate"]["observed"]["inputs"]["lane_definition_sha256"]
                .as_str()
                .unwrap(),
            Some(60),
            false,
            Some("2030-01-01T00:01:00Z"),
        );
        assert_eq!(oracle["reason"], expected);
        assert_eq!(oracle["decided_by"], record);
    }
}

#[test]
fn tiers_vetoes_and_compound_inputs_have_explicit_oracle_contracts() {
    use mergemaster_evidence::evidence::{Statement, record_degraded};
    for mode in ["required_evidence", "optional_fallback"] {
        for case in [
            "degraded_pass",
            "test_tier",
            "host_failure",
            "old_failure",
            "degraded_veto",
            "degraded_fallback",
            "definition_input",
            "equal_level",
            "equal_definition",
        ] {
            let mut f = Fixture::new();
            let mut policy = Fixture::policy(mode);
            policy["lanes"][CHECK]["max_age_seconds"] = json!(60);
            f.write(".mergemaster/lanes.json", policy.to_string());
            let public = fs::read_to_string(f.key.with_extension("pub")).unwrap();
            let host_public = fs::read_to_string(f.stranger.with_extension("pub")).unwrap();
            f.write(
                ".mergemaster/evidence-keys",
                format!("{PRINCIPAL} namespaces=\"git\" {public}\nhost/fixture namespaces=\"git\" {host_public}"),
            );
            f.base = f.commit("authorize host but accept agent only");
            f.refresh_head();
            let now = chrono::Utc::now();
            let mut older = f.statement();
            older["predicate"]["observed_at"] =
                json!((now - chrono::Duration::seconds(30)).to_rfc3339());
            older["predicate"]["observed"]["inputs"]["wrapper_sha256"] = json!(hex::encode(
                sha2::Sha256::digest(b"fixture command, never executed\n")
            ));
            let definition = older["predicate"]["observed"]["inputs"]["lane_definition_sha256"]
                .as_str()
                .unwrap()
                .to_owned();
            let mut newer = older.clone();
            if case == "degraded_fallback" {
                older["predicate"]["observed"]["checks"][CHECK]["command"] = json!(["true"]);
            }
            let older_id = f.note(&older, &f.key, "tree");
            newer["predicate"]["observed_at"] = json!(
                (now - chrono::Duration::seconds(if case == "old_failure" {
                    90
                } else if case.starts_with("equal_") {
                    30
                } else {
                    20
                }))
                .to_rfc3339()
            );
            if case.starts_with("degraded_") {
                newer["predicate"]["tier"] = json!("degraded");
                newer["predicate"]["signer"] = Value::Null;
            }
            if case == "test_tier" {
                newer["predicate"]["tier"] = json!("test");
            }
            if matches!(case, "host_failure" | "equal_level") {
                newer["predicate"]["signer"] = json!("host/fixture");
            }
            if matches!(
                case,
                "host_failure" | "old_failure" | "degraded_veto" | "degraded_fallback"
            ) {
                newer["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1);
            }
            if matches!(case, "definition_input" | "equal_definition") {
                newer["predicate"]["observed"]["inputs"]["lane_definition_sha256"] =
                    json!("0".repeat(64));
            }
            if case == "definition_input" {
                newer["predicate"]["observed"]["inputs"]
                    .as_object_mut()
                    .unwrap()
                    .remove("wrapper_sha256");
            }
            let newer_id = if case.starts_with("degraded_") {
                let statement: Statement = serde_json::from_value(newer).unwrap();
                let id = record_degraded(&f.repo, &statement).unwrap();
                f.publish(&id, "tree");
                id
            } else {
                f.note(
                    &newer,
                    if matches!(case, "host_failure" | "equal_level") {
                        &f.stranger
                    } else {
                        &f.key
                    },
                    "tree",
                )
            };
            if case == "equal_level" {
                f.git(
                    &[
                        "update-ref",
                        "-d",
                        &format!("refs/notes/evidence/{}/{older_id}", f.tree),
                    ],
                    b"",
                );
                let alone = f.decision(&[]);
                assert_eq!(alone["reason"], "untrusted_level");
                assert_eq!(alone["record"], newer_id);
                f.publish(&older_id, "tree");
            }
            let oracle = f.oracle_selection_with(&definition, Some(60), true, None);
            let decision = f.decision(&[]);
            if case == "definition_input" {
                // P3: Python skips before bound-input validation; Rust stays conservative.
                assert_eq!(oracle["reason"], "satisfied");
                assert_eq!(oracle["decided_by"], older_id);
                assert_eq!(decision["reason"], "wrong_input");
                assert_eq!(decision["record"], newer_id);
                assert_eq!(
                    decision["decision"],
                    if mode == "optional_fallback" {
                        "run"
                    } else {
                        "refuse"
                    }
                );
            } else {
                assert_eq!(
                    decision["reason"], oracle["reason"],
                    "{mode}/{case}: {decision} / {oracle}"
                );
                assert_eq!(decision["record"], oracle["decided_by"], "{mode}/{case}");
                assert_eq!(decision["decision"] == "skip", oracle["satisfied"] == true);
                if matches!(case, "host_failure" | "old_failure") {
                    assert_eq!(
                        decision["reason"], "check_failed",
                        "{mode}/{case}: {decision} / {oracle}"
                    );
                }
            }
        }
    }
}

#[test]
fn equal_time_passes_follow_oracle_discovery_order() {
    for pass_over in [false, true] {
        for invalid_lower in [false, true] {
            for prioritize_higher_tag in [false, true] {
                let f = Fixture::new();
                let mut valid = f.statement();
                valid["predicate"]["observed_at"] =
                    json!((chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339());
                let mut invalid = valid.clone();
                invalid["predicate"]["observed"]["checks"][CHECK]["command"] = json!(["true"]);
                // Search both sides instead of bracketing one potentially extreme ID.
                // Disjoint 16-record ranges have probability 2 / binomial(32, 16).
                let records = |statement: &mut Value| {
                    (0..16)
                        .map(|nonce| {
                            statement["predicate"]["change_id"] = json!(format!("tie-{nonce}"));
                            f.note(statement, &f.key, "tree")
                        })
                        .collect::<Vec<_>>()
                };
                let valid_ids = records(&mut valid);
                let invalid_ids = records(&mut invalid);
                let valid_min = valid_ids.iter().min().unwrap();
                let valid_max = valid_ids.iter().max().unwrap();
                let invalid_min = invalid_ids.iter().min().unwrap();
                let invalid_max = invalid_ids.iter().max().unwrap();
                assert!(invalid_min < valid_max, "need a lower-ID invalid record");
                assert!(valid_min < invalid_max, "need a higher-ID invalid record");
                let (valid_id, invalid_id) = if invalid_lower {
                    (valid_max, invalid_min)
                } else {
                    (valid_min, invalid_max)
                };
                assert_eq!(invalid_id < valid_id, invalid_lower);
                for id in valid_ids.iter().chain(&invalid_ids) {
                    if id != valid_id && id != invalid_id {
                        f.git(
                            &[
                                "update-ref",
                                "-d",
                                &format!("refs/notes/evidence/{}/{id}", f.tree),
                            ],
                            b"",
                        );
                    }
                }
                let lower = if invalid_lower { invalid_id } else { valid_id };
                let higher = if invalid_lower { valid_id } else { invalid_id };
                if prioritize_higher_tag {
                    f.publish(higher, "tag");
                }
                if pass_over {
                    let mut newer = f.statement();
                    newer["predicate"]["observed"]["inputs"]["lane_definition_sha256"] =
                        json!("0".repeat(64));
                    f.note(&newer, &f.key, "tree");
                }
                let definition = valid["predicate"]["observed"]["inputs"]["lane_definition_sha256"]
                    .as_str()
                    .unwrap();
                let oracle = f.oracle_selection(definition);
                let decision = f.decision(&[]);
                let expected = if prioritize_higher_tag { higher } else { lower };
                assert_eq!(oracle["decided_by"], *expected);
                assert_eq!(
                    oracle["reason"],
                    if expected == valid_id {
                        "satisfied"
                    } else {
                        "wrong_command"
                    }
                );
                assert_eq!(decision["record"], oracle["decided_by"]);
                assert_eq!(decision["reason"], oracle["reason"]);
                assert_eq!(decision["decision"] == "skip", oracle["satisfied"] == true);
            }
        }
    }
}

#[test]
fn nonpush_newest_valid_pass_matches_oracle() {
    for mode in ["required_evidence", "optional_fallback"] {
        for case in [
            "level",
            "definition",
            "definition+argv",
            "invalid+failure",
            "no_valid",
            "tie",
        ] {
            for failure_offset in [None, Some(-121), Some(-120), Some(1)] {
                let mut f = Fixture::new();
                f.write(".mergemaster/lanes.json", Fixture::policy(mode).to_string());
                let public = fs::read_to_string(f.key.with_extension("pub")).unwrap();
                let host_public = fs::read_to_string(f.stranger.with_extension("pub")).unwrap();
                f.write(
                    ".mergemaster/evidence-keys",
                    format!("{PRINCIPAL} namespaces=\"git\" {public}\nhost/fixture namespaces=\"git\" {host_public}"),
                );
                f.base = f.commit("authorize both levels, accept agent only");
                f.refresh_head();
                let note = |statement: &Value| {
                    f.note(
                        statement,
                        if statement["predicate"]["signer"] == "host/fixture" {
                            &f.stranger
                        } else {
                            &f.key
                        },
                        "tree",
                    )
                };
                let now = chrono::Utc::now() - chrono::Duration::minutes(10);
                let mut older = f.statement();
                older["predicate"]["observed_at"] = json!(now.to_rfc3339());
                let definition = older["predicate"]["observed"]["inputs"]["lane_definition_sha256"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                if case == "no_valid" {
                    older["predicate"]["signer"] = json!("host/fixture");
                }
                let older_id = note(&older);
                let mut newer = f.statement();
                newer["predicate"]["observed_at"] =
                    json!((now + chrono::Duration::seconds(300)).to_rfc3339());
                match case {
                    "level" | "no_valid" => newer["predicate"]["signer"] = json!("host/fixture"),
                    "definition" | "definition+argv" => {
                        newer["predicate"]["observed"]["inputs"]["lane_definition_sha256"] =
                            json!("0".repeat(64))
                    }
                    _ => {}
                }
                if matches!(case, "definition+argv" | "invalid+failure") {
                    newer["predicate"]["observed"]["checks"][CHECK]["command"] = json!(["true"]);
                }
                let newer_id = note(&newer);
                if case == "level" {
                    f.git(
                        &[
                            "update-ref",
                            "-d",
                            &format!("refs/notes/evidence/{}/{older_id}", f.tree),
                        ],
                        b"",
                    );
                    let alone = f.decision(&[]);
                    assert_eq!(alone["reason"], "untrusted_level");
                    assert_eq!(alone["record"], newer_id);
                    let oracle_alone = f.oracle_selection(&definition);
                    assert_eq!(oracle_alone["reason"], "untrusted_level");
                    assert_eq!(oracle_alone["decided_by"], newer_id);
                    f.publish(&older_id, "tree");
                }
                let offset = if matches!(case, "invalid+failure" | "tie") {
                    Some(300)
                } else {
                    failure_offset
                };
                if let Some(offset) = offset {
                    let mut failure = older.clone();
                    failure["predicate"]["observed_at"] =
                        json!((now + chrono::Duration::seconds(offset)).to_rfc3339());
                    failure["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1);
                    note(&failure);
                }
                let oracle = f.oracle_selection(&definition);
                if case == "level" {
                    assert_eq!(oracle["skipped_newer"].as_array().unwrap().len(), 1);
                }
                if case == "no_valid" {
                    assert_eq!(oracle["reason"], "untrusted_level");
                }
                let decision = f.decision(&[]);
                assert_eq!(
                    decision["reason"], oracle["reason"],
                    "{case}/{offset:?}: {decision} / {oracle}"
                );
                assert_eq!(
                    decision["record"], oracle["decided_by"],
                    "{case}/{offset:?}: {decision} / {oracle}"
                );
                assert_eq!(decision["decision"] == "skip", oracle["satisfied"] == true);
                if case == "invalid+failure" {
                    // Main also runs/refuses; only check_failed/failure diagnostics change.
                    assert_eq!(
                        decision["decision"],
                        if mode == "optional_fallback" {
                            "run"
                        } else {
                            "refuse"
                        }
                    );
                    assert_eq!(decision["reason"], "wrong_command");
                    assert_eq!(decision["record"], newer_id);
                }
            }
        }
    }
}

#[test]
fn push_retains_newest_pass_and_failure_precedence() {
    let f = push_fixture(false);
    let mut older = f.statement();
    older["predicate"]["observed_at"] =
        json!((chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339());
    f.note(&older, &f.key, "tree");
    let mut newer = f.statement();
    newer["predicate"]["observed"]["inputs"]["lane_definition_sha256"] = json!("0".repeat(64));
    let record = f.note(&newer, &f.key, "tree");
    let decision = f.push("refs/heads/main", &f.head, &f.head);
    assert_eq!(decision["decision"], "refuse");
    assert_eq!(decision["reason"], "wrong_input");
    assert_eq!(decision["record"], record);
    newer["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1);
    let failure = f.note(&newer, &f.key, "tree");
    let decision = f.push("refs/heads/main", &f.head, &f.head);
    assert_eq!(decision["decision"], "refuse");
    assert_eq!(decision["reason"], "check_failed");
    assert_eq!(decision["record"], failure);
}

#[test]
fn record_ref_names_must_match_the_immutable_signed_object() {
    let f = Fixture::new();
    let record = f.note(&f.statement(), &f.key, "tree");
    f.git(
        &[
            "update-ref",
            "-d",
            &format!("refs/notes/evidence/{}/{record}", f.tree),
        ],
        b"",
    );
    f.git(
        &[
            "update-ref",
            &format!("refs/notes/evidence/{}/{}", f.tree, "0".repeat(40)),
            &record,
        ],
        b"",
    );
    let decision = f.decision(&[]);
    assert_eq!(decision["decision"], "refuse");
    assert_eq!(decision["reason"], "invalid_record");
    assert!(!f.python().status.success());
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
    statement["predicate"]["observed_at"] =
        json!((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
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
            .find(|path| {
                fs::metadata(path).is_ok_and(|metadata| {
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                })
            })
            .unwrap_or_else(|| panic!("a real {program} must be available"));
        tool_dirs.insert(executable.parent().unwrap().to_path_buf());
    }
    let signer_path = std::env::join_paths(tool_dirs).unwrap();
    fs::write(
        config_dir.join("evidence-sign.json"),
        json!({
            "signer":PRINCIPAL,"ssh_key":f.key,
            "scratch_repo":f.root.path().join("signer.git"),
            "path":signer_path.to_str().unwrap()
        })
        .to_string(),
    )
    .unwrap();
    let statement = f.statement();
    let mut inputs = statement["predicate"]["observed"]["inputs"].clone();
    inputs["flake_lock_sha256"] = json!(hex::encode(Sha256::digest(lock)));
    let request = json!({
        "commit":f.head,"check":CHECK,"command":["tools/graph","check","--full"],
        "exit_code":0,"output_sha256":"b".repeat(64),"change_id":"python-produced",
        "inputs":inputs
    });
    let script = PathBuf::from(
        std::env::var_os("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must be set; run tests in nix develop"),
    )
    .join("scripts/evidence-sign");
    let mut signer = f
        .command("python3")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    signer
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = signer.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "moved signer: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["commit"], f.head);
    assert_eq!(response["tree"], f.tree);
    let pack = base64::engine::general_purpose::STANDARD
        .decode(response["object_pack_base64"].as_str().unwrap())
        .unwrap();
    f.git(&["unpack-objects", "-q"], &pack);
    let record = response["record"].as_str().unwrap();
    f.publish(record, "tree");
    let decision = f.decision(&[]);
    assert_eq!(decision["decision"], "skip", "{decision}");
    assert_eq!(decision["record"], record);
    let python = f.python();
    assert!(
        python.status.success(),
        "{}",
        String::from_utf8_lossy(&python.stdout)
    );
    let reference: Value = serde_json::from_slice(&python.stdout).unwrap();
    assert_eq!(reference["record"], record);
}

#[test]
fn protected_aliases_and_symlink_replacements_never_skip() {
    for path in [
        ".MERGEMASTER/new",
        ".GitHub/Workflows/new.yml",
        ".github/ｗｏｒｋｆｌｏｗｓ/new.yml",
        "．mergemaster/new",
        ".github/actions/new",
    ] {
        let mut f = Fixture::new();
        f.write(path, "protected alias\n");
        f.refresh_head();
        f.note(&f.statement(), &f.key, "tree");
        assert_eq!(f.decision(&[])["reason"], "protected_paths", "{path}");
    }
    for path in [".github/workflows/evidence.yml", ".github", ".mergemaster"] {
        let mut f = Fixture::new();
        let target = f.repo.join(path);
        if target.is_dir() {
            fs::remove_dir_all(&target).unwrap();
        } else {
            fs::remove_file(&target).unwrap();
        }
        std::os::unix::fs::symlink("outside", target).unwrap();
        f.refresh_head();
        // Trust still comes from BASE even when HEAD replaces the entire root.
        assert_eq!(f.decision(&[])["reason"], "protected_paths", "{path}");
    }
}

#[test]
fn foreign_merges_anywhere_in_candidate_history_refuse() {
    for (at_tip, octopus) in [(true, false), (false, false), (true, true)] {
        let mut f = Fixture::new();
        let side = f.git(&["commit-tree", &f.tree, "-p", &f.base, "-m", "side"], b"");
        let mut parents = vec!["commit-tree", &f.tree, "-p", &f.head];
        if octopus {
            parents.extend(["-p", &f.base]);
        }
        parents.extend(["-p", &side, "-m", "merge"]);
        let merge = f.git(&parents, b"");
        f.git(&["update-ref", "HEAD", &merge], b"");
        f.head = merge;
        if !at_tip {
            f.refresh_head();
        }
        f.note(&f.statement(), &f.key, "tree");
        assert_eq!(f.decision(&[])["reason"], "foreign_merge");
    }
}

#[test]
fn optional_fallback_foreign_merge_refuses_and_lists_protected_edits() {
    for protected in [false, true] {
        let mut f = Fixture::new();
        f.write(
            ".mergemaster/lanes.json",
            Fixture::policy("optional_fallback").to_string(),
        );
        f.base = f.commit("optional base policy");
        if protected {
            f.write(".github/workflows/evidence.yml", "name: changed\n");
        }
        f.refresh_head();
        let side = f.git(&["commit-tree", &f.tree, "-p", &f.base, "-m", "side"], b"");
        let merge = f.git(
            &[
                "commit-tree",
                &f.tree,
                "-p",
                &f.head,
                "-p",
                &side,
                "-m",
                "merge",
            ],
            b"",
        );
        f.git(&["update-ref", "HEAD", &merge], b"");
        f.head = merge;
        let decision = f.decision(&[]);
        assert_eq!(decision["decision"], "refuse");
        assert_eq!(decision["reason"], "foreign_merge");
        assert_eq!(
            decision["protected_paths"],
            if protected {
                json!([".github/workflows/evidence.yml"])
            } else {
                json!([])
            }
        );
        let output = f.root.path().join("github-output");
        f.decision(&["--github-output", output.to_str().unwrap()]);
        assert!(
            fs::read_to_string(output)
                .unwrap()
                .contains("refuse=true\n")
        );
    }
}

#[test]
fn live_github_recheck_precedes_all_decision_outputs() {
    for outcome in ["skip", "no_note", "protected"] {
        for moved in [
            "head",
            "base",
            "/head/repo/full_name",
            "/base/repo/full_name",
            "/base/ref",
            "unavailable",
            "unchanged",
        ] {
            let mut f = Fixture::new();
            if outcome == "protected" {
                f.write(".github/actions/new", "changed");
                f.refresh_head();
            }
            if outcome == "skip" {
                f.note(&f.statement(), &f.key, "tree");
            }
            f.live_api(
                if moved == "head" { &f.base } else { &f.head },
                if moved == "base" { &f.head } else { &f.base },
            );
            if moved == "unavailable" {
                fs::remove_file(f.root.path().join("live-pull")).unwrap();
            }
            if moved.starts_with('/') {
                let path = f.root.path().join("live-pull");
                let mut pull: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                *pull.pointer_mut(moved).unwrap() = json!("changed");
                fs::write(path, pull.to_string()).unwrap();
            }
            let event = f.root.path().join("event.json");
            fs::write(
                &event,
                json!({"number":1, "repository":{"full_name":"fixture/repo"},
                    "pull_request":{"head":{"sha":f.head,"repo":{"full_name":"fixture/repo"}},
                        "base":{"sha":f.base,"ref":"main","repo":{"full_name":"fixture/repo"}}}
                })
                .to_string(),
            )
            .unwrap();
            let outputs = f.root.path().join("outputs");
            let result = f.gate(&[
                "--event-file",
                event.to_str().unwrap(),
                "--github-output",
                outputs.to_str().unwrap(),
            ]);
            assert_eq!(
                result.status.code(),
                Some(if moved == "unavailable" { 1 } else { 0 }),
                "{outcome}/{moved}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            if moved == "unavailable" {
                assert!(result.stdout.is_empty());
                assert!(!outputs.exists() || fs::read(outputs).unwrap().is_empty());
            } else if moved != "unchanged" {
                let value: Value = serde_json::from_slice(&result.stdout).unwrap();
                let (reason, summary) = match moved {
                    "head" => (
                        "stale_head",
                        format!("live head tip moved: event {} live {}", f.head, f.base),
                    ),
                    "base" => (
                        "stale_base",
                        format!("live base tip moved: event {} live {}", f.base, f.head),
                    ),
                    field => (
                        "pr_metadata_changed",
                        format!(
                            "live PR {field} changed: event {} live changed; head event {} live {}; base event {} live {}",
                            if field == "/base/ref" {
                                "main"
                            } else {
                                "fixture/repo"
                            },
                            f.head,
                            f.head,
                            f.base,
                            f.base
                        ),
                    ),
                };
                assert_eq!(value["decision"], "refuse");
                assert_eq!(value["outcome"], "rejected");
                assert_eq!(value["reason"], reason);
                assert!(value["record"].is_null());
                assert_eq!(value["summary"], summary);
                let outputs = fs::read_to_string(outputs).unwrap();
                assert!(outputs.contains("skip=false\nrecord=\noutcome=rejected\nrefuse=true\n"));
                assert!(outputs.contains(&format!("refusal={reason}\n")));
            }
            assert!(
                f.root.path().join("api-calls").exists(),
                "{outcome}/{moved}: no live recheck"
            );
        }
    }
}

#[test]
fn concurrent_local_head_and_base_movements_cannot_publish_decisions() {
    use std::os::unix::fs::PermissionsExt;
    for evidence in [false, true] {
        for reference in ["HEAD", "refs/heads/gate-base"] {
            let f = Fixture::new();
            if evidence {
                f.note(&f.statement(), &f.key, "tree");
            }
            // A Git interposer moves a real ref at evidence discovery, after the
            // initial snapshot. No sleeps or scheduler-dependent timing.
            let real_git = f
                .command("sh")
                .args(["-c", "command -v git"])
                .output()
                .unwrap();
            let real_git = String::from_utf8(real_git.stdout)
                .unwrap()
                .trim()
                .to_owned();
            let bin = f.root.path().join("bin");
            fs::create_dir_all(&bin).unwrap();
            let script = bin.join("git");
            fs::write(
                &script,
                format!(
                    r#"#!{python}
import subprocess, sys
git = {real_git:?}
args = sys.argv[1:]
if "refs/notes/evidence/" in args:
    subprocess.run([git, "-C", {repo:?}, "update-ref", {reference:?}, {replacement:?}], check=True)
raise SystemExit(subprocess.run([git] + args).returncode)
"#,
                    python = python_executable(),
                    repo = f.repo.to_str().unwrap(),
                    replacement = if reference == "HEAD" {
                        &f.base
                    } else {
                        &f.head
                    }
                ),
            )
            .unwrap();
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
        let result = f
            .command(env!("CARGO_BIN_EXE_mergemaster"))
            .args([
                "gate",
                "--check",
                CHECK,
                "--base",
                &f.base,
                "--head",
                &f.head,
                "--format",
                "json",
                "--github-output",
                outputs.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!outputs.exists() || fs::read(outputs).unwrap().is_empty());
    }
}

fn push_fixture(merge: bool) -> Fixture {
    let mut f = Fixture::new();
    f.git(&["checkout", "-q", "--detach", &f.base], b"");
    let mut policy = Fixture::policy("required_evidence");
    policy["lanes"][CHECK]["events"] = json!(["pull_request", "push"]);
    f.write(".mergemaster/lanes.json", policy.to_string());
    f.base = f.commit("accepted push policy");
    f.write("source.txt", "candidate\n");
    f.refresh_head();
    f.note(&f.statement(), &f.key, "tree");
    let mut args = vec!["commit-tree", &f.tree, "-p", &f.base];
    if merge {
        args.extend(["-p", &f.head]);
    }
    let main = f.git(&args, b"main integration\n");
    f.head = main;
    f.git(&["checkout", "-q", "--detach", &f.head], b"");
    f
}

#[test]
fn push_reuses_signed_tree_for_squash_and_merge_but_pr_default_is_unchanged() {
    for merge in [false, true] {
        let f = push_fixture(merge);
        let pr = f.decision(&[]);
        assert_eq!(
            pr["reason"],
            if merge {
                "foreign_merge"
            } else {
                "wrong_commit"
            }
        );
        assert_ne!(pr["decision"], "skip");
        let push = f.push("refs/heads/main", &f.head, &f.head);
        assert_eq!(push["decision"], "skip", "{push}");
        assert_eq!(push["outcome"], "satisfied");
    }
}

#[test]
fn push_refuses_tree_mismatch_and_protected_policy_edits() {
    for protected in [false, true] {
        let mut f = push_fixture(false);
        if protected {
            let policy = f.git(&["show", "HEAD:.mergemaster/lanes.json"], b"");
            f.write(".mergemaster/lanes.json", format!("{policy}\n"));
        } else {
            f.write("source.txt", "different tree\n");
        }
        f.git(&["add", "-A"], b"");
        f.tree = f.git(&["write-tree"], b"");
        f.head = f.git(
            &["commit-tree", &f.tree, "-p", &f.base],
            b"changed integration\n",
        );
        f.git(&["checkout", "-q", "--detach", &f.head], b"");
        let value = f.push("refs/heads/main", &f.head, &f.head);
        assert_eq!(value["decision"], "refuse", "{value}");
        assert_eq!(
            value["reason"],
            if protected {
                "protected_paths"
            } else {
                "tree_mismatch"
            }
        );
    }
}

#[test]
fn push_requires_opt_in_default_branch_and_current_live_sha() {
    let f = Fixture::new();
    f.note(&f.statement(), &f.key, "tree");
    assert_eq!(
        f.push("refs/heads/main", &f.head, &f.head)["reason"],
        "event_not_allowed"
    );
    let f = push_fixture(false);
    for (reference, after, live, reason) in [
        ("refs/heads/topic", &f.head, &f.head, "not_default_branch"),
        ("refs/heads/main", &f.base, &f.head, "stale_push"),
        ("refs/heads/main", &f.head, &f.base, "stale_push"),
    ] {
        let value = f.push(reference, after, live);
        assert_eq!(value["decision"], "refuse", "{value}");
        assert_eq!(value["reason"], reason);
    }
}

#[test]
fn push_requires_a_first_parent_and_exact_parent_base() {
    let mut f = push_fixture(false);
    let parent = f.base.clone();
    f.base = f.head.clone();
    assert_eq!(
        f.push("refs/heads/main", &f.head, &f.head)["reason"],
        "base_not_parent"
    );
    f.base = parent;
    let root = f.git(&["rev-list", "--max-parents=0", &f.head], b"");
    f.head = root;
    f.tree = f.git(&["rev-parse", &format!("{}^{{tree}}", f.head)], b"");
    assert_eq!(
        f.push("refs/heads/main", &f.head, &f.head)["reason"],
        "no_parent"
    );
}

#[test]
fn push_keeps_binding_validation_and_newest_failure_selection() {
    for (field, value, reason) in [
        ("lane_definition_sha256", "wrong", "wrong_input"),
        ("workspace_clean", "false", "workspace_dirty"),
        ("exit_code", "1", "check_failed"),
    ] {
        let f = push_fixture(false);
        let mut statement = f.statement();
        if field == "exit_code" {
            statement["predicate"]["observed"]["checks"][CHECK][field] = json!(1);
        } else {
            statement["predicate"]["observed"]["inputs"][field] = json!(value);
        }
        f.note(&statement, &f.key, "tree");
        let decision = f.push("refs/heads/main", &f.head, &f.head);
        assert_eq!(decision["decision"], "refuse", "{decision}");
        assert_eq!(decision["reason"], reason);
    }
}

fn base_merge_fixture(protected_resolution: bool) -> Fixture {
    let mut f = Fixture::new();
    let base_tree = f.git(&["rev-parse", &format!("{}^{{tree}}", f.base)], b"");
    let main_one = f.git(
        &["commit-tree", &base_tree, "-p", &f.base],
        b"main advance\n",
    );
    let carry = f.git(
        &["commit-tree", &f.tree, "-p", &f.head, "-p", &main_one],
        b"carry main\n",
    );
    f.base = f.git(
        &["commit-tree", &base_tree, "-p", &main_one],
        b"main advance again\n",
    );
    if protected_resolution {
        let policy = f.git(&["show", "HEAD:.mergemaster/lanes.json"], b"");
        f.write(".mergemaster/lanes.json", format!("{policy}\n"));
        f.git(&["add", "-A"], b"");
        f.tree = f.git(&["write-tree"], b"");
    }
    f.head = f.git(
        &["commit-tree", &f.tree, "-p", &carry, "-p", &f.base],
        b"resolve main merge\n",
    );
    f.git(&["checkout", "-q", "--detach", &f.head], b"");
    f
}

#[test]
fn protected_base_merges_accept_older_and_current_base_parents() {
    for at_tip in [true, false] {
        let mut f = base_merge_fixture(false);
        if !at_tip {
            f.refresh_head();
        }
        f.note(&f.statement(), &f.key, "tree");
        let value = f.decision(&[]);
        assert_eq!(value["decision"], "skip", "{value}");
        assert_eq!(value["reason"], "satisfied");
    }
}

#[test]
fn merge_resolution_cannot_hide_protected_policy_edits() {
    let f = base_merge_fixture(true);
    // Neither parent contains this resolution-only policy edit.
    for parent in ["HEAD^1", "HEAD^2"] {
        assert!(
            !f.git(
                &[
                    "diff",
                    "--name-only",
                    parent,
                    "HEAD",
                    "--",
                    ".mergemaster/lanes.json"
                ],
                b""
            )
            .is_empty()
        );
    }
    f.note(&f.statement(), &f.key, "tree");
    let value = f.decision(&[]);
    assert_eq!(value["decision"], "refuse", "{value}");
    assert_eq!(value["reason"], "protected_paths");
    assert_eq!(value["protected_paths"], json!([".mergemaster/lanes.json"]));
}

#[test]
fn linear_pull_request_history_still_uses_exact_head_evidence() {
    let f = Fixture::new();
    f.note(&f.statement(), &f.key, "tree");
    assert_eq!(f.decision(&[])["decision"], "skip");
}

#[test]
fn merge_resolution_lane_definition_requires_final_tree_measurement() {
    let mut f = base_merge_fixture(false);
    let mut stale = f.statement();
    let first_parent = f.git(&["rev-parse", "HEAD^1"], b"");
    f.write("tools/graph", "changed only by merge resolution\n");
    f.git(&["add", "-A"], b"");
    f.tree = f.git(&["write-tree"], b"");
    f.head = f.git(
        &["commit-tree", &f.tree, "-p", &first_parent, "-p", &f.base],
        b"resolve command\n",
    );
    f.git(&["checkout", "-q", "--detach", &f.head], b"");
    stale["subject"][0]["name"] = json!(f.head);
    stale["subject"][0]["digest"]["gitTree"] = json!(f.tree);
    f.note(&stale, &f.key, "tree");
    assert_eq!(f.decision(&[])["reason"], "wrong_input");
    f.note(&f.statement(), &f.key, "tree");
    assert_eq!(f.decision(&[])["decision"], "skip");
}

fn merge_graph_decision(f: &mut Fixture, parents: &[String]) -> Value {
    let mut args = vec!["commit-tree", &f.tree];
    for parent in parents {
        args.extend(["-p", parent.as_str()]);
    }
    f.head = f.git(&args, b"merge graph candidate\n");
    f.git(&["checkout", "-q", "--detach", &f.head], b"");
    f.note(&f.statement(), &f.key, "tree");
    f.decision(&[])
}

#[test]
fn merge_graph_parent_order_cannot_trust_a_foreign_second_parent() {
    for base_first in [true, false] {
        let mut f = Fixture::new();
        let parents = if base_first {
            [f.base.clone(), f.head.clone()]
        } else {
            [f.head.clone(), f.base.clone()]
        };
        let value = merge_graph_decision(&mut f, &parents);
        assert_eq!(
            value["decision"],
            if base_first { "refuse" } else { "skip" },
            "{value}"
        );
        assert_eq!(
            value["reason"],
            if base_first {
                "foreign_merge"
            } else {
                "satisfied"
            }
        );
    }
}

#[test]
fn merge_graph_criss_cross_uses_accepted_base_ancestry_not_one_merge_base() {
    for accepted_cross in [true, false] {
        let mut f = Fixture::new();
        let left = f.head.clone();
        let right = f.git(&["commit-tree", &f.tree, "-p", &f.base], b"right fork\n");
        let left_cross = f.git(
            &["commit-tree", &f.tree, "-p", &left, "-p", &right],
            b"left cross\n",
        );
        let right_cross = f.git(
            &["commit-tree", &f.tree, "-p", &right, "-p", &left],
            b"right cross\n",
        );
        let bases = f.git(&["merge-base", "--all", &left_cross, &right_cross], b"");
        let actual: std::collections::BTreeSet<_> = bases.lines().collect();
        assert_eq!(
            actual,
            std::collections::BTreeSet::from([left.as_str(), right.as_str()])
        );
        f.base = if accepted_cross {
            right_cross.clone()
        } else {
            left
        };
        let value = merge_graph_decision(&mut f, &[left_cross, right_cross]);
        assert_eq!(
            value["decision"],
            if accepted_cross { "skip" } else { "refuse" },
            "{value}"
        );
        assert_eq!(
            value["reason"],
            if accepted_cross {
                "satisfied"
            } else {
                "foreign_merge"
            }
        );
    }
}

#[test]
fn merge_graph_accepts_a_base_that_is_itself_a_merge() {
    let mut f = Fixture::new();
    let root = f.base.clone();
    let base_tree = f.git(&["rev-parse", &format!("{root}^{{tree}}")], b"");
    let side = f.git(
        &["commit-tree", &base_tree, "-p", &root],
        b"accepted main side\n",
    );
    f.base = f.git(
        &["commit-tree", &base_tree, "-p", &root, "-p", &side],
        b"accepted main merge\n",
    );
    assert_eq!(
        f.git(&["rev-list", "--parents", "-n", "1", &f.base], b"")
            .split_whitespace()
            .count(),
        3
    );
    let parents = [f.head.clone(), f.base.clone()];
    let value = merge_graph_decision(&mut f, &parents);
    assert_eq!(value["decision"], "skip", "{value}");
}

#[test]
fn merge_graph_all_trusted_non_first_octopus_parents_are_accepted() {
    let mut f = Fixture::new();
    let root = f.base.clone();
    let base_tree = f.git(&["rev-parse", &format!("{root}^{{tree}}")], b"");
    let older = f.git(&["commit-tree", &base_tree, "-p", &root], b"older main\n");
    f.base = f.git(
        &["commit-tree", &base_tree, "-p", &older],
        b"current main\n",
    );
    let parents = [f.head.clone(), root, older, f.base.clone()];
    let value = merge_graph_decision(&mut f, &parents);
    assert_eq!(
        f.git(&["rev-list", "--parents", "-n", "1", &f.head], b"")
            .split_whitespace()
            .count(),
        5
    );
    assert_eq!(value["decision"], "skip", "{value}");
}

#[test]
fn inspection_only_missing_subject_never_authorizes_a_gate() {
    let mut f = Fixture::new();
    let record = f.note(&f.statement(), &f.key, "tree");
    let absent = f.head.clone();
    f.head = f.git(
        &["commit-tree", &f.tree, "-p", &f.base],
        b"same tree, another commit\n",
    );
    f.git(&["update-ref", "HEAD", &f.head], b"");
    fs::remove_file(
        f.repo
            .join(".git/objects")
            .join(&absent[..2])
            .join(&absent[2..]),
    )
    .unwrap();
    let shown = f
        .command(env!("CARGO_BIN_EXE_mergemaster"))
        .args(["evidence", "show", "--repo"])
        .arg(&f.repo)
        .args(["--record", &record])
        .output()
        .unwrap();
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let decision = f.decision(&[]);
    assert_eq!(decision["decision"], "refuse", "{decision}");
    assert_eq!(decision["reason"], "untrusted_signer", "{decision}");
}

#[test]
fn legacy_policy_routing_matches_signed_oracle_reason_order() {
    use mergemaster_evidence::evidence::{
        Fact, Statement,
        legacy_policy::PolicyDocument,
        legacy_verify::{
            events::narrowed_events,
            routing::{RecordFacts, route},
        },
    };
    for (case, reason) in [
        ("satisfied", "satisfied"),
        ("tier_and_kind", "untrusted_tier"),
        ("failed_part_and_tier", "check_failed"),
        ("kind_and_level", "unsupported_kind"),
        ("level_and_runner", "untrusted_level"),
        ("wrong_runner", "wrong_runner"),
        ("kind_levels", "satisfied"),
        ("override", "satisfied"),
        ("override_runner", "wrong_runner"),
        ("missing_kind", "unsupported_kind"),
        ("prefix", "satisfied"),
    ] {
        let f = Fixture::new();
        let mut statement = f.statement();
        let command = statement["predicate"]["observed"]["checks"][CHECK]["command"].clone();
        let mut entry = json!({"trust_levels":["agent"],"events":["pull_request"],
            "kinds":{"wrapper":{"command":command}}});
        match case {
            "tier_and_kind" => {
                statement["predicate"]["tier"] = json!("test");
                statement["predicate"]["observed"]["runner"] = json!("other");
            }
            "failed_part_and_tier" => {
                statement["predicate"]["tier"] = json!("test");
                statement["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1);
                statement["predicate"]["observed"]["inputs"]["i"] = json!("0");
                entry["kinds"]["wrapper"]["shard_inputs"] =
                    json!({"count":"n","results":"r","index":"i"});
            }
            "kind_and_level" => {
                statement["predicate"]["observed"]["runner"] = json!("other");
                entry["trust_levels"] = json!(["host"]);
            }
            "level_and_runner" | "wrong_runner" => {
                entry["kinds"]["wrapper"]["runner_prefix"] = json!("github:");
                if case == "level_and_runner" {
                    entry["trust_levels"] = json!(["host"]);
                }
            }
            "kind_levels" => {
                entry["trust_levels"] = json!(["host"]);
                entry["kinds"]["wrapper"]["trust_levels"] = json!(["agent"]);
            }
            "override" | "override_runner" => {
                entry["kinds"]["wrapper"]["command"] = json!(["false"]);
                entry["kinds"]["wrapper"]["required_inputs"] = json!(["missing"]);
                entry["kinds"]["wrapper"]["bind_inputs"] = json!({"missing":"nonexistent"});
                entry["kinds"]["wrapper"]["by_level"] = json!({"agent":{
                    "command":command,"events":["merge_group","pull_request"]}});
                if case == "override_runner" {
                    entry["kinds"]["wrapper"]["runner_prefix"] = json!("github:");
                }
            }
            "missing_kind" => {
                entry["kinds"] = json!({"observed":{"command":command}});
            }
            "prefix" => {
                entry["kinds"]["wrapper"]["runner_prefix"] = json!("wrap");
            }
            _ => {}
        }
        f.note(&statement, &f.key, "tree");
        let policy = json!({"version":1,"checks":{CHECK:entry}}).to_string();
        let rules = PolicyDocument::parse(&policy, CHECK)
            .unwrap()
            .into_rules("owner/repo")
            .unwrap();
        let typed: Statement = serde_json::from_value(statement).unwrap();
        let Fact::Tests {
            runner,
            checks,
            inputs,
        } = &typed.predicate.fact
        else {
            unreachable!()
        };
        let record = RecordFacts {
            tier: typed.predicate.tier,
            runner,
            principal: PRINCIPAL,
            check: &checks[CHECK],
            inputs,
        };
        let actual = route(&rules, &record, 1).and_then(|routing| {
            routing.check_runner(runner, 1)?;
            Ok(json!({"reason":"satisfied","command":routing.command_inputs.command,
                "events":narrowed_events(rules.header.events.as_deref(), routing.level.map(|level| level.events.as_slice()))}))
        }).unwrap_or_else(|failure| json!({"reason":failure.reason,"attempts":failure.attempts}));
        let keys = f.root.path().join("routing-keys");
        fs::write(
            &keys,
            f.git(
                &["show", &format!("{}:.mergemaster/evidence-keys", f.base)],
                b"",
            ),
        )
        .unwrap();
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap();
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
rules = oracle['policy_rules'](sys.argv[6], sys.argv[4], 'owner/repo')
try:
    result = oracle['verify'](sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], None, rules=rules)
    print(json.dumps(dict(reason='satisfied', command=result['command'], events=result['events'])))
except oracle['Failure'] as failure:
    print(json.dumps(dict(reason=failure.reason, attempts=failure.extra['attempts'])))
"#;
        let output = f
            .command("python3")
            .args([
                "-c",
                script,
                &root,
                f.repo.to_str().unwrap(),
                &f.tree,
                CHECK,
                keys.to_str().unwrap(),
                &policy,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(expected["reason"], reason, "{case}");
        assert_eq!(actual, expected, "{case}");
    }
}

#[test]
fn legacy_clock_and_input_guards_match_signed_oracle_order() {
    use mergemaster_evidence::evidence::{
        Fact, Statement,
        legacy_policy::PolicyDocument,
        legacy_verify::{
            inputs::{Clock, check_inputs},
            routing::{RecordFacts, route},
        },
    };
    let now = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:01:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    for (case, reason) in [
        ("exact_age", "satisfied"),
        ("fraction_over", "too_old"),
        ("fraction_under", "satisfied"),
        ("future_exact", "satisfied"),
        ("future_over", "future_dated"),
        ("future_overflow", "future_dated"),
        ("age_and_required", "too_old"),
        ("required_and_exit", "missing_input"),
        ("exit_and_command", "check_failed"),
        ("command_and_value", "wrong_command"),
        ("value_weak", "wrong_input"),
        ("value_no_run", "no_run_input"),
        ("value_strong", "satisfied"),
        ("duration_limit", "satisfied"),
        ("duration_overflow", "error"),
        ("u64_max", "error"),
        ("minimum_age", "too_old"),
        ("no_age", "satisfied"),
        ("age_now_tail", "satisfied"),
        ("age_observed_tail", "satisfied"),
        ("age_micro_under", "satisfied"),
        ("age_micro_over", "too_old"),
        ("future_observed_tail", "satisfied"),
        ("future_micro_under", "satisfied"),
        ("future_micro_over", "future_dated"),
        ("age_before_epoch", "satisfied"),
        ("future_before_epoch_offset", "satisfied"),
    ] {
        let f = Fixture::new();
        let mut now = now;
        let mut statement = f.statement();
        let mut at = now - chrono::Duration::seconds(60);
        let mut entry = json!({"trust_levels":["agent"],"max_age_s":60,
            "kinds":{"wrapper":{"command":statement["predicate"]["observed"]["checks"][CHECK]["command"]}}});
        let mut run = json!({});
        match case {
            "fraction_over" => at -= chrono::Duration::microseconds(1),
            "fraction_under" => at += chrono::Duration::microseconds(1),
            "future_exact" => at = now + chrono::Duration::seconds(120),
            "future_over" | "future_overflow" => {
                at = now + chrono::Duration::seconds(120) + chrono::Duration::microseconds(1);
                entry["kinds"]["wrapper"]["required_inputs"] = json!(["missing"]);
                if case == "future_overflow" {
                    entry["max_age_s"] = json!(u64::MAX);
                }
            }
            "age_and_required" | "required_and_exit" => {
                entry["kinds"]["wrapper"]["required_inputs"] = json!(["missing"]);
                if case == "age_and_required" {
                    entry["max_age_s"] = json!(59);
                }
                if case == "required_and_exit" {
                    statement["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1);
                    statement["predicate"]["observed"]["checks"][CHECK]["command"] =
                        json!(["false"]);
                }
            }
            "exit_and_command" => {
                statement["predicate"]["observed"]["checks"][CHECK]["exit_code"] = json!(1);
                statement["predicate"]["observed"]["checks"][CHECK]["command"] = json!(["false"]);
            }
            "command_and_value" | "value_weak" | "value_no_run" | "value_strong" => {
                entry["kinds"]["wrapper"]["input_order"] = json!({"mode":["strong","weak"]});
                statement["predicate"]["observed"]["inputs"]["mode"] =
                    json!(if case == "value_strong" {
                        "strong"
                    } else {
                        "weak"
                    });
                if case != "value_no_run" {
                    run["mode"] = json!(if case == "value_strong" {
                        "weak"
                    } else {
                        "strong"
                    });
                }
                if case == "command_and_value" {
                    statement["predicate"]["observed"]["checks"][CHECK]["command"] =
                        json!(["false"]);
                }
            }
            "duration_limit" => entry["max_age_s"] = json!(86_399_999_999_999_u64),
            "duration_overflow" | "u64_max" => {
                entry["max_age_s"] = json!(if case == "u64_max" {
                    u64::MAX
                } else {
                    86_400_000_000_000
                });
                entry["kinds"]["wrapper"]["required_inputs"] = json!(["missing"]);
            }
            "minimum_age" => {
                entry["max_age_s"] = json!(1);
                at = now - chrono::Duration::seconds(1) - chrono::Duration::microseconds(1);
            }
            "no_age" => entry["max_age_s"] = Value::Null,
            _ => {}
        }
        // Both operands retain nanoseconds in Rust, while the unchanged oracle
        // parses each independently to microseconds (without rounding).
        let precise_clock = match case {
            "age_now_tail" => Some((
                "2025-01-01T00:01:00.000000999Z",
                "2025-01-01T00:00:00.000000000Z",
            )),
            "age_observed_tail" => Some((
                "2025-01-01T00:01:00.000000900Z",
                "2025-01-01T00:00:00.000000100Z",
            )),
            "age_micro_under" => Some((
                "2025-01-01T00:01:00.000000999Z",
                "2025-01-01T00:00:00.000001000Z",
            )),
            "age_micro_over" => Some((
                "2025-01-01T00:01:00.000001000Z",
                "2025-01-01T00:00:00.000000999Z",
            )),
            "future_observed_tail" => Some((
                "2025-01-01T00:01:00.000000100Z",
                "2025-01-01T00:03:00.000000999Z",
            )),
            "future_micro_under" => Some((
                "2025-01-01T00:01:00.000001000Z",
                "2025-01-01T00:03:00.000000999Z",
            )),
            "future_micro_over" => Some((
                "2025-01-01T00:01:00.000000999Z",
                "2025-01-01T00:03:00.000001000Z",
            )),
            "age_before_epoch" => Some((
                "1969-12-31T23:59:59.999999999Z",
                "1969-12-31T23:58:59.999999000Z",
            )),
            "future_before_epoch_offset" => Some((
                "1969-12-31T23:57:59.999999100Z",
                "1970-01-01T00:59:59.999999999+01:00",
            )),
            _ => None,
        };
        if let Some((current, _)) = precise_clock {
            now = chrono::DateTime::parse_from_rfc3339(current)
                .unwrap()
                .with_timezone(&chrono::Utc);
        }
        statement["predicate"]["observed_at"] = json!(
            precise_clock.map_or_else(|| at.to_rfc3339(), |(_, observed)| observed.to_owned())
        );
        f.note(&statement, &f.key, "tree");
        let policy = json!({"version":1,"checks":{CHECK:entry}}).to_string();
        let rules = PolicyDocument::parse(&policy, CHECK)
            .unwrap()
            .into_rules("owner/repo")
            .unwrap();
        let typed: Statement = serde_json::from_value(statement).unwrap();
        let Fact::Tests {
            runner,
            checks,
            inputs,
        } = &typed.predicate.fact
        else {
            unreachable!()
        };
        let record = RecordFacts {
            tier: typed.predicate.tier,
            runner,
            principal: PRINCIPAL,
            check: &checks[CHECK],
            inputs,
        };
        let routing = route(&rules, &record, 1).unwrap();
        routing.check_runner(runner, 1).unwrap();
        let clock = Clock {
            observed_at: chrono::DateTime::parse_from_rfc3339(&typed.predicate.observed_at)
                .unwrap(),
            now,
        };
        let actual = check_inputs(
            &rules,
            &routing,
            &record,
            &clock,
            &serde_json::from_value(run.clone()).unwrap(),
            1,
        )
        .map(|()| json!({"reason":"satisfied"}))
        .unwrap_or_else(|failure| json!({"reason":failure.reason,"attempts":failure.attempts}));
        let keys = f.root.path().join("input-keys");
        fs::write(
            &keys,
            f.git(
                &["show", &format!("{}:.mergemaster/evidence-keys", f.base)],
                b"",
            ),
        )
        .unwrap();
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
rules = oracle['policy_rules'](sys.argv[6], sys.argv[4], 'owner/repo')
try:
    oracle['verify'](sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], None, rules=rules,
        run_inputs=json.loads(sys.argv[7]), now=oracle['parse_time'](sys.argv[8]))
    print(json.dumps(dict(reason='satisfied')))
except oracle['Failure'] as failure:
    print(json.dumps(dict(reason=failure.reason, attempts=failure.extra['attempts'])))
except OverflowError:
    print(json.dumps(dict(reason='error', attempts=1, exception='OverflowError')))
"#;
        let output = f
            .command("python3")
            .args([
                "-c",
                script,
                &root,
                f.repo.to_str().unwrap(),
                &f.tree,
                CHECK,
                keys.to_str().unwrap(),
                &policy,
                &run.to_string(),
                &now.to_rfc3339(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut expected: Value = serde_json::from_slice(&output.stdout).unwrap();
        if matches!(case, "duration_overflow" | "u64_max") {
            assert_eq!(
                expected.as_object_mut().unwrap().remove("exception"),
                Some(json!("OverflowError"))
            );
        } else {
            assert!(expected.get("exception").is_none());
        }
        assert_eq!(expected["reason"], reason, "{case}");
        assert_eq!(actual, expected, "{case}");
    }
}

#[test]
fn legacy_lane_definition_and_blob_guards_match_signed_oracle() {
    use mergemaster_evidence::evidence::{
        Fact, Statement,
        legacy_policy::{PolicyDocument, PolicyError},
        legacy_verify::{
            inputs::{Clock, check_inputs},
            judgment::{LaneDefinition, Provider, check_bindings},
            routing::{RecordFacts, route},
        },
    };
    use sha2::{Digest, Sha256};
    struct Source<'a> {
        fixture: &'a Fixture,
        blobs: Vec<String>,
    }
    impl Provider for Source<'_> {
        fn blob_sha256(&mut self, path: &str) -> Result<Option<String>, PolicyError> {
            self.blobs.push(path.into());
            let output = self
                .fixture
                .command("git")
                .args(["show", &format!("{}:{path}", self.fixture.tree)])
                .output()
                .unwrap();
            Ok(output
                .status
                .success()
                .then(|| hex::encode(Sha256::digest(output.stdout))))
        }
    }
    for (case, reason) in [
        ("satisfied", "satisfied"),
        ("tier_before_lane", "untrusted_tier"),
        ("age_and_definition", "too_old"),
        ("required_and_definition", "missing_input"),
        ("definition_and_bound", "definition_changed"),
        ("digest_and_bound", "wrong_definition"),
        ("tree_edit", "satisfied"),
        ("tree_unchanged", "satisfied"),
        ("bound_wrong", "wrong_input"),
        ("bound_missing", "wrong_input"),
        ("ordered_binds", "wrong_input"),
    ] {
        let f = Fixture::new();
        let mut statement = f.statement();
        let command = statement["predicate"]["observed"]["checks"][CHECK]["command"].clone();
        let mut entry = json!({"trust_levels":["agent"],"max_age_s":60,"kinds":{"wrapper":{
            "command":command,"bind_inputs":{"bound":"source.txt"},"by_level":{"agent":{
                "command":command,"lane":true,"bind_inputs":{"bound":"source.txt"}}}}}});
        // Identical supplied context isolates judgment; 3c's byte/hash matrix covers derivation.
        let mut lane = json!({"sha256":"a".repeat(64),"tree_sha256":"b".repeat(64),"changed":[]});
        let now = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:01:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        statement["predicate"]["observed_at"] = json!(now.to_rfc3339());
        let bound = hex::encode(Sha256::digest(
            f.git(&["show", &format!("{}:source.txt", f.tree)], b""),
        ));
        statement["predicate"]["observed"]["inputs"]["bound"] = json!(bound);
        statement["predicate"]["observed"]["inputs"]["lane_definition_sha256"] =
            lane["sha256"].clone();
        match case {
            "tier_before_lane" => statement["predicate"]["tier"] = json!("test"),
            "age_and_definition" => {
                statement["predicate"]["observed_at"] = json!("2025-01-01T00:00:00Z");
                entry["max_age_s"] = json!(1);
                lane["changed"] = json!(["tools/graph"]);
            }
            "required_and_definition" => {
                entry["kinds"]["wrapper"]["by_level"]["agent"]["required_inputs"] =
                    json!(["missing"]);
                lane["changed"] = json!(["tools/graph"]);
            }
            "definition_and_bound" => {
                lane["changed"] = json!(["tools/graph"]);
                statement["predicate"]["observed"]["inputs"]["bound"] = json!("wrong");
            }
            "digest_and_bound" => {
                statement["predicate"]["observed"]["inputs"]["lane_definition_sha256"] =
                    json!("wrong");
                statement["predicate"]["observed"]["inputs"]["bound"] = json!("wrong");
            }
            "tree_edit" | "tree_unchanged" => {
                entry["kinds"]["wrapper"]["by_level"]["agent"]["lane"] = json!("tree");
                if case == "tree_edit" {
                    lane["changed"] = json!(["tools/graph"]);
                    statement["predicate"]["observed"]["inputs"]["lane_definition_sha256"] =
                        lane["tree_sha256"].clone();
                }
            }
            "bound_wrong" => statement["predicate"]["observed"]["inputs"]["bound"] = json!("wrong"),
            "bound_missing" => {
                entry["kinds"]["wrapper"]["by_level"]["agent"]["bind_inputs"]["bound"] =
                    json!("missing.txt")
            }
            "ordered_binds" => {
                entry["kinds"]["wrapper"]["by_level"]["agent"]["bind_inputs"] =
                    json!({"z":"source.txt","a":"missing.txt"});
                statement["predicate"]["observed"]["inputs"]["z"] = json!("wrong");
                statement["predicate"]["observed"]["inputs"]["a"] = json!("wrong");
            }
            _ => {}
        }
        f.note(&statement, &f.key, "tree");
        let policy = json!({"version":1,"checks":{CHECK:entry}}).to_string();
        let rules = PolicyDocument::parse(&policy, CHECK)
            .unwrap()
            .into_rules("owner/repo")
            .unwrap();
        let typed: Statement = serde_json::from_value(statement).unwrap();
        let Fact::Tests {
            runner,
            checks,
            inputs,
        } = &typed.predicate.fact
        else {
            unreachable!()
        };
        let record = RecordFacts {
            tier: typed.predicate.tier,
            runner,
            principal: PRINCIPAL,
            check: &checks[CHECK],
            inputs,
        };
        let clock = Clock {
            observed_at: chrono::DateTime::parse_from_rfc3339(&typed.predicate.observed_at)
                .unwrap(),
            now,
        };
        let given = LaneDefinition {
            sha256: lane["sha256"].as_str().unwrap().into(),
            tree_sha256: lane["tree_sha256"].as_str().unwrap().into(),
            changed: lane["changed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|path| path.as_str().unwrap().as_bytes().to_vec())
                .collect(),
        };
        let mut provider = Source {
            fixture: &f,
            blobs: Vec::new(),
        };
        let actual = route(&rules, &record, 1)
            .and_then(|routing| {
                routing.check_runner(runner, 1)?;
                check_inputs(&rules, &routing, &record, &clock, &BTreeMap::new(), 1)?;
                check_bindings(&routing, &record, Some(&given), &mut provider, 1)
            })
            .map(|_| json!({"reason":"satisfied"}))
            .unwrap_or_else(|e| json!({"reason":e.reason,"attempts":e.attempts}));
        let keys = f.root.path().join("lazy-keys");
        fs::write(
            &keys,
            f.git(
                &["show", &format!("{}:.mergemaster/evidence-keys", f.base)],
                b"",
            ),
        )
        .unwrap();
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
rules = oracle['policy_rules'](sys.argv[6],sys.argv[4],'owner/repo')
context = json.loads(sys.argv[7])
blobs = []
original = oracle['blob_sha256']
def blob(*args):
    blobs.append(args[2])
    return original(*args)
oracle['verified'].__globals__['blob_sha256'] = blob
try:
    oracle['verify'](sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5],None,rules=rules,
        lane=context,now=oracle['parse_time'](sys.argv[8]))
    result = dict(reason='satisfied')
except oracle['Failure'] as failure:
    result = dict(reason=failure.reason,attempts=failure.extra['attempts'])
print(json.dumps(dict(result=result,blobs=blobs)))
"#;
        let output = f
            .command("python3")
            .args([
                "-c",
                script,
                &root,
                f.repo.to_str().unwrap(),
                &f.tree,
                CHECK,
                keys.to_str().unwrap(),
                &policy,
                &lane.to_string(),
                &now.to_rfc3339(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(actual["reason"], reason, "{case}");
        assert_eq!(actual, expected["result"], "{case}");
        assert_eq!(json!(provider.blobs), expected["blobs"], "{case}");
    }
}
