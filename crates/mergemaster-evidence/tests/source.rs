//! Native v2 versus the independently pinned v1 producer on recorded synthetic repositories.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Fixture {
    root: tempfile::TempDir,
    repo: PathBuf,
    base: String,
    author: String,
    source: String,
    tree: String,
}
fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_DATE", "2001-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2001-01-01T00:00:00Z")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().into()
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        for (key, value) in [
            ("user.name", "Fixture Observer"),
            ("user.email", "observer@example.invalid"),
            ("maintenance.auto", "false"),
            ("gc.auto", "0"),
        ] {
            git(&repo, &["config", key, value]);
        }
        fs::create_dir(repo.join(".mergemaster")).unwrap();
        let pin = json!({"version":1,"repository":"compoundingtech/mergemaster","revision":"a".repeat(40),"release":{"version":"v1.2.3","sha256":"b".repeat(64)}});
        fs::write(
            repo.join(".mergemaster/tool-pin.json"),
            serde_json::to_vec(&pin).unwrap(),
        )
        .unwrap();
        fs::write(repo.join("unchanged"), "same").unwrap();
        fs::write(repo.join("deleted"), "old").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "initial"]);
        let base = git(&repo, &["rev-parse", "HEAD"]);
        fs::write(repo.join("changed"), "reviewed").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "author"]);
        let author = git(&repo, &["rev-parse", "HEAD"]);
        git(&repo, &["checkout", "-q", "-b", "accepted-main", &base]);
        fs::write(repo.join("unrelated-main"), "new").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "main changed"]);
        git(
            &repo,
            &[
                "merge",
                "-q",
                "--no-ff",
                &author,
                "-m",
                "synthetic checked merge",
            ],
        );
        let source = git(&repo, &["rev-parse", "HEAD"]);
        let tree = git(&repo, &["rev-parse", "HEAD^{tree}"]);
        Self {
            root,
            repo,
            base,
            author,
            source,
            tree,
        }
    }
    fn event(&self, kind: &str) -> Value {
        match kind {
            "merge_group" => {
                json!({"repository":{"full_name":"example/project"},"merge_group":{"head_sha":self.source,"head_ref":format!("refs/heads/gh-readonly-queue/main/pr-7-{}",self.source)}})
            }
            "push" => {
                json!({"repository":{"full_name":"example/project"},"ref":"refs/heads/main","before":self.base,"after":self.source})
            }
            _ => {
                json!({"repository":{"full_name":"example/project"},"number":7,"pull_request":{"number":7,"head":{"sha":self.author}}})
            }
        }
    }
    fn command(&self, repo: &Path, temp: &Path, kind: &str) -> Command {
        fs::create_dir_all(temp).unwrap();
        let event = temp.join("event.json");
        fs::write(&event, serde_json::to_vec(&self.event(kind)).unwrap()).unwrap();
        let mut cmd = Command::new(mergemaster_bin());
        cmd.args(["evidence", "source"])
            .current_dir(repo)
            .env("BASE_SHA", &self.base)
            .env("GITHUB_SHA", &self.source)
            .env("GITHUB_REPOSITORY", "example/project")
            .env("GITHUB_EVENT_NAME", kind)
            .env("GITHUB_EVENT_PATH", event)
            .env("GITHUB_RUN_ID", "123")
            .env("GITHUB_RUN_ATTEMPT", "2")
            .env("RUNNER_TEMP", temp)
            .env("GITHUB_STEP_SUMMARY", temp.join("summary"));
        cmd
    }
    fn success(&self, repo: &Path, temp: &Path, kind: &str) -> Value {
        let out = self.command(repo, temp, kind).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
}
fn receipt(temp: &Path) -> Value {
    serde_json::from_slice(&fs::read(temp.join("ci-evidence-source/receipt.json")).unwrap())
        .unwrap()
}
fn objects(pack: &Path, destination: &Path) -> Vec<String> {
    fs::create_dir(destination).unwrap();
    git(destination, &["init", "-q", "--bare"]);
    let out = Command::new("git")
        .arg("-C")
        .arg(destination)
        .args(["index-pack", "--stdin"])
        .stdin(fs::File::open(pack).unwrap())
        .output()
        .unwrap();
    assert!(out.status.success());
    let mut list: Vec<_> = git(
        destination,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ],
    )
    .lines()
    .map(str::to_owned)
    .collect();
    list.sort();
    list
}
#[test]
fn source_shallow_pack_oracle_and_version_two_contract() {
    let f = Fixture::new();
    let shallow = f.root.path().join("shallow");
    git(
        f.root.path(),
        &[
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            "clone",
            "-q",
            "--depth=1",
            &format!("file://{}", f.repo.display()),
            shallow.to_str().unwrap(),
        ],
    );
    assert_eq!(
        git(&shallow, &["rev-parse", "--is-shallow-repository"]),
        "true"
    );
    // A depth-one source still needs the separately fetched accepted base pin.
    git(&shallow, &["fetch", "-q", "--depth=1", "origin", &f.base]);
    for kind in ["pull_request", "merge_group", "workflow_dispatch"] {
        let temp = f.root.path().join(kind);
        let native = f.success(&shallow, &temp, kind);
        assert_eq!(native, receipt(&temp));
        assert_eq!(native["source"], f.source);
        assert_ne!(native["source"], f.author);
        assert_eq!(native["tree"], f.tree);
        assert_eq!(
            native["change_id"],
            if kind == "workflow_dispatch" {
                format!("github:example/project@{}", f.source)
            } else {
                "github:example/project#7".into()
            }
        );
        let binary = fs::read(mergemaster_bin()).unwrap();
        assert_eq!(
            native["tool"]["binary_sha256"],
            hex::encode(Sha256::digest(binary))
        );
        let bytes = fs::read(temp.join("ci-evidence-source/source.pack")).unwrap();
        assert_eq!(native["pack_bytes"], bytes.len());
        assert_eq!(native["pack_sha256"], hex::encode(Sha256::digest(bytes)));
        let imported = f.root.path().join(format!("import-{kind}"));
        let native_objects = objects(&temp.join("ci-evidence-source/source.pack"), &imported);
        assert_eq!(
            git(&imported, &["rev-parse", &format!("{}^{{tree}}", f.source)]),
            f.tree
        );
        assert_eq!(
            git(&imported, &["ls-tree", "-rz", &f.source]),
            git(&f.repo, &["ls-tree", "-rz", &f.source])
        );
        for (file, contents) in [("changed", "reviewed"), ("unrelated-main", "new")] {
            assert_eq!(
                git(&imported, &["show", &format!("{}:{file}", f.source)]),
                contents
            );
        }
        assert!(!native_objects.contains(&f.base));
        assert!(!native_objects.contains(&f.author));
        assert!(git(&imported, &["for-each-ref"]).is_empty());
        let oracle = temp.join("oracle");
        let python = std::env::var("MERGEMASTER_ORACLE_PYTHON").unwrap_or_else(|_| {
            "/nix/store/d64q19q1xjdwfhqx6czvrjgrhq0n3lcc-python3-3.14.7/bin/python3.14".into()
        });
        let oracle_root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .unwrap_or_else(|_| "/nix/store/bbj5s0bmhsv4a9mjqb97x80r8dvkas45-source".into());
        let script = Path::new(&oracle_root).join("scripts/ci-evidence-source");
        let code = "import importlib.machinery,importlib.util,os,pathlib,sys\np=sys.argv[1];l=importlib.machinery.SourceFileLoader('source',p);s=importlib.util.spec_from_loader(l.name,l);m=importlib.util.module_from_spec(s);l.exec_module(m);m.produce(pathlib.Path.cwd(),pathlib.Path(sys.argv[2]),os.environ,pathlib.Path(p).read_bytes())";
        let cmd = f.command(&shallow, &temp, kind); // reuse identical producer environment, not its executable
        let envs: Vec<_> = cmd
            .get_envs()
            .map(|(k, v)| (k.to_owned(), v.unwrap().to_owned()))
            .collect();
        let out = Command::new(&python)
            .args([
                "-B",
                "-c",
                code,
                script.to_str().unwrap(),
                oracle.to_str().unwrap(),
            ])
            .current_dir(&shallow)
            .envs(envs)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut old: Value =
            serde_json::from_slice(&fs::read(oracle.join("receipt.json")).unwrap()).unwrap();
        assert_eq!(old["version"], 1);
        assert!(
            old.as_object_mut()
                .unwrap()
                .remove("producer_sha256")
                .is_some()
        );
        // The only decided v1 -> v2 receipt differences are version and measured tool identity.
        old["version"] = json!(2);
        old["tool"] = native["tool"].clone();
        assert_eq!(old, native);
        // The pinned producer uses json.dumps(sort_keys=True), no indent,
        // default ", " / ": " separators, and exactly one trailing newline.
        // Serialize the same v2 fields (including tool) with that Python call.
        let receipt_path = temp.join("ci-evidence-source/receipt.json");
        let expected = Command::new(&python)
            .args([
                "-B",
                "-c",
                "import json,pathlib,sys; sys.stdout.write(json.dumps(json.loads(pathlib.Path(sys.argv[1]).read_bytes()), sort_keys=True) + '\\n')",
            ])
            .arg(&receipt_path)
            .output()
            .unwrap();
        assert!(
            expected.status.success(),
            "{}",
            String::from_utf8_lossy(&expected.stderr)
        );
        assert_eq!(
            fs::read(receipt_path).unwrap(),
            expected.stdout,
            "{kind}: exact Python receipt bytes"
        );
        assert_eq!(
            objects(&oracle.join("source.pack"), &temp.join("oracle-import")),
            native_objects
        );
        let summary = fs::read_to_string(temp.join("summary")).unwrap();
        assert!(summary.contains(&f.source));
        assert!(summary.contains("neither check success nor signing trust"));
    }
}
#[test]
fn source_push_identity_names_the_pushed_commit_and_retains_its_tree() {
    let f = Fixture::new();
    let temp = f.root.path().join("push");
    let native = f.success(&f.repo, &temp, "push");
    assert_eq!(native, receipt(&temp));
    assert_eq!(native["source"], f.source);
    assert_eq!(native["tree"], f.tree);
    assert_eq!(
        native["change_id"],
        format!("github:example/project@{}", f.source)
    );
    let imported = f.root.path().join("push-import");
    objects(&temp.join("ci-evidence-source/source.pack"), &imported);
    assert_eq!(
        git(&imported, &["rev-parse", &format!("{}^{{tree}}", f.source)]),
        f.tree
    );
    for (index, after) in [json!(f.base), json!("0".repeat(40)), Value::Null]
        .into_iter()
        .enumerate()
    {
        let temp = f.root.path().join(format!("push-mismatch-{index}"));
        let mut command = f.command(&f.repo, &temp, "push");
        let mut event = f.event("push");
        event["after"] = after;
        fs::write(temp.join("event.json"), serde_json::to_vec(&event).unwrap()).unwrap();
        let out = command.output().unwrap();
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .any(|line| line == "ValueError: mismatched push identity")
        );
        assert!(!temp.join("ci-evidence-source").exists());
    }
}

#[test]
fn source_event_bytes_match_frozen_cpython_identity_and_errors() {
    // Generated with CPython 3.14.7 json.loads(bytes) and the independently pinned
    // source.change_identity. Only queue source OIDs are rebound to this repository.
    let oracle: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/oracle/source-events.json"
    ))
    .unwrap();
    assert_eq!(oracle["python"], "3.14.7");
    let recorded_source = oracle["source"].as_str().unwrap();
    let f = Fixture::new();
    let python = std::env::var("MERGEMASTER_ORACLE_PYTHON").unwrap_or_else(|_| {
        "/nix/store/d64q19q1xjdwfhqx6czvrjgrhq0n3lcc-python3-3.14.7/bin/python3.14".into()
    });
    for case in oracle["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let kind = case["event_name"].as_str().unwrap();
        let temp = f.root.path().join(format!("event-{name}"));
        let mut command = f.command(&f.repo, &temp, kind);
        let mut event = hex::decode(case["event_hex"].as_str().unwrap()).unwrap();
        if case["substitute_source"].as_bool().unwrap() {
            event = String::from_utf8(event)
                .unwrap()
                .replace(recorded_source, &f.source)
                .into_bytes();
        }
        fs::write(temp.join("event.json"), event).unwrap();
        let out = command.output().unwrap();
        let expected = &case["expected"];
        assert_eq!(
            out.status.code(),
            Some(expected["exit"].as_i64().unwrap() as i32),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        if expected["exit"] == 1 {
            let exception = format!(
                "{}: {}",
                expected["class"].as_str().unwrap(),
                expected["message"].as_str().unwrap()
            );
            let stderr = String::from_utf8(out.stderr).unwrap();
            assert!(
                stderr.lines().any(|line| line == exception),
                "{name}: expected {exception:?}, got {stderr:?}"
            );
            assert!(
                !temp.join("ci-evidence-source/receipt.json").exists(),
                "{name}: failed event must not produce a receipt"
            );
            continue;
        }
        let native: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(native, receipt(&temp), "{name}: stdout and receipt");
        assert_eq!(
            native["change_id"],
            expected["change_id"]
                .as_str()
                .unwrap()
                .replace(recorded_source, &f.source),
            "{name}"
        );
        assert_eq!(native["repository"], "example/project", "{name}");
        assert_eq!(native["event"], kind, "{name}");
        assert_eq!(native["run_id"], "123", "{name}");
        assert_eq!(native["run_attempt"], "2", "{name}");
        assert_eq!(native["source"], f.source, "{name}");
        assert_eq!(native["tree"], f.tree, "{name}");
        assert_eq!(native["version"], 2, "{name}");
        let receipt_path = temp.join("ci-evidence-source/receipt.json");
        // As in the full-producer oracle test, serialize the same v2 fields with
        // Python's actual dumps, including default separators and final newline.
        let expected_bytes = Command::new(&python)
            .args([
                "-B",
                "-c",
                "import json,pathlib,sys; sys.stdout.write(json.dumps(json.loads(pathlib.Path(sys.argv[1]).read_bytes()), sort_keys=True) + '\\n')",
            ])
            .arg(&receipt_path)
            .output()
            .unwrap();
        assert!(
            expected_bytes.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&expected_bytes.stderr)
        );
        assert_eq!(
            fs::read(receipt_path).unwrap(),
            expected_bytes.stdout,
            "{name}: exact Python receipt bytes"
        );
    }
}

#[test]
fn source_replacements_reruns_wrong_checkout_existing_destination_and_base_pin() {
    let f = Fixture::new();
    git(&f.repo, &["replace", &f.source, &f.author]);
    let first = f.root.path().join("first");
    let a = f.success(&f.repo, &first, "pull_request");
    assert_eq!(a["source"], f.source);
    assert_eq!(a["tree"], f.tree);
    let second = f.root.path().join("second");
    let out = f
        .command(&f.repo, &second, "pull_request")
        .env("GITHUB_RUN_ATTEMPT", "3")
        .output()
        .unwrap();
    assert!(out.status.success());
    let b = receipt(&second);
    assert_eq!(a["tree"], b["tree"]);
    assert_ne!(a["run_attempt"], b["run_attempt"]);
    assert_eq!(a["pack_sha256"], b["pack_sha256"]);
    assert!(
        !f.command(&f.repo, &first, "pull_request")
            .output()
            .unwrap()
            .status
            .success()
    );
    let wrong = f.root.path().join("wrong");
    let out: Output = f
        .command(&f.repo, &wrong, "pull_request")
        .env("GITHUB_SHA", &f.author)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("effective tested"));
    assert!(!wrong.join("ci-evidence-source").exists());
    fs::write(
        f.repo.join(".mergemaster/tool-pin.json"),
        "invalid candidate pin",
    )
    .unwrap();
    let candidate = f.root.path().join("candidate");
    assert_eq!(
        f.success(&f.repo, &candidate, "pull_request")["tool"]["release_version"],
        "v1.2.3"
    );
    let bad = f.root.path().join("bad-group");
    let mut cmd = f.command(&f.repo, &bad, "merge_group");
    let mut event = f.event("merge_group");
    event["merge_group"]["head_sha"] = json!(f.author);
    fs::write(bad.join("event.json"), serde_json::to_vec(&event).unwrap()).unwrap();
    assert!(!cmd.output().unwrap().status.success());
}

#[test]
fn source_fixture_ignores_inherited_signing_hooks_and_maintenance() {
    if std::env::var_os("SOURCE_FIXTURE_ISOLATION_CHILD").is_some() {
        let fixture = Fixture::new();
        assert_eq!(git(&fixture.repo, &["config", "maintenance.auto"]), "false");
        assert_eq!(git(&fixture.repo, &["config", "gc.auto"]), "0");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let hooks = root.path().join("hooks");
    fs::create_dir(&hooks).unwrap();
    let marker = root.path().join("invoked");
    let program = hooks.join("commit-msg");
    fs::write(
        &program,
        format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    for signing in ["true", "false"] {
        let config = root.path().join("gitconfig");
        fs::write(&config, format!("[commit]\n gpgSign = {signing}\n[gpg]\n program = {}\n[core]\n hooksPath = {}\n[maintenance]\n auto = true\n[gc]\n auto = 1\n autoDetach = false\n", program.display(), hooks.display())).unwrap();
        let trace = root.path().join(format!("trace-{signing}.jsonl"));
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "source_fixture_ignores_inherited_signing_hooks_and_maintenance",
            ])
            .env("SOURCE_FIXTURE_ISOLATION_CHILD", "1")
            .env("GIT_CONFIG_GLOBAL", &config)
            .env("GIT_CONFIG_SYSTEM", &config)
            .env("GIT_TRACE2_EVENT", &trace)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!marker.exists());
        // Fixture Git drops all caller GIT_* selectors, including tracing.
        assert!(!trace.exists());
    }
}

fn mergemaster_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var_os("CARGO_BIN_EXE_mergemaster")
            .expect("CARGO_BIN_EXE_mergemaster is set at test runtime"),
    )
}
