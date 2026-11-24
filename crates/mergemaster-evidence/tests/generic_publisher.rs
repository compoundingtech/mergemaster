//! Staged harness port: production Python remains embedded in the unchanged Genie adapter.
#[path = "../src/pinned_python.rs"]
mod pinned_python;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const REPOSITORY: &str = "example/project";
const CHECK: &str = "graph-full-check";
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn temporary() -> tempfile::TempDir {
    let directory = root().join("tmp");
    fs::create_dir_all(&directory).unwrap();
    tempfile::Builder::new()
        .prefix("generic-publisher-")
        .tempdir_in(directory)
        .unwrap()
}
fn source() -> String {
    let text = fs::read_to_string(root().join("genie/generic-evidence.ts")).unwrap();
    format!(
        "{}\n",
        text.split_once("String.raw`")
            .unwrap()
            .1
            .split_once("\n`")
            .unwrap()
            .0
    )
}
fn report_source() -> String {
    let text = fs::read_to_string(root().join("genie/generic-evidence.ts")).unwrap();
    text.split_once("export const genericEvidenceReport = String.raw`")
        .unwrap()
        .1
        .split_once("\n`")
        .unwrap()
        .0
        .into()
}
fn executable(path: &Path, bytes: &[u8]) {
    // A separate writer process avoids Linux ETXTBSY when this test immediately executes the shim.
    let mut child = Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "fixture"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    assert!(child.wait().unwrap().success());
}
fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .unwrap();
    success(&out);
    String::from_utf8(out.stdout).unwrap().trim().into()
}
fn success(out: &Output) {
    assert!(
        out.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
fn refusal(out: &Output, message: &str) {
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(message),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// This is only the gh transport fixture: Rust supplies every route, payload and assertion.
const GH: &str = r#"import { appendFileSync, copyFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
const directory = process.env.FIXTURE;
const argv = process.argv.slice(2);
const payload = argv.includes('--input') ? JSON.parse(readFileSync(0, 'utf8')) : null;
appendFileSync(join(directory, 'calls.jsonl'), JSON.stringify({argv, payload, token: process.env.GH_TOKEN}) + '\n');
if (argv[0] === 'release' && argv[1] === 'download') {
  copyFileSync(join(directory, 'asset'), join(argv[argv.indexOf('--dir') + 1], 'mergemaster-x86_64-unknown-linux-musl'));
} else if (argv[0] === 'attestation' && argv[1] === 'verify') {
  process.stdout.write('verified\n');
} else if (argv[0] === 'api') {
  if (payload !== null) {
    process.stdout.write('{"id":100}\n');
  } else {
    const endpoint = argv.find(value => value.startsWith('repos/'));
    const routes = JSON.parse(readFileSync(join(directory, 'routes.json'), 'utf8'));
    if (!(endpoint in routes)) throw new Error('Unexpected API endpoint: ' + endpoint);
    process.stdout.write(JSON.stringify(routes[endpoint]) + '\n');
  }
} else { throw new Error('Unexpected gh command: ' + JSON.stringify(argv)); }
"#;
struct Fixture {
    temporary: tempfile::TempDir,
    repo: PathBuf,
    base: String,
    head: String,
    pull: Value,
    check: Value,
    run: Value,
    job: Value,
    decision: Value,
    pin: Value,
}
impl Fixture {
    fn new() -> Self {
        let temporary = temporary();
        let directory = temporary.path();
        let repo = directory.join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        git(&repo, &["config", "maintenance.auto", "false"]);
        git(&repo, &["config", "gc.auto", "0"]);
        let pin = json!({"version":1,"repository":"compoundingtech/mergemaster","revision":"c".repeat(40),"release":{"version":"v1.2.3","sha256":hex::encode(Sha256::digest(b"binary"))}});
        fs::create_dir(repo.join(".mergemaster")).unwrap();
        fs::write(repo.join(".mergemaster/tool-pin.json"), pin.to_string()).unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "base"]);
        let base = git(&repo, &["rev-parse", "HEAD"]);
        git(&repo, &["checkout", "-qb", "candidate"]);
        fs::write(repo.join("candidate"), "data only\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "candidate"]);
        let head = git(&repo, &["rev-parse", "HEAD"]);
        git(&repo, &["checkout", "-q", "main"]);
        let remote = directory.join("origin.git");
        git(
            directory,
            &[
                "clone",
                "--bare",
                "-q",
                repo.to_str().unwrap(),
                remote.to_str().unwrap(),
            ],
        );
        git(
            &repo,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        fs::create_dir(directory.join("bin")).unwrap();
        fs::create_dir(directory.join("home")).unwrap();
        fs::create_dir(directory.join("runner")).unwrap();
        fs::write(directory.join("gh.mjs"), GH).unwrap();
        fs::write(directory.join("asset"), b"binary").unwrap();
        executable(
            &directory.join("bin/gh"),
            b"#!/bin/sh\nexec node \"$FIXTURE/gh.mjs\" \"$@\"\n",
        );
        let resolved = Command::new("sh")
            .args(["-c", "command -v git"])
            .output()
            .unwrap();
        success(&resolved);
        fs::write(
            directory.join("real-git"),
            String::from_utf8(resolved.stdout).unwrap().trim(),
        )
        .unwrap();
        fs::write(directory.join("git.mjs"), r#"import { appendFileSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
const root = process.env.FIXTURE;
const argv = process.argv.slice(2);
appendFileSync(join(root, 'git-calls.jsonl'), JSON.stringify({argv, authorization: process.env.GIT_CONFIG_VALUE_0}) + '\n');
const result = spawnSync(readFileSync(join(root, 'real-git'), 'utf8'), argv, {stdio: 'inherit'});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
"#).unwrap();
        executable(
            &directory.join("bin/git"),
            b"#!/bin/sh\nexec node \"$FIXTURE/git.mjs\" \"$@\"\n",
        );
        let pull = json!({"number":3,"state":"open","head":{"sha":head,"repo":{"full_name":REPOSITORY}},"base":{"ref":"main","repo":{"full_name":REPOSITORY}}});
        let check = json!({"id":7,"name":"validate","head_sha":head,"status":"completed","conclusion":"success","app":{"slug":"github-actions"},"details_url":format!("https://github.com/{REPOSITORY}/actions/runs/8/job/9")});
        let run = json!({"id":8,"repository":{"full_name":REPOSITORY},"workflow_id":123,"path":".github/workflows/validate.yml","head_sha":head,"event":"pull_request"});
        let job = json!({"id":9,"run_id":8,"name":"validate","head_sha":head,"status":"completed","conclusion":"success","check_run_url":format!("https://api.github.com/repos/{REPOSITORY}/check-runs/7")});
        let decision = json!({"version":1,"check":CHECK,"base":base,"head":head,"decision":"skip","outcome":"satisfied","summary":"this PR changes the validate workflow; validate ran the changed file"});
        let fixture = Self {
            temporary,
            repo,
            base,
            head,
            pull,
            check,
            run,
            job,
            decision,
            pin,
        };
        fixture.save();
        fixture
    }
    fn path(&self, name: &str) -> PathBuf {
        self.temporary.path().join(name)
    }
    fn save(&self) {
        fs::write(
            self.path("event.json"),
            json!({"pull_request":self.pull}).to_string(),
        )
        .unwrap();
        fs::write(
            self.path("runner/generic-evidence-decision.json"),
            self.decision.to_string(),
        )
        .unwrap();
        let prefix = format!("repos/{REPOSITORY}");
        let mut routes = serde_json::Map::new();
        routes.insert(format!("{prefix}/pulls/3"), self.pull.clone());
        routes.insert(
            format!("{prefix}/git/ref/heads/main"),
            json!({"object":{"sha":self.base}}),
        );
        routes.insert(format!("{prefix}/actions/runs/8"), self.run.clone());
        let review = json!({"id":1,"user":{"login":"schickling","id":42},"state":"APPROVED","commit_id":self.head,"submitted_at":"2026-10-30T00:00:00Z"});
        for (endpoint, key, entry) in [
            (format!("{prefix}/pulls/3/reviews"), None, review),
            (
                format!("{prefix}/commits/{}/check-runs?filter=all", self.head),
                Some("check_runs"),
                self.check.clone(),
            ),
            (
                format!("{prefix}/actions/runs/8/jobs?filter=latest"),
                Some("jobs"),
                self.job.clone(),
            ),
        ] {
            for page in 1..=2 {
                let values = if page == 1 {
                    json!(vec![entry.clone(); 100])
                } else {
                    json!([])
                };
                let value = match key {
                    Some(key) => json!({key:values}),
                    None => values,
                };
                let separator = if endpoint.contains('?') { '&' } else { '?' };
                routes.insert(
                    format!("{endpoint}{separator}per_page=100&page={page}"),
                    value,
                );
            }
        }
        fs::write(self.path("routes.json"), Value::Object(routes).to_string()).unwrap();
    }
    fn command(&self) -> Command {
        let mut command = pinned_python::command();
        command
            .env_clear()
            .current_dir(&self.repo)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.path("bin").display(),
                    std::env::var("PATH").unwrap()
                ),
            )
            .env("HOME", self.path("home"))
            .env("FIXTURE", self.temporary.path())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GITHUB_REPOSITORY", REPOSITORY)
            .env("GITHUB_EVENT_NAME", "pull_request_target")
            .env("GITHUB_EVENT_PATH", self.path("event.json"))
            .env("RUNNER_TEMP", self.path("runner"))
            .env("HEAD_SHA", &self.head)
            .env("BASE_SHA", &self.base)
            .env("GH_TOKEN", "read-only")
            .env("CHECK", CHECK)
            .env("GATE_OUTCOME", "success")
            .env("GATE_SKIP", "true")
            .env("APP_TOKEN", "app-only")
            .env("APP_OUTCOME", "success")
            .env("GITHUB_STEP_SUMMARY", self.path("summary"));
        command
    }
    fn execute(&self, mode: &str, env: &[(&str, &str)]) -> Output {
        let source = match mode {
            "report" => report_source(),
            "report-prepare" => format!(
                "{}\nprepare()\n",
                source().split_once("\ndef finalize():").unwrap().0
            ),
            _ => source(),
        };
        let before = git(&self.repo, &["rev-parse", "HEAD"]);
        let out = self
            .command()
            .args(["-c", &source, mode])
            .envs(env.iter().copied())
            .output()
            .unwrap();
        assert_eq!(git(&self.repo, &["rev-parse", "HEAD"]), before);
        assert_eq!(git(&self.repo, &["status", "--porcelain"]), "");
        out
    }
    fn records(&self, name: &str) -> Vec<Value> {
        if !self.path(name).exists() {
            return Vec::new();
        }
        fs::read_to_string(self.path(name))
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }
    fn calls(&self) -> Vec<Value> {
        self.records("calls.jsonl")
    }
    fn git_calls(&self) -> Vec<Value> {
        self.records("git-calls.jsonl")
    }
    fn posts(&self) -> Vec<Value> {
        self.calls()
            .into_iter()
            .filter(|c| !c["payload"].is_null())
            .collect()
    }
    fn evidence(&self) -> Value {
        serde_json::from_slice(&fs::read(self.path("runner/generic-hosted-evidence.json")).unwrap())
            .unwrap()
    }
}

#[test]
fn exact_api_join_and_pagination() {
    let f = Fixture::new();
    success(&f.execute("prepare", &[]));
    let evidence = f.evidence();
    assert_eq!(evidence["head"], f.head);
    assert_eq!(
        evidence["reviews"][0]["user"],
        json!({"login":"schickling"})
    );
    let mut expected = serde_json::Map::new();
    for key in ["id", "workflow_id", "path", "head_sha", "event"] {
        expected.insert(key.into(), f.run[key].clone());
    }
    assert_eq!(
        evidence["checks"][0]["workflow_run"],
        Value::Object(expected)
    );
    let calls = f.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|c| c["argv"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s.contains("page=2"))))
            .count(),
        3
    );
    assert!(calls.iter().any(|c| {
        let args = c["argv"].as_array().unwrap();
        args.contains(&json!("--source-digest")) && args.contains(&json!("--signer-workflow"))
    }));
}
#[test]
fn same_named_check_cannot_invent_run_identity() {
    let mut f = Fixture::new();
    f.run["workflow_id"] = json!(999);
    f.run["path"] = json!(".github/workflows/spoof.yml");
    f.save();
    success(&f.execute("prepare", &[]));
    let evidence = f.evidence();
    assert_eq!(evidence["checks"][0]["workflow_run"]["workflow_id"], 999);
    assert_eq!(
        evidence["checks"][0]["workflow_run"]["path"],
        ".github/workflows/spoof.yml"
    );
}
#[test]
fn job_check_mismatch_is_fatal() {
    let mut f = Fixture::new();
    f.job["check_run_url"] = json!(format!("{}0", f.job["check_run_url"].as_str().unwrap()));
    f.save();
    refusal(&f.execute("prepare", &[]), "identity mismatch");
}
#[test]
fn digest_mismatch_never_fetches_candidate() {
    let mut f = Fixture::new();
    f.pin["release"]["sha256"] = json!("0".repeat(64));
    fs::write(f.repo.join(".mergemaster/tool-pin.json"), f.pin.to_string()).unwrap();
    git(&f.repo, &["add", "."]);
    git(&f.repo, &["commit", "-qm", "wrong release digest"]);
    f.base = git(&f.repo, &["rev-parse", "HEAD"]);
    f.decision["base"] = json!(f.base);
    f.save();
    refusal(&f.execute("prepare", &[]), "digest mismatch");
    assert!(!f.repo.join(".git/FETCH_HEAD").exists());
    assert!(
        git(
            &f.repo,
            &["for-each-ref", "refs/notes/", "refs/tags/evidence/"]
        )
        .is_empty()
    );
    assert!(
        !f.git_calls()
            .iter()
            .any(|call| call["argv"].as_array().unwrap().contains(&json!("fetch")))
    );
}
#[test]
fn success_exact_head_app_token_and_changed_workflow_summary() {
    let f = Fixture::new();
    success(&f.execute("finalize", &[]));
    let posts = f.posts();
    let post = &posts[0];
    assert_eq!(post["payload"]["head_sha"], f.head);
    assert_eq!(post["payload"]["conclusion"], "success");
    assert_eq!(post["token"], "app-only");
    assert!(
        post["payload"]["output"]["summary"]
            .as_str()
            .unwrap()
            .contains("this PR changes the validate workflow; validate ran the changed file")
    );
}
#[test]
fn policy_accepted_reuse_preserves_nonfresh_summary() {
    let mut f = Fixture::new();
    f.decision["outcome"] = json!("reused");
    f.decision["reason"] = json!("execution_reused");
    f.decision["summary"] =
        json!("A trusted realization was reused; no fresh test execution is asserted.");
    f.save();
    success(&f.execute("finalize", &[]));
    let posts = f.posts();
    assert_eq!(posts[0]["payload"]["conclusion"], "success");
    assert!(
        posts[0]["payload"]["output"]["summary"]
            .as_str()
            .unwrap()
            .contains("no fresh test execution")
    );
}

#[test]
fn optional_selective_reuse_absence_preserves_legacy_acceptance() {
    for outcome in ["satisfied", "reused"] {
        let case = format!("selective_reuse absent / outcome={outcome}");
        let mut f = Fixture::new();
        f.decision["outcome"] = json!(outcome);
        if outcome == "reused" {
            f.decision["reason"] = json!("execution_reused");
            f.decision["summary"] =
                json!("Legacy realization reused; no fresh execution asserted.");
        }
        f.save();
        let out = f.execute("finalize", &[]);
        assert!(
            out.status.success(),
            "{case}: finalize: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let posts = f.posts();
        let payload = &posts
            .last()
            .unwrap_or_else(|| panic!("{case}: no published check"))["payload"];
        assert_eq!(payload["conclusion"], "success", "{case}");
        assert_eq!(
            payload["output"]["summary"], f.decision["summary"],
            "{case}"
        );
        let out = f.execute("report", &[]);
        assert_eq!(out.status.code(), Some(0), "{case}");
        let summary = fs::read_to_string(f.path("summary")).unwrap();
        assert!(!summary.contains("selective_reuse"), "{case}: {summary}");
    }
}

#[test]
fn selective_reuse_diagnostics_preserve_legacy_fallback_and_provenance() {
    for (status, reason) in [
        ("disabled", "receipt_contract_undefined"),
        ("refused", "reuse_candidate_unverified"),
    ] {
        for root in [None, Some("c".repeat(40))] {
            for accepted in [false, true] {
                let case = format!("status={status} / root={root:?} / accepted={accepted}");
                let mut f = Fixture::new();
                let mut diagnostic = json!({"version":1,"status":status,"reason":reason});
                let root_text = match &root {
                    Some(root) => {
                        diagnostic["root_record"] = json!(root);
                        format!(", \"root_record\": \"{root}\"")
                    }
                    None => String::new(),
                };
                // Exact CPython json.dumps default separators and insertion order.
                let diagnostic_text = format!(
                    "{{\"version\": 1, \"status\": \"{status}\", \"reason\": \"{reason}\"{root_text}}}"
                );
                f.decision["selective_reuse"] = diagnostic;
                f.decision["decision"] = json!(if accepted { "skip" } else { "run" });
                f.decision["outcome"] = json!(if accepted { "satisfied" } else { "unavailable" });
                f.save();
                let out = f.execute("finalize", &[]);
                assert_eq!(
                    out.status.code(),
                    Some(i32::from(!accepted)),
                    "{case}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                if !accepted {
                    assert!(
                        String::from_utf8_lossy(&out.stderr).contains("evidence refused"),
                        "{case}"
                    );
                }
                let posts = f.posts();
                let payload = &posts
                    .last()
                    .unwrap_or_else(|| panic!("{case}: no published check"))["payload"];
                assert_eq!(
                    payload["conclusion"],
                    if accepted { "success" } else { "failure" },
                    "{case}"
                );
                let summary = payload["output"]["summary"].as_str().unwrap();
                assert!(
                    summary.contains(f.decision["summary"].as_str().unwrap()),
                    "{case}: {summary}"
                );
                assert!(
                    summary.contains("not a fresh execution claim"),
                    "{case}: {summary}"
                );
                assert!(
                    summary.contains(&diagnostic_text),
                    "{case}: expected {diagnostic_text:?} in {summary:?}"
                );
                let out = f.execute("report", &[]);
                assert_eq!(out.status.code(), Some(i32::from(!accepted)), "{case}");
                let summary = fs::read_to_string(f.path("summary")).unwrap();
                assert!(
                    summary.contains("not a fresh execution claim"),
                    "{case}: {summary}"
                );
                assert!(summary.contains(reason), "{case}: {summary}");
                if let Some(root) = &root {
                    assert!(summary.contains(root), "{case}: {summary}");
                }
            }
        }
    }
}

#[test]
fn selective_reuse_validated_and_malformed_diagnostics_never_accept() {
    let valid = json!({"version":1,"status":"disabled","reason":"receipt_contract_undefined"});
    let mut cases = vec![
        ("null", Value::Null),
        ("array", json!([])),
        ("string", json!("disabled")),
        ("empty-object", json!({})),
    ];
    for (name, key, value) in [
        ("version-true", "version", json!(true)),
        ("version-two", "version", json!(2)),
        ("status-validated", "status", json!("validated")),
        ("status-success", "status", json!("success")),
        ("status-null", "status", Value::Null),
        ("status-array", "status", json!([])),
        ("reason-number", "reason", json!(1)),
        ("extra-key", "extra", json!("unexpected")),
    ] {
        let mut diagnostic = valid.clone();
        diagnostic[key] = value;
        cases.push((name, diagnostic));
    }
    let mut missing_reason = valid.clone();
    missing_reason.as_object_mut().unwrap().remove("reason");
    // Keep the case order identical to Python's invalid list.
    cases.insert(11, ("reason-missing", missing_reason));
    for (name, root) in [
        ("root-null", Value::Null),
        ("root-number", json!(1)),
        ("root-array", json!([])),
        ("root-short", json!("c".repeat(39))),
        ("root-uppercase", json!("C".repeat(40))),
        ("root-nonhex", json!("g".repeat(40))),
        ("root-newline", json!(format!("{}\n", "c".repeat(40)))),
    ] {
        let mut diagnostic = valid.clone();
        diagnostic["root_record"] = root;
        cases.push((name, diagnostic));
    }
    assert_eq!(cases.len(), 20);
    for (name, diagnostic) in cases {
        let case = format!("invalid selective_reuse / {name}: {diagnostic}");
        let mut f = Fixture::new();
        f.decision["selective_reuse"] = diagnostic;
        f.save();
        let out = f.execute("finalize", &[]);
        assert_eq!(out.status.code(), Some(1), "{case}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("evidence refused"),
            "{case}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let posts = f.posts();
        assert_eq!(
            posts
                .last()
                .unwrap_or_else(|| panic!("{case}: no published check"))["payload"]["conclusion"],
            "failure",
            "{case}"
        );
        let out = f.execute("report", &[]);
        assert_eq!(out.status.code(), Some(1), "{case}");
    }
}
#[test]
fn refusal_preserves_changed_workflow_summary() {
    let mut f = Fixture::new();
    f.decision["decision"] = json!("run");
    f.decision["outcome"] = json!("rejected");
    f.save();
    refusal(
        &f.execute("finalize", &[("GATE_SKIP", "false")]),
        "evidence refused",
    );
    let posts = f.posts();
    assert_eq!(posts[0]["payload"]["conclusion"], "failure");
    assert!(
        posts[0]["payload"]["output"]["summary"]
            .as_str()
            .unwrap()
            .contains(f.decision["summary"].as_str().unwrap())
    );
}
#[test]
fn stale_base_and_incomplete_gate_never_publish_success() {
    for env in [
        None,
        Some(("GATE_SKIP", "false")),
        Some(("GATE_OUTCOME", "failure")),
        Some(("APP_OUTCOME", "failure")),
    ] {
        let f = Fixture::new();
        let env: Vec<_> = env.into_iter().collect();
        if env.is_empty() {
            let mut routes: Value =
                serde_json::from_slice(&fs::read(f.path("routes.json")).unwrap()).unwrap();
            routes[format!("repos/{REPOSITORY}/git/ref/heads/main")]["object"]["sha"] =
                json!(f.head);
            fs::write(f.path("routes.json"), routes.to_string()).unwrap();
        }
        refusal(&f.execute("finalize", &env), "evidence refused");
        assert_eq!(
            f.posts().last().unwrap()["payload"]["conclusion"],
            "failure"
        );
    }
}
#[test]
fn app_placeholder_cannot_fall_back_to_workflow_token() {
    let f = Fixture::new();
    refusal(
        &f.execute("finalize", &[("APP_TOKEN", "")]),
        "not configured",
    );
    assert!(f.posts().is_empty());
}
#[test]
fn reporter_rejects_write_api_before_starting_a_process() {
    let f = Fixture::new();
    let prefix = source()
        .split_once("\ndef finalize():")
        .unwrap()
        .0
        .to_owned();
    let probe =
        format!("{prefix}\napi('repos/example/project/check-runs', {{'name': 'forbidden'}})\n");
    let out = f
        .command()
        .args(["-c", &probe, "report-prepare"])
        .env("GITHUB_EVENT_NAME", "pull_request")
        .output()
        .unwrap();
    refusal(&out, "reporter cannot write GitHub APIs");
    assert!(
        f.calls().is_empty(),
        "gh process started before the write guard"
    );
    assert!(!f.path("calls.jsonl").exists());
}
#[test]
fn reporter_fetches_only_objects_and_never_collects_hosted_or_publishes() {
    let f = Fixture::new();
    success(&f.execute("report-prepare", &[("GITHUB_EVENT_NAME", "pull_request")]));
    assert!(f.posts().is_empty());
    assert!(
        !f.calls()
            .iter()
            .any(|c| c["argv"].as_array().unwrap().iter().any(|v| v
                .as_str()
                .is_some_and(|s| s.contains("/reviews?") || s.contains("/check-runs?"))))
    );
    assert_eq!(git(&f.repo, &["rev-parse", "FETCH_HEAD"]), f.head);
    assert!(!f.repo.join("candidate").exists());
    assert!(!f.path("runner/generic-hosted-evidence.json").exists());
    let calls = f.git_calls();
    let fetch = calls
        .iter()
        .find(|call| call["argv"].as_array().unwrap().contains(&json!("fetch")))
        .unwrap();
    let argv = fetch["argv"].as_array().unwrap();
    assert!(argv.contains(&json!(f.head)));
    assert!(!argv.contains(&json!("checkout")));
    let reporter = source()
        .split_once("\ndef finalize():")
        .unwrap()
        .0
        .to_owned();
    assert!(!reporter.contains("def finalize("));
}
#[test]
fn reporter_summary_is_only_output_and_preserves_refusal() {
    let mut f = Fixture::new();
    for (decision, code) in [("skip", 0), ("refuse", 1)] {
        f.decision["decision"] = json!(decision);
        f.decision["summary"] = json!("<script>unsafe</script>");
        f.save();
        let out = f.execute("report", &[]);
        assert_eq!(out.status.code(), Some(code));
    }
    assert!(
        fs::read_to_string(f.path("summary"))
            .unwrap()
            .contains("&lt;script&gt;")
    );
    assert!(f.posts().is_empty());
}
#[test]
fn reporter_accepts_policy_allowed_reuse_without_asserting_freshness() {
    let mut f = Fixture::new();
    f.decision["outcome"] = json!("reused");
    f.decision["reason"] = json!("execution_reused");
    f.decision["summary"] = json!("A trusted realization was reused; no fresh execution asserted.");
    f.save();
    success(&f.execute("report", &[]));
    let summary = fs::read_to_string(f.path("summary")).unwrap();
    assert!(summary.contains("no fresh execution asserted"));
    assert!(summary.contains("execution_reused"));
    assert!(f.posts().is_empty());
}
#[test]
fn reporter_incomplete_gate_cannot_look_successful() {
    let f = Fixture::new();
    let out = f.execute("report", &[("GATE_OUTCOME", "failure")]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn golden_real_genie_workflow_object_matches_semantic_json() {
    let temporary = temporary();
    let work = temporary.path();
    let workflows = work.join(".github/workflows");
    fs::create_dir_all(&workflows).unwrap();
    let effect_utils =
        PathBuf::from(std::env::var_os("MERGEMASTER_EFFECT_UTILS").expect(
            "MERGEMASTER_EFFECT_UTILS must name the pinned source for the real Genie golden",
        ));
    assert!(effect_utils.is_dir());
    symlink(root().join("genie"), work.join("genie")).unwrap();
    fs::create_dir(work.join("repos")).unwrap();
    symlink(effect_utils, work.join("repos/effect-utils")).unwrap();
    let fixture = root().join("tests/fixtures/generic-evidence");
    fs::copy(
        fixture.join("generic.yml.genie.ts"),
        workflows.join("generic.yml.genie.ts"),
    )
    .unwrap();
    git(work, &["init", "-q"]);
    let formatter = Command::new("oxfmt")
        .arg("--version")
        .output()
        .expect("oxfmt is required for faithful Genie output; run in nix develop");
    success(&formatter);
    let out = Command::new("genie")
        .current_dir(work)
        .env("HOME", work)
        .output()
        .expect("genie is required for the real workflow golden; run in nix develop");
    success(&out);
    assert!(workflows.join("generic.yml").is_file());
    let mut actual: Value =
        serde_norway::from_slice(&fs::read(workflows.join("generic.yml")).unwrap()).unwrap();
    let publisher = &mut actual["jobs"]["generic-evidence"];
    for (index, mode) in [(1, "prepare"), (4, "finalize")] {
        let script = publisher["steps"][index]["run"].as_str().unwrap();
        let expected = format!(
            "python3 - {mode} <<'GENERIC_EVIDENCE_PY'\n{}\nGENERIC_EVIDENCE_PY",
            source()
        );
        assert_eq!(script.trim_end_matches('\n'), expected);
        publisher["steps"][index]["run"] = json!(
            script
                .replace(&source(), "<BASE-TRUSTED-PUBLISHER>\n")
                .trim_end_matches('\n')
        );
    }
    for job in actual["jobs"].as_object_mut().unwrap().values_mut() {
        for step in job["steps"].as_array_mut().unwrap() {
            if let Some(script) = step.get("run").and_then(Value::as_str) {
                step["run"] = json!(script.trim_end_matches('\n'));
            }
        }
    }
    let reporter = actual["jobs"]
        .as_object_mut()
        .unwrap()
        .remove("evidence-report")
        .unwrap();
    assert_eq!(reporter["if"], "github.event_name == 'pull_request'");
    assert_eq!(reporter["continue-on-error"], true);
    assert_eq!(
        reporter["permissions"],
        json!({"contents":"read","pull-requests":"read"})
    );
    assert_eq!(
        reporter["steps"][0]["with"]["ref"],
        "${{ github.event.pull_request.base.sha }}"
    );
    assert_eq!(reporter["steps"][0]["with"]["persist-credentials"], false);
    let prepare = reporter["steps"][1]["run"].as_str().unwrap();
    assert!(prepare.contains("report-prepare"));
    assert!(!prepare.contains("\ndef finalize():"));
    assert!(!prepare.contains("gh release"));
    assert!(
        !reporter["steps"][2]["run"]
            .as_str()
            .unwrap()
            .contains("--hosted-evidence")
    );
    assert_eq!(reporter["steps"][3]["if"], "always()");
    let expected: Value =
        serde_json::from_slice(&fs::read(fixture.join("generic.yml")).unwrap()).unwrap();
    assert_eq!(
        actual, expected,
        "Generic generated workflow differs from semantic golden"
    );
}
