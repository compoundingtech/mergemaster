//! Assertion-for-assertion port of scripts/ci-evidence-observe-test; real Git packs and SSH signatures.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn environment(command: &mut Command) -> &mut Command {
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("LC_ALL", "C")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
}
fn gitb(repo: &Path, args: &[&str], input: Option<&[u8]>) -> Vec<u8> {
    let mut cmd = Command::new("git");
    environment(&mut cmd)
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}
fn git(repo: &Path, args: &[&str]) -> String {
    String::from_utf8(gitb(repo, args, None))
        .unwrap()
        .trim()
        .to_owned()
}
fn executable(path: &Path, body: &str) {
    let staged = path.with_extension("tmp");
    fs::write(&staged, body).unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).unwrap();
    fs::rename(staged, path).unwrap();
}
struct Fixture {
    root: tempfile::TempDir,
    source: PathBuf,
    commit: String,
    tree: String,
    full: String,
    degraded: String,
}
impl Fixture {
    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        git(root.path(), &["init", "-q", source.to_str().unwrap()]);
        fs::write(source.join("a"), "one\n").unwrap();
        git(&source, &["add", "a"]);
        git(&source, &["commit", "-qm", "one"]);
        fs::write(source.join("a"), "two\n").unwrap();
        git(&source, &["commit", "-qam", "two"]);
        let commit = git(&source, &["rev-parse", "HEAD"]);
        let tree = git(&source, &["rev-parse", "HEAD^{tree}"]);
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(root.path().join("key"))
            .status()
            .unwrap();
        assert!(status.success());
        let public = fs::read_to_string(root.path().join("key.pub")).unwrap();
        let pubkey: Vec<_> = public.split_whitespace().collect();
        fs::write(
            root.path().join("allowed"),
            format!(
                "machine/ci-test namespaces=\"git\" {} {}\n",
                pubkey[0], pubkey[1]
            ),
        )
        .unwrap();
        fs::create_dir(root.path().join("bin")).unwrap();
        executable(
            &root.path().join("bin/gh"),
            r##"#!/bin/sh
if [ "$1" = run ]; then printf '%s\n' "${GH_RUNS:-[]}"; exit 0; fi
if [ "$1" = auth ]; then if [ "$BAD_AUTH_UTF8" = 1 ]; then printf '\377'; else printf '%s\n' fixture-token; fi; exit 0; fi
case "$2" in
  */artifacts\?*) if [ -n "$GH_ARTIFACTS" ]; then printf '%s\n' "$GH_ARTIFACTS"; else printf '{"artifacts":[{"name":"ci-evidence-source-1","id":9,"expired":false}]}\n'; fi;;
  */jobs\?*) case "$2" in *'&page=1') if [ -n "$GH_JOBS" ]; then printf '%s\n' "$GH_JOBS"; else printf '{"jobs":[]}\n'; fi;; *) printf '{"jobs":[]}\n';; esac;;
  */attempts/*) printf '{"conclusion":"%s"}\n' "${GH_CONCLUSION:-success}";;
  *) printf '{"run_attempt":1,"name":"%s"}\n' "${GH_RUN_NAME:-Workspace CI}";;
esac
"##,
        );
        executable(
            &root.path().join("observer"),
            r##"#!/bin/sh
while [ "$#" -gt 0 ]; do if [ "$1" = --run ] && [ "$2" = 8 ]; then echo 'observer cannot read run 8' >&2; exit 1; fi; shift; done
if [ -n "$OBSERVER_EXIT" ]; then echo 'missing or ambiguous CI job: linux-gate' >&2; exit "$OBSERVER_EXIT"; fi
cat "$FIXTURE/response.json"
"##,
        );
        executable(
            &root.path().join("verifier"),
            r##"#!/bin/sh
[ "$1" = legacy-evidence-verify ] || exit 90
shift
printf 'CALL\n' >> "$FIXTURE/calls"
printf '%s\n' "$@" >> "$FIXTURE/calls"
if [ -n "$VERIFIER_OUTPUT" ]; then cat "$VERIFIER_OUTPUT"; exit "${VERIFIER_EXIT:-0}"; fi
if [ "$VERIFIER_OK" = 1 ]; then echo '{"satisfied":true,"reason":"no_record"}'; else echo '{"satisfied":false,"reason":"no_record"}'; exit 1; fi
"##,
        );
        let mut fixture = Self {
            root,
            source,
            commit,
            tree,
            full: String::new(),
            degraded: String::new(),
        };
        fixture.full = fixture.record("full", "linux-gate", true);
        fixture.degraded = fixture.record("degraded", "typescript-client", false);
        fixture
    }
    fn record(&self, tier: &str, check: &str, signed: bool) -> String {
        self.record_kind(tier, check, signed, "tests")
    }
    fn record_kind(&self, tier: &str, check: &str, signed: bool, kind: &str) -> String {
        let body = json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":self.commit,"digest":{"gitTree":self.tree}}],"predicateType":"https://smalltalk.dev/evidence/gate/v1","predicate":{"schema_version":1,"change_id":"github:example/repo#1","signer":if signed {json!("machine/ci-test")} else {Value::Null},"tier":tier,"re_attests":null,"producer_sha256":"0".repeat(64),"observed_at":"2026-10-14T10:00:00Z","observed":{"kind":kind,"runner":"ci","inputs":{},"checks":{check:{"command":["gh","job"],"exit_code":0,"output_sha256":"1".repeat(64)}}}}});
        self.record_body(&body, signed)
    }
    fn record_body(&self, body: &Value, signed: bool) -> String {
        let blob = String::from_utf8(gitb(
            &self.source,
            &["hash-object", "-w", "--stdin"],
            Some(&serde_json::to_vec(&body).unwrap()),
        ))
        .unwrap();
        let tree = String::from_utf8(gitb(
            &self.source,
            &["mktree"],
            Some(format!("100644 blob {}\t{}\n", blob.trim(), self.tree).as_bytes()),
        ))
        .unwrap();
        let key = format!("user.signingKey={}", self.path("key").display());
        let mut args = vec!["-c", "gpg.format=ssh", "-c", &key, "commit-tree"];
        if signed {
            args.push("-S");
        }
        args.extend([tree.trim(), "-p", &self.commit]);
        String::from_utf8(gitb(&self.source, &args, Some(b"st gate observation v1\n")))
            .unwrap()
            .trim()
            .to_owned()
    }
    fn pack(&self, records: &[&str]) -> Vec<u8> {
        let mut objects = format!(
            "{}\n{}",
            self.commit,
            git(
                &self.source,
                &["rev-list", "--objects", "--no-object-names", &self.tree]
            )
        );
        objects.push('\n');
        for record in records {
            objects.push_str(&format!(
                "{record}\n{}\n",
                git(
                    &self.source,
                    &[
                        "rev-list",
                        "--objects",
                        "--no-object-names",
                        &format!("{record}^{{tree}}")
                    ]
                )
            ));
        }
        gitb(
            &self.source,
            &["pack-objects", "--stdout"],
            Some(objects.as_bytes()),
        )
    }
    fn answer(&self, records: &[(&str, &str)]) -> Value {
        json!({"repository":"example/repo","run":7,"attempt":1,"source":self.commit,"tree":self.tree,"full_trust_eligible":true,"trust_limitation":null,"records":records.iter().map(|(r,t)|json!({"record":r,"tier":t,"signing_unavailable":false,"signing_latency_ms":3,"newly_recorded":true})).collect::<Vec<_>>(),"object_pack_base64":STANDARD.encode(self.pack(&records.iter().map(|(r,_)| *r).collect::<Vec<_>>())),"metrics":{"fresh_records":records.len(),"full_records":1}})
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mergemaster"));
        environment(&mut cmd)
            .args([
                "evidence",
                "observe",
                "--repository",
                "example/repo",
                "--observer",
                &json!([self.path("observer")]).to_string(),
                "--verifier",
            ])
            .arg(self.path("verifier"))
            .arg("--state-dir")
            .arg(self.path("state"))
            .env("FIXTURE", self.root.path())
            .env("VERIFIER_OK", "1")
            .env("GH_TOKEN", "fixture-token")
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.path("bin").display(),
                    std::env::var("PATH").unwrap()
                ),
            )
            .env_remove("GITHUB_STEP_SUMMARY")
            .current_dir(self.root.path());
        cmd
    }
    fn execute(
        &self,
        response: &Value,
        scratch: &str,
        extra: &[&str],
        env: &[(&str, &str)],
    ) -> (Output, Value) {
        let out = self.execute_raw(response, scratch, extra, env);
        let value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "{e}: {} / {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out, value)
    }
    fn execute_raw(
        &self,
        response: &Value,
        scratch: &str,
        extra: &[&str],
        env: &[(&str, &str)],
    ) -> Output {
        fs::write(
            self.path("response.json"),
            serde_json::to_vec(response).unwrap(),
        )
        .unwrap();
        fs::write(self.path("calls"), "").unwrap();
        self.command()
            .args(["--run", "7", "--attempt", "1", "--artifact", "9", "--keys"])
            .arg(self.path("allowed"))
            .arg("--scratch")
            .arg(self.path(scratch))
            .args(extra)
            .envs(env.iter().copied())
            .output()
            .unwrap()
    }
    fn remote(&self, name: &str) -> PathBuf {
        let remote = self.path(name);
        git(
            self.root.path(),
            &["init", "-q", "--bare", remote.to_str().unwrap()],
        );
        git(
            &remote,
            &["config", "uploadpack.allowAnySHA1InWant", "true"],
        );
        git(
            &self.source,
            &[
                "push",
                "-q",
                remote.to_str().unwrap(),
                "HEAD~1:refs/heads/main",
            ],
        );
        remote
    }
    fn names(&self, records: &[&str]) -> String {
        let mut names: Vec<_> = records
            .iter()
            .flat_map(|r| {
                [
                    format!("refs/notes/evidence/{}/{r} {r}", self.tree),
                    format!("refs/tags/evidence/{}/{r} {r}", self.tree),
                ]
            })
            .collect();
        names.sort();
        names.join("\n")
    }
}
fn success(out: &Output) {
    assert!(
        out.status.success(),
        "{} / {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
fn failure(out: &Output, value: &Value, message: &str) {
    assert_eq!(out.status.code(), Some(1));
    assert!(
        value["failures"][0].as_str().unwrap().contains(message),
        "{value}"
    );
}

#[test]
fn full_and_degraded_records() {
    let f = Fixture::new();
    let response = f.answer(&[(&f.full, "full"), (&f.degraded, "degraded")]);
    let (out, value) = f.execute(&response, "ok", &[], &[]);
    success(&out);
    assert_eq!(
        git(
            &f.path("ok"),
            &["for-each-ref", "--format=%(refname) %(objectname)"]
        ),
        f.names(&[&f.full, &f.degraded])
    );
    let calls = fs::read_to_string(f.path("calls")).unwrap();
    assert_eq!(calls.lines().filter(|line| *line == "CALL").count(), 1);
    let args: Vec<_> = calls.lines().skip(1).collect();
    let check = args.iter().position(|a| *a == "--check").unwrap();
    assert_eq!(args[check + 1], "linux-gate");
    assert!(args.contains(&f.tree.as_str()));
    assert_eq!(value["records"][0]["verified"], true);
    assert_eq!(value["records"][1]["verified"], false);
    let (out, value) = f.execute(
        &f.answer(&[(&f.full, "full")]),
        "refused",
        &[],
        &[("VERIFIER_OK", "0")],
    );
    failure(&out, &value, "did not verify");
    assert_eq!(git(&f.path("refused"), &["for-each-ref"]), "");
}
#[test]
fn response_identity_pack_tier_and_cancellation() {
    let f = Fixture::new();
    let response = f.answer(&[(&f.full, "full")]);
    let mut bad = response.clone();
    bad["run"] = json!(8);
    let (out, v) = f.execute(&bad, "wrongrun", &[], &[]);
    failure(&out, &v, "not 7");
    let mut bad = response.clone();
    bad["object_pack_base64"] = json!(STANDARD.encode(b"not a pack"));
    let (out, v) = f.execute(&bad, "garbage", &[], &[]);
    failure(&out, &v, "git index-pack");
    let mut bad = response.clone();
    bad["records"][0]["tier"] = json!("bogus");
    let (out, v) = f.execute(&bad, "tier", &[], &[]);
    failure(&out, &v, "unexpected tier");
    for conclusion in ["cancelled", "skipped"] {
        let (out, v) = f.execute(
            &response,
            conclusion,
            &[],
            &[("OBSERVER_EXIT", "2"), ("GH_CONCLUSION", conclusion)],
        );
        success(&out);
        assert!(
            v["nothing_to_attest"]
                .as_str()
                .unwrap()
                .contains("cancelled")
        );
        assert!(v.get("failures").is_none());
    }
    let (out, v) = f.execute(
        &response,
        "broken",
        &[],
        &[("OBSERVER_EXIT", "2"), ("GH_CONCLUSION", "success")],
    );
    failure(&out, &v, "linux-gate");
}
#[test]
fn missing_history_stale_scratch_and_immutable_refs() {
    let f = Fixture::new();
    let response = f.answer(&[(&f.full, "full")]);
    let remote = f.remote("remote.git");
    let remote = remote.to_str().unwrap();
    let (out, v) = f.execute(&response, "pushed", &["--remote", remote], &[]);
    success(&out);
    assert_eq!(v["published"], 1);
    assert_eq!(
        git(
            Path::new(remote),
            &["for-each-ref", "--format=%(refname)", "refs/notes/"]
        ),
        format!("refs/notes/evidence/{}/{}", f.tree, f.full)
    );
    assert_eq!(
        git(
            Path::new(remote),
            &[
                "for-each-ref",
                "--format=%(refname) %(objectname)",
                "refs/tags/"
            ]
        ),
        format!("refs/tags/evidence/{}/{} {}", f.tree, f.full, f.full)
    );
    let (out, _) = f.execute(&response, "stale", &[], &[]);
    success(&out);
    assert_eq!(
        git(
            &f.path("stale"),
            &["for-each-ref", "--format=%(refname) %(objectname)"]
        ),
        f.names(&[&f.full])
    );
    let other = f.remote("other.git");
    let (out, v) = f.execute(
        &response,
        "stale",
        &["--remote", other.to_str().unwrap()],
        &[],
    );
    success(&out);
    assert_eq!(v["published"], 1);
    assert_eq!(
        git(
            &other,
            &["for-each-ref", "--format=%(refname)", "refs/notes/"]
        ),
        format!("refs/notes/evidence/{}/{}", f.tree, f.full)
    );
    let (out, _) = f.execute(&response, "pushed", &["--remote", remote], &[]);
    success(&out);
    for (space, check) in [("notes", "another"), ("tags", "third")] {
        let record = f.record("full", check, true);
        let name = format!("refs/{space}/evidence/{}/{record}", f.tree);
        git(&f.path("pushed"), &["update-ref", &name, &f.full]);
        let (out, v) = f.execute(&f.answer(&[(&record, "full")]), "pushed", &[], &[]);
        failure(&out, &v, "never replaced");
        assert!(
            v["failures"][0]
                .as_str()
                .unwrap()
                .contains(&format!("{name} already names"))
        );
        assert_eq!(git(&f.path("pushed"), &["rev-parse", &name]), f.full);
        if space == "tags" {
            assert_eq!(
                git(
                    &f.path("pushed"),
                    &[
                        "for-each-ref",
                        &format!("refs/notes/evidence/{}/{record}", f.tree)
                    ]
                ),
                ""
            );
        }
    }
}
#[test]
fn checkout_keys_and_missing_keys_fail_closed() {
    let f = Fixture::new();
    fs::write(
        f.path("response.json"),
        serde_json::to_vec(&f.answer(&[(&f.full, "full")])).unwrap(),
    )
    .unwrap();
    for directory in [".st", ".fractal"] {
        let checkout = f.path(directory);
        fs::create_dir(&checkout).unwrap();
        git(&checkout, &["init", "-q"]);
        fs::create_dir(checkout.join(directory)).unwrap();
        fs::copy(
            f.path("allowed"),
            checkout.join(directory).join("evidence-keys"),
        )
        .unwrap();
        git(&checkout, &["add", "."]);
        git(&checkout, &["commit", "-qm", "keys"]);
        fs::write(f.path("calls"), "").unwrap();
        let out = f
            .command()
            .args([
                "--run",
                "7",
                "--attempt",
                "1",
                "--artifact",
                "9",
                "--scratch",
            ])
            .arg(f.path(&format!("keys-{directory}")))
            .current_dir(checkout)
            .output()
            .unwrap();
        success(&out);
        let calls = fs::read_to_string(f.path("calls")).unwrap();
        let argv: Vec<_> = calls.lines().skip(1).collect();
        let pos = argv.iter().position(|s| *s == "--keys").unwrap();
        assert_ne!(argv[pos + 1], f.path("allowed").to_str().unwrap());
        assert!(!argv.contains(&"--keys-from"));
    }
    let empty = f.path("nokeys");
    fs::create_dir(&empty).unwrap();
    git(&empty, &["init", "-q"]);
    git(&empty, &["commit", "-q", "--allow-empty", "-m", "none"]);
    let out = f
        .command()
        .args([
            "--run",
            "7",
            "--attempt",
            "1",
            "--artifact",
            "9",
            "--scratch",
        ])
        .arg(f.path("nokeys-scratch"))
        .current_dir(empty)
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    failure(&out, &v, "git show");
    assert!(
        v["failures"][0]
            .as_str()
            .unwrap()
            .contains(".st/evidence-keys")
    );
}
#[test]
fn poll_caps_failures_and_never_retries_done_or_cancelled() {
    let f = Fixture::new();
    let remote = f.remote("remote.git");
    fs::write(
        f.path("response.json"),
        serde_json::to_vec(&f.answer(&[(&f.full, "full")])).unwrap(),
    )
    .unwrap();
    let runs=json!([{"databaseId":9,"attempt":1,"conclusion":"cancelled"},{"databaseId":8,"attempt":1,"conclusion":"failure"},{"databaseId":7,"attempt":1,"conclusion":"success"}]).to_string();
    let timer = || {
        let out = f
            .command()
            .args(["--poll", "--keys"])
            .arg(f.path("allowed"))
            .arg("--remote")
            .arg(&remote)
            .env("GH_RUNS", &runs)
            .output()
            .unwrap();
        let lines: Vec<Value> = String::from_utf8(out.stdout.clone())
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        (out, lines)
    };
    let (out, lines) = timer();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        lines
            .iter()
            .map(|v| (v["run"].as_i64().unwrap(), v["state"].as_str().unwrap()))
            .collect::<Vec<_>>(),
        [(7, "done"), (8, "failed")]
    );
    assert_eq!(
        git(
            &remote,
            &["for-each-ref", "--format=%(refname)", "refs/notes/"]
        ),
        format!("refs/notes/evidence/{}/{}", f.tree, f.full)
    );
    for state in ["failed", "gave_up"] {
        let (out, lines) = timer();
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["run"], 8);
        assert_eq!(lines[0]["state"], state);
    }
    let (out, lines) = timer();
    success(&out);
    assert!(lines.is_empty());
    let ledger: Vec<Value> = fs::read_to_string(f.path("state/observed.jsonl"))
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(ledger.iter().filter(|e| e["run"] == 8).count(), 3);
    assert!(!ledger.iter().any(|e| e["run"] == 9));
}
fn jobs(entries: &[(&str, &str, &str)]) -> String {
    json!({"jobs":entries.iter().map(|(name,step,conclusion)|json!({"name":name,"steps":[{"name":step,"conclusion":conclusion}]})).collect::<Vec<_>>()}).to_string()
}
#[test]
fn independent_skip_signals_and_workflow_guard_fail_closed() {
    let f = Fixture::new();
    let remote = f.remote("remote.git");
    let response = f.answer(&[(&f.full, "full")]);
    for (scratch, metadata) in [
        (
            "skip-taken",
            jobs(&[
                ("evidence-gate-linux-gate", "evidence skip taken", "success"),
                ("linux-tests", "evidence skip taken", "success"),
            ]),
        ),
        (
            "covered",
            jobs(&[
                ("evidence-gate-linux-gate", "Verify", "success"),
                (
                    "linux-gate",
                    "evidence covered by a trusted note",
                    "success",
                ),
            ]),
        ),
    ] {
        let (out, v) = f.execute(
            &response,
            scratch,
            &["--remote", remote.to_str().unwrap()],
            &[("GH_JOBS", &metadata)],
        );
        success(&out);
        assert_eq!(v["records"], json!([]));
        assert_eq!(v["skip_taken"][0]["checks"], json!(["linux-gate"]));
        assert_eq!(v["published"], 0);
        assert_eq!(
            git(&f.path(scratch), &["for-each-ref", "refs/notes/evidence/"]),
            ""
        );
    }
    for (scratch, metadata) in [
        (
            "not-covered",
            jobs(&[(
                "linux-gate",
                "evidence covered by a trusted note",
                "skipped",
            )]),
        ),
        (
            "skip-not-taken",
            jobs(&[("evidence-gate-linux-gate", "evidence skip taken", "skipped")]),
        ),
    ] {
        let (out, v) = f.execute(&response, scratch, &[], &[("GH_JOBS", &metadata)]);
        success(&out);
        assert_eq!(v["records"].as_array().unwrap().len(), 1);
        assert!(v.get("skip_taken").is_none());
    }
    let (out, v) = f.execute(
        &response,
        "wrong-workflow",
        &[],
        &[("GH_RUN_NAME", "Evidence observe")],
    );
    failure(&out, &v, "never acting on any other workflow");
    let (out, v) = f.execute(
        &response,
        "unreadable-jobs",
        &[],
        &[("GH_JOBS", "not json")],
    );
    failure(&out, &v, "skips cannot be ruled out");
}
#[test]
fn cli_selection_usage_and_metadata_defaults() {
    let f = Fixture::new();
    for args in [
        vec![],
        vec!["--run", "7", "--poll"],
        vec!["--run", "0"],
        vec!["--attempt", "invalid"],
    ] {
        let out = f.command().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("ci-evidence-observe: error:"));
    }
    fs::write(
        f.path("response.json"),
        serde_json::to_vec(&f.answer(&[(&f.full, "full")])).unwrap(),
    )
    .unwrap();
    let out = f
        .command()
        .args(["--run", "7", "--keys"])
        .arg(f.path("allowed"))
        .output()
        .unwrap();
    success(&out);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["attempt"], 1);
    assert_eq!(v["records"].as_array().unwrap().len(), 1);
}

#[test]
fn pinned_native_verifier_checks_real_ssh_signatures() {
    let f = Fixture::new();
    let blob = git(&f.source, &["show", &format!("{}:{}", f.full, f.tree)]);
    let mut body: Value = serde_json::from_str(&blob).unwrap();
    body["predicate"]["observed"]["runner"] = json!("github:example/repo/actions/runs/7");
    let valid = f.record_body(&body, true);
    // Like Python, observe verifies before creating publication refs. The real
    // verifier needs an existing discovery ref; importing a pack creates none.
    let seed = |scratch: &str, record: &str| {
        let repo = f.path(scratch);
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q", "--bare"]);
        gitb(&repo, &["index-pack", "--stdin"], Some(&f.pack(&[record])));
        let name = format!("refs/tags/evidence/{}/{record}", f.tree);
        git(&repo, &["update-ref", &name, record]);
        name
    };
    seed("native-verifier", &valid);
    let (out, value) = f.execute(
        &f.answer(&[(&valid, "full")]),
        "native-verifier",
        &["--verifier", env!("CARGO_BIN_EXE_mergemaster")],
        &[],
    );
    success(&out);
    assert_eq!(value["records"][0]["verified"], true);
    let unsigned = f.record_body(&body, false);
    let existing = seed("native-refusal", &unsigned);
    let (out, value) = f.execute(
        &f.answer(&[(&unsigned, "full")]),
        "native-refusal",
        &["--verifier", env!("CARGO_BIN_EXE_mergemaster")],
        &[],
    );
    failure(&out, &value, "did not verify: bad_signature");
    assert_eq!(
        git(
            &f.path("native-refusal"),
            &["for-each-ref", "--format=%(refname)"]
        ),
        existing
    );
}

#[test]
fn github_summary_and_partial_record_failure() {
    let f = Fixture::new();
    let mut response = f.answer(&[(&f.full, "full"), (&f.degraded, "degraded")]);
    response["trust_limitation"] = json!("fixture limitation");
    let summary = f.path("summary");
    let (out, value) = f.execute(
        &response,
        "summary-scratch",
        &[],
        &[
            ("VERIFIER_OK", "0"),
            ("GITHUB_STEP_SUMMARY", summary.to_str().unwrap()),
        ],
    );
    failure(&out, &value, "did not verify");
    assert_eq!(
        git(
            &f.path("summary-scratch"),
            &["for-each-ref", "--format=%(refname) %(objectname)"]
        ),
        f.names(&[&f.degraded])
    );
    assert_eq!(value["metrics"], response["metrics"]);
    assert_eq!(value["full_trust_eligible"], true);
    assert_eq!(value["trust_limitation"], "fixture limitation");
    let expected = format!(
        "### Evidence observation of run 7 attempt 1\n- `linux-gate` full NOT VERIFIED: `{}`\n- `typescript-client` degraded unsigned, not verified: `{}`\n- fresh 2, full 1, signing latency None ms\n- trust limitation: fixture limitation\n- **failure:** record for linux-gate on {} did not verify: no_record\n",
        f.full, f.degraded, f.tree
    );
    assert_eq!(fs::read_to_string(summary).unwrap(), expected);
}

#[test]
fn malformed_observer_arguments_json_and_record_ids_are_refused() {
    let f = Fixture::new();
    let response = f.answer(&[(&f.full, "full")]);
    for observer in ["[]", "[1]", "{}"] {
        let (out, value) = f.execute(&response, "observer-args", &["--observer", observer], &[]);
        failure(&out, &value, "--observer must be a JSON array of strings");
    }
    executable(&f.path("bad-observer"), "#!/bin/sh\nprintf 'not json'\n");
    let (out, value) = f.execute(
        &response,
        "bad-json",
        &["--observer", &json!([f.path("bad-observer")]).to_string()],
        &[],
    );
    failure(
        &out,
        &value,
        "observer printed no JSON document: Expecting value: line 1 column 1 (char 0)",
    );
    let mut bad = response;
    bad["records"][0]["record"] = json!("A".repeat(40));
    let (out, value) = f.execute(&bad, "record-id", &[], &[]);
    failure(&out, &value, "observer returned a malformed record id");
}

#[test]
fn missing_subject_name_aborts_without_remote() {
    let f = Fixture::new();
    let blob = git(&f.source, &["show", &format!("{}:{}", f.degraded, f.tree)]);
    let mut body: Value = serde_json::from_str(&blob).unwrap();
    body["subject"][0].as_object_mut().unwrap().remove("name");
    let record = f.record_body(&body, false);
    let (out, value) = f.execute(
        &f.answer(&[(&record, "degraded")]),
        "missing-name",
        &[],
        &[],
    );
    failure(&out, &value, "'name'");
    assert_eq!(value["records"], json!([]));
    assert!(git(&f.path("missing-name"), &["for-each-ref"]).is_empty());
}

#[test]
fn malformed_steps_abort_before_observation() {
    let f = Fixture::new();
    fs::write(
        f.path("response.json"),
        serde_json::to_vec(&f.answer(&[(&f.degraded, "degraded")])).unwrap(),
    )
    .unwrap();
    for steps in [
        Value::Null,
        json!({}),
        json!("bad"),
        json!([null]),
        json!([1]),
    ] {
        let out = f
            .command()
            .args(["--run", "7", "--attempt", "1"])
            .env(
                "GH_JOBS",
                json!({"jobs":[{"name":"job","steps":steps}]}).to_string(),
            )
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("TypeError:"));
        assert!(!f.path("state/scratch.git").exists());
    }
    let (out, _) = f.execute(
        &f.answer(&[]),
        "missing-steps",
        &[],
        &[("GH_JOBS", r#"{"jobs":[{"name":"job"}]}"#)],
    );
    success(&out);
}

#[test]
fn missing_verifier_stops_before_later_records_and_push() {
    let f = Fixture::new();
    let remote = f.remote("fatal-verifier-remote");
    let (out, value) = f.execute(
        &f.answer(&[(&f.full, "full"), (&f.degraded, "degraded")]),
        "fatal-verifier",
        &[
            "--verifier",
            "/nonexistent",
            "--remote",
            remote.to_str().unwrap(),
        ],
        &[],
    );
    failure(&out, &value, "/nonexistent");
    assert_eq!(value["records"].as_array().unwrap().len(), 1);
    assert!(value["records"][0].get("error").is_none());
    assert!(git(&f.path("fatal-verifier"), &["for-each-ref"]).is_empty());
    assert!(
        git(
            &remote,
            &["for-each-ref", "refs/tags/evidence", "refs/notes/evidence"]
        )
        .is_empty()
    );
}

#[test]
fn json_output_matches_python_bytes_and_ascii() {
    let f = Fixture::new();
    let mut response = f.answer(&[]);
    response["trust_limitation"] = json!("é😀");
    let (out, _) = f.execute(&response, "json-output", &[], &[]);
    success(&out);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "{\n  \"repository\": \"example/repo\",\n  \"run\": 7,\n  \"attempt\": 1,\n  \"records\": [],\n  \"metrics\": {\n    \"fresh_records\": 0,\n    \"full_records\": 1\n  },\n  \"full_trust_eligible\": true,\n  \"trust_limitation\": \"\\u00e9\\ud83d\\ude00\",\n  \"published\": 0\n}\n"
    );
    let out = f
        .command()
        .arg("--poll")
        .env(
            "GH_RUNS",
            r#"[{"databaseId":7,"attempt":1,"conclusion":"success"}]"#,
        )
        .output()
        .unwrap();
    success(&out);
    assert_eq!(
        out.stdout,
        b"{\"run\": 7, \"attempt\": 1, \"state\": \"done\", \"records\": 0, \"failures\": []}\n"
    );
    assert_eq!(
        fs::read(f.path("state/observed.jsonl")).unwrap(),
        b"{\"run\": 7, \"attempt\": 1, \"state\": \"done\", \"tries\": 0, \"records\": []}\n"
    );
}

#[test]
fn remote_failure_masks_token_in_every_output() {
    let f = Fixture::new();
    executable(
        &f.path("bin/git"),
        "#!/bin/sh\ncase \" $* \" in *' push '*) printf '%s\\n' \"$GH_TOKEN\" >&2; exit 1;; esac\nexec \"$REAL_GIT\" \"$@\"\n",
    );
    let real_git = Command::new("sh")
        .args(["-c", "command -v git"])
        .output()
        .unwrap();
    let real_git = String::from_utf8(real_git.stdout).unwrap();
    let summary = f.path("masked-summary");
    let (out, value) = f.execute(
        &f.answer(&[(&f.degraded, "degraded")]),
        "masked",
        &["--remote", f.source.to_str().unwrap()],
        &[
            ("REAL_GIT", real_git.trim()),
            ("GITHUB_STEP_SUMMARY", summary.to_str().unwrap()),
        ],
    );
    failure(&out, &value, "***");
    for bytes in [
        &out.stdout,
        &out.stderr,
        &fs::read(summary).unwrap(),
        &serde_json::to_vec(&value["failures"]).unwrap(),
    ] {
        assert!(!String::from_utf8_lossy(bytes).contains("fixture-token"));
    }
}

#[test]
fn invalid_job_and_unhashable_successful_step_names_abort() {
    let f = Fixture::new();
    let response = f.answer(&[(&f.degraded, "degraded")]);
    for jobs in [
        json!({"jobs":[{"name":null,"steps":[]}]}),
        json!({"jobs":[{"name":7,"steps":[]}]}),
        json!({"jobs":[{"name":"job","steps":[{"name":[],"conclusion":"success"}]}]}),
        json!({"jobs":[{"name":"job","steps":[{"name":{},"conclusion":"success"}]}]}),
        json!({"jobs":null}),
    ] {
        let out = f.execute_raw(
            &response,
            "bad-job-names",
            &[],
            &[("GH_JOBS", &jobs.to_string())],
        );
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("TypeError:") || stderr.contains("AttributeError:"),
            "{stderr}"
        );
        assert!(!f.path("bad-job-names").exists());
    }
    for name in [json!(7), Value::Null, json!(false)] {
        let jobs = json!({"jobs":[{"name":"job","steps":[{"name":name,"conclusion":"success"}]}]});
        let (out, _) = f.execute(
            &response,
            "hashable-step-names",
            &[],
            &[("GH_JOBS", &jobs.to_string())],
        );
        success(&out);
    }
    let jobs = json!({"jobs":[{"name":"job","steps":[{"name":[],"conclusion":"skipped"}]}]});
    let (out, _) = f.execute(
        &response,
        "unsuccessful-unhashable-name",
        &[],
        &[("GH_JOBS", &jobs.to_string())],
    );
    success(&out);
}

#[test]
fn non_object_artifact_entry_aborts_before_observation() {
    let f = Fixture::new();
    let remote = f.remote("artifact-entry-remote");
    fs::write(
        f.path("response.json"),
        serde_json::to_vec(&f.answer(&[(&f.degraded, "degraded")])).unwrap(),
    )
    .unwrap();
    let out = f
        .command()
        .args(["--run", "7", "--attempt", "1", "--keys"])
        .arg(f.path("allowed"))
        .arg("--remote")
        .arg(&remote)
        .env(
            "GH_ARTIFACTS",
            r#"{"artifacts":[null,{"name":"ci-evidence-source-1","id":9,"expired":false}]}"#,
        )
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("TypeError:"));
    assert!(!f.path("state/scratch.git").exists());
    assert!(
        git(
            &remote,
            &["for-each-ref", "refs/tags/evidence", "refs/notes/evidence"]
        )
        .is_empty()
    );
}

#[test]
fn poll_rejects_truthy_non_integer_attempts_and_preserves_falsy_default() {
    let f = Fixture::new();
    let remote = f.remote("poll-attempt-remote");
    fs::write(
        f.path("response.json"),
        serde_json::to_vec(&f.answer(&[(&f.degraded, "degraded")])).unwrap(),
    )
    .unwrap();
    for attempt in [
        json!("2"),
        json!(true),
        json!(1.5),
        json!([1]),
        json!({"x":1}),
    ] {
        let out = f
            .command()
            .arg("--poll")
            .arg("--remote")
            .arg(&remote)
            .env(
                "GH_RUNS",
                json!([{"databaseId":7,"attempt":attempt,"conclusion":"success"}]).to_string(),
            )
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(!f.path("state/scratch.git").exists());
        assert!(
            git(
                &remote,
                &["for-each-ref", "refs/tags/evidence", "refs/notes/evidence"]
            )
            .is_empty()
        );
    }
    for (index, attempt) in [
        Value::Null,
        json!(0),
        json!(""),
        json!([]),
        json!({}),
        json!(false),
    ]
    .into_iter()
    .enumerate()
    {
        let out = f
            .command()
            .arg("--poll")
            .arg("--state-dir")
            .arg(f.path(&format!("falsy-attempt-{index}")))
            .env(
                "GH_RUNS",
                json!([{"databaseId":7,"attempt":attempt,"conclusion":"success"}]).to_string(),
            )
            .output()
            .unwrap();
        success(&out);
        let result: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(result["attempt"], 1);
    }
}

#[test]
fn python_parsable_non_object_verifier_answers_abort_before_later_records() {
    let f = Fixture::new();
    let remote = f.remote("verifier-json-remote");
    let response = f.answer(&[(&f.full, "full"), (&f.degraded, "degraded")]);
    let output = f.path("verifier-output");
    let mut payloads = vec![
        b"NaN".to_vec(),
        b"Infinity".to_vec(),
        b"-Infinity".to_vec(),
        br#""\ud800""#.to_vec(),
        b"[]".to_vec(),
    ];
    payloads.push(
        [
            b"\xff\xfe".as_slice(),
            &"null"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        ]
        .concat(),
    );
    for (index, payload) in payloads.into_iter().enumerate() {
        fs::write(&output, payload).unwrap();
        let scratch = format!("verifier-json-{index}");
        let out = f.execute_raw(
            &response,
            &scratch,
            &["--remote", remote.to_str().unwrap()],
            &[("VERIFIER_OUTPUT", output.to_str().unwrap())],
        );
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("AttributeError:"));
        assert!(git(&f.path(&scratch), &["for-each-ref"]).is_empty());
        assert!(
            git(
                &remote,
                &["for-each-ref", "refs/tags/evidence", "refs/notes/evidence"]
            )
            .is_empty()
        );
        assert_eq!(
            fs::read_to_string(f.path("calls"))
                .unwrap()
                .matches("CALL")
                .count(),
            1
        );
    }
}

#[test]
fn malformed_auth_token_utf8_refuses_before_push() {
    let f = Fixture::new();
    let remote = f.remote("auth-utf8-remote");
    fs::write(
        f.path("response.json"),
        serde_json::to_vec(&f.answer(&[(&f.degraded, "degraded")])).unwrap(),
    )
    .unwrap();
    let out = f
        .command()
        .args(["--run", "7", "--attempt", "1", "--artifact", "9"])
        .arg("--remote")
        .arg(&remote)
        .env_remove("EVIDENCE_PUSH_TOKEN")
        .env_remove("GH_TOKEN")
        .env("BAD_AUTH_UTF8", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(value["failures"][0].as_str().unwrap().contains("utf-8"));
    assert!(git(&f.path("state/scratch.git"), &["for-each-ref"]).is_empty());
    assert!(
        git(
            &remote,
            &["for-each-ref", "refs/tags/evidence", "refs/notes/evidence"]
        )
        .is_empty()
    );
}

#[test]
fn malformed_record_containers_abort_instead_of_continuing() {
    let f = Fixture::new();
    let original = git(&f.source, &["show", &format!("{}:{}", f.degraded, f.tree)]);
    let mut empty_subject: Value = serde_json::from_str(&original).unwrap();
    empty_subject["subject"] = json!([]);
    for (index, body) in [json!([]), empty_subject].into_iter().enumerate() {
        let record = f.record_body(&body, false);
        let scratch = format!("bad-container-{index}");
        let out = f.execute_raw(
            &f.answer(&[(&record, "degraded"), (&f.degraded, "degraded")]),
            &scratch,
            &[],
            &[],
        );
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert!(git(&f.path(&scratch), &["for-each-ref"]).is_empty());
    }
}

#[test]
fn malformed_ledger_tries_is_not_defaulted_to_zero() {
    let f = Fixture::new();
    fs::create_dir(f.path("state")).unwrap();
    fs::write(
        f.path("state/observed.jsonl"),
        b"{\"run\":7,\"attempt\":1,\"state\":\"failed\",\"tries\":null}\n",
    )
    .unwrap();
    let out = f
        .command()
        .arg("--poll")
        .env(
            "GH_RUNS",
            r#"[{"databaseId":7,"attempt":1,"conclusion":"success"}]"#,
        )
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(!f.path("state/scratch.git").exists());
}

#[test]
fn invalid_verifier_json_remains_a_per_record_failure() {
    let f = Fixture::new();
    let remote = f.remote("invalid-json-remote");
    let output = f.path("invalid-verifier-output");
    fs::write(&output, b"not json").unwrap();
    let (out, value) = f.execute(
        &f.answer(&[(&f.full, "full"), (&f.degraded, "degraded")]),
        "invalid-json-scratch",
        &["--remote", remote.to_str().unwrap()],
        &[("VERIFIER_OUTPUT", output.to_str().unwrap())],
    );
    failure(&out, &value, "unreadable verifier output");
    assert_eq!(value["published"], 1);
    assert_eq!(
        git(
            &remote,
            &[
                "for-each-ref",
                "--format=%(refname) %(objectname)",
                "refs/tags/evidence",
                "refs/notes/evidence"
            ]
        ),
        f.names(&[&f.degraded])
    );
}

#[test]
fn source_parent_without_oid_aborts_before_publication() {
    let f = Fixture::new();
    let remote = f.remote("missing-parent-remote");
    let scratch = f.path("missing-parent");
    fs::create_dir(&scratch).unwrap();
    git(&scratch, &["init", "-q", "--bare"]);
    let source = gitb(
        &scratch,
        &[
            "hash-object",
            "--literally",
            "-t",
            "commit",
            "-w",
            "--stdin",
        ],
        Some(format!("tree {}\nparent \n\nmalformed source\n", f.tree).as_bytes()),
    );
    let source = String::from_utf8(source).unwrap();
    let original = git(&f.source, &["show", &format!("{}:{}", f.degraded, f.tree)]);
    let mut body: Value = serde_json::from_str(&original).unwrap();
    body["subject"][0]["name"] = json!(source.trim());
    let record = f.record_body(&body, false);
    let out = f.execute_raw(
        &f.answer(&[(&record, "degraded")]),
        "missing-parent",
        &["--remote", remote.to_str().unwrap()],
        &[],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("IndexError:"));
    assert!(git(&scratch, &["for-each-ref"]).is_empty());
    assert!(
        git(
            &remote,
            &["for-each-ref", "refs/tags/evidence", "refs/notes/evidence"]
        )
        .is_empty()
    );
}
