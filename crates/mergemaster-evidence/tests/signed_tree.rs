//! Real Git/SSH assertion port of scripts/ci-signed-tree-test; candidate code is never executed.
use serde_json::{Value, json};
use std::{
    cell::Cell,
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
fn environment(command: &mut Command) -> &mut Command {
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
}
fn gitb(repo: &Path, args: &[&str], input: Option<&[u8]>) -> Vec<u8> {
    let mut command = Command::new("git");
    environment(&mut command)
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().unwrap();
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
        .into()
}
fn policy(require: Option<&str>, other: Option<&str>) -> Value {
    let entry = json!({"trust_levels":["machine"],"kinds":{"observed":{"command":["github-actions","{repository}",".github/workflows/fleet.yml","{check}"],"runner_prefix":"github:{repository}/"}}});
    let mut value = json!({"version":1,"checks":{"unit":entry.clone(),"other":entry}});
    if let Some(require) = require {
        value["checks"]["unit"]["require"] = json!(require);
    }
    if let Some(require) = other {
        value["checks"]["other"]["require"] = json!(require);
    }
    value
}
fn lanes() -> Value {
    json!({"version":1,"lanes":{"unit":{"argv":["github-actions","org/repo",".github/workflows/fleet.yml","unit"],"definition_paths":["scripts/lane.sh"]}}})
}
struct Fixture {
    root: tempfile::TempDir,
    repo: PathBuf,
    counter: Cell<usize>,
}
struct Job {
    fields: BTreeMap<String, String>,
    errors: Vec<String>,
    checkout: PathBuf,
}
impl Job {
    fn get(&self, key: &str) -> &str {
        self.fields.get(key).unwrap()
    }
    fn judgment(&self) -> (&str, &str) {
        (self.get("decision"), self.get("lanes"))
    }
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        git(root.path(), &["init", "-q", repo.to_str().unwrap()]);
        git(&repo, &["config", "maintenance.auto", "false"]);
        git(&repo, &["config", "gc.auto", "0"]);
        let out = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(root.path().join("ci"))
            .output()
            .unwrap();
        assert!(out.status.success());
        let key = fs::read_to_string(root.path().join("ci.pub")).unwrap();
        fs::create_dir(repo.join("scripts")).unwrap();
        fs::create_dir(repo.join(".st")).unwrap();
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/ci-signed-tree"),
            repo.join("scripts/ci-signed-tree"),
        )
        .unwrap();
        fs::write(repo.join("scripts/lane.sh"), "lane\n").unwrap();
        fs::write(
            repo.join(".st/evidence-keys"),
            format!("machine/ci1 namespaces=\"git\" {key}"),
        )
        .unwrap();
        let f = Self {
            root,
            repo,
            counter: Cell::new(0),
        };
        f.set_policy(&policy(Some("shadow"), None));
        f.write(".st/required-lanes.json", &lanes().to_string());
        f.commit("base");
        git(&f.repo, &["branch", "-M", "main"]);
        f
    }
    fn path(&self, path: &str) -> PathBuf {
        self.root.path().join(path)
    }
    fn write(&self, path: &str, text: &str) {
        fs::write(self.repo.join(path), text).unwrap();
    }
    fn set_policy(&self, value: &Value) {
        self.write(".st/evidence-skip-policy.json", &value.to_string());
    }
    fn commit(&self, message: &str) {
        git(&self.repo, &["add", "-A"]);
        git(&self.repo, &["commit", "-qm", message]);
    }
    fn pr(&self, changes: &[(&str, &str)], number: usize) -> (String, String) {
        git(
            &self.repo,
            &["checkout", "-q", "-b", &format!("pr{number}"), "main"],
        );
        for (path, text) in changes {
            self.write(path, text);
        }
        self.commit(&format!("pr {number}"));
        let head = git(&self.repo, &["rev-parse", "HEAD"]);
        let tree = git(&self.repo, &["rev-parse", "HEAD^{tree}"]);
        git(
            &self.repo,
            &["update-ref", &format!("refs/pull/{number}/head"), &head],
        );
        git(&self.repo, &["checkout", "-q", "main"]);
        (head, tree)
    }
    fn note(
        &self,
        head: &str,
        tree: &str,
        inputs: Value,
        seconds: i64,
        exit: i32,
        tag: bool,
    ) -> String {
        let body = json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":head,"digest":{"gitTree":tree}}],"predicateType":"https://smalltalk.dev/evidence/gate/v1","predicate":{"schema_version":1,"change_id":"change-1","signer":"machine/ci1","tier":"full","re_attests":null,"producer_sha256":"a".repeat(64),"observed_at":(chrono::Utc::now()+chrono::Duration::seconds(seconds)).to_rfc3339(),"observed":{"kind":"tests","runner":"github:org/repo/actions/runs/7/attempts/1/jobs/9","inputs":inputs,"checks":{"unit":{"command":["github-actions","org/repo",".github/workflows/fleet.yml","unit"],"exit_code":exit,"output_sha256":"b".repeat(64)}}}}});
        let blob = String::from_utf8(gitb(
            &self.repo,
            &["hash-object", "-w", "--stdin"],
            Some(&serde_json::to_vec(&body).unwrap()),
        ))
        .unwrap();
        let notes = String::from_utf8(gitb(
            &self.repo,
            &["mktree"],
            Some(format!("100644 blob {}\t{tree}\n", blob.trim()).as_bytes()),
        ))
        .unwrap();
        let key = format!("user.signingKey={}", self.path("ci").display());
        let record = git(
            &self.repo,
            &[
                "-c",
                "gpg.format=ssh",
                "-c",
                &key,
                "commit-tree",
                "-S",
                notes.trim(),
                "-p",
                head,
                "-m",
                "st gate observation v1",
            ],
        );
        let namespace = if tag { "tags" } else { "notes" };
        git(
            &self.repo,
            &[
                "update-ref",
                &format!("refs/{namespace}/evidence/{tree}/{record}"),
                &record,
            ],
        );
        record
    }
    fn project(&self, tree: &str) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_mergemaster"))
            .args(["legacy-evidence-verify", "--repo"])
            .arg(&self.repo)
            .args([
                "--tree",
                tree,
                "--check",
                "fixture",
                "--project",
                "--paths",
                "src.txt",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["source_inputs"]
            .as_str()
            .unwrap()
            .into()
    }
    fn digest(&self, base: &str, tree: &str) -> String {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mergemaster"))
            .args(["legacy-evidence-verify-helper", "lane-definition", "--repo"])
            .arg(&self.repo)
            .args(["--base-tree", base, "--tree", tree, "--check", "unit"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(lanes().to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["sha256"]
            .as_str()
            .unwrap()
            .into()
    }
    fn job(&self, head: &str, number: usize, shallow: bool, env: &[(&str, &str)]) -> Job {
        let n = self.counter.get();
        self.counter.set(n + 1);
        let checkout = self.path(&format!("checkout-{n}"));
        let mut args = vec!["clone", "-q", "--no-tags"];
        let source = if shallow {
            git(&self.repo, &["config", "uploadpack.allowFilter", "true"]);
            git(
                &self.repo,
                &["config", "uploadpack.allowAnySHA1InWant", "true"],
            );
            args.push("--depth=1");
            format!("file://{}", self.repo.display())
        } else {
            self.repo.to_str().unwrap().into()
        };
        args.extend([&source, checkout.to_str().unwrap()]);
        git(self.root.path(), &args);
        git(&checkout, &["config", "maintenance.auto", "false"]);
        git(&checkout, &["config", "gc.auto", "0"]);
        let summary = self.path(&format!("summary-{n}"));
        let output = self.path(&format!("output-{n}"));
        fs::write(&summary, "").unwrap();
        fs::write(&output, "").unwrap();
        let before = git(&checkout, &["rev-parse", "HEAD"]);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mergemaster"));
        environment(&mut cmd)
            .args(["evidence", "signed-tree"])
            .current_dir(&checkout)
            .env("MERGEMASTER_BIN", env!("CARGO_BIN_EXE_mergemaster"))
            .env("REPOSITORY", "org/repo")
            .env("PR_NUMBER", number.to_string())
            .env("PR_HEAD_SHA", head)
            .env("PR_HEAD_REPOSITORY", "org/repo")
            .env("PR_DRAFT", "false")
            .env("SIGNED_TREE_VERIFIER_TIMEOUT", "60")
            .env("GITHUB_STEP_SUMMARY", &summary)
            .env("GITHUB_OUTPUT", &output)
            .envs(env.iter().copied());
        let out = cmd.output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            git(&checkout, &["status", "--porcelain"]),
            "",
            "candidate code was checked out"
        );
        assert_eq!(git(&checkout, &["rev-parse", "HEAD"]), before);
        let stdout = String::from_utf8(out.stdout).unwrap();
        let text = stdout.trim();
        assert_eq!(text, fs::read_to_string(summary).unwrap().trim());
        let mut lines = text.lines();
        let line = lines.next().unwrap();
        assert!(line.starts_with("signed-tree v1 "), "{line}");
        let errors: Vec<_> = lines.map(str::to_owned).collect();
        assert!(
            errors
                .iter()
                .all(|e| e.starts_with("signed-tree v1 error ")),
            "{text}"
        );
        let fields: BTreeMap<String, String> = line
            .split_whitespace()
            .skip(2)
            .map(|part| {
                let (k, v) = part.split_once('=').unwrap();
                (k.into(), v.into())
            })
            .collect();
        assert_eq!(
            fs::read_to_string(output).unwrap().trim(),
            format!("decision={}", fields["decision"])
        );
        Job {
            fields,
            errors,
            checkout,
        }
    }
    fn run(&self, head: &str) -> Job {
        self.job(head, 1, false, &[])
    }
    fn lagging(&self) -> (String, String) {
        let point = git(&self.repo, &["rev-parse", "main^{tree}"]);
        let (head, tree) = self.pr(&[("src.txt", "behind main\n")], 1);
        self.write("scripts/lane.sh", "lane, changed on main\n");
        self.commit("main changes lane");
        let digest = self.digest(&point, &tree);
        self.note(
            &head,
            &tree,
            json!({"lane_definition_sha256":digest}),
            0,
            0,
            false,
        );
        (head, tree)
    }
}
#[test]
fn missing_note_would_reject_and_shadow_job_passes() {
    let f = Fixture::new();
    let (head, tree) = f.pr(&[("src.txt", "one\n")], 1);
    let job = f.run(&head);
    assert_eq!(job.judgment(), ("would-reject", "unit:no_record"));
    assert_eq!(job.get("tree"), tree);
}
#[test]
fn external_native_verifier_ignores_consumer_decoy_and_projects_head() {
    let f = Fixture::new();
    let marker = f.path("consumer-verifier-ran");
    f.write(
        "scripts/evidence-verify",
        &format!("#!/bin/sh\ntouch '{}'\nexit 91\n", marker.display()),
    );
    let mut p = policy(Some("shadow"), None);
    p["checks"]["unit"]["inputs"] = json!(["src.txt"]);
    f.set_policy(&p);
    f.commit("consumer decoy and input policy");
    let (old, old_tree) = f.pr(&[("src.txt", "same\n"), ("other.txt", "one\n")], 1);
    let key = f.project(&old_tree);
    let record = f.note(&old, &old_tree, json!({"source_inputs":key}), 0, 0, false);
    git(
        &f.repo,
        &[
            "update-ref",
            &format!("refs/notes/evidence-input/unit/{key}/{record}"),
            &record,
        ],
    );
    let (head, tree) = f.pr(&[("src.txt", "same\n"), ("other.txt", "two\n")], 2);
    assert_ne!(tree, old_tree);
    let job = f.job(&head, 2, false, &[]);
    assert!(!marker.exists());
    assert_eq!(job.judgment(), ("would-reject", "unit:wrong_definition"));
    assert_eq!(job.get("tree"), tree);
    assert_eq!(
        git(
            &job.checkout,
            &["for-each-ref", "--format=%(refname)", "refs/notes/"]
        ),
        format!("refs/notes/evidence-input/unit/{key}/{record}")
    );
}
#[test]
fn preferred_configuration_layout_and_malformed_policy() {
    let f = Fixture::new();
    git(&f.repo, &["mv", ".st", ".fractal"]);
    f.commit("new layout");
    let (head, tree) = f.pr(&[("src.txt", "new layout\n")], 1);
    let job = f.run(&head);
    assert_eq!(job.judgment(), ("would-reject", "unit:no_record"));
    assert_eq!(job.get("tree"), tree);
    let f = Fixture::new();
    fs::create_dir(f.repo.join(".fractal")).unwrap();
    f.write(
        ".fractal/evidence-skip-policy.json",
        &policy(Some("off"), Some("off")).to_string(),
    );
    f.commit("preferred policy");
    let (head, _) = f.pr(&[("src.txt", "both layouts\n")], 1);
    assert_eq!(f.run(&head).get("reason"), "nothing-requires-a-signed-note");
    f.write(".fractal/evidence-skip-policy.json", "{broken");
    f.commit("malformed preferred");
    assert_eq!(f.run(&head).get("reason"), "no-readable-policy-at-base");
}
#[test]
fn trusted_signed_note_requires_matching_lane_digest() {
    let f = Fixture::new();
    let (head, tree) = f.pr(&[("src.txt", "two\n")], 1);
    let digest = f.digest(&git(&f.repo, &["rev-parse", "main^{tree}"]), &tree);
    f.note(&head, &tree, json!({}), 0, 0, false);
    assert_eq!(f.run(&head).get("lanes"), "unit:wrong_definition");
    f.note(
        &head,
        &tree,
        json!({"lane_definition_sha256":digest}),
        5,
        0,
        false,
    );
    let job = f.run(&head);
    assert_eq!(job.judgment(), ("ok", "unit:ok"));
    assert_eq!(job.get("reason"), "satisfied");
}
#[test]
fn only_head_tree_notes_are_fetched() {
    let f = Fixture::new();
    let (other, other_tree) = f.pr(&[("src.txt", "elsewhere\n")], 2);
    f.note(&other, &other_tree, json!({}), 0, 0, false);
    let (head, tree) = f.pr(&[("src.txt", "mine\n")], 1);
    let mine = f.note(&head, &tree, json!({}), 0, 0, false);
    let job = f.run(&head);
    assert_eq!(job.get("lanes"), "unit:wrong_definition");
    assert_eq!(
        git(
            &job.checkout,
            &["for-each-ref", "--format=%(refname)", "refs/notes/"]
        ),
        format!("refs/notes/evidence/{tree}/{mine}")
    );
}
#[test]
fn tree_tags_and_input_index_tags_are_fetched_without_unrelated_records() {
    let f = Fixture::new();
    let mut p = policy(Some("shadow"), None);
    p["checks"]["unit"]["inputs"] = json!(["src.txt"]);
    f.set_policy(&p);
    f.commit("unit declares inputs");
    let (other, other_tree) = f.pr(&[("src.txt", "elsewhere\n")], 3);
    f.note(&other, &other_tree, json!({}), 0, 0, true);
    let (head, tree) = f.pr(&[("src.txt", "mine\n")], 1);
    let key = f.project(&tree);
    let mine = f.note(&head, &tree, json!({"source_inputs":key}), 0, 0, true);
    let job = f.run(&head);
    assert_eq!(job.get("lanes"), "unit:wrong_definition");
    assert_eq!(
        git(
            &job.checkout,
            &[
                "for-each-ref",
                "--format=%(refname)",
                "refs/tags/evidence/",
                "refs/notes/"
            ]
        ),
        format!("refs/tags/evidence/{tree}/{mine}")
    );
    git(
        &f.repo,
        &[
            "update-ref",
            &format!("refs/tags/evidence/input/unit/{key}/{mine}"),
            &mine,
        ],
    );
    let (later, later_tree) = f.pr(&[("src.txt", "mine\n"), ("other.txt", "two\n")], 2);
    assert_ne!(later_tree, tree);
    let job = f.job(&later, 2, false, &[]);
    assert_eq!(job.get("lanes"), "unit:wrong_definition");
    assert_eq!(
        git(
            &job.checkout,
            &[
                "for-each-ref",
                "--format=%(refname)",
                "refs/tags/evidence/",
                "refs/notes/"
            ]
        ),
        format!("refs/tags/evidence/input/unit/{key}/{mine}")
    );
}
#[test]
fn input_index_only_note_is_found_from_the_pr_head_projection() {
    let f = Fixture::new();
    let mut p = policy(Some("shadow"), None);
    p["checks"]["unit"]["inputs"] = json!(["src.txt"]);
    f.set_policy(&p);
    f.commit("unit inputs");
    let (old, old_tree) = f.pr(&[("src.txt", "same\n"), ("other.txt", "one\n")], 1);
    let key = f.project(&old_tree);
    let record = f.note(&old, &old_tree, json!({"source_inputs":key}), 0, 0, false);
    git(
        &f.repo,
        &[
            "update-ref",
            &format!("refs/notes/evidence-input/unit/{key}/{record}"),
            &record,
        ],
    );
    let (head, tree) = f.pr(&[("src.txt", "same\n"), ("other.txt", "two\n")], 2);
    assert_ne!(tree, old_tree);
    let job = f.job(&head, 2, false, &[]);
    assert_eq!(job.get("lanes"), "unit:wrong_definition");
    assert_eq!(
        git(
            &job.checkout,
            &["for-each-ref", "--format=%(refname)", "refs/notes/"]
        ),
        format!("refs/notes/evidence-input/unit/{key}/{record}")
    );
}
#[test]
fn failed_check_and_reject_policy_remain_shadow_only() {
    let f = Fixture::new();
    let (head, tree) = f.pr(&[("src.txt", "three\n")], 1);
    f.note(&head, &tree, json!({}), 0, 1, false);
    assert_eq!(f.run(&head).get("lanes"), "unit:check_failed");
    f.set_policy(&policy(Some("reject"), None));
    f.commit("reject");
    assert_eq!(f.run(&head).judgment(), ("reject", "unit:check_failed"));
}
#[test]
fn require_off_avoids_fetch_and_forks_and_drafts_are_skipped() {
    let f = Fixture::new();
    f.set_policy(&policy(None, None));
    f.commit("require off");
    let (head, _) = f.pr(&[("src.txt", "four\n")], 1);
    git(&f.repo, &["update-ref", "-d", "refs/pull/1/head"]);
    let job = f.run(&head);
    assert_eq!(
        (job.get("decision"), job.get("reason")),
        ("ok", "nothing-requires-a-signed-note")
    );
    assert_eq!(
        f.job(&head, 1, false, &[("PR_HEAD_REPOSITORY", "someone/fork")])
            .get("decision"),
        "skipped"
    );
    assert_eq!(
        f.job(&head, 1, false, &[("PR_DRAFT", "true")])
            .get("reason"),
        "draft"
    );
}
#[test]
fn candidate_scripts_policy_and_lane_file_cannot_change_judgment() {
    let f = Fixture::new();
    let marker = f.path("ran-pr-code");
    let evil = format!(
        "#!/bin/sh\ntouch '{}'\nprintf '{{\"decision\":\"ok\"}}'\n",
        marker.display()
    );
    let (head, _) = f.pr(
        &[
            ("scripts/evidence-verify", &evil),
            ("scripts/ci-signed-tree", &evil),
            (
                ".st/evidence-skip-policy.json",
                &policy(None, None).to_string(),
            ),
            (".st/required-lanes.json", "{}"),
        ],
        1,
    );
    assert_eq!(f.run(&head).judgment(), ("would-reject", "unit:no_record"));
    assert!(!marker.exists());
    let f = Fixture::new();
    let (head, tree) = f.pr(&[("scripts/lane.sh", "lane, but fewer tests\n")], 1);
    f.note(
        &head,
        &tree,
        json!({"lane_definition_sha256":"f".repeat(64)}),
        0,
        0,
        false,
    );
    assert_eq!(
        f.run(&head).judgment(),
        ("would-reject", "unit:definition_changed")
    );
}
#[test]
fn errors_are_reported_without_failing_the_job() {
    let f = Fixture::new();
    let (head, _) = f.pr(&[("src.txt", "six\n")], 1);
    assert_eq!(
        f.job(&head, 1, false, &[("PR_NUMBER", "x")]).get("reason"),
        "bad-context"
    );
    assert_eq!(f.run("nothex").get("decision"), "error");
    assert_eq!(
        f.run(&"a".repeat(40)).get("reason"),
        "fetched-head-differs-from-the-event"
    );
    assert_eq!(
        f.job(&head, 2, false, &[]).get("reason"),
        "could-not-fetch-the-head"
    );
    f.write(".st/evidence-skip-policy.json", "not json");
    f.commit("broken policy");
    assert_eq!(f.run(&head).get("reason"), "no-readable-policy-at-base");
    f.set_policy(&json!({"version":1,"checks":{"unit":{"require":"sometimes"}}}));
    f.commit("invalid require");
    let job = f.run(&head);
    assert_eq!(
        (job.get("decision"), job.get("reason")),
        ("error", "verifier:error")
    );
}
#[test]
fn lagging_pr_uses_branch_point_with_full_and_shallow_history() {
    let f = Fixture::new();
    let (head, _) = f.lagging();
    for shallow in [false, true] {
        let job = f.job(&head, 1, shallow, &[]);
        assert_eq!(job.judgment(), ("ok", "unit:ok"));
        assert_eq!(job.get("reason"), "satisfied");
        assert!(job.errors.is_empty());
    }
}
#[test]
fn unrelated_history_uses_tip_and_reports_missing_branch_point() {
    let f = Fixture::new();
    let (_, tree) = f.lagging();
    let head = git(&f.repo, &["commit-tree", &tree, "-m", "unrelated history"]);
    git(&f.repo, &["update-ref", "refs/pull/2/head", &head]);
    let job = f.job(&head, 2, true, &[]);
    assert_eq!(job.judgment(), ("would-reject", "unit:definition_changed"));
    assert!(
        job.get("reason")
            .ends_with(",lanes-at-the-base-tip:no-branch-point")
    );
}
#[test]
fn failed_notes_fetch_diagnostic_survives_verifier_timeout() {
    let f = Fixture::new();
    let (head, tree) = f.pr(&[("src.txt", "unfetchable\n")], 1);
    let reference = f
        .repo
        .join(".git/refs/notes/evidence")
        .join(&tree)
        .join("0".repeat(40));
    fs::create_dir_all(reference.parent().unwrap()).unwrap();
    fs::write(reference, format!("{}\n", "1".repeat(40))).unwrap();
    let job = f.run(&head);
    assert_eq!(job.get("decision"), "would-reject");
    assert!(job.get("reason").ends_with(",notes-fetch-failed"));
    assert_eq!(job.errors.len(), 1);
    assert!(job.errors[0].starts_with("signed-tree v1 error notes-fetch: "));
    assert!(!job.errors[0].contains("no stderr"));
    let job = f.job(&head, 1, false, &[("SIGNED_TREE_VERIFIER_TIMEOUT", "0")]);
    assert_eq!(
        (job.get("decision"), job.get("reason")),
        ("error", "verifier-exit-124-without-json")
    );
    assert_eq!(job.errors.len(), 1);
    assert!(job.errors[0].starts_with("signed-tree v1 error notes-fetch: "));
}

#[test]
fn malformed_timeout_fails_before_writing_workflow_outputs() {
    let root = tempfile::tempdir().unwrap();
    let summary = root.path().join("summary");
    let output = root.path().join("output");
    fs::write(&summary, "").unwrap();
    fs::write(&output, "").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mergemaster"))
        .args(["evidence", "signed-tree"])
        .current_dir(root.path())
        .env("SIGNED_TREE_VERIFIER_TIMEOUT", "not-an-integer")
        .env("GITHUB_STEP_SUMMARY", &summary)
        .env("GITHUB_OUTPUT", &output)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        "ValueError: invalid literal for int() with base 10: 'not-an-integer'\n"
    );
    assert!(out.stdout.is_empty());
    assert_eq!(fs::read(summary).unwrap(), b"");
    assert_eq!(fs::read(output).unwrap(), b"");
}

#[test]
fn context_regex_accepts_only_one_terminal_newline_without_removing_it() {
    let f = Fixture::new();
    let (head, _) = f.pr(&[("src.txt", "newline context\n")], 1);
    let newline_head = format!("{head}\n");
    let job = f.job(
        &newline_head,
        1,
        false,
        &[("PR_HEAD_REPOSITORY", "someone/fork")],
    );
    assert_eq!(
        (job.get("decision"), job.get("reason")),
        ("skipped", "not-a-same-repository-pull-request")
    );
    assert_eq!(job.get("head"), format!("{head}_"));
    // The event value is retained: it no longer equals Git's stripped FETCH_HEAD.
    assert_eq!(
        f.run(&newline_head).get("reason"),
        "fetched-head-differs-from-the-event"
    );
    let job = f.job(&head, 1, false, &[("REPOSITORY", "org/repo\n")]);
    assert_eq!(
        (job.get("decision"), job.get("reason")),
        ("skipped", "not-a-same-repository-pull-request")
    );
    for suffix in ["\n\n", "\r\n", "\r", "\nextra"] {
        let invalid_head = format!("{head}{suffix}");
        assert_eq!(
            f.job(
                &invalid_head,
                1,
                false,
                &[("PR_HEAD_REPOSITORY", "someone/fork")]
            )
            .get("reason"),
            "bad-context",
            "head suffix {suffix:?}"
        );
        let invalid_repository = format!("org/repo{suffix}");
        assert_eq!(
            f.job(&head, 1, false, &[("REPOSITORY", &invalid_repository)])
                .get("reason"),
            "bad-context",
            "repository suffix {suffix:?}"
        );
    }
}

#[test]
fn base_policy_uses_python_json_numbers_and_rejects_invalid_json() {
    let f = Fixture::new();
    let (head, _) = f.pr(&[("src.txt", "numeric policy\n")], 1);
    for number in ["1e400", "-1e400", "NaN", "Infinity", "-Infinity"] {
        f.write(
            ".st/evidence-skip-policy.json",
            &format!("{{\"checks\":{{}},\"unused\":{number}}}"),
        );
        f.commit(&format!("Python JSON {number}"));
        let job = f.run(&head);
        assert_eq!(
            (job.get("decision"), job.get("reason")),
            ("ok", "nothing-requires-a-signed-note"),
            "{number}"
        );
    }
    for invalid in [
        "{\"checks\":{},\"unused\":1e}",
        "{\"checks\":{},}",
        "{\"checks\":{},\"unused\":undefined}",
    ] {
        f.write(".st/evidence-skip-policy.json", invalid);
        f.commit("invalid JSON");
        let job = f.run(&head);
        assert_eq!(
            (job.get("decision"), job.get("reason")),
            ("error", "no-readable-policy-at-base"),
            "{invalid}"
        );
    }
}
