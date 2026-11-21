//! The explicit write path runs against a disposable local origin; GitHub is recorded by a shell shim.
#[path = "../src/pinned_python.rs"]
mod pinned_python;
use chrono::{Duration, TimeZone, Utc};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    origin: PathBuf,
    data: PathBuf,
    bin: PathBuf,
    cache: PathBuf,
}
fn cleanup_with_backoff(
    mut cleanup: impl FnMut() -> std::io::Result<()>,
    mut sleep: impl FnMut(std::time::Duration),
) -> std::io::Result<()> {
    for attempt in 0..4 {
        match cleanup() {
            Ok(()) => return Ok(()),
            Err(_) => sleep(std::time::Duration::from_millis(200 * (attempt + 1))),
        }
    }
    cleanup()
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let result =
            cleanup_with_backoff(|| fs::remove_dir_all(self._temp.path()), std::thread::sleep);
        assert!(result.is_ok(), "fixture cleanup failed: {result:?}");
    }
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        let origin = temp.path().join("origin.git");
        let data = temp.path().join("data");
        let bin = temp.path().join("bin");
        let cache = temp.path().join("cache");
        for path in [&root, &data, &bin] {
            fs::create_dir_all(path).unwrap();
        }
        git(&root, &["init", "-q", "-b", "main"]);
        git(
            &root,
            &[
                "init",
                "-q",
                "--bare",
                "-b",
                "main",
                origin.to_str().unwrap(),
            ],
        );
        for repo in [&root, &origin] {
            for (key, value) in [
                ("maintenance.auto", "false"),
                ("gc.auto", "0"),
                ("receive.autogc", "false"),
            ] {
                git(repo, &["config", key, value]);
            }
        }
        for (key, value) in [
            ("user.name", "Test"),
            ("user.email", "test@example.com"),
            ("commit.gpgsign", "false"),
        ] {
            git(&root, &["config", key, value]);
        }
        let policy = json!({
            "checks": {
                "genie-freshness": {
                    "trust_levels": ["host"], "enforce": false,
                    "kinds": {"wrapper": {"command": ["genie-freshness"]}}
                },
                "linux-gate": {
                    "enforce": false, "sample_one_in": 5,
                    "kinds": {"wrapper": {
                        "command": ["linux-gate"],
                        "by_level": {
                            "host": {"required_inputs": ["clippy_base_sha"]},
                            "agent": {"required_inputs": ["clippy_base_sha"]}
                        }
                    }}
                }
            }
        });
        let doc = "### Which checks skip today\n\n| Check | enforce | events | sample | Since |\n| --- | --- | --- | --- | --- |\n| `genie-freshness`, `linux-gate` | false | - | 5 or 1 | - |\n\nAfter.\n";
        let files = [
            (
                ".st/evidence-skip-policy.json",
                format!("{}\n", serde_json::to_string_pretty(&policy).unwrap()),
            ),
            ("docs/st3/gate-evidence.md", doc.to_owned()),
            (
                ".github/workflows/fleet.yml",
                "jobs:\n  genie-freshness:\n    steps: []\n  linux-gate:\n    steps: []\n"
                    .to_owned(),
            ),
            (
                "scripts/ci-evidence-gate-test",
                "enforced = ('other',)\n".to_owned(),
            ),
            (
                "scripts/evidence-verify-test",
                "ENFORCED = ('other',)\n".to_owned(),
            ),
        ];
        for (path, text) in files {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), text).unwrap();
        }
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "base"]);
        git(
            &root,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        );
        git(&root, &["push", "-q", "origin", "main"]);
        let now = Utc.with_ymd_and_hms(2026, 10, 22, 12, 0, 0).unwrap();
        let mut runs = Vec::new();
        for i in 0..31 {
            let id = 1000 + i;
            let created = now - Duration::hours(if i == 0 { 25 } else { 23 - i * 20 / 31 });
            runs.push(json!({"id":id,"created_at":created.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),"status":"completed","conclusion":"success","actor":{"login":"otter-bot"}}));
            fs::write(data.join(format!("jobs-{id}.json")),serde_json::to_vec(&json!([{"jobs":[{"id":id*100,"name":"evidence-gate-genie-freshness","status":"completed","conclusion":"success","run_attempt":1},{"id":id*100+50,"name":"genie-freshness","status":"completed","conclusion":"success","run_attempt":1}]}])).unwrap()).unwrap();
            fs::write(data.join(format!("log-{}",id*100)),"2026-10-22T05:58:36.1Z evidence-decision v1 check=genie-freshness decision=run outcome=satisfied log=ok trust_level=host\n").unwrap();
        }
        fs::write(
            data.join("runs.json"),
            serde_json::to_vec(&json!({"total_count":31,"workflow_runs":runs})).unwrap(),
        )
        .unwrap();
        fs::write(data.join("open.json"), "[]").unwrap();
        let shell = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join("bash"))
            .find(|candidate| candidate.is_file())
            .unwrap()
            .canonicalize()
            .unwrap();
        let shim = r#"set -eu
printf '%s\0' "$@" >> "$DATA/calls"
printf '\n' >> "$DATA/calls"
if [[ "$1" == pr ]]; then
  if [[ "$2" == list ]]; then cat "$DATA/open.json"; exit; fi
  if [[ "$2" == create ]]; then
    while (($#)); do if [[ "$1" == --body ]]; then printf '%s' "$2" > "$DATA/body"; fi; shift; done
    echo https://github.com/org/repo/pull/9; exit
  fi
fi
path="${!#}"
case "$path" in
  */workflows/fleet.yml/runs*) cat "$DATA/runs.json";;
  */runs/*/jobs*) id="${path#*/runs/}"; id="${id%%/*}"; cat "$DATA/jobs-$id.json";;
  */jobs/*/logs) id="${path#*/jobs/}"; id="${id%%/*}"; cat "$DATA/log-$id";;
  *) echo "unexpected $*" >&2; exit 1;;
esac
"#;
        fs::write(bin.join("gh"), format!("#!{}\n{shim}", shell.display())).unwrap();
        fs::set_permissions(bin.join("gh"), fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            _temp: temp,
            root,
            origin,
            data,
            bin,
            cache,
        }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mergemaster"))
            .args([
                "evidence",
                "flip-ready",
                "--repo",
                "org/repo",
                "--cache",
                self.cache.to_str().unwrap(),
                "--now",
                "2026-10-22T12:00:00Z",
            ])
            .args(args)
            .current_dir(&self.root)
            .env("DATA", &self.data)
            .env(
                "PATH",
                format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap()),
            )
            .output()
            .unwrap()
    }
    fn run_python(&self, args: &[&str]) -> Output {
        let source = PathBuf::from(
            std::env::var_os("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle source"),
        )
        .join("scripts/evidence-flip-ready");
        pinned_python::command()
            .args(["-B", "-c", "import datetime,pathlib,runpy,sys; m=runpy.run_path(sys.argv[1]); sys.exit(m['main'](['--repo','org/repo','--cache',sys.argv[3],*sys.argv[4:]], now=datetime.datetime(2026,10,22,12,tzinfo=datetime.timezone.utc), root=pathlib.Path(sys.argv[2])))"])
            .arg(source)
            .arg(&self.root)
            .arg(&self.cache)
            .args(args)
            .current_dir(&self.root)
            .env("DATA", &self.data)
            .env("PATH", format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap()))
            .output()
            .unwrap()
    }
    fn show(&self, path: &str) -> String {
        git(
            &self.origin,
            &["show", &format!("evidence-flip/genie-freshness:{path}")],
        )
    }
    fn no_branch(&self) {
        assert_eq!(
            git(&self.origin, &["branch", "--list", "evidence-flip/*"]),
            ""
        );
        assert_eq!(git(&self.root, &["worktree", "list"]).lines().count(), 1);
    }
}
#[test]
fn propose_pushes_exact_flip_opens_pr_and_removes_worktree() {
    let f = Fixture::new();
    let out = f.run(&["--propose"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let original: Value = serde_json::from_str(&git(
        &f.origin,
        &["show", "main:.st/evidence-skip-policy.json"],
    ))
    .unwrap();
    let policy: Value = serde_json::from_str(&f.show(".st/evidence-skip-policy.json")).unwrap();
    let entry = &policy["checks"]["genie-freshness"];
    assert_eq!(entry["enforce"], true);
    assert_eq!(entry["events"], json!(["pull_request"]));
    assert_eq!(entry["sample_one_in"], 1);
    assert_eq!(
        entry
            .as_object()
            .unwrap()
            .keys()
            .take(4)
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["trust_levels", "enforce", "events", "sample_one_in"]
    );
    let mut expected = original;
    expected["checks"]["genie-freshness"] = entry.clone();
    assert_eq!(policy, expected);
    let doc = f.show("docs/st3/gate-evidence.md");
    assert!(doc.contains("| `genie-freshness` | true | `pull_request` | 1 | 2026-10-22 |\n"));
    assert!(doc.contains("| `linux-gate` | false | - | 5 or 1 | - |\n"));
    for (path, name) in [
        ("scripts/ci-evidence-gate-test", "enforced"),
        ("scripts/evidence-verify-test", "ENFORCED"),
    ] {
        assert_eq!(
            f.show(path),
            format!("{name} = ('other', 'genie-freshness')\n")
        );
        let diff = git(
            &f.origin,
            &["diff", "main", "evidence-flip/genie-freshness", "--", path],
        );
        assert!(
            diff.lines()
                .filter(|line| (line.starts_with('+') || line.starts_with('-'))
                    && !line.starts_with("+++")
                    && !line.starts_with("---"))
                .count()
                <= 3
        );
    }
    let note: Value =
        serde_json::from_str(&f.show("release-notes/evidence-enforce-genie-freshness.json"))
            .unwrap();
    assert_eq!(note["version"], 1);
    for key in [
        "replay",
        "schema",
        "rules",
        "compatibility",
        "downtime",
        "manual",
        "recovery",
    ] {
        assert_eq!(note[key]["status"], "none");
    }
    let mut changed: Vec<String> = git(
        &f.origin,
        &[
            "diff",
            "--name-only",
            "main",
            "evidence-flip/genie-freshness",
        ],
    )
    .lines()
    .map(str::to_owned)
    .collect();
    changed.sort();
    assert_eq!(
        changed,
        [
            ".st/evidence-skip-policy.json",
            "docs/st3/gate-evidence.md",
            "release-notes/evidence-enforce-genie-freshness.json",
            "scripts/ci-evidence-gate-test",
            "scripts/evidence-verify-test"
        ]
    );
    let body = fs::read_to_string(f.data.join("body")).unwrap();
    let trigger: Value = serde_json::from_str(
        body.split("```json\n")
            .nth(1)
            .unwrap()
            .split("\n```")
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(trigger["check"], "genie-freshness");
    assert_eq!(trigger["ready"], true);
    assert_eq!(trigger["satisfied_log_ok"], 30);
    let calls = fs::read_to_string(f.data.join("calls")).unwrap();
    assert_eq!(calls.matches("pr\0create\0").count(), 1);
    assert!(calls.contains("pr\0list\0--repo\0org/repo\0--head\0evidence-flip/genie-freshness\0--state\0open\0--json\0number\0"));
    assert_eq!(git(&f.root, &["worktree", "list"]).lines().count(), 1);
}
#[test]
fn open_pr_and_dry_run_never_push_or_create_pr() {
    let f = Fixture::new();
    fs::write(f.data.join("open.json"), "[{\"number\":7}]").unwrap();
    let out = f.run(&["--propose"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("#7 is already open"));
    f.no_branch();
    fs::write(f.data.join("open.json"), "[]").unwrap();
    let out = f.run(&["--propose", "--dry-run"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("+      \"enforce\": true,"));
    assert!(stdout.contains("+| `genie-freshness` | true | `pull_request` | 1 | 2026-10-22 |"));
    assert!(
        !fs::read_to_string(f.data.join("calls"))
            .unwrap()
            .contains("pr\0create\0")
    );
    f.no_branch();
}
#[test]
fn mechanical_refusal_does_not_push_and_always_removes_worktree() {
    let f = Fixture::new();
    let path = f.root.join("docs/st3/gate-evidence.md");
    let doc = fs::read_to_string(&path).unwrap();
    fs::write(&path, doc.replace("`genie-freshness`, ", "")).unwrap();
    git(&f.root, &["commit", "-qam", "drop row"]);
    git(&f.root, &["push", "-q", "origin", "main"]);
    let out = f.run(&["--propose"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot be made mechanically"));
    f.no_branch();
}
#[test]
fn dry_run_requires_propose_and_repository_is_validated() {
    let f = Fixture::new();
    assert_eq!(f.run(&["--dry-run"]).status.code(), Some(2));
}

#[test]
fn proposal_and_dry_run_match_the_independent_pinned_python() {
    for mode in ["propose", "dry-run", "open-pr", "mechanical-refusal"] {
        let native = Fixture::new();
        let python = Fixture::new();
        for fixture in [&native, &python] {
            if mode == "open-pr" {
                fs::write(fixture.data.join("open.json"), "[{\"number\":7}]").unwrap();
            }
            if mode == "mechanical-refusal" {
                let path = fixture.root.join("docs/st3/gate-evidence.md");
                fs::write(
                    &path,
                    fs::read_to_string(&path)
                        .unwrap()
                        .replace("`genie-freshness`, ", ""),
                )
                .unwrap();
                git(&fixture.root, &["commit", "-qam", "drop row"]);
                git(&fixture.root, &["push", "-q", "origin", "main"]);
            }
        }
        let args: &[&str] = if mode == "dry-run" {
            &["--propose", "--dry-run"]
        } else {
            &["--propose"]
        };
        let expected = python.run_python(args);
        let actual = native.run(args);
        assert_eq!(actual.status.code(), expected.status.code(), "{mode}");
        assert_eq!(actual.stdout, expected.stdout, "{mode}: stdout");
        assert_eq!(actual.stderr, expected.stderr, "{mode}: stderr");
        let canonical_calls = |fixture: &Fixture| {
            let calls = fs::read_to_string(fixture.data.join("calls")).unwrap();
            let mut calls: Vec<String> = calls
                .split("\0\n")
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            calls.sort();
            calls
        };
        assert_eq!(
            canonical_calls(&native),
            canonical_calls(&python),
            "{mode}: GitHub access"
        );
        if mode == "propose" {
            for path in [
                ".st/evidence-skip-policy.json",
                "docs/st3/gate-evidence.md",
                "scripts/ci-evidence-gate-test",
                "scripts/evidence-verify-test",
                "release-notes/evidence-enforce-genie-freshness.json",
            ] {
                assert_eq!(native.show(path), python.show(path), "{path}");
            }
            assert_eq!(
                fs::read(native.data.join("body")).unwrap(),
                fs::read(python.data.join("body")).unwrap()
            );
        } else {
            native.no_branch();
            python.no_branch();
        }
    }
}

#[test]
fn cleanup_records_backoff_until_success_or_exhaustion() {
    for failures in [0, 2, 4, 5] {
        let mut calls = 0;
        let mut sleeps = Vec::new();
        let result = cleanup_with_backoff(
            || {
                calls += 1;
                if calls <= failures {
                    Err(std::io::Error::other("busy"))
                } else {
                    Ok(())
                }
            },
            |duration| sleeps.push(duration),
        );
        assert_eq!(result.is_err(), failures == 5);
        if let Err(error) = result {
            assert_eq!(error.to_string(), "busy");
        }
        assert_eq!(calls, (failures + 1).min(5));
        assert_eq!(
            sleeps,
            (1..=failures.min(4))
                .map(|step| std::time::Duration::from_millis(200 * step))
                .collect::<Vec<_>>()
        );
    }
}
