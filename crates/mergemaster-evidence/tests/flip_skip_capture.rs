//! Exercise capture failures through the real CLI and isolated executable lookup.
//! A successful prerequisite makes the next executable unavailable; no global PATH changes,
//! network requests, timeout knobs, or long-running children are involved.
use chrono::{Duration, TimeZone, Utc};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output},
};

const BASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CHECKS: [&str; 2] = ["genie-freshness", "z-check"];

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    data: PathBuf,
    cache: PathBuf,
}

impl Fixture {
    fn new(ready: bool, fields: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        let bin = temp.path().join("bin");
        let data = temp.path().join("data");
        let cache = temp.path().join("cache");
        for path in [&root, &bin, &data] {
            fs::create_dir_all(path).unwrap();
        }
        let mut checks = serde_json::Map::new();
        for check in CHECKS {
            checks.insert(
                check.to_owned(),
                json!({
                    "enforce": false,
                    "kinds": {"wrapper": {"command": [check]}}
                }),
            );
        }
        for (path, contents) in [
            (".st/evidence-skip-policy.json", serde_json::to_string_pretty(&json!({"checks": checks})).unwrap()),
            (".st/required-lanes.json", "{\"lanes\":{\"genie-freshness\":{\"definition_paths\":[]}}}".to_owned()),
            (".github/workflows/fleet.yml", "jobs:\n  genie-freshness:\n    steps: []\n  z-check:\n    steps: []\n".to_owned()),
            ("docs/st3/gate-evidence.md", "### Which checks skip today\n\n| Check | enforce | events | sample | Since |\n| --- | --- | --- | --- | --- |\n| `genie-freshness`, `z-check` | false | - | 5 or 1 | - |\n\nAfter.\n".to_owned()),
            ("scripts/ci-evidence-gate-test", "enforced = ('other',)\n".to_owned()),
            ("scripts/evidence-verify-test", "ENFORCED = ('other',)\n".to_owned()),
        ] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        let now = Utc.with_ymd_and_hms(2026, 10, 22, 12, 0, 0).unwrap();
        let count = if ready { 31 } else { 1 };
        let mut runs = Vec::new();
        let mut last_log = 0;
        for i in 0..count {
            let run = 1000 + i;
            let created = now - Duration::hours(if ready && i == 0 { 25 } else { 1 });
            runs.push(json!({
                "id": run, "created_at": created.to_rfc3339(),
                "status": "completed", "conclusion": "success",
                "actor": {"login": "otter-bot"}, "head_branch": "topic",
                "pull_requests": [{"number": 9, "base": {"sha": BASE}}]
            }));
            let mut jobs = Vec::new();
            for (index, check) in CHECKS.iter().enumerate() {
                // One check suffices for read witnesses; proposals require two ready checks
                // so that an incorrectly swallowed capture error has an observable successor.
                if !ready && index != 0 {
                    continue;
                }
                let job = run * 10 + index as i64;
                jobs.push(json!({"id": job, "name": format!("evidence-gate-{check}"), "status": "completed", "conclusion": "success", "run_attempt": 1}));
                jobs.push(json!({"id": job + 50000, "name": check, "status": "completed", "conclusion": "success", "run_attempt": 1}));
                fs::write(
                    data.join(format!("log-{job}")),
                    format!("evidence-decision v1 check={check} decision=run {fields}\n"),
                )
                .unwrap();
                last_log = job;
            }
            fs::write(
                data.join(format!("jobs-{run}.json")),
                serde_json::to_vec(&json!([{ "jobs": jobs }])).unwrap(),
            )
            .unwrap();
        }
        fs::write(
            data.join("runs.json"),
            serde_json::to_vec(&json!({"total_count": count, "workflow_runs": runs})).unwrap(),
        )
        .unwrap();
        fs::write(data.join("last-log"), last_log.to_string()).unwrap();
        // Nix hosts need not expose utilities in /bin. Admit just these helpers,
        // never the ambient git or gh, to each child's private lookup directory.
        let path = std::env::var_os("PATH").unwrap();
        for utility in ["cat", "chmod", "cp", "mkdir", "rm"] {
            let executable = std::env::split_paths(&path)
                .map(|directory| directory.join(utility))
                .find(|candidate| candidate.is_file())
                .unwrap()
                .canonicalize()
                .unwrap();
            std::os::unix::fs::symlink(executable, bin.join(utility)).unwrap();
        }
        let shell = std::env::split_paths(&path)
            .map(|directory| directory.join("sh"))
            .find(|candidate| candidate.is_file())
            .unwrap()
            .canonicalize()
            .unwrap();
        for name in ["git", "gh"] {
            let executable = bin.join(name);
            fs::write(&executable, format!("#!{}\n{SHIM}", shell.display())).unwrap();
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self {
            _temp: temp,
            root,
            bin,
            data,
            cache,
        }
    }

    fn run(&self, command: &str, arm: &str, victim: &str, mode: &str, propose: bool) -> Output {
        let mut child = Command::new(
            std::env::var_os("CARGO_BIN_EXE_mergemaster")
                .expect("CARGO_BIN_EXE_mergemaster is set at test runtime"),
        );
        child
            .args(["evidence", command, "--repo", "org/repo", "--cache"])
            .arg(&self.cache)
            .args(["--now", "2026-10-22T12:00:00Z"])
            .current_dir(&self.root)
            // Every child has its own lookup directory, with no real git/gh fallback.
            .env("PATH", &self.bin)
            .env("BIN", &self.bin)
            .env("ROOT", &self.root)
            .env("DATA", &self.data)
            .env("ARM", arm)
            .env("VICTIM", victim)
            .env("FAIL_MODE", mode);
        if propose {
            child.arg("--propose");
        }
        child.output().unwrap()
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.data.join("calls")).unwrap_or_default()
    }

    fn armed(&self, stage: &str) {
        assert_eq!(fs::read_to_string(self.data.join("armed")).unwrap(), stage);
    }
}

// An absolute interpreter and explicitly admitted utilities keep PATH hermetic. Invalidation
// happens only after the selected prerequisite has produced its successful result.
const SHIM: &str = r#"set -eu
name=${0##*/}
tag=
if [ "$name" = gh ]; then
  case "$*" in
    pr\ list*) tag=pr-list;;
    pr\ create*) tag=pr-create;;
    *'/workflows/fleet.yml/runs?'*) tag=runs;;
    *'/workflows/release-fractal.yml/runs?'*) tag=release-runs;;
    *'/jobs/'*'/logs') tag=job-log;;
    *'/runs/'*'/jobs?'*) tag=jobs;;
    *'/pulls/9/files?'*) tag=pr-files;;
    *) echo "unexpected gh: $*" >&2; exit 97;;
  esac
else
  # Every production git invocation except bare init carries -C <directory>.
  if [ "${1-}" = -C ]; then shift 2; fi
  case "${1-}" in
    fetch) case "$*" in *refs/evidence-log/main*) tag=published-fetch;; *) tag=fetch;; esac;;
    ls-tree)
      case "$*" in
        *required-lanes.json*) tag=lane-path;;
        *aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa*)
          case "$*" in *.fractal/*) tag=old-config-path;; *) tag=old-config-tree;; esac;;
        *) tag=config-path;;
      esac;;
    show)
      case "$*" in
        *required-lanes.json*) tag=lane-show;;
        *evidence-skip-policy.json*)
          case "$*" in *aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa*) tag=old-config-show;; *) tag=policy-show;; esac;;
        *) tag=workflow-show;;
      esac;;
    cat-file) case "$*" in *ci-evidence-gate*) tag=gate-probe;; *) tag=commit-probe;; esac;;
    remote) tag=published-url;;
    init) tag=published-init;;
    log) tag=published-log;;
    grep) tag=published-grep;;
    worktree) case "${2-}" in add) tag=worktree-add;; remove) tag=worktree-remove;; esac;;
    add) tag=add;;
    commit) tag=commit;;
    push) tag=push;;
    *) echo "unexpected git: $*" >&2; exit 98;;
  esac
fi
printf '%s %s\n' "$tag" "$*" >> "$DATA/calls"
if [ -f "$DATA/fail-next-$name" ]; then
  rm "$DATA/fail-next-$name"
  echo 'completed child rejected the probe' >&2
  exit 23
fi
case "$tag" in
  runs) cat "$DATA/runs.json";;
  release-runs) printf '{"total_count":1,"workflow_runs":[{"id":1,"created_at":"2020-01-01T00:00:00Z"}]}';;
  jobs)
    path=; for path do :; done
    id=${path#*/runs/}; id=${id%%/*}
    cat "$DATA/jobs-$id.json";;
  job-log)
    path=; for path do :; done
    id=${path#*/jobs/}; id=${id%%/*}
    cat "$DATA/log-$id"
    if [ "$id" = "$(cat "$DATA/last-log")" ]; then tag=last-job-log; fi;;
  pr-files) printf '[[]]';;
  pr-list) printf '[]';;
  pr-create) printf 'https://github.com/org/repo/pull/9\n';;
  lane-path|config-path|old-config-path) :;;
  old-config-tree) printf 'policy exists\n';;
  lane-show) cat "$ROOT/.st/required-lanes.json";;
  old-config-show|policy-show) cat "$ROOT/.st/evidence-skip-policy.json";;
  workflow-show) cat "$ROOT/.github/workflows/fleet.yml";;
  published-url) printf '/unused/local/origin\n';;
  published-log) printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb as_of=2026-10-21T10:00:00Z\n';;
  worktree-add) mkdir -p "$5"; cp -R "$ROOT/." "$5/";;
  *) :;;
esac
if [ "$tag" = "$ARM" ]; then
  printf '%s' "$tag" > "$DATA/armed"
  case "$FAIL_MODE" in
    missing) rm "$BIN/$VICTIM";;
    denied) chmod 000 "$BIN/$VICTIM";;
    completed) : > "$DATA/fail-next-$VICTIM";;
    *) echo 'invalid failure mode' >&2; exit 99;;
  esac
fi
"#;

fn assert_capture_exit(output: &Output, mode: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={}\nstderr={stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    let expected = if mode == "missing" {
        "No such file or directory"
    } else {
        "Permission denied"
    };
    assert!(
        stderr.contains(expected),
        "expected original OS error {expected:?}: {stderr}"
    );
}

#[test]
fn flip_initial_git_and_github_spawn_errors_are_not_readability_exit_two() {
    for mode in ["missing", "denied"] {
        for (arm, victim) in [("before-start", "git"), ("workflow-show", "gh")] {
            let f = Fixture::new(false, "outcome=satisfied log=ok");
            if arm == "before-start" {
                if mode == "missing" {
                    fs::remove_file(f.bin.join(victim)).unwrap();
                } else {
                    fs::set_permissions(f.bin.join(victim), fs::Permissions::from_mode(0o000))
                        .unwrap();
                }
            }
            let output = f.run("flip-ready", arm, victim, mode, false);
            assert_capture_exit(&output, mode);
            assert!(output.stdout.is_empty());
        }
    }
}

#[test]
fn old_base_commit_gate_and_policy_capture_errors_escape() {
    for (arm, reason) in [
        ("last-job-log", "no-gate-at-base"),
        ("commit-probe", "no-gate-at-base"),
        ("commit-probe", "no_policy"),
        ("old-config-path", "no_policy"),
        ("old-config-tree", "no_policy"),
    ] {
        for mode in ["missing", "denied"] {
            let f = Fixture::new(
                false,
                &format!("outcome=unavailable log=- reason={reason} base={BASE}"),
            );
            let output = f.run("flip-ready", arm, "git", mode, false);
            f.armed(arm);
            assert_capture_exit(&output, mode);
            assert!(output.stdout.is_empty());
            assert!(!f.calls().contains("published-url "));
            // A failed commit capture must not be converted into a missing-commit fetch.
            assert!(!f.calls().contains(&format!("fetch fetch -q origin {BASE}")));
        }
    }
}

#[test]
fn published_url_init_fetch_and_log_oserrors_keep_observed_clock_fallback() {
    for arm in [
        "last-job-log",
        "published-url",
        "published-init",
        "published-fetch",
    ] {
        for mode in ["missing", "denied"] {
            let f = Fixture::new(false, "outcome=satisfied log=ok");
            let output = f.run("flip-ready", arm, "git", mode, false);
            f.armed(arm);
            assert_eq!(
                output.status.code(),
                Some(0),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            let clock = report["log_clock"].as_str().unwrap();
            assert!(clock.starts_with("observed_at ("), "{clock}");
            let expected = if mode == "missing" {
                "No such file or directory"
            } else {
                "Permission denied"
            };
            assert!(clock.contains(expected), "{clock}");
        }
    }
}

#[test]
fn published_grep_capture_error_is_not_a_missing_record() {
    for mode in ["missing", "denied"] {
        let f = Fixture::new(
            false,
            &format!("outcome=satisfied log=unlogged_pass record={BASE}"),
        );
        let output = f.run("flip-ready", "published-log", "git", mode, false);
        f.armed("published-log");
        assert_capture_exit(&output, mode);
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn proposal_list_and_push_capture_errors_stop_before_the_next_ready_check() {
    for (arm, victim) in [("published-log", "gh"), ("commit", "git")] {
        let f = Fixture::new(true, "outcome=satisfied log=ok");
        let output = f.run("flip-ready", arm, victim, "missing", true);
        f.armed(arm);
        assert_capture_exit(&output, "missing");
        let calls = f.calls();
        assert!(!calls.contains("--head evidence-flip/z-check"), "{calls}");
        assert!(!calls.contains("pr-create "), "{calls}");
        if arm == "commit" {
            assert!(calls.contains("pr-list "), "{calls}");
            assert!(calls.contains("commit commit -q -m"), "{calls}");
        }
    }
}

#[test]
fn proposal_cleanup_capture_error_escapes_after_successful_creation() {
    let f = Fixture::new(true, "outcome=satisfied log=ok");
    let output = f.run("flip-ready", "pr-create", "git", "missing", true);
    f.armed("pr-create");
    assert_capture_exit(&output, "missing");
    let calls = f.calls();
    assert!(
        calls.contains("push push -q origin HEAD:refs/heads/evidence-flip/genie-freshness"),
        "{calls}"
    );
    assert!(calls.contains("pr-create "), "{calls}");
    assert!(!calls.contains("--head evidence-flip/z-check"), "{calls}");
}

#[test]
fn skip_lane_capture_errors_do_not_retry_and_policy_capture_errors_do_not_default() {
    for arm in ["last-job-log", "lane-path", "lane-show", "old-config-path"] {
        for mode in ["missing", "denied"] {
            let f = Fixture::new(false, &format!("outcome=no_note log=unsigned base={BASE}"));
            let output = f.run("skip-report", arm, "git", mode, false);
            f.armed(arm);
            assert_capture_exit(&output, mode);
            assert!(output.stdout.is_empty());
            let calls = f.calls();
            assert!(
                !calls.lines().any(|line| line.starts_with("fetch ")),
                "capture error retried: {calls}"
            );
            assert!(
                !calls.contains("release-runs "),
                "capture error defaulted: {calls}"
            );
        }
    }
}

#[test]
fn skip_initial_github_spawn_error_is_not_readability_exit_two() {
    for mode in ["missing", "denied"] {
        let f = Fixture::new(false, "outcome=satisfied log=ok");
        if mode == "missing" {
            fs::remove_file(f.bin.join("gh")).unwrap();
        } else {
            fs::set_permissions(f.bin.join("gh"), fs::Permissions::from_mode(0o000)).unwrap();
        }
        let output = f.run("skip-report", "unused", "gh", mode, false);
        assert_capture_exit(&output, mode);
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn completed_old_base_and_grep_probes_keep_their_nonfatal_boundaries() {
    for (arm, fields) in [
        (
            "last-job-log",
            format!("outcome=unavailable log=- reason=no-gate-at-base base={BASE}"),
        ),
        (
            "commit-probe",
            format!("outcome=unavailable log=- reason=no-gate-at-base base={BASE}"),
        ),
        (
            "old-config-tree",
            format!("outcome=unavailable log=- reason=no_policy base={BASE}"),
        ),
        (
            "published-log",
            format!("outcome=satisfied log=unlogged_pass record={BASE}"),
        ),
    ] {
        let f = Fixture::new(false, &fields);
        let output = f.run("flip-ready", arm, "git", "completed", false);
        f.armed(arm);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["log_clock"], "published log");
        if arm == "last-job-log" {
            assert!(f.calls().contains(&format!("fetch fetch -q origin {BASE}")));
        }
        if arm == "commit-probe" {
            assert_eq!(
                report["checks"]["genie-freshness"]["old_base_lines"]["no-gate-at-base"],
                1
            );
        }
        if arm == "published-log" {
            assert_eq!(
                report["checks"]["genie-freshness"]["unlogged_pass_unexplained"],
                1
            );
        }
    }
}

#[test]
fn completed_skip_lane_probe_retries_and_policy_probe_may_default() {
    for arm in ["last-job-log", "old-config-path"] {
        let f = Fixture::new(false, &format!("outcome=no_note log=unsigned base={BASE}"));
        let output = f.run("skip-report", arm, "git", "completed", false);
        f.armed(arm);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        if arm == "last-job-log" {
            assert!(f.calls().contains(&format!("fetch fetch -q origin {BASE}")));
            assert_eq!(report["checks"]["genie-freshness"]["shadow_unsigned"], 1);
        } else {
            assert_eq!(report["checks"]["genie-freshness"]["not_signed"], 1);
        }
    }
}
