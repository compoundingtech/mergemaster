use mergemaster_evidence::evidence::log_watch::{MAX_STATE_DEPTH, State, step};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const T0: i64 = 1_800_000_000;
const LOG: &str = "refs/evidence-log/main";
const SEEN: &str = "refs/evidence-log/watched";
fn python() -> String {
    std::env::var("MERGEMASTER_ORACLE_PYTHON").unwrap_or_else(|_| {
        "/nix/store/d64q19q1xjdwfhqx6czvrjgrhq0n3lcc-python3-3.14.7/bin/python3.14".into()
    })
}
fn git(repo: &Path, args: &[&str]) -> Output {
    let mut command = Command::new("git");
    for (key, _) in std::env::vars_os() {
        if key.as_encoded_bytes().starts_with(b"GIT_") {
            command.env_remove(key);
        }
    }
    command
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "l")
        .env("GIT_AUTHOR_EMAIL", "l@x")
        .env("GIT_COMMITTER_NAME", "l")
        .env("GIT_COMMITTER_EMAIL", "l@x")
        .env("GIT_AUTHOR_DATE", "1800000000 +0000")
        .env("GIT_COMMITTER_DATE", "1800000000 +0000")
        .output()
        .unwrap()
}
fn success(done: Output) -> String {
    assert!(
        done.status.success(),
        "{}",
        String::from_utf8_lossy(&done.stderr)
    );
    String::from_utf8(done.stdout).unwrap().trim().to_owned()
}
struct Watch {
    root: tempfile::TempDir,
    remote: PathBuf,
    state: PathBuf,
    sent: PathBuf,
}
impl Watch {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let remote = root.path().join("remote.git");
        success(
            Command::new("git")
                .args(["init", "-q", "--bare"])
                .arg(&remote)
                .output()
                .unwrap(),
        );
        let state = root.path().join("state");
        let sent = root.path().join("sent");
        Self {
            root,
            remote,
            state,
            sent,
        }
    }
    fn publish(&self, time: i64) {
        let stamp = chrono::DateTime::from_timestamp(time, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S+00:00");
        self.subject(&format!(
            "evidence-log v1 as_of={stamp} added=0 gc=0 missing=0"
        ));
    }
    fn subject(&self, subject: &str) {
        let tree = success(git(
            &self.remote,
            &["hash-object", "-w", "-t", "tree", "--stdin"],
        ));
        let parent = git(&self.remote, &["rev-parse", "--verify", LOG]);
        let parent = String::from_utf8(parent.stdout).unwrap();
        let mut args = vec!["commit-tree", &tree, "-m", subject];
        if !parent.trim().is_empty() {
            args.extend(["-p", parent.trim()]);
        }
        let head = success(git(&self.remote, &args));
        success(git(&self.remote, &["update-ref", LOG, &head]));
    }
    fn notify(&self) -> Value {
        json!([
            python(),
            "-c",
            "import sys; open(sys.argv[1], 'a').write(sys.argv[2] + '\\n')",
            self.sent
        ])
    }
    fn command(
        &self,
        now: i64,
        notify: &Value,
        remote: &Path,
        state: &Path,
        oracle: bool,
    ) -> Command {
        let mut command = if oracle {
            let mut command = Command::new(python());
            command.args(["-I", "-B"]).arg(
                Path::new(&std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
                    .join("scripts/evidence-log-watch"),
            );
            command
        } else {
            let mut command = Command::new(
                std::env::var_os("CARGO_BIN_EXE_mergemaster")
                    .expect("CARGO_BIN_EXE_mergemaster is set at test runtime"),
            );
            command.args(["evidence", "log-watch"]);
            command
        };
        command
            .arg("--remote")
            .arg(remote)
            .arg("--state")
            .arg(state)
            .args([
                "--notify",
                &notify.to_string(),
                "--now",
                &now.to_string(),
                "--repeat",
                "3600",
            ]);
        command
    }
    fn run(&self, now: i64) -> (i32, Value) {
        self.run_with(now, &self.notify(), &self.remote)
    }
    fn run_with(&self, now: i64, notify: &Value, remote: &Path) -> (i32, Value) {
        let done = self
            .command(now, notify, remote, &self.state, false)
            .output()
            .unwrap();
        let text = String::from_utf8(done.stdout).unwrap();
        let result = serde_json::from_str(text.lines().last().unwrap_or("null")).unwrap();
        (done.status.code().unwrap(), result)
    }
    fn lines(&self) -> Vec<String> {
        fs::read_to_string(&self.sent)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

#[test]
fn log_watch_frozen_transition_recordings_are_pure() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/oracle/log-watch.json"
    ))
    .unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        let before = State::parse(&serde_json::to_vec(&case["before"]).unwrap()).unwrap();
        let unchanged = before.json().unwrap();
        let (state, line, stalled) = step(
            &before,
            case["now"].as_f64().unwrap(),
            case["as_of"].as_f64(),
            case["detail"].as_str().unwrap(),
            case["max_age"].as_i64().unwrap(),
            case["repeat"].as_i64().unwrap(),
        )
        .unwrap();
        assert_eq!(before.json().unwrap(), unchanged, "{}", case["id"]);
        let mut state: Value = serde_json::from_str(&state.json().unwrap()).unwrap();
        let mut expected = case["expected"].clone();
        // JSON time numbers are compared numerically, not by integer/float spelling.
        for value in state
            .as_object_mut()
            .unwrap()
            .values_mut()
            .chain(expected["state"].as_object_mut().unwrap().values_mut())
        {
            if let Some(number) = value.as_f64() {
                *value = json!(number);
            }
        }
        assert_eq!(
            json!({"state":state,"line":line,"stalled":stalled}),
            expected,
            "{}",
            case["id"]
        );
    }
}

#[test]
fn log_watch_current_stall_repeat_recovery() {
    let watch = Watch::new();
    watch.publish(T0);
    assert_eq!(watch.run(T0 + 130).0, 0);
    assert!(watch.lines().is_empty());
    let (code, result) = watch.run(T0 + 400);
    assert_eq!(
        (
            code,
            result["stalled"].as_bool(),
            result["notified"].as_bool()
        ),
        (1, Some(true), Some(true))
    );
    assert_eq!(watch.lines().len(), 1);
    assert!(watch.lines()[0].contains("evidence log STALLED"));
    assert!(watch.lines()[0].contains("400s old"));
    assert_eq!(watch.run(T0 + 520).0, 1);
    assert_eq!(watch.lines().len(), 1);
    assert_eq!(watch.run(T0 + 4000).0, 1);
    assert_eq!(watch.lines().len(), 2);
    assert!(watch.lines()[1].contains("still stalled since"));
    watch.publish(T0 + 4100);
    assert_eq!(watch.run(T0 + 4120).0, 0);
    assert_eq!(watch.lines().len(), 3);
    assert!(watch.lines()[2].contains("evidence log moving again"));
    assert_eq!(watch.run(T0 + 4240).0, 0);
    assert_eq!(watch.lines().len(), 3);
}

#[test]
fn log_watch_unreadable_grace() {
    let watch = Watch::new();
    let (code, result) = watch.run(T0);
    assert_eq!((code, result["stalled"].as_bool()), (0, Some(false)));
    assert!(
        result["problem"]
            .as_str()
            .unwrap()
            .contains("fetch of the log head failed")
    );
    assert_eq!(watch.run(T0 + 300).0, 0);
    assert!(watch.lines().is_empty());
    assert_eq!(watch.run(T0 + 400).0, 1);
    assert!(watch.lines()[0].contains("cannot be read for 400s"));
}

#[test]
fn log_watch_failed_notification_retries() {
    let watch = Watch::new();
    watch.publish(T0);
    assert_eq!(
        watch
            .run_with(
                T0 + 400,
                &json!([python(), "-c", "import sys; sys.exit(1)"]),
                &watch.remote
            )
            .0,
        3
    );
    assert_eq!(watch.run(T0 + 520).0, 1);
    assert_eq!(watch.lines().len(), 1);
    assert!(watch.lines()[0].contains("evidence log STALLED"));
}

#[test]
fn log_watch_corrupt_objects_repair_preserves_notifications() {
    let watch = Watch::new();
    watch.publish(T0);
    assert_eq!(watch.run(T0 + 400).0, 1);
    let repo = watch.state.join("head.git");
    for offset in [500, 600] {
        watch.publish(T0 + offset);
        success(git(
            &repo,
            &[
                "fetch",
                "-q",
                "--no-tags",
                "--depth=1",
                watch.remote.to_str().unwrap(),
                &format!("+{LOG}:{SEEN}"),
            ],
        ));
        let old = success(git(&repo, &["rev-parse", SEEN]));
        let loose = repo.join("objects").join(&old[..2]).join(&old[2..]);
        fs::create_dir_all(loose.parent().unwrap()).unwrap();
        if loose.exists() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
        }
        fs::write(loose, b"").unwrap();
        let (code, result) = watch.run(T0 + offset + 1);
        assert_eq!((code, result["stalled"].as_bool()), (0, Some(false)));
        assert_eq!(
            result["head"],
            success(git(&watch.remote, &["rev-parse", LOG]))
        );
        assert_eq!(
            fs::read_dir(&watch.state)
                .unwrap()
                .filter(|entry| entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("head.git.broken-"))
                .count(),
            1
        );
    }
    assert_eq!(watch.lines().len(), 2);
    assert!(watch.lines()[1].contains("moving again"));
}

#[test]
fn log_watch_unreachable_does_not_rebuild_healthy_copy() {
    let watch = Watch::new();
    watch.publish(T0);
    assert_eq!(watch.run(T0).1["as_of"], "2027-01-15T08:00:00Z");
    let (code, result) = watch.run_with(
        T0,
        &watch.notify(),
        &watch.root.path().join("unreachable.git"),
    );
    assert_eq!(code, 0);
    assert!(result["as_of"].is_null());
    assert!(
        result["problem"]
            .as_str()
            .unwrap()
            .contains("fetch of the log head failed")
    );
    assert!(!fs::read_dir(&watch.state).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("head.git.broken-")
    }));
    #[cfg(target_os = "linux")]
    {
        let command = watch.command(
            T0,
            &watch.notify(),
            &watch.root.path().join("unreachable.git"),
            &watch.state,
            false,
        );
        let trace = watch.root.path().join("fetch-trace");
        success(
            Command::new("strace")
                .args(["-f", "-e", "trace=execve", "-o"])
                .arg(&trace)
                .arg(command.get_program())
                .args(command.get_args())
                .output()
                .expect("strace is required"),
        );
        let trace = fs::read_to_string(trace).unwrap();
        assert_eq!(
            trace
                .lines()
                .filter(|line| line.contains("execve(")
                    && line.contains("\"fetch\"")
                    && line.ends_with("= 0"))
                .count(),
            1,
            "{trace}"
        );
    }
}

#[test]
fn log_watch_bad_notify_argv_and_subject_errors() {
    let watch = Watch::new();
    for notify in [json!("x"), json!([]), json!([1]), Value::Null] {
        assert_eq!(watch.run_with(T0, &notify, &watch.remote).0, 2);
    }
    for (subject, problem) in [
        ("no time", "names no time"),
        ("as_of=bad", "unreadable time"),
        ("as_of=2027-01-15T08:00:00", "without a zone"),
    ] {
        watch.subject(subject);
        assert!(
            watch.run(T0).1["problem"]
                .as_str()
                .unwrap()
                .contains(problem)
        );
    }
}

#[test]
fn log_watch_pinned_python_assertions_and_differential() {
    let oracle = PathBuf::from(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap());
    let source = fs::read(oracle.join("scripts/evidence-log-watch")).unwrap();
    use sha1::{Digest, Sha1};
    let mut blob = Sha1::new();
    blob.update(format!("blob {}\0", source.len()));
    blob.update(source);
    assert_eq!(
        hex::encode(blob.finalize()),
        "f580ed13fe4f8130ec936dfeefb64f6c3b97b2f1"
    );
    success(
        Command::new(python())
            .args(["-I", "-B"])
            .arg(oracle.join("scripts/evidence-log-watch-test"))
            .output()
            .unwrap(),
    );
    let watch = Watch::new();
    let native = watch.state.clone();
    let independent = watch.root.path().join("oracle-state");
    for (offset, publish, failed) in [
        (130, Some(T0), false),
        (400, None, true),
        (520, None, false),
        (600, None, false),
        (4120, None, false),
        (4300, Some(T0 + 4290), false),
    ] {
        if let Some(time) = publish {
            watch.publish(time);
        }
        let notify = json!([
            python(),
            "-c",
            if failed {
                "import sys; sys.exit(1)"
            } else {
                "pass"
            }
        ]);
        let mut results = Vec::new();
        for (oracle, state) in [(false, &native), (true, &independent)] {
            let done = watch
                .command(T0 + offset, &notify, &watch.remote, state, oracle)
                .output()
                .unwrap();
            let saved: Value =
                serde_json::from_slice(&fs::read(state.join("watch.json")).unwrap()).unwrap();
            results.push((done.status.code(), done.stdout, done.stderr, saved));
        }
        assert_eq!(results[0], results[1]);
    }
    let root = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set at test runtime"),
    )
    .join("../..");
    success(Command::new(python()).args(["-B", "-c", "import sys; sys.path.insert(0, 'tests'); from oracle_corpus import replay_log_watch; from pathlib import Path; replay_log_watch(Path(sys.executable))"]).current_dir(root).output().unwrap());
}

/// aarch64 Linux has no plain rename syscall; libc uses renameat there.
#[cfg(target_os = "linux")]
fn is_rename(line: &str) -> bool {
    ["rename(", "renameat(", "renameat2("]
        .iter()
        .any(|call| line.contains(&format!(" {call}")))
}

#[cfg(target_os = "linux")]
#[test]
fn log_watch_state_syncs_before_rename_and_after_directory_update() {
    let watch = Watch::new();
    watch.publish(T0);
    let command = watch.command(T0, &watch.notify(), &watch.remote, &watch.state, false);
    let trace = watch.root.path().join("trace");
    let done = Command::new("strace")
        .args([
            "-f",
            "-yy",
            "-e",
            "trace=fsync,fdatasync,rename,renameat,renameat2,openat",
            "-o",
        ])
        .arg(&trace)
        .arg(command.get_program())
        .args(command.get_args())
        .output()
        .expect("strace is a required Linux evidence test dependency");
    success(done);
    let trace = fs::read_to_string(trace).unwrap();
    let events: Vec<_> = trace
        .lines()
        .filter(|line| line.contains("watch.json") && (line.contains("fsync(") || is_rename(line)))
        .collect();
    assert_eq!(events.len(), 2, "{trace}");
    assert!(events[0].contains("fsync("), "{trace}");
    assert!(is_rename(events[1]), "{trace}");
    let rename = trace.find(events[1]).unwrap();
    assert!(
        trace[rename..].lines().any(|line| line.contains("fsync(")
            && line.contains(&format!("<{}>", watch.state.display()))),
        "{trace}"
    );
    let saved: Value =
        serde_json::from_slice(&fs::read(watch.state.join("watch.json")).unwrap()).unwrap();
    assert_eq!(saved["last_as_of"].as_f64(), Some(T0 as f64));
}

#[test]
fn log_watch_frozen_subject_recordings_differential() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/oracle/log-watch.json"
    ))
    .unwrap();
    let watch = Watch::new();
    let oracle_state = watch.root.path().join("oracle-state");
    let notify = json!([python(), "-c", "pass"]);
    for case in corpus["subjects"].as_array().unwrap() {
        watch.subject(case["subject"].as_str().unwrap());
        for (oracle, state) in [(false, &watch.state), (true, &oracle_state)] {
            let done = watch
                .command(
                    case["now"].as_i64().unwrap(),
                    &notify,
                    &watch.remote,
                    state,
                    oracle,
                )
                .output()
                .unwrap();
            assert_eq!(
                done.status.code(),
                Some(case["exit_code"].as_i64().unwrap() as i32),
                "{case}"
            );
            assert_eq!(
                String::from_utf8(done.stdout).unwrap(),
                case["stdout"].as_str().unwrap(),
                "{case}"
            );
            assert_eq!(
                String::from_utf8(done.stderr).unwrap(),
                case["stderr"].as_str().unwrap(),
                "{case}"
            );
        }
    }
}

#[test]
fn log_watch_invalid_recovery_timestamp_fails_without_notification_or_state_write() {
    let watch = Watch::new();
    watch.publish(T0);
    let before = json!({"stalled_since": 1e20, "told_at": T0 - 4000});
    let notify = watch.notify();
    for oracle in [false, true] {
        let state = watch.root.path().join(if oracle {
            "oracle-invalid-state"
        } else {
            "native-invalid-state"
        });
        fs::create_dir_all(&state).unwrap();
        let path = state.join("watch.json");
        let bytes = serde_json::to_vec(&before).unwrap();
        fs::write(&path, &bytes).unwrap();
        let done = watch
            .command(T0, &notify, &watch.remote, &state, oracle)
            .output()
            .unwrap();
        assert_eq!(done.status.code(), Some(1));
        assert!(done.stdout.is_empty());
        assert!(!done.stderr.is_empty());
        assert_eq!(fs::read(path).unwrap(), bytes);
        assert!(watch.lines().is_empty());
    }
}

#[test]
fn log_watch_persisted_numeric_edges_match_frozen_python() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/oracle/log-watch-state.json"
    ))
    .unwrap();
    for case in corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .chain(corpus["encodings"].as_array().unwrap())
    {
        let watch = Watch::new();
        if case["mode"] == "unreadable" {
            watch.subject("no time");
        } else {
            watch.publish(T0);
        }
        let notify = json!([python(), "-c", "pass"]);
        for oracle in [false, true] {
            let state = watch.root.path().join(if oracle {
                "oracle-matrix"
            } else {
                "native-matrix"
            });
            fs::create_dir_all(&state).unwrap();
            let path = state.join("watch.json");
            let bytes = if let Some(encoded) = case["state_before_base64"].as_str() {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap()
            } else {
                case["state_before"].as_str().unwrap().as_bytes().to_vec()
            };
            fs::write(&path, bytes).unwrap();
            let done = watch
                .command(
                    case["now"].as_i64().unwrap(),
                    &notify,
                    &watch.remote,
                    &state,
                    oracle,
                )
                .output()
                .unwrap();
            let expected = &case["expected"];
            assert_eq!(
                done.status.code(),
                Some(expected["exit_code"].as_i64().unwrap() as i32),
                "{}",
                case["id"]
            );
            assert_eq!(
                String::from_utf8(done.stdout).unwrap(),
                expected["stdout"].as_str().unwrap(),
                "{}",
                case["id"]
            );
            assert_eq!(
                !done.stderr.is_empty(),
                expected["stderr_nonempty"].as_bool().unwrap(),
                "{}",
                case["id"]
            );
            assert_eq!(
                fs::read_to_string(path).unwrap(),
                expected["state_after"].as_str().unwrap(),
                "{}",
                case["id"]
            );
        }
    }
}

#[test]
fn log_watch_state_depth_bound_fails_without_notification_or_save() {
    let watch = Watch::new();
    watch.publish(T0);
    for depth in [MAX_STATE_DEPTH, MAX_STATE_DEPTH + 1, 5000, 100000] {
        let state = watch.root.path().join(format!("depth-{depth}"));
        fs::create_dir_all(&state).unwrap();
        let path = state.join("watch.json");
        let bytes = format!(
            "{{\"unknown\": {}0{}}}",
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        fs::write(&path, &bytes).unwrap();
        let done = watch
            .command(T0, &watch.notify(), &watch.remote, &state, false)
            .output()
            .unwrap();
        if depth == MAX_STATE_DEPTH {
            assert!(
                done.status.success(),
                "{}",
                String::from_utf8_lossy(&done.stderr)
            );
            let saved = fs::read_to_string(&path).unwrap();
            assert!(saved.contains("\"last_head\""));
            assert!(State::parse(saved.as_bytes()).is_ok());
        } else {
            assert_eq!(done.status.code(), Some(1));
            assert!(done.stdout.is_empty());
            assert!(String::from_utf8_lossy(&done.stderr).contains("container levels"));
            assert_eq!(fs::read_to_string(path).unwrap(), bytes);
        }
        assert!(watch.lines().is_empty());
    }
}
