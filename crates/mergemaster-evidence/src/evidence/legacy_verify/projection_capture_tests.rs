use super::*;
use serde_json::Value;
use std::process::Stdio;
#[test]
fn record_subject_requires_an_exact_missing_result() {
    let subject = "a".repeat(40);
    for (stdout, stderr, status, expected) in [
        (format!("{subject}\n"), "", 0, Some(true)),
        (
            format!("{subject}\n"),
            "ERROR: ld.so: object cannot be preloaded",
            0,
            Some(true),
        ),
        (format!("{subject} missing\n"), "", 0, Some(false)),
        (format!("{subject} missing\n"), "corrupt object", 0, None),
        (String::new(), "", 1, None),
        (String::new(), "fatal: repository unavailable", 128, None),
        ("x".repeat(128), "", 0, None),
        ("x".repeat(129), "", 0, None),
    ] {
        let mut command = Command::new("python3");
        command
            .args(["-c", "import sys;sys.stdin.buffer.read();sys.stdout.write(sys.argv[1]);sys.stderr.write(sys.argv[2]);sys.exit(int(sys.argv[3]))"])
            .arg(stdout)
            .arg(stderr)
            .arg(status.to_string())
            .stdin(Stdio::piped());
        let result = record_subject(&mut command, &subject);
        if let Some(expected) = expected {
            assert_eq!(result.unwrap(), expected);
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.reason, "subject-probe-failed");
            assert_eq!(
                error.origin,
                crate::evidence::legacy_policy::ErrorOrigin::Failure
            );
        }
    }
    let error = record_subject(
        &mut Command::new("/definitely-missing-subject-git"),
        &subject,
    )
    .unwrap_err();
    assert_eq!(error.reason, "subject-probe-failed");
    assert!(
        error
            .detail
            .to_string()
            .contains("No such file or directory")
    );
}

#[test]
fn record_subject_timeout_refuses() {
    let subject = "a".repeat(40);
    let mut command = Command::new("python3");
    command
        .args(["-c", "import signal;signal.pause()"])
        .stdin(Stdio::piped());
    let sink = SubjectCapture {
        capture: ProjectionCapture::new("cat-file", ExpectedOutput::Bytes(128)),
        subject: &subject,
    };
    let error = collect(&mut command, b"", "cat-file", Duration::ZERO, sink)
        .map_err(subject_error)
        .unwrap_err();
    assert_eq!(error.reason, "subject-probe-failed");
    assert!(error.detail.to_string().contains("timed out"));
}
fn run(
    bytes: &[u8],
    expected: ExpectedOutput,
    stderr: &str,
    repeat: usize,
    status: i32,
) -> Result<Vec<u8>, PolicyError> {
    let mut command = Command::new("python3");
    command.args(["-c","import sys;data=sys.stdin.buffer.read();sys.stderr.buffer.write(bytes.fromhex(sys.argv[1])*int(sys.argv[2]));sys.stderr.buffer.flush();sys.stdout.buffer.write(data);sys.exit(int(sys.argv[3]))",stderr,&repeat.to_string(),&status.to_string()]).stdin(Stdio::piped());
    exchange(
        &mut command,
        bytes,
        "write-tree",
        expected,
        Duration::from_secs(60),
    )
}
#[test]
fn stderr_is_bounded_but_only_exit_status_refuses() {
    let oid = vec![b'a'; 40];
    assert!(
        run(&vec![b'x'; 200_000], ExpectedOutput::Discard, "", 0, 0)
            .unwrap()
            .is_empty()
    );
    for size in [1_048_576, 1_048_577] {
        assert_eq!(run(&oid, ExpectedOutput::Sha1, "65", size, 0).unwrap(), oid);
        let error = run(&oid, ExpectedOutput::Sha1, "65", size, 7).unwrap_err();
        assert_eq!(error.reason, "error");
        if size > STDERR_LIMIT {
            assert_eq!(error.detail, "Git projection stderr exceeds 1048576 bytes");
        } else {
            assert_eq!(
                error.detail.to_string().len(),
                size + "git write-tree: ".len()
            );
        }
    }
    let oracle=crate::pinned_python::command().args(["-c","import json; samples=[b'fatal: bad tree\\n',b'warning: first\\nfatal: last\\n',b'\\xff\\xfe fatal\\n',b'\\x1c\\xc2\\x85fatal: unicode\\xc2\\x85\\x1f']; print(json.dumps([[s.hex(),'git write-tree: '+s.decode(errors='replace').strip()] for s in samples]))"]).output().unwrap();
    let cases: Vec<Value> = serde_json::from_slice(&oracle.stdout).unwrap();
    for case in cases {
        let error = run(&oid, ExpectedOutput::Sha1, case[0].as_str().unwrap(), 1, 7).unwrap_err();
        assert_eq!(error.detail.to_string(), case[1].as_str().unwrap());
    }
}
#[test]
fn spawn_and_timeout_keep_python_operation_context() {
    for (program, timeout, expected) in [
        (
            "/definitely-missing-projection-git",
            Duration::from_secs(60),
            "git write-tree: [Errno 2] No such file or directory: '/definitely-missing-projection-git'",
        ),
        (
            "python3",
            Duration::ZERO,
            "git write-tree: Command '['python3', '-c', 'import signal;signal.pause()']' timed out after 0 seconds",
        ),
    ] {
        let mut command = Command::new(program);
        command
            .args(["-c", "import signal;signal.pause()"])
            .stdin(Stdio::piped());
        let error = exchange(
            &mut command,
            b"",
            "write-tree",
            ExpectedOutput::Sha1,
            timeout,
        )
        .unwrap_err();
        assert_eq!(error.reason, "error");
        assert_eq!(error.detail, expected);
    }
}

#[test]
fn byte_capture_preserves_binary_and_aborts_overflow() {
    let bytes = vec![0xff; 200_000];
    assert_eq!(
        run(
            &bytes,
            ExpectedOutput::Bytes(bytes.len()),
            "65",
            1_048_577,
            0
        )
        .unwrap(),
        bytes
    );
    assert_eq!(
        run(&bytes, ExpectedOutput::Bytes(17), "", 0, 0)
            .unwrap_err()
            .detail,
        "Git output exceeds 17 bytes"
    );
    assert_eq!(run(b"", ExpectedOutput::Bytes(0), "", 0, 0).unwrap(), b"");
}

#[cfg(target_os = "linux")]
#[test]
fn byte_overflow_stops_endless_output_and_reaps_child() {
    for limit in [0, 17, 16 * 1024 * 1024] {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("pid");
        let mut command = crate::pinned_python::command();
        command.args(["-c", "import os,signal,sys;open(sys.argv[1],'w').write(str(os.getpid()));signal.alarm(30)\nwhile True: os.write(1,b'x'*65536)"])
            .arg(&pid_path).stdin(Stdio::piped());
        let error = exchange(
            &mut command,
            b"",
            "show",
            ExpectedOutput::Bytes(limit),
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert_eq!(
            error.detail.to_string(),
            format!("Git output exceeds {limit} bytes")
        );
        assert_eq!(error.reason, "error");
        assert_eq!(error.resource, None);
        assert_eq!(
            error.origin,
            crate::evidence::legacy_policy::ErrorOrigin::Failure
        );
        let pid = std::fs::read_to_string(pid_path).unwrap().parse().unwrap();
        assert_reaped(pid);
        let exact = vec![b'x'; limit];
        assert_eq!(
            run(&exact, ExpectedOutput::Bytes(limit), "", 0, 0).unwrap(),
            exact
        );
    }
}

#[test]
fn source_capture_aborts_at_boundary_and_reaps_child() {
    use super::super::{
        source_resource::{SOURCE_BYTES, SourceResource},
        statement_document::PolicyResource,
    };
    let resource = SourceResource::PolicyJson(PolicyResource::SourceBytes);
    let exact = vec![b'x'; SOURCE_BYTES];
    assert_eq!(
        run(
            &exact,
            ExpectedOutput::Source(resource.clone()),
            "65",
            SOURCE_BYTES + 1,
            0
        )
        .unwrap(),
        exact
    );
    let error = run(&exact, ExpectedOutput::Source(resource.clone()), "65", 3, 7).unwrap_err();
    assert_eq!(error.resource, None);
    assert_eq!(error.detail, "git write-tree: eee");
    let directory = tempfile::tempdir().unwrap();
    let pid_path = directory.path().join("pid");
    let mut command = Command::new("python3");
    command.args(["-c", "import os,sys;open(sys.argv[1],'w').write(str(os.getpid()));sys.stderr.buffer.write(b'e'*1048577);sys.stderr.buffer.flush();sys.stdout.buffer.write(b'x'*1048577);sys.stdout.buffer.flush();\nwhile True: os.write(1,b'x'*65536)"]).arg(&pid_path);
    command.stdin(Stdio::piped());
    let error = exchange(
        &mut command,
        b"",
        "show",
        ExpectedOutput::Source(resource.clone()),
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert_eq!(error.resource, Some(resource.clone()));
    assert_eq!(error.detail, resource.detail());
    assert_eq!(
        error.origin,
        crate::evidence::legacy_policy::ErrorOrigin::Failure
    );
    assert_eq!(error.reason, "error");
    let pid: i32 = std::fs::read_to_string(pid_path).unwrap().parse().unwrap();
    let status = Command::new("python3").args(["-c", "import os,sys\ntry: os.kill(int(sys.argv[1]),0)\nexcept ProcessLookupError: sys.exit(0)\nsys.exit(1)", &pid.to_string()]).status().unwrap();
    assert!(
        status.success(),
        "capture must kill and reap the direct child"
    );
}

#[cfg(target_os = "linux")]
fn assert_reaped(pid: u32) {
    let mut status = 0;
    // SAFETY: status is writable, and WNOHANG only queries this former direct child.
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn signal_and_eof_before_exit_refuse_and_reap() {
    for (script, timeout, detail) in [
        (
            "import os,signal,sys;open(sys.argv[1],'w').write(str(os.getpid()));os.write(1,b'a'*40);os.write(2,b'fatal\\n');os.kill(os.getpid(),signal.SIGTERM)",
            Duration::from_secs(60),
            "git write-tree: fatal",
        ),
        (
            "import os,signal,sys;os.write(1,b'a'*40);os.close(1);os.close(2);open(sys.argv[1],'w').write(str(os.getpid()));signal.alarm(30);signal.pause()",
            Duration::from_secs(2),
            "timed out after 2 seconds",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("pid");
        let mut command = crate::pinned_python::command();
        command
            .args(["-c", script])
            .arg(&pid_path)
            .stdin(Stdio::piped());
        let error = exchange(
            &mut command,
            b"",
            "write-tree",
            ExpectedOutput::Sha1,
            timeout,
        )
        .unwrap_err();
        assert_eq!(error.reason, "error");
        assert_eq!(error.resource, None);
        assert_eq!(
            error.origin,
            crate::evidence::legacy_policy::ErrorOrigin::Failure
        );
        if timeout == Duration::from_secs(60) {
            assert_eq!(error.detail, detail);
        } else {
            assert!(error.detail.to_string().starts_with("git write-tree: "));
            assert!(error.detail.to_string().ends_with(detail));
        }
        let pid = std::fs::read_to_string(pid_path).unwrap().parse().unwrap();
        assert_reaped(pid);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn io_error_and_early_drop_kill_and_reap() {
    use std::io::Read;
    let directory = tempfile::tempdir().unwrap();
    let pid_path = directory.path().join("pid");
    let mut command = crate::pinned_python::command();
    command.args(["-c", "import os,signal,sys;open(sys.argv[1],'w').write(str(os.getpid()));os.close(0);signal.alarm(30);signal.pause()"]).arg(&pid_path).stdin(Stdio::piped());
    let error = exchange(
        &mut command,
        &vec![b'x'; 1_048_576],
        "hash-object",
        ExpectedOutput::Discard,
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert_eq!(error.detail, "git hash-object: [Errno 32] Broken pipe");
    assert_eq!(error.reason, "error");
    assert_eq!(error.resource, None);
    assert_eq!(
        error.origin,
        crate::evidence::legacy_policy::ErrorOrigin::Failure
    );
    assert_reaped(std::fs::read_to_string(pid_path).unwrap().parse().unwrap());

    // The synchronous collector owns this same GitChild; dropping its owner
    // must cancel a live child even before EOF or a completed exchange.
    let mut command = crate::pinned_python::command();
    command.args([
        "-c",
        "import os,signal;os.write(1,b'x');signal.alarm(30);signal.pause()",
    ]);
    let mut child = GitChild::spawn(&mut command).unwrap();
    let pid = child.id();
    let mut ready = [0];
    child.stdout().unwrap().read_exact(&mut ready).unwrap();
    assert_eq!(ready, [b'x']);
    drop(child);
    assert_reaped(pid);
}
