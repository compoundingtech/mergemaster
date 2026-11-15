use super::*;
use serde_json::Value;
use std::process::Stdio;
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
    let oracle=Command::new("python3").args(["-c","import json; samples=[b'fatal: bad tree\\n',b'warning: first\\nfatal: last\\n',b'\\xff\\xfe fatal\\n',b'\\x1c\\xc2\\x85fatal: unicode\\xc2\\x85\\x1f']; print(json.dumps([[s.hex(),'git write-tree: '+s.decode(errors='replace').strip()] for s in samples]))"]).output().unwrap();
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
