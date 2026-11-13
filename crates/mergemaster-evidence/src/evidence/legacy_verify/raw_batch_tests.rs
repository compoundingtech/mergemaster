use super::*;
use std::{io::Cursor, time::Duration};
#[test]
fn declared_limits_precede_body_reads_and_framing_is_exact() {
    let id = "a".repeat(64);
    for size in [MAX_STATEMENT_BYTES, MAX_STATEMENT_BYTES + 1] {
        let header = format!("{id} blob {size}\n");
        let mut bytes = header.as_bytes().to_vec();
        bytes.extend(vec![b'x'; size]);
        bytes.push(b'\n');
        let mut reader = Cursor::new(bytes);
        let result = frame(&mut reader, &id);
        if size == MAX_STATEMENT_BYTES {
            assert_eq!(result.unwrap().unwrap().len(), size);
        } else {
            assert_eq!(result.unwrap_err().reason, "stale-scan-too-large");
            assert_eq!(reader.position(), header.len() as u64);
        }
    }
    for length in [MAX_HEADER_BYTES, MAX_HEADER_BYTES + 1] {
        let mut header = format!("{id} blob 0");
        header.extend(std::iter::repeat_n(' ', length - header.len() - 1));
        header.push('\n');
        let mut reader = Cursor::new(format!("{header}\n").into_bytes());
        if length == MAX_HEADER_BYTES {
            assert_eq!(frame(&mut reader, &id).unwrap(), Some(Vec::new()));
        } else {
            assert_eq!(
                frame(&mut reader, &id).unwrap_err().reason,
                "stale-scan-header-too-large"
            );
        }
    }
    assert_eq!(
        frame(&mut Cursor::new(format!("{id} missing\n")), &id).unwrap(),
        None
    );
    for invalid in [
        format!("{id} blob 3\nab"),
        format!("{id} blob 0\nx"),
        format!("{id} blob nope\n"),
        "unterminated".into(),
    ] {
        assert_eq!(
            frame(&mut Cursor::new(invalid), &id).unwrap_err().reason,
            "error"
        );
    }
}
fn fixture(bytes: &[u8], status: u8) -> RawBatch {
    fixture_timed(bytes, status, Duration::from_secs(60))
}
fn fixture_timed(bytes: &[u8], status: u8, timeout: Duration) -> RawBatch {
    let mut command = std::process::Command::new("python3");
    command.args(["-c",
        "import sys;sys.stdin.readline();sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]));sys.stdout.flush();sys.stdin.read();sys.exit(int(sys.argv[2]))",
        &hex::encode(bytes),&status.to_string()]).stdin(Stdio::piped());
    RawBatch::owned(GitChild::with_timeout(&mut command, timeout).unwrap()).unwrap()
}
#[test]
fn owned_children_finish_fail_and_cancel_without_leaks() {
    let id = "a".repeat(40);
    for status in [0, 7] {
        let mut batch = fixture(format!("{id} blob 0\n\n").as_bytes(), status);
        #[cfg(target_os = "linux")]
        let pid = batch.child.as_ref().unwrap().id();
        assert_eq!(batch.read(&id).unwrap(), Some(Vec::new()));
        if status == 0 {
            batch.finish().unwrap();
        } else {
            assert_eq!(batch.finish().unwrap_err().reason, "error");
        }
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
    for output in [format!("{id} blob 0\n\n"), "x".repeat(MAX_HEADER_BYTES + 1)] {
        let mut batch = fixture(output.as_bytes(), 0);
        #[cfg(target_os = "linux")]
        let pid = batch.child.as_ref().unwrap().id();
        if output.starts_with(&id) {
            batch.read(&id).unwrap();
        } else {
            assert_eq!(
                batch.read(&id).unwrap_err().reason,
                "stale-scan-header-too-large"
            );
            assert!(batch.child.is_none());
            assert_eq!(batch.read(&id).unwrap_err().reason, "error");
        }
        drop(batch);
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
}
#[test]
fn raw_batch_deadline_refuses_requests_and_finish_without_renewal() {
    let id = "a".repeat(40);
    for finish in [false, true] {
        let mut batch = fixture_timed(format!("{id} blob 0\n\n").as_bytes(), 0, Duration::ZERO);
        #[cfg(target_os = "linux")]
        let pid = batch.child.as_ref().unwrap().id();
        let failure = if finish {
            batch.finish().unwrap_err()
        } else {
            let failure = batch.read(&id).unwrap_err();
            assert!(batch.child.is_none());
            assert_eq!(
                batch.read(&id).unwrap_err().detail,
                "raw Git batch is closed"
            );
            failure
        };
        assert_eq!(failure.reason, "error");
        assert!(failure.detail.contains("Git subprocess deadline exceeded"));
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
}
#[test]
fn actual_git_supports_both_formats_missing_objects_and_size_refusal() {
    for format in ["sha1", "sha256"] {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path();
        crate::gate::git::git(repo, &["init", &format!("--object-format={format}")]).unwrap();
        let mut ids = Vec::new();
        for size in [MAX_STATEMENT_BYTES, MAX_STATEMENT_BYTES + 1] {
            let mut child = command(repo)
                .args(["hash-object", "-w", "--stdin"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&vec![b'x'; size])
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success());
            ids.push(String::from_utf8(out.stdout).unwrap().trim().to_owned());
        }
        let mut batch = RawBatch::open(repo).unwrap();
        assert!(batch.read(&"f".repeat(ids[0].len())).unwrap().is_none());
        assert_eq!(
            batch.read(&ids[0]).unwrap().unwrap().len(),
            MAX_STATEMENT_BYTES
        );
        batch.finish().unwrap();
        let mut batch = RawBatch::open(repo).unwrap();
        assert_eq!(
            batch.read(&ids[1]).unwrap_err().reason,
            "stale-scan-too-large"
        );
        assert!(batch.child.is_none());
    }
}

#[test]
fn scanner_match_drops_owned_child_without_consuming_later_overflow() {
    let id = "a".repeat(40);
    let body = br#"{"predicate":{"observed":{"checks":"check"}}}"#;
    let mut bytes = format!("{id} blob {}\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(format!("\n{id} blob 1048577\n").as_bytes());
    let batch = fixture(&bytes, 0);
    #[cfg(target_os = "linux")]
    let pid = batch.child.as_ref().unwrap().id();
    assert!(super::super::stale::bodies_have(batch, &[id.clone(), id], "check").unwrap());
    #[cfg(target_os = "linux")]
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}
