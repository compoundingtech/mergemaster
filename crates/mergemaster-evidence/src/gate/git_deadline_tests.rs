use super::*;

fn paused() -> GitChild {
    let mut command = Command::new("python3");
    command.args(["-c", "import os,signal; os.write(1,b'R'); signal.pause()"]);
    command.stdin(Stdio::piped());
    let mut child = GitChild::with_timeout(&mut command, Duration::from_secs(60)).unwrap();
    let mut ready = [0];
    child.stdout().unwrap().read_exact(&mut ready).unwrap();
    assert_eq!(ready, *b"R");
    child
}
fn assert_reaped(pid: u32) {
    let mut status = 0;
    // SAFETY: status is writable; WNOHANG never blocks and pid names our former child.
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}
#[test]
fn normal_exit_collects_output_and_reaps() {
    let mut command = Command::new("python3");
    command.args(["-c", "import os; os.write(1,b'normal')"]);
    let mut child = GitChild::spawn(&mut command).unwrap();
    let pid = child.child.id();
    let mut bytes = Vec::new();
    child.stdout().unwrap().read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"normal");
    assert!(child.wait().unwrap().success());
    assert_reaped(pid);
}
#[test]
fn expired_wait_kills_and_reaps_without_sleeping() {
    let mut child = paused();
    let pid = child.child.id();
    child.deadline = Instant::now();
    assert_eq!(child.wait().unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_reaped(pid);
}
#[test]
fn full_stdin_pipe_refuses_a_blocked_writer_at_the_same_deadline() {
    let mut child = paused();
    let pid = child.child.id();
    let stdin = child.child.stdin.take().unwrap();
    let mut input = child.pipe(stdin).unwrap();
    loop {
        match input.inner.write(&[0; 65_536]) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("{error}"),
        }
    }
    let expired = Instant::now();
    input.deadline = expired;
    child.deadline = expired;
    assert_eq!(
        input.write(b"blocked").unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(child.wait().unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_reaped(pid);
}
#[test]
fn early_drop_kills_and_reaps_the_owned_child() {
    let child = paused();
    let pid = child.child.id();
    drop(child);
    assert_reaped(pid);
}
#[test]
fn expired_read_does_not_wait_for_a_pipe_held_elsewhere() {
    let child = paused();
    let pid = child.child.id();
    let (reader, _held_open) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut pipe = child.pipe(reader).unwrap();
    pipe.deadline = Instant::now();
    assert_eq!(
        pipe.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    drop(child);
    assert_reaped(pid);
}

#[test]
fn capture_deadline_drains_both_streams_while_writing_input() {
    for status in [0, 7] {
        let mut command = Command::new("python3");
        command
            .args([
                "-c",
                r"
import sys
sys.stderr.buffer.write(b'e'*1048576);sys.stderr.buffer.flush()
sys.stdout.buffer.write(b'o'*1048576);sys.stdout.buffer.flush()
data=sys.stdin.buffer.read()
sys.stdout.buffer.write(data);sys.exit(int(sys.argv[1]))
",
                &status.to_string(),
            ])
            .stdin(Stdio::piped());
        let input = vec![b'i'; 1_048_576];
        let output =
            GitChild::capture(&mut command, Some(&input), Duration::from_secs(300)).unwrap();
        assert_eq!(output.status.code(), Some(status));
        assert_eq!(output.stderr, vec![b'e'; 1_048_576]);
        assert_eq!(output.stdout, [vec![b'o'; 1_048_576], input].concat());
    }
}

#[test]
fn capture_deadline_handles_null_empty_and_expired_input() {
    for input in [None, Some(b"".as_slice())] {
        let mut command = Command::new("python3");
        command.args(["-c", "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'\\xff');sys.stderr.write('detail')"])
            .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() });
        let output = GitChild::capture(&mut command, input, Duration::from_secs(60)).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"\xff");
        assert_eq!(output.stderr, b"detail");
    }
    for input in [None, Some(b"input".as_slice())] {
        let mut command = Command::new("python3");
        command
            .args(["-c", "import signal;signal.pause()"])
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        let error = GitChild::capture(&mut command, input, Duration::ZERO).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            error
                .to_string()
                .contains("Git subprocess deadline exceeded")
        );
    }
}
