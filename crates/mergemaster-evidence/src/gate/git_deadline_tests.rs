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
