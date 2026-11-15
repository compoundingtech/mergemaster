//! One POSIX deadline per owned Git child, including pipe I/O and final wait.
use std::{
    io::{self, Read, Write},
    os::fd::AsRawFd,
    process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
#[path = "git_capture.rs"]
mod capture;
use capture::RawCapture;
pub(crate) use capture::{CaptureSink, Stream};

pub(crate) struct GitChild {
    child: Child,
    deadline: Instant,
    reaped: bool,
}
impl GitChild {
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }
    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self) {
        self.deadline = Instant::now();
    }
    pub(crate) fn spawn(command: &mut Command) -> io::Result<Self> {
        Self::with_timeout(command, Duration::from_secs(60))
    }
    pub(crate) fn with_timeout(command: &mut Command, timeout: Duration) -> io::Result<Self> {
        Self::with_stdio(command, timeout, Stdio::piped(), Stdio::null())
    }
    pub(crate) fn with_stdio(
        command: &mut Command,
        timeout: Duration,
        stdout: Stdio,
        stderr: Stdio,
    ) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Git deadline overflow"))?;
        Ok(Self {
            child: command.stdout(stdout).stderr(stderr).spawn()?,
            deadline,
            reaped: false,
        })
    }
    /// Capture both streams while feeding stdin, under one owned-child deadline.
    pub(crate) fn capture(
        command: &mut Command,
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> io::Result<std::process::Output> {
        Self::capture_with_sink(command, input, timeout, RawCapture::default())
    }
    pub(crate) fn capture_with_sink<S: CaptureSink>(
        command: &mut Command,
        input: Option<&[u8]>,
        timeout: Duration,
        mut sink: S,
    ) -> Result<S::Output, S::Error> {
        let mut child = Self::with_stdio(command, timeout, Stdio::piped(), Stdio::piped())?;
        let mut stdin = input.map(|_| child.stdin()).transpose()?;
        let stdout = child.stdout()?;
        let stderr = child
            .child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("Git stderr"))?;
        let mut stdout = stdout.inner;
        let mut stderr = child.pipe(stderr)?.inner;
        let mut bytes = input.unwrap_or_default();
        let result = (|| -> Result<ExitStatus, S::Error> {
            let mut fds = [
                libc::pollfd {
                    fd: stdout.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stderr.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: -1,
                    events: libc::POLLOUT,
                    revents: 0,
                },
            ];
            while fds[0].fd >= 0 || fds[1].fd >= 0 || stdin.is_some() {
                if bytes.is_empty() {
                    stdin.take();
                }
                fds[2].fd = stdin.as_ref().map_or(-1, |pipe| pipe.inner.as_raw_fd());
                if fds.iter().all(|fd| fd.fd < 0) {
                    break;
                }
                let timeout = remaining(child.deadline)?
                    .as_millis()
                    .saturating_add(1)
                    .min(i32::MAX as u128) as i32;
                // SAFETY: fds is a live array of three pollfd entries.
                if unsafe { libc::poll(fds.as_mut_ptr(), 3, timeout) } < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error.into());
                }
                remaining(child.deadline)?;
                if fds[0].revents != 0
                    && capture_read(
                        &mut stdout,
                        &mut sink,
                        Stream::Stdout,
                        #[cfg(test)]
                        &mut child.deadline,
                    )?
                {
                    fds[0].fd = -1;
                }
                if fds[1].revents != 0
                    && capture_read(
                        &mut stderr,
                        &mut sink,
                        Stream::Stderr,
                        #[cfg(test)]
                        &mut child.deadline,
                    )?
                {
                    fds[1].fd = -1;
                }
                if fds[2].revents != 0
                    && let Some(pipe) = &mut stdin
                {
                    match pipe.inner.write(bytes) {
                        Ok(0) => {
                            return Err(
                                io::Error::new(io::ErrorKind::WriteZero, "Git stdin").into()
                            );
                        }
                        Ok(n) => bytes = &bytes[n..],
                        Err(e) if retry_io(&e) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Ok(child.wait()?)
        })();
        match result {
            Ok(status) => Ok(sink.finish(status)),
            Err(error) => Err(sink.context(error)),
        }
    }
    pub(crate) fn stdin(&mut self) -> io::Result<Pipe<ChildStdin>> {
        let stdin = self
            .child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("Git stdin already taken"))?;
        self.pipe(stdin)
    }
    pub(crate) fn stdout(&mut self) -> io::Result<Pipe<ChildStdout>> {
        let stdout = self
            .child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("Git stdout already taken"))?;
        self.pipe(stdout)
    }
    fn pipe<T: AsRawFd>(&self, inner: T) -> io::Result<Pipe<T>> {
        // SAFETY: inner owns a live descriptor throughout both fcntl calls.
        let flags = unsafe { libc::fcntl(inner.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // Preserve existing flags; nonblocking I/O makes readiness races bounded.
        if unsafe { libc::fcntl(inner.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Pipe {
            inner,
            deadline: self.deadline,
        })
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        let result = (|| {
            remaining(self.deadline)?;
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            wait_ready(self.child.id(), self.deadline)?;
            self.child.wait()
        })();
        match &result {
            Ok(_) => self.reaped = true,
            Err(error) if error.kind() == io::ErrorKind::TimedOut => self.cancel(),
            Err(_) => {}
        }
        result
    }
    // The hosted matrix is Linux-only; preserve other platforms until a tested
    // readiness implementation is available rather than add untested kqueue code.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            let remaining = match remaining(self.deadline) {
                Ok(remaining) => remaining,
                Err(error) => {
                    self.cancel();
                    return Err(error);
                }
            };
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                return Ok(status);
            }
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }
    fn cancel(&mut self) {
        if !self.reaped {
            // Python POSIX parity: kill/reap only the direct child, not its group.
            let _ = self.child.kill();
            self.reaped = self.child.wait().is_ok();
        }
    }
}
impl Drop for GitChild {
    fn drop(&mut self) {
        self.cancel();
    }
}
#[cfg(target_os = "linux")]
fn wait_ready(pid: u32, deadline: Instant) -> io::Result<()> {
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: pid is our live, unreaped child. Flags=0 is the pidfd_open ABI.
    // Owning Child prevents PID reuse even if it exits before this syscall.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pidfd_open returns a new descriptor, now solely owned.
    let fd = unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) };
    loop {
        let timeout = remaining(deadline)?
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut event = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: event is one live pollfd and fd remains owned across poll.
        let ready = unsafe { libc::poll(&mut event, 1, timeout) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue; // Recompute from the same absolute deadline.
            }
            return Err(error);
        }
        remaining(deadline)?;
        if ready > 0 {
            if event.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            return Ok(());
        }
    }
}
fn retry_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
fn capture_read<S: CaptureSink>(
    reader: &mut impl Read,
    sink: &mut S,
    stream: Stream,
    #[cfg(test)] deadline: &mut Instant,
) -> Result<bool, S::Error> {
    let mut buffer = [0; 64 * 1024];
    match reader.read(&mut buffer) {
        Ok(0) => Ok(true),
        Ok(n) => {
            sink.push(stream, &buffer[..n])?;
            #[cfg(test)]
            if stream == Stream::Stderr
                && tests::EXPIRE_AFTER_STDERR.with(|flag| flag.replace(false))
            {
                *deadline = Instant::now();
            }
            Ok(false)
        }
        Err(error) if retry_io(&error) => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Git subprocess deadline exceeded"))
}
pub(crate) struct Pipe<T> {
    inner: T,
    deadline: Instant,
}
impl<T: AsRawFd> Pipe<T> {
    fn ready(&self, events: libc::c_short) -> io::Result<()> {
        loop {
            let timeout = remaining(self.deadline)?
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let mut fd = libc::pollfd {
                fd: self.inner.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: fd is a valid one-element pollfd array for this call.
            let result = unsafe { libc::poll(&mut fd, 1, timeout) };
            if result > 0 {
                remaining(self.deadline)?;
                return Ok(());
            }
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
    }
}
impl<T: AsRawFd + Read> Read for Pipe<T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.ready(libc::POLLIN)?;
            match self.inner.read(bytes) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => return result,
            }
        }
    }
}
impl<T: AsRawFd + Write> Write for Pipe<T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.ready(libc::POLLOUT)?;
            match self.inner.write(bytes) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
#[path = "git_deadline_tests.rs"]
mod tests;
