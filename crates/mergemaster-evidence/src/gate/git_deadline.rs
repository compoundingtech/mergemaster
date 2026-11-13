//! One POSIX deadline per owned Git child, including pipe I/O and final wait.
use std::{
    io::{self, Read, Write},
    os::fd::AsRawFd,
    process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

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
        Self::start(command.stderr(Stdio::null()), timeout)
    }
    fn start(command: &mut Command, timeout: Duration) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Git deadline overflow"))?;
        Ok(Self {
            child: command.stdout(Stdio::piped()).spawn()?,
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
        let mut child = Self::start(command.stderr(Stdio::piped()), timeout)?;
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
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = (|| {
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
                    return Err(error);
                }
                remaining(child.deadline)?;
                if fds[0].revents != 0 && capture_read(&mut stdout, &mut out)? {
                    fds[0].fd = -1;
                }
                if fds[1].revents != 0 && capture_read(&mut stderr, &mut err)? {
                    fds[1].fd = -1;
                }
                if fds[2].revents != 0
                    && let Some(pipe) = &mut stdin
                {
                    match pipe.inner.write(bytes) {
                        Ok(0) => {
                            return Err(io::Error::new(io::ErrorKind::WriteZero, "Git stdin"));
                        }
                        Ok(n) => bytes = &bytes[n..],
                        Err(e) if retry_io(&e) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            child.wait()
        })();
        let status = result.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{e}: {}", String::from_utf8_lossy(&err).trim()),
            )
        })?;
        Ok(std::process::Output {
            status,
            stdout: out,
            stderr: err,
        })
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
fn retry_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
fn capture_read(reader: &mut impl Read, output: &mut Vec<u8>) -> io::Result<bool> {
    let mut buffer = [0; 64 * 1024];
    match reader.read(&mut buffer) {
        Ok(0) => Ok(true),
        Ok(n) => {
            output.extend_from_slice(&buffer[..n]);
            Ok(false)
        }
        Err(error) if retry_io(&error) => Ok(false),
        Err(error) => Err(error),
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
