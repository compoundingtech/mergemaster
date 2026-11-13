//! One POSIX deadline per owned Git child, including pipe I/O and final wait.
use std::{
    io::{self, Read, Write},
    os::fd::AsRawFd,
    process::{Child, ChildStdout, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

pub(crate) struct GitChild {
    child: Child,
    deadline: Instant,
    reaped: bool,
}
impl GitChild {
    pub(crate) fn spawn(command: &mut Command) -> io::Result<Self> {
        Self::with_timeout(command, Duration::from_secs(60))
    }
    fn with_timeout(command: &mut Command, timeout: Duration) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Git deadline overflow"))?;
        Ok(Self {
            child: command
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?,
            deadline,
            reaped: false,
        })
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
