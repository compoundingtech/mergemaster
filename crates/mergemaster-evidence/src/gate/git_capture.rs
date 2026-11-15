use std::{
    io,
    process::{ExitStatus, Output},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}
/// Each sink owns retention and its error type; pipe/deadline ownership stays shared.
pub(crate) trait CaptureSink {
    type Error: From<io::Error>;
    type Output;
    fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), Self::Error>;
    fn finish(self, status: ExitStatus) -> Self::Output;
    fn context(self, error: Self::Error) -> Self::Error;
}
#[derive(Default)]
pub(super) struct RawCapture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
impl CaptureSink for RawCapture {
    type Error = io::Error;
    type Output = Output;
    fn push(&mut self, stream: Stream, bytes: &[u8]) -> io::Result<()> {
        match stream {
            Stream::Stdout => self.stdout.extend_from_slice(bytes),
            Stream::Stderr => self.stderr.extend_from_slice(bytes),
        }
        Ok(())
    }
    fn finish(self, status: ExitStatus) -> Output {
        Output {
            status,
            stdout: self.stdout,
            stderr: self.stderr,
        }
    }
    fn context(self, error: io::Error) -> io::Error {
        io::Error::new(
            error.kind(),
            format!("{error}: {}", String::from_utf8_lossy(&self.stderr).trim()),
        )
    }
}
