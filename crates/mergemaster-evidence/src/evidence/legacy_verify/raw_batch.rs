//! Scanner-specific, one-request-at-a-time Git raw-object transport.
use super::statement::MAX_STATEMENT_BYTES;
use crate::{
    evidence::{legacy_policy::PolicyError, oid},
    gate::git::{
        command,
        deadline::{GitChild, Pipe},
    },
};
use std::{
    io::{Read, Write},
    path::Path,
    process::{ChildStdin, ChildStdout, Stdio},
};
// Largest normal header: 64hex + space + 6-byte type + space + 20-digit u64 + LF.
// 128 also covers a missing <64hex>^{tree} request (80 bytes).
const MAX_HEADER_BYTES: usize = 128;
fn error(detail: impl ToString) -> PolicyError {
    PolicyError {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason: "error",
        detail: detail.to_string().into(),
    }
}
fn frame(output: &mut impl Read, request: &str) -> Result<Option<Vec<u8>>, PolicyError> {
    let mut header = Vec::new();
    // No buffered prefetch: an oversized declaration must not read body bytes.
    for _ in 0..=MAX_HEADER_BYTES {
        let mut byte = [0];
        output.read_exact(&mut byte).map_err(error)?;
        header.push(byte[0]);
        if byte == *b"\n" {
            break;
        }
    }
    if header.len() > MAX_HEADER_BYTES {
        return Err(PolicyError {
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: "stale-scan-header-too-large",
            detail: "raw Git header exceeds 128 bytes".into(),
        });
    }
    if header.last() != Some(&b'\n') {
        return Err(error("unterminated raw Git header"));
    }
    let mut fields = std::str::from_utf8(&header)
        .map_err(error)?
        .split_ascii_whitespace();
    let (name, kind, size, extra) = (fields.next(), fields.next(), fields.next(), fields.next());
    if name == Some(request) && kind == Some("missing") && size.is_none() {
        return Ok(None);
    }
    let (Some(name), Some(_), Some(size), None) = (name, kind, size, extra) else {
        return Err(error("invalid raw Git header"));
    };
    oid(name).map_err(error)?;
    let size: u64 = size.parse().map_err(error)?;
    if size > MAX_STATEMENT_BYTES as u64 {
        return Err(PolicyError {
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: "stale-scan-too-large",
            detail: "raw Git body exceeds 1048576 bytes".into(),
        });
    }
    let mut body = vec![0; size as usize];
    output.read_exact(&mut body).map_err(error)?;
    let mut newline = [0];
    output.read_exact(&mut newline).map_err(error)?;
    if newline != *b"\n" {
        return Err(error("invalid raw Git body terminator"));
    }
    Ok(Some(body))
}
/// Owns one Git child and one 60-second deadline across all requests and finish.
pub struct RawBatch {
    child: Option<GitChild>,
    input: Option<Pipe<ChildStdin>>,
    output: Pipe<ChildStdout>,
}
impl RawBatch {
    pub fn open(repo: &Path) -> Result<Self, PolicyError> {
        Self::owned(
            GitChild::spawn(
                command(repo)
                    .args(["cat-file", "--batch"])
                    .stdin(Stdio::piped()),
            )
            .map_err(error)?,
        )
    }
    fn owned(mut child: GitChild) -> Result<Self, PolicyError> {
        Ok(Self {
            input: Some(child.stdin().map_err(error)?),
            output: child.stdout().map_err(error)?,
            child: Some(child),
        })
    }
    /// Full OID or full OID^{tree}; at most 72 input bytes before reading a reply.
    pub fn read(&mut self, request: &str) -> Result<Option<Vec<u8>>, PolicyError> {
        let result = (|| {
            oid(request.strip_suffix("^{tree}").unwrap_or(request)).map_err(error)?;
            let input = self
                .input
                .as_mut()
                .ok_or_else(|| error("raw Git batch is closed"))?;
            writeln!(input, "{request}").map_err(error)?;
            input.flush().map_err(error)?;
            frame(&mut self.output, request)
        })();
        if result.is_err() {
            self.cancel();
        }
        result
    }
    pub fn finish(mut self) -> Result<(), PolicyError> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| error("raw Git batch is closed"))?;
        self.input.take();
        let mut byte = [0];
        if self.output.read(&mut byte).map_err(error)? != 0 {
            return Err(error("unexpected raw Git output"));
        }
        let status = child.wait().map_err(error)?;
        self.child.take();
        if !status.success() {
            return Err(error("raw Git batch failed"));
        }
        Ok(())
    }
    fn cancel(&mut self) {
        self.input.take();
        self.child.take();
    }
}
impl Drop for RawBatch {
    fn drop(&mut self) {
        self.cancel();
    }
}
#[cfg(test)]
#[path = "raw_batch_tests.rs"]
mod tests;
