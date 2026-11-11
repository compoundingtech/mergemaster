//! Scanner-specific, one-request-at-a-time Git raw-object transport.
use super::statement::MAX_STATEMENT_BYTES;
use crate::{
    evidence::{legacy_policy::PolicyError, oid},
    gate::git::command,
};
use std::{
    io::{Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Stdio},
};
// Largest normal header: 64hex + space + 6-byte type + space + 20-digit u64 + LF.
// 128 also covers a missing <64hex>^{tree} request (80 bytes).
const MAX_HEADER_BYTES: usize = 128;
fn error(detail: impl ToString) -> PolicyError {
    PolicyError {
        reason: "error",
        detail: detail.to_string(),
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
/// Owns exactly one Git child. Finish validates EOF/status; early drop kills/reaps.
pub struct RawBatch {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: ChildStdout,
}
impl RawBatch {
    pub fn open(repo: &Path) -> Result<Self, PolicyError> {
        let child = command(repo)
            .arg("cat-file")
            .arg("--batch")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(error)?;
        Ok(Self::owned(child))
    }
    fn owned(mut child: Child) -> Self {
        Self {
            input: child.stdin.take(),
            output: child.stdout.take().expect("piped stdout"),
            child: Some(child),
        }
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
        if self.child.is_none() {
            return Err(error("raw Git batch is closed"));
        }
        self.input.take();
        let mut byte = [0];
        if self.output.read(&mut byte).map_err(error)? != 0 {
            return Err(error("unexpected raw Git output"));
        }
        let status = self.child.as_mut().unwrap().wait().map_err(error)?;
        self.child.take();
        if !status.success() {
            return Err(error("raw Git batch failed"));
        }
        Ok(())
    }
    fn cancel(&mut self) {
        self.input.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
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
