//! Bare inherited, no-timeout capture for rust-test-keys manifest blobs.
use super::{
    source_io,
    source_resource::{SOURCE_BYTES, SourceResource},
};
use crate::evidence::legacy_policy::PolicyError;
use std::{
    io::Read,
    process::{Child, Command, Stdio},
};
struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
pub(super) fn read(
    command: &mut Command,
    resource: SourceResource,
) -> Result<Option<Vec<u8>>, PolicyError> {
    let program = command.get_program().to_owned();
    // The oracle captures stderr but show() never consumes it; discard it without retention.
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| source_io::error(&program, &e))?;
    let mut child = Owned(child);
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| source_io::error(&program, &std::io::Error::other("Git stdout")))?;
    let mut bytes = Vec::new();
    stdout
        .take((SOURCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| source_io::error(&program, &e))?;
    if bytes.len() > SOURCE_BYTES {
        return Err(resource.into_error());
    }
    let status = child.0.wait().map_err(|e| source_io::error(&program, &e))?;
    Ok(status.success().then_some(bytes))
}
