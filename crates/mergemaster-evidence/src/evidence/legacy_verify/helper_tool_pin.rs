//! Running release identity and base-tree tool-pin verification.
//!
//! A pin's revision is provenance, not independently observed binary identity.
//! Provisioning binds that revision to the release through its attestation (#405);
//! this helper checks repository, release version, and actual executable digest.
use super::{
    binding_path::encode, crate_inputs::failure, projection::read_git_source,
    source_resource::SourceResource, value_inputs::TextRef,
};
use crate::evidence::{
    legacy_output,
    legacy_policy::{PolicyError, normalized_text::NormalizedText},
    source,
};
use sha2::{Digest, Sha256};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

const REPOSITORY: &str = source::TOOL_REPOSITORY;
const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const PIN_SUFFIX: &str = ":.mergemaster/tool-pin.json";

/// Report only independently observed release identity, never a claimed revision.
pub(super) fn identity(output: &mut String) -> Result<(), PolicyError> {
    let digest = source::running_binary_sha256().map_err(|error| failure(error.to_string()))?;
    legacy_output::write(output, |w| {
        w.object(|o| {
            o.field_text("repository", |w| w.text(REPOSITORY))?;
            o.field_text("version", |w| w.text(VERSION))?;
            o.field_text("binary_sha256", |w| w.text(&digest))
        })
    })
    .map_err(|error| failure(error.to_string()))
}

/// Read the pin from an arbitrary Git treeish, without consulting checkout files.
pub(super) fn verify(
    repo: &Path,
    base: TextRef<'_>,
    output: &mut String,
) -> Result<(), PolicyError> {
    let spec = NormalizedText::around("", base, PIN_SUFFIX);
    let encoded = encode(spec.borrowed(), 0, true)?.into_owned();
    let bytes = read_git_source(
        repo,
        &[
            OsStr::new("show"),
            OsStr::new("--end-of-options"),
            OsStr::from_bytes(&encoded),
        ],
        SourceResource::RawBlob(spec),
    )?;
    let pin = source::parse_tool_pin(&bytes).map_err(|error| failure(error.to_string()))?;
    let digest = source::running_binary_sha256().map_err(|error| failure(error.to_string()))?;
    if pin.repository != REPOSITORY || pin.release_version != VERSION || pin.binary_sha256 != digest
    {
        return Err(failure("tool pin does not match running tool identity"));
    }
    let pin_digest = hex::encode(Sha256::digest(&bytes));
    legacy_output::write(output, |w| {
        w.object(|o| {
            o.field_text("repository", |w| w.text(REPOSITORY))?;
            // Provenance copied from the validated pin, not verified against the binary.
            o.field_text("revision", |w| w.text(&pin.revision))?;
            o.field_text("version", |w| w.text(VERSION))?;
            o.field_text("binary_sha256", |w| w.text(&digest))?;
            o.field_text("tool_pin_sha256", |w| w.text(&pin_digest))
        })
    })
    .map_err(|error| failure(error.to_string()))
}

#[cfg(test)]
#[path = "helper_tool_pin_tests.rs"]
mod tests;
