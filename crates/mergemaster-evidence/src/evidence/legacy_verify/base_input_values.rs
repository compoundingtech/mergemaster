//! Accepted-base values use no_lazy, not the candidate projection transport.
use super::{
    binding_path::encode, crate_manifest_ops::exception, log_transport,
    source_resource::SourceResource, value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{PolicyError, PolicyRules, normalized_text::NormalizedText};
use sha2::{Digest, Sha256};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

/// Preserve first insertion position while later kinds replace an input's value.
/// Names borrow the validated policy; values are hashes of raw bytes or `absent`.
pub fn base_input_values<'a>(
    repo: &Path,
    base: TextRef<'_>,
    rules: Option<&'a PolicyRules>,
) -> Result<Vec<(TextRef<'a>, String)>, PolicyError> {
    let mut values: Vec<(TextRef<'a>, String)> = Vec::new();
    for (_, rule) in rules.into_iter().flat_map(|rules| &rules.kinds) {
        for (name, path) in &rule.base_inputs {
            if repo.as_os_str().as_bytes().contains(&0) {
                return Err(exception("ValueError", "embedded null byte"));
            }
            let spec =
                NormalizedText::concat([base, TextRef::Str(":"), TextRef::Str(path)].into_iter());
            let object = encode(spec.borrowed(), 0, true)?.into_owned();
            let read = log_transport::read(
                repo,
                &[
                    OsStr::new("show"),
                    OsStr::new("--end-of-options"),
                    OsStr::from_bytes(&object),
                ],
                SourceResource::RawBlob(spec),
            )?;
            let value = if read.status.success() {
                format!("{:x}", Sha256::digest(read.stdout))
            } else {
                "absent".into()
            };
            let name = name.borrowed();
            if let Some((_, previous)) = values
                .iter_mut()
                .find(|(key, _)| key.points().eq(name.points()))
            {
                *previous = value;
            } else {
                values.push((name, value));
            }
        }
    }
    Ok(values)
}

#[cfg(test)]
#[path = "base_input_values_tests.rs"]
mod tests;
