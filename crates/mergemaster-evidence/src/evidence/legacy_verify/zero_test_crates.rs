//! The verifier's standalone accepted-base no-tests allowance, not read_inputs.
use super::{
    crate_input_document::Inputs,
    crate_inputs::failure,
    projection::read_git_source,
    source_resource::SourceResource,
    statement_document::{Document, Node},
};
use crate::evidence::legacy_policy::PolicyError;
use std::{collections::BTreeSet, path::Path};
const INPUTS: &str = ".st/rust-test-inputs.json";
fn parse(bytes: &[u8]) -> Result<BTreeSet<Vec<u32>>, PolicyError> {
    let unreadable = || failure(format!("{INPUTS} at the accepted base is not readable"));
    let text = std::str::from_utf8(bytes).map_err(|_| unreadable())?;
    let document = Document::from_text(text).map_err(|_| unreadable())?;
    if !matches!(document.root(), Node::Object(_)) {
        return Err(unreadable());
    }
    let Some(listed) = Inputs::field(&document, document.root(), "no_tests") else {
        return Ok(BTreeSet::new());
    };
    let invalid = || {
        failure(format!(
            "{INPUTS}: no_tests must be an array of crate names"
        ))
    };
    let Node::Array(ids) = listed else {
        return Err(invalid());
    };
    ids.iter()
        .map(|id| match document.node(*id) {
            Node::String(name) => Ok(name.clone()),
            _ => Err(invalid()),
        })
        .collect()
}
/// Missing configuration is an empty allowance; malformed preferred bytes never fall back.
pub fn zero_test_crates(
    repo: &Path,
    base: super::value_inputs::TextRef<'_>,
) -> Result<BTreeSet<Vec<u32>>, PolicyError> {
    // Share exact inherited lookup, including unresolved revision and lossless filename errors.
    let Some(path) = super::cli_config::path(repo, base, INPUTS)? else {
        return Ok(BTreeSet::new());
    };
    let spec = crate::evidence::legacy_policy::normalized_text::NormalizedText::concat(
        [base, ":".into(), path.as_str().into()].into_iter(),
    );
    let encoded = super::binding_path::encode(spec.borrowed(), 0, true)?;
    if encoded.contains(&0) {
        return Err(super::crate_manifest_ops::exception(
            "ValueError",
            "embedded null byte",
        ));
    }
    let bytes = read_git_source(
        repo,
        &[
            std::ffi::OsStr::new("show"),
            std::ffi::OsStr::new("--end-of-options"),
            std::os::unix::ffi::OsStrExt::from_bytes(encoded.as_ref()),
        ],
        SourceResource::RawBlob(spec.clone()),
    )?;
    parse(&bytes)
}
#[cfg(test)]
#[path = "zero_test_crates_tests.rs"]
mod tests;
