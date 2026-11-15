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
pub fn zero_test_crates(repo: &Path, base: &str) -> Result<BTreeSet<Vec<u32>>, PolicyError> {
    // Share exact inherited lookup, including unresolved revision and lossless filename errors.
    let Some(path) = super::cli_config::path(repo, base.into(), INPUTS)? else {
        return Ok(BTreeSet::new());
    };
    let spec = format!("{base}:{path}");
    let bytes = read_git_source(
        repo,
        &["show", "--end-of-options", &spec],
        SourceResource::RawBlob(spec.clone().into()),
    )?;
    parse(&bytes)
}
#[cfg(test)]
#[path = "zero_test_crates_tests.rs"]
mod tests;
