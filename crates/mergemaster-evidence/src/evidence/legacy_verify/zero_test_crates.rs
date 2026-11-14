//! The verifier's standalone accepted-base no-tests allowance, not read_inputs.
use super::{
    crate_input_document::Inputs,
    crate_inputs::failure,
    projection::read_git,
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
    // Unlike the native config helper, Python accepts unresolved revision names.
    let preferred = INPUTS.replacen(".st/", ".fractal/", 1);
    let listing = read_git(
        repo,
        &[
            "ls-tree",
            "-z",
            "--full-tree",
            base,
            "--",
            &preferred,
            INPUTS,
        ],
        usize::MAX,
    )?;
    let mut names = BTreeSet::new();
    for row in listing
        .split(|byte| *byte == 0)
        .filter(|row| !row.is_empty())
    {
        let name = row
            .splitn(2, |byte| *byte == b'\t')
            .nth(1)
            .unwrap_or_default();
        let name = super::crate_inputs_text::utf8(name).map_err(|detail| PolicyError {
            reason: "error",
            origin: crate::evidence::legacy_policy::ErrorOrigin::Exception {
                class: "UnicodeDecodeError",
            },
            detail: detail.into(),
        })?;
        names.insert(name);
    }
    let Some(path) = [preferred.as_str(), INPUTS]
        .into_iter()
        .find(|path| names.contains(path))
    else {
        return Ok(BTreeSet::new());
    };
    let bytes = read_git(
        repo,
        &["show", "--end-of-options", &format!("{base}:{path}")],
        usize::MAX,
    )?;
    parse(&bytes)
}
#[cfg(test)]
#[path = "zero_test_crates_tests.rs"]
mod tests;
