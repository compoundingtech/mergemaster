//! Original-main composition boundaries, not a binary entry or partial dispatcher.
//! Uses compiled member APIs only: never AcceptedSource or json_bytes::parse.
use super::{
    argparse_parse::ParsedArguments, binding_path::encode, cli_adapter::Exit,
    crate_inputs_text::utf8, crate_manifest_ops::exception, failure_json::WireError, projection,
    projection_oid::space, source_resource::SourceResource, value_inputs::TextRef,
};
use crate::evidence::{
    legacy_output,
    legacy_policy::{PolicyError, check_names::CheckName, normalized_text::NormalizedText},
};
use std::{ffi::OsStr, fmt, os::unix::ffi::OsStrExt, path::Path};

pub fn check<'a>(args: &ParsedArguments<'a>) -> CheckName<'a> {
    match args.value("--check").unwrap_or(TextRef::Str("")) {
        TextRef::Str(s) => s.into(),
        TextRef::Points(p) => p.into(),
    }
}
/// Tree syntax precedes project/key preparation, even for an absent repository.
pub fn resolve_tree(repo: &Path, args: &ParsedArguments<'_>) -> Result<String, PolicyError> {
    let tree = if let Some(tree) = args.value("--tree") {
        // OID validation is ASCII-only and must not encode a rejected argument.
        if !matches!(tree.points().count(), 40 | 64)
            || !tree.points().all(|p| matches!(p, 48..=57 | 97..=102))
        {
            return Err(super::crate_inputs::failure(
                "expected a full lowercase Git tree ID",
            ));
        }
        tree.points().map(|p| char::from(p as u8)).collect()
    } else {
        projection::check_repo_argument(repo)?;
        let expression = NormalizedText::around(
            "",
            args.value("--revision").unwrap_or(TextRef::Str("HEAD")),
            "^{tree}",
        );
        let encoded = encode(expression.borrowed(), 0, true)?.into_owned();
        let bytes = projection::read_git_source(
            repo,
            &[
                OsStr::new("rev-parse"),
                OsStr::new("--verify"),
                OsStr::new("--end-of-options"),
                OsStr::from_bytes(&encoded),
            ],
            SourceResource::RawBlob(expression),
        )?;
        utf8(&bytes)
            .map_err(|m| exception("UnicodeDecodeError", m))?
            .trim_matches(space)
            .to_owned()
    };
    super::paths_project::validate_tree(&tree)?;
    Ok(tree)
}
/// The original outer handler, including require-all's distinct global envelope.
/// JSON is the safe wire sink; no diagnostic text is written raw to a terminal.
pub fn refusal(args: &ParsedArguments<'_>, error: &PolicyError) -> Result<Exit, fmt::Error> {
    let global = args.value("--require-all").is_some();
    let mut stdout = String::new();
    legacy_output::write(&mut stdout, |w| {
        let view = WireError::from_policy(error);
        if global {
            view.write_global(w)
        } else {
            view.write_json(check(args), w)
        }
    })?;
    stdout.push('\n');
    Ok(Exit {
        stdout,
        stderr: String::new(),
        code: if global { 2 } else { 1 },
    })
}

#[cfg(test)]
#[path = "cli_dispatch_tests.rs"]
mod tests;
