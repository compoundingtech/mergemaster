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
use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    fmt,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
};

pub fn check<'a>(args: &ParsedArguments<'a>) -> CheckName<'a> {
    match args.value("--check").unwrap_or(TextRef::Str("")) {
        TextRef::Str(s) => s.into(),
        TextRef::Points(p) => p.into(),
    }
}
/// Tree syntax precedes project/key preparation, even for an absent repository.
pub fn resolve_tree(repo: &Path, args: &ParsedArguments<'_>) -> Result<String, PolicyError> {
    if args
        .value("--policy-from")
        .is_some_and(|v| v.points().next() == Some(45))
    {
        return Err(super::crate_inputs::failure(
            "--policy-from must not start with '-'",
        ));
    }
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

pub enum Project<'a> {
    Members(super::member_project::MemberProject<'a>),
    Paths(
        super::paths_project::PathsProject<'a>,
        Vec<(TextRef<'a>, String)>,
    ),
}
impl Project<'_> {
    pub fn write_json<'s>(
        &self,
        writer: legacy_output::ValueWriter<'s, '_, impl fmt::Write>,
    ) -> Result<legacy_output::Written<'s>, fmt::Error> {
        match self {
            Self::Members(project) => project.write_json(writer),
            Self::Paths(project, base) => project.write_json_with_base(base, writer),
        }
    }
}
/// Complete project early-return, before signers, lanes, run inputs or log keys.
/// The callback borrows policy names, avoiding a self-referential result or clones.
pub fn project<T>(
    repo: &Path,
    tree: &str,
    args: &ParsedArguments<'_>,
    emit: impl FnOnce(Project<'_>) -> T,
) -> Result<T, PolicyError> {
    if args.value("--members").is_some() {
        return super::member_project::MemberProject::read(
            repo,
            tree,
            check(args),
            args.value("--policy-from"),
        )
        .map(|project| emit(Project::Members(project)));
    }
    let base = args
        .value("--policy-from")
        .filter(|p| p.points().next().is_some());
    let rules = base
        .map(|base| {
            super::policy_loader::load(repo, base, check(args))?
                .into_rules(args.value("--repository").unwrap_or(TextRef::Str("")))
        })
        .transpose()?;
    let project = super::paths_project::PathsProject::read_with_inputs(
        repo,
        tree,
        check(args),
        args.value("--paths"),
        rules.as_ref().and_then(|r| r.header.inputs.as_deref()),
    )?;
    let values = super::base_input_values::base_input_values(
        repo,
        base.unwrap_or(TextRef::Str("")),
        rules.as_ref(),
    )?;
    Ok(emit(Project::Paths(project, values)))
}

/// Filesystem conversion without an eager NUL check: the eventual operation
/// owns that check, so unused paths and original-main precedence stay lazy.
pub fn path(text: TextRef<'_>) -> Result<Cow<'_, Path>, PolicyError> {
    Ok(match encode(text, 0, true)? {
        Cow::Borrowed(bytes) => Cow::Borrowed(Path::new(OsStr::from_bytes(bytes))),
        Cow::Owned(bytes) => Cow::Owned(OsString::from_vec(bytes).into()),
    })
}
/// Capture any operation result before closing; an explicit close error wins.
pub fn with_signers<T>(
    repo: &Path,
    args: &ParsedArguments<'_>,
    operation: impl FnOnce(&Path) -> T,
) -> Result<T, PolicyError> {
    let from = args.value("--keys-from").filter(|v| !v.equals(""));
    let explicit = if from.is_some() {
        Cow::Borrowed(Path::new(""))
    } else {
        path(args.value("--keys").unwrap_or(TextRef::Str("")))?
    };
    let keys = super::cli_keys::signers(repo, &explicit, from)?;
    let result = operation(keys.path());
    keys.close()?;
    Ok(result)
}
/// Require-all returns before ordinary policy/run-input/log/crate preparation.
pub fn required<T>(
    repo: &Path,
    tree: &str,
    args: &ParsedArguments<'_>,
    emit: impl FnOnce(super::require_all::All<'_>) -> T,
) -> Result<T, PolicyError> {
    with_signers(repo, args, |keys| {
        let from = args.value("--lanes-from").filter(|v| !v.equals(""));
        let lanes = from
            .map(|from| super::cli_config::lanes(repo, from))
            .transpose()?;
        let text = super::policy_loader::read_policy(
            repo,
            args.value("--policy-from").unwrap_or(TextRef::Str("")),
        )?;
        super::require_all::require_all_cli(
            repo,
            tree,
            keys,
            &text,
            args.value("--repository").unwrap_or(TextRef::Str("")),
            lanes.as_deref().zip(from),
            args.value("--lane-base"),
        )
        .map(emit)
    })?
}

#[cfg(test)]
#[path = "cli_dispatch_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cli_ordinary_tests.rs"]
mod ordinary_tests;
