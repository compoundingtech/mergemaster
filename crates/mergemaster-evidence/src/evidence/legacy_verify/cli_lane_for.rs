//! Oracle lane_for ordering and inherited transports, separate from native Git.
use super::{
    binding_path::encode,
    cli_config,
    cli_lane_definition::{failure, lane_definition},
    cli_lane_entry,
    cli_lanes::LaneRules,
    crate_inputs_text::utf8,
    crate_manifest_ops::exception,
    judgment::LaneDefinition,
    log_transport,
    projection::read_git_source,
    projection_oid::space,
    source_resource::SourceResource,
    statement_document::PolicyResource,
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{PolicyError, normalized_text::NormalizedText};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};
const LANES: &str = ".st/required-lanes.json";
fn repo_nul(repo: &Path) -> Result<(), PolicyError> {
    if repo.as_os_str().as_bytes().contains(&0) {
        Err(exception("ValueError", "embedded null byte"))
    } else {
        Ok(())
    }
}
pub fn lane_for(
    repo: &Path,
    tree: TextRef<'_>,
    lanes: Option<(&str, TextRef<'_>)>,
    check: TextRef<'_>,
    lane_base: Option<TextRef<'_>>,
) -> Result<Option<LaneDefinition>, PolicyError> {
    let Some((text, accepted)) = lanes else {
        return Ok(None);
    };
    let mut definition_base = accepted;
    if let Some(base) = lane_base {
        if !matches!(base.points().count(), 40 | 64)
            || !base.points().all(|p| matches!(p, 48..=57 | 97..=102))
        {
            return Err(failure(
                "error",
                "the lane base must be a full lowercase commit ID".into(),
            ));
        }
        repo_nul(repo)?;
        let encoded_base = encode(base, 0, true)?;
        let encoded_accepted = encode(accepted, 0, true)?;
        let read = log_transport::read(
            repo,
            &[
                OsStr::new("merge-base"),
                OsStr::new("--is-ancestor"),
                OsStr::from_bytes(&encoded_base),
                OsStr::from_bytes(&encoded_accepted),
            ],
            SourceResource::RawBlob(NormalizedText::concat(std::iter::once(base))),
        )?;
        if !read.status.success() {
            return Err(failure(
                "error",
                format!(
                    "the lane base {} is not an ancestor of the accepted base",
                    String::from_utf8_lossy(&encoded_base[..12])
                )
                .into(),
            ));
        }
        let path = cli_config::path(repo, base, LANES)?;
        let object = NormalizedText::concat(
            [
                base,
                TextRef::Str(":"),
                TextRef::Str(path.as_deref().unwrap_or(LANES)),
            ]
            .into_iter(),
        );
        let encoded_object = encode(object.borrowed(), 0, true)?;
        let shown = log_transport::read(
            repo,
            &[OsStr::new("show"), OsStr::from_bytes(&encoded_object)],
            SourceResource::LaneJson(PolicyResource::SourceBytes),
        )?;
        if path.is_some() && !shown.status.success() {
            return Err(failure(
                "error",
                NormalizedText::around("could not read lane file at ", object.borrowed(), ""),
            ));
        }
        if !shown.status.success()
            || !cli_lane_entry::matches(&String::from_utf8_lossy(&shown.stdout), text, check)?
        {
            return Err(failure(
                "definition_changed",
                NormalizedText::around(
                    "lane ",
                    check,
                    " in .st/required-lanes.json differs between the branch point and the accepted base",
                ),
            ));
        }
        definition_base = base;
    }
    repo_nul(repo)?;
    let expression = NormalizedText::around("", definition_base, "^{tree}");
    let encoded = encode(expression.borrowed(), 0, true)?.into_owned();
    let shown = read_git_source(
        repo,
        &[
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("--end-of-options"),
            OsStr::from_bytes(&encoded),
        ],
        SourceResource::RawBlob(expression),
    )?;
    let base_tree = utf8(&shown)
        .map_err(|m| exception("UnicodeDecodeError", m))?
        .trim_matches(space);
    lane_definition(
        repo,
        TextRef::Str(base_tree),
        tree,
        &LaneRules::parse(text, check)?,
    )
    .map(Some)
}

#[cfg(test)]
#[path = "cli_lane_for_tests.rs"]
mod tests;
