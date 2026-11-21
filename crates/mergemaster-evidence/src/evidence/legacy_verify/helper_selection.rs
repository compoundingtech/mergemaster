//! Python import-helper selection. Unlike verifier projections, this accepts
//! Python JSON extensions and arbitrary Git tree-ish expressions.
use super::{
    binding_path::encode,
    crate_inputs_text::utf8,
    crate_manifest_ops::exception,
    projection::read_git_source,
    source_resource::SourceResource,
    statement_document::{Document, Node},
    value_inputs::TextRef,
};
use crate::evidence::{
    legacy_json,
    legacy_policy::{PolicyError, normalized_text::NormalizedText},
};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

/// The iterative reader/serializer has no depth limit and succeeds beyond CPython's platform-dependent json.loads RecursionError threshold (about 100000 on 3.14).
pub fn select_part(
    text: &str,
    path: TextRef<'_>,
    mut selector: TextRef<'_>,
) -> Result<Option<Vec<u8>>, PolicyError> {
    if let Some(job) = selector.strip_prefix("jobs.") {
        return super::workflow::workflow_job(text, job);
    }
    let document = Document::from_text(text).map_err(|_| {
        super::crate_inputs::failure(NormalizedText::around("", path, " is not JSON"))
    })?;
    let mut node = document.root();
    loop {
        let (key, tail) = selector
            .split_once(".")
            .map_or((selector, None), |(key, tail)| (key, Some(tail)));
        let Node::Object(fields) = node else {
            return Ok(None);
        };
        let Some((_, id)) = fields
            .iter()
            .find(|(name, _)| name.iter().copied().eq(key.points()))
        else {
            return Ok(None);
        };
        node = document.node(*id);
        let Some(tail) = tail else { break };
        selector = tail;
    }
    serialize(&document, node, JsonFormat::Selection).map(|text| Some(text.into_bytes()))
}
/// Full original fields in insertion order, matching Python json.dumps defaults.
pub(super) fn statement_json(document: &Document) -> Result<String, PolicyError> {
    serialize(document, document.root(), JsonFormat::Statement)
}
#[derive(Clone, Copy)]
enum JsonFormat {
    Selection,
    Statement,
}
enum Emit<'a> {
    Node(&'a Node),
    Text(&'static str),
    Key(&'a [u32]),
}
fn object_entries<'a>(
    stack: &mut Vec<Emit<'a>>,
    document: &'a Document,
    entries: impl DoubleEndedIterator<Item = (&'a Vec<u32>, &'a usize)> + ExactSizeIterator,
    comma: &'static str,
    colon: &'static str,
) {
    for (index, (key, id)) in entries.enumerate().rev() {
        stack.push(Emit::Node(document.node(*id)));
        stack.push(Emit::Text(colon));
        stack.push(Emit::Key(key));
        if index != 0 {
            stack.push(Emit::Text(comma));
        }
    }
}
fn serialize(document: &Document, root: &Node, format: JsonFormat) -> Result<String, PolicyError> {
    let (comma, colon) = match format {
        JsonFormat::Selection => (",", ":"),
        JsonFormat::Statement => (", ", ": "),
    };
    let mut output = String::new();
    let mut stack = vec![Emit::Node(root)];
    let failure = super::crate_inputs::failure;
    while let Some(action) = stack.pop() {
        match action {
            Emit::Text(text) => output.push_str(text),
            Emit::Key(points) => legacy_json::codepoints(points.iter().copied(), &mut output)
                .map_err(|error| failure(error.to_string()))?,
            Emit::Node(node) => match node {
                Node::Null => output.push_str("null"),
                Node::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
                Node::Integer(value) => output.push_str(if value == "-0" { "0" } else { value }),
                Node::Float(value) => {
                    if value.is_nan() {
                        output.push_str("NaN");
                    } else if value.is_infinite() {
                        output.push_str(if value.is_sign_negative() {
                            "-Infinity"
                        } else {
                            "Infinity"
                        });
                    } else {
                        output.push_str(
                            &crate::evidence::legacy_request::float_token(*value)
                                .map_err(|error| failure(error.to_string()))?,
                        );
                    }
                }
                Node::String(points) => {
                    legacy_json::codepoints(points.iter().copied(), &mut output)
                        .map_err(|error| failure(error.to_string()))?
                }
                Node::Array(items) => {
                    output.push('[');
                    stack.push(Emit::Text("]"));
                    for (index, id) in items.iter().enumerate().rev() {
                        stack.push(Emit::Node(document.node(*id)));
                        if index != 0 {
                            stack.push(Emit::Text(comma));
                        }
                    }
                }
                Node::Object(fields) => {
                    output.push('{');
                    stack.push(Emit::Text("}"));
                    match format {
                        JsonFormat::Selection => {
                            let mut ordered: Vec<_> = fields.iter().collect();
                            ordered.sort_unstable_by(|a, b| a.0.cmp(b.0));
                            object_entries(&mut stack, document, ordered.into_iter(), comma, colon);
                        }
                        JsonFormat::Statement => {
                            object_entries(&mut stack, document, fields.iter(), comma, colon);
                        }
                    }
                }
            },
        }
    }
    Ok(output)
}
fn replace_first(text: TextRef<'_>, needle: &str, replacement: &str) -> NormalizedText {
    match text.split_once(needle) {
        Some((head, tail)) => {
            NormalizedText::concat([head, TextRef::Str(replacement), tail].into_iter())
        }
        None => NormalizedText::around("", text, ""),
    }
}
fn read(repo: &Path, tree: &OsStr, args: &[&OsStr]) -> Result<Vec<u8>, PolicyError> {
    read_git_source(
        repo,
        args,
        SourceResource::RawBlob(super::cli_adapter::decode(tree)),
    )
}
/// Keep the original ls-tree/show operations, so invalid expressions fail in
/// precisely the operation Python performs (never an eager rev-parse).
pub fn selected(
    repo: &Path,
    tree: &OsStr,
    item: TextRef<'_>,
) -> Result<Option<Vec<u8>>, PolicyError> {
    let (path, selector) = item.split_once("::").unwrap_or((item, TextRef::Str("")));
    let resolved;
    let path = if path.starts_with(".st/") || path.starts_with(".fractal/") {
        let legacy = replace_first(path, ".fractal/", ".st/");
        let preferred = replace_first(legacy.borrowed(), ".st/", ".fractal/");
        let legacy_bytes = encode(legacy.borrowed(), 0, true)?;
        let preferred_bytes = encode(preferred.borrowed(), 0, true)?;
        let listing = read(
            repo,
            tree,
            &[
                OsStr::new("ls-tree"),
                OsStr::new("-z"),
                OsStr::new("--full-tree"),
                tree,
                OsStr::new("--"),
                OsStr::from_bytes(&preferred_bytes),
                OsStr::from_bytes(&legacy_bytes),
            ],
        )?;
        let mut has_preferred = false;
        let mut has_legacy = false;
        for entry in listing
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let name = entry
                .splitn(2, |byte| *byte == b'\t')
                .nth(1)
                .unwrap_or_default();
            utf8(name).map_err(|error| exception("UnicodeDecodeError", error))?;
            has_preferred |= name == preferred_bytes.as_ref();
            has_legacy |= name == legacy_bytes.as_ref();
        }
        drop(legacy_bytes);
        drop(preferred_bytes);
        resolved = if has_preferred {
            preferred
        } else if has_legacy {
            legacy
        } else {
            return Ok(None);
        };
        resolved.borrowed()
    } else {
        path
    };
    selected_content(repo, tree, path, selector)
}
pub(super) fn selected_content(
    repo: &Path,
    tree: &OsStr,
    path: TextRef<'_>,
    selector: TextRef<'_>,
) -> Result<Option<Vec<u8>>, PolicyError> {
    let encoded = encode(path, 0, true)?;
    let listing = read(
        repo,
        tree,
        &[
            OsStr::new("ls-tree"),
            OsStr::new("--full-tree"),
            tree,
            OsStr::new("--"),
            OsStr::from_bytes(&encoded),
        ],
    )?;
    if listing.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(None);
    }
    let object = [tree.as_bytes(), b":", &encoded].concat();
    let shown = read(
        repo,
        tree,
        &[
            OsStr::new("show"),
            OsStr::new("--end-of-options"),
            OsStr::from_bytes(&object),
        ],
    )?;
    let text = std::str::from_utf8(&shown).map_err(|_| {
        super::crate_inputs::failure(NormalizedText::around("", path, " is not text"))
    })?;
    select_part(text, path, selector)
}
