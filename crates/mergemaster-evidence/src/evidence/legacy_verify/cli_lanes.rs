//! CLI-only lossless lane ingress; native lane parsing remains unchanged.
use super::{
    statement_document::{Document, Node, PolicyTextError, TextError},
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{
    ErrorOrigin, PolicyError, SourceResource, declared_path_items, normalized_text::NormalizedText,
};

pub struct LaneRules {
    pub argv: Vec<NormalizedText>,
    pub definition_paths: Vec<String>,
    pub tree_inputs: Vec<String>,
    pub absent_paths: Vec<String>,
    pub ci_inputs: Option<Vec<String>>,
}
fn failure(reason: &'static str, detail: NormalizedText) -> PolicyError {
    PolicyError {
        resource: None,
        origin: ErrorOrigin::Failure,
        reason,
        detail,
    }
}
fn get<'a>(doc: &'a Document, node: &'a Node, key: TextRef<'_>) -> Option<&'a Node> {
    let Node::Object(entries) = node else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.iter().copied().eq(key.points()))
        .map(|(_, id)| doc.node(*id))
}
fn truthy(node: &Node) -> bool {
    match node {
        Node::Null | Node::Bool(false) => false,
        Node::Integer(n) => n != "0" && n != "-0",
        Node::Float(n) => *n != 0.0,
        Node::String(s) => !s.is_empty(),
        Node::Array(a) => !a.is_empty(),
        Node::Object(o) => !o.is_empty(),
        Node::Bool(true) => true,
    }
}
fn tuple_falsey(node: Option<&Node>) -> Result<(), PolicyError> {
    let kind = match node {
        Some(Node::Null) => "NoneType",
        Some(Node::Bool(_)) => "bool",
        Some(Node::Integer(_)) => "int",
        Some(Node::Float(_)) => "float",
        _ => return Ok(()),
    };
    Err(PolicyError {
        resource: None,
        origin: ErrorOrigin::Exception { class: "TypeError" },
        reason: "error",
        detail: format!("'{kind}' object is not iterable").into(),
    })
}
impl LaneRules {
    pub fn parse(text: &str, lane: TextRef<'_>) -> Result<Self, PolicyError> {
        let doc = Document::from_policy_text(text).map_err(|error| match error {
            PolicyTextError::Resource(resource) => {
                let resource = SourceResource::LaneJson(resource);
                resource.into_error()
            }
            PolicyTextError::Text(error) => {
                let detail = match error {
                    TextError::Syntax(error) => error.to_string(),
                    TextError::IntegerLimit { digits } => format!("Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"),
                };
                failure("error", format!("lane file is not valid JSON: {detail}").into())
            }
        })?;
        let root = doc.root();
        let lookup = |node, key: &str| get(&doc, node, TextRef::Str(key));
        let version = lookup(root, "version");
        let one = match version {
            Some(Node::Bool(true)) => true,
            Some(Node::Integer(n)) => n == "1",
            Some(Node::Float(n)) => *n == 1.0,
            _ => false,
        };
        let lanes = lookup(root, "lanes");
        if !matches!(root, Node::Object(o) if o.len() == 2)
            || !one
            || !matches!(lanes, Some(Node::Object(_)))
        {
            return Err(failure(
                "error",
                "lane file must be {\"version\": 1, \"lanes\": {...}}".into(),
            ));
        }
        let entry = lanes
            .and_then(|lanes| get(&doc, lanes, lane))
            .ok_or_else(|| {
                failure(
                    "no_lane",
                    NormalizedText::around("the lane file has no entry for ", lane, ""),
                )
            })?;
        let error = |suffix| failure("error", NormalizedText::around("lane ", lane, suffix));
        let shape = || error(" needs argv and definition_paths, and nothing unknown");
        if !matches!(entry, Node::Object(o) if o.keys().all(|k| ["argv", "definition_paths", "tree_inputs", "absent_paths", "ci_inputs"].iter().any(|name| TextRef::Points(k).equals(name))))
            || lookup(entry, "argv").is_none()
            || lookup(entry, "definition_paths").is_none()
        {
            return Err(shape());
        }
        let argv = match lookup(entry, "argv") {
            Some(Node::Array(ids)) if !ids.is_empty() => ids
                .iter()
                .map(|id| match doc.node(*id) {
                    Node::String(s) if !s.is_empty() => Some(NormalizedText::from_points(s)),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>(),
            _ => None,
        }
        .ok_or_else(|| error(": argv must be a nonempty list of strings"))?;
        let paths = |key: &str, selectors| {
            let values = match lookup(entry, key) {
                Some(Node::Array(ids)) => Some(ids.iter().map(|id| match doc.node(*id) {
                    Node::String(s) => Some(TextRef::Points(s)),
                    _ => None,
                })),
                _ => None,
            };
            declared_path_items(
                values,
                &[
                    TextRef::Str("lane "),
                    lane,
                    TextRef::Str(" "),
                    TextRef::Str(key),
                ],
                selectors,
            )
        };
        let definition_paths = paths("definition_paths", false)?;
        if definition_paths.iter().any(|p| p == ".") {
            return Err(error(
                ": definition_paths must name files or directories, not the whole tree",
            ));
        }
        let tree = lookup(entry, "tree_inputs");
        let tree_inputs = if tree.is_some_and(truthy) {
            paths("tree_inputs", false)?
        } else {
            Vec::new()
        };
        let absent = lookup(entry, "absent_paths");
        let absent_paths = if absent.is_some_and(truthy) {
            paths("absent_paths", false)?
        } else {
            Vec::new()
        };
        if absent_paths.iter().any(|p| p == ".") {
            return Err(error(
                ": absent_paths must name files or directories, not the whole tree",
            ));
        }
        let ci_inputs = match lookup(entry, "ci_inputs") {
            None | Some(Node::Null) => None,
            Some(_) => Some(paths("ci_inputs", true)?),
        };
        if tree.is_some_and(|n| !truthy(n)) {
            tuple_falsey(tree)?;
        }
        if absent.is_some_and(|n| !truthy(n)) {
            tuple_falsey(absent)?;
        }
        Ok(Self {
            argv,
            definition_paths,
            tree_inputs,
            absent_paths,
            ci_inputs,
        })
    }
}
#[cfg(test)]
#[path = "cli_lanes_boundary_tests.rs"]
mod boundary_tests;
#[cfg(test)]
#[path = "cli_lanes_tests.rs"]
mod tests;
