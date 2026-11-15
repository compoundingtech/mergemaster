//! Declared per-crate paths, before Git projection or any string encoding.
use super::{
    crate_closure::ClosureCache,
    crate_input_document::Inputs,
    crate_inputs::{INPUTS_PATH, TreeSource, failure, joined},
    crate_manifest_ops::{exception, object, truthy},
    statement_document::Node,
};
use crate::evidence::legacy_policy::{PolicyError, normalized_text::NormalizedText};
use indexmap::IndexMap;
use std::collections::BTreeSet;
fn node_type(node: &Node) -> &'static str {
    match node {
        Node::Null => "NoneType",
        Node::Bool(_) => "bool",
        Node::Integer(_) => "int",
        Node::Float(_) => "float",
        Node::String(_) => "str",
        Node::Array(_) => "list",
        Node::Object(_) => "dict",
    }
}
fn node_truthy(node: &Node) -> bool {
    match node {
        Node::Null => false,
        Node::Bool(b) => *b,
        Node::Integer(s) => s != "0",
        Node::Float(f) => *f != 0.0,
        Node::String(s) => !s.is_empty(),
        Node::Array(a) => !a.is_empty(),
        Node::Object(o) => !o.is_empty(),
    }
}
fn add_node(paths: &mut BTreeSet<NormalizedText>, node: &Node) -> Result<bool, PolicyError> {
    match node {
        Node::String(s) => {
            paths.insert(NormalizedText::from_points(s));
            Ok(false)
        }
        Node::Array(_) | Node::Object(_) => {
            let name = node_type(node);
            Err(exception(
                "TypeError",
                format!("cannot use '{name}' as a set element (unhashable type: '{name}')"),
            ))
        }
        _ => Ok(true), // Defer the approved mixed-type sorting refusal until after the walk.
    }
}
fn extras(
    inputs: &Inputs,
    name: &str,
    paths: &mut BTreeSet<NormalizedText>,
) -> Result<bool, PolicyError> {
    let crate_spec = inputs
        .get("crates")
        .and_then(|crates| Inputs::field(inputs.document(), crates, name))
        .filter(|v| node_truthy(v));
    let extra = match crate_spec {
        None => None,
        Some(v @ Node::Object(_)) => Inputs::field(inputs.document(), v, "extra"),
        Some(v) => {
            return Err(exception(
                "AttributeError",
                format!("'{}' object has no attribute 'get'", node_type(v)),
            ));
        }
    };
    let mut invalid = false;
    match extra {
        None | Some(Node::Null) => {
            paths.insert(".".into());
        }
        Some(Node::Array(ids)) => {
            for id in ids {
                invalid |= add_node(paths, inputs.document().node(*id))?;
            }
        }
        Some(Node::Object(keys)) => {
            for key in keys.keys() {
                paths.insert(NormalizedText::from_points(key));
            }
        }
        Some(Node::String(points)) => {
            for point in points {
                paths.insert(NormalizedText::from_points(std::slice::from_ref(point)));
            }
        }
        Some(v) => {
            return Err(exception(
                "TypeError",
                format!("'{}' object is not iterable", node_type(v)),
            ));
        }
    }
    Ok(invalid)
}
impl TreeSource<'_> {
    pub fn declared_paths(
        &self,
        inputs: &Inputs,
    ) -> Result<IndexMap<String, Vec<NormalizedText>>, PolicyError> {
        let layout = self.layout()?;
        let mut result = IndexMap::new();
        if layout.members.is_empty() {
            return Ok(result);
        }
        let mut global = BTreeSet::new();
        let mut invalid_global = false;
        if let Some(Node::Array(ids)) = inputs.get("global") {
            for id in ids {
                invalid_global |= add_node(&mut global, inputs.document().node(*id))?;
            }
        }
        global.extend(layout.patched.into_iter().map(NormalizedText::from));
        global.extend(
            layout
                .members
                .values()
                .map(|dir| NormalizedText::from(joined(dir, "Cargo.toml"))),
        );
        let workspace = object(layout.root.get("workspace"), true, "get")?;
        let workspace_deps = workspace
            .and_then(|t| t.get("dependencies"))
            .filter(|v| truthy(v));
        let mut cache = ClosureCache::default();
        for (name, directory) in layout.members {
            let mut paths = global.clone();
            self.closure(&directory, workspace_deps, &mut cache)?;
            if let Some(closure) = cache.paths(&directory) {
                for dir in closure {
                    if dir == "." {
                        paths.extend(
                            ["src", "tests", "benches", "build.rs"].map(NormalizedText::from),
                        );
                    } else {
                        paths.insert(dir.clone().into());
                    }
                }
            }
            let invalid_extra = extras(inputs, &name, &mut paths)?;
            if invalid_global || invalid_extra {
                return Err(failure(format!(
                    "{INPUTS_PATH}: declared path is not a string"
                )));
            }
            result.insert(name, paths.into_iter().collect());
        }
        Ok(result)
    }
}
#[cfg(test)]
#[path = "crate_paths_tests.rs"]
mod tests;
