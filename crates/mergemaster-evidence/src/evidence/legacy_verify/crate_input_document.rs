//! Accepted-base rust-test-inputs.json, retained as a lossless document.
use super::{
    crate_inputs::{INPUTS_PATH, TreeSource, failure, utf8},
    statement_document::{Document, Node, TextError},
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::PolicyError;
pub struct Inputs {
    document: Document,
}
impl Inputs {
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self, PolicyError> {
        let prefix = |error: String| failure(format!("{INPUTS_PATH}: {error}"));
        let text = utf8(bytes).map_err(prefix)?;
        let document=Document::from_text(text).map_err(|error|prefix(match error {
            TextError::Syntax(error)=>error.to_string(),
            TextError::IntegerLimit{digits}=>format!("Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"),
        }))?;
        let inputs = Self { document };
        if !matches!(inputs.document.root(), Node::Object(_))
            || inputs
                .get("global")
                .is_some_and(|v| !matches!(v, Node::Array(_)))
            || inputs
                .get("crates")
                .is_some_and(|v| !matches!(v, Node::Object(_)))
        {
            return Err(prefix(
                "expected {\"global\": [...], \"crates\": {name: {\"extra\": [...]}}}".into(),
            ));
        }
        if inputs.get("no_tests").is_some_and(|v| match v {
            Node::Array(ids) => ids
                .iter()
                .any(|id| !matches!(inputs.document.node(*id), Node::String(_))),
            _ => true,
        }) {
            return Err(prefix("no_tests must be an array of crate names".into()));
        }
        Ok(inputs)
    }
    pub fn document(&self) -> &Document {
        &self.document
    }
    pub fn get(&self, name: &str) -> Option<&Node> {
        Self::field(&self.document, self.document.root(), name)
    }
    pub fn field<'a>(document: &'a Document, node: &'a Node, name: &str) -> Option<&'a Node> {
        let Node::Object(entries) = node else {
            return None;
        };
        entries
            .iter()
            .find(|(key, _)| TextRef::Points(key).equals(name))
            .and_then(|(_, id)| document.try_node(*id))
    }
    pub fn no_tests(&self) -> impl Iterator<Item = &[u32]> {
        let ids = match self.get("no_tests") {
            Some(Node::Array(ids)) => ids.as_slice(),
            _ => &[],
        };
        ids.iter().filter_map(|id| match self.document.node(*id) {
            Node::String(s) => Some(s.as_slice()),
            _ => None,
        })
    }
}
impl TreeSource<'_> {
    pub fn read_inputs(&self) -> Result<Inputs, PolicyError> {
        let data = match self.config_path(INPUTS_PATH)? {
            Some(path) => self.show(&path)?,
            None => None,
        };
        let data =
            data.ok_or_else(|| failure(format!("{}:{INPUTS_PATH} is not readable", self.tree)))?;
        Inputs::parse_bytes(&data)
    }
}
#[cfg(test)]
#[path = "crate_input_document_tests.rs"]
mod tests;
