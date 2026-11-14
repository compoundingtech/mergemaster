//! Uncaught json.loads(bytes) boundary, without the statement depth budget.
use super::{
    crate_manifest_ops::exception,
    statement_bytes::decode_json_bytes_exact,
    statement_document::{Document, TextError},
};
use crate::evidence::legacy_policy::PolicyError;

pub fn parse(bytes: &[u8]) -> Result<Document, PolicyError> {
    let points =
        decode_json_bytes_exact(bytes).map_err(|error| exception("UnicodeDecodeError", error))?;
    Document::from_points(points).map_err(|error| match error {
        TextError::Syntax(error) => exception("JSONDecodeError", error),
        TextError::IntegerLimit { digits } => exception("ValueError", format!(
            "Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"
        )),
    })
}
#[cfg(test)]
#[path = "json_bytes_tests.rs"]
mod tests;
