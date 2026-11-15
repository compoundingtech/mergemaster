//! Python operations on lossless TOML values, without imposing a Cargo schema.
use super::{
    crate_inputs_text::{joined, normpath},
    toml::{Table, Value},
};
use crate::evidence::legacy_policy::{ErrorOrigin, PolicyError};
pub fn exception(class: &'static str, detail: impl ToString) -> PolicyError {
    PolicyError {
        resource: None,
        reason: "error",
        origin: ErrorOrigin::Exception { class },
        detail: detail.to_string().into(),
    }
}
pub fn type_name(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "str",
        Value::Bool(_) => "bool",
        Value::Integer(_) => "int",
        Value::Float(_) => "float",
        Value::Array(_) => "list",
        Value::Table(_) => "dict",
        Value::Date(_) => "datetime.date",
        Value::Time(_) => "datetime.time",
        Value::DateTime { .. } => "datetime.datetime",
    }
}
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::String(s) => !s.is_empty(),
        Value::Bool(b) => *b,
        Value::Float(f) => *f != 0.0,
        Value::Integer(s) => {
            let raw = s.trim_start_matches(['+', '-']);
            let digits = raw
                .strip_prefix("0x")
                .or_else(|| raw.strip_prefix("0o"))
                .or_else(|| raw.strip_prefix("0b"))
                .unwrap_or(raw);
            digits.chars().any(|c| c != '0' && c != '_')
        }
        Value::Array(a) => !a.is_empty(),
        Value::Table(t) => !t.is_empty(),
        _ => true,
    }
}
pub fn attribute(value: &Value, method: &str) -> PolicyError {
    exception(
        "AttributeError",
        format!("'{}' object has no attribute '{method}'", type_name(value)),
    )
}
pub fn object<'a>(
    value: Option<&'a Value>,
    falsy_default: bool,
    method: &str,
) -> Result<Option<&'a Table>, PolicyError> {
    match value {
        None => Ok(None),
        Some(v) if falsy_default && !truthy(v) => Ok(None),
        Some(Value::Table(t)) => Ok(Some(t)),
        Some(v) => Err(attribute(v, method)),
    }
}
pub fn contains_star(value: &Value) -> Result<bool, PolicyError> {
    match value {
        Value::String(s) => Ok(s.contains('*')),
        Value::Table(t) => Ok(t.contains_key("*")),
        Value::Array(a) => Ok(a.iter().any(|v| matches!(v,Value::String(s) if s=="*"))),
        other => Err(exception(
            "TypeError",
            format!(
                "argument of type '{}' is not a container or iterable",
                type_name(other)
            ),
        )),
    }
}
pub fn path(value: &Value, directory: Option<&str>) -> Result<String, PolicyError> {
    if let Value::String(s) = value {
        return Ok(directory.map_or_else(|| normpath(s), |d| joined(d, s)));
    }
    let name = type_name(value).rsplit('.').next().unwrap_or_default();
    let message = if directory.is_some() {
        format!("join() argument must be str, bytes, or os.PathLike object, not '{name}'")
    } else {
        format!("_path_normpath: path should be string, bytes or os.PathLike, not {name}")
    };
    Err(exception("TypeError", message))
}
pub fn dependency_paths(
    table: Option<&Value>,
    directory: &str,
    workspace_deps: Option<&Value>,
) -> Result<Vec<String>, PolicyError> {
    let mut found = Vec::new();
    for (name, spec) in object(table, true, "items")?
        .into_iter()
        .flat_map(|t| t.iter())
    {
        let Value::Table(spec) = spec else { continue };
        if matches!(spec.get("workspace"), Some(Value::Bool(true))) {
            let inherited = object(workspace_deps, false, "get")?.and_then(|t| t.get(name));
            if let Some(Value::Table(inherited)) = inherited
                && let Some(value) = inherited.get("path")
            {
                found.push(path(value, None)?);
            }
        } else if let Some(value) = spec.get("path") {
            found.push(path(value, Some(directory))?);
        }
    }
    Ok(found)
}
#[cfg(test)]
#[path = "crate_manifest_ops_tests.rs"]
mod tests;
