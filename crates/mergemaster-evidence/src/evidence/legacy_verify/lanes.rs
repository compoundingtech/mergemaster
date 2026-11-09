//! Legacy lane declarations; no Git reads or native hashing.
use crate::evidence::legacy_policy::{PolicyError, declared_paths, selected_entry};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct LaneRules {
    pub argv: Vec<String>,
    pub definition_paths: Vec<String>,
    pub tree_inputs: Vec<String>,
    pub absent_paths: Vec<String>,
    pub ci_inputs: Option<Vec<String>>,
}
impl LaneRules {
    pub fn parse(text: &str, lane: &str) -> Result<Self, PolicyError> {
        let error = || PolicyError {
            reason: "error",
            detail: format!("invalid lane {lane}"),
        };
        let entry = selected_entry(text, lane, "lanes")?.ok_or_else(|| PolicyError {
            reason: "no_lane",
            detail: format!("lane {lane} is absent"),
        })?;
        let Value::Object(mut entry) = entry else {
            return Err(error());
        };
        if entry.keys().any(|k| {
            ![
                "argv",
                "definition_paths",
                "tree_inputs",
                "absent_paths",
                "ci_inputs",
            ]
            .contains(&k.as_str())
        }) {
            return Err(error());
        }
        let argv: Vec<String> =
            serde_json::from_value(entry.remove("argv").ok_or_else(error)?).map_err(|_| error())?;
        if argv.is_empty() || argv.iter().any(String::is_empty) {
            return Err(error());
        }
        let paths = |key: &str, optional: bool| -> Result<Vec<String>, PolicyError> {
            let Some(value) = entry.get(key) else {
                return if optional {
                    Ok(Vec::new())
                } else {
                    Err(error())
                };
            };
            if optional
                && (matches!(value, Value::String(s) if s.is_empty())
                    || matches!(value, Value::Object(m) if m.is_empty())
                    || matches!(value, Value::Array(a) if a.is_empty()))
            {
                return Ok(Vec::new());
            }
            let paths = declared_paths(value, lane, false)?;
            if key != "tree_inputs" && paths.iter().any(|p| p == ".") {
                return Err(error());
            }
            Ok(paths)
        };
        Ok(Self {
            argv,
            definition_paths: paths("definition_paths", false)?,
            tree_inputs: paths("tree_inputs", true)?,
            absent_paths: paths("absent_paths", true)?,
            ci_inputs: entry
                .get("ci_inputs")
                .filter(|v| !v.is_null())
                .map(|v| declared_paths(v, lane, true))
                .transpose()?,
        })
    }
}
#[cfg(test)]
#[path = "lanes_tests.rs"]
mod tests;
