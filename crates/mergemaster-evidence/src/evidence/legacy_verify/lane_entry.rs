//! Guarded, lexeme-preserving lane entries; conservative failures are not missing lanes.
pub use crate::evidence::legacy_json::Value;
use crate::evidence::legacy_json::{encode_integer, extension_syntax, has_float, limits};
use crate::evidence::{
    legacy_json,
    legacy_policy::{PolicyError, check_names::CheckName},
};
/// Maximum simultaneously open JSON containers, including the root.
pub const MAX_CONTAINERS: usize = 127;
fn refusal(reason: &'static str) -> PolicyError {
    PolicyError {
        reason,
        detail: format!("legacy lane canonicalization refused: {reason}"),
    }
}
/// Select raw values before canonicalization and lane schema validation.
pub fn selected<'a>(
    text: &str,
    lane: impl Into<CheckName<'a>>,
) -> Result<Option<Value>, PolicyError> {
    let lane = lane.into();
    let (depth, long_integer) = limits(text);
    if long_integer {
        return Ok(None);
    } // Python json.loads' integer conversion limit.
    if depth > MAX_CONTAINERS {
        return Err(refusal("lane-entry-nesting-depth"));
    }
    let entry = match legacy_json::selected_lane(text, lane.text()) {
        Ok(entry) => entry,
        Err(_) => {
            // Probe grammar without accepting replacement values or altering strings.
            return if extension_syntax(text) {
                Err(refusal("lane-entry-json-extensions"))
            } else {
                Ok(None)
            };
        }
    };
    let Some(entry) = entry else {
        return Ok(None);
    };
    if has_float(&entry) {
        return Err(refusal("lane-entry-float-text"));
    }
    Ok(Some(entry))
}
/// Compare this serialized text before validating the lane schema.
pub fn canonical<'a>(
    text: &str,
    lane: impl Into<CheckName<'a>>,
) -> Result<Option<String>, PolicyError> {
    selected(text, lane).map(|entry| {
        entry.map(|entry| {
            let mut text = String::new();
            encode_integer(&entry, &mut text);
            text
        })
    })
}

#[cfg(test)]
#[path = "lane_name_tests.rs"]
mod name_tests;
#[cfg(test)]
#[path = "lane_entry_tests.rs"]
mod tests;
