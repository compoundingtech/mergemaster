//! Guarded, lexeme-preserving lane entries; conservative failures are not missing lanes.
pub use crate::evidence::legacy_json::Value;
use crate::evidence::{legacy_json, legacy_policy::PolicyError};
/// Maximum simultaneously open JSON containers, including the root.
pub const MAX_CONTAINERS: usize = 127;
fn refusal(reason: &'static str) -> PolicyError {
    PolicyError {
        reason,
        detail: format!("legacy lane canonicalization refused: {reason}"),
    }
}
fn extension_syntax(text: &str) -> bool {
    let bytes = text.as_bytes();
    let (mut i, mut quoted, mut escaped) = (0, false, false);
    let mut probe = Vec::with_capacity(bytes.len());
    while i < bytes.len() {
        let token = ["-Infinity", "Infinity", "NaN"]
            .into_iter()
            .find(|t| !quoted && bytes[i..].starts_with(t.as_bytes()));
        if let Some(token) = token {
            probe.extend_from_slice(b"null");
            i += token.len();
            continue;
        }
        let b = bytes[i];
        probe.push(b);
        if escaped {
            escaped = false;
        } else if quoted && b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            quoted = !quoted;
        }
        i += 1;
    }
    serde_json::from_slice::<serde::de::IgnoredAny>(&probe).is_ok()
}
fn limits(text: &str) -> (usize, bool) {
    let bytes = text.as_bytes();
    let (mut i, mut quoted, mut depth, mut maximum, mut long_integer) =
        (0, false, 0usize, 0, false);
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if quoted => {
                i += 2;
                continue;
            }
            b'"' => quoted = !quoted,
            b'[' | b'{' if !quoted => {
                depth += 1;
                maximum = maximum.max(depth);
            }
            b']' | b'}' if !quoted => depth = depth.saturating_sub(1),
            b'-' | b'0'..=b'9' if !quoted => {
                let start = i;
                while i < bytes.len() && b"0123456789.eE+-".contains(&bytes[i]) {
                    i += 1;
                }
                let number = &text[start..i];
                long_integer |= !number.contains(['.', 'e', 'E'])
                    && number.trim_start_matches('-').len() > 4300;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    (maximum, long_integer)
}
fn has_float(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.contains(['.', 'e', 'E']),
        Value::Array(a) => a.iter().any(has_float),
        Value::Object(m) => m.values().any(has_float),
        _ => false,
    }
}
/// Select raw values before canonicalization and lane schema validation.
pub fn selected(text: &str, lane: &str) -> Result<Option<Value>, PolicyError> {
    let (depth, long_integer) = limits(text);
    if long_integer {
        return Ok(None);
    } // Python json.loads' integer conversion limit.
    if depth > MAX_CONTAINERS {
        return Err(refusal("lane-entry-nesting-depth"));
    }
    let doc = match legacy_json::parse(text.as_bytes()) {
        Ok(doc) => doc,
        Err(_) => {
            // Probe grammar without accepting replacement values or altering strings.
            return if extension_syntax(text) {
                Err(refusal("lane-entry-json-extensions"))
            } else {
                Ok(None)
            };
        }
    };
    let Value::Object(mut doc) = doc else {
        return Ok(None);
    };
    let Some(Value::Object(mut lanes)) = doc.remove("lanes") else {
        return Ok(None);
    };
    let Some(entry) = lanes.remove(lane) else {
        return Ok(None);
    };
    if has_float(&entry) {
        return Err(refusal("lane-entry-float-text"));
    }
    Ok(Some(entry))
}

#[cfg(test)]
#[path = "lane_entry_tests.rs"]
mod tests;
