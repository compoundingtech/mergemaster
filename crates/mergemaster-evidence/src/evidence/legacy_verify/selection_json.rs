//! Exact supported JSON selections; approved refusals never become missing entries.
use crate::evidence::{
    legacy_json::{self, Value, encode_integer, extension_syntax, has_float, limits},
    legacy_policy::{PolicyError, normalized_text::NormalizedText},
};
fn error(reason: &'static str, detail: impl Into<NormalizedText>) -> PolicyError {
    PolicyError {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason,
        detail: detail.into(),
    }
}
fn unit(bytes: Option<&[u8]>) -> Option<u16> {
    u16::from_str_radix(std::str::from_utf8(bytes?).ok()?, 16).ok()
}
/// The first extension token and its byte offset, excluding escaped backslashes and paired surrogates.
fn extension(text: &str) -> Option<(&str, usize)> {
    let b = text.as_bytes();
    let (mut i, mut quoted) = (0, false);
    while i < b.len() {
        if b[i] == b'"' {
            quoted = !quoted;
            i += 1;
            continue;
        }
        if quoted && b[i] == b'\\' {
            if b.get(i + 1) == Some(&b'u') {
                let value = unit(b.get(i + 2..i + 6))?;
                if (0xd800..=0xdfff).contains(&value) {
                    if value <= 0xdbff
                        && b.get(i + 6..i + 8) == Some(b"\\u")
                        && unit(b.get(i + 8..i + 12))
                            .is_some_and(|v| (0xdc00..=0xdfff).contains(&v))
                    {
                        i += 12;
                        continue;
                    }
                    return Some((&text[i..i + 6], i));
                }
                i += 6;
            } else {
                i += 2;
            }
            continue;
        }
        if !quoted
            && let Some(token) = ["-Infinity", "Infinity", "NaN"]
                .into_iter()
                .find(|t| b[i..].starts_with(t.as_bytes()))
        {
            return Some((token, i));
        }
        i += 1;
    }
    None
}
pub fn select_json(text: &str, selector: &str) -> Result<Option<Vec<u8>>, PolicyError> {
    let (depth, long) = limits(text);
    if long {
        return Err(error("error", "JSON integer exceeds 4300 digits"));
    }
    if depth > 127 {
        return Err(error(
            "input-selection-nesting-depth",
            "JSON exceeds 127 open containers",
        ));
    }
    let mut value = legacy_json::parse(text.as_bytes()).map_err(|_| {
        if let Some((token, at)) = extension(text).filter(|_| extension_syntax(text)) {
            error(
                "input-selection-json-extensions",
                format!("unsupported JSON token {token} at byte offset {at}"),
            )
        } else {
            error("error", "selected input is not supported JSON")
        }
    })?;
    for key in selector.split('.') {
        let Value::Object(mut object) = value else {
            return Ok(None);
        };
        let Some(next) = object.remove(key) else {
            return Ok(None);
        };
        value = next;
    }
    if has_float(&value) {
        return Err(error(
            "input-selection-float-text",
            "selected value contains a floating number",
        ));
    }
    let mut output = String::new();
    encode_integer(&value, &mut output);
    Ok(Some(output.into_bytes()))
}
#[cfg(test)]
#[path = "selection_json_tests.rs"]
mod tests;
