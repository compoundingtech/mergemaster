//! Legacy tests statements; structural validity grants no signature trust.
pub use crate::evidence::legacy_json::Value;
use crate::evidence::oid;
use chrono::{Datelike, NaiveDate};
fn nonblank(s: &str) -> bool {
    !s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
        .is_empty()
}
fn clock(s: &str, offset: bool) -> bool {
    let (main, fraction) = s
        .split_once(['.', ','])
        .map_or((s, None), |(a, b)| (a, Some(b)));
    if fraction.is_some_and(|v| {
        v.is_empty()
            || !v.bytes().all(|b| b.is_ascii_digit())
            || main.len() != if main.contains(':') { 8 } else { 6 }
    }) {
        return false;
    }
    let extended = main.contains(':');
    if !(if extended {
        [2, 5, 8].contains(&main.len())
    } else {
        [2, 4, 6].contains(&main.len())
    }) {
        return false;
    }
    let mut seconds = 0;
    let mut number = 0;
    let mut count = 0_usize;
    for (i, b) in main.bytes().enumerate() {
        if extended && i % 3 == 2 {
            if b != b':' {
                return false;
            }
            continue;
        }
        if !b.is_ascii_digit() {
            return false;
        }
        number = number * 10 + u32::from(b - b'0');
        count += 1;
        if count.is_multiple_of(2) {
            if !offset && number >= if count == 2 { 25 } else { 60 } {
                return false;
            }
            seconds += number * [3600, 60, 1][count / 2 - 1];
            number = 0;
        }
    }
    seconds < 86400
        || (!offset
            && seconds == 86400
            && fraction.unwrap_or("").bytes().take(6).all(|b| b == b'0'))
}
fn zoned_time(s: &str) -> bool {
    // Python replaces every Z before fromisoformat, including a separator Z.
    let s = if s.contains('Z') {
        std::borrow::Cow::Owned(s.replace('Z', "+00:00"))
    } else {
        std::borrow::Cow::Borrowed(s)
    };
    let date = [10, 8, 7].into_iter().find_map(|end| {
        let head = s.get(..end)?;
        if !"dddd-dd-dd|dddddddd|dddd-Wdd-d|ddddWddd|dddd-Wdd|ddddWdd"
            .split('|')
            .any(|shape| {
                shape.len() == head.len()
                    && shape
                        .bytes()
                        .zip(head.bytes())
                        .all(|(p, b)| (p == b'd' && b.is_ascii_digit()) || (p != b'd' && p == b))
            })
        {
            return None;
        }
        let parsed = ["%Y-%m-%d", "%Y%m%d", "%G-W%V-%u", "%GW%V%u"]
            .into_iter()
            .find_map(|f| NaiveDate::parse_from_str(head, f).ok())
            .or_else(|| {
                ["%G-W%V-%u", "%GW%V%u"].into_iter().find_map(|f| {
                    NaiveDate::parse_from_str(
                        &format!("{head}{}", if head.contains('-') { "-1" } else { "1" }),
                        f,
                    )
                    .ok()
                })
            })?;
        (parsed.year() >= 1 && parsed.year() <= 9999).then_some((end, parsed))
    });
    let Some((end, date)) = date else {
        return false;
    };
    let Some(tail) = s
        .get(end..)
        .and_then(|v| v.chars().next().map(|c| &v[c.len_utf8()..]))
    else {
        return false;
    };
    let Some(zone) = tail.find(['+', '-']) else {
        return false;
    };
    clock(&tail[..zone], false)
        && clock(&tail[zone + 1..], true)
        && (!tail.starts_with("24") || date.succ_opt().is_some_and(|d| d.year() <= 9999))
}
/// Validate a decoded legacy tests statement, retaining unknown fields and number lexemes.
/// JSON byte decoding belongs to the record loader, not this structural guard.
pub fn statement_of(v: Value, tree: &str) -> Option<Value> {
    let p = &v["predicate"];
    let subjects = v["subject"].as_array()?;
    let observed = &p["observed"];
    let schema_one = matches!(&p["schema_version"], Value::Bool(true))
        || p["schema_version"]
            .as_number()
            .is_some_and(|n| n.parse::<f64>().ok() == Some(1.0));
    if v["_type"] != "https://in-toto.io/Statement/v1"
        || !matches!(
            v["predicateType"].as_str(),
            Some(
                "https://compounding.tech/fractal/evidence/gate/v1"
                    | "https://smalltalk.dev/evidence/gate/v1"
            )
        )
        || subjects.len() != 1
        || oid(subjects[0]["name"].as_str()?).is_err()
        || subjects[0]["digest"].as_object()?.len() != 1
        || subjects[0]["digest"]["gitTree"].as_str() != Some(tree)
        || !schema_one
        || !nonblank(p["change_id"].as_str()?)
        || !matches!(p["tier"].as_str(), Some("full" | "degraded" | "test"))
        || !matches!(p.get("signer")?, Value::Null | Value::String(_))
        || observed["kind"] != "tests"
        || !observed["runner"].is_string()
        || !zoned_time(p["observed_at"].as_str()?)
    {
        return None;
    }
    if let Some(inputs) = observed.get("inputs") {
        for (key, value) in inputs.as_object()? {
            if !nonblank(key) || !nonblank(value.as_str()?) {
                return None;
            }
        }
    }
    for (name, check) in observed["checks"].as_object()? {
        let command = check["command"].as_array()?;
        let code = check["exit_code"].as_number()?;
        let hash = check["output_sha256"].as_str()?;
        if !nonblank(name)
            || command.is_empty()
            || !command.iter().all(Value::is_string)
            || code.contains(['.', 'e', 'E'])
            || code.trim_start_matches('-').len() > 4300
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
    }
    Some(v)
}
#[cfg(test)]
#[path = "statement_tests.rs"]
mod tests;
