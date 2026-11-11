//! Legacy tests statements; structural validity grants no signature trust.
use super::statement_document::{Document, Error, MAX_CONTAINER_DEPTH, Node};
use crate::evidence::legacy_policy::PolicyError;
use chrono::{Datelike, NaiveDate};
fn nonblank(s: &[u32]) -> bool {
    s.iter().any(|p| {
        char::from_u32(*p)
            .is_none_or(|c| !(c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)))
    })
}
pub(super) fn string(v: &Node) -> Option<&[u32]> {
    if let Node::String(s) = v {
        Some(s)
    } else {
        None
    }
}
fn text(v: &Node, expected: &str) -> bool {
    string(v).is_some_and(|s| s.iter().copied().eq(expected.chars().map(u32::from)))
}
fn object(v: &Node) -> Option<&indexmap::IndexMap<Vec<u32>, usize>> {
    if let Node::Object(v) = v {
        Some(v)
    } else {
        None
    }
}
pub(super) fn array(v: &Node) -> Option<&[usize]> {
    if let Node::Array(v) = v {
        Some(v)
    } else {
        None
    }
}
pub(super) fn field<'a>(doc: &'a Document, v: &Node, key: &str) -> Option<&'a Node> {
    // All guard field names are static ASCII and shorter than this stack buffer.
    let mut points = [0; 32];
    for (p, b) in points.iter_mut().zip(key.bytes()) {
        *p = u32::from(b);
    }
    object(v)?.get(&points[..key.len()]).map(|id| doc.node(*id))
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
fn zoned_time(points: &[u32]) -> bool {
    // Python replaces every Z before fromisoformat, including a separator Z.
    let expanded;
    let s = if points.contains(&90) {
        expanded = points
            .iter()
            .flat_map(|p| {
                if *p == 90 {
                    &[43, 48, 48, 58, 48, 48][..]
                } else {
                    std::slice::from_ref(p)
                }
            })
            .copied()
            .collect::<Vec<_>>();
        &expanded[..]
    } else {
        points
    };
    let date = [10, 8, 7].into_iter().find_map(|end| {
        let mut bytes = [0; 10];
        for (b, p) in bytes.iter_mut().zip(s.get(..end)?) {
            *b = u8::try_from(*p).ok().filter(u8::is_ascii)?;
        }
        let head = std::str::from_utf8(&bytes[..end]).ok()?;
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
    // Consume exactly one Python code point as separator, including a surrogate.
    // The date and clock themselves remain strict ASCII; no sentinel substitution.
    let Some(tail) = s.get(end + 1..).and_then(|points| {
        points
            .iter()
            .map(|p| u8::try_from(*p).ok().filter(u8::is_ascii))
            .collect::<Option<Vec<_>>>()
            .and_then(|b| String::from_utf8(b).ok())
    }) else {
        return false;
    };
    let Some(zone) = tail.find(['+', '-']) else {
        return false;
    };
    clock(&tail[..zone], false)
        && clock(&tail[zone + 1..], true)
        && (!tail.starts_with("24") || date.succ_opt().is_some_and(|d| d.year() <= 9999))
}
/// Rust-only cap: Python's reader is unbounded. Checked before any JSON allocation.
pub const MAX_STATEMENT_BYTES: usize = 1024 * 1024;
/// Decode and validate a legacy tests statement; this grants no signature trust.
pub fn statement_of(blob: &[u8], tree: &str) -> Result<Option<Document>, PolicyError> {
    if blob.len() > MAX_STATEMENT_BYTES {
        return Err(PolicyError {
            reason: "statement-too-large",
            detail: format!("record statement exceeds {MAX_STATEMENT_BYTES} bytes"),
        });
    }
    let doc = match Document::from_bytes(blob) {
        Ok(doc) => doc,
        Err(Error::NestingLimit) => {
            return Err(PolicyError {
                reason: "statement-too-deep",
                detail: format!("record statement exceeds {MAX_CONTAINER_DEPTH} containers"),
            });
        }
        Err(_) => return Ok(None),
    };
    Ok(valid(&doc, tree).map(|()| doc))
}
fn valid(doc: &Document, tree: &str) -> Option<()> {
    let get = |v, key| field(doc, v, key);
    let v = doc.root();
    let p = get(v, "predicate")?;
    let subjects = array(get(v, "subject")?)?;
    if subjects.len() != 1 {
        return None;
    }
    let subject = doc.node(subjects[0]);
    let observed = get(p, "observed")?;
    let schema_one = match get(p, "schema_version")? {
        Node::Bool(true) => true,
        Node::Integer(n) => n == "1",
        Node::Float(n) => *n == 1.0,
        _ => false,
    };
    let name = string(get(subject, "name")?)?;
    let hex = |s: &[u32]| {
        s.iter()
            .all(|p| (48..=57).contains(p) || (97..=102).contains(p))
    };
    if !text(get(v, "_type")?, "https://in-toto.io/Statement/v1")
        || ![
            "https://compounding.tech/fractal/evidence/gate/v1",
            "https://smalltalk.dev/evidence/gate/v1",
        ]
        .iter()
        .any(|t| get(v, "predicateType").is_some_and(|v| text(v, t)))
        || ![40, 64].contains(&name.len())
        || !hex(name)
        || object(get(subject, "digest")?)?.len() != 1
        || !text(get(get(subject, "digest")?, "gitTree")?, tree)
        || !schema_one
        || !nonblank(string(get(p, "change_id")?)?)
        || !["full", "degraded", "test"]
            .iter()
            .any(|t| get(p, "tier").is_some_and(|v| text(v, t)))
        || !matches!(get(p, "signer")?, Node::Null | Node::String(_))
        || !text(get(observed, "kind")?, "tests")
        || string(get(observed, "runner")?).is_none()
        || !zoned_time(string(get(p, "observed_at")?)?)
    {
        return None;
    }
    if let Some(inputs) = get(observed, "inputs") {
        for (key, value) in object(inputs)? {
            if !nonblank(key) || !nonblank(string(doc.node(*value))?) {
                return None;
            }
        }
    }
    for (name, check) in object(get(observed, "checks")?)? {
        let check = doc.node(*check);
        let command = array(get(check, "command")?)?;
        let hash = string(get(check, "output_sha256")?)?;
        if !nonblank(name)
            || command.is_empty()
            || !command.iter().all(|id| string(doc.node(*id)).is_some())
            || !matches!(get(check, "exit_code")?, Node::Integer(_))
            || hash.len() != 64
            || !hex(hash)
        {
            return None;
        }
    }
    Some(())
}
#[cfg(test)]
#[path = "statement_tests.rs"]
mod tests;
