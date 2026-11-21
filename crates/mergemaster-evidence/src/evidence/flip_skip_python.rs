//! Python scalar semantics shared by the flip and skip reports.
use super::legacy_verify::{
    python_repr::Repr,
    statement_document::{Document, Node},
    value_inputs::TextRef,
};
use serde_json::Value;
use std::fmt::Write;

pub(super) trait PythonTruthy {
    fn python_truthy(&self) -> bool;
}
impl PythonTruthy for Value {
    fn python_truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(value) => *value,
            Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
            Value::String(value) => !value.is_empty(),
            Value::Array(value) => !value.is_empty(),
            Value::Object(value) => !value.is_empty(),
        }
    }
}
impl PythonTruthy for Node {
    fn python_truthy(&self) -> bool {
        match self {
            Node::Null => false,
            Node::Bool(value) => *value,
            Node::Integer(value) => value.bytes().any(|byte| matches!(byte, b'1'..=b'9')),
            Node::Float(value) => *value != 0.0,
            Node::String(value) => !value.is_empty(),
            Node::Array(value) => !value.is_empty(),
            Node::Object(value) => !value.is_empty(),
        }
    }
}
pub(super) fn truthy<T: PythonTruthy + ?Sized>(value: &T) -> bool {
    value.python_truthy()
}
/// Fixed precision rounds the exact binary float ties-to-even, like Python round.
pub(super) fn rounded(value: f64, digits: usize) -> f64 {
    format!("{value:.digits$}").parse().unwrap_or(value)
}
/// Python's default :g has six significant digits and a two-digit signed exponent.
pub(super) fn general(value: f64) -> String {
    if !value.is_finite() {
        return float_str(value);
    }
    let scientific = format!("{value:.5e}");
    let Some((mantissa, exponent)) = scientific.split_once('e') else {
        return scientific;
    };
    let exponent = exponent.parse::<i32>().unwrap_or(0);
    if !(-4..6).contains(&exponent) {
        format!(
            "{}e{exponent:+03}",
            mantissa.trim_end_matches('0').trim_end_matches('.')
        )
    } else {
        let digits = (5 - exponent).max(0) as usize;
        let fixed = format!("{value:.digits$}");
        if digits == 0 {
            fixed
        } else {
            fixed.trim_end_matches('0').trim_end_matches('.').to_owned()
        }
    }
}
fn float_str(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf"
        } else {
            "inf"
        }
        .to_owned();
    }
    // Rust's shortest debug representation, with Python's exponent spelling.
    let shortest = format!("{value:?}");
    if let Some((mantissa, exponent)) = shortest.split_once('e') {
        let exponent = exponent.parse::<i32>().unwrap_or(0);
        format!("{mantissa}e{exponent:+03}")
    } else {
        shortest
    }
}
fn quoted(text: TextRef<'_>, out: &mut String) -> std::fmt::Result {
    write!(out, "{}", Repr(text))
}
fn sequence<T>(
    out: &mut String,
    open: char,
    close: char,
    values: impl Iterator<Item = T>,
    mut emit: impl FnMut(T, &mut String) -> std::fmt::Result,
) -> std::fmt::Result {
    out.push(open);
    for (index, value) in values.enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        emit(value, out)?;
    }
    out.push(close);
    Ok(())
}
fn value_repr(value: &Value, nested: bool, out: &mut String) -> std::fmt::Result {
    match value {
        Value::Null => out.push_str("None"),
        Value::Bool(value) => out.push_str(if *value { "True" } else { "False" }),
        Value::Number(value) if value.is_f64() => {
            out.push_str(&float_str(value.as_f64().unwrap_or(0.0)))
        }
        Value::Number(value) => write!(out, "{value}")?,
        Value::String(value) if nested => quoted(TextRef::Str(value), out)?,
        Value::String(value) => out.push_str(value),
        Value::Array(values) => sequence(out, '[', ']', values.iter(), |value, out| {
            value_repr(value, true, out)
        })?,
        Value::Object(values) => sequence(out, '{', '}', values.iter(), |(key, value), out| {
            quoted(TextRef::Str(key), out)?;
            out.push_str(": ");
            value_repr(value, true, out)
        })?,
    }
    Ok(())
}
pub(super) fn value_str(value: &Value) -> String {
    let mut result = String::new();
    // String's fmt::Write sink cannot fail.
    let _ = value_repr(value, false, &mut result);
    result
}
pub(super) fn node_str(document: &Document, node: &Node) -> std::io::Result<String> {
    if let Node::String(points) = node {
        return points
            .iter()
            .copied()
            .map(char::from_u32)
            .collect::<Option<String>>()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UnicodeEncodeError: raw Python string contains a lone surrogate",
                )
            });
    }
    let mut result = String::new();
    // String's fmt::Write sink cannot fail.
    let _ = node_repr(document, node, &mut result);
    Ok(result)
}
fn node_repr(document: &Document, node: &Node, out: &mut String) -> std::fmt::Result {
    match node {
        Node::Null => out.push_str("None"),
        Node::Bool(value) => out.push_str(if *value { "True" } else { "False" }),
        Node::Integer(value) => out.push_str(if value == "-0" { "0" } else { value }),
        Node::Float(value) => out.push_str(&float_str(*value)),
        Node::String(value) => quoted(TextRef::Points(value), out)?,
        Node::Array(values) => sequence(out, '[', ']', values.iter(), |id, out| {
            node_repr(document, document.node(*id), out)
        })?,
        Node::Object(values) => sequence(out, '{', '}', values.iter(), |(key, id), out| {
            quoted(TextRef::Points(key), out)?;
            out.push_str(": ");
            node_repr(document, document.node(*id), out)
        })?,
    }
    Ok(())
}
/// Lossless json.dumps value fragment. String escaping uses the existing encoder.
pub(super) fn node_json(
    document: &Document,
    node: &Node,
    depth: usize,
    out: &mut String,
) -> std::fmt::Result {
    match node {
        Node::Null => out.push_str("null"),
        Node::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Node::Integer(value) => out.push_str(if value == "-0" { "0" } else { value }),
        Node::Float(value) if value.is_nan() => out.push_str("NaN"),
        Node::Float(value) if value.is_infinite() => out.push_str(if value.is_sign_negative() {
            "-Infinity"
        } else {
            "Infinity"
        }),
        Node::Float(value) => out.push_str(&float_str(*value)),
        Node::String(value) => super::legacy_json::codepoints(value.iter().copied(), out)?,
        Node::Array(values) => {
            out.push('[');
            for (index, id) in values.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                write!(out, "\n{:width$}", "", width = (depth + 1) * 2)?;
                node_json(document, document.node(*id), depth + 1, out)?;
            }
            if !values.is_empty() {
                write!(out, "\n{:width$}", "", width = depth * 2)?;
            }
            out.push(']');
        }
        Node::Object(values) => {
            out.push('{');
            for (index, (key, id)) in values.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                write!(out, "\n{:width$}", "", width = (depth + 1) * 2)?;
                super::legacy_json::codepoints(key.iter().copied(), out)?;
                out.push_str(": ");
                node_json(document, document.node(*id), depth + 1, out)?;
            }
            if !values.is_empty() {
                write!(out, "\n{:width$}", "", width = depth * 2)?;
            }
            out.push('}');
        }
    }
    Ok(())
}
/// Python str.splitlines, including CRLF as a single boundary.
pub(super) fn splitlines(mut text: &str) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        if text.is_empty() {
            return None;
        }
        let boundary = text.find([
            '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
            '\u{2029}',
        ]);
        match boundary {
            Some(index) => {
                let (line, rest) = text.split_at(index);
                let length = if rest.starts_with("\r\n") {
                    2
                } else {
                    rest.chars().next().map_or(0, char::len_utf8)
                };
                text = &rest[length..];
                Some(line)
            }
            None => {
                let line = text;
                text = "";
                Some(line)
            }
        }
    })
}
