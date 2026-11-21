//! Lossless operator-owned policy input; only the requested flip is rewritten.
use super::*;
use crate::evidence::{
    flip_skip_python::{node_json, node_str},
    legacy_verify::statement_document::{Document, Node},
};
use std::fmt::Write;

fn parse(text: &str) -> Result<Document> {
    Document::from_text(text).map_err(|error| anyhow!("{POLICY}: {error:?}"))
}
fn object(node: &Node) -> Result<&indexmap::IndexMap<Vec<u32>, usize>> {
    match node {
        Node::Object(value) => Ok(value),
        _ => bail!("{POLICY}: expected an object"),
    }
}
fn named(key: &[u32], name: &str) -> bool {
    key.iter().copied().eq(name.chars().map(u32::from))
}
fn get<'a>(document: &'a Document, node: &Node, key: &str) -> Option<&'a Node> {
    let Node::Object(entries) = node else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| named(name, key))
        .map(|(_, id)| document.node(*id))
}
fn scalar(points: &[u32]) -> Result<String> {
    points
        .iter()
        .map(|point| {
            char::from_u32(*point)
                .ok_or_else(|| anyhow!("{POLICY}: a check name contains a lone surrogate"))
        })
        .collect()
}
fn member(out: &mut String, count: &mut usize, depth: usize, key: &[u32]) -> Result<()> {
    if *count != 0 {
        out.push(',');
    }
    write!(out, "\n{:width$}", "", width = (depth + 1) * 2)?;
    crate::evidence::legacy_json::codepoints(key.iter().copied(), out)?;
    out.push_str(": ");
    *count += 1;
    Ok(())
}
fn close(out: &mut String, count: usize, depth: usize) -> Result<()> {
    if count != 0 {
        write!(out, "\n{:width$}", "", width = depth * 2)?;
    }
    out.push('}');
    Ok(())
}
fn replace(
    document: &Document,
    node: &Node,
    name: &str,
    replacement: &str,
    depth: usize,
) -> Result<String> {
    let mut out = String::from("{");
    let mut count = 0;
    for (key, id) in object(node)? {
        member(&mut out, &mut count, depth, key)?;
        if named(key, name) {
            out.push_str(replacement);
        } else {
            node_json(document, document.node(*id), depth + 1, &mut out)?;
        }
    }
    close(&mut out, count, depth)?;
    Ok(out)
}
fn narrowed_kinds(document: &Document, entry: &Node, depth: usize) -> Result<String> {
    let invalid =
        || anyhow!("{POLICY}: the wrapper kind does not already trust host, agent, queue");
    let kinds = get(document, entry, "kinds").ok_or_else(invalid)?;
    let wrapper = get(document, kinds, "wrapper").ok_or_else(invalid)?;
    let levels = get(document, wrapper, "trust_levels").ok_or_else(invalid)?;
    if let Node::Array(ids) = levels {
        ensure!(
            ids.iter()
                .all(|id| !matches!(document.node(*id), Node::Array(_) | Node::Object(_))),
            "{POLICY}: trust_levels contains an unhashable value"
        );
    }
    let names: Vec<&[u32]> = match levels {
        Node::Array(ids) => ids
            .iter()
            .filter_map(|id| match document.node(*id) {
                Node::String(value) => Some(value.as_slice()),
                _ => None,
            })
            .collect(),
        Node::Object(values) => values.keys().map(Vec::as_slice).collect(),
        _ => return Err(invalid()),
    };
    ensure!(
        ["host", "agent", "queue"]
            .iter()
            .all(|level| names.iter().any(|name| named(name, level))),
        "{POLICY}: the wrapper kind does not already trust host, agent, queue"
    );
    let mut narrowed = String::from("[");
    let mut count = 0;
    for name in names.into_iter().filter(|name| {
        ["host", "agent", "queue"]
            .iter()
            .any(|level| named(name, level))
    }) {
        if count != 0 {
            narrowed.push(',');
        }
        write!(narrowed, "\n{:width$}", "", width = (depth + 3) * 2)?;
        crate::evidence::legacy_json::codepoints(name.iter().copied(), &mut narrowed)?;
        count += 1;
    }
    if count != 0 {
        write!(narrowed, "\n{:width$}", "", width = (depth + 2) * 2)?;
    }
    narrowed.push(']');
    let wrapper = replace(document, wrapper, "trust_levels", &narrowed, depth + 1)?;
    replace(document, kinds, "wrapper", &wrapper, depth)
}
fn flipped_entry(document: &Document, entry: &Node, lowered: bool, depth: usize) -> Result<String> {
    let entries = object(entry)?;
    let kinds = lowered
        .then(|| narrowed_kinds(document, entry, depth + 1))
        .transpose()?;
    let mut out = String::from("{");
    let mut count = 0;
    let mut events = false;
    let mut sample = false;
    for (key, id) in entries {
        if (named(key, "events") && events) || (named(key, "sample_one_in") && sample) {
            continue;
        }
        member(&mut out, &mut count, depth, key)?;
        if named(key, "enforce") {
            out.push_str("true");
            if !events {
                member(
                    &mut out,
                    &mut count,
                    depth,
                    &"events".chars().map(u32::from).collect::<Vec<_>>(),
                )?;
                if let Some(value) = get(document, entry, "events") {
                    node_json(document, value, depth + 1, &mut out)?;
                } else {
                    write!(
                        out,
                        "[\n{:width$}\"pull_request\"\n{:close$}]",
                        "",
                        "",
                        width = (depth + 2) * 2,
                        close = (depth + 1) * 2
                    )?;
                }
                events = true;
            }
            if !sample {
                member(
                    &mut out,
                    &mut count,
                    depth,
                    &"sample_one_in".chars().map(u32::from).collect::<Vec<_>>(),
                )?;
                out.push('1');
                sample = true;
            }
        } else if named(key, "sample_one_in") {
            out.push('1');
            sample = true;
        } else if named(key, "kinds")
            && let Some(kinds) = &kinds
        {
            out.push_str(kinds);
        } else {
            node_json(document, document.node(*id), depth + 1, &mut out)?;
            events |= named(key, "events");
        }
    }
    close(&mut out, count, depth)?;
    Ok(out)
}

fn equivalent(left: &Document, a: &Node, right: &Document, b: &Node) -> bool {
    match (a, b) {
        (Node::Null, Node::Null) => true,
        (Node::Bool(a), Node::Bool(b)) => a == b,
        (Node::Integer(a), Node::Integer(b)) => {
            a == b || (a == "-0" && b == "0") || (a == "0" && b == "-0")
        }
        (Node::Float(a), Node::Float(b)) => a == b || (a.is_nan() && b.is_nan()),
        (Node::String(a), Node::String(b)) => a == b,
        (Node::Array(a), Node::Array(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|(a, b)| equivalent(left, left.node(*a), right, right.node(*b)))
        }
        (Node::Object(a), Node::Object(b)) => {
            a.len() == b.len()
                && a.iter().all(|(key, a)| {
                    b.get(key)
                        .is_some_and(|b| equivalent(left, left.node(*a), right, right.node(*b)))
                })
        }
        _ => false,
    }
}

pub(super) fn flip_policy(text: &str, check: &str) -> Result<(String, String)> {
    let document = parse(text)?;
    let checks = get(&document, document.root(), "checks")
        .ok_or_else(|| anyhow!("{POLICY}: missing checks"))?;
    let entry = get(&document, checks, check)
        .ok_or_else(|| anyhow!("{POLICY}: {check} has no \"enforce\": false"))?;
    ensure!(
        matches!(get(&document, entry, "enforce"), Some(Node::Bool(false))),
        "{POLICY}: {check} has no \"enforce\": false"
    );
    let expected_entry = flipped_entry(&document, entry, check == "rust-tests", 2)?;
    let expected_checks = replace(&document, checks, check, &expected_entry, 1)?;
    let mut expected = replace(&document, document.root(), "checks", &expected_checks, 0)?;
    expected.push('\n');
    let mut original = String::new();
    node_json(&document, document.root(), 0, &mut original)?;
    original.push('\n');
    if original == text {
        return Ok((expected, expected_entry));
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let block = lines
        .iter()
        .position(|line| line.trim_start() == format!("\"{check}\": {{\n"))
        .ok_or_else(|| anyhow!("{POLICY}: cannot find the enforce line of {check}"))?;
    let pad = format!("{}  ", lines[block].split('"').next().unwrap_or(""));
    let enforce = lines
        .iter()
        .enumerate()
        .skip(block + 1)
        .find(|(_, line)| {
            **line == format!("{pad}\"enforce\": false,\n")
                || **line == format!("{pad}\"enforce\": false\n")
        })
        .map(|(i, _)| i)
        .ok_or_else(|| anyhow!("{POLICY}: cannot find the enforce line of {check}"))?;
    ensure!(
        lines[enforce].ends_with(",\n"),
        "{POLICY}: a textual edit of {check} would not give the expected policy"
    );
    let mut output = String::new();
    let mut sample_replaced = false;
    for (index, line) in lines.iter().enumerate() {
        if index == enforce {
            writeln!(output, "{pad}\"enforce\": true,")?;
            if get(&document, entry, "events").is_none() {
                writeln!(output, "{pad}\"events\": [\"pull_request\"],")?;
            }
            if get(&document, entry, "sample_one_in").is_none() {
                writeln!(output, "{pad}\"sample_one_in\": 1,")?;
            }
        } else if index > block
            && !sample_replaced
            && get(&document, entry, "sample_one_in").is_some()
            && line.starts_with(&format!("{pad}\"sample_one_in\": "))
        {
            let numeric = line
                .trim_end_matches('\n')
                .trim_end_matches(',')
                .strip_prefix(&format!("{pad}\"sample_one_in\": "))
                .unwrap_or("");
            ensure!(
                !numeric.is_empty() && numeric.bytes().all(|byte| byte.is_ascii_digit()),
                "{POLICY}: a textual edit of {check} would not give the expected policy"
            );
            let comma = if line.trim_end().ends_with(',') {
                ","
            } else {
                ""
            };
            writeln!(output, "{pad}\"sample_one_in\": 1{comma}")?;
            sample_replaced = true;
        } else {
            output.push_str(line);
        }
    }
    let actual = parse(&output)?;
    let expected = parse(&expected)?;
    ensure!(
        equivalent(&actual, actual.root(), &expected, expected.root()),
        "{POLICY}: a textual edit of {check} would not give the expected policy"
    );
    Ok((output, expected_entry))
}

/// Runtime reads only these fields; unconsumed metadata remains in the Document
/// and is never converted to a bounded JSON number or Unicode scalar string.
pub(super) fn has_check(text: &str, check: &str) -> Result<bool> {
    let document = parse(text)?;
    let checks = get(&document, document.root(), "checks")
        .ok_or_else(|| anyhow!("{POLICY}: missing checks"))?;
    Ok(object(checks)?.keys().any(|name| named(name, check)))
}

fn contains(document: &Document, node: &Node, needle: &str) -> Result<bool> {
    if !truthy(node) {
        return Ok(false);
    }
    match node {
        Node::String(points) => Ok(points.windows(needle.len()).any(|part| named(part, needle))),
        Node::Array(ids) => Ok(ids
            .iter()
            .any(|id| matches!(document.node(*id), Node::String(points) if named(points, needle)))),
        Node::Object(values) => Ok(values.keys().any(|points| named(points, needle))),
        _ => bail!("{POLICY}: required_inputs must be iterable"),
    }
}

pub(super) fn checks(text: &str) -> Result<Map<String, Value>> {
    let document = parse(text)?;
    let checks = get(&document, document.root(), "checks")
        .ok_or_else(|| anyhow!("{POLICY}: missing checks"))?;
    let mut projected = Map::new();
    for (name, id) in object(checks)? {
        let entry = document.node(*id);
        object(entry)?;
        let enforce = matches!(get(&document, entry, "enforce"), Some(Node::Bool(true)));
        let mut value = json!({"enforce":enforce});
        if let Some(kinds) = get(&document, entry, "kinds").filter(|value| truthy(*value)) {
            object(kinds)?;
            if let Some(wrapper) = get(&document, kinds, "wrapper").filter(|value| truthy(*value)) {
                object(wrapper)?;
                let mut body = json!({});
                body["shard_inputs"] =
                    json!(get(&document, wrapper, "shard_inputs").is_some_and(truthy));
                if let Some(command) =
                    get(&document, wrapper, "command").filter(|value| truthy(*value))
                {
                    ensure!(
                        matches!(command, Node::Array(_) | Node::String(_)),
                        "{POLICY}: wrapper command must support slicing"
                    );
                    if let Node::Array(ids) = command {
                        body["command"] = json!(
                            ids.iter()
                                .map(|id| match document.node(*id) {
                                    Node::String(s) if named(s, "aggregate") => "aggregate",
                                    _ => "",
                                })
                                .collect::<Vec<_>>()
                        );
                    }
                }
                if named(name, "fractal-web")
                    && let Some(order) =
                        get(&document, wrapper, "input_order").filter(|value| truthy(*value))
                {
                    object(order)?;
                    let valid = get(&document, order, "kit_inputs").is_some_and(|inputs| match inputs { Node::Array(ids) if ids.len() == 2 => matches!(document.node(ids[0]), Node::String(s) if named(s,"true")) && matches!(document.node(ids[1]), Node::String(s) if named(s,"false")), _ => false });
                    if valid {
                        body["input_order"] = json!({"kit_inputs":["true","false"]});
                    }
                }
                if named(name, "linux-gate")
                    && let Some(levels) =
                        get(&document, wrapper, "by_level").filter(|value| truthy(*value))
                {
                    object(levels)?;
                    for level in ["host", "agent"] {
                        if let Some(rule) =
                            get(&document, levels, level).filter(|value| truthy(*value))
                        {
                            object(rule)?;
                            let contains = get(&document, rule, "required_inputs")
                                .map(|inputs| contains(&document, inputs, "clippy_base_sha"))
                                .transpose()?
                                .unwrap_or(false);
                            if contains {
                                body["by_level"][level] =
                                    json!({"required_inputs":["clippy_base_sha"]});
                            }
                        }
                    }
                }
                value["kinds"] = json!({"wrapper":body});
            }
        }
        projected.insert(scalar(name)?, value);
    }
    Ok(projected)
}

pub(super) fn doc_cells(entry: &str) -> Result<(String, String)> {
    let document = parse(entry)?;
    let events = get(&document, document.root(), "events")
        .ok_or_else(|| anyhow!("{POLICY}: missing events"))?;
    let events = match events {
        Node::Array(ids) => ids
            .iter()
            .map(|id| node_str(&document, document.node(*id)))
            .collect::<std::io::Result<Vec<_>>>()?,
        Node::Object(values) => values
            .keys()
            .map(|points| scalar(points))
            .collect::<Result<Vec<_>>>()?,
        Node::String(points) => points
            .iter()
            .map(|point| scalar(std::slice::from_ref(point)))
            .collect::<Result<Vec<_>>>()?,
        _ => bail!("{POLICY}: events must be iterable"),
    }
    .into_iter()
    .map(|event| format!("`{event}`"))
    .collect::<Vec<_>>()
    .join(", ");
    let sample = get(&document, document.root(), "sample_one_in")
        .ok_or_else(|| anyhow!("{POLICY}: missing sample_one_in"))?;
    Ok((events, node_str(&document, sample)?))
}
