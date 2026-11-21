//! GitHub is a schema-bound ingress, unlike operator-owned JSON documents.
use super::*;
use crate::evidence::legacy_verify::statement_document::{Document, Node};
use crate::evidence::legacy_verify::{python_repr::Repr, value_inputs::TextRef};

fn named(points: &[u32], name: &str) -> bool {
    points.iter().copied().eq(name.chars().map(u32::from))
}
fn any_name(points: &[u32], names: &[&str]) -> bool {
    names.iter().any(|name| named(points, name))
}

pub(in crate::evidence) fn parse_api(text: &str) -> Result<Value> {
    let document = Document::from_text(text)
        .map_err(|error| anyhow!("GitHub API JSON outside schema: {error:?}"))?;
    let mut pending = vec![(document.root(), &[][..])];
    while let Some((node, field)) = pending.pop() {
        match node {
            Node::Integer(value) => {
                ensure!(
                    value
                        .parse::<i64>()
                        .is_ok_and(|value| value.unsigned_abs() <= 9_007_199_254_740_991),
                    "GitHub API field {} outside schema: integer exceeds exact 53-bit range",
                    Repr(TextRef::Points(field))
                );
            }
            Node::Float(value) => ensure!(
                value.is_finite(),
                "GitHub API field {} outside schema: nonfinite number",
                Repr(TextRef::Points(field))
            ),
            Node::String(points) => ensure!(
                points.iter().all(|point| char::from_u32(*point).is_some()),
                "GitHub API field {} outside schema: lone surrogate",
                Repr(TextRef::Points(field))
            ),
            Node::Array(ids) => pending.extend(ids.iter().map(|id| (document.node(*id), field))),
            Node::Object(entries) => {
                for (key, id) in entries {
                    ensure!(
                        key.iter().all(|point| char::from_u32(*point).is_some()),
                        "GitHub API field outside schema: lone surrogate in key"
                    );
                    let value = document.node(*id);
                    let valid = if any_name(key, &["id", "number", "run_attempt", "total_count"]) {
                        matches!(value, Node::Integer(raw) if !raw.starts_with('-') || raw == "-0")
                    } else if any_name(
                        key,
                        &[
                            "created_at",
                            "status",
                            "name",
                            "login",
                            "head_sha",
                            "filename",
                        ],
                    ) {
                        matches!(value, Node::String(_))
                    } else if any_name(
                        key,
                        &[
                            "conclusion",
                            "head_branch",
                            "sha",
                            "started_at",
                            "completed_at",
                        ],
                    ) {
                        matches!(value, Node::String(_) | Node::Null)
                    } else if any_name(key, &["actor", "base"]) {
                        matches!(value, Node::Object(_) | Node::Null)
                    } else if any_name(key, &["workflow_runs", "jobs", "pull_requests", "labels"]) {
                        matches!(value, Node::Array(_))
                    } else {
                        true
                    };
                    ensure!(
                        valid,
                        "GitHub API field {} outside schema: unexpected JSON type",
                        Repr(TextRef::Points(key))
                    );
                    if any_name(key, &["workflow_runs", "jobs", "pull_requests"])
                        && let Node::Array(ids) = value
                    {
                        ensure!(
                            ids.iter()
                                .all(|id| matches!(document.node(*id), Node::Object(_))),
                            "GitHub API field {} outside schema: expected object items",
                            Repr(TextRef::Points(key))
                        );
                    }
                    if named(key, "labels")
                        && let Node::Array(ids) = value
                    {
                        ensure!(
                            ids.iter()
                                .all(|id| matches!(document.node(*id), Node::String(_))),
                            "GitHub API field labels outside schema: expected string labels"
                        );
                    }
                    pending.push((value, key.as_slice()));
                }
            }
            Node::Null | Node::Bool(_) => {}
        }
    }
    serde_json::from_str(text).context("GitHub API JSON outside schema")
}
