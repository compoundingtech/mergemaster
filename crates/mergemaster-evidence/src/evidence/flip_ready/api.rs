//! Endpoint/object-kind validation of consumed GitHub fields, never global key rules.
use super::*;

#[derive(Clone, Copy)]
pub(in crate::evidence) enum RunUse {
    Flip,
    Skip,
    Release,
}
#[derive(Clone, Copy)]
pub(in crate::evidence) enum JobUse {
    Flip,
    Skip,
    Release,
}

pub(in crate::evidence) fn parse_api(text: &str) -> Result<Value> {
    // Unknown response metadata is not interpreted. Consumed integer fields are
    // checked before use, including integers serde would otherwise narrow to f64.
    serde_json::from_str(text).context("GitHub API JSON outside schema")
}
fn object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| anyhow!("GitHub API {context} outside schema: expected an object"))
}
pub(in crate::evidence) fn number(value: Option<&Value>, context: &str) -> Result<u64> {
    value.and_then(Value::as_u64).filter(|number| *number <= 9_007_199_254_740_991)
        .ok_or_else(|| anyhow!("GitHub API {context} outside schema: expected an integral number in the exact 53-bit range"))
}
pub(in crate::evidence) fn string<'a>(value: Option<&'a Value>, context: &str) -> Result<&'a str> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("GitHub API {context} outside schema: expected a string"))
}
fn optional_text(value: &Value, key: &str, nullable: bool) -> Result<()> {
    if let Some(field) = value.get(key)
        && !(nullable && field.is_null())
    {
        string(Some(field), key)?;
    }
    Ok(())
}
fn optional_number(value: &Value, key: &str) -> Result<()> {
    if let Some(field) = value.get(key) {
        number(Some(field), key)?;
    }
    Ok(())
}
fn array<'a>(value: &'a Value, key: &str) -> Result<Option<&'a Vec<Value>>> {
    value
        .get(key)
        .filter(|field| !field.is_null())
        .map(|field| {
            field
                .as_array()
                .ok_or_else(|| anyhow!("GitHub API {key} outside schema: expected an array"))
        })
        .transpose()
}
pub(in crate::evidence) fn page(value: &Value, key: &str) -> Result<()> {
    object(value, "paginated page")?;
    if let Some(items) = value.get(key) {
        ensure!(
            items.is_array(),
            "GitHub API {key} outside schema: expected an array"
        );
    }
    Ok(())
}

pub(in crate::evidence) fn listing(value: &Value) -> Result<()> {
    object(value, "run listing")?;
    optional_number(value, "total_count")?;
    if let Some(runs) = array(value, "workflow_runs")? {
        for run in runs {
            object(run, "workflow run")?;
            optional_text(run, "created_at", true)?;
        }
    }
    Ok(())
}
pub(in crate::evidence) fn run(value: &Value, usage: RunUse) -> Result<()> {
    object(value, "workflow run")?;
    optional_text(value, "status", true)?;
    if let Some(actor) = value.get("actor").filter(|actor| !actor.is_null()) {
        object(actor, "run actor")?;
        optional_text(actor, "login", false)?;
    }
    if matches!(usage, RunUse::Flip) {
        optional_text(value, "conclusion", true)?;
    }
    if matches!(usage, RunUse::Skip) {
        optional_text(value, "head_branch", true)?;
    }
    if let Some(pulls) = array(value, "pull_requests")? {
        let consumed = if matches!(usage, RunUse::Release) {
            pulls.len()
        } else {
            1
        };
        for pull in pulls.iter().take(consumed) {
            object(pull, "run pull request")?;
            if matches!(usage, RunUse::Flip) {
                if let Some(base) = pull.get("base").filter(|base| !base.is_null()) {
                    object(base, "pull request base")?;
                    optional_text(base, "sha", true)?;
                }
            } else {
                optional_number(pull, "number")?;
            }
        }
    }
    Ok(())
}
pub(in crate::evidence) fn job(value: &Value, usage: JobUse) -> Result<()> {
    object(value, "job")?;
    optional_text(value, "conclusion", true)?;
    if matches!(usage, JobUse::Release) {
        optional_text(value, "started_at", true)?;
        optional_text(value, "completed_at", true)?;
        if let Some(labels) = array(value, "labels")? {
            for label in labels {
                string(Some(label), "release job label")?;
            }
        }
    } else {
        optional_text(value, "name", true)?;
        optional_text(value, "status", true)?;
        if matches!(usage, JobUse::Flip) {
            optional_number(value, "run_attempt")?;
        }
    }
    Ok(())
}
pub(in crate::evidence) fn first_pull(value: &Value) -> Result<Option<u64>> {
    let pulls = value
        .as_array()
        .ok_or_else(|| anyhow!("GitHub API pull requests outside schema: expected an array"))?;
    pulls
        .first()
        .map(|pull| {
            object(pull, "first pull request")?;
            number(pull.get("number"), "first pull request number")
        })
        .transpose()
}
