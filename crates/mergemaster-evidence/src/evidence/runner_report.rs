//! Read-only summaries of the local runner's version-one JSONL records.
use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use indexmap::IndexMap;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fmt::Write, path::PathBuf};

#[derive(clap::Args)]
#[command(disable_help_flag = true)]
pub struct RunnerReportArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<String>,
}

pub fn run(args: RunnerReportArgs) -> anyhow::Result<()> {
    let (code, stdout, stderr) = run_at(&args.argv, Utc::now());
    if !stdout.is_empty() {
        crate::cli_println!("{}", stdout.trim_end_matches('\n'));
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn time(text: &str) -> Option<DateTime<Utc>> {
    use super::legacy_verify::statement::zoned_time_micros;
    let mut points: Vec<_> = text.chars().map(u32::from).collect();
    if let Some(micros) = zoned_time_micros(&points) {
        return DateTime::from_timestamp_micros(micros);
    }
    let length = points.len();
    points.extend("+00:00".chars().map(u32::from));
    if let Some(micros) = zoned_time_micros(&points) {
        return DateTime::from_timestamp_micros(micros);
    }
    points.truncate(length);
    points.extend("T00:00:00+00:00".chars().map(u32::from));
    DateTime::from_timestamp_micros(zoned_time_micros(&points)?)
}
fn iso(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn rank(sorted: &[&Value], share: f64) -> Value {
    sorted
        .get(((share * sorted.len() as f64).ceil() as usize).saturating_sub(1))
        .map_or(Value::Null, |v| (*v).clone())
}
fn ordered(values: &[Value]) -> Vec<&Value> {
    let mut sorted: Vec<_> = values.iter().collect();
    sorted.sort_by(|a, b| compare_numbers(a, b));
    sorted
}
fn compare_numbers(a: &Value, b: &Value) -> std::cmp::Ordering {
    match (number(a), number(b)) {
        (Some(a), Some(b)) => a.total_cmp(&b),
        (a, b) => a.is_some().cmp(&b.is_some()),
    }
}
fn report_error(error: impl std::fmt::Display) -> (i32, String, String) {
    (1, String::new(), format!("fractal-test-report: {error}\n"))
}
pub fn percentile(values: &[Value], share: f64) -> Value {
    rank(&ordered(values), share)
}
fn summary(values: &[Value]) -> Value {
    let sorted = ordered(values);
    json!({"count":values.len(), "p50_s":rank(&sorted,0.5), "p90_s":rank(&sorted,0.9), "max_s":sorted.last().copied()})
}
fn truth(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}
fn number(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_bool().map(|b| if b { 1.0 } else { 0.0 }))
}
fn numeric(v: &Value) -> Value {
    if let Some(b) = v.as_bool() {
        json!(if b { 1 } else { 0 })
    } else {
        v.clone()
    }
}
fn pystr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        _ => v.to_string(),
    }
}
const WAITS: [(&str, &str); 3] = [
    ("tree_wait_s", "pool tree"),
    ("tree_slot_wait_s", "build slot, tree free"),
    ("burst_wait_s", "lane burst"),
];

/// Explicit clock boundary keeps frozen observations independent of wall-clock time.
pub fn run_at(argv: &[String], until: DateTime<Utc>) -> (i32, String, String) {
    let super::runner_report_args::Options {
        hours,
        slo,
        max,
        since,
        markdown,
        mut files,
    } = match super::runner_report_args::parse(argv) {
        Ok(options) => options,
        Err(exit) => return exit,
    };
    if !hours.is_finite() || hours <= 0.0 || slo <= 0 || max <= 0 {
        return (
            2,
            String::new(),
            "--hours, --slo-s and --max-s must be positive\n".into(),
        );
    }
    let since = if let Some(text) = since {
        match time(&text) {
            Some(v) => v,
            None => return (2, String::new(), "bad --since\n".into()),
        }
    } else {
        let Some(duration) = Duration::try_milliseconds((hours * 3_600_000.0).round() as i64)
        else {
            return (2, String::new(), "bad --hours\n".into());
        };
        let Some(value) = until.checked_sub_signed(duration) else {
            return (2, String::new(), "bad --hours\n".into());
        };
        value
    };
    if files.is_empty() {
        let explicit = std::env::var_os("ST_TEST_RUNS").filter(|v| !v.is_empty() && v != "off");
        files.push(explicit.map(PathBuf::from).unwrap_or_else(|| {
            let state = std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| {
                    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/state")
                });
            state.join("st-test/runs.jsonl")
        }));
    }
    let mut unreadable = 0;
    let mut window = Vec::new();
    for path in files {
        let bytes = match std::fs::read(&path) {
            Ok(v) => v,
            Err(e) => {
                let message = e.to_string();
                let message = message.split(" (os error ").next().unwrap_or(&message);
                let errno = e
                    .raw_os_error()
                    .map_or(String::new(), |n| format!("[Errno {n}] "));
                return (
                    1,
                    String::new(),
                    format!(
                        "fractal-test-report: cannot read the runs: {errno}{message}: '{}'\n",
                        path.display()
                    ),
                );
            }
        };
        for line in String::from_utf8_lossy(&bytes)
            .lines()
            .filter(|s| !s.trim().is_empty())
        {
            let value = serde_json::from_str::<Value>(line).ok();
            let valid = value.as_ref().filter(|v| {
                v.is_object()
                    && number(&v["v"]) == Some(1.0)
                    && (v["total_s"].is_i64() || v["total_s"].is_u64() || v["total_s"].is_boolean())
            });
            let ended = valid.and_then(|v| v["ended"].as_str()).and_then(time);
            match (value, ended) {
                (Some(v), Some(t)) => {
                    if since <= t && t <= until {
                        window.push((t, v));
                    }
                }
                _ => unreadable += 1,
            }
        }
    }
    let mut excluded = json!({"not_full":0,"cold":0,"partial":0,"failed":0,"candidate":0});
    let mut counted = Vec::new();
    for (ended, record) in &window {
        let reason = if truth(&record["candidate"]) {
            Some("candidate")
        } else if record["full"] != true {
            Some("not_full")
        } else if record["warm"] != true {
            Some("cold")
        } else if number(&record["exit"]) == Some(4.0) {
            Some("partial")
        } else if number(&record["exit"]) != Some(0.0) {
            Some("failed")
        } else {
            None
        };
        if let Some(reason) = reason {
            let Some(count) = excluded[reason].as_u64() else {
                return report_error("invalid exclusion counter");
            };
            excluded[reason] = json!(count + 1);
        } else {
            counted.push((ended, record));
        }
    }
    counted.sort_by_key(|(ended, _)| *ended);
    let totals: Vec<_> = counted
        .iter()
        .map(|(_, r)| numeric(&r["total_s"]))
        .collect();
    let mut reasons = Vec::new();
    let mut result =
        json!({"window":{"since":iso(since),"until":iso(until)},"slo_s":slo,"max_allowed_s":max});
    let overall = summary(&totals);
    let Some(overall) = overall.as_object() else {
        return report_error("invalid overall summary");
    };
    for (key, value) in overall {
        result[key] = value.clone();
    }
    if number(&result["p90_s"]).is_some_and(|v| v > slo as f64) {
        reasons.push(format!(
            "p90 {}s is over the {slo}s objective",
            result["p90_s"]
        ));
    }
    let over: Vec<_> = totals
        .iter()
        .filter(|v| number(v).is_some_and(|n| n > max as f64))
        .cloned()
        .collect();
    if !over.is_empty() {
        reasons.push(format!(
            "{} full warm run(s) over {max}s (slowest {}s)",
            over.len(),
            percentile(&over, 1.0)
        ));
    }
    let within = totals
        .iter()
        .filter(|v| number(v).is_some_and(|n| n <= slo as f64))
        .count();
    result["within_slo"] = if totals.is_empty() {
        Value::Null
    } else {
        json!(super::pyfloat::python_round(
            within as f64 / totals.len() as f64,
            3
        ))
    };
    result["breach"] = json!(!reasons.is_empty());
    result["breach_reasons"] = json!(reasons);
    result["excluded"] = excluded;
    result["unreadable"] = json!(unreadable);
    let mut hosts: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut spent: IndexMap<(String, String), Vec<Value>> = IndexMap::new();
    for (_, record) in &counted {
        hosts
            .entry(pystr(&record["host"]))
            .or_default()
            .push(numeric(&record["total_s"]));
        let stages = record["stages"].as_array().filter(|v| !v.is_empty());
        let (kind, rows) = if let Some(rows) = stages {
            ("stage", Some(rows))
        } else {
            ("check", record["rows"].as_array())
        };
        for row in rows.into_iter().flatten() {
            if let (Some(name), Some(_)) = (row["name"].as_str(), number(&row["seconds"])) {
                spent
                    .entry((kind.into(), name.into()))
                    .or_default()
                    .push(numeric(&row["seconds"]));
            }
        }
    }
    result["by_host"] = Value::Object(hosts.into_iter().map(|(k, v)| (k, summary(&v))).collect());
    result["waits"] = json!({});
    for (key, label) in WAITS {
        let values: Vec<_> = window
            .iter()
            .filter(|(_, r)| number(&r[key]).is_some())
            .map(|(_, r)| numeric(&r[key]))
            .collect();
        if !values.is_empty() {
            result["waits"][label] = summary(&values);
        }
    }
    let mut slowest = Vec::with_capacity(spent.len());
    for ((kind, name), values) in spent {
        let Some(total) = values.iter().map(number).sum::<Option<f64>>() else {
            return report_error("invalid stage duration");
        };
        slowest.push(json!({
            "name": name, "kind": kind, "count": values.len(),
            "mean_s": super::pyfloat::python_round(total / values.len() as f64, 1),
            "p90_s": percentile(&values, 0.9)
        }));
    }
    slowest.sort_by(|a, b| {
        compare_numbers(&b["mean_s"], &a["mean_s"])
            .then_with(|| a["name"].as_str().cmp(&b["name"].as_str()))
    });
    slowest.truncate(5);
    result["slowest"] = json!(slowest);
    result["candidates"]=json!(window.iter().filter(|(_,r)|truth(&r["candidate"])).map(|(_,r)|json!({"head":r["candidate"],"ended":r["ended"],"total_s":r["total_s"],"exit":r["exit"]})).collect::<Vec<_>>());
    result["runs"]=json!(counted.iter().map(|(_,r)|json!({"ended":r["ended"],"host":r["host"],"total_s":r["total_s"],"tree":r["tree"]})).collect::<Vec<_>>());
    let output = if markdown {
        render_markdown(&result)
    } else {
        let mut out = String::new();
        pretty(&result, 0, &mut out)
            .map(|()| out)
            .map_err(anyhow::Error::from)
    };
    match output {
        Ok(output) => (0, format!("{output}\n"), String::new()),
        Err(error) => report_error(error),
    }
}
fn pretty(value: &Value, depth: usize, out: &mut String) -> std::fmt::Result {
    match value {
        Value::String(text) => super::legacy_json::string(text, out)?,
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                out.push('\n');
                out.extend(std::iter::repeat_n(' ', (depth + 1) * 2));
                pretty(item, depth + 1, out)?;
            }
            if !items.is_empty() {
                out.push('\n');
                out.extend(std::iter::repeat_n(' ', depth * 2));
            }
            out.push(']');
        }
        Value::Object(items) => {
            out.push('{');
            for (index, (key, item)) in items.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                out.push('\n');
                out.extend(std::iter::repeat_n(' ', (depth + 1) * 2));
                super::legacy_json::string(key, out)?;
                out.push_str(": ");
                pretty(item, depth + 1, out)?;
            }
            if !items.is_empty() {
                out.push('\n');
                out.extend(std::iter::repeat_n(' ', depth * 2));
            }
            out.push('}');
        }
        _ => write!(out, "{value}")?,
    }
    Ok(())
}

fn seconds(v: &Value) -> String {
    if v.is_null() {
        "-".into()
    } else {
        format!("{v}s")
    }
}
fn render_markdown(r: &Value) -> anyhow::Result<String> {
    let excluded = r["excluded"]
        .as_object()
        .context("invalid exclusions")?
        .iter()
        .filter(|(_, v)| v.as_u64() != Some(0))
        .map(|(k, v)| format!("{v} {k}"))
        .collect::<Vec<_>>()
        .join(", ");
    let share = number(&r["within_slo"]).map_or("-".into(), |v| format!("{:.0}%", v * 100.0));
    let unreadable = if r["unreadable"] != 0 {
        format!("; {} unreadable lines", r["unreadable"])
    } else {
        String::new()
    };
    let mut out = format!(
        "**fractal-test full warm runs**, {} .. {}: {} counted (left out: {}{unreadable})\n\nObjective: p90 at most {}s, no run over {}s; {share} of runs within {}s.\n\n| runs | count | p50 | p90 | max |\n|---|---:|---:|---:|---:|",
        r["window"]["since"]
            .as_str()
            .context("invalid window start")?,
        r["window"]["until"]
            .as_str()
            .context("invalid window end")?,
        r["count"],
        if excluded.is_empty() {
            "none"
        } else {
            &excluded
        },
        r["slo_s"],
        r["max_allowed_s"],
        r["slo_s"]
    );
    let row = |out: &mut String, label: &str, v: &Value| -> std::fmt::Result {
        write!(
            out,
            "\n| {label} | {} | {} | {} | {} |",
            v["count"],
            seconds(&v["p50_s"]),
            seconds(&v["p90_s"]),
            seconds(&v["max_s"])
        )
    };
    row(&mut out, "all", r)?;
    for (host, v) in r["by_host"].as_object().context("invalid host summaries")? {
        row(&mut out, host, v)?;
    }
    let waits = r["waits"].as_object().context("invalid wait summaries")?;
    if !waits.is_empty() {
        out.push_str("\n\n| waited for (every run in the window) | runs | p50 | p90 | max |\n|---|---:|---:|---:|---:|");
        for (label, v) in waits {
            row(&mut out, label, v)?;
        }
    }
    let candidates = r["candidates"].as_array().context("invalid candidates")?;
    if !candidates.is_empty() {
        out.push_str("\n\nCandidate measurements (excluded from SLO figures):");
        for v in candidates {
            write!(
                out,
                "\n- {}: {}s, exit {}, ended {}",
                pystr(&v["head"]),
                v["total_s"],
                pystr(&v["exit"]),
                pystr(&v["ended"])
            )?;
        }
    }
    let slowest = r["slowest"]
        .as_array()
        .context("invalid slowest durations")?;
    if !slowest.is_empty() {
        out.push_str("\n\n| slowest stage or check | mean | p90 |\n|---|---:|---:|");
        for v in slowest {
            write!(
                out,
                "\n| {} ({}) | {:.1}s | {} |",
                pystr(&v["name"]),
                pystr(&v["kind"]),
                number(&v["mean_s"]).context("invalid mean duration")?,
                seconds(&v["p90_s"])
            )?;
        }
    }
    out.push_str("\n\n");
    if r["breach"] == true {
        out.push_str("**Breach**: ");
        for (index, reason) in r["breach_reasons"]
            .as_array()
            .context("invalid breach reasons")?
            .iter()
            .enumerate()
        {
            if index != 0 {
                out.push_str("; ");
            }
            out.push_str(reason.as_str().context("invalid breach reason")?);
        }
    } else {
        out.push_str(if r["count"] == 0 {
            "No full warm run in the window: nothing to judge."
        } else {
            "**Within the objective.**"
        });
    }
    Ok(out)
}
