//! Read-only summaries of the local runner's version-one JSONL records.
use super::{
    legacy_verify::statement_document::{Document, Node},
    runner_report_numbers as numbers,
    runner_report_value::{Input, Output, scalar_text},
};
use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use indexmap::IndexMap;
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
    time_points(&text.chars().map(u32::from).collect::<Vec<_>>())
}
fn time_points(points: &[u32]) -> Option<DateTime<Utc>> {
    use super::legacy_verify::statement::zoned_time_micros;
    if let Some(micros) = zoned_time_micros(points) {
        return DateTime::from_timestamp_micros(micros);
    }
    let mut points = points.to_vec();
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
fn report_error(error: impl std::fmt::Display) -> (i32, String, String) {
    (1, String::new(), format!("fractal-test-report: {error}\n"))
}
fn rank_index(count: usize, share: f64) -> usize {
    ((share * count as f64).ceil() as usize).saturating_sub(1)
}
/// Nearest-rank percentile over Python numeric nodes, preserving exact integers.
pub fn percentile<'a>(values: &[&'a Node], share: f64) -> Option<&'a Node> {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| numbers::compare(a, b).unwrap_or(std::cmp::Ordering::Equal));
    sorted.get(rank_index(sorted.len(), share)).copied()
}
#[derive(Clone, Copy)]
struct Summary<'a> {
    count: usize,
    p50: Option<Input<'a>>,
    p90: Option<Input<'a>>,
    max: Option<Input<'a>>,
}
impl<'a> Summary<'a> {
    fn new(values: &[Input<'a>]) -> Self {
        let mut sorted = values.to_vec();
        sorted
            .sort_by(|a, b| numbers::compare(a.node, b.node).unwrap_or(std::cmp::Ordering::Equal));
        let mut max = values.first().copied();
        for value in values.iter().skip(1) {
            if max.is_some_and(|previous| {
                numbers::compare(value.node, previous.node) == Some(std::cmp::Ordering::Greater)
            }) {
                max = Some(*value);
            }
        }
        Self {
            count: values.len(),
            p50: sorted.get(rank_index(sorted.len(), 0.5)).copied(),
            p90: sorted.get(rank_index(sorted.len(), 0.9)).copied(),
            max,
        }
    }
    fn output(self) -> Output<'a> {
        Output::object([
            ("count", Output::Integer(self.count as i128)),
            ("p50_s", raw(self.p50)),
            ("p90_s", raw(self.p90)),
            ("max_s", raw(self.max)),
        ])
    }
}
fn raw<'a>(value: Option<Input<'a>>) -> Output<'a> {
    value.map_or(Output::Null, Output::Raw)
}
const WAITS: [(&str, &str); 3] = [
    ("tree_wait_s", "pool tree"),
    ("tree_slot_wait_s", "build slot, tree free"),
    ("burst_wait_s", "lane burst"),
];
const EXCLUDED: [&str; 5] = ["not_full", "cold", "partial", "failed", "candidate"];

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
    let one = Node::Integer("1".into());
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
        // The producer writes UTF-8 text. Match read_text(errors='replace') before
        // invoking the existing Python JSON parser; byte-encoding detection is not used.
        for line in crate::parity_drift::splitlines(&String::from_utf8_lossy(&bytes))
            .filter(|s| !s.chars().all(super::legacy_verify::projection_oid::space))
        {
            let document = Document::from_text_with_depth_limit(line, None).ok();
            let ended = document.as_ref().and_then(|document| {
                let record = Input::root(document);
                if !matches!(record.node, Node::Object(_))
                    || numbers::compare(record.field("v").node, &one)
                        != Some(std::cmp::Ordering::Equal)
                    || !matches!(
                        record.field("total_s").node,
                        Node::Integer(_) | Node::Bool(_)
                    )
                {
                    return None;
                }
                time_points(record.field("ended").points()?)
            });
            match (document, ended) {
                (Some(document), Some(ended)) => {
                    if since <= ended && ended <= until {
                        window.push((ended, document));
                    }
                }
                _ => unreadable += 1,
            }
        }
    }
    match report(&window, since, until, slo, max, unreadable, markdown) {
        Ok(out) => (0, format!("{out}\n"), String::new()),
        Err(error) => report_error(error),
    }
}
fn report(
    window: &[(DateTime<Utc>, Document)],
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    slo: i64,
    max: i64,
    unreadable: usize,
    markdown: bool,
) -> anyhow::Result<String> {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let zero = Node::Integer("0".into());
    let partial = Node::Integer("4".into());
    let slo_number = Node::Integer(slo.to_string());
    let max_number = Node::Integer(max.to_string());
    let mut excluded = [0usize; 5];
    let mut counted = Vec::new();
    for (ended, document) in window {
        let record = Input::root(document);
        let reason = if record.field("candidate").truth() {
            Some(4)
        } else if !matches!(record.field("full").node, Node::Bool(true)) {
            Some(0)
        } else if !matches!(record.field("warm").node, Node::Bool(true)) {
            Some(1)
        } else if numbers::compare(record.field("exit").node, &partial) == Some(Equal) {
            Some(2)
        } else if numbers::compare(record.field("exit").node, &zero) != Some(Equal) {
            Some(3)
        } else {
            None
        };
        if let Some(reason) = reason {
            excluded[reason] += 1;
        } else {
            counted.push((ended, record));
        }
    }
    counted.sort_by_key(|(ended, _)| *ended);
    let totals: Vec<_> = counted.iter().map(|(_, r)| r.field("total_s")).collect();
    let overall = Summary::new(&totals);
    let mut reasons = Vec::new();
    if overall
        .p90
        .is_some_and(|v| numbers::compare(v.node, &slo_number) == Some(Greater))
    {
        reasons.push(format!(
            "p90 {}s is over the {slo}s objective",
            Output::Raw(overall.p90.context("missing p90")?).scalar()?
        ));
    }
    let over: Vec<_> = totals
        .iter()
        .copied()
        .filter(|v| numbers::compare(v.node, &max_number) == Some(Greater))
        .collect();
    if !over.is_empty() {
        reasons.push(format!(
            "{} full warm run(s) over {max}s (slowest {}s)",
            over.len(),
            Output::Raw(Summary::new(&over).max.context("missing maximum")?).scalar()?
        ));
    }
    let within = totals
        .iter()
        .filter(|v| matches!(numbers::compare(v.node, &slo_number), Some(Less | Equal)))
        .count();
    let within_slo = if totals.is_empty() {
        Output::Null
    } else {
        Output::Float(super::pyfloat::python_round(
            within as f64 / totals.len() as f64,
            3,
        ))
    };
    let mut hosts: BTreeMap<std::borrow::Cow<'_, [u32]>, Vec<Input<'_>>> = BTreeMap::new();
    let mut spent: IndexMap<(&str, &[u32]), Vec<Input<'_>>> = IndexMap::new();
    for (_, record) in &counted {
        hosts
            .entry(record.field("host").text()?)
            .or_default()
            .push(record.field("total_s"));
        let stages = record.field("stages");
        let (kind, parts) = if stages.truth() {
            ("stage", stages)
        } else {
            ("check", record.field("rows"))
        };
        for part in parts.array() {
            if matches!(part.node, Node::Object(_))
                && let Some(name) = part.field("name").points()
            {
                let seconds = part.field("seconds");
                if seconds.numeric() {
                    spent.entry((kind, name)).or_default().push(seconds);
                }
            }
        }
    }
    let by_host = Output::Object(
        hosts
            .into_iter()
            .map(|(host, values)| (host, Summary::new(&values).output()))
            .collect(),
    );
    let mut waits = Vec::new();
    for (key, label) in WAITS {
        let values: Vec<_> = window
            .iter()
            .map(|(_, document)| Input::root(document).field(key))
            .filter(|v| v.numeric())
            .collect();
        if !values.is_empty() {
            waits.push((
                std::borrow::Cow::Owned(label.chars().map(u32::from).collect()),
                Summary::new(&values).output(),
            ));
        }
    }
    let mut slowest = Vec::with_capacity(spent.len());
    for ((kind, name), values) in spent {
        let mean = super::pyfloat::python_round(numbers::mean(values.iter().map(|v| v.node))?, 1);
        let summary = Summary::new(&values);
        slowest.push((
            mean,
            name,
            Output::object([
                ("name", Output::Text(std::borrow::Cow::Borrowed(name))),
                ("kind", Output::text(kind)),
                ("count", Output::Integer(values.len() as i128)),
                ("mean_s", Output::Float(mean)),
                ("p90_s", raw(summary.p90)),
            ]),
        ));
    }
    slowest.sort_by(|a, b| {
        let order = b.0.partial_cmp(&a.0).unwrap_or(Equal);
        if order == Equal && a.0 == b.0 {
            a.1.cmp(b.1)
        } else {
            order
        }
    });
    slowest.truncate(5);
    let breach = !reasons.is_empty();
    let result = Output::object([
        (
            "window",
            Output::object([
                ("since", Output::text(iso(since))),
                ("until", Output::text(iso(until))),
            ]),
        ),
        ("slo_s", Output::Integer(i128::from(slo))),
        ("max_allowed_s", Output::Integer(i128::from(max))),
        ("count", Output::Integer(overall.count as i128)),
        ("p50_s", raw(overall.p50)),
        ("p90_s", raw(overall.p90)),
        ("max_s", raw(overall.max)),
        ("within_slo", within_slo),
        ("breach", Output::Bool(breach)),
        (
            "breach_reasons",
            Output::Array(reasons.iter().map(Output::text).collect()),
        ),
        (
            "excluded",
            Output::Object(
                EXCLUDED
                    .into_iter()
                    .zip(excluded)
                    .map(|(key, count)| {
                        (
                            std::borrow::Cow::Owned(key.chars().map(u32::from).collect()),
                            Output::Integer(count as i128),
                        )
                    })
                    .collect(),
            ),
        ),
        ("unreadable", Output::Integer(unreadable as i128)),
        ("by_host", by_host),
        ("waits", Output::Object(waits)),
        (
            "slowest",
            Output::Array(slowest.into_iter().map(|(_, _, row)| row).collect()),
        ),
        (
            "candidates",
            Output::Array(
                window
                    .iter()
                    .map(|(_, document)| Input::root(document))
                    .filter(|r| r.field("candidate").truth())
                    .map(|r| {
                        Output::object([
                            ("head", Output::Raw(r.field("candidate"))),
                            ("ended", Output::Raw(r.field("ended"))),
                            ("total_s", Output::Raw(r.field("total_s"))),
                            ("exit", Output::Raw(r.field("exit"))),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "runs",
            Output::Array(
                counted
                    .iter()
                    .map(|(_, r)| {
                        Output::object([
                            ("ended", Output::Raw(r.field("ended"))),
                            ("host", Output::Raw(r.field("host"))),
                            ("total_s", Output::Raw(r.field("total_s"))),
                            ("tree", Output::Raw(r.field("tree"))),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);
    if markdown {
        render_markdown(
            &result,
            excluded,
            within,
            totals.len(),
            unreadable,
            (slo, max),
            &reasons,
        )
    } else {
        let mut out = String::new();
        result.pretty(0, &mut out)?;
        Ok(out)
    }
}
fn seconds(value: &Output<'_>) -> anyhow::Result<String> {
    if matches!(value, Output::Null) {
        Ok("-".into())
    } else {
        Ok(format!("{}s", value.scalar()?))
    }
}
fn render_markdown(
    r: &Output<'_>,
    excluded: [usize; 5],
    within: usize,
    count: usize,
    unreadable: usize,
    limits: (i64, i64),
    reasons: &[String],
) -> anyhow::Result<String> {
    let (slo, max) = limits;
    let excluded = EXCLUDED
        .into_iter()
        .zip(excluded)
        .filter(|(_, n)| *n != 0)
        .map(|(reason, n)| format!("{n} {reason}"))
        .collect::<Vec<_>>()
        .join(", ");
    let share = if count == 0 {
        "-".into()
    } else {
        format!(
            "{:.0}%",
            super::pyfloat::python_round(within as f64 / count as f64, 3) * 100.0
        )
    };
    let unreadable = if unreadable != 0 {
        format!("; {unreadable} unreadable lines")
    } else {
        String::new()
    };
    let mut out = format!(
        "**fractal-test full warm runs**, {} .. {}: {count} counted (left out: {}{unreadable})\n\nObjective: p90 at most {slo}s, no run over {max}s; {share} of runs within {slo}s.\n\n| runs | count | p50 | p90 | max |\n|---|---:|---:|---:|---:|",
        r.field("window").field("since").scalar()?,
        r.field("window").field("until").scalar()?,
        if excluded.is_empty() {
            "none"
        } else {
            &excluded
        }
    );
    let row = |out: &mut String, label: &str, v: &Output<'_>| -> anyhow::Result<()> {
        write!(
            out,
            "\n| {label} | {} | {} | {} | {} |",
            v.field("count").scalar()?,
            seconds(v.field("p50_s"))?,
            seconds(v.field("p90_s"))?,
            seconds(v.field("max_s"))?
        )?;
        Ok(())
    };
    row(&mut out, "all", r)?;
    for (host, value) in r.field("by_host").fields()? {
        row(&mut out, &scalar_text(host)?, value)?;
    }
    let waits = r.field("waits").fields()?;
    if !waits.is_empty() {
        out.push_str("\n\n| waited for (every run in the window) | runs | p50 | p90 | max |\n|---|---:|---:|---:|---:|");
        for (label, value) in waits {
            row(&mut out, &scalar_text(label)?, value)?;
        }
    }
    let candidates = r.field("candidates").array()?;
    if !candidates.is_empty() {
        out.push_str("\n\nCandidate measurements (excluded from SLO figures):");
        for v in candidates {
            write!(
                out,
                "\n- {}: {}s, exit {}, ended {}",
                v.field("head").scalar()?,
                v.field("total_s").scalar()?,
                v.field("exit").scalar()?,
                v.field("ended").scalar()?
            )?;
        }
    }
    let slowest = r.field("slowest").array()?;
    if !slowest.is_empty() {
        out.push_str("\n\n| slowest stage or check | mean | p90 |\n|---|---:|---:|");
        for v in slowest {
            write!(
                out,
                "\n| {} ({}) | {}s | {} |",
                v.field("name").scalar()?,
                v.field("kind").scalar()?,
                v.field("mean_s").scalar()?,
                seconds(v.field("p90_s"))?
            )?;
        }
    }
    out.push_str("\n\n");
    if !reasons.is_empty() {
        out.push_str("**Breach**: ");
        out.push_str(&reasons.join("; "));
    } else {
        out.push_str(if count == 0 {
            "No full warm run in the window: nothing to judge."
        } else {
            "**Within the objective.**"
        });
    }
    Ok(out)
}

#[cfg(test)]
mod text_tests {
    #[test]
    fn whitespace_set_matches_pinned_python_exhaustively() {
        let output = crate::pinned_python::command()
            .args([
                "-B",
                "-c",
                "import json; print(json.dumps([p for p in range(0x110000) if chr(p).isspace()]))",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<u32> = serde_json::from_slice(&output.stdout).unwrap();
        let actual: Vec<_> = (0..=0x10ffff)
            .filter_map(|point| char::from_u32(point).map(|character| (point, character)))
            .filter(|(_, character)| super::super::legacy_verify::projection_oid::space(*character))
            .map(|(point, _)| point)
            .collect();
        assert_eq!(actual, expected);
    }
}
