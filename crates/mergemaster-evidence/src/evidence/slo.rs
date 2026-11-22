//! Read-only evidence-gate SLO counters, compatible with the pinned ci-evidence-slo oracle.
use super::argparse_compat::{
    Action, DefaultValue, OptionSpec, Parser, Value as ArgumentValue, float,
};
use chrono::{DateTime, SecondsFormat, Utc};
use indexmap::IndexMap;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fmt::Write, process::Command, time::Duration};

const USAGE: &str = "usage: ci-evidence-slo [-h] --repository REPOSITORY [--hours HOURS]\n                       [--since SINCE] [--until UNTIL] [--max-logs MAX_LOGS]\n                       [--json]\n";
const HELP: &str = "\nSLO counters for the evidence gate: how often is a required check covered by\nan existing note, by whom, and how often is a note produced but not verified.\n\noptions:\n  -h, --help            show this help message and exit\n  --repository REPOSITORY\n  --hours HOURS\n  --since SINCE\n  --until UNTIL\n  --max-logs MAX_LOGS\n  --json\n";
const OUTCOMES: [(&str, &str); 5] = [
    ("evidence satisfied by existing note", "satisfied"),
    ("evidence existing note is degraded", "degraded"),
    ("evidence no note", "no_note"),
    ("evidence note rejected", "rejected"),
    ("evidence verifier unavailable", "unavailable"),
];

pub struct Exit {
    pub code: u8,
    pub stdout: String,
    pub stderr: String,
}
impl Exit {
    fn error(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            stdout: String::new(),
            stderr: message.into(),
        }
    }
}

const fn option(long: &'static str, metavar: Option<&'static str>, action: Action) -> OptionSpec {
    OptionSpec {
        long,
        short: None,
        metavar,
        action,
        choices: &[],
        help: "",
        hidden: false,
        default: DefaultValue::None,
    }
}
fn max_logs(text: &str) -> Option<ArgumentValue> {
    let number = super::legacy_verify::argparse_int::parse(
        super::legacy_verify::value_inputs::TextRef::Str(text),
    )
    .ok()?;
    Some(ArgumentValue::String(format!(
        "{}{}",
        if number.negative { "-" } else { "" },
        number.digits
    )))
}
const PARSER: Parser = Parser {
    program: "ci-evidence-slo",
    description: "",
    options: &[
        OptionSpec {
            short: Some("-h"),
            ..option("--help", None, Action::Help)
        },
        option("--repository", Some("REPOSITORY"), Action::Store),
        OptionSpec {
            default: DefaultValue::Float(24.0),
            ..option(
                "--hours",
                Some("HOURS"),
                Action::Convert {
                    name: "float",
                    parse: float,
                },
            )
        },
        option("--since", Some("SINCE"), Action::Store),
        option("--until", Some("UNTIL"), Action::Store),
        OptionSpec {
            default: DefaultValue::String("300"),
            ..option(
                "--max-logs",
                Some("MAX_LOGS"),
                Action::Convert {
                    name: "int",
                    parse: max_logs,
                },
            )
        },
        option("--json", None, Action::Flag),
    ],
};

fn string(value: Option<&ArgumentValue>) -> Option<&str> {
    match value {
        Some(ArgumentValue::String(value)) => Some(value),
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct Time {
    local: DateTime<Utc>,
    offset: Option<i64>,
}
fn parse_time(text: &str) -> Option<Time> {
    use super::legacy_verify::statement::{zoned_time_components, zoned_time_micros};
    let mut points: Vec<_> = text.chars().map(u32::from).collect();
    if let Some((utc, local)) = zoned_time_components(&points) {
        return Some(Time {
            local: DateTime::from_timestamp_micros(local)?,
            offset: Some(local - utc),
        });
    }
    // fromisoformat also accepts naive date/time and date-only values. Use the
    // same clock/date parser with a synthetic zero offset, retaining naivety.
    points.extend("+00:00".chars().map(u32::from));
    let local = zoned_time_micros(&points).or_else(|| {
        points.truncate(text.chars().count());
        points.extend("T00:00+00:00".chars().map(u32::from));
        zoned_time_micros(&points)
    })?;
    Some(Time {
        local: DateTime::from_timestamp_micros(local)?,
        offset: None,
    })
}
fn iso(time: Time) -> String {
    let mut text = time.local.to_rfc3339_opts(
        if time.local.timestamp_subsec_micros() == 0 {
            SecondsFormat::Secs
        } else {
            SecondsFormat::Micros
        },
        true,
    );
    let _ = text.pop(); // The local projection's synthetic UTC suffix is not its timezone.
    if let Some(offset) = time.offset {
        let magnitude = offset.abs();
        let seconds = magnitude / 1_000_000;
        let _ = write!(
            text,
            "{}{:02}:{:02}",
            if offset < 0 { '-' } else { '+' },
            seconds / 3600,
            seconds / 60 % 60
        );
        if seconds % 60 != 0 || magnitude % 1_000_000 != 0 {
            let _ = write!(text, ":{:02}", seconds % 60);
            if magnitude % 1_000_000 != 0 {
                let _ = write!(text, ".{:06}", magnitude % 1_000_000);
            }
        }
    }
    text
}

/// Keep argparse diagnostics at this compatibility boundary; the rest of the CLI uses clap.
pub fn run(argv: &[String]) -> Exit {
    let parsed = match PARSER.parse_required(argv, &["--repository"]) {
        Ok(parsed) => parsed,
        Err(exit) => {
            return Exit {
                code: if exit.code == 0 { 0 } else { 2 },
                stdout: if exit.code == 0 {
                    format!("{USAGE}{HELP}")
                } else {
                    exit.stdout
                },
                stderr: exit.stderr.replacen(&PARSER.usage(), USAGE, 1),
            };
        }
    };
    let values = parsed.values;
    let repository = string(values.get("--repository")).unwrap_or("");
    let hours = match values.get("--hours") {
        Some(ArgumentValue::Float(value)) => *value,
        _ => 24.0,
    };
    let max_logs_text = string(values.get("--max-logs")).unwrap_or("300");
    let max_logs = max_logs_text.parse::<i128>().unwrap_or_else(|_| {
        if max_logs_text.starts_with('-') {
            i128::MIN
        } else {
            i128::MAX
        }
    });
    let parts: Vec<_> = repository.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|p| {
            p.is_empty()
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
        || hours <= 0.0
        || max_logs < 0
    {
        return Exit::error(2, "bad --repository, --hours or --max-logs\n");
    }
    let until = match string(values.get("--until")) {
        Some(value) => parse_time(value),
        None => Some(Time {
            local: Utc::now(),
            offset: Some(0),
        }),
    };
    let Some(until) = until else {
        return Exit::error(2, "bad --since or --until\n");
    };
    let since = match string(values.get("--since")) {
        Some(value) => parse_time(value),
        None => until
            .local
            .checked_sub_signed(chrono::Duration::microseconds(
                (hours * 3_600_000_000.0).round_ties_even() as i64,
            ))
            .map(|local| Time {
                local,
                offset: until.offset,
            }),
    };
    let Some(since) = since else {
        return Exit::error(2, "bad --since or --until\n");
    };
    if since.offset.is_some() != until.offset.is_some() {
        return Exit::error(
            1,
            "TypeError: can't compare offset-naive and offset-aware datetimes\n",
        );
    }
    // Python compares equal-tzinfo datetimes in local time, others in UTC.
    let comparable = |time: Time| {
        time.local.timestamp_micros()
            - if since.offset == until.offset {
                0
            } else {
                time.offset.unwrap_or(0)
            }
    };
    if comparable(since) >= comparable(until) {
        return Exit::error(2, "--since must be before --until\n");
    }
    let since_text = iso(since);
    let until_text = iso(until);
    match collect(repository, since, until, max_logs) {
        Ok(mut report) => {
            report["interval"] = json!({"since": since_text, "until": until_text});
            let stdout = if values.get("--json") == Some(&ArgumentValue::Bool(true)) {
                let mut out = String::new();
                pretty(&report, 0, &mut out);
                out.push('\n');
                out
            } else {
                text_report(&report)
            };
            Exit {
                code: 0,
                stdout,
                stderr: String::new(),
            }
        }
        Err(error) => Exit::error(1, format!("could not read the runs: {error}\n")),
    }
}

fn request(path: &str, paginate: Option<&str>) -> Result<Value, String> {
    let mut command = Command::new("gh");
    command.args(["api", "--allow-escape-sequences", path]);
    if paginate.is_some() {
        command.args(["--paginate", "--slurp"]);
    }
    let done =
        crate::gate::git::deadline::GitChild::capture(&mut command, None, Duration::from_secs(300))
            .map_err(|error| capture_error(&command, Duration::from_secs(300), &error))?;
    if !done.status.success() {
        return Err(format!(
            "RuntimeError: gh api {path}: {}",
            String::from_utf8_lossy(&done.stderr)
                .chars()
                .take(200)
                .collect::<String>()
        ));
    }
    let value: Value = serde_json::from_slice(&done.stdout)
        .map_err(|error| format!("JSONDecodeError: {error}"))?;
    if let Some(key) = paginate {
        Ok(Value::Array(
            value
                .as_array()
                .ok_or("TypeError: API pages are not an array")?
                .iter()
                .flat_map(|page| page[key].as_array().into_iter().flatten().cloned())
                .collect(),
        ))
    } else {
        Ok(value)
    }
}

fn strip_ansi(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("\x1b[") {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        let end = tail
            .bytes()
            .take_while(|b| b.is_ascii_digit() || *b == b';')
            .count();
        if tail.as_bytes().get(end) == Some(&b'm') {
            rest = &tail[end + 1..];
        } else {
            out.push_str("\x1b[");
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}
fn log(job: &Value, repository: &str) -> Result<String, String> {
    log_with(
        std::ffi::OsStr::new("gh"),
        job,
        repository,
        Duration::from_secs(300),
    )
}
fn log_with(
    program: &std::ffi::OsStr,
    job: &Value,
    repository: &str,
    timeout: Duration,
) -> Result<String, String> {
    let mut command = Command::new(program);
    command.args([
        "api",
        "--allow-escape-sequences",
        &format!("repos/{repository}/actions/jobs/{}/logs", job["id"]),
    ]);
    let done = crate::gate::git::deadline::GitChild::capture(&mut command, None, timeout)
        .map_err(|error| capture_error(&command, timeout, &error))?;
    Ok(if done.status.success() {
        strip_ansi(&String::from_utf8_lossy(&done.stdout))
    } else {
        String::new()
    })
}
fn capture_error(command: &Command, timeout: Duration, error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::TimedOut {
        let mut argv = String::from("[");
        for (index, arg) in std::iter::once(command.get_program())
            .chain(command.get_args())
            .enumerate()
        {
            if index > 0 {
                argv.push_str(", ");
            }
            let _ = write!(
                argv,
                "{}",
                super::legacy_verify::python_repr::Repr(
                    super::legacy_verify::value_inputs::TextRef::Str(&arg.to_string_lossy())
                )
            );
        }
        argv.push(']');
        return format!(
            "TimeoutExpired: Command '{argv}' timed out after {} seconds",
            timeout.as_secs_f64()
        );
    }
    let class = match error.kind() {
        std::io::ErrorKind::NotFound => "FileNotFoundError",
        std::io::ErrorKind::PermissionDenied => "PermissionError",
        _ => "OSError",
    };
    match error.raw_os_error() {
        Some(errno) => {
            let description = error.to_string();
            let description = description
                .split(" (os error")
                .next()
                .unwrap_or(&description);
            format!("{class}: [Errno {errno}] {description}: 'gh'")
        }
        None => format!("{class}: {error}"),
    }
}
fn fields(text: &str) -> BTreeMap<&str, &str> {
    for line in text.split('\n') {
        if let Some((_, tail)) = line.split_once("evidence-decision v1 ") {
            let fields: BTreeMap<_, _> = tail
                .split_whitespace()
                .filter_map(|part| part.split_once('='))
                .collect();
            if !tail.contains('$') && fields.contains_key("gate_sha256") {
                return fields;
            }
        }
    }
    BTreeMap::new()
}
#[derive(Default)]
struct Counts {
    counts: BTreeMap<&'static str, u64>,
    producers: IndexMap<String, u64>,
    reasons: IndexMap<String, u64>,
}
fn increment(map: &mut IndexMap<String, u64>, key: String) {
    *map.entry(key).or_default() += 1;
}
fn collect(repository: &str, since: Time, until: Time, max_logs: i128) -> Result<Value, String> {
    let runs = request(
        &format!(
            "repos/{repository}/actions/workflows/fleet.yml/runs?per_page=100&created={}..{}",
            since.local.format("%Y-%m-%dT%H:%M:%SZ"),
            until.local.format("%Y-%m-%dT%H:%M:%SZ")
        ),
        Some("workflow_runs"),
    )?;
    let finished: Vec<_> = runs
        .as_array()
        .ok_or("TypeError: runs are not an array")?
        .iter()
        .filter(|run| run["status"] == "completed")
        .collect();
    let mut table: BTreeMap<(&str, &str), Counts> = BTreeMap::new();
    let mut logs_read = 0i128;
    // Independent jobs requests are bounded at six; traversal retains run order for the log budget.
    let mut lists = Vec::with_capacity(finished.len());
    for batch in finished.chunks(6) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|run| {
                    scope.spawn(move || {
                        request(
                            &format!(
                                "repos/{repository}/actions/runs/{}/jobs?per_page=100&filter=all",
                                run["id"]
                            ),
                            Some("jobs"),
                        )
                    })
                })
                .collect();
            for handle in handles {
                lists.push(
                    handle
                        .join()
                        .unwrap_or_else(|_| Err("RuntimeError: jobs reader panicked".into())),
                );
            }
        });
    }
    for (run, jobs) in finished.iter().zip(&lists) {
        let jobs = jobs.as_ref().map_err(Clone::clone)?;
        for job in jobs.as_array().ok_or("TypeError: jobs are not an array")? {
            let Some(check) = job["name"]
                .as_str()
                .and_then(|s| s.strip_prefix("evidence-gate-"))
                .filter(|s| {
                    !s.is_empty()
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                })
            else {
                continue;
            };
            if job["status"] != "completed" {
                continue;
            }
            let mut outcome = None;
            let mut skipped = false;
            for step in job["steps"].as_array().into_iter().flatten() {
                if step["conclusion"] != "success" {
                    continue;
                }
                if let Some((_, value)) = OUTCOMES.iter().find(|(name, _)| step["name"] == *name) {
                    outcome = Some(*value);
                } else if step["name"] == "evidence skip taken" {
                    skipped = true;
                }
            }
            let row = table
                .entry((check, run["event"].as_str().unwrap_or("?")))
                .or_default();
            let Some(outcome) = outcome else {
                *row.counts.entry("gate_incomplete").or_default() += 1;
                continue;
            };
            *row.counts.entry("decisions").or_default() += 1;
            *row.counts.entry(outcome).or_default() += 1;
            if outcome == "satisfied" {
                *row.counts
                    .entry(if skipped { "skipped" } else { "shadow" })
                    .or_default() += 1;
            }
            if matches!(outcome, "satisfied" | "rejected" | "degraded") && logs_read < max_logs {
                logs_read += 1;
                let text = log(job, repository)?;
                let fields = fields(&text);
                if outcome == "satisfied" {
                    increment(
                        &mut row.producers,
                        format!(
                            "{}/{}",
                            fields.get("kind").unwrap_or(&"?"),
                            fields.get("trust_level").unwrap_or(&"?")
                        ),
                    );
                } else {
                    increment(
                        &mut row.reasons,
                        fields.get("reason").unwrap_or(&"?").to_string(),
                    );
                }
            } else if outcome == "satisfied" {
                increment(&mut row.producers, "unread".into());
            }
        }
    }
    let mut rows = Vec::with_capacity(table.len());
    let (mut decisions, mut satisfied, mut bad_total) = (0, 0, 0);
    for ((check, event), row) in table {
        let count = |key| row.counts.get(key).copied().unwrap_or(0);
        let total = count("decisions");
        let bad = count("rejected") + count("degraded");
        let rate = |n| rounded_rate(n, total);
        decisions += total;
        satisfied += count("satisfied");
        bad_total += bad;
        rows.push(json!({"check":check, "event":event, "decisions":total,
            "satisfied":count("satisfied"), "skipped":count("skipped"), "shadow":count("shadow"),
            "satisfied_rate":rate(count("satisfied")), "satisfied_by_producer":row.producers.iter().map(|(k,v)| (k.clone(), json!(v))).collect::<serde_json::Map<_,_>>(),
            "produced_not_verified":bad, "rejected":count("rejected"), "degraded":count("degraded"),
            "produced_not_verified_rate":rate(bad), "produced_not_verified_reasons":row.reasons.iter().map(|(k,v)| (k.clone(), json!(v))).collect::<serde_json::Map<_,_>>(),
            "no_note":count("no_note"), "unavailable":count("unavailable"), "gate_incomplete":count("gate_incomplete")}));
    }
    Ok(
        json!({"interval":null,"runs_read":finished.len(),"logs_read":logs_read,
        "totals":{"decisions":decisions,"satisfied":satisfied,"produced_not_verified":bad_total},
        "target":{"produced_not_verified":0},"checks":rows}),
    )
}

fn rounded_rate(numerator: u64, denominator: u64) -> Value {
    if denominator == 0 {
        return Value::Null;
    }
    if numerator == 0 {
        return json!(0.0);
    }
    // Python round(x, 4) rounds the exact binary float, not x*10000 (which
    // introduces another rounding). Counts bound x to [1/u64::MAX, 1], so
    // the significand times 10000 and the denominator both fit in u128.
    let bits = (numerator as f64 / denominator as f64).to_bits();
    let shift = 1075 - ((bits >> 52) & 0x7ff);
    let scaled = u128::from((bits & ((1 << 52) - 1)) | (1 << 52)) * 10000;
    let whole = scaled >> shift;
    let remainder = scaled - (whole << shift);
    let half = 1_u128 << (shift - 1);
    let rounded = whole + u128::from(remainder > half || (remainder == half && whole & 1 == 1));
    json!(rounded as f64 / 10000.0)
}

fn pretty(value: &Value, depth: usize, out: &mut String) {
    match value {
        Value::String(text) => {
            let _ = super::legacy_json::string(text, out);
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                out.extend(std::iter::repeat_n(' ', (depth + 1) * 2));
                pretty(item, depth + 1, out);
            }
            if !items.is_empty() {
                out.push('\n');
                out.extend(std::iter::repeat_n(' ', depth * 2));
            }
            out.push(']');
        }
        Value::Object(items) => {
            out.push('{');
            for (i, (key, item)) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                out.extend(std::iter::repeat_n(' ', (depth + 1) * 2));
                let _ = super::legacy_json::string(key, out);
                out.push_str(": ");
                pretty(item, depth + 1, out);
            }
            if !items.is_empty() {
                out.push('\n');
                out.extend(std::iter::repeat_n(' ', depth * 2));
            }
            out.push('}');
        }
        _ => {
            let _ = write!(out, "{value}");
        }
    }
}
fn dictionary(value: &Value, empty: &str) -> String {
    let Some(map) = value.as_object().filter(|m| !m.is_empty()) else {
        return empty.into();
    };
    let mut out = String::from("{");
    for (i, (key, value)) in map.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(
            out,
            "{}",
            super::legacy_verify::python_repr::Repr(
                super::legacy_verify::value_inputs::TextRef::Str(key)
            )
        );
        let _ = write!(out, ": {value}");
    }
    out.push('}');
    out
}
fn text_report(report: &Value) -> String {
    let totals = &report["totals"];
    let mut out = format!(
        "evidence gate, {} .. {}: {} runs, {} logs read\ntotals: {} decisions, {} satisfied by an existing note, {} produced-but-not-verified (target 0)\n",
        report["interval"]["since"].as_str().unwrap_or(""),
        report["interval"]["until"].as_str().unwrap_or(""),
        report["runs_read"],
        report["logs_read"],
        totals["decisions"],
        totals["satisfied"],
        totals["produced_not_verified"]
    );
    for row in report["checks"].as_array().into_iter().flatten() {
        let rate = row["satisfied_rate"]
            .as_f64()
            .map_or_else(|| "-".into(), |rate| format!("{:.1}%", rate * 100.0));
        let _ = writeln!(
            out,
            "  {:<26} {:<12} decisions={:<4} satisfied={:<4} ({rate}) skipped={} by={} bad={} {}",
            row["check"].as_str().unwrap_or(""),
            row["event"].as_str().unwrap_or(""),
            row["decisions"].to_string(),
            row["satisfied"].to_string(),
            row["skipped"],
            dictionary(&row["satisfied_by_producer"], "-"),
            row["produced_not_verified"],
            dictionary(&row["produced_not_verified_reasons"], "")
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_capture_deadline_is_an_error_not_an_empty_log() {
        let root = tempfile::tempdir().unwrap();
        let gh = root.path().join("gh");
        // Keep executable write descriptors out of this multithreaded test process:
        // a concurrently forked child could retain one until exec and cause ETXTBSY.
        assert!(
            Command::new("/bin/sh")
                .args([
                    "-c",
                    "printf '%s' \"$1\" > \"$2\" && chmod 700 \"$2\"",
                    "sh",
                    "#!/bin/sh\nexec sleep 2\n",
                ])
                .arg(&gh)
                .status()
                .unwrap()
                .success()
        );
        let error = log_with(
            gh.as_os_str(),
            &json!({"id": 11}),
            "org/repo",
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert_eq!(
            error,
            format!(
                "TimeoutExpired: Command '['{}', 'api', '--allow-escape-sequences', 'repos/org/repo/actions/jobs/11/logs']' timed out after 0.05 seconds",
                gh.display()
            )
        );
    }
}
