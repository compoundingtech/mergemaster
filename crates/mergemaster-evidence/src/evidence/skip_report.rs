//! Per-pull-request evidence decisions and release build cost accounting.
use super::flip_ready::{
    GitHub, cache_dir, config_path, fields_of, git, iso, json_pretty, parse_time,
};
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Duration, Timelike, Utc};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const CATEGORIES: [&str; 11] = [
    "skipped",
    "not_relevant",
    "lane_edit",
    "merge_tree",
    "not_signed",
    "failed",
    "protected",
    "sampled",
    "shadow",
    "shadow_unsigned",
    "other",
];
const RELEASE_WORKFLOW: &str = "release-fractal.yml";
type Lanes = BTreeMap<String, Vec<String>>;

#[derive(clap::Args)]
pub struct Args {
    #[arg(long, default_value = "compoundingtech/fractal")]
    repo: String,
    #[arg(long, default_value_t = 24.0, allow_hyphen_values = true)]
    hours: f64,
    #[arg(long = "actor")]
    actors: Vec<String>,
    #[arg(long)]
    receipts: Vec<PathBuf>,
    #[arg(long)]
    cache: Option<PathBuf>,
    #[arg(long)]
    markdown: bool,
    /// Override the end of the reporting window for deterministic replay.
    #[arg(long, hide = true)]
    now: Option<String>,
}

// The production implementation delegates all GitHub selection and transport to
// flip-ready; the report itself only interprets the selected evidence.
trait Source {
    fn gh(&self, args: &[&str]) -> Result<String>;
    fn items(&self, path: &str, key: &str) -> Result<Vec<Value>>;
    fn lines_of(&self, job: &Value) -> Result<Vec<String>>;
    fn pr_runs(
        &self,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
        workflow: &str,
    ) -> Result<Vec<Value>>;
    fn repo(&self) -> &str;
}
impl Source for GitHub {
    fn gh(&self, args: &[&str]) -> Result<String> {
        GitHub::gh(self, args)
    }
    fn items(&self, path: &str, key: &str) -> Result<Vec<Value>> {
        GitHub::items(self, path, key)
    }
    fn lines_of(&self, job: &Value) -> Result<Vec<String>> {
        GitHub::lines_of(self, job)
    }
    fn pr_runs(
        &self,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
        workflow: &str,
    ) -> Result<Vec<Value>> {
        GitHub::pr_runs(self, since, until, workflow)
    }
    fn repo(&self) -> &str {
        &self.repo
    }
}
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}
fn selected(run: &Value, actors: &BTreeSet<String>) -> bool {
    text(run, "status") == "completed"
        && (actors.is_empty() || actors.contains(text(&run["actor"], "login")))
}
fn revision(base: &str) -> &str {
    if base.is_empty() { "origin/main" } else { base }
}
fn read_config(root: &Path, path: &str, base: &str) -> Result<String> {
    let revision = revision(base);
    let path = config_path(root, path, Some(revision))?;
    git(root, &["show", &format!("{revision}:{path}")])
}
fn lanes_at<'a>(
    root: &Path,
    base: &str,
    cache: &'a mut BTreeMap<String, Lanes>,
) -> Result<&'a Lanes> {
    if !cache.contains_key(base) {
        let read = read_config(root, ".st/required-lanes.json", base);
        let data = match read {
            Ok(data) => data,
            Err(error) => {
                if base.is_empty() || !super::flip_ready::child_exited(&error) {
                    return Err(error);
                }
                git(root, &["fetch", "-q", "origin", base])?;
                read_config(root, ".st/required-lanes.json", base)?
            }
        };
        let data: Value = serde_json::from_str(&data)?;
        let lanes = data
            .get("lanes")
            .filter(|v| !v.is_null())
            .unwrap_or(&data)
            .as_object()
            .ok_or_else(|| anyhow!("required lanes must be an object"))?;
        let mut parsed = Lanes::new();
        for (check, lane) in lanes {
            let paths = match lane.get("definition_paths").filter(|v| !v.is_null()) {
                Some(paths) => serde_json::from_value(paths.clone())?,
                None => Vec::new(),
            };
            parsed.insert(check.clone(), paths);
        }
        cache.insert(base.to_owned(), parsed);
    }
    cache
        .get(base)
        .ok_or_else(|| anyhow!("missing lane cache entry"))
}
fn enforced_at(
    root: &Path,
    base: &str,
    cache: &mut BTreeMap<String, Value>,
    check: &str,
) -> Result<bool> {
    let policy = match cache.entry(base.to_owned()) {
        std::collections::btree_map::Entry::Occupied(slot) => slot.into_mut(),
        std::collections::btree_map::Entry::Vacant(slot) => {
            let checks = match read_config(root, ".st/evidence-skip-policy.json", base) {
                Ok(text) => serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| v.get("checks").cloned())
                    .unwrap_or(Value::Null),
                Err(error) if super::flip_ready::child_exited(&error) => Value::Null,
                Err(error) => return Err(error),
            };
            slot.insert(checks)
        }
    };
    Ok(match policy.get(check).filter(|v| v.is_object()) {
        Some(entry) => entry.get("enforce") == Some(&Value::Bool(true)),
        None => true,
    })
}
fn touches(files: &[String], paths: &[String]) -> bool {
    files.iter().any(|file| {
        paths.iter().any(|path| {
            file == path
                || file
                    .strip_prefix(path.trim_end_matches('/'))
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
    })
}
fn pr_of(source: &impl Source, run: &Value) -> Result<Option<u64>> {
    if let Some(number) = run["pull_requests"]
        .as_array()
        .and_then(|v| v.first())
        .and_then(|v| v["number"].as_u64())
        .filter(|n| *n != 0)
    {
        return Ok(Some(number));
    }
    let path = format!(
        "repos/{}/commits/{}/pulls",
        source.repo(),
        text(run, "head_sha")
    );
    let pulls: Vec<Value> = serde_json::from_str(&source.gh(&["api", &path])?)?;
    Ok(pulls.first().and_then(|v| v["number"].as_u64()))
}
fn pr_files<'a>(
    source: &impl Source,
    number: u64,
    cache: &'a mut BTreeMap<u64, Vec<String>>,
) -> Result<&'a [String]> {
    if let std::collections::btree_map::Entry::Vacant(slot) = cache.entry(number) {
        let path = format!("repos/{}/pulls/{number}/files?per_page=100", source.repo());
        let pages: Vec<Vec<Value>> =
            serde_json::from_str(&source.gh(&["api", "--paginate", "--slurp", &path])?)?;
        let files = pages
            .into_iter()
            .flatten()
            .map(|item| {
                item["filename"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("PR file has no filename"))
            })
            .collect::<Result<_>>()?;
        slot.insert(files);
    }
    cache
        .get(&number)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("missing file cache entry"))
}
fn classify(fields: &Value, lane_edit: bool) -> &'static str {
    if text(fields, "decision") == "skip" {
        return "skipped";
    }
    if lane_edit {
        return "lane_edit";
    }
    let outcome = text(fields, "outcome");
    let reason = text(fields, "reason");
    if outcome == "no_note" || reason == "crate_uncovered" {
        return if text(fields, "tree_of") == "merge" {
            "merge_tree"
        } else {
            "not_signed"
        };
    }
    if reason == "check_failed" {
        return "failed";
    }
    if outcome == "satisfied" {
        if reason.contains("a_file_that_decides") {
            return "protected";
        }
        if reason.contains("sampled") {
            return "sampled";
        }
        if reason.contains("shadow") {
            return "shadow";
        }
    }
    "other"
}
fn not_run(conclusions: &BTreeMap<&str, &str>, check: &str) -> bool {
    conclusions.get(format!("{check}-execution").as_str()) == Some(&"skipped")
        && conclusions.get(check) == Some(&"success")
}
fn seats(receipts: &[PathBuf]) -> BTreeMap<String, Value> {
    let mut found = BTreeMap::new();
    for path in receipts {
        let Ok(bytes) = fs::read(path) else { continue };
        for line in String::from_utf8_lossy(&bytes).lines() {
            let Ok(record) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if let Some(branch) = record["branch"].as_str().filter(|v| !v.is_empty())
                && let Some(agent) = record.get("agent").filter(|v| {
                    !v.is_null() && **v != json!("") && **v != json!(false) && **v != json!(0)
                })
            {
                found.insert(branch.to_owned(), agent.clone());
            }
        }
    }
    found
}
fn rounded_minutes(value: f64) -> f64 {
    // Like Python round(value, 1): fixed-precision formatting rounds the exact
    // binary value (ties-to-even), and parsing correctly rounds it back.
    // Parsing cannot fail for a finite formatted f64; keep the input otherwise.
    format!("{value:.1}").parse().unwrap_or(value)
}
fn release_surface(
    source: &impl Source,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    actors: &BTreeSet<String>,
) -> Result<Value> {
    let runs = source.pr_runs(since, until, RELEASE_WORKFLOW)?;
    let mut count = 0;
    let (mut minutes, mut macos) = (0.0_f64, 0.0_f64);
    let mut prs = BTreeSet::new();
    for run in runs.iter().filter(|run| selected(run, actors)) {
        count += 1;
        if let Some(pulls) = run["pull_requests"].as_array() {
            for pull in pulls {
                if let Some(n) = pull["number"].as_u64().filter(|n| *n != 0) {
                    prs.insert(n);
                }
            }
        }
        let id = run
            .get("id")
            .ok_or_else(|| anyhow!("release run has no id"))?;
        for job in source.items(
            &format!(
                "repos/{}/actions/runs/{id}/jobs?per_page=100&filter=all",
                source.repo()
            ),
            "jobs",
        )? {
            if text(&job, "conclusion") == "skipped" {
                continue;
            }
            let (Some(start), Some(end)) = (
                parse_time(text(&job, "started_at")),
                parse_time(text(&job, "completed_at")),
            ) else {
                continue;
            };
            let spent =
                ((end.timestamp_micros() - start.timestamp_micros()) as f64 / 1_000_000.0 / 60.0)
                    .max(0.0);
            minutes += spent;
            if job["labels"].as_array().is_some_and(|labels| {
                labels
                    .iter()
                    .any(|label| label.as_str().is_some_and(|s| s.contains("macos")))
            }) {
                macos += spent;
            }
        }
    }
    Ok(
        json!({"workflow": RELEASE_WORKFLOW, "runs": count, "minutes": rounded_minutes(minutes), "macos_minutes": rounded_minutes(macos), "prs": prs}),
    )
}
#[derive(Default)]
struct Unsigned {
    branch: Value,
    checks: BTreeSet<String>,
    runs: BTreeSet<u64>,
}
fn report(
    source: &impl Source,
    root: &Path,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    actors: &BTreeSet<String>,
    receipts: &[PathBuf],
) -> Result<Value> {
    let runs = source.pr_runs(since, until, "fleet.yml")?;
    let mut count = 0;
    let mut counts: BTreeMap<String, [u64; 11]> = BTreeMap::new();
    let mut others: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut unsigned: BTreeMap<u64, Unsigned> = BTreeMap::new();
    let (mut lane_cache, mut file_cache, mut policy_cache) =
        (BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    for run in runs.iter().filter(|run| selected(run, actors)) {
        count += 1;
        let id = run["id"]
            .as_u64()
            .ok_or_else(|| anyhow!("run has no numeric id"))?;
        let jobs = source.items(
            &format!(
                "repos/{}/actions/runs/{id}/jobs?per_page=100&filter=latest",
                source.repo()
            ),
            "jobs",
        )?;
        let conclusions = jobs
            .iter()
            .map(|job| (text(job, "name"), text(job, "conclusion")))
            .collect();
        let mut number = None;
        for job in &jobs {
            let Some(check) = text(job, "name").strip_prefix("evidence-gate-") else {
                continue;
            };
            if text(job, "status") != "completed" || text(job, "conclusion") == "skipped" {
                continue;
            }
            let fields = source
                .lines_of(job)?
                .iter()
                .map(|line| fields_of(line))
                .find(|fields| text(fields, "check") == check);
            let Some(fields) = fields else { continue };
            let mut lane_edit = false;
            if text(&fields, "decision") != "skip" {
                if number.is_none() {
                    number = pr_of(source, run)?;
                }
                let lanes = lanes_at(root, text(&fields, "base"), &mut lane_cache)?;
                if let (Some(n), Some(paths)) = (number, lanes.get(check)) {
                    lane_edit = touches(pr_files(source, n, &mut file_cache)?, paths);
                }
            }
            let mut category = classify(&fields, lane_edit);
            if matches!(category, "not_signed" | "merge_tree") && not_run(&conclusions, check) {
                category = "not_relevant";
            }
            if category == "not_signed"
                && !enforced_at(root, text(&fields, "base"), &mut policy_cache, check)?
            {
                category = "shadow_unsigned";
            }
            let index = CATEGORIES
                .iter()
                .position(|c| *c == category)
                .ok_or_else(|| anyhow!("unknown report category {category}"))?;
            counts.entry(check.to_owned()).or_default()[index] += 1;
            if category == "other" {
                let outcome = fields
                    .get("outcome")
                    .and_then(Value::as_str)
                    .unwrap_or("None");
                let key = format!(
                    "{outcome}:{}",
                    text(&fields, "reason").chars().take(40).collect::<String>()
                );
                let value = others
                    .entry(check.to_owned())
                    .or_default()
                    .entry(key)
                    .or_insert(json!(0));
                *value = json!(value.as_u64().unwrap_or(0) + 1);
            }
            if category == "not_signed"
                && let Some(number) = number.filter(|n| *n != 0)
            {
                let entry = unsigned.entry(number).or_insert_with(|| Unsigned {
                    branch: run["head_branch"].clone(),
                    ..Unsigned::default()
                });
                entry.checks.insert(check.to_owned());
                entry.runs.insert(id);
            }
        }
    }
    let by_branch = seats(receipts);
    let listed: Vec<Value> = unsigned.into_iter().map(|(pr, entry)| json!({"pr": pr, "branch": entry.branch, "seat": by_branch.get(entry.branch.as_str().unwrap_or("")).cloned().unwrap_or(json!("unknown")), "checks": entry.checks, "runs": entry.runs.len()})).collect();
    let checks: Map<String, Value> = counts
        .into_iter()
        .map(|(check, counts)| {
            (
                check,
                Value::Object(
                    CATEGORIES
                        .iter()
                        .zip(counts)
                        .map(|(category, count)| ((*category).to_owned(), json!(count)))
                        .collect(),
                ),
            )
        })
        .collect();
    Ok(
        json!({"window": {"since": iso(since), "until": iso(until)}, "actors": actors, "runs": count, "checks": checks, "other_reasons": others, "not_signed": listed, "release_surface": release_surface(source, since, until, actors)?}),
    )
}
fn markdown(result: &Value) -> String {
    let actors = result["actors"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let mut lines = vec![format!("**Our pull request runs**, {} .. {}: {} runs{}", text(&result["window"], "since"), text(&result["window"], "until"), result["runs"], if actors.is_empty() { String::new() } else { format!(" (accounts: {actors})") }), String::new(), "| check | skipped | not run: not relevant | ran: lane edit | ran: merge tree | ran: not signed | ran: failed | ran: protected file | ran: sampled | ran: shadow | ran: shadow, unsigned | ran: other |".to_owned(), "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|".to_owned()];
    if let Some(checks) = result["checks"].as_object() {
        for (check, row) in checks {
            lines.push(format!(
                "| {check} | {} |",
                CATEGORIES
                    .iter()
                    .map(|category| row[*category].to_string())
                    .collect::<Vec<_>>()
                    .join(" | ")
            ));
        }
    }
    if let Some(entries) = result["not_signed"].as_array().filter(|a| !a.is_empty()) {
        lines.extend([
            String::new(),
            "Not signed (pushed without a covering note, lane untouched):".to_owned(),
            String::new(),
        ]);
        for entry in entries {
            let checks = entry["checks"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let seat = entry["seat"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| entry["seat"].to_string());
            lines.push(format!(
                "- #{} `{}`, seat {seat}: {checks} ({} run(s))",
                entry["pr"],
                entry["branch"].as_str().unwrap_or("None"),
                entry["runs"]
            ));
        }
    }
    if let Some(release) = result.get("release_surface").filter(|v| v.is_object()) {
        let prs = release["prs"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|n| format!("#{n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        lines.extend([String::new(), format!("**Release-surface PR runs** ({} on pull_request, real release builds): {} runs, {} job minutes ({} on macOS){}", text(release, "workflow"), release["runs"], release["minutes"].as_f64().unwrap_or(0.0), release["macos_minutes"].as_f64().unwrap_or(0.0), if prs.is_empty() { String::new() } else { format!(": {prs}") })]);
    }
    lines.join("\n") + "\n"
}
fn emit(result: Result<Value>, as_markdown: bool) -> Result<i32> {
    match result {
        Ok(result) => {
            crate::cli_println!(
                "{}",
                if as_markdown {
                    markdown(&result)
                } else {
                    json_pretty(&result)?
                }
            );
            Ok(0)
        }
        Err(error) if super::flip_ready::uncaught(&error) => Err(error),
        Err(error) => {
            eprintln!("could not read GitHub or selected base: {error}");
            Ok(2)
        }
    }
}
pub fn run(args: Args) -> Result<i32> {
    let root = std::env::current_dir().context("reading current directory")?;
    let now = match args.now {
        Some(value) => {
            parse_time(&value).ok_or_else(|| anyhow!("invalid --now timestamp: {value}"))?
        }
        None => Utc::now()
            .with_nanosecond(0)
            .ok_or_else(|| anyhow!("cannot truncate current time"))?,
    };
    let cache = args.cache.unwrap_or_else(cache_dir);
    let github = GitHub {
        repo: args.repo,
        cache,
    };
    let micros = (args.hours * 3_600_000_000.0).round_ties_even();
    let since = if micros.is_finite() && micros >= i64::MIN as f64 && micros < i64::MAX as f64 {
        now.checked_sub_signed(Duration::microseconds(micros as i64))
    } else {
        None
    };
    let result = since
        .ok_or_else(|| anyhow!("hours outside supported time range"))
        .and_then(|since| {
            report(
                &github,
                &root,
                since,
                now,
                &args.actors.into_iter().collect(),
                &args.receipts,
            )
        });
    emit(result, args.markdown)
}

#[cfg(test)]
mod tests;
