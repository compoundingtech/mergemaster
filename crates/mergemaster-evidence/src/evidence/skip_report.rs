//! Per-pull-request evidence decisions and release build cost accounting.
use super::flip_ready::api;
use super::flip_ready::{
    GitHub, cache_dir, config_path, fields_of, git, iso, json_pretty, parse_api, parse_time,
};
use super::flip_skip_python::{
    general, node_json, node_str, rounded, splitlines, truthy, value_str,
};
use super::legacy_verify::statement_document::{Document, Node};
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
        let runs = GitHub::pr_runs(self, since, until, workflow)?;
        let usage = if workflow == RELEASE_WORKFLOW {
            api::RunUse::Release
        } else {
            api::RunUse::Skip
        };
        for run in &runs {
            api::run(run, usage)?;
        }
        Ok(runs)
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
        && (actors.is_empty()
            || run
                .get("actor")
                .and_then(|actor| actor.get("login"))
                .and_then(Value::as_str)
                .is_some_and(|login| actors.contains(login)))
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
        let data = Document::from_text_with_depth_limit(&data, None)
            .map_err(|error| anyhow!("invalid required lanes JSON: {error:?}"))?;
        let lanes = node_get(&data, data.root(), "lanes")
            .filter(|node| truthy(*node))
            .unwrap_or(data.root());
        let Node::Object(lanes) = lanes else {
            return Err(anyhow!("required lanes must be an object"));
        };
        let mut parsed = Lanes::new();
        for (check, id) in lanes {
            let check = scalar_text(check)?;
            let lane = data.node(*id);
            if !matches!(lane, Node::Object(_)) {
                return Err(anyhow!("required lane definition must be an object"));
            }
            let paths = match node_get(&data, lane, "definition_paths").filter(|node| truthy(*node))
            {
                None => Vec::new(),
                Some(Node::Array(paths)) => paths
                    .iter()
                    .map(|id| match data.node(*id) {
                        Node::String(points) => scalar_text(points),
                        _ => Err(anyhow!("definition path must be text")),
                    })
                    .collect::<Result<_>>()?,
                Some(Node::String(points)) => points
                    .iter()
                    .map(|point| scalar_text(&[*point]))
                    .collect::<Result<_>>()?,
                Some(Node::Object(paths)) => paths
                    .keys()
                    .map(|points| scalar_text(points))
                    .collect::<Result<_>>()?,
                Some(_) => return Err(anyhow!("definition paths must be iterable")),
            };
            parsed.insert(check, paths);
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
    cache: &mut BTreeMap<String, Option<Document>>,
    check: &str,
) -> Result<bool> {
    let policy = match cache.entry(base.to_owned()) {
        std::collections::btree_map::Entry::Occupied(slot) => slot.into_mut(),
        std::collections::btree_map::Entry::Vacant(slot) => {
            let checks = match read_config(root, ".st/evidence-skip-policy.json", base) {
                Ok(text) => Document::from_text_with_depth_limit(&text, None).ok(),
                Err(error) if super::flip_ready::child_exited(&error) => None,
                Err(error) => return Err(error),
            };
            slot.insert(checks)
        }
    };
    let checks = policy.as_ref().and_then(|document| {
        node_get(document, document.root(), "checks").map(|checks| (document, checks))
    });
    Ok(
        match checks.and_then(|(document, checks)| {
            node_get(document, checks, check).map(|entry| (document, entry))
        }) {
            Some((document, entry @ Node::Object(_))) => {
                matches!(node_get(document, entry, "enforce"), Some(Node::Bool(true)))
            }
            _ => true,
        },
    )
}
fn node_get<'a>(document: &'a Document, node: &'a Node, key: &str) -> Option<&'a Node> {
    let Node::Object(values) = node else {
        return None;
    };
    values
        .iter()
        .find(|(points, _)| points.iter().copied().eq(key.chars().map(u32::from)))
        .map(|(_, id)| document.node(*id))
}
fn scalar_text(points: &[u32]) -> Result<String> {
    points
        .iter()
        .copied()
        .map(char::from_u32)
        .collect::<Option<String>>()
        .ok_or_else(|| anyhow!("configuration name or path contains a lone surrogate"))
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
        api::string(run.get("head_sha"), "commit head_sha")?
    );
    let pulls = parse_api(&source.gh(&["api", &path])?)?;
    api::first_pull(&pulls)
}
fn pr_files<'a>(
    source: &impl Source,
    number: u64,
    cache: &'a mut BTreeMap<u64, Vec<String>>,
) -> Result<&'a [String]> {
    if let std::collections::btree_map::Entry::Vacant(slot) = cache.entry(number) {
        let path = format!("repos/{}/pulls/{number}/files?per_page=100", source.repo());
        let pages: Vec<Vec<Value>> = serde_json::from_value(parse_api(&source.gh(&[
            "api",
            "--paginate",
            "--slurp",
            &path,
        ])?)?)?;
        let files = pages
            .into_iter()
            .flatten()
            .map(|item| api::string(item.get("filename"), "PR file filename").map(str::to_owned))
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
struct Receipt {
    document: Document,
    agent: usize,
}
impl Receipt {
    fn node(&self) -> &Node {
        self.document.node(self.agent)
    }
}
fn seats(receipts: &[PathBuf]) -> Result<BTreeMap<String, Receipt>> {
    let mut found = BTreeMap::new();
    for path in receipts {
        let Ok(bytes) = fs::read(path) else { continue };
        // Rust and Python both replace each maximal invalid UTF-8 subsequence.
        for line in splitlines(&String::from_utf8_lossy(&bytes)) {
            let Ok(document) = Document::from_text_with_depth_limit(line, None) else {
                continue;
            };
            let Node::Object(record) = document.root() else {
                continue;
            };
            let get = |key: &str| {
                record
                    .iter()
                    .find(|(points, _)| points.iter().copied().eq(key.chars().map(u32::from)))
                    .map(|(_, id)| *id)
            };
            let (Some(branch), Some(agent)) = (get("branch"), get("agent")) else {
                continue;
            };
            if !truthy(document.node(branch)) || !truthy(document.node(agent)) {
                continue;
            }
            if matches!(document.node(branch), Node::Array(_) | Node::Object(_)) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TypeError: unhashable receipt branch",
                )
                .into());
            }
            // GitHub head_branch is text; only text keys can match it.
            let Node::String(branch) = document.node(branch) else {
                continue;
            };
            let Some(branch) = branch
                .iter()
                .copied()
                .map(char::from_u32)
                .collect::<Option<String>>()
            else {
                continue;
            };
            found.insert(branch, Receipt { document, agent });
        }
    }
    Ok(found)
}
struct Report {
    value: Value,
    seats: BTreeMap<String, Receipt>,
}
impl std::ops::Deref for Report {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.value
    }
}
impl Report {
    fn receipt(&self, entry: &Value) -> Option<&Receipt> {
        entry["branch"]
            .as_str()
            .and_then(|branch| self.seats.get(branch))
    }
    fn json(&self) -> Result<String> {
        let mut out = String::new();
        self.write_json(&self.value, 0, &mut out)?;
        Ok(out)
    }
    fn write_json(&self, value: &Value, depth: usize, out: &mut String) -> Result<()> {
        use std::fmt::Write;
        match value {
            Value::Array(values) => {
                out.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(',');
                    }
                    write!(out, "\n{:width$}", "", width = (depth + 1) * 2)?;
                    self.write_json(value, depth + 1, out)?;
                }
                if !values.is_empty() {
                    write!(out, "\n{:width$}", "", width = depth * 2)?;
                }
                out.push(']');
            }
            Value::Object(values) => {
                out.push('{');
                for (index, (key, child)) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(',');
                    }
                    // Entries keep seats in the lossless receipt arena instead
                    // of projecting arbitrary Python JSON into serde_json.
                    if key == "checks" && depth == 2 && values.contains_key("pr") {
                        write!(out, "\n{:width$}\"seat\": ", "", width = (depth + 1) * 2)?;
                        match self.receipt(value) {
                            Some(receipt) => {
                                node_json(&receipt.document, receipt.node(), depth + 1, out)?
                            }
                            None => out.push_str("\"unknown\""),
                        }
                        out.push(',');
                    }
                    write!(out, "\n{:width$}", "", width = (depth + 1) * 2)?;
                    super::legacy_json::string(key, out)?;
                    out.push_str(": ");
                    self.write_json(child, depth + 1, out)?;
                }
                if !values.is_empty() {
                    write!(out, "\n{:width$}", "", width = depth * 2)?;
                }
                out.push('}');
            }
            _ => out.push_str(&json_pretty(value)?),
        }
        Ok(())
    }
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
        let id = api::number(run.get("id"), "release run id")?;
        for job in source.items(
            &format!(
                "repos/{}/actions/runs/{id}/jobs?per_page=100&filter=all",
                source.repo()
            ),
            "jobs",
        )? {
            api::job(&job, api::JobUse::Release)?;
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
        json!({"workflow": RELEASE_WORKFLOW, "runs": count, "minutes": rounded(minutes, 1), "macos_minutes": rounded(macos, 1), "prs": prs}),
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
) -> Result<Report> {
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
        for job in &jobs {
            api::job(job, api::JobUse::Skip)?;
        }
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
                if let (Some(n), Some(paths)) =
                    (number.filter(|number| *number != 0), lanes.get(check))
                {
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
    let by_branch = seats(receipts)?;
    let listed: Vec<Value> = unsigned.into_iter().map(|(pr, entry)| json!({"pr": pr, "branch": entry.branch, "checks": entry.checks, "runs": entry.runs.len()})).collect();
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
    Ok(Report {
        value: json!({"window": {"since": iso(since), "until": iso(until)}, "actors": actors, "runs": count, "checks": checks, "other_reasons": others, "not_signed": listed, "release_surface": release_surface(source, since, until, actors)?}),
        seats: by_branch,
    })
}
fn markdown(result: &Report) -> Result<String> {
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
                    .map(|category| value_str(&row[*category]))
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
            let seat = match result.receipt(entry) {
                Some(receipt) => node_str(&receipt.document, receipt.node())?,
                None => "unknown".to_owned(),
            };
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
        lines.extend([String::new(), format!("**Release-surface PR runs** ({} on pull_request, real release builds): {} runs, {} job minutes ({} on macOS){}", text(release, "workflow"), release["runs"], general(release["minutes"].as_f64().unwrap_or(0.0)), general(release["macos_minutes"].as_f64().unwrap_or(0.0)), if prs.is_empty() { String::new() } else { format!(": {prs}") })]);
    }
    Ok(lines.join("\n") + "\n")
}
fn emit(result: Result<Report>, as_markdown: bool) -> Result<i32> {
    match result {
        Ok(result) => {
            crate::cli_println!(
                "{}",
                if as_markdown {
                    markdown(&result)?
                } else {
                    result.json()?
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
