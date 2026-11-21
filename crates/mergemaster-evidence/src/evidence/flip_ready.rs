//! Read-only skip readiness and the explicit, opt-in proposal operation.
use anyhow::{Context, Result, anyhow, bail, ensure};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use clap::Args as ClapArgs;
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration as Sleep,
};

const POLICY: &str = ".st/evidence-skip-policy.json";
const WORKFLOW: &str = ".github/workflows/fleet.yml";
const DOC: &str = "docs/st3/gate-evidence.md";
const DOC_SECTION: &str = "### Which checks skip today";
const LOG_REF: &str = "refs/evidence-log/main";
const TEST_LISTS: [(&str, &str); 2] = [
    ("scripts/ci-evidence-gate-test", "enforced"),
    ("scripts/evidence-verify-test", "ENFORCED"),
];

#[derive(ClapArgs)]
pub struct Args {
    #[arg(long, default_value = "compoundingtech/fractal")]
    repo: String,
    #[arg(long)]
    cache: Option<PathBuf>,
    #[arg(long)]
    propose: bool,
    #[arg(long, requires = "propose")]
    dry_run: bool,
    #[arg(long, hide = true)]
    now: Option<String>,
}

pub fn parse_time(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}
pub fn iso(moment: DateTime<Utc>) -> String {
    moment.to_rfc3339_opts(SecondsFormat::Secs, true)
}
pub fn fields_of(text: &str) -> Value {
    Value::Object(
        text.split(' ')
            .filter_map(|part| {
                part.split_once('=')
                    .map(|(key, value)| (key.to_owned(), Value::String(value.to_owned())))
            })
            .collect(),
    )
}
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}
fn array(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or(&[])
}
fn tail(text: &str, count: usize) -> &str {
    if count == 0 {
        return "";
    }
    let start = text
        .char_indices()
        .rev()
        .nth(count - 1)
        .map(|(i, _)| i)
        .unwrap_or(0);
    &text[start..]
}
pub fn cache_dir() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cache")
        })
        .join("evidence-flip-ready")
}
#[derive(Debug)]
struct Unreadable(String);
impl std::fmt::Display for Unreadable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl std::error::Error for Unreadable {}
pub struct GitHub {
    pub repo: String,
    pub cache: PathBuf,
}
impl GitHub {
    pub fn gh(&self, args: &[&str]) -> Result<String> {
        let mut error = String::new();
        for attempt in 0..3 {
            let done = capture(Command::new("gh").args(args))?;
            if done.status.success() {
                return Ok(String::from_utf8_lossy(&done.stdout).into_owned());
            }
            error = tail(String::from_utf8_lossy(&done.stderr).trim(), 200).to_owned();
            if attempt < 2 {
                thread::sleep(Sleep::from_secs(1 << attempt));
            }
        }
        Err(Unreadable(format!(
            "gh {}: {error}",
            args.iter().take(2).copied().collect::<Vec<_>>().join(" ")
        ))
        .into())
    }
    pub fn items(&self, path: &str, key: &str) -> Result<Vec<Value>> {
        let pages: Vec<Value> =
            serde_json::from_str(&self.gh(&["api", "--paginate", "--slurp", path])?)?;
        let mut result = Vec::new();
        for mut page in pages {
            if let Some(items) = page.get_mut(key).and_then(Value::as_array_mut) {
                result.append(items);
            }
        }
        Ok(result)
    }
    fn decision_lines(&self, job_id: &Value) -> Result<Vec<String>> {
        let id = job_id.as_u64().ok_or_else(|| anyhow!("invalid job id"))?;
        let cached = self.cache.join(format!("{id}.lines"));
        if cached.exists() {
            return Ok(fs::read_to_string(cached)?
                .split('\n')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect());
        }
        let log = self.gh(&[
            "api",
            "--allow-escape-sequences",
            &format!("repos/{}/actions/jobs/{id}/logs", self.repo),
        ])?;
        let clean = strip_ansi(&log);
        let lines: Vec<String> = clean
            .lines()
            .filter_map(|line| {
                let line = if let Some((stamp, rest)) = line.split_once(' ') {
                    if stamp.ends_with('Z') { rest } else { line }
                } else {
                    line
                };
                line.strip_prefix("evidence-decision v1 ")
                    .filter(|s| s.starts_with("check=") && s.contains(' ') && !s.contains("$CHECK"))
                    .map(str::to_owned)
            })
            .collect();
        fs::create_dir_all(&self.cache)?;
        let partial = cached.with_extension(format!("{}.tmp", std::process::id()));
        fs::write(
            &partial,
            lines.iter().map(|s| format!("{s}\n")).collect::<String>(),
        )?;
        fs::rename(partial, cached)?;
        Ok(lines)
    }
    pub fn lines_of(&self, job: &Value) -> Result<Vec<String>> {
        match self.decision_lines(&job["id"]) {
            Err(error)
                if job["conclusion"] == "cancelled"
                    && error.downcast_ref::<Unreadable>().is_some() =>
            {
                Ok(Vec::new())
            }
            result => result,
        }
    }
    pub fn pr_runs(
        &self,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
        workflow: &str,
    ) -> Result<Vec<Value>> {
        let mut runs = indexmap::IndexMap::new();
        for page in 1..=10 {
            let path = format!(
                "repos/{}/actions/workflows/{workflow}/runs?event=pull_request&per_page=100&page={page}",
                self.repo
            );
            let mut batch = Vec::new();
            for attempt in 0..4 {
                let mut out: Value = serde_json::from_str(&self.gh(&["api", &path])?)?;
                let total = out["total_count"].as_u64().unwrap_or(0).min(1000) as usize;
                batch = out
                    .get_mut("workflow_runs")
                    .and_then(Value::as_array_mut)
                    .map(std::mem::take)
                    .unwrap_or_default();
                let expected = total
                    .saturating_sub((page - 1) * 100)
                    .min(100)
                    .max(usize::from(page == 1));
                if batch.len() >= expected {
                    break;
                }
                if attempt == 3 {
                    bail!(
                        "page {page} of the pull request run listing came back with {} of the {expected} runs it holds",
                        batch.len()
                    );
                }
                thread::sleep(Sleep::from_secs(1 << attempt));
            }
            let reached_end = batch.len() < 100
                || batch
                    .iter()
                    .any(|run| parse_time(text(run, "created_at")).is_some_and(|t| t < since));
            for run in batch {
                if parse_time(text(&run, "created_at")).is_some_and(|t| t >= since && t <= until) {
                    runs.insert(
                        run["id"]
                            .as_u64()
                            .ok_or_else(|| anyhow!("invalid run id"))?,
                        run,
                    );
                }
            }
            if reached_end {
                return Ok(runs.into_values().collect());
            }
        }
        bail!("more than the listing's 1,000 runs since {}", iso(since))
    }
}
fn strip_ansi(input: &str) -> String {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            while let Some(c) = chars.peek() {
                if c.is_ascii_digit() || *c == ';' {
                    chars.next();
                } else {
                    break;
                }
            }
            if chars.peek().is_some_and(char::is_ascii_alphabetic) {
                chars.next();
            }
        } else {
            out.push(c);
        }
    }
    out
}
fn capture(command: &mut Command) -> std::io::Result<std::process::Output> {
    crate::gate::git::deadline::GitChild::capture(command, None, Sleep::from_secs(300))
}
pub fn git(root: &Path, args: &[&str]) -> Result<String> {
    let done = capture(Command::new("git").arg("-C").arg(root).args(args))?;
    ensure!(
        done.status.success(),
        "git {}: {}",
        args.first().copied().unwrap_or(""),
        tail(String::from_utf8_lossy(&done.stderr).trim(), 300)
    );
    Ok(String::from_utf8_lossy(&done.stdout).into_owned())
}
pub fn config_path(root: &Path, path: &str, revision: Option<&str>) -> Result<String> {
    let new = path.replacen(".st/", ".fractal/", 1);
    let exists = match revision {
        Some(rev) => !git(root, &["ls-tree", "--full-tree", "-z", rev, "--", &new])?.is_empty(),
        None => match fs::symlink_metadata(root.join(&new)) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        },
    };
    Ok(if exists { new } else { path.to_owned() })
}
fn member_of(name: &str, members: &[String]) -> bool {
    members
        .iter()
        .any(|key| name == key || name.strip_prefix(key).is_some_and(|s| s.starts_with(" (")))
}
fn derived_result<'a>(values: impl Iterator<Item = &'a str>) -> Option<String> {
    let mut success = false;
    for value in values {
        if matches!(value, "failure" | "cancelled") {
            return Some("failure".to_owned());
        }
        success |= value == "success";
    }
    success.then(|| "success".to_owned())
}
fn skipped_members(
    workflow: &str,
    policy: &Map<String, Value>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut jobs: BTreeMap<&str, String> = BTreeMap::new();
    let mut current = None;
    for line in workflow.split_inclusive('\n') {
        if let Some(name) = line
            .strip_prefix("  ")
            .and_then(|s| s.strip_suffix(":\n"))
            .filter(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            })
        {
            jobs.entry(name).or_default();
            current = Some(name);
        } else if line.starts_with("    ") || line.trim().is_empty() {
            if let Some(name) = current
                && let Some(body) = jobs.get_mut(name)
            {
                body.push_str(line);
            }
        } else {
            current = None;
        }
    }
    let mut members = BTreeMap::new();
    for (check, entry) in policy {
        let reads = format!("needs.evidence-gate-{check}.outputs.skip");
        let aggregate = entry
            .pointer("/kinds/wrapper/command/1")
            .is_some_and(|v| v == "aggregate");
        if aggregate || !jobs.contains_key(check.as_str()) {
            let found: Vec<String> = jobs
                .iter()
                .filter(|(name, body)| {
                    **name != check
                        && if aggregate {
                            body.contains(&reads)
                        } else {
                            body.lines().any(|line| {
                                line.strip_prefix("    if: ")
                                    .is_some_and(|s| s.contains(&reads))
                            })
                        }
                })
                .map(|(name, _)| (*name).to_owned())
                .collect();
            ensure!(
                !aggregate || !found.is_empty(),
                "no job of {WORKFLOW} reads the skip output of the aggregate {check}"
            );
            members.insert(check.clone(), found);
        }
    }
    Ok(members)
}
fn no_evidence(run: &Value, jobs: &[&Value], needed: &[String], own: Option<&str>) -> bool {
    run["conclusion"] == "cancelled"
        && if needed.is_empty() {
            own != Some("failure")
        } else {
            !jobs
                .iter()
                .any(|job| member_of(text(job, "name"), needed) && job["conclusion"] == "failure")
        }
}
#[derive(Clone)]
struct Row {
    check: String,
    run: u64,
    created: Option<DateTime<Utc>>,
    actor: String,
    base: String,
    fields: Value,
    real: Option<String>,
    aggregate: bool,
    members_red: Vec<String>,
    cancelled: bool,
    old_base: Option<String>,
}
fn collect(
    github: &GitHub,
    checks: &Map<String, Value>,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    members: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for run in github.pr_runs(since, until, "fleet.yml")? {
        if run["status"] != "completed" {
            continue;
        }
        let jobs = github.items(
            &format!(
                "repos/{}/actions/runs/{}/jobs?per_page=100&filter=all",
                github.repo, run["id"]
            ),
            "jobs",
        )?;
        for job in &jobs {
            let Some(check) = text(job, "name").strip_prefix("evidence-gate-") else {
                continue;
            };
            if !checks.contains_key(check)
                || job["status"] != "completed"
                || job["conclusion"] == "skipped"
            {
                continue;
            }
            let same: Vec<&Value> = jobs
                .iter()
                .filter(|other| other["run_attempt"] == job["run_attempt"])
                .collect();
            let needed = members.get(check).map(Vec::as_slice).unwrap_or(&[]);
            let own = same
                .iter()
                .rev()
                .find(|other| other["name"] == check)
                .and_then(|other| other["conclusion"].as_str())
                .map(str::to_owned)
                .or_else(|| {
                    members
                        .contains_key(check)
                        .then(|| {
                            derived_result(
                                same.iter()
                                    .filter(|other| member_of(text(other, "name"), needed))
                                    .map(|other| text(other, "conclusion")),
                            )
                        })
                        .flatten()
                });
            let reds: Vec<String> = same
                .iter()
                .filter(|other| {
                    member_of(text(other, "name"), needed)
                        && matches!(text(other, "conclusion"), "failure" | "cancelled")
                })
                .map(|other| text(other, "name").to_owned())
                .collect();
            let cancelled = no_evidence(&run, &same, needed, own.as_deref());
            for line in github.lines_of(job)? {
                let fields = fields_of(&line);
                if fields["check"] != check {
                    continue;
                }
                rows.push(Row {
                    check: check.to_owned(),
                    run: run["id"]
                        .as_u64()
                        .ok_or_else(|| anyhow!("invalid run id"))?,
                    created: parse_time(text(&run, "created_at")),
                    actor: run
                        .pointer("/actor/login")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("-")
                        .to_owned(),
                    base: run
                        .pointer("/pull_requests/0/base/sha")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                    fields,
                    real: own.clone(),
                    aggregate: members.contains_key(check),
                    members_red: reds.clone(),
                    cancelled,
                    old_base: None,
                });
            }
        }
    }
    Ok(rows)
}
fn valid_hex(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn old_base(
    root: &Path,
    row: &Row,
    seen: &mut BTreeMap<(String, String, String), bool>,
) -> Option<String> {
    let reason = text(&row.fields, "reason");
    let base = row
        .fields
        .get("base")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(&row.base);
    if row.fields["outcome"] != "unavailable"
        || row.fields.get("log").and_then(Value::as_str).unwrap_or("-") != "-"
        || !matches!(reason, "no_policy" | "no-gate-at-base")
        || !valid_hex(base, &[40])
    {
        return None;
    }
    let key = (base.to_owned(), reason.to_owned(), row.check.clone());
    let predates = *seen.entry(key).or_insert_with(|| {
        let commit = format!("{base}^{{commit}}");
        if git(root, &["cat-file", "-e", &commit]).is_err()
            && (git(root, &["fetch", "-q", "origin", base]).is_err()
                || git(root, &["cat-file", "-e", &commit]).is_err())
        {
            return false;
        }
        if reason == "no-gate-at-base" {
            return git(
                root,
                &[
                    "cat-file",
                    "-e",
                    &format!("{base}:scripts/ci-evidence-gate"),
                ],
            )
            .is_err();
        }
        let read = || -> Result<bool> {
            let path = config_path(root, POLICY, Some(base))?;
            if git(root, &["ls-tree", "--full-tree", "-z", base, "--", &path])?.is_empty() {
                return Ok(true);
            }
            let policy: Value =
                serde_json::from_str(&git(root, &["show", &format!("{base}:{path}")])?)?;
            Ok(!policy["checks"]
                .as_object()
                .ok_or_else(|| anyhow!("invalid policy"))?
                .contains_key(&row.check))
        };
        read().unwrap_or(false)
    });
    predates.then(|| reason.to_owned())
}
struct PublishedLog {
    repo: PathBuf,
    heads: Vec<(DateTime<Utc>, String)>,
}
impl PublishedLog {
    fn load(root: &Path, cache: &Path, since: DateTime<Utc>) -> Result<Self> {
        let url = git(root, &["remote", "get-url", "origin"])
            .map_err(|_| anyhow!("origin has no URL"))?;
        let repo = cache.join("log.git");
        if !repo.join("objects").is_dir() {
            let _ = capture(
                Command::new("git")
                    .args(["init", "-q", "--bare"])
                    .arg(&repo),
            )?;
        }
        let fetched = capture(Command::new("git").arg("-C").arg(&repo).args([
            "fetch",
            "-q",
            "--no-tags",
            &format!("--shallow-since={}", iso(since - Duration::hours(1))),
            url.trim(),
            &format!("+{LOG_REF}:{LOG_REF}"),
        ]))?;
        ensure!(
            fetched.status.success(),
            "the published log: {}",
            tail(String::from_utf8_lossy(&fetched.stderr).trim(), 160)
        );
        let listed = capture(Command::new("git").arg("-C").arg(&repo).args([
            "log",
            "--format=%H %s",
            LOG_REF,
        ]))?;
        let mut heads = Vec::new();
        for line in String::from_utf8_lossy(&listed.stdout).lines() {
            let Some((head, subject)) = line.split_once(' ') else {
                continue;
            };
            if let Some(moment) = subject
                .split(' ')
                .find_map(|s| s.strip_prefix("as_of=").and_then(parse_time))
            {
                heads.push((moment, head.to_owned()));
            }
        }
        heads.sort();
        ensure!(
            !heads.is_empty(),
            "the published log has no head with a time"
        );
        Ok(Self { repo, heads })
    }
    fn lists(&self, moment: DateTime<Utc>, records: &[String]) -> bool {
        let Some((_, head)) = self.heads.iter().rev().find(|(when, _)| *when <= moment) else {
            return false;
        };
        records.iter().all(|record| {
            git(
                &self.repo,
                &["grep", "-q", "-F", "-e", &format!("record {record}"), head],
            )
            .is_ok()
        })
    }
}
fn no_time(text: Option<&str>) -> bool {
    matches!(text, None | Some("-" | "None"))
}
fn unlogged_records(fields: &Value) -> Option<Vec<String>> {
    let crates = fields.get("log_unlogged_crates").and_then(Value::as_str);
    if !no_time(crates) {
        let records: Option<Vec<String>> = crates
            .unwrap_or_default()
            .split('+')
            .map(|item| {
                if item.ends_with("_more") {
                    return None;
                }
                let record = item.split_once('=').map(|(_, value)| value)?;
                (record.len() >= 12 && record.len() <= 64 && valid_hex(record, &[record.len()]))
                    .then(|| record.to_owned())
            })
            .collect();
        return records;
    }
    let record = text(fields, "record");
    valid_hex(record, &[40, 64]).then(|| vec![record.to_owned()])
}
fn explained(row: &Row, published: Option<&PublishedLog>) -> bool {
    let Some(created) = row.created else {
        return false;
    };
    let unlogged = row
        .fields
        .get("log_unlogged_observed_at")
        .and_then(Value::as_str);
    let observed = parse_time(if no_time(unlogged) {
        text(&row.fields, "observed_at")
    } else {
        unlogged.unwrap_or_default()
    });
    if observed.is_some_and(|t| t >= created) {
        return true;
    }
    if let (Some(log), Some(records)) = (published, unlogged_records(&row.fields)) {
        return log.lists(created + Duration::seconds(240), &records);
    }
    observed.is_some_and(|t| created.signed_duration_since(t) <= Duration::seconds(240))
}
fn log_value(row: &Row) -> &str {
    row.fields.get("log").and_then(Value::as_str).unwrap_or("-")
}
fn evaluate<'a>(
    rows: impl IntoIterator<Item = &'a Row>,
    enforce: bool,
    now: DateTime<Utc>,
    lowered: bool,
    published: Option<&PublishedLog>,
) -> Value {
    let start = now - Duration::days(1);
    let mut rows: Vec<&Row> = rows
        .into_iter()
        .filter(|row| row.created.is_some())
        .collect();
    rows.sort_by_key(|row| row.created);
    let window: Vec<&Row> = rows
        .iter()
        .copied()
        .filter(|row| row.created.is_some_and(|t| t >= start && t <= now))
        .collect();
    let unexplained = window
        .iter()
        .filter(|row| log_value(row) == "unlogged_pass" && !explained(row, published))
        .count();
    let counted: Vec<&Row> = window
        .iter()
        .copied()
        .filter(|row| !row.cancelled)
        .collect();
    let red: Vec<&Row> = counted
        .iter()
        .copied()
        .filter(|row| {
            row.fields["outcome"] == "satisfied" && row.real.as_deref() == Some("failure")
        })
        .collect();
    let hidden: BTreeSet<u64> = red
        .iter()
        .filter(|row| !row.aggregate || !row.members_red.is_empty())
        .map(|row| row.run)
        .collect();
    let visible: BTreeSet<u64> = red
        .iter()
        .map(|row| row.run)
        .filter(|run| !hidden.contains(run))
        .collect();
    let cancelled: BTreeSet<u64> = window
        .iter()
        .filter(|row| row.cancelled)
        .map(|row| row.run)
        .collect();
    let mut ignored: BTreeMap<String, usize> = BTreeMap::new();
    for row in &window {
        if let Some(reason) = &row.old_base {
            *ignored.entry(reason.clone()).or_default() += 1;
        }
    }
    rows.retain(|row| row.old_base.is_none());
    let after = rows
        .iter()
        .rposition(|row| log_value(row) == "-")
        .map(|i| i + 1)
        .unwrap_or(0);
    let began = rows.get(after).and_then(|row| row.created);
    let satisfied = counted
        .iter()
        .filter(|row| log_value(row) == "ok" && row.fields["outcome"] == "satisfied")
        .count();
    let missing = window
        .iter()
        .filter(|row| log_value(row) == "missing")
        .count();
    let mut result = json!({"enforce":enforce,"lines":window.len(),"satisfied_log_ok":satisfied,"log_missing":missing,"unlogged_pass_unexplained":unexplained,"hidden_red":hidden,"visible_red":visible,"log_window_start":began.map(iso),"old_base_lines":ignored,"cancelled_runs":cancelled});
    let mut why = Vec::new();
    for value in ["stale", "absent", "unsigned", "-"] {
        let count = window
            .iter()
            .filter(|row| row.old_base.is_none() && log_value(row) == value)
            .count();
        if count > 0 {
            why.push(format!("{count} lines with log={value}"));
        }
    }
    match began {
        None => why.push("no line with a log value".to_owned()),
        Some(time) if time > start => why.push(format!(
            "log window started {}, less than 24 h ago",
            iso(time)
        )),
        _ => {}
    }
    if lowered {
        let mine: Vec<&Row> = counted
            .iter()
            .copied()
            .filter(|row| {
                row.fields["outcome"] == "satisfied" && row.fields["trust_level"] == "host"
            })
            .collect();
        let agreeing = mine
            .iter()
            .filter(|row| log_value(row) == "ok" && row.real.as_deref() == Some("success"))
            .count();
        let disagreeing: BTreeSet<u64> = mine
            .iter()
            .filter(|row| row.real.as_deref() == Some("failure"))
            .map(|row| row.run)
            .collect();
        if agreeing < 5 {
            why.push(format!(
                "{agreeing} agreeing host lines (satisfied, log=ok, real job success), fewer than 5"
            ));
        }
        if !disagreeing.is_empty() {
            why.push(format!(
                "{} runs where a host note disagreed with the real job",
                disagreeing.len()
            ));
        }
        result["agreeing"] = json!(agreeing);
        result["disagreeing"] = json!(disagreeing);
    } else if satisfied < 30 {
        why.push(format!(
            "{satisfied} satisfied lines with log=ok, fewer than 30"
        ));
    }
    if missing > 0 {
        why.push(format!("{missing} lines with log=missing"));
    }
    if unexplained > 0 {
        why.push(format!("{unexplained} unexplained log=unlogged_pass"));
    }
    if !hidden.is_empty() {
        why.push(format!("{} runs with a hidden red", hidden.len()));
    }
    result["ready"] = json!(why.is_empty());
    result["why_not"] = json!(why);
    result
}
fn preconditions(
    mut result: Value,
    check: &str,
    entry: &Value,
    members: Option<&Vec<String>>,
) -> Value {
    let mut why = array(&result["why_not"]).to_vec();
    if check == "linux-gate" {
        let missing: Vec<&str> = ["host", "agent"]
            .into_iter()
            .filter(|level| {
                !array(&entry["kinds"]["wrapper"]["by_level"][*level]["required_inputs"])
                    .iter()
                    .any(|input| input == "clippy_base_sha")
            })
            .collect();
        if !missing.is_empty() {
            why.push(json!(format!(
                "the policy does not require clippy_base_sha of {} linux-gate notes",
                missing.join(" and ")
            )));
        }
    }
    if check == "fractal-web" {
        let wrapper = &entry["kinds"]["wrapper"];
        if wrapper["input_order"]["kit_inputs"] != json!(["true", "false"]) {
            why.push(json!(
                "the policy does not order kit_inputs (true before false) for fractal-web notes"
            ));
        }
        if wrapper["shard_inputs"].is_null()
            || wrapper["shard_inputs"]
                .as_object()
                .is_some_and(Map::is_empty)
            || wrapper["shard_inputs"] == false
        {
            why.push(json!(
                "the policy does not check the shard inputs of fractal-web notes"
            ));
        }
    }
    if members.is_some_and(Vec::is_empty) {
        why.push(json!(format!(
            "no job of {WORKFLOW} skips on its skip output"
        )));
    }
    result["ready"] = json!(why.is_empty());
    result["why_not"] = json!(why);
    result
}
fn presign_rates(rows: &[Row], now: DateTime<Utc>) -> Value {
    let mut heads: BTreeMap<(&str, &str, &str), usize> = BTreeMap::new();
    for row in rows {
        if !row
            .created
            .is_some_and(|t| t >= now - Duration::days(1) && t <= now)
        {
            continue;
        }
        let f = &row.fields;
        let head = match f.get("pr_head").and_then(Value::as_str).unwrap_or("-") {
            "-" => f.get("head").and_then(Value::as_str).unwrap_or("-"),
            head => head,
        };
        let level = if matches!(text(f, "outcome"), "satisfied" | "degraded") {
            text(f, "trust_level")
        } else {
            ""
        };
        let rank = match level {
            "host" | "agent" => 2,
            "fleet" => 1,
            _ => 0,
        };
        let best = heads
            .entry((
                row.actor.as_str(),
                f.get("pr").and_then(Value::as_str).unwrap_or("-"),
                head,
            ))
            .or_default();
        *best = (*best).max(rank);
    }
    let mut counts: BTreeMap<&str, [usize; 3]> = BTreeMap::new();
    for ((actor, _, _), rank) in heads {
        counts.entry(actor).or_default()[rank] += 1;
    }
    Value::Object(counts.into_iter().map(|(actor, counts)| { let total: usize = counts.iter().sum(); (actor.to_owned(), json!({"heads":total,"presigned":counts[2],"ci_note":counts[1],"no_note":counts[0],"presigned_share":((counts[2] as f64 / total as f64)*1000.0).round_ties_even()/1000.0})) }).collect())
}

pub fn run(args: Args) -> Result<i32> {
    let parts: Vec<&str> = args.repo.split('/').collect();
    if parts.len() != 2
        || !parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        })
    {
        eprintln!("error: bad --repo, or --dry-run without --propose");
        return Ok(2);
    }
    let root = std::env::current_dir()?;
    let now = match args.now {
        Some(value) => parse_time(&value).ok_or_else(|| anyhow!("invalid --now"))?,
        None => Utc::now(),
    };
    let now =
        DateTime::from_timestamp(now.timestamp(), 0).ok_or_else(|| anyhow!("invalid clock"))?;
    let github = GitHub {
        repo: args.repo,
        cache: args.cache.unwrap_or_else(cache_dir),
    };
    let since = now - Duration::hours(26);
    let read = || -> Result<_> {
        git(&root, &["fetch", "-q", "origin", "main"])?;
        let path = config_path(&root, POLICY, Some("origin/main"))?;
        let policy: Value =
            serde_json::from_str(&git(&root, &["show", &format!("origin/main:{path}")])?)?;
        let checks = policy["checks"]
            .as_object()
            .ok_or_else(|| anyhow!("invalid checks"))?
            .clone();
        let members = skipped_members(
            &git(&root, &["show", &format!("origin/main:{WORKFLOW}")])?,
            &checks,
        )?;
        let mut rows = collect(&github, &checks, since, now, &members)?;
        let mut seen = BTreeMap::new();
        for row in &mut rows {
            row.old_base = old_base(&root, row, &mut seen);
        }
        Ok((checks, members, rows))
    };
    let (policy, members, rows) = match read() {
        Ok(result) => result,
        Err(error) => {
            eprintln!("could not read GitHub or origin/main: {error}");
            return Ok(2);
        }
    };
    let log = PublishedLog::load(&root, &github.cache, since);
    let clock = match &log {
        Ok(_) => "published log".to_owned(),
        Err(error) => format!("observed_at ({error})"),
    };
    let mut checks = Map::new();
    for (check, entry) in &policy {
        checks.insert(
            check.clone(),
            preconditions(
                evaluate(
                    rows.iter().filter(|row| row.check == *check),
                    entry["enforce"] == true,
                    now,
                    check == "rust-tests",
                    log.as_ref().ok(),
                ),
                check,
                entry,
                members.get(check),
            ),
        );
    }
    let report = json!({"as_of":iso(now),"window_s":86400,"log_clock":clock,"checks":checks,"presign":presign_rates(&rows, now)});
    crate::cli_println!("{}", json_pretty(&report)?);
    if args.propose {
        propose(
            &report,
            &root,
            &github,
            args.dry_run,
            &now.date_naive().to_string(),
        )
    } else {
        Ok(0)
    }
}

pub(super) fn json_pretty(value: &Value) -> Result<String> {
    use std::fmt::Write as _;
    let text = serde_json::to_string_pretty(value)?;
    if text.bytes().all(|byte| byte < 127) {
        return Ok(text);
    }
    // json.dumps defaults to ensure_ascii, including UTF-16 surrogate pairs.
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if character < '\u{7f}' {
            escaped.push(character);
        } else {
            let mut units = [0; 2];
            for unit in character.encode_utf16(&mut units) {
                write!(escaped, "\\u{unit:04x}")?;
            }
        }
    }
    Ok(escaped)
}
fn pretty(value: &Value) -> Result<String> {
    let mut text = json_pretty(value)?;
    text.push('\n');
    Ok(text)
}
fn flipped_entry(entry: &Value, lowered: bool) -> Result<Value> {
    let object = entry
        .as_object()
        .ok_or_else(|| anyhow!("invalid policy entry"))?;
    let mut out = Map::new();
    for (key, value) in object {
        out.insert(
            key.clone(),
            match key.as_str() {
                "enforce" => json!(true),
                "sample_one_in" => json!(1),
                _ => value.clone(),
            },
        );
        if key == "enforce" {
            out.entry("events".to_owned()).or_insert_with(|| {
                object
                    .get("events")
                    .cloned()
                    .unwrap_or_else(|| json!(["pull_request"]))
            });
            out.entry("sample_one_in".to_owned()).or_insert(json!(1));
        }
    }
    if lowered {
        let levels = out
            .get("kinds")
            .and_then(|k| k.get("wrapper"))
            .and_then(|w| w.get("trust_levels"))
            .and_then(Value::as_array)
            .ok_or_else(|| {
                anyhow!("{POLICY}: the wrapper kind does not already trust host, agent, queue")
            })?;
        ensure!(
            ["host", "agent", "queue"]
                .iter()
                .all(|level| levels.iter().any(|v| v.as_str() == Some(*level))),
            "{POLICY}: the wrapper kind does not already trust host, agent, queue"
        );
        let narrowed: Vec<Value> = levels
            .iter()
            .filter(|v| matches!(v.as_str(), Some("host" | "agent" | "queue")))
            .cloned()
            .collect();
        let mut value = Value::Object(out);
        value["kinds"]["wrapper"]["trust_levels"] = json!(narrowed);
        return Ok(value);
    }
    Ok(Value::Object(out))
}
fn flip_policy(text: &str, check: &str) -> Result<(String, Value)> {
    let doc: Value = serde_json::from_str(text)?;
    let entry = &doc["checks"][check];
    ensure!(
        entry.is_object() && entry["enforce"] == false,
        "{POLICY}: {check} has no \"enforce\": false"
    );
    let expected_entry = flipped_entry(entry, check == "rust-tests")?;
    let mut expected = doc.clone();
    expected["checks"][check] = expected_entry.clone();
    if pretty(&doc)? == text {
        return Ok((pretty(&expected)?, expected_entry));
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
    for (i, line) in lines.iter().enumerate() {
        if i == enforce {
            output.push_str(&format!("{pad}\"enforce\": true,\n"));
            for key in ["events", "sample_one_in"] {
                if entry.get(key).is_none() {
                    let compact =
                        serde_json::to_string(&expected_entry[key])?.replace("\",\"", "\", \"");
                    output.push_str(&format!("{pad}\"{key}\": {compact},\n"));
                }
            }
        } else if i > block
            && !sample_replaced
            && entry.get("sample_one_in").is_some()
            && line.starts_with(&format!("{pad}\"sample_one_in\": "))
        {
            let comma = if line.trim_end().ends_with(',') {
                ","
            } else {
                ""
            };
            output.push_str(&format!("{pad}\"sample_one_in\": 1{comma}\n"));
            sample_replaced = true;
        } else {
            output.push_str(line);
        }
    }
    ensure!(
        serde_json::from_str::<Value>(&output)? == expected,
        "{POLICY}: a textual edit of {check} would not give the expected policy"
    );
    Ok((output, expected_entry))
}
fn flip_doc(text: &str, check: &str, entry: &Value, today: &str) -> Result<String> {
    let head = text
        .find(&format!("{DOC_SECTION}\n"))
        .ok_or_else(|| anyhow!("{DOC}: no \"{DOC_SECTION}\" section"))?;
    let mut lines: Vec<String> = text[head..].split('\n').map(str::to_owned).collect();
    let table: Vec<usize> = lines
        .iter()
        .take(20)
        .enumerate()
        .filter(|(_, line)| line.starts_with('|'))
        .map(|(i, _)| i)
        .collect();
    ensure!(
        table.len() >= 3 && table.windows(2).all(|w| w[1] == w[0] + 1),
        "{DOC}: no table under \"{DOC_SECTION}\""
    );
    let name = format!("`{check}`");
    let cells = |line: &str| {
        line.trim_matches('|')
            .split('|')
            .map(|s| s.trim().to_owned())
            .collect::<Vec<_>>()
    };
    let mut found = None;
    for i in table.iter().skip(2) {
        let row = cells(&lines[*i]);
        if row.len() != 5 || row[1] != "false" {
            continue;
        }
        let names: Vec<String> = row[0].split(',').map(|s| s.trim().to_owned()).collect();
        if let Some(mine) = names
            .iter()
            .find(|part| **part == name || part.starts_with(&format!("{name} (")))
        {
            found = Some((
                *i,
                names
                    .iter()
                    .filter(|part| *part != mine)
                    .cloned()
                    .collect::<Vec<_>>(),
                mine.clone(),
                row,
            ));
        }
    }
    let (row, rest, name, old) = found
        .ok_or_else(|| anyhow!("{DOC}: {check} is not in a row of the table with enforce false"))?;
    let events = array(&entry["events"])
        .iter()
        .filter_map(Value::as_str)
        .map(|event| format!("`{event}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let new_row = format!(
        "| {name} | true | {events} | {} | {today} |",
        entry["sample_one_in"]
    );
    let after = table
        .iter()
        .skip(2)
        .copied()
        .filter(|i| cells(&lines[*i]).get(1).is_some_and(|s| s == "true"))
        .max()
        .unwrap_or(table[1]);
    if rest.is_empty() {
        lines[row].clear();
    } else {
        lines[row] = format!("| {} | {} |", rest.join(", "), old[1..].join(" | "));
    }
    if rest.is_empty() {
        lines.remove(row);
    }
    lines.insert(after + 1, new_row);
    Ok(format!("{}{}", &text[..head], lines.join("\n")))
}
fn flip_test_list(text: &str, path: &str, name: &str, check: &str) -> Result<String> {
    let marker = format!("{name} = ");
    let found: Vec<&str> = text
        .lines()
        .filter(|line| line.trim_start().starts_with(&marker) && line.ends_with(')'))
        .collect();
    ensure!(
        found.len() == 1,
        "{path}: expected one `{name} = (...)` line, found {}",
        found.len()
    );
    let line = found[0];
    let tuple = line
        .trim_start()
        .strip_prefix(&marker)
        .ok_or_else(|| anyhow!("invalid test list"))?;
    ensure!(
        tuple.starts_with('('),
        "{path}: {name} is not a tuple without {check}"
    );
    let mut listed = Vec::new();
    // The pinned lists are tuples of literal check names, not arbitrary Python.
    for item in tuple[1..tuple.len() - 1]
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let quote = item
            .chars()
            .next()
            .ok_or_else(|| anyhow!("invalid tuple"))?;
        ensure!(
            matches!(quote, '\'' | '"') && item.ends_with(quote) && item.len() >= 2,
            "{path}: {name} is not a tuple without {check}"
        );
        let item = &item[1..item.len() - 1];
        ensure!(
            !item.contains(['\\', '\'', '"']),
            "{path}: {name} is not a tuple without {check}"
        );
        listed.push(item);
    }
    ensure!(
        !listed.contains(&check),
        "{path}: {name} is not a tuple without {check}"
    );
    listed.push(check);
    let suffix = if listed.len() == 1 { "," } else { "" };
    let new_tuple = format!(
        "({}{suffix})",
        listed
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(text.replacen(tuple, &new_tuple, 1))
}
fn release_note(check: &str) -> Value {
    json!({
        "version":1,
        "summary":format!("Pull requests now skip the {check} check when a trusted signed note already covers the tree (no run is sampled); the merge queue keeps running it"),
        "replay":{"status":"none","detail":"No graph, claim or storage change."},
        "schema":{"status":"none","detail":"No schema change."},
        "rules":{"status":"none","detail":format!("No checkpoint rule change. {check} is enforced in the skip policy for pull_request only.")},
        "compatibility":{"status":"none","detail":format!("Required check names and results are unchanged: a skipped {check} job still ends in success. Merge-group runs are unchanged.")},
        "downtime":{"status":"none","detail":"No restart."},
        "manual":{"status":"none","detail":"No manual step."},
        "recovery":{"status":"none","detail":format!("Set enforce back to false for {check} in {POLICY} (the policy is read from the base, so it takes effect for runs after the revert merges).")}
    })
}
fn flip(tree: &Path, check: &str, today: &str) -> Result<()> {
    let note = format!("release-notes/evidence-enforce-{check}.json");
    ensure!(!tree.join(&note).exists(), "{note} already exists");
    let path = config_path(tree, POLICY, None)?;
    let (policy, entry) = flip_policy(&fs::read_to_string(tree.join(&path))?, check)?;
    // Compute every mechanical edit before writing any of them.
    let mut edits = vec![
        (path, policy),
        (
            DOC.to_owned(),
            flip_doc(&fs::read_to_string(tree.join(DOC))?, check, &entry, today)?,
        ),
    ];
    for (path, name) in TEST_LISTS {
        edits.push((
            path.to_owned(),
            flip_test_list(&fs::read_to_string(tree.join(path))?, path, name, check)?,
        ));
    }
    for (path, text) in edits {
        fs::write(tree.join(path), text)?;
    }
    fs::create_dir_all(tree.join("release-notes"))?;
    fs::write(tree.join(note), pretty(&release_note(check))?)?;
    Ok(())
}
fn propose(
    report: &Value,
    root: &Path,
    github: &GitHub,
    dry_run: bool,
    today: &str,
) -> Result<i32> {
    let mut failed = false;
    let checks = report["checks"]
        .as_object()
        .ok_or_else(|| anyhow!("invalid report"))?;
    for (check, entry) in checks {
        if entry["ready"] != true || entry["enforce"] == true {
            continue;
        }
        let branch = format!("evidence-flip/{check}");
        let listed = github
            .gh(&[
                "pr",
                "list",
                "--repo",
                &github.repo,
                "--head",
                &branch,
                "--state",
                "open",
                "--json",
                "number",
            ])
            .and_then(|s| Ok(serde_json::from_str::<Value>(&s)?));
        let open = match listed {
            Ok(value) => value,
            Err(error) => {
                eprintln!("{check}: not proposed: could not list pull requests: {error}");
                failed = true;
                continue;
            }
        };
        if let Some(pr) = array(&open).first() {
            eprintln!("{check}: #{} is already open from {branch}", pr["number"]);
            continue;
        }
        let scratch = tempfile::Builder::new()
            .prefix("evidence-flip-")
            .tempdir()?;
        let tree = scratch.path().join("tree");
        let tree_arg = tree.to_str().context("non-UTF8 worktree")?;
        git(
            root,
            &["worktree", "add", "-q", "--detach", tree_arg, "origin/main"],
        )?;
        let operation = || -> Result<()> {
            if let Err(error) = flip(&tree, check, today) {
                eprintln!("{check}: not proposed, the flip cannot be made mechanically: {error}");
                bail!("mechanical flip");
            }
            git(&tree, &["add", "-A"])?;
            if dry_run {
                crate::cli_print!("{}", git(&tree, &["diff", "--cached"])?);
                return Ok(());
            }
            let mut trigger =
                json!({"as_of":report["as_of"],"window_s":report["window_s"],"check":check});
            trigger
                .as_object_mut()
                .ok_or_else(|| anyhow!("invalid trigger"))?
                .extend(
                    entry
                        .as_object()
                        .ok_or_else(|| anyhow!("invalid check"))?
                        .clone(),
                );
            let trigger = json_pretty(&trigger)?;
            let message = format!(
                "Enforce the {check} evidence skip on pull requests\n\nThe flip trigger held (scripts/evidence-flip-ready, docs/st3/gate-evidence.md):\n\n{trigger}\n"
            );
            git(&tree, &["commit", "-q", "-m", &message])?;
            git(
                &tree,
                &["push", "-q", "origin", &format!("HEAD:refs/heads/{branch}")],
            )?;
            let body = format!(
                "Turns on skipping for `{check}` on pull requests (`\"enforce\": true`, `\"events\": [\"pull_request\"]`, `\"sample_one_in\": 1`: no run sampled); the merge queue keeps running it.\n\nOpened by `scripts/evidence-flip-ready --propose` because the flip trigger held over the last 24 hours:\n\n```json\n{trigger}\n```\n"
            );
            let created = github.gh(&[
                "pr",
                "create",
                "--repo",
                &github.repo,
                "--base",
                "main",
                "--head",
                &branch,
                "--title",
                &format!("Enforce the {check} evidence skip on pull requests"),
                "--body",
                &body,
            ])?;
            crate::cli_println!("{check}: {}", created.trim());
            Ok(())
        };
        let result = operation();
        let _ = git(root, &["worktree", "remove", "--force", tree_arg]);
        if let Err(error) = result {
            if error.to_string() != "mechanical flip" {
                eprintln!("{check}: not proposed: {error}");
            }
            failed = true;
        }
    }
    Ok(i32::from(failed))
}

#[cfg(test)]
mod flip_ready_tests;
