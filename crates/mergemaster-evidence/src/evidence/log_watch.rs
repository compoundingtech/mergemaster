//! Watch the independently published log head; retain Python-compatible transition state.
use crate::gate::git::deadline::GitChild;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use clap::Args;
use serde_json::{Map, Value, json};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const LOG: &str = "refs/evidence-log/main";
const SEEN: &str = "refs/evidence-log/watched";
#[derive(Args)]
pub struct LogWatchArgs {
    #[arg(long)]
    remote: String,
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    notify: String,
    #[arg(long, default_value_t = 360, allow_negative_numbers = true)]
    max_age: i64,
    #[arg(long, default_value_t = 3600, allow_negative_numbers = true)]
    repeat: i64,
    #[arg(long, allow_negative_numbers = true)]
    now: Option<f64>,
}
fn capture(command: &mut Command) -> io::Result<Output> {
    GitChild::capture(command, None, Duration::from_secs(120))
}
fn git(repo: &Path, args: &[&str], timeout: Duration) -> io::Result<Output> {
    let mut command = Command::new("git");
    for (key, _) in std::env::vars_os() {
        if key.as_encoded_bytes().starts_with(b"GIT_") {
            command.env_remove(key);
        }
    }
    GitChild::capture(
        command
            .arg("-C")
            .arg(repo)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "maintenance.auto=false",
                "-c",
                "gc.auto=0",
            ])
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C"),
        None,
        timeout,
    )
}
fn rebuild(repo: &Path) -> io::Result<()> {
    let parent = repo
        .parent()
        .ok_or_else(|| io::Error::other("fetch repository has no parent"))?;
    let name = repo
        .file_name()
        .ok_or_else(|| io::Error::other("fetch repository has no name"))?
        .to_string_lossy();
    let prefix = format!("{name}.broken-");
    let broken = parent.join(format!(
        "{prefix}{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos()
    ));
    fs::rename(repo, &broken)?;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(&prefix) && entry.path() != broken {
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}
fn published(
    repo: &Path,
    remote: &str,
    repaired: bool,
    timeout: Duration,
) -> Result<(Option<f64>, String)> {
    if !repo.join("objects").is_dir()
        && !Command::new("git")
            .args(["init", "-q", "--bare"])
            .arg(repo)
            .output()?
            .status
            .success()
    {
        return Ok((None, format!("cannot create {}", repo.display())));
    }
    let fetched = match git(
        repo,
        &[
            "fetch",
            "-q",
            "--no-tags",
            "--depth=1",
            remote,
            &format!("+{LOG}:{SEEN}"),
        ],
        timeout,
    ) {
        Ok(done) => done,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            return Ok((None, "the fetch of the log head timed out".into()));
        }
        Err(e) => return Err(e.into()),
    };
    if !fetched.status.success() {
        if !repaired {
            match git(
                repo,
                &[
                    "fsck",
                    "--connectivity-only",
                    "--no-reflogs",
                    "--no-dangling",
                ],
                timeout,
            ) {
                Ok(done) if !done.status.success() => {
                    rebuild(repo)?;
                    return published(repo, remote, true, timeout);
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    return Ok((None, "checking the local log copy timed out".into()));
                }
                Err(e) => return Err(e.into()),
                _ => {}
            }
        }
        let error = String::from_utf8_lossy(&fetched.stderr);
        let tail: String = error
            .trim()
            .chars()
            .rev()
            .take(160)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        return Ok((None, format!("the fetch of the log head failed: {tail}")));
    }
    let shown = match git(repo, &["show", "-s", "--format=%H%x00%s", SEEN], timeout) {
        Ok(done) => done,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            return Ok((None, "reading the log head timed out".into()));
        }
        Err(e) => return Err(e.into()),
    };
    if !shown.status.success() && !repaired {
        rebuild(repo)?;
        return published(repo, remote, true, timeout);
    }
    let text = String::from_utf8_lossy(&shown.stdout);
    let (head, subject) = text.trim().split_once('\0').unwrap_or((text.trim(), ""));
    let short = &head[..head.len().min(12)];
    let stamp = subject.split(' ').find_map(|part| {
        part.strip_prefix("as_of=")
            .filter(|s| s.chars().next().is_some_and(|c| !c.is_whitespace()))
            .and_then(|s| s.split_whitespace().next())
    });
    let Some(stamp) = stamp.filter(|_| shown.status.success()) else {
        return Ok((
            None,
            format!(
                "the log head {} names no time",
                if short.is_empty() { "?" } else { short }
            ),
        ));
    };
    let mut points: Vec<u32> = stamp.chars().map(u32::from).collect();
    if let Some(micros) = super::legacy_verify::statement::zoned_time_micros(&points) {
        return Ok((Some(micros as f64 / 1_000_000.0), head.into()));
    }
    let length = points.len();
    let naive = ["+00:00", "T00:00:00+00:00"].into_iter().any(|suffix| {
        points.truncate(length);
        points.extend(suffix.chars().map(u32::from));
        super::legacy_verify::statement::zoned_time_micros(&points).is_some()
    });
    Ok((
        None,
        if naive {
            format!("the log head {short} names a time without a zone")
        } else {
            format!(
                "the log head {short} has an unreadable time {}",
                super::legacy_verify::python_repr::Repr(stamp.into())
            )
        },
    ))
}
fn iso(unix: f64) -> Result<String> {
    ensure!(
        unix.is_finite() && (-62_135_596_800.0..253_402_300_800.0).contains(&unix),
        "timestamp out of range for datetime"
    );
    let time = DateTime::<Utc>::from_timestamp(unix.floor() as i64, 0)
        .context("timestamp out of range for datetime")?;
    Ok(time.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}
fn number(state: &Map<String, Value>, key: &str) -> f64 {
    state.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}
pub fn step(
    before: &Map<String, Value>,
    now: f64,
    as_of: Option<f64>,
    detail: &str,
    max_age: i64,
    repeat: i64,
) -> Result<(Map<String, Value>, Option<String>, bool)> {
    let mut state = before.clone();
    let (age, why) = if let Some(time) = as_of {
        state.insert("last_as_of".into(), json!(time));
        state.insert("last_head".into(), json!(detail));
        state.remove("unreadable_since");
        let age = now - time;
        (
            age,
            format!(
                "the published evidence log head {} is {:.0}s old (as_of {}; at most {max_age}s expected)",
                &detail[..detail.len().min(12)],
                age.round_ties_even() + 0.0,
                iso(time)?
            ),
        )
    } else {
        state.entry("unreadable_since").or_insert(json!(now));
        let age = now - number(&state, "unreadable_since");
        (
            age,
            format!(
                "the published evidence log head cannot be read for {:.0}s: {detail}",
                age.round_ties_even() + 0.0
            ),
        )
    };
    let stalled = age > max_age as f64;
    let mut line = None;
    if stalled {
        if !state.contains_key("stalled_since") {
            state.insert(
                "stalled_since".into(),
                json!(now - (age - max_age as f64).max(0.0)),
            );
            line = Some(format!(
                "evidence log STALLED: {why}. The log host's pull (evidence-log.timer) is not publishing."
            ));
        } else if now - number(&state, "told_at") >= repeat as f64 {
            line = Some(format!(
                "evidence log still stalled since {}: {why}.",
                iso(number(&state, "stalled_since"))?
            ));
        }
        if line.is_some() {
            state.insert("told_at".into(), json!(now));
        }
    } else if state.contains_key("stalled_since") {
        let since = number(&state, "stalled_since");
        line = Some(format!(
            "evidence log moving again: {why}; it was stalled from {} ({:.0}s).",
            iso(since)?,
            (now - since).round_ties_even() + 0.0
        ));
        state.remove("stalled_since");
        state.remove("told_at");
    }
    Ok((state, line, stalled))
}
fn save(path: &Path, state: &Map<String, Value>) -> Result<()> {
    let temporary = path.with_extension(format!("json.{}", std::process::id()));
    let mut file = File::create(&temporary)?;
    serde_json::to_writer(&mut file, state)?;
    file.flush()?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("state has no parent"))?,
    )?
    .sync_all()?;
    Ok(())
}
fn summary(stalled: bool, as_of: Option<f64>, detail: &str, notified: bool) -> Result<String> {
    let mut out = format!("{{\"stalled\": {stalled}");
    let stamp = as_of.map(iso).transpose()?;
    for (key, value) in [
        ("as_of", stamp.as_deref()),
        ("head", as_of.map(|_| detail)),
        ("problem", if as_of.is_none() { Some(detail) } else { None }),
    ] {
        out.push_str(", \"");
        out.push_str(key);
        out.push_str("\": ");
        if let Some(value) = value {
            super::legacy_json::string(value, &mut out)?;
        } else {
            out.push_str("null");
        }
    }
    out.push_str(if notified {
        ", \"notified\": true}"
    } else {
        ", \"notified\": false}"
    });
    Ok(out)
}
pub fn run(args: LogWatchArgs) -> Result<()> {
    let notify = serde_json::from_str::<Vec<String>>(&args.notify)
        .ok()
        .filter(|v| !v.is_empty());
    let Some(notify) = notify else {
        eprintln!("evidence-log-watch: --notify must be a JSON array of strings");
        std::process::exit(2);
    };
    fs::create_dir_all(&args.state)?;
    let (as_of, detail) = published(
        &args.state.join("head.git"),
        &args.remote,
        false,
        Duration::from_secs(120),
    )?;
    let now = match args.now {
        Some(now) => now,
        None => SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
    };
    let path = args.state.join("watch.json");
    let before = fs::read(&path)
        .ok()
        .and_then(|data| serde_json::from_slice::<Value>(&data).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let (mut state, line, stalled) = step(&before, now, as_of, &detail, args.max_age, args.repeat)?;
    let mut code = i32::from(stalled);
    if let Some(line) = &line {
        crate::cli_println!("{line}");
        std::io::stdout().flush()?;
        let sent = capture(Command::new(&notify[0]).args(&notify[1..]).arg(line));
        if !sent.is_ok_and(|done| done.status.success()) {
            for key in ["stalled_since", "told_at"] {
                state.remove(key);
                if let Some(value) = before.get(key) {
                    state.insert(key.into(), value.clone());
                }
            }
            eprintln!(
                "evidence-log-watch: the notification failed; it is tried again on the next run"
            );
            code = 3;
        }
    }
    save(&path, &state)?;
    crate::cli_println!(
        "{}",
        summary(stalled, as_of, &detail, line.is_some() && code != 3)?
    );
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_watch_fetch_timeout_does_not_rebuild() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("head.git");
        let (as_of, problem) = published(&repo, "unused", false, Duration::ZERO).unwrap();
        assert!(as_of.is_none());
        assert!(problem.contains("timed out"));
        assert!(repo.is_dir());
        assert!(!fs::read_dir(root.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("head.git.broken-")
        }));
    }

    #[test]
    fn log_watch_iso_rejects_non_finite_and_out_of_range_timestamps() {
        for unix in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -62_135_596_801.0,
            253_402_300_800.0,
            1e20,
        ] {
            assert!(iso(unix).is_err(), "{unix}");
        }
        for unix in [-62_135_596_800.0, 253_402_300_799.0] {
            assert!(iso(unix).is_ok(), "{unix}");
        }
    }
}
