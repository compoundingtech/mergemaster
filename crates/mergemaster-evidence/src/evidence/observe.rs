//! Import protected CI observations, verify full records, and publish immutable refs.
use super::observe_args::Args;
use crate::gate::git::deadline::GitChild;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
    time::Duration,
};

fn capture(command: &mut Command, input: Option<&[u8]>, seconds: u64) -> Result<Output> {
    Ok(GitChild::capture(
        command,
        input,
        Duration::from_secs(seconds),
    )?)
}
fn tail(bytes: &[u8], count: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let start = text
        .char_indices()
        .rev()
        .nth(count.saturating_sub(1))
        .map_or(0, |(i, _)| i);
    text[start..].to_owned()
}
fn git(repo: &Path, args: &[&str], input: Option<&[u8]>, check: bool) -> Result<Output> {
    let out = capture(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C"),
        input,
        300,
    )?;
    ensure!(
        !check || out.status.success(),
        "git {} failed: {}",
        args.first().copied().unwrap_or_default(),
        tail(String::from_utf8_lossy(&out.stderr).trim().as_bytes(), 2000)
    );
    Ok(out)
}
fn text(repo: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git(repo, args, None, true)?.stdout)?
        .trim()
        .to_owned())
}
fn api(repository: &str, suffix: &str) -> Result<Output> {
    capture(
        Command::new("gh").args(["api", &format!("repos/{repository}/actions/runs/{suffix}")]),
        None,
        120,
    )
}
fn object(value: &Value) -> Result<&serde_json::Map<String, Value>> {
    value.as_object().context("expected a JSON object")
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    object(value)?.get(key).with_context(|| format!("'{key}'"))
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    field(value, key)?
        .as_str()
        .with_context(|| format!("'{key}' must be a string"))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    field(value, key)?
        .as_array()
        .with_context(|| format!("'{key}' must be an array"))
}
fn read_json(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice(bytes).map_err(|error| {
        use super::legacy_verify::statement_document::{Document, Error};
        match Document::from_bytes(bytes) {
            Err(Error::Syntax(syntax)) => anyhow::anyhow!(syntax.to_string()),
            _ => error.into(),
        }
    })
}
fn repr(value: &Value) -> String {
    match value {
        Value::String(s) => format!(
            "{}",
            super::legacy_verify::python_repr::Repr(
                super::legacy_verify::value_inputs::TextRef::Str(s)
            )
        ),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        _ => value.to_string(),
    }
}
fn truth(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}
fn run_info(args: &Args, run: i64) -> Result<Value> {
    let done = api(&args.repository, &run.to_string())?;
    read_json(&done.stdout)
        .with_context(|| format!("cannot read run {run} of {} from GitHub", args.repository))
}
fn skipped(args: &Args, run: i64, attempt: i64) -> Result<BTreeSet<String>> {
    let mut skipped = BTreeSet::new();
    for page in 1.. {
        let message = || {
            format!(
                "cannot read the jobs of run {run} attempt {attempt}, so skips cannot be ruled out"
            )
        };
        let done = api(
            &args.repository,
            &format!("{run}/attempts/{attempt}/jobs?per_page=100&page={page}"),
        )?;
        let value = read_json(&done.stdout).map_err(|_| anyhow::anyhow!(message()))?;
        let jobs = array(&value, "jobs").map_err(|_| anyhow::anyhow!(message()))?;
        for job in jobs {
            object(job)?;
            let name = job.get("name").and_then(Value::as_str).unwrap_or_default();
            let steps = job.get("steps").and_then(Value::as_array);
            let ran = |wanted| {
                steps.is_some_and(|steps| {
                    steps.iter().any(|s| {
                        s.get("name").and_then(Value::as_str) == Some(wanted)
                            && s.get("conclusion").and_then(Value::as_str) == Some("success")
                    })
                })
            };
            if let Some(check) = name.strip_prefix("evidence-gate-")
                && ran("evidence skip taken")
            {
                skipped.insert(check.to_owned());
            }
            if ran("evidence covered by a trusted note") {
                skipped.insert(name.to_owned());
            }
        }
        if jobs.len() < 100 {
            return Ok(skipped);
        }
    }
    Ok(skipped)
}
fn artifact(args: &Args, run: i64, attempt: i64) -> Result<i64> {
    let done = api(&args.repository, &format!("{run}/artifacts?per_page=100"))?;
    ensure!(
        done.status.success(),
        "gh api failed ({}): {}",
        done.status.code().unwrap_or(-1),
        tail(done.stderr.trim_ascii(), 2000)
    );
    let listing = read_json(&done.stdout)?;
    object(&listing)?;
    let name = format!("ci-evidence-source-{attempt}");
    let found: Vec<_> = listing
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|a| {
            a.get("name").and_then(Value::as_str) == Some(&name) && !truth(a.get("expired"))
        })
        .collect();
    ensure!(
        found.len() == 1,
        "expected exactly one live artifact {name}, found {}",
        found.len()
    );
    field(found[0], "id")?
        .as_i64()
        .context("artifact id must be an integer")
}
fn statement(repo: &Path, record: &str) -> Result<Value> {
    let listing = text(repo, &["ls-tree", "-r", record])?;
    let parts: Vec<_> = listing.split_whitespace().collect();
    ensure!(
        parts.len() == 4 && parts[0] == "100644" && parts[1] == "blob",
        "record {record} is not a single-note commit"
    );
    let body = read_json(&git(repo, &["cat-file", "blob", parts[2]], None, true)?.stdout)?;
    object(&body)?;
    Ok(body)
}
fn subject(body: &Value) -> Result<&Value> {
    array(body, "subject")?
        .first()
        .context("list index out of range")
}
fn token() -> Result<String> {
    for key in ["EVIDENCE_PUSH_TOKEN", "GH_TOKEN"] {
        if let Ok(s) = std::env::var(key)
            && !s.is_empty()
        {
            return Ok(s);
        }
    }
    let out = capture(Command::new("gh").args(["auth", "token"]), None, 600)?;
    Ok(if out.status.success() {
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    } else {
        String::new()
    })
}
fn remote_git(repo: &Path, args: &[&str], token: &str, fetch: bool) -> Result<()> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0");
    if !token.is_empty() {
        command
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "http.extraheader")
            .env(
                "GIT_CONFIG_VALUE_0",
                format!(
                    "Authorization: Basic {}",
                    STANDARD.encode(format!("x-access-token:{token}"))
                ),
            );
    }
    let done = capture(&mut command, None, 1800)?;
    if !done.status.success() {
        let text = String::from_utf8_lossy(&done.stderr);
        let text = if token.is_empty() {
            text.into_owned()
        } else {
            text.replace(token, "***")
        };
        if fetch {
            bail!(
                "fetching the source's history failed: {}",
                tail(text.trim().as_bytes(), 2000)
            );
        }
        bail!(
            "git {} against the remote failed: {}",
            args[0],
            tail(text.trim().as_bytes(), 2000)
        );
    }
    Ok(())
}
fn fetch_parents(repo: &Path, remote: &str, token: &str, sources: BTreeSet<String>) -> Result<()> {
    let mut parents = BTreeSet::new();
    for source in sources {
        let header = text(repo, &["cat-file", "commit", &source])?;
        for line in header.split("\n\n").next().unwrap_or_default().lines() {
            if let Some(parent) = line.strip_prefix("parent ")
                && !git(repo, &["cat-file", "-e", parent], None, false)?
                    .status
                    .success()
            {
                parents.insert(parent.to_owned());
            }
        }
    }
    if parents.is_empty() {
        return Ok(());
    }
    let absolute = std::path::absolute(repo)?;
    let name = absolute
        .file_name()
        .context("scratch repository has no name")?
        .to_string_lossy();
    let history = absolute.with_file_name(format!("{name}-history"));
    if !history.exists() {
        let done = capture(
            Command::new("git")
                .args(["init", "--quiet", "--bare"])
                .arg(&history),
            None,
            300,
        )?;
        ensure!(
            done.status.success(),
            "git init failed: {}",
            String::from_utf8_lossy(&done.stderr)
        );
    }
    let mut argv = vec!["fetch", "--quiet", "--no-tags", remote];
    argv.extend(parents.iter().map(String::as_str));
    remote_git(&history, &argv, token, true)?;
    let alternates = repo.join("objects/info/alternates");
    let line = format!("{}\n", history.join("objects").display());
    let mut existing = if alternates.exists() {
        fs::read_to_string(&alternates)?
    } else {
        String::new()
    };
    if !existing.contains(&line) {
        existing.push_str(&line);
        if let Some(parent) = alternates.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(alternates, existing)?;
    }
    Ok(())
}
fn verify(args: &Args, repo: &Path, tree: &str, check: &str, keys: &str) -> Result<()> {
    let done = capture(
        Command::new(&args.verifier)
            .arg("legacy-evidence-verify")
            .arg("--repo")
            .arg(repo)
            .args(["--tree", tree, "--check", check, "--keys", keys]),
        None,
        120,
    )?;
    let answer =
        read_json(&done.stdout).unwrap_or_else(|_| json!({"reason":"unreadable verifier output"}));
    object(&answer)?;
    ensure!(
        done.status.success() && truth(answer.get("satisfied")),
        "record for {check} on {tree} did not verify: {}",
        answer.get("reason").map_or_else(
            || "unknown".into(),
            |v| v.as_str().map_or_else(|| repr(v), str::to_owned)
        )
    );
    Ok(())
}
fn keys(args: &Args) -> Result<tempfile::NamedTempFile> {
    let new = ".fractal/evidence-keys";
    let path = if git(
        &args.checkout,
        &["ls-tree", "--full-tree", "-z", &args.keys_from, "--", new],
        None,
        true,
    )?
    .stdout
    .is_empty()
    {
        ".st/evidence-keys"
    } else {
        new
    };
    let found = git(
        &args.checkout,
        &["show", &format!("{}:{path}", args.keys_from)],
        None,
        true,
    )?;
    let mut file = tempfile::Builder::new()
        .prefix("evidence-keys-")
        .tempfile()?;
    file.write_all(&found.stdout)?;
    Ok(file)
}
fn observe(args: &Args, run: i64, attempt: i64, summary: &mut Value) -> Result<()> {
    let argv = read_json(args.observer.as_bytes())?;
    let argv = argv
        .as_array()
        .filter(|a| !a.is_empty() && a.iter().all(Value::is_string))
        .context("--observer must be a JSON array of strings")?;
    let info = run_info(args, run)?;
    object(&info)?;
    ensure!(
        info.get("name").and_then(Value::as_str) == Some("Workspace CI"),
        "run {run} is a run of {}, not 'Workspace CI': never acting on any other workflow, this one included",
        repr(&info["name"])
    );
    let skipped = skipped(args, run, attempt)?;
    let artifact = match args.artifact {
        Some(a) => a,
        None => artifact(args, run, attempt)?,
    };
    let mut command = Command::new(argv[0].as_str().context("observer executable")?);
    for arg in &argv[1..] {
        command.arg(arg.as_str().context("observer argument")?);
    }
    command.args([
        "--run",
        &run.to_string(),
        "--attempt",
        &attempt.to_string(),
        "--artifact",
        &artifact.to_string(),
    ]);
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let status = GitChild::with_stdio(
        &mut command,
        Duration::from_secs(600),
        Stdio::from(stdout.try_clone()?),
        Stdio::from(stderr.try_clone()?),
    )?
    .wait()?;
    use std::io::{Read, Seek};
    stdout.rewind()?;
    if !status.success() {
        stderr.rewind()?;
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes)?;
        let message = tail(String::from_utf8_lossy(&bytes).trim().as_bytes(), 2000);
        if let Ok(done) = api(&args.repository, &format!("{run}/attempts/{attempt}"))
            && done.status.success()
            && read_json(&done.stdout).ok().is_some_and(|v| {
                matches!(
                    v.get("conclusion").and_then(Value::as_str),
                    Some("cancelled" | "skipped")
                )
            })
        {
            summary["nothing_to_attest"] = json!(format!(
                "run {run} attempt {attempt} was cancelled or skipped: {message}"
            ));
            return Ok(());
        }
        bail!(
            "{} failed ({}): {message}",
            argv[0].as_str().unwrap_or_default(),
            status.code().unwrap_or(-1)
        );
    }
    let response: Value = match serde_json::from_reader(&mut stdout) {
        Ok(response) => response,
        Err(error) => {
            stdout.rewind()?;
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes)?;
            let message = read_json(&bytes)
                .err()
                .map_or_else(|| error.to_string(), |error| error.to_string());
            bail!("observer printed no JSON document: {message}");
        }
    };
    object(&response)?;
    for (key, expected) in [
        ("repository", json!(args.repository)),
        ("run", json!(run)),
        ("attempt", json!(attempt)),
    ] {
        ensure!(
            response.get(key) == Some(&expected),
            "observer answered for {key} {}, not {}",
            repr(&response[key]),
            repr(&expected)
        );
    }
    let scratch = args
        .scratch
        .clone()
        .unwrap_or_else(|| args.state_dir.join("scratch.git"));
    fs::create_dir_all(&scratch)?;
    git(
        &scratch,
        &["init", "--quiet", "--bare", "--object-format=sha1"],
        None,
        false,
    )?;
    let pack = STANDARD.decode(string(&response, "object_pack_base64")?)?;
    git(&scratch, &["index-pack", "--stdin"], Some(&pack), true)?;
    let records = array(&response, "records")?;
    if let Some(remote) = &args.remote {
        let mut sources = BTreeSet::new();
        for produced in records {
            sources.insert(
                string(
                    subject(&statement(&scratch, string(produced, "record")?)?)?,
                    "name",
                )?
                .to_owned(),
            );
        }
        fetch_parents(&scratch, remote, &token()?, sources)?;
    }
    let mut keys_file = None;
    let mut refs = Vec::new();
    let mut failures = Vec::new();
    for produced in records {
        let record = string(produced, "record")?;
        ensure!(
            [40, 64].contains(&record.len())
                && record
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "observer returned a malformed record id"
        );
        let tier = string(produced, "tier")?;
        let body = statement(&scratch, record)?;
        let subject = subject(&body)?;
        let tree = string(field(subject, "digest")?, "gitTree")?;
        let observed = field(field(&body, "predicate")?, "observed")?;
        object(observed)?;
        let checks: Vec<String> = match observed.get("checks") {
            Some(v) => object(v)?
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            None => Vec::new(),
        };
        let taken: Vec<_> = checks.iter().filter(|c| skipped.contains(*c)).collect();
        if !taken.is_empty() {
            if summary.get("skip_taken").is_none() {
                summary["skip_taken"] = json!([]);
            }
            summary["skip_taken"]
                .as_array_mut()
                .context("skip_taken")?
                .push(json!({"record":record,"checks":taken}));
            continue;
        }
        let entries = summary["records"].as_array_mut().context("records")?;
        entries.push(json!({"record":record,"tier":tier,"checks":checks,"tree":tree,"verified":false,"newly_recorded":truth(produced.get("newly_recorded"))}));
        let entry = entries.last_mut().context("record entry")?;
        let verified = (|| -> Result<()> {
            if tier == "full" {
                for check in &checks {
                    let key_path = match &args.keys {
                        Some(path) => path.as_str(),
                        None => {
                            if keys_file.is_none() {
                                keys_file = Some(keys(args)?);
                            }
                            keys_file
                                .as_ref()
                                .context("accepted keys")?
                                .path()
                                .to_str()
                                .context("accepted key path is not UTF-8")?
                        }
                    };
                    verify(args, &scratch, tree, check, key_path)?;
                }
                entry["verified"] = json!(true);
            } else {
                ensure!(
                    tier == "degraded",
                    "record {record} has unexpected tier {}; not published",
                    repr(&json!(tier))
                );
            }
            Ok(())
        })();
        if let Err(error) = verified {
            let message = error.to_string();
            entry["error"] = json!(message);
            failures.push(message);
            continue;
        }
        let names = [
            format!("refs/tags/evidence/{tree}/{record}"),
            format!("refs/notes/evidence/{tree}/{record}"),
        ];
        let mut collision = None;
        for name in &names {
            let existing = text(&scratch, &["for-each-ref", "--format=%(objectname)", name])?;
            if !existing.is_empty() && existing != record && collision.is_none() {
                collision = Some(format!(
                    "{name} already names {existing}; evidence refs are never replaced"
                ));
            }
        }
        if let Some(message) = collision {
            entry["error"] = json!(message);
            failures.push(message);
            continue;
        }
        for name in &names {
            if text(&scratch, &["for-each-ref", "--format=%(objectname)", name])?.is_empty() {
                git(
                    &scratch,
                    &["update-ref", name, record, &"0".repeat(record.len())],
                    None,
                    true,
                )?;
            }
        }
        refs.extend(names);
    }
    if let Some(remote) = &args.remote
        && !refs.is_empty()
    {
        let refspecs: Vec<_> = refs.iter().map(|r| format!("{r}:{r}")).collect();
        let mut argv = vec!["push", "--quiet", remote];
        argv.extend(refspecs.iter().map(String::as_str));
        remote_git(&scratch, &argv, &token()?, false)?;
    }
    summary["metrics"] = response
        .get("metrics")
        .cloned()
        .unwrap_or_else(|| json!({}));
    summary["full_trust_eligible"] = response["full_trust_eligible"].clone();
    summary["trust_limitation"] = response["trust_limitation"].clone();
    summary["published"] = json!(if args.remote.is_some() {
        refs.len() / 2
    } else {
        0
    });
    if !failures.is_empty() {
        summary["failures"] = json!(failures);
    }
    Ok(())
}
fn write_summary(summary: &Value) -> Result<()> {
    let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY").filter(|p| !p.is_empty()) else {
        return Ok(());
    };
    let mut lines = vec![format!(
        "### Evidence observation of run {} attempt {}",
        summary["run"], summary["attempt"]
    )];
    for entry in array(summary, "records")? {
        let tier = string(entry, "tier")?;
        let state = if entry["verified"] == true {
            "verified"
        } else if tier == "degraded" {
            "unsigned, not verified"
        } else {
            "NOT VERIFIED"
        };
        let checks = array(entry, "checks")?
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!(
            "- `{checks}` {tier} {state}: `{}`",
            string(entry, "record")?
        ));
    }
    let metrics = &summary["metrics"];
    if truth(Some(metrics)) {
        let show = |key| {
            metrics.get(key).map_or_else(
                || "None".into(),
                |v| v.as_str().map_or_else(|| repr(v), str::to_owned),
            )
        };
        lines.push(format!(
            "- fresh {}, full {}, signing latency {} ms",
            show("fresh_records"),
            show("full_records"),
            show("signing_latency_ms")
        ));
    }
    if truth(summary.get("trust_limitation")) {
        lines.push(format!(
            "- trust limitation: {}",
            string(summary, "trust_limitation")?
        ));
    }
    if let Some(taken) = summary.get("skip_taken").and_then(Value::as_array) {
        for item in taken {
            lines.push(format!(
                "- not recorded, the evidence gate skipped it in this run: `{}` (`{}`)",
                array(item, "checks")?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
                string(item, "record")?
            ));
        }
    }
    if let Some(note) = summary.get("nothing_to_attest").and_then(Value::as_str) {
        lines.push(format!("- nothing to attest: {note}"));
    }
    if let Some(failures) = summary.get("failures").and_then(Value::as_array) {
        for failure in failures {
            lines.push(format!(
                "- **failure:** {}",
                failure.as_str().unwrap_or_default()
            ));
        }
    }
    writeln!(
        OpenOptions::new().create(true).append(true).open(path)?,
        "{}",
        lines.join("\n")
    )?;
    Ok(())
}
fn one_run(args: &Args, run: i64, attempt: i64) -> Result<Value> {
    let mut summary =
        json!({"repository":args.repository,"run":run,"attempt":attempt,"records":[]});
    if let Err(error) = observe(args, run, attempt, &mut summary) {
        summary["failures"] = json!([error.to_string()]);
    }
    write_summary(&summary)?;
    Ok(summary)
}
fn poll(args: &Args) -> Result<i32> {
    let ledger = args.state_dir.join("observed.jsonl");
    let mut seen = BTreeMap::new();
    if ledger.exists() {
        for line in fs::read_to_string(&ledger)?.lines() {
            let entry = read_json(line.as_bytes())?;
            seen.insert(
                (
                    field(&entry, "run")?.as_i64().context("run")?,
                    field(&entry, "attempt")?.as_i64().context("attempt")?,
                ),
                (
                    string(&entry, "state")?.to_owned(),
                    entry.get("tries").and_then(Value::as_i64).unwrap_or(0),
                ),
            );
        }
    }
    let done = capture(
        Command::new("gh").args([
            "run",
            "list",
            "--repo",
            &args.repository,
            "--workflow",
            "Workspace CI",
            "--event",
            "merge_group",
            "--status",
            "completed",
            "--limit",
            &args.limit.to_string(),
            "--json",
            "databaseId,conclusion,attempt",
        ]),
        None,
        120,
    )?;
    if !done.status.success() {
        crate::cli_println!(
            "{}",
            json!({"failures":[format!("cannot list runs: {}", tail(&done.stderr, 300))]})
        );
        return Ok(1);
    }
    let listing = read_json(&done.stdout)?;
    let mut runs: Vec<_> = listing
        .as_array()
        .context("run listing must be an array")?
        .iter()
        .collect();
    runs.sort_by_key(|r| r.get("databaseId").and_then(Value::as_i64));
    let mut status = 0;
    for item in runs {
        let run = field(item, "databaseId")?.as_i64().context("databaseId")?;
        let attempt = item
            .get("attempt")
            .and_then(Value::as_i64)
            .filter(|n| *n != 0)
            .unwrap_or(1);
        let (state, tries) = seen
            .get(&(run, attempt))
            .map_or(("new", 0), |(state, tries)| (state.as_str(), *tries));
        if ["done", "gave_up"].contains(&state)
            || matches!(
                item.get("conclusion").and_then(Value::as_str),
                Some("cancelled" | "skipped")
            )
        {
            continue;
        }
        let summary = one_run(args, run, attempt)?;
        let failed = truth(summary.get("failures"));
        let state = if !failed {
            "done"
        } else if tries + 1 >= 3 {
            "gave_up"
        } else {
            "failed"
        };
        let records = array(&summary, "records")?;
        let ids: Vec<_> = records.iter().map(|r| r["record"].clone()).collect();
        writeln!(
            OpenOptions::new().create(true).append(true).open(&ledger)?,
            "{}",
            json!({"run":run,"attempt":attempt,"state":state,"tries":tries + i64::from(failed),"records":ids})
        )?;
        crate::cli_println!(
            "{}",
            json!({"run":run,"attempt":attempt,"state":state,"records":records.len(),"failures":summary.get("failures").cloned().unwrap_or_else(|| json!([]))})
        );
        status |= i32::from(failed);
    }
    Ok(status)
}
pub(super) fn run(argv: &[String]) -> Result<i32> {
    let args = match super::observe_args::parse(argv) {
        Ok(args) => args,
        Err(exit) => {
            std::io::stdout().write_all(exit.stdout.as_bytes())?;
            std::io::stderr().write_all(exit.stderr.as_bytes())?;
            return Ok(exit.code);
        }
    };
    fs::create_dir_all(&args.state_dir)?;
    if let Some(run) = args.run {
        let attempt = match args.attempt {
            Some(attempt) => attempt,
            None => run_info(&args, run)
                .ok()
                .and_then(|info| info.get("run_attempt").and_then(Value::as_i64))
                .with_context(|| {
                    format!("cannot read run {run} of {} from GitHub", args.repository)
                })?,
        };
        let summary = one_run(&args, run, attempt)?;
        crate::cli_println!("{}", serde_json::to_string_pretty(&summary)?);
        Ok(i32::from(truth(summary.get("failures"))))
    } else {
        poll(&args)
    }
}
