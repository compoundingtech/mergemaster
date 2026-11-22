//! Read-only PR-head judgment from the trusted base checkout; every decision is shadow-only.
use crate::gate::git::deadline::GitChild;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    os::unix::process::ExitStatusExt,
    process::Command,
    time::{Duration, Instant},
};

type Result<T, E = &'static str> = std::result::Result<T, E>;
struct Done {
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
fn capture(command: &[&str], seconds: u64, no_lazy_fetch: bool) -> Done {
    capture_command(
        Command::new(command[0]).args(&command[1..]),
        seconds,
        no_lazy_fetch,
    )
}
fn capture_command(cmd: &mut Command, seconds: u64, no_lazy_fetch: bool) -> Done {
    if no_lazy_fetch {
        cmd.env("GIT_NO_LAZY_FETCH", "1");
    }
    match GitChild::capture(cmd, None, Duration::from_secs(seconds)) {
        Ok(out) => Done {
            code: out
                .status
                .code()
                .unwrap_or_else(|| -out.status.signal().unwrap_or(1)),
            stdout: out.stdout,
            stderr: out.stderr,
        },
        Err(error) => Done {
            code: 124,
            stdout: Vec::new(),
            stderr: if error.kind() == std::io::ErrorKind::TimedOut {
                format!("timed out after {seconds} s").into_bytes()
            } else {
                error.to_string().into_bytes()
            },
        },
    }
}
fn git(args: &[&str]) -> Done {
    capture_command(Command::new("git").args(args), 120, false)
}
fn text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes)
        .map(str::trim)
        .map_err(|_| "UnicodeDecodeError")
}
fn oid(s: &str) -> bool {
    [40, 64].contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn repository(s: &str) -> bool {
    s.split_once('/').is_some_and(|(a, b)| {
        [a, b].iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    })
}
fn config_path(base: &str, legacy: &str) -> Result<Option<String>> {
    let preferred = legacy.replacen(".st/", ".fractal/", 1);
    let out = git(&[
        "ls-tree",
        "-z",
        "--full-tree",
        base,
        "--",
        &preferred,
        legacy,
    ]);
    if out.code != 0 {
        return Err("RuntimeError");
    }
    let mut old = false;
    for entry in out.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let name = entry.splitn(2, |b| *b == b'\t').nth(1).unwrap_or_default();
        let name = std::str::from_utf8(name).map_err(|_| "UnicodeDecodeError")?;
        if name == preferred {
            return Ok(Some(preferred));
        }
        old |= name == legacy;
    }
    Ok(old.then(|| legacy.to_owned()))
}
struct BranchPoint {
    point: Option<String>,
    reason: &'static str,
    stderr: Vec<u8>,
}
fn branch_point(base: &str, head: &str, pr: &str) -> Result<BranchPoint> {
    let missing = |reason, stderr| BranchPoint {
        point: None,
        reason,
        stderr,
    };
    if git(&["rev-parse", "--is-shallow-repository"])
        .stdout
        .trim_ascii()
        == b"true"
    {
        let out = capture(
            &[
                "git",
                "fetch",
                "--no-tags",
                "-q",
                "--filter=blob:none",
                "--unshallow",
                "origin",
                base,
                &format!("refs/pull/{pr}/head"),
            ],
            180,
            false,
        );
        if out.code != 0 {
            return Ok(missing("history-fetch-failed", out.stderr));
        }
    }
    let out = git(&["merge-base", base, head]);
    let point = text(&out.stdout)?;
    if out.code != 0 || !oid(point) {
        return Ok(missing("no-branch-point", Vec::new()));
    }
    if let Some(path) = config_path(point, ".st/required-lanes.json")? {
        let out = git(&["rev-parse", "--verify", &format!("{point}:{path}")]);
        let blob = text(&out.stdout)?;
        if out.code != 0 || !oid(blob) {
            return Ok(missing("no-lane-file-at-the-branch-point", Vec::new()));
        }
        if capture(&["git", "cat-file", "-e", blob], 120, true).code != 0 {
            let fetched = git(&[
                "-c",
                "fetch.negotiationAlgorithm=noop",
                "fetch",
                "--no-tags",
                "-q",
                "origin",
                blob,
            ]);
            if fetched.code != 0 {
                return Ok(missing("lane-file-fetch-failed", fetched.stderr));
            }
        }
    }
    Ok(BranchPoint {
        point: Some(point.to_owned()),
        reason: "",
        stderr: Vec::new(),
    })
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
fn python_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        _ => value.to_string(),
    }
}
fn field(value: &str) -> String {
    let value = if value.is_empty() { "-" } else { value };
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._:/@+=,-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(200)
        .collect()
}
fn error_text(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if text.is_empty() {
        "no stderr".into()
    } else {
        text.chars().take(400).collect()
    }
}
struct Outcome {
    decision: String,
    reason: String,
    tree: String,
    base: String,
    lanes: BTreeMap<String, String>,
    errors: Vec<(String, Vec<u8>)>,
}
impl Outcome {
    fn new(decision: &str, reason: &str) -> Self {
        Self {
            decision: decision.into(),
            reason: reason.into(),
            tree: "-".into(),
            base: "-".into(),
            lanes: BTreeMap::new(),
            errors: Vec::new(),
        }
    }
    fn base(decision: &str, reason: &str, base: &str) -> Self {
        Self {
            base: base.into(),
            ..Self::new(decision, reason)
        }
    }
}
struct Context {
    pr: String,
    head: String,
    repository: String,
    verifier: String,
    timeout: u64,
}
fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}
fn required(entry: &Value) -> bool {
    entry
        .as_object()
        .is_some_and(|e| e.get("require").is_some_and(|v| v != "off"))
}
fn judge(context: &Context) -> Result<Outcome> {
    let Context {
        pr,
        head,
        repository: repo,
        verifier,
        timeout,
    } = context;
    if !repository(repo)
        || !oid(head)
        || pr.is_empty()
        || !pr
            .chars()
            .all(|c| super::legacy_verify::python_digits::is_digit(u32::from(c)))
    {
        return Ok(Outcome::new("error", "bad-context"));
    }
    if env("PR_HEAD_REPOSITORY", "") != *repo {
        return Ok(Outcome::new(
            "skipped",
            "not-a-same-repository-pull-request",
        ));
    }
    if env("PR_DRAFT", "false") == "true" {
        return Ok(Outcome::new("skipped", "draft"));
    }
    let out = git(&["rev-parse", "--verify", "HEAD"]);
    let base = text(&out.stdout)?;
    if out.code != 0 || !oid(base) {
        return Ok(Outcome::new("error", "no-base-checkout"));
    }
    let policy_path = config_path(base, ".st/evidence-skip-policy.json")?;
    let policy = git(&[
        "show",
        &format!(
            "{base}:{}",
            policy_path
                .as_deref()
                .unwrap_or(".st/evidence-skip-policy.json")
        ),
    ]);
    let policy: Option<Value> = if policy.code == 0 {
        serde_json::from_slice(&policy.stdout).ok()
    } else {
        None
    };
    let Some(checks) = policy
        .as_ref()
        .and_then(|v| v.get("checks"))
        .and_then(Value::as_object)
    else {
        return Ok(Outcome::base("error", "no-readable-policy-at-base", base));
    };
    if !checks.values().any(required) {
        return Ok(Outcome::base("ok", "nothing-requires-a-signed-note", base));
    }
    if git(&[
        "fetch",
        "--no-tags",
        "--depth=1",
        "-q",
        "origin",
        &format!("refs/pull/{pr}/head"),
    ])
    .code
        != 0
    {
        return Ok(Outcome::base("error", "could-not-fetch-the-head", base));
    }
    let fetched = git(&["rev-parse", "--verify", "FETCH_HEAD^{commit}"]);
    if fetched.code != 0 || text(&fetched.stdout)? != head {
        return Ok(Outcome::base(
            "error",
            "fetched-head-differs-from-the-event",
            base,
        ));
    }
    let out = git(&["rev-parse", "--verify", "FETCH_HEAD^{tree}"]);
    let tree = text(&out.stdout)?;
    if out.code != 0 || !oid(tree) {
        return Ok(Outcome::base("error", "no-head-tree", base));
    }
    let mut outcome = Outcome {
        tree: tree.into(),
        ..Outcome::base("error", "", base)
    };
    let tree_tags = format!("+refs/tags/evidence/{tree}/*:refs/tags/evidence/{tree}/*");
    let tree_notes = format!("+refs/notes/evidence/{tree}/*:refs/notes/evidence/{tree}/*");
    let fetched = git(&[
        "fetch",
        "--no-tags",
        "--depth=1",
        "--no-filter",
        "-q",
        "origin",
        &tree_tags,
        &tree_notes,
    ]);
    if fetched.code != 0 {
        outcome.errors.push(("notes-fetch".into(), fetched.stderr));
    }
    let mut sorted_checks: Vec<_> = checks.iter().collect();
    sorted_checks.sort_unstable_by_key(|(name, _)| *name);
    for (check, entry) in sorted_checks {
        if !required(entry)
            || entry.get("inputs").is_none_or(Value::is_null)
            || check.is_empty()
            || !check
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            continue;
        }
        let projected = capture(
            &[
                verifier,
                "legacy-evidence-verify",
                "--repo",
                ".",
                "--revision",
                head,
                "--check",
                check,
                "--project",
                "--policy-from",
                base,
                "--repository",
                repo,
            ],
            *timeout,
            false,
        );
        if projected.code != 0 {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(&projected.stdout) else {
            continue;
        };
        if !value.is_object() {
            return Err("AttributeError");
        }
        if let Some(key) = value
            .get("source_inputs")
            .and_then(Value::as_str)
            .filter(|key| oid(key))
        {
            let tags = format!(
                "+refs/tags/evidence/input/{check}/{key}/*:refs/tags/evidence/input/{check}/{key}/*"
            );
            let notes = format!(
                "+refs/notes/evidence-input/{check}/{key}/*:refs/notes/evidence-input/{check}/{key}/*"
            );
            let fetched = git(&[
                "fetch",
                "--no-tags",
                "--depth=1",
                "--no-filter",
                "-q",
                "origin",
                &tags,
                &notes,
            ]);
            if fetched.code != 0 {
                outcome
                    .errors
                    .push((format!("notes-fetch:{check}"), fetched.stderr));
            }
        }
    }
    let notes_failed = !outcome.errors.is_empty();
    let mut command = vec![
        verifier.as_str(),
        "legacy-evidence-verify",
        "--repo",
        ".",
        "--tree",
        tree,
        "--require-all",
        "--keys-from",
        base,
        "--policy-from",
        base,
        "--repository",
        repo,
    ];
    let has_lanes = config_path(base, ".st/required-lanes.json")?.is_some();
    let branch = if has_lanes {
        Some(branch_point(base, head, pr)?)
    } else {
        None
    };
    if has_lanes {
        command.extend(["--lanes-from", base]);
    }
    if let Some(point) = branch.as_ref().and_then(|b| b.point.as_deref()) {
        command.extend(["--lane-base", point]);
    }
    if let Some(branch) = &branch
        && branch.point.is_none()
        && !branch.stderr.is_empty()
    {
        outcome
            .errors
            .push((branch.reason.into(), branch.stderr.clone()));
    }
    let out = capture(&command, *timeout, false);
    let value: Value = match serde_json::from_slice(&out.stdout) {
        Ok(value) => value,
        Err(_) => {
            outcome.reason = format!("verifier-exit-{}-without-json", out.code);
            return Ok(outcome);
        }
    };
    let value = value.as_object().ok_or("AttributeError")?;
    if value.get("decision").is_some_and(|d| d == "error") {
        outcome.reason = format!(
            "verifier:{}",
            value
                .get("reason")
                .map_or_else(|| "error".into(), python_text)
        );
        return Ok(outcome);
    }
    if let Some(lanes) = value.get("lanes") {
        for (name, lane) in lanes.as_object().ok_or("AttributeError")? {
            let lane = lane.as_object().ok_or("AttributeError")?;
            outcome.lanes.insert(
                name.clone(),
                if truth(lane.get("satisfied")) {
                    "ok".into()
                } else {
                    lane.get("reason")
                        .map_or_else(|| "unsatisfied".into(), python_text)
                },
            );
        }
    }
    outcome.reason = if truth(value.get("satisfied")) {
        "satisfied".into()
    } else {
        "unsatisfied".into()
    };
    if notes_failed {
        outcome.reason.push_str(",notes-fetch-failed");
    }
    if let Some(branch) = &branch
        && branch.point.is_none()
    {
        outcome
            .reason
            .push_str(&format!(",lanes-at-the-base-tip:{}", branch.reason));
    }
    outcome.decision = value
        .get("decision")
        .map_or_else(|| "error".into(), python_text);
    Ok(outcome)
}
pub fn run() -> std::io::Result<()> {
    use super::legacy_verify::{
        argparse_int::{IntegerError, parse},
        python_repr::Repr,
        value_inputs::TextRef,
    };
    let timeout_text = env("SIGNED_TREE_VERIFIER_TIMEOUT", "60");
    let timeout = match parse(TextRef::Str(&timeout_text)) {
        Ok(number) => {
            if number.negative {
                0
            } else {
                number.digits.parse::<u64>().unwrap_or(u64::MAX)
            }
        }
        Err(error) => {
            match error {
                IntegerError::InvalidLiteral => writeln!(
                    std::io::stderr().lock(),
                    "ValueError: invalid literal for int() with base 10: {}",
                    Repr(TextRef::Str(&timeout_text))
                )?,
                IntegerError::DigitLimit { digits } => writeln!(
                    std::io::stderr().lock(),
                    "ValueError: Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"
                )?,
            }
            std::process::exit(1);
        }
    };
    let started = Instant::now();
    let context = Context {
        pr: env("PR_NUMBER", ""),
        head: env("PR_HEAD_SHA", ""),
        repository: env("REPOSITORY", ""),
        verifier: env("MERGEMASTER_BIN", "mergemaster"),
        timeout,
    };
    let outcome = judge(&context).unwrap_or_else(|class| Outcome::new("error", class));
    let lanes = outcome
        .lanes
        .iter()
        .map(|(name, state)| format!("{name}:{state}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut line = format!(
        "signed-tree v1 decision={} mode=shadow pr={} head={} tree={} base={} reason={} lanes={} seconds={:.1}",
        outcome.decision,
        field(&context.pr),
        field(&context.head),
        field(&outcome.tree),
        field(&outcome.base),
        field(&outcome.reason),
        field(&lanes),
        started.elapsed().as_secs_f64()
    );
    for (what, stderr) in outcome.errors {
        line.push_str(&format!(
            "\nsigned-tree v1 error {what}: {}",
            error_text(&stderr)
        ));
    }
    crate::cli_println!("{line}");
    for (key, body) in [
        ("GITHUB_STEP_SUMMARY", format!("{line}\n")),
        ("GITHUB_OUTPUT", format!("decision={}\n", outcome.decision)),
    ] {
        if let Some(path) = std::env::var_os(key).filter(|p| !p.is_empty()) {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?
                .write_all(body.as_bytes())?;
        }
    }
    Ok(())
}
