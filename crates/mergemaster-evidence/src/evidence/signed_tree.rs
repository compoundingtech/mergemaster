//! Read-only PR-head judgment from the trusted base checkout; every decision is shadow-only.
use super::legacy_verify::statement_document::{Document, Node};
use crate::gate::git::deadline::GitChild;
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
    let s = s.strip_suffix('\n').unwrap_or(s);
    [40, 64].contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn repository(s: &str) -> bool {
    let s = s.strip_suffix('\n').unwrap_or(s);
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
/// Borrow only consumed fields from the shared, uncapped Python JSON byte loader.
#[derive(Clone, Copy)]
struct Json<'a> {
    document: &'a Document,
    node: &'a Node,
}
impl<'a> Json<'a> {
    fn root(document: &'a Document) -> Self {
        Self {
            document,
            node: document.root(),
        }
    }
    fn get(self, key: &str) -> Option<Self> {
        let Node::Object(fields) = self.node else {
            return None;
        };
        let (_, id) = fields
            .iter()
            .find(|(name, _)| name.iter().copied().eq(key.chars().map(u32::from)))?;
        Some(Self {
            document: self.document,
            node: self.document.node(*id),
        })
    }
    fn object(self) -> Option<impl Iterator<Item = (&'a [u32], Self)>> {
        let Node::Object(fields) = self.node else {
            return None;
        };
        Some(fields.iter().map(move |(name, id)| {
            (
                name.as_slice(),
                Self {
                    document: self.document,
                    node: self.document.node(*id),
                },
            )
        }))
    }
    fn string(self) -> Option<String> {
        let Node::String(points) = self.node else {
            return None;
        };
        points.iter().copied().map(char::from_u32).collect()
    }
    fn is(self, text: &str) -> bool {
        matches!(self.node, Node::String(points) if points.iter().copied().eq(text.chars().map(u32::from)))
    }
}
fn truth(value: Option<Json<'_>>) -> bool {
    match value.map(|value| value.node) {
        None | Some(Node::Null) => false,
        Some(Node::Bool(b)) => *b,
        Some(Node::Integer(n)) => n != "0" && n != "-0",
        Some(Node::Float(n)) => *n != 0.0,
        Some(Node::String(s)) => !s.is_empty(),
        Some(Node::Array(a)) => !a.is_empty(),
        Some(Node::Object(o)) => !o.is_empty(),
    }
}
fn python_text(value: Json<'_>) -> Result<String> {
    super::flip_skip_python::node_str(value.document, value.node).map_err(|_| "UnicodeEncodeError")
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
fn required(entry: Json<'_>) -> bool {
    entry.object().is_some() && entry.get("require").is_some_and(|v| !v.is("off"))
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
    let policy = if policy.code == 0 {
        Document::from_bytes_with_depth_limit(&policy.stdout, None).ok()
    } else {
        None
    };
    let Some(checks) = policy
        .as_ref()
        .and_then(|v| Json::root(v).get("checks"))
        .filter(|v| v.object().is_some())
    else {
        return Ok(Outcome::base("error", "no-readable-policy-at-base", base));
    };
    if !checks
        .object()
        .is_some_and(|mut entries| entries.any(|(_, entry)| required(entry)))
    {
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
    let mut sorted_checks: Vec<_> = checks.object().into_iter().flatten().collect();
    sorted_checks.sort_unstable_by_key(|(name, _)| *name);
    for (check, entry) in sorted_checks {
        if !required(entry)
            || entry
                .get("inputs")
                .is_none_or(|v| matches!(v.node, Node::Null))
            || check.is_empty()
            || !check.iter().all(|point| {
                u8::try_from(*point).is_ok_and(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
        {
            continue;
        }
        let check: String = check.iter().copied().filter_map(char::from_u32).collect();
        let projected = capture(
            &[
                verifier,
                "legacy-evidence-verify",
                "--repo",
                ".",
                "--revision",
                head,
                "--check",
                &check,
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
        let Ok(document) = Document::from_bytes_with_depth_limit(&projected.stdout, None) else {
            continue;
        };
        let value = Json::root(&document);
        if value.object().is_none() {
            return Err("AttributeError");
        }
        if let Some(key) = value
            .get("source_inputs")
            .and_then(Json::string)
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
    let document = match Document::from_bytes_with_depth_limit(&out.stdout, None) {
        Ok(value) => value,
        Err(_) => {
            outcome.reason = format!("verifier-exit-{}-without-json", out.code);
            return Ok(outcome);
        }
    };
    let value = Json::root(&document);
    if value.object().is_none() {
        return Err("AttributeError");
    }
    if value.get("decision").is_some_and(|d| d.is("error")) {
        outcome.reason = format!(
            "verifier:{}",
            value
                .get("reason")
                .map(python_text)
                .transpose()?
                .unwrap_or_else(|| "error".into())
        );
        return Ok(outcome);
    }
    if let Some(lanes) = value.get("lanes") {
        for (name, lane) in lanes.object().ok_or("AttributeError")? {
            if lane.object().is_none() {
                return Err("AttributeError");
            }
            outcome.lanes.insert(
                name.iter()
                    .copied()
                    .map(char::from_u32)
                    .collect::<Option<String>>()
                    .ok_or("UnicodeEncodeError")?,
                if truth(lane.get("satisfied")) {
                    "ok".into()
                } else {
                    lane.get("reason")
                        .map(python_text)
                        .transpose()?
                        .unwrap_or_else(|| "unsatisfied".into())
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
        .map(python_text)
        .transpose()?
        .unwrap_or_else(|| "error".into());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projected_and_final_verifier_json_accept_python_nonfinite_numbers() {
        let projected = Document::from_bytes_with_depth_limit(
            format!(
                "{{\"source_inputs\":\"{}\\n\",\"unused\":1e400}}",
                "a".repeat(40)
            )
            .as_bytes(),
            None,
        )
        .unwrap();
        let key = Json::root(&projected)
            .get("source_inputs")
            .unwrap()
            .string()
            .unwrap();
        assert!(oid(&key));
        assert!(key.ends_with('\n'));
        for number in ["1e400", "-1e400", "NaN", "Infinity", "-Infinity"] {
            let document = Document::from_bytes_with_depth_limit(
                format!("{{\"decision\":\"ok\",\"satisfied\":{number},\"lanes\":{{\"unit\":{{\"satisfied\":{number}}}}}}}").as_bytes(),
                None,
            ).unwrap();
            let value = Json::root(&document);
            assert!(truth(value.get("satisfied")), "{number}");
            assert!(
                truth(
                    value
                        .get("lanes")
                        .unwrap()
                        .get("unit")
                        .unwrap()
                        .get("satisfied")
                ),
                "{number}"
            );
        }
        assert!(Document::from_bytes_with_depth_limit(b"{\"satisfied\":1e}", None).is_err());
    }
}
