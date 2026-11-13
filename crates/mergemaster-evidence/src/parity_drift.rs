//! Read upstream history as data without executing upstream sources.
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fmt::Write,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Args)]
pub struct ParityDriftArgs {
    #[arg(long)]
    fractal_repo: PathBuf,
    #[arg(long, default_value = "HEAD")]
    r#ref: String,
    /// Inventory path. Defaults to scripts/PROVENANCE at the Git top level of the
    /// current directory; an error if the work tree or inventory is missing.
    #[arg(long)]
    provenance: Option<PathBuf>,
    #[arg(long)]
    report_only: bool,
}

fn sha<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let value = line.strip_prefix(prefix)?;
    (value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(value)
}
// Python str.splitlines(): https://docs.python.org/3/library/stdtypes.html#str.splitlines
fn splitlines(mut text: &str) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        if text.is_empty() {
            return None;
        }
        let end = text
            .find([
                '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
                '\u{2029}',
            ])
            .unwrap_or(text.len());
        let (line, tail) = text.split_at(end);
        text = if let Some(tail) = tail.strip_prefix("\r\n") {
            tail
        } else {
            tail.chars().next().map_or("", |ch| &tail[ch.len_utf8()..])
        };
        Some(line)
    })
}

fn fixture_paths(root: &Path, paths: &mut BTreeSet<String>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            fixture_paths(&entry.path(), paths)?;
        } else if entry.file_name().to_string_lossy().ends_with("PROVENANCE") {
            for line in splitlines(&fs::read_to_string(entry.path())?) {
                if line.contains('\t')
                    && !line.starts_with('#')
                    && !line.starts_with("original_path\t")
                {
                    paths.insert(line.split('\t').next().unwrap_or_default().to_owned());
                }
            }
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct Report<'a> {
    ported_through: &'a str,
    upstream_head: String,
    scope: &'static str,
    commits: Vec<&'a str>,
}

/// Return the Python CLI's status, including drift (1) without an error message.
pub fn run(args: ParityDriftArgs) -> Result<u8> {
    let provenance = match args.provenance {
        Some(path) => path,
        None => {
            // Intentional no deadline, consistent with this tool's oracle Git calls.
            let output = Command::new("git")
                .args(["rev-parse", "--show-toplevel"])
                .output()
                .context("cannot locate caller repository; pass --provenance")?;
            ensure!(
                output.status.success(),
                "not inside a Git work tree; pass --provenance"
            );
            PathBuf::from(String::from_utf8(output.stdout)?.trim()).join("scripts/PROVENANCE")
        }
    };
    let text =
        fs::read_to_string(&provenance).context("cannot read provenance; pass --provenance")?;
    let baseline = text
        .split(['\r', '\n'])
        .find_map(|line| sha(line, "# Commit: "))
        .context("missing extraction commit")?;
    let baseline = text
        .split(['\r', '\n'])
        .filter_map(|line| sha(line, "# Port: "))
        .next_back()
        .unwrap_or(baseline);
    let mut paths: BTreeSet<String> = splitlines(&text)
        .filter(|line| line.starts_with("scripts/"))
        .map(|line| line.split('\t').next().unwrap_or_default().to_owned())
        .collect();
    ensure!(!paths.is_empty(), "missing mapped script paths");
    paths.extend(
        [
            "crates/fractal-kernel/src/evidence",
            "crates/fractal-kernel/src/cli_output.rs",
            "crates/fractal/tests/git_evidence.rs",
        ]
        .map(str::to_owned),
    );
    let root = provenance
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new(""));
    fixture_paths(&root.join("tests/fixtures/fractal"), &mut paths)?;
    let git = |argv: &[&str]| -> Result<String> {
        // Pinned scripts/parity-drift:33-37 has no timeout (intentional None).
        // Adding one would be a separately decided fail-closed divergence.
        let output = Command::new("git")
            .arg("-C")
            .arg(&args.fractal_repo)
            .args(argv)
            .output()?;
        ensure!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?
            .trim_matches(|ch: char| ch.is_whitespace() || matches!(ch, '\u{1c}'..='\u{1f}'))
            .to_owned())
    };
    let head = git(&[
        "rev-parse",
        "--verify",
        "--end-of-options",
        &format!("{}^{{commit}}", args.r#ref),
    ])?;
    git(&["merge-base", "--is-ancestor", baseline, &head])?;
    let range = format!("{baseline}..{head}");
    let mut argv = vec![
        "log",
        "--full-history",
        "--diff-merges=first-parent",
        "--no-patch",
        "--reverse",
        "--format=%H %s",
        &range,
        "--",
    ];
    argv.extend(paths.iter().map(String::as_str));
    let pending = git(&argv)?;
    let report = Report {
        ported_through: baseline,
        upstream_head: head,
        scope: "newer commits only; older unported work remains in the cutover inventory",
        commits: splitlines(&pending).collect(),
    };
    // Python json.dumps defaults to ensure_ascii, including UTF-16 surrogate pairs.
    let json = serde_json::to_string_pretty(&report)?;
    let mut ascii = String::with_capacity(json.len());
    for ch in json.chars() {
        if ch < '\u{7f}' {
            ascii.push(ch);
        } else {
            for unit in ch.encode_utf16(&mut [0; 2]) {
                write!(ascii, "\\u{unit:04x}")?;
            }
        }
    }
    println!("{ascii}");
    Ok(u8::from(!args.report_only && !report.commits.is_empty()))
}
