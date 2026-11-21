//! Best-effort advisory output; this command never changes gate outcomes.
use serde_json::Value;
use std::{
    collections::BTreeMap,
    env,
    fs::OpenOptions,
    io::{self, Write},
    process::Command,
};

type Lanes = BTreeMap<String, Vec<String>>;
const HOW: &str = "https://github.com/compoundingtech/fractal/issues/3621";

fn environment(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("'{name}'"))
}

fn output(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
    Command::new(program).args(args).output().map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            format!("[Errno 2] No such file or directory: '{program}'")
        } else {
            error.to_string()
        }
    })
}

fn lanes_at(base: &str) -> Result<Lanes, String> {
    let mut path = ".fractal/required-lanes.json";
    let probe = output("git", &["ls-tree", "--full-tree", "-z", base, "--", path])?;
    let short: String = base.chars().take(12).collect();
    if !probe.status.success() {
        return Err(format!("cannot inspect lane definition at {short}"));
    }
    if probe.stdout.is_empty() {
        path = ".st/required-lanes.json";
    }
    let done = output("git", &["show", &format!("{base}:{path}")])?;
    if !done.status.success() {
        return Err(format!("cannot read {path} at {short}"));
    }
    let document: Value = serde_json::from_slice(&done.stdout).map_err(|error| {
        super::legacy_verify::json_bytes::parse(&done.stdout)
            .err()
            .map_or_else(|| error.to_string(), |error| error.detail.to_string())
    })?;
    let lanes = document
        .get("lanes")
        .ok_or("'lanes'")?
        .as_object()
        .ok_or("'lanes' is not an object")?;
    lanes
        .iter()
        .map(|(name, lane)| {
            let paths = match lane.get("definition_paths") {
                None | Some(Value::Null) => Vec::new(),
                Some(value) => value
                    .as_array()
                    .ok_or("definition_paths is not an array")?
                    .iter()
                    .map(|path| {
                        path.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| "definition path is not a string".to_owned())
                    })
                    .collect::<Result<_, _>>()?,
            };
            Ok((name.clone(), paths))
        })
        .collect()
}

fn changed_files(repository: &str, number: &str) -> Result<Vec<String>, String> {
    let number = number
        .trim()
        .parse::<i128>()
        .map_err(|_| format!("invalid literal for int() with base 10: '{number}'"))?;
    let done = output(
        "gh",
        &[
            "api",
            "--paginate",
            &format!("repos/{repository}/pulls/{number}/files?per_page=100"),
            "--jq",
            ".[].filename",
        ],
    )?;
    if !done.status.success() {
        let error = String::from_utf8_lossy(&done.stderr);
        let error = error.trim();
        let tail: String = error
            .chars()
            .skip(error.chars().count().saturating_sub(200))
            .collect();
        return Err(format!("could not read the pull request files: {tail}"));
    }
    Ok(String::from_utf8_lossy(&done.stdout)
        .split('\n')
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect())
}

fn edits(paths: &[String], files: &[String]) -> bool {
    paths.iter().any(|path| {
        files.iter().any(|name| {
            name == path
                || name
                    .strip_prefix(path.trim_end_matches('/'))
                    .is_some_and(|tail| tail.starts_with('/'))
        })
    })
}

fn assess(
    lines: &str,
    lanes: &Lanes,
    files: Option<&[String]>,
) -> (Vec<String>, BTreeMap<String, String>) {
    let mut listed = Vec::new();
    let mut passed = BTreeMap::new();
    for text in lines.lines() {
        let Some(text) = text.trim().strip_prefix("evidence-decision v1 check=") else {
            continue;
        };
        // The Python expression requires a nonempty, non-whitespace check followed by a literal space.
        let Some((check, _)) = text.split_once(' ') else {
            continue;
        };
        if check.is_empty() || check.chars().any(char::is_whitespace) {
            continue;
        }
        let mut fields = BTreeMap::from([("check", check)]);
        // fields_of permits a later check= field to overwrite the first one.
        for (key, value) in text.split(' ').filter_map(|part| part.split_once('=')) {
            fields.insert(key, value);
        }
        let check = fields.get("check").copied().unwrap_or("");
        let Some(paths) = lanes.get(check) else {
            continue;
        };
        if fields.get("decision") != Some(&"run") || fields.get("outcome") != Some(&"no_note") {
            continue;
        }
        let reason = if fields.get("fork") != Some(&"false") {
            Some("fork".to_owned())
        } else if fields.get("tree_of") != Some(&"head") || fields.get("head_tree") != Some(&"used")
        {
            Some(format!(
                "merge tree ({})",
                fields.get("head_tree").copied().unwrap_or("-")
            ))
        } else if let Some(files) = files {
            edits(paths, files).then(|| "edits its own lane".to_owned())
        } else {
            Some("file list unreadable".to_owned())
        };
        if let Some(reason) = reason {
            passed.insert(check.to_owned(), reason);
        } else {
            listed.push(check.to_owned());
        }
    }
    listed.sort();
    (listed, passed)
}

fn message(listed: &[String]) -> String {
    format!(
        "These jobs ran in full because no pre-signed note covered this head: {}. Run `scripts/fractal-test --push origin` before marking the pull request ready, and CI can skip them. How: {HOW}. This never fails a check or blocks a merge.",
        listed.join(", ")
    )
}

fn notice(out: &mut impl Write) -> io::Result<()> {
    let lanes = match environment("BASE_SHA").and_then(|base| lanes_at(&base)) {
        Ok(lanes) => lanes,
        Err(error) => {
            writeln!(out, "evidence-presign-notice: {error}; nothing to say")?;
            return Ok(());
        }
    };
    let files = match environment("REPOSITORY").and_then(|repository| {
        environment("PR_NUMBER").and_then(|number| changed_files(&repository, &number))
    }) {
        Ok(files) => Some(files),
        Err(error) => {
            writeln!(out, "evidence-presign-notice: {error}")?;
            None
        }
    };
    let (listed, passed) = assess(
        &env::var("LINES").unwrap_or_default(),
        &lanes,
        files.as_deref(),
    );
    let passed = passed
        .iter()
        .map(|(check, why)| format!("{check}:{}", why.replace(' ', "_")))
        .collect::<Vec<_>>()
        .join(",");
    let record = format!(
        "evidence-presign-notice v1 pr={} listed={} passed_over={}",
        env::var("PR_NUMBER").unwrap_or_else(|_| "-".to_owned()),
        if listed.is_empty() {
            "-".to_owned()
        } else {
            listed.join(",")
        },
        if passed.is_empty() { "-" } else { &passed }
    );
    writeln!(out, "{record}")?;
    let summary = if listed.is_empty() {
        format!("{record}\n")
    } else {
        let text = message(&listed);
        writeln!(out, "::notice title=Not pre-signed::{text}")?;
        format!("{text}\n\n{record}\n")
    };
    if let Some(target) = env::var_os("GITHUB_STEP_SUMMARY").filter(|target| !target.is_empty()) {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(target)?
            .write_all(summary.as_bytes())?;
    }
    Ok(())
}

pub fn run() {
    let mut out = io::stdout().lock();
    if let Err(error) = notice(&mut out) {
        let class = match error.kind() {
            io::ErrorKind::NotFound => "FileNotFoundError",
            io::ErrorKind::PermissionDenied => "PermissionError",
            io::ErrorKind::IsADirectory => "IsADirectoryError",
            io::ErrorKind::NotADirectory => "NotADirectoryError",
            io::ErrorKind::BrokenPipe => "BrokenPipeError",
            _ => "OSError",
        };
        let detail = error.to_string();
        let detail = if let Some(errno) = error.raw_os_error() {
            let description = detail
                .rsplit_once(" (os error ")
                .map_or(detail.as_str(), |(text, _)| text);
            let target = env::var("GITHUB_STEP_SUMMARY").unwrap_or_default();
            let quoted = if target.contains('\'') && !target.contains('"') {
                format!("\"{}\"", target.replace('\\', "\\\\"))
            } else {
                format!("'{}'", target.replace('\\', "\\\\").replace('\'', "\\'"))
            };
            format!("[Errno {errno}] {description}: {quoted}")
        } else {
            detail
        };
        let _ = writeln!(
            out,
            "evidence-presign-notice: {class}: {detail}; nothing to say"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lanes() -> Lanes {
        [
            (
                "genie-freshness",
                vec![".st", "flake.lock", "flake.nix", "scripts"],
            ),
            (
                "typescript-client",
                vec!["package.json", "scripts/ci-typescript-client"],
            ),
            ("stage-lane", vec![".st", "scripts"]),
        ]
        .into_iter()
        .map(|(name, paths)| {
            (
                name.to_owned(),
                paths.into_iter().map(str::to_owned).collect(),
            )
        })
        .collect()
    }
    fn line(check: &str, extra: &str) -> String {
        format!(
            "evidence-decision v1 check={check} decision=run outcome=no_note reason=no_record tree_of=head head_tree=used fork=false event=pull_request pr=7 {extra} gate_sha256=abc"
        )
    }
    #[test]
    fn signable_checks_and_single_command() {
        let (listed, passed) = assess(
            &[
                line("typescript-client", ""),
                line("genie-freshness", ""),
                line("linux-gate", ""),
            ]
            .join("\n"),
            &lanes(),
            Some(&["crates/a.rs".into()]),
        );
        assert_eq!(listed, ["genie-freshness", "typescript-client"]);
        assert!(passed.is_empty());
        let text = message(&listed);
        assert!(text.contains("genie-freshness, typescript-client."));
        assert!(text.contains("`scripts/fractal-test --push origin`"));
        assert!(text.contains("never fails a check or blocks a merge"));
        let (listed, _) = assess(&line("stage-lane", ""), &lanes(), Some(&[]));
        assert!(message(&listed).contains("`scripts/fractal-test --push origin`"));
        assert!(!message(&listed).contains("--all"));
    }
    #[test]
    fn covered_sampled_shadow_and_skipped() {
        let lines = [
            line("typescript-client", "decision=skip outcome=satisfied"),
            line(
                "typescript-client",
                "outcome=satisfied reason=satisfied_but_not_skipped:_sampled",
            ),
            line(
                "genie-freshness",
                "outcome=satisfied reason=satisfied_but_not_skipped:_shadow",
            ),
            line("stage-lane", "outcome=rejected"),
        ]
        .join("\n");
        assert_eq!(
            assess(&lines, &lanes(), Some(&[])),
            (vec![], BTreeMap::new())
        );
    }
    #[test]
    fn merge_fork_and_lane_edits() {
        let lines = [
            line(
                "typescript-client",
                "tree_of=merge head_tree=fallback:protected_files_differ_from_the_branch_point",
            ),
            line("stage-lane", "fork=true"),
            line("genie-freshness", ""),
        ]
        .join("\n");
        let (listed, passed) = assess(
            &lines,
            &lanes(),
            Some(&["scripts/ci-local".into(), "crates/a.rs".into()]),
        );
        assert!(listed.is_empty());
        assert_eq!(passed["genie-freshness"], "edits its own lane");
        assert_eq!(passed["stage-lane"], "fork");
        assert_eq!(
            passed["typescript-client"],
            "merge tree (fallback:protected_files_differ_from_the_branch_point)"
        );
    }
    #[test]
    fn path_boundaries() {
        assert!(edits(&["scripts".into()], &["scripts/ci-local".into()]));
        assert!(edits(&["flake.lock".into()], &["flake.lock".into()]));
        assert!(!edits(
            &["scripts".into()],
            &["scripts-extra/x".into(), "docs/scripts".into()]
        ));
        assert!(!edits(
            &["package.json".into()],
            &["apps/fractal-web/package.json".into()]
        ));
    }
    #[test]
    fn unreadable_files_and_noise() {
        let (listed, passed) = assess(&line("typescript-client", ""), &lanes(), None);
        assert!(listed.is_empty());
        assert_eq!(passed["typescript-client"], "file list unreadable");
        assert_eq!(
            assess(
                "\nnoise\nevidence-decision v1 check=$CHECK decision=run outcome=unavailable",
                &lanes(),
                Some(&[])
            ),
            (vec![], BTreeMap::new())
        );
    }
    #[test]
    fn required_lanes_have_definition_paths() {
        // The Python self-test ran inside the pinned Fractal fixture overlay; this
        // repository has no required-lanes file of its own.
        let root = std::path::PathBuf::from(
            std::env::var("MERGEMASTER_FRACTAL_FIXTURE")
                .expect("MERGEMASTER_FRACTAL_FIXTURE must point to the pinned Fractal consumer"),
        );
        let current = root.join(".fractal/required-lanes.json");
        let path = if current.symlink_metadata().is_ok() {
            current
        } else {
            root.join(".st/required-lanes.json")
        };
        let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(value["lanes"].as_object().unwrap().values().all(|lane| {
            lane["definition_paths"]
                .as_array()
                .is_some_and(|paths| !paths.is_empty())
        }));
    }
}
