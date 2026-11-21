use super::super::flip_skip_python::value_str;
use super::*;
use std::cell::RefCell;
use std::process::Command;
use tempfile::TempDir;

fn now() -> DateTime<Utc> {
    parse_time("2026-10-25T12:00:00Z").unwrap()
}
fn lanes() -> Value {
    json!({"lanes": {"linux-gate": {"definition_paths": ["scripts/ci-local", ".config/nextest.toml"]}, "typescript-client": {"definition_paths": ["scripts/ci-typescript-client", "package.json"]}}})
}
fn git_test(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
fn repository(policy: Option<Value>) -> (TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    git_test(root.path(), &["init", "-q"]);
    fs::create_dir(root.path().join(".st")).unwrap();
    fs::write(
        root.path().join(".st/required-lanes.json"),
        lanes().to_string(),
    )
    .unwrap();
    if let Some(policy) = policy {
        fs::write(
            root.path().join(".st/evidence-skip-policy.json"),
            policy.to_string(),
        )
        .unwrap();
    }
    git_test(root.path(), &["add", "-A"]);
    git_test(root.path(), &["commit", "-qm", "old"]);
    let base = git_test(root.path(), &["rev-parse", "HEAD"]);
    (root, base)
}
fn line(check: &str, base: &str, overrides: Value) -> String {
    let mut fields =
        json!({"decision": "run", "outcome": "no_note", "reason": "no_record", "base": base});
    for (key, value) in overrides.as_object().unwrap() {
        fields[key] = value.clone();
    }
    format!(
        "check={check} {}",
        fields
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| format!("{k}={}", v.as_str().unwrap()))
            .collect::<Vec<_>>()
            .join(" ")
    )
}
#[derive(Default)]
struct Fixture {
    runs: Vec<Value>,
    release_runs: Vec<Value>,
    jobs: BTreeMap<u64, Vec<Value>>,
    lines: BTreeMap<u64, Vec<String>>,
    files: BTreeMap<u64, Vec<String>>,
    requests: RefCell<Vec<String>>,
    broken: bool,
}
struct Run<'a> {
    id: u64,
    number: u64,
    branch: &'a str,
    actor: &'a str,
    hours: i64,
}
impl Fixture {
    fn run(
        &mut self,
        run: Run<'_>,
        decisions: &[(&str, String)],
        files: &[&str],
        extra: &[(&str, &str)],
    ) {
        let Run {
            id,
            number,
            branch,
            actor,
            hours,
        } = run;
        self.runs.push(json!({"id": id, "status": "completed", "created_at": iso(now() - Duration::hours(hours)), "actor": {"login": actor}, "head_branch": branch, "head_sha": format!("{id:040x}"), "pull_requests": [{"number": number}]}));
        let mut jobs = Vec::new();
        for (offset, (check, line)) in decisions.iter().enumerate() {
            let job_id = id * 100 + offset as u64;
            jobs.push(json!({"id": job_id, "name": format!("evidence-gate-{check}"), "status": "completed", "conclusion": "success"}));
            self.lines.insert(job_id, vec![line.clone()]);
        }
        for (name, conclusion) in extra {
            jobs.push(json!({"name": name, "status": "completed", "conclusion": conclusion}));
        }
        self.jobs.insert(id, jobs);
        self.files
            .insert(number, files.iter().map(|s| (*s).to_owned()).collect());
    }
    fn release(
        &mut self,
        id: u64,
        pr: u64,
        jobs: &[(&str, &str, &str, f64)],
        actor: &str,
        hours: i64,
    ) {
        let start = now() - Duration::hours(hours);
        self.release_runs.push(json!({"id": id, "status": "completed", "created_at": iso(start), "actor": {"login": actor}, "pull_requests": [{"number": pr}]}));
        self.jobs.insert(id, jobs.iter().map(|(name, label, conclusion, minutes)| json!({"name": name, "labels": [label], "conclusion": conclusion, "started_at": iso(start), "completed_at": iso(start + Duration::milliseconds((minutes * 60_000.0) as i64))})).collect());
    }
    fn report(&self, root: &Path, receipts: &[PathBuf]) -> Report {
        report(
            self,
            root,
            now() - Duration::hours(24),
            now(),
            &BTreeSet::from(["bot".to_owned()]),
            receipts,
        )
        .unwrap()
    }
}
impl Source for Fixture {
    fn repo(&self) -> &str {
        "org/repo"
    }
    fn gh(&self, args: &[&str]) -> Result<String> {
        let path = args.last().unwrap();
        self.requests.borrow_mut().push((*path).to_owned());
        if path.contains("/commits/") {
            return Ok(json!([{"number": 101}]).to_string());
        }
        let number: u64 = path
            .split("/pulls/")
            .nth(1)
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        Ok(json!([self.files[&number]
            .iter()
            .map(|filename| json!({"filename": filename}))
            .collect::<Vec<_>>()])
        .to_string())
    }
    fn items(&self, path: &str, _: &str) -> Result<Vec<Value>> {
        self.requests.borrow_mut().push(path.to_owned());
        let id = path
            .split("/runs/")
            .nth(1)
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        Ok(self.jobs[&id].clone())
    }
    fn lines_of(&self, job: &Value) -> Result<Vec<String>> {
        Ok(self.lines[&job["id"].as_u64().unwrap()].clone())
    }
    fn pr_runs(
        &self,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
        workflow: &str,
    ) -> Result<Vec<Value>> {
        if self.broken {
            anyhow::bail!("HTTP 502");
        }
        let runs = if workflow == "fleet.yml" {
            &self.runs
        } else {
            assert_eq!(workflow, RELEASE_WORKFLOW);
            &self.release_runs
        };
        Ok(runs
            .iter()
            .filter(|run| {
                let time = parse_time(text(run, "created_at")).unwrap();
                time >= since && time <= until
            })
            .cloned()
            .collect())
    }
}

#[test]
fn lane_reads_are_pinned_and_new_malformed_never_falls_back() {
    let (root, old) = repository(None);
    fs::create_dir(root.path().join(".fractal")).unwrap();
    let new = root.path().join(".fractal/required-lanes.json");
    fs::write(
        &new,
        json!({"lanes": {"demo": {"definition_paths": ["new-only"]}}}).to_string(),
    )
    .unwrap();
    git_test(root.path(), &["add", "-A"]);
    git_test(root.path(), &["commit", "-qm", "new"]);
    let revision = git_test(root.path(), &["rev-parse", "HEAD"]);
    fs::write(&new, "{").unwrap();
    assert_eq!(
        lanes_at(root.path(), &old, &mut BTreeMap::new()).unwrap()["linux-gate"],
        vec!["scripts/ci-local", ".config/nextest.toml"]
    );
    assert_eq!(
        *lanes_at(root.path(), &revision, &mut BTreeMap::new()).unwrap(),
        BTreeMap::from([("demo".to_owned(), vec!["new-only".to_owned()])])
    );
    git_test(root.path(), &["add", "-A"]);
    git_test(root.path(), &["commit", "-qm", "malformed"]);
    let malformed = git_test(root.path(), &["rev-parse", "HEAD"]);
    assert!(lanes_at(root.path(), &malformed, &mut BTreeMap::new()).is_err());
    assert!(lanes_at(root.path(), &"f".repeat(40), &mut BTreeMap::new()).is_err());
}
#[test]
fn each_decision_is_counted_once_in_its_category() {
    for (fields, lane_edit, expected) in [
        (
            json!({"decision":"skip", "outcome":"satisfied", "reason":"satisfied"}),
            false,
            "skipped",
        ),
        (
            json!({"outcome":"no_note", "reason":"no_record"}),
            true,
            "lane_edit",
        ),
        (
            json!({"outcome":"no_note", "reason":"no_record"}),
            false,
            "not_signed",
        ),
        (
            json!({"outcome":"no_note", "reason":"no_record", "tree_of":"merge"}),
            false,
            "merge_tree",
        ),
        (
            json!({"outcome":"rejected", "reason":"crate_uncovered", "tree_of":"merge"}),
            false,
            "merge_tree",
        ),
        (
            json!({"outcome":"no_note", "reason":"no_record", "tree_of":"head"}),
            false,
            "not_signed",
        ),
        (
            json!({"outcome":"rejected", "reason":"crate_uncovered"}),
            false,
            "not_signed",
        ),
        (
            json!({"outcome":"rejected", "reason":"check_failed"}),
            false,
            "failed",
        ),
        (
            json!({"outcome":"satisfied", "reason":"satisfied_but_not_skipped:_a_file_that_decides_skipping_changed"}),
            false,
            "protected",
        ),
        (
            json!({"outcome":"satisfied", "reason":"satisfied_but_not_skipped:_sampled:_the_real_job_runs_anyway"}),
            false,
            "sampled",
        ),
        (
            json!({"outcome":"satisfied", "reason":"satisfied_but_not_skipped:_shadow:_the_note_would_cover"}),
            false,
            "shadow",
        ),
        (
            json!({"outcome":"unavailable", "reason":"no_policy"}),
            false,
            "other",
        ),
        (
            json!({"decision":"skip", "outcome":"satisfied", "reason":"satisfied"}),
            true,
            "skipped",
        ),
    ] {
        assert_eq!(classify(&fields, lane_edit), expected, "{fields}");
    }
}
#[test]
fn a_lane_edit_is_a_changed_file_that_is_or_is_under_a_definition_path() {
    let check = |file: &str, path: &str| touches(&[file.to_owned()], &[path.to_owned()]);
    assert!(check("scripts/ci-local", "scripts/ci-local"));
    assert!(check(".st/x.json", ".st"));
    assert!(!check("scripts/ci-local-web", "scripts/ci-local"));
    assert!(!check("README.md", "scripts"));
}
#[test]
fn report_counts_our_runs_per_check_and_lists_unsigned_with_seat() {
    let (root, base) = repository(None);
    let mut gh = Fixture::default();
    gh.run(
        Run {
            id: 1,
            number: 101,
            branch: "agent/a",
            actor: "bot",
            hours: 2,
        },
        &[
            ("linux-gate", line("linux-gate", &base, json!({}))),
            (
                "typescript-client",
                line(
                    "typescript-client",
                    &base,
                    json!({"decision":"skip","outcome":"satisfied","reason":"satisfied"}),
                ),
            ),
        ],
        &["crates/x/src/lib.rs"],
        &[],
    );
    gh.run(
        Run {
            id: 2,
            number: 102,
            branch: "agent/b",
            actor: "bot",
            hours: 2,
        },
        &[
            ("linux-gate", line("linux-gate", &base, json!({}))),
            (
                "typescript-client",
                line("typescript-client", &base, json!({})),
            ),
        ],
        &["scripts/ci-local", "apps/x.ts"],
        &[],
    );
    gh.run(
        Run {
            id: 3,
            number: 103,
            branch: "other/c",
            actor: "someone-else",
            hours: 2,
        },
        &[("linux-gate", line("linux-gate", &base, json!({})))],
        &["crates/y.rs"],
        &[],
    );
    gh.run(
        Run { id: 5, number: 105, branch: "agent/e", actor: "bot", hours: 2 },
        &[("linux-gate", line("linux-gate", &base, json!({"tree_of":"merge","head_tree":"fallback:protected_files_differ_from_the_branch_point"})))],
        &["crates/w.rs"],
        &[],
    );
    gh.run(
        Run {
            id: 4,
            number: 104,
            branch: "agent/d",
            actor: "bot",
            hours: 30,
        },
        &[("linux-gate", line("linux-gate", &base, json!({})))],
        &["crates/z.rs"],
        &[],
    );
    let receipts = root.path().join("receipts.jsonl");
    fs::write(
        &receipts,
        "{\"branch\":\"agent/a\",\"agent\":\"agent/seat-one\"}\n{\"nonsense\":1}\nnot json\n",
    )
    .unwrap();
    let result = gh.report(root.path(), &[receipts]);
    assert_eq!(result["runs"], 3);
    assert_eq!(result["checks"]["linux-gate"]["merge_tree"], 1);
    assert_eq!(result["checks"]["linux-gate"]["not_signed"], 1);
    assert_eq!(result["checks"]["linux-gate"]["lane_edit"], 1);
    assert_eq!(result["checks"]["typescript-client"]["skipped"], 1);
    assert_eq!(result["checks"]["typescript-client"]["not_signed"], 1);
    assert_eq!(
        result["not_signed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| json!([
                e["pr"],
                result
                    .receipt(e)
                    .map(|receipt| node_str(&receipt.document, receipt.node()).unwrap())
                    .unwrap_or_else(|| "unknown".to_owned()),
                e["checks"]
            ]))
            .collect::<Vec<_>>(),
        vec![
            json!([101, "agent/seat-one", ["linux-gate"]]),
            json!([102, "unknown", ["typescript-client"]])
        ]
    );
    let text = markdown(&result).unwrap();
    assert!(text.contains("| linux-gate | 0 | 0 | 1 | 1 | 1 |"));
    assert!(text.contains("#101 `agent/a`, seat agent/seat-one: linux-gate (1 run(s))"));
    assert!(
        gh.requests
            .borrow()
            .iter()
            .filter(|r| r.contains("/jobs?"))
            .all(|r| r.ends_with("filter=latest"))
    );
}
#[test]
fn unsigned_check_whose_skip_is_off_is_shadow_unsigned_and_not_listed() {
    let (root, base) = repository(Some(
        json!({"checks":{"linux-gate":{"enforce":true},"linux-fleet-compat":{"enforce":false}}}),
    ));
    let mut gh = Fixture::default();
    gh.run(
        Run {
            id: 1,
            number: 101,
            branch: "agent/a",
            actor: "bot",
            hours: 2,
        },
        &[
            ("linux-gate", line("linux-gate", &base, json!({}))),
            (
                "linux-fleet-compat",
                line("linux-fleet-compat", &base, json!({"reason":"wrong_check"})),
            ),
            (
                "typescript-client",
                line("typescript-client", &base, json!({})),
            ),
        ],
        &["crates/x/src/lib.rs"],
        &[],
    );
    let result = gh.report(root.path(), &[]);
    assert_eq!(result["checks"]["linux-fleet-compat"]["shadow_unsigned"], 1);
    assert_eq!(result["checks"]["linux-fleet-compat"]["not_signed"], 0);
    assert_eq!(result["checks"]["linux-gate"]["not_signed"], 1);
    assert_eq!(result["checks"]["typescript-client"]["not_signed"], 1);
    assert_eq!(
        result["not_signed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| json!([e["pr"], e["checks"]]))
            .collect::<Vec<_>>(),
        vec![json!([101, ["linux-gate", "typescript-client"]])]
    );
    assert!(
        markdown(&result)
            .unwrap()
            .contains("| linux-fleet-compat | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |")
    );
}
#[test]
fn unsigned_check_that_passed_with_execution_skipped_was_not_run_and_not_listed() {
    let (root, base) = repository(None);
    let mut gh = Fixture::default();
    let refused = line(
        "fractal-web",
        &base,
        json!({"decision":"refuse","reason":"wrong_check","tree_of":"head"}),
    );
    gh.run(
        Run {
            id: 1,
            number: 101,
            branch: "agent/a",
            actor: "bot",
            hours: 2,
        },
        &[("fractal-web", refused.clone())],
        &["crates/x.rs"],
        &[
            ("fractal-web-changes", "success"),
            ("fractal-web-execution", "skipped"),
            ("fractal-web", "success"),
        ],
    );
    gh.run(
        Run {
            id: 2,
            number: 102,
            branch: "agent/b",
            actor: "bot",
            hours: 2,
        },
        &[(
            "fractal-web",
            line(
                "fractal-web",
                &base,
                json!({"decision":"refuse","reason":"wrong_check","tree_of":"merge"}),
            ),
        )],
        &["crates/y.rs"],
        &[
            ("fractal-web-execution", "skipped"),
            ("fractal-web", "success"),
        ],
    );
    gh.run(
        Run {
            id: 3,
            number: 103,
            branch: "agent/c",
            actor: "bot",
            hours: 2,
        },
        &[("fractal-web", refused)],
        &["apps/web/x.ts"],
        &[
            ("fractal-web-execution", "skipped"),
            ("fractal-web", "failure"),
        ],
    );
    gh.run(
        Run {
            id: 4,
            number: 104,
            branch: "agent/d",
            actor: "bot",
            hours: 2,
        },
        &[(
            "linux-gate",
            line("linux-gate", &base, json!({"tree_of":"head"})),
        )],
        &["crates/z.rs"],
        &[("linux-gate", "success")],
    );
    let result = gh.report(root.path(), &[]);
    assert_eq!(result["checks"]["fractal-web"]["not_relevant"], 2);
    assert_eq!(result["checks"]["fractal-web"]["not_signed"], 1);
    assert_eq!(result["checks"]["fractal-web"]["merge_tree"], 0);
    assert_eq!(result["checks"]["linux-gate"]["not_signed"], 1);
    assert_eq!(
        result["not_signed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| json!([e["pr"], e["checks"]]))
            .collect::<Vec<_>>(),
        vec![json!([103, ["fractal-web"]]), json!([104, ["linux-gate"]])]
    );
    assert!(
        markdown(&result)
            .unwrap()
            .contains("| fractal-web | 0 | 2 | 0 | 0 | 1 |")
    );
}
#[test]
fn release_surface_pull_request_runs_are_counted_apart_with_minutes() {
    let (root, base) = repository(None);
    let mut gh = Fixture::default();
    gh.run(
        Run {
            id: 1,
            number: 101,
            branch: "agent/a",
            actor: "bot",
            hours: 100,
        },
        &[("linux-gate", line("linux-gate", &base, json!({})))],
        &["crates/x.rs"],
        &[],
    );
    gh.release(
        7,
        4629,
        &[
            (
                "release-build (x86_64-unknown-linux-gnu)",
                "ubuntu-latest",
                "success",
                8.0,
            ),
            (
                "release-build (aarch64-apple-darwin)",
                "macos-15",
                "success",
                20.0,
            ),
            ("installer (macos-15)", "macos-15", "failure", 2.5),
            ("pick-runner", "ubuntu-latest", "skipped", 0.0),
        ],
        "bot",
        2,
    );
    gh.release(
        8,
        4630,
        &[("installer (ubuntu-latest)", "ubuntu-latest", "success", 1.0)],
        "someone-else",
        2,
    );
    gh.release(
        6,
        4600,
        &[("installer (ubuntu-latest)", "ubuntu-latest", "success", 1.0)],
        "bot",
        30,
    );
    let result = gh.report(root.path(), &[]);
    assert_eq!(result["runs"], 0);
    assert_eq!(
        result["release_surface"],
        json!({"workflow":"release-fractal.yml","runs":1,"minutes":30.5,"macos_minutes":22.5,"prs":[4629]})
    );
    assert!(markdown(&result).unwrap().contains("**Release-surface PR runs** (release-fractal.yml on pull_request, real release builds): 1 runs, 30.5 job minutes (22.5 on macOS): #4629"));
    assert!(
        gh.requests
            .borrow()
            .iter()
            .any(|r| r.ends_with("filter=all"))
    );
}
#[test]
fn unreadable_github_exits_two() {
    let gh = Fixture {
        broken: true,
        ..Fixture::default()
    };
    let root = tempfile::tempdir().unwrap();
    let result = report(
        &gh,
        root.path(),
        now() - Duration::hours(24),
        now(),
        &BTreeSet::new(),
        &[],
    );
    assert_eq!(emit(result, false).unwrap(), 2);
}
#[test]
fn receipts_last_record_wins_and_unreadable_paths_are_ignored() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("receipts");
    fs::write(&path,"{\"branch\":\"a\",\"agent\":\"first\"}\n[]\ninvalid\n{\"branch\":\"a\",\"agent\":\"last\"}\n").unwrap();
    let found = seats(&[root.path().join("missing"), path]).unwrap();
    assert_eq!(
        node_str(&found["a"].document, found["a"].node()).unwrap(),
        "last"
    );
}

#[test]
fn shared_python_scalar_semantics_match_pinned_interpreter() {
    let literals = [
        "null",
        "false",
        "true",
        "0",
        "-0",
        "0.0",
        "-0.0",
        "[]",
        "{}",
        "\"\"",
        "[false]",
        "{\"z\":false,\"a\":[null,true,\"x'y\"]}",
        "1e-5",
        "1e16",
        "NaN",
        "Infinity",
        "-Infinity",
        "1e400",
        "184467440737095516160000",
    ];
    let output = crate::pinned_python::command()
        .args(["-B", "-c", "import json,sys; print(json.dumps([(bool(v:=json.loads(s)), str(v), json.dumps(v,indent=2)) for s in sys.argv[1:]]))"])
        .args(literals)
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    for (index, literal) in literals.iter().enumerate() {
        let document = Document::from_text_with_depth_limit(literal, None).unwrap();
        assert_eq!(truthy(document.root()), expected[index][0], "{literal}");
        assert_eq!(
            node_str(&document, document.root()).unwrap(),
            expected[index][1],
            "{literal}"
        );
        let mut encoded = String::new();
        node_json(&document, document.root(), 0, &mut encoded).unwrap();
        assert_eq!(encoded, expected[index][2], "{literal}");
        if let Ok(value) = serde_json::from_str::<Value>(literal) {
            assert_eq!(truthy(&value), expected[index][0], "{literal}");
            // The API schema rejects integers that serde would turn into floats.
            if *literal != "-0" && (!value.is_f64() || literal.contains(['.', 'e', 'E'])) {
                assert_eq!(value_str(&value), expected[index][1], "{literal}");
            }
        }
    }
}

#[test]
fn shared_rounding_and_general_format_match_pinned_exact_ties() {
    let values = [
        -0.0,
        0.05,
        0.15,
        0.25,
        0.35,
        0.75,
        1.25,
        1.75,
        2.25,
        2.675,
        123456.5,
        123457.5,
        999999.5,
        999999.95,
        1000000.0,
        0.00009999995,
        0.00001,
        1e20,
    ];
    let output = crate::pinned_python::command()
        .args(["-B", "-c", "import json,struct,sys; print(json.dumps([(format(v,'g'),[struct.pack('>d',round(v,n)).hex() for n in (1,2)]) for v in map(float,sys.argv[1:])]))"])
        .args(values.iter().map(|value| format!("{value:?}")))
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    for (index, value) in values.into_iter().enumerate() {
        assert_eq!(general(value), expected[index][0], "{value:?}");
        for digits in [1, 2] {
            assert_eq!(
                format!("{:016x}", rounded(value, digits).to_bits()),
                expected[index][1][digits - 1].as_str().unwrap(),
                "{value:?}, {digits}"
            );
        }
    }
    // Independent fixed expectations include exact binary halfway ties and
    // decimal-looking non-ties; the CLI differential covers release accounting.
    for (value, digits, expected) in [
        (0.25, 1, 0.2_f64),
        (0.75, 1, 0.8),
        (1.25, 1, 1.2),
        (1.75, 1, 1.8),
        (2.675, 2, 2.67),
        (0.15, 1, 0.1),
        (-0.0, 1, -0.0),
    ] {
        assert_eq!(
            rounded(value, digits).to_bits(),
            expected.to_bits(),
            "{value} {digits}"
        );
    }
}

#[test]
fn receipt_splitlines_matches_python_all_boundaries_and_replacement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("receipts");
    for separator in [
        "\n", "\r", "\r\n", "\u{b}", "\u{c}", "\u{1c}", "\u{1d}", "\u{1e}", "\u{85}", "\u{2028}",
        "\u{2029}",
    ] {
        let bytes = format!(
            "{{\"branch\":\"a\",\"agent\":\"first\"}}{separator}{{\"branch\":\"a\",\"agent\":\"last\"}}{separator}"
        );
        fs::write(&path, bytes).unwrap();
        let found = seats(std::slice::from_ref(&path)).unwrap();
        assert_eq!(
            node_str(&found["a"].document, found["a"].node()).unwrap(),
            "last",
            "{separator:?}"
        );
    }
    fs::write(
        &path,
        b"{\"branch\":\"a\",\"agent\":\"\xed\xa0\x80\xf0\x90\x80x\xff\"}\n",
    )
    .unwrap();
    let found = seats(&[path]).unwrap();
    assert_eq!(
        node_str(&found["a"].document, found["a"].node()).unwrap(),
        "\u{fffd}\u{fffd}\u{fffd}\u{fffd}x\u{fffd}"
    );
}

#[test]
fn raw_surrogate_seats_and_unhashable_branches_fail_instead_of_changing_data() {
    let document = Document::from_text_with_depth_limit("\"\\ud800\"", None).unwrap();
    assert!(
        node_str(&document, document.root())
            .unwrap_err()
            .to_string()
            .contains("UnicodeEncodeError")
    );
    let document = Document::from_text_with_depth_limit("[\"\\ud800\"]", None).unwrap();
    assert_eq!(node_str(&document, document.root()).unwrap(), "['\\ud800']");
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("receipts");
    for branch in ["[1]", "{\"x\":1}"] {
        fs::write(&path, format!("{{\"branch\":{branch},\"agent\":\"seat\"}}")).unwrap();
        assert!(seats(std::slice::from_ref(&path)).is_err(), "{branch}");
    }
}

#[test]
fn absent_actor_is_not_an_empty_login() {
    let actors = BTreeSet::from([String::new()]);
    for actor in [Value::Null, json!({}), json!({"login":null})] {
        assert!(!selected(
            &json!({"status":"completed","actor":actor}),
            &actors
        ));
    }
    assert!(selected(
        &json!({"status":"completed","actor":{"login":""}}),
        &actors
    ));
}
