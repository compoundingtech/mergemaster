use super::*;

fn now() -> DateTime<Utc> {
    parse_time("2026-10-22T12:00:00Z").unwrap()
}
fn at(hours: i64) -> DateTime<Utc> {
    now() - Duration::hours(hours)
}
fn row(id: u64, hours: i64) -> Row {
    Row {
        check: "genie-freshness".to_owned(),
        run: id,
        created: Some(at(hours)),
        actor: "otter-bot".to_owned(),
        base: String::new(),
        fields: json!({"check":"genie-freshness","decision":"run","outcome":"satisfied","log":"ok","observed_at":iso(at(30))}),
        real: Some("success".to_owned()),
        aggregate: false,
        members_red: vec![],
        cancelled: false,
        old_base: None,
    }
}
fn history(count: usize) -> Vec<Row> {
    (0..count)
        .map(|i| {
            row(
                1000 + i as u64,
                if i == 0 {
                    25
                } else {
                    23 - i as i64 * 20 / count as i64
                },
            )
        })
        .collect()
}
fn eval(rows: &[Row]) -> Value {
    evaluate(rows, false, now(), false, None)
}
fn reasons(result: &Value) -> Vec<String> {
    array(&result["why_not"])
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn thirty_fresh_lines_require_full_window_and_enforced_checks_still_report() {
    let mut rows = history(30);
    assert_eq!(
        eval(&rows),
        json!({"enforce":false,"lines":29,"satisfied_log_ok":29,"log_missing":0,"unlogged_pass_unexplained":0,"hidden_red":[],"visible_red":[],"log_window_start":iso(at(25)),"old_base_lines":{},"cancelled_runs":[],"ready":false,"why_not":["29 satisfied lines with log=ok, fewer than 30"]})
    );
    rows.push(row(2000, 1));
    assert_eq!(reasons(&eval(&rows)), Vec::<String>::new());
    assert_eq!(evaluate(&[], true, now(), false, None)["enforce"], true);
    assert_eq!(evaluate(&[], true, now(), false, None)["lines"], 0);
}
#[test]
fn freshness_unpinned_missing_and_latency_reasons() {
    let mut rows = history(40);
    for (i, value) in ["stale", "unsigned", "absent"].iter().enumerate() {
        let mut r = row(3000 + i as u64, 2);
        r.fields["log"] = json!(value);
        rows.push(r);
    }
    assert_eq!(
        reasons(&eval(&rows)),
        [
            "1 lines with log=stale",
            "1 lines with log=absent",
            "1 lines with log=unsigned"
        ]
    );
    let mut r = row(1, 1);
    r.fields.as_object_mut().unwrap().remove("log");
    assert_eq!(
        &reasons(&eval(&[r]))[..2],
        ["1 lines with log=-", "no line with a log value"]
    );
    let mut rows = history(40);
    let mut unset = row(3000, 20);
    unset.fields["log"] = json!("-");
    rows.push(unset);
    let result = eval(&rows);
    assert_eq!(result["ready"], false);
    assert!(reasons(&result)[1].contains("less than 24 h ago"));
    assert!(parse_time(result["log_window_start"].as_str().unwrap()).unwrap() > at(20));
    let mut rows = history(40);
    for (i, seconds) in [200, -60, 300].iter().enumerate() {
        let mut r = row(3000 + i as u64, 3);
        r.fields["log"] = json!("unlogged_pass");
        r.fields["observed_at"] = json!(iso(at(3) - Duration::seconds(*seconds)));
        rows.push(r);
    }
    let mut no_time = row(3003, 2);
    no_time.fields["log"] = json!("unlogged_pass");
    no_time.fields["observed_at"] = json!("-");
    rows.push(no_time);
    let mut missing = row(3004, 1);
    missing.fields["log"] = json!("missing");
    missing.fields["outcome"] = json!("rejected");
    rows.push(missing);
    let result = eval(&rows);
    assert_eq!(result["unlogged_pass_unexplained"], 2);
    assert_eq!(result["log_missing"], 1);
    assert_eq!(
        reasons(&result),
        [
            "1 lines with log=missing",
            "2 unexplained log=unlogged_pass"
        ]
    );
}
#[test]
fn old_base_lines_are_counted_but_do_not_restart_window() {
    let mut rows = history(40);
    for (i, reason) in ["no_policy", "no-gate-at-base"].iter().enumerate() {
        let mut r = row(3000 + i as u64, 1);
        r.fields["log"] = json!("-");
        r.old_base = Some(reason.to_string());
        rows.push(r);
    }
    let result = eval(&rows);
    assert_eq!(result["ready"], true);
    assert_eq!(
        result["old_base_lines"],
        json!({"no_policy":1,"no-gate-at-base":1})
    );
    assert_eq!(result["log_window_start"], iso(at(25)));
    rows.last_mut().unwrap().old_base = None;
    assert_eq!(reasons(&eval(&rows))[0], "1 lines with log=-");
}
#[test]
fn none_and_aggregate_member_times_are_not_the_oldest_note() {
    let mut r = row(3000, 3);
    r.fields["log"] = json!("unlogged_pass");
    r.fields["observed_at"] = json!(iso(at(3) - Duration::seconds(170)));
    r.fields["log_unlogged_observed_at"] = json!("None");
    assert!(explained(&r, None));
    r.fields["observed_at"] = json!("None");
    assert!(!explained(&r, None));
    r.fields["observed_at"] = json!(iso(at(4)));
    r.fields["log_unlogged_observed_at"] = json!(iso(at(3) - Duration::seconds(100)));
    assert!(explained(&r, None));
    r.fields["log_unlogged_observed_at"] = json!(iso(at(3) - Duration::seconds(300)));
    assert!(!explained(&r, None));
    for bad in ["a=0123456789ab+2_more", "a=not-hex", "bad"] {
        r.fields["log_unlogged_crates"] = json!(bad);
        assert!(unlogged_records(&r.fields).is_none());
    }
    r.fields["log_unlogged_crates"] = json!("a=0123456789ab+b=abcdef012345");
    assert_eq!(
        unlogged_records(&r.fields),
        Some(vec!["0123456789ab".to_owned(), "abcdef012345".to_owned()])
    );
}
#[test]
fn hidden_and_visible_red_attempts_deduplicate_by_run() {
    let mut rows = history(40);
    let mut hidden = row(4001, 5);
    hidden.real = Some("failure".to_owned());
    rows.push(hidden.clone());
    hidden.real = Some("success".to_owned());
    rows.push(hidden);
    let mut uncovered = row(4002, 4);
    uncovered.fields["outcome"] = json!("no_note");
    uncovered.real = Some("failure".to_owned());
    rows.push(uncovered);
    assert_eq!(eval(&rows)["hidden_red"], json!([4001]));
    assert_eq!(reasons(&eval(&rows)), ["1 runs with a hidden red"]);
    let mut rows = history(40);
    for (id, reds) in [
        (5000, vec![]),
        (5001, vec![]),
        (5001, vec!["linux-tests".to_owned()]),
        (6000, vec!["linux-tests".to_owned()]),
        (6001, vec!["linux-tests-shard-3".to_owned()]),
    ] {
        let mut r = row(id, 5);
        r.aggregate = true;
        r.real = Some("failure".to_owned());
        r.members_red = reds;
        rows.push(r);
    }
    let result = eval(&rows);
    assert_eq!(result["hidden_red"], json!([5001, 6000, 6001]));
    assert_eq!(result["visible_red"], json!([5000]));
    rows.retain(|r| r.run == 5000 || r.run < 5000);
    assert_eq!(eval(&rows)["ready"], true);
}
#[test]
fn cancelled_attempt_is_neither_ok_nor_red_but_failure_stays() {
    let mut rows = history(40);
    let before = eval(&rows)["satisfied_log_ok"].clone();
    let mut cancelled = row(7100, 3);
    cancelled.cancelled = true;
    cancelled.real = Some("failure".to_owned());
    cancelled.aggregate = true;
    cancelled.members_red = vec!["execution".to_owned()];
    rows.push(cancelled);
    let result = eval(&rows);
    assert_eq!(result["cancelled_runs"], json!([7100]));
    assert_eq!(result["hidden_red"], json!([]));
    assert_eq!(result["satisfied_log_ok"], before);
    assert_eq!(result["lines"], 40);
    let mut failed = row(7101, 2);
    failed.real = Some("failure".to_owned());
    rows.push(failed);
    assert_eq!(eval(&rows)["hidden_red"], json!([7101]));
    assert_eq!(eval(&rows)["visible_red"], json!([]));
}
#[test]
fn lowered_host_only_five_agreements_and_no_disagreement() {
    let mut rows = history(40);
    for r in &mut rows {
        r.fields["trust_level"] = json!("fleet");
    }
    for i in 0..4 {
        let mut r = row(1200 + i, 10 - i as i64);
        r.fields["trust_level"] = json!("host");
        rows.push(r);
    }
    let result = evaluate(&rows, false, now(), true, None);
    assert_eq!(result["agreeing"], 4);
    assert_eq!(result["disagreeing"], json!([]));
    assert_eq!(result["ready"], false);
    assert!(
        !reasons(&result)
            .iter()
            .any(|why| why.contains("fewer than 30"))
    );
    let mut unlogged = row(1300, 2);
    unlogged.fields["trust_level"] = json!("host");
    unlogged.fields["log"] = json!("unlogged_pass");
    unlogged.fields["observed_at"] = json!(iso(at(2) - Duration::seconds(60)));
    rows.push(unlogged);
    assert_eq!(evaluate(&rows, false, now(), true, None)["agreeing"], 4);
    let mut host = row(1301, 1);
    host.fields["trust_level"] = json!("host");
    rows.push(host.clone());
    assert_eq!(evaluate(&rows, false, now(), true, None)["ready"], true);
    host.run = 1302;
    rows.push(host.clone());
    host.run = 1303;
    host.real = Some("failure".to_owned());
    rows.push(host);
    let result = evaluate(&rows, false, now(), true, None);
    assert_eq!(result["agreeing"], 6);
    assert_eq!(result["disagreeing"], json!([1303]));
    assert_eq!(result["hidden_red"], json!([1303]));
    assert!(
        reasons(&result)
            .contains(&"1 runs where a host note disagreed with the real job".to_owned())
    );
}
#[test]
fn policy_preconditions_and_no_consumers_block_proposals() {
    let ready = json!({"ready":true,"why_not":[]});
    assert_eq!(
        preconditions(ready.clone(), "linux-gate", &json!({}), None)["why_not"],
        json!(["the policy does not require clippy_base_sha of host and agent linux-gate notes"])
    );
    let mut entry = json!({"kinds":{"wrapper":{"by_level":{"host":{"required_inputs":["clippy_base_sha"]},"agent":{"required_inputs":[]}}}}});
    assert_eq!(
        preconditions(ready.clone(), "linux-gate", &entry, None)["why_not"],
        json!(["the policy does not require clippy_base_sha of agent linux-gate notes"])
    );
    entry["kinds"]["wrapper"]["by_level"]["agent"]["required_inputs"] = json!(["clippy_base_sha"]);
    assert_eq!(
        preconditions(ready.clone(), "linux-gate", &entry, None),
        ready
    );
    let existing = json!({"ready":false,"why_not":["x"]});
    assert_eq!(
        preconditions(existing, "linux-gate", &json!({}), None)["why_not"][0],
        "x"
    );
    assert_eq!(
        preconditions(ready.clone(), "other", &json!({}), None),
        ready
    );
    let mut web = json!({"kinds":{"wrapper":{}}});
    assert_eq!(
        array(&preconditions(ready.clone(), "fractal-web", &web, None)["why_not"]).len(),
        2
    );
    web["kinds"]["wrapper"]["shard_inputs"] = json!({"count":"n"});
    assert_eq!(
        array(&preconditions(ready.clone(), "fractal-web", &web, None)["why_not"]).len(),
        1
    );
    web["kinds"]["wrapper"]["input_order"] = json!({"kit_inputs":["false","true"]});
    assert_eq!(
        preconditions(ready.clone(), "fractal-web", &web, None)["ready"],
        false
    );
    web["kinds"]["wrapper"]["input_order"]["kit_inputs"] = json!(["true", "false"]);
    assert_eq!(
        preconditions(ready.clone(), "fractal-web", &web, None),
        ready
    );
    assert_eq!(
        preconditions(ready.clone(), "rust-tests", &json!({}), Some(&vec![]))["why_not"],
        json!([format!("no job of {WORKFLOW} skips on its skip output")])
    );
    assert_eq!(
        preconditions(
            ready.clone(),
            "rust-tests",
            &json!({}),
            Some(&vec!["tests".to_owned()])
        ),
        ready
    );
}
#[test]
fn members_follow_workflow_skip_reads_and_matrix_names() {
    // The Python self-test ran inside the pinned Fractal fixture overlay, which owns
    // fleet.yml and the skip policy; this repository has neither at its root.
    let root = std::path::PathBuf::from(
        std::env::var("MERGEMASTER_FRACTAL_FIXTURE")
            .expect("MERGEMASTER_FRACTAL_FIXTURE must point to the pinned Fractal consumer"),
    );
    let policy_path = root.join(".st/evidence-skip-policy.json");
    let policy: Value = serde_json::from_str(&fs::read_to_string(policy_path).unwrap()).unwrap();
    let workflow = fs::read_to_string(root.join(".github/workflows/fleet.yml")).unwrap();
    let members = skipped_members(&workflow, policy["checks"].as_object().unwrap()).unwrap();
    assert_eq!(
        members.keys().map(String::as_str).collect::<Vec<_>>(),
        ["fractal-web", "linux-gate", "rust-tests"]
    );
    assert_eq!(members["fractal-web"], ["fractal-web-execution"]);
    assert_eq!(
        members["linux-gate"],
        [
            "linux-clippy",
            "linux-fleet-compat",
            "linux-test-build",
            "linux-tests",
            "linux-tests-shard-2",
            "linux-tests-shard-3",
            "linux-tests-shard-4"
        ]
    );
    assert_eq!(
        members["rust-tests"],
        [
            "linux-test-build",
            "linux-tests",
            "linux-tests-shard-2",
            "linux-tests-shard-3",
            "linux-tests-shard-4"
        ]
    );
    for always in ["upgrade-impact", "fractal-web-changes"] {
        assert!(
            !members["fractal-web"]
                .iter()
                .chain(&members["linux-gate"])
                .any(|s| s == always)
        );
    }
    assert!(
        skipped_members(
            "jobs:\n  linux-gate:\n    steps: []\n",
            policy["checks"].as_object().unwrap()
        )
        .is_err()
    );
    assert_eq!(
        skipped_members(
            "jobs:\n  linux-gate:\n    if: always()\n",
            json!({"rust-tests":{}}).as_object().unwrap()
        )
        .unwrap()["rust-tests"],
        Vec::<String>::new()
    );
    assert!(member_of(
        "fractal-web-execution (0)",
        &members["fractal-web"]
    ));
    assert!(!member_of(
        "fractal-web-execution-extra",
        &members["fractal-web"]
    ));
    for (values, expected) in [
        (vec![], None),
        (vec!["skipped"], None),
        (vec!["success", "skipped"], Some("success")),
        (vec!["success", "cancelled"], Some("failure")),
        (vec!["failure"], Some("failure")),
    ] {
        assert_eq!(derived_result(values.into_iter()).as_deref(), expected);
    }
}
#[test]
fn presign_rates_take_best_note_per_account_head() {
    let mut rows = Vec::new();
    for (id, hours, actor, head, pr, level, outcome) in [
        (1, 2, "otter-bot", "a", "5", "host", "satisfied"),
        (1, 2, "otter-bot", "a", "5", "-", "no_note"),
        (2, 3, "otter-bot", "b", "5", "fleet", "satisfied"),
        (3, 4, "otter-bot", "c", "6", "-", "no_note"),
        (4, 4, "otter-bot", "c", "6", "-", "no_note"),
        (5, 1, "heron-bot", "d", "8", "agent", "satisfied"),
        (6, 30, "heron-bot", "e", "8", "agent", "satisfied"),
    ] {
        let mut r = row(id, hours);
        r.actor = actor.to_owned();
        r.fields["pr_head"] = json!(head);
        r.fields["pr"] = json!(pr);
        r.fields["trust_level"] = json!(level);
        r.fields["outcome"] = json!(outcome);
        rows.push(r);
    }
    assert_eq!(
        presign_rates(&rows, now()),
        json!({"heron-bot":{"heads":1,"presigned":1,"ci_note":0,"no_note":0,"presigned_share":1.0},"otter-bot":{"heads":3,"presigned":1,"ci_note":1,"no_note":1,"presigned_share":0.333}})
    );
}
#[test]
fn flip_policy_preserves_other_entries_order_and_narrows_only_lowered_trust() {
    let policy = json!({"version":1,"checks":{"genie-freshness":{"trust_levels":["host"],"enforce":false,"kinds":{"wrapper":{"trust_levels":["host","fleet"]}}},"linux-gate":{"trust_levels":[],"enforce":false,"sample_one_in":5},"rust-tests":{"enforce":false,"events":["pull_request"],"sample_one_in":5,"kinds":{"wrapper":{"trust_levels":["fleet","host","agent","queue"],"by_level":{"queue":{"events":["merge_group"]}}}}},"already":{"enforce":true}}});
    let text = pretty(&policy).unwrap();
    let (new, entry) = flip_policy(&text, "genie-freshness").unwrap();
    let new: Value = serde_json::from_str(&new).unwrap();
    assert_eq!(
        entry
            .as_object()
            .unwrap()
            .keys()
            .take(4)
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["trust_levels", "enforce", "events", "sample_one_in"]
    );
    assert_eq!(entry["enforce"], true);
    assert_eq!(entry["events"], json!(["pull_request"]));
    assert_eq!(entry["sample_one_in"], 1);
    assert_eq!(entry["kinds"], policy["checks"]["genie-freshness"]["kinds"]);
    let mut expected = policy.clone();
    expected["checks"]["genie-freshness"] = entry;
    assert_eq!(new, expected);
    let (new, entry) = flip_policy(&text, "rust-tests").unwrap();
    assert_eq!(
        entry["kinds"]["wrapper"]["trust_levels"],
        json!(["host", "agent", "queue"])
    );
    assert_eq!(
        entry["kinds"]["wrapper"]["by_level"]["queue"]["events"],
        json!(["merge_group"])
    );
    assert_eq!(entry["sample_one_in"], 1);
    let mut expected = policy.clone();
    expected["checks"]["rust-tests"] = entry;
    assert_eq!(serde_json::from_str::<Value>(&new).unwrap(), expected);
    let unusual = text.replace("\"version\": 1,", "\"version\":  1,");
    for check in ["genie-freshness", "linux-gate"] {
        let (new, entry) = flip_policy(&unusual, check).unwrap();
        assert!(new.contains("\"version\":  1,"));
        assert_eq!(entry["sample_one_in"], 1);
        assert_eq!(
            serde_json::from_str::<Value>(&new).unwrap()["checks"][check],
            entry
        );
    }
    assert!(flip_policy(&unusual, "already").is_err());
    let mut bad = policy["checks"]["rust-tests"].clone();
    bad["kinds"]["wrapper"]["trust_levels"] = json!(["host"]);
    assert!(flipped_entry(&bad, true).is_err());
}
fn doc() -> String {
    format!(
        "{DOC_SECTION}\n\n| Check | enforce | events | sample | Since |\n| --- | --- | --- | --- | --- |\n| `typescript-client` | true | `pull_request` | 5 | this change |\n| `web` (whole-check note; one shard never counts), `other` | false | - | 5 | - |\n\nAfter.\n"
    )
}
#[test]
fn documentation_note_moves_with_check_and_tuple_is_appended() {
    let entry = json!({"events":["pull_request"],"sample_one_in":5});
    let flipped = flip_doc(&doc(), "web", &entry, "2026-10-23").unwrap();
    assert!(flipped.contains("| `web` (whole-check note; one shard never counts) | true | `pull_request` | 5 | 2026-10-23 |\n"));
    assert!(flipped.contains("| `other` | false |"));
    assert!(flip_doc(&doc(), "we", &entry, "today").is_err());
    let only = doc().replace(", `other`", "");
    assert!(
        !flip_doc(&only, "web", &entry, "today")
            .unwrap()
            .contains("| false |")
    );
    assert_eq!(
        flip_test_list(
            "  enforced = ('one', 'two')\nx\n",
            "test",
            "enforced",
            "web"
        )
        .unwrap(),
        "  enforced = ('one', 'two', 'web')\nx\n"
    );
    assert!(flip_test_list("enforced = ('web',)\n", "test", "enforced", "web").is_err());
    assert!(
        flip_test_list(
            "enforced = ('a',)\nenforced = ('b',)\n",
            "test",
            "enforced",
            "web"
        )
        .is_err()
    );
}
#[test]
fn selected_new_policy_is_only_policy_written_and_failed_edits_write_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let tree = temp.path();
    let policy = pretty(&json!({"checks":{"web":{"enforce":false,"trust_levels":[]}}})).unwrap();
    for path in [POLICY, ".fractal/evidence-skip-policy.json"] {
        fs::create_dir_all(tree.join(path).parent().unwrap()).unwrap();
        fs::write(tree.join(path), &policy).unwrap();
    }
    fs::create_dir_all(tree.join(DOC).parent().unwrap()).unwrap();
    fs::write(tree.join(DOC), doc()).unwrap();
    for (path, name) in TEST_LISTS {
        fs::create_dir_all(tree.join(path).parent().unwrap()).unwrap();
        fs::write(tree.join(path), format!("{name} = ('other',)\n")).unwrap();
    }
    flip(tree, "web", "2026-10-27").unwrap();
    assert_eq!(fs::read_to_string(tree.join(POLICY)).unwrap(), policy);
    let new: Value = serde_json::from_str(
        &fs::read_to_string(tree.join(".fractal/evidence-skip-policy.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(new["checks"]["web"]["enforce"], true);
    let note: Value = serde_json::from_str(
        &fs::read_to_string(tree.join("release-notes/evidence-enforce-web.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(note, release_note("web"));
    for key in [
        "replay",
        "schema",
        "rules",
        "compatibility",
        "downtime",
        "manual",
        "recovery",
    ] {
        assert_eq!(note[key]["status"], "none");
        assert!(note[key]["detail"].as_str().unwrap().len() > 3);
    }
    assert!(
        flip(tree, "web", "today")
            .unwrap_err()
            .to_string()
            .contains("already exists")
    );
}

fn init_repo(root: &Path) {
    fs::create_dir_all(root).unwrap();
    git(root, &["init", "-q", "-b", "main"]).unwrap();
    for (key, value) in [
        ("user.name", "Test"),
        ("user.email", "test@example.com"),
        ("commit.gpgsign", "false"),
        ("maintenance.auto", "false"),
        ("gc.auto", "0"),
    ] {
        git(root, &["config", key, value]).unwrap();
    }
}
fn commit(root: &Path, message: &str) -> String {
    git(root, &["add", "-A"]).unwrap();
    git(root, &["commit", "-q", "-m", message]).unwrap();
    git(root, &["rev-parse", "HEAD"]).unwrap().trim().to_owned()
}
#[test]
fn historical_base_proof_requires_readable_commit_and_missing_gate_or_policy_entry() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    init_repo(root);
    fs::create_dir_all(root.join(".st")).unwrap();
    fs::write(root.join(POLICY), "{\"checks\":{}}").unwrap();
    let no_entry = commit(root, "old");
    fs::write(root.join(POLICY), "{\"checks\":{\"genie-freshness\":{}}}").unwrap();
    let main = commit(root, "entry");
    fs::create_dir_all(root.join("scripts")).unwrap();
    fs::write(root.join("scripts/ci-evidence-gate"), "#").unwrap();
    let with_gate = commit(root, "gate");
    let mut r = row(3000, 1);
    r.fields = json!({"outcome":"unavailable","reason":"no_policy","log":"-","base":no_entry});
    let mut seen = BTreeMap::new();
    assert_eq!(old_base(root, &r, &mut seen).as_deref(), Some("no_policy"));
    r.fields["base"] = json!(main);
    assert!(old_base(root, &r, &mut seen).is_none());
    r.fields["reason"] = json!("no-gate-at-base");
    r.fields.as_object_mut().unwrap().remove("base");
    r.base = main;
    assert_eq!(
        old_base(root, &r, &mut seen).as_deref(),
        Some("no-gate-at-base")
    );
    r.base = with_gate;
    assert!(old_base(root, &r, &mut seen).is_none());
    r.base = "f".repeat(40);
    assert!(old_base(root, &r, &mut seen).is_none());
    r.base.clear();
    assert!(old_base(root, &r, &mut seen).is_none());
    r.fields["outcome"] = json!("satisfied");
    assert!(old_base(root, &r, &mut seen).is_none());
    // A present .fractal policy is authoritative, including malformed contents.
    fs::create_dir_all(root.join(".fractal")).unwrap();
    fs::write(root.join(".fractal/evidence-skip-policy.json"), "bad").unwrap();
    let malformed = commit(root, "malformed");
    r.fields = json!({"outcome":"unavailable","reason":"no_policy","log":"-","base":malformed});
    assert!(old_base(root, &r, &mut seen).is_none());
}
#[test]
fn published_log_latency_uses_run_creation_and_newest_head_not_note_observation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let origin = temp.path().join("origin.git");
    init_repo(&root);
    let out = Command::new("git")
        .args(["init", "-q", "--bare", "-b", "main"])
        .arg(&origin)
        .output()
        .unwrap();
    assert!(out.status.success());
    git(&origin, &["config", "receive.autogc", "false"]).unwrap();
    git(
        &root,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    )
    .unwrap();
    let late = "a".repeat(40);
    let stalled = "b".repeat(40);
    let one_pull = "c".repeat(40);
    let mut listed = String::new();
    for (time, records) in [
        (at(4), vec![]),
        (
            at(3) + Duration::seconds(54),
            vec![late.clone(), one_pull.clone()],
        ),
        (at(2) + Duration::seconds(200), vec![]),
        (at(2) + Duration::seconds(600), vec![stalled.clone()]),
    ] {
        for record in records {
            listed.push_str(&format!("record {record} test\n"));
        }
        fs::write(root.join("log"), &listed).unwrap();
        git(&root, &["add", "-A"]).unwrap();
        let stamp = iso(time);
        let out = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args([
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                &format!("evidence-log v1 as_of={stamp} added=1"),
            ])
            .env("GIT_AUTHOR_DATE", &stamp)
            .env("GIT_COMMITTER_DATE", &stamp)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    git(&root, &["push", "-q", "origin", &format!("HEAD:{LOG_REF}")]).unwrap();
    let log = PublishedLog::load(&root, &temp.path().join("cache"), at(26)).unwrap();
    let mut r = row(3000, 3);
    r.fields["record"] = json!(late);
    r.fields["observed_at"] = json!(iso(at(3) - Duration::seconds(366)));
    assert!(explained(&r, Some(&log)));
    r.created = Some(at(2));
    r.fields["record"] = json!(stalled);
    r.fields["observed_at"] = json!(iso(at(2) - Duration::seconds(100)));
    assert!(!explained(&r, Some(&log))); // observed fallback would incorrectly excuse this.
    r.created = Some(at(3) + Duration::seconds(134));
    r.fields["record"] = json!(one_pull);
    r.fields["observed_at"] = json!(iso(r.created.unwrap() - Duration::seconds(289)));
    assert!(explained(&r, Some(&log)));
    r.fields["log_unlogged_crates"] = json!("crate=aaaaaaaaaaaa+2_more");
    r.fields["observed_at"] = json!(iso(r.created.unwrap() - Duration::seconds(100)));
    assert!(explained(&r, Some(&log)));
}

#[test]
fn cancelled_wrapper_aggregate_and_matrix_member_decisions_keep_only_real_failures() {
    let cancelled = json!({"conclusion":"cancelled"});
    let failure = json!({"conclusion":"failure"});
    let needed = vec!["execution".to_owned()];
    for conclusion in ["cancelled", "success", "skipped"] {
        let job = json!({"name":"execution","conclusion":conclusion});
        let unrelated = json!({"name":"upgrade-impact","conclusion":"failure"});
        assert!(no_evidence(
            &cancelled,
            &[&job, &unrelated],
            &needed,
            Some("failure")
        ));
        assert!(!no_evidence(
            &failure,
            &[&job, &unrelated],
            &needed,
            Some("failure")
        ));
    }
    let job = json!({"name":"execution","conclusion":"failure"});
    assert!(!no_evidence(&cancelled, &[&job], &needed, Some("failure")));
    for own in [Some("success"), Some("cancelled"), None] {
        assert!(no_evidence(&cancelled, &[], &[], own));
    }
    assert!(!no_evidence(&cancelled, &[], &[], Some("failure")));
    for (conclusions, expected) in [
        (vec!["cancelled", "cancelled"], true),
        (vec!["cancelled", "failure"], false),
        (vec!["success", "failure"], false),
    ] {
        let jobs: Vec<Value> = conclusions
            .iter()
            .enumerate()
            .map(|(i, c)| json!({"name":format!("execution ({i})"),"conclusion":c}))
            .collect();
        assert_eq!(
            no_evidence(
                &cancelled,
                &jobs.iter().collect::<Vec<_>>(),
                &needed,
                Some("failure")
            ),
            expected
        );
    }
    let aggregate = vec!["linux-tests".to_owned(), "linux-clippy".to_owned()];
    let tests = json!({"name":"linux-tests","conclusion":"cancelled"});
    let impact = json!({"name":"upgrade-impact","conclusion":"failure"});
    let clippy = json!({"name":"linux-clippy","conclusion":"failure"});
    assert!(no_evidence(
        &cancelled,
        &[&tests, &impact],
        &aggregate,
        Some("failure")
    ));
    assert!(!no_evidence(
        &cancelled,
        &[&tests, &clippy],
        &aggregate,
        Some("failure")
    ));
}
