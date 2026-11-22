//! Fixed-clock CLI recordings from the immutable Python source, including API calls.
#[path = "../src/pinned_python.rs"]
mod pinned_python;

use serde_json::Value;
use std::path::Path;

fn fixture(command: &str) -> Value {
    let bytes = match command {
        "flip-ready" => include_str!("../../../tests/fixtures/oracle/flip-ready.json"),
        "skip-report" => include_str!("../../../tests/fixtures/oracle/skip-report.json"),
        _ => panic!("unknown fixture"),
    };
    serde_json::from_str(bytes).unwrap()
}

fn replay(command: &str) {
    let root = Path::new(&std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    let output = pinned_python::command()
        .args([
            "-B",
            "-c",
            "import runpy,sys; module=runpy.run_path(sys.argv[1]); module['replay_flip_skip'](sys.executable, sys.argv[2], (sys.argv[3],))",
        ])
        .arg(root.join("tests/oracle_corpus.py"))
        .arg(env!("CARGO_BIN_EXE_mergemaster"))
        .arg(command)
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{command}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn flip_ready_matches_frozen_stdout_stderr_status_endpoints_and_cache_reuse() {
    replay("flip-ready");
}

#[test]
fn skip_report_matches_frozen_json_markdown_endpoints_receipts_and_cache_reuse() {
    replay("skip-report");
}

#[test]
fn recordings_cover_ready_red_cancellation_latency_and_all_report_categories() {
    let flip = fixture("flip-ready");
    let cases = flip["cases"].as_array().unwrap();
    let report = |id: &str| -> Value {
        let case = cases.iter().find(|case| case["id"] == id).unwrap();
        serde_json::from_str(case["observations"][0]["stdout"].as_str().unwrap()).unwrap()
    };
    assert_eq!(report("ready-cache-reuse")["checks"]["lint"]["ready"], true);
    assert_eq!(
        report("hidden-red-and-missing")["checks"]["lint"]["hidden_red"],
        serde_json::json!([1])
    );
    assert_eq!(
        report("hidden-red-and-missing")["checks"]["lint"]["log_missing"],
        1
    );
    assert_eq!(
        report("cancelled-run")["checks"]["lint"]["cancelled_runs"],
        serde_json::json!([1])
    );
    assert_eq!(
        report("latency-observed-fallback")["checks"]["lint"]["unlogged_pass_unexplained"],
        0
    );
    let skip = fixture("skip-report");
    let case = &skip["cases"][0];
    let report: Value =
        serde_json::from_str(case["observations"][0]["stdout"].as_str().unwrap()).unwrap();
    for (check, category) in [
        ("skip", "skipped"),
        ("irrelevant", "not_relevant"),
        ("lane", "lane_edit"),
        ("merge", "merge_tree"),
        ("unsigned", "not_signed"),
        ("failed", "failed"),
        ("protected", "protected"),
        ("sampled", "sampled"),
        ("shadow", "shadow"),
        ("shadow_unsigned", "shadow_unsigned"),
        ("other", "other"),
    ] {
        assert_eq!(report["checks"][check][category], 1, "{check}: {category}");
    }
    assert_eq!(report["not_signed"][0]["seat"], "seat-one");
    assert_eq!(report["release_surface"]["minutes"], 5.5);
    assert_eq!(report["release_surface"]["macos_minutes"], 3.5);
}

#[test]
fn recordings_bound_transport_retries_pagination_and_cancelled_log_absence() {
    let fixture = fixture("flip-ready");
    let cases = fixture["cases"].as_array().unwrap();
    let observation = |id: &str| -> &Value {
        &cases.iter().find(|case| case["id"] == id).unwrap()["observations"][0]
    };
    for (id, count, status) in [
        ("listing-empty", 4, 2),
        ("listing-short", 4, 2),
        ("listing-recover", 2, 0),
        ("listing-two-pages", 2, 0),
        ("listing-quiet", 1, 0),
        ("listing-cap", 10, 2),
        ("gh-error", 3, 2),
        ("gh-retry-recovery", 3, 0),
    ] {
        let observed = observation(id);
        let listing_calls = observed["calls"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|call| {
                call[0] == "gh"
                    && call[1]
                        .as_str()
                        .unwrap()
                        .contains("/workflows/fleet.yml/runs?")
            })
            .count();
        assert_eq!(listing_calls, count, "{id}");
        assert_eq!(observed["exit_code"], status, "{id}");
    }
    for (id, status) in [("cancelled-missing-log", 0), ("completed-missing-log", 2)] {
        let observed = observation(id);
        let missing_log_calls = observed["calls"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|call| call[0] == "gh" && call[1].as_str().unwrap().ends_with("/jobs/11/logs"))
            .count();
        assert_eq!(missing_log_calls, 3, "{id}");
        assert_eq!(observed["exit_code"], status, "{id}");
    }
    let template: Value = serde_json::from_str(
        observation("template-ansi-cache")["stdout"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(template["checks"]["lint"]["lines"], 1);
    assert_eq!(template["checks"]["lint"]["log_missing"], 0);
}
