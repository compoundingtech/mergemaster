//! Every assertion formerly in scripts/ci-evidence-slo-test, exercised through the native CLI.
#[path = "../src/pinned_python.rs"]
mod pinned_python;

use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../tests/fixtures/oracle/slo.json")).unwrap()
}
fn native(id: &str) -> (std::process::Output, Vec<u64>) {
    let fixture = fixture();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == id)
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let gh = root.path().join("gh");
    fs::write(
        &gh,
        format!(
            "#!{}\n{}",
            Path::new(pinned_python::command().get_program()).display(),
            fixture["gh_shim"].as_str().unwrap()
        ),
    )
    .unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
    let api = root.path().join("api.json");
    fs::write(&api, case["api"].to_string()).unwrap();
    let calls = root.path().join("calls");
    fs::write(&calls, "").unwrap();
    let mut paths = vec![root.path().to_path_buf()];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let output = Command::new(env!("CARGO_BIN_EXE_mergemaster"))
        .args(["evidence", "slo"])
        .args(
            case["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap()),
        )
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("SLO_API", api)
        .env("SLO_CALLS", &calls)
        .output()
        .unwrap();
    let calls = fs::read_to_string(calls)
        .unwrap()
        .lines()
        .map(|line| line.parse().unwrap())
        .collect();
    (output, calls)
}
fn report(id: &str) -> (Value, Vec<u64>) {
    let (output, calls) = native(id);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    (serde_json::from_slice(&output.stdout).unwrap(), calls)
}
fn row<'a>(report: &'a Value, check: &str, event: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["check"] == check && r["event"] == event)
        .unwrap()
}

#[test]
fn counters_denominator_producers_and_produced_but_not_verified() {
    let (result, calls) = report("counters");
    assert_eq!(result["runs_read"], 3);
    assert_eq!(
        result["totals"],
        json!({"decisions":7,"satisfied":3,"produced_not_verified":2})
    );
    let gate = row(&result, "linux-gate", "pull_request");
    assert_eq!(
        (
            &gate["decisions"],
            &gate["satisfied"],
            &gate["skipped"],
            &gate["shadow"]
        ),
        (&json!(2), &json!(2), &json!(1), &json!(1))
    );
    assert_eq!(
        gate["satisfied_by_producer"],
        json!({"wrapper/host":1,"observed/fleet":1})
    );
    assert_eq!(
        row(&result, "linux-gate", "merge_group")["satisfied_by_producer"],
        json!({"observed/fleet":1})
    );
    let bad = row(&result, "typescript-client", "pull_request");
    assert_eq!(
        (
            &bad["produced_not_verified"],
            &bad["rejected"],
            &bad["unavailable"]
        ),
        (&json!(1), &json!(1), &json!(1))
    );
    assert_eq!(
        bad["produced_not_verified_reasons"],
        json!({"untrusted_signer":1})
    );
    let genie = row(&result, "genie-freshness", "pull_request");
    assert_eq!(
        genie["produced_not_verified_reasons"],
        json!({"degraded":1})
    );
    assert_eq!(genie["no_note"], 1);
    assert_eq!(result["target"], json!({"produced_not_verified":0}));
    assert!(!calls.contains(&24));
}
#[test]
fn a_gate_job_that_never_printed_its_outcome_is_not_a_decision() {
    let (result, _) = report("incomplete");
    assert_eq!(result["totals"]["decisions"], 0);
    assert_eq!(result["checks"][0]["gate_incomplete"], 1);
    assert_eq!(result["checks"][0]["satisfied_rate"], Value::Null);
}
#[test]
fn the_log_budget_bounds_downloads_and_the_rest_is_reported_unread() {
    let (result, calls) = report("budget");
    assert_eq!(calls.len(), 2);
    assert_eq!(result["logs_read"], 2);
    assert_eq!(
        result["checks"][0]["satisfied_by_producer"],
        json!({"?/?":2,"unread":3})
    );
}
#[test]
fn an_empty_interval_is_zero_decisions_not_an_error_and_bad_arguments_exit_two() {
    let (result, _) = report("empty");
    assert_eq!(result["totals"]["decisions"], 0);
    assert_eq!(result["checks"], json!([]));
    for id in [
        "bad-hours",
        "bad-since",
        "reversed",
        "bad-budget",
        "bad-repository",
    ] {
        let (output, calls) = native(id);
        assert_eq!(output.status.code(), Some(2), "{id}");
        assert!(output.stdout.is_empty());
        assert!(calls.is_empty());
    }
}
#[test]
fn an_unreadable_api_exits_one_instead_of_reporting_zeros() {
    let (output, _) = native("api-error");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("could not read the runs")
    );
}
#[test]
fn the_text_report_names_the_target() {
    let (output, _) = native("text");
    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8(output.stdout).unwrap();
    assert!(out.contains("produced-but-not-verified (target 0)"));
    assert!(out.contains("observed/fleet"));
}
#[test]
fn frozen_cli_bytes_match_the_pinned_python_oracle() {
    let fixture = fixture();
    for case in fixture["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let (output, calls) = native(id);
        assert_eq!(
            output.status.code(),
            Some(case["exit_code"].as_i64().unwrap() as i32),
            "{id}"
        );
        assert_eq!(
            output.stdout,
            case["stdout"].as_str().unwrap().as_bytes(),
            "{id}: stdout"
        );
        assert_eq!(
            output.stderr,
            case["stderr"].as_str().unwrap().as_bytes(),
            "{id}: stderr"
        );
        assert_eq!(json!(calls), case["logs"], "{id}: log calls");
    }
    let output = pinned_python::command()
        .args([
            "-B",
            "-c",
            r#"
import importlib.util, pathlib, sys
root = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('corpus', root / 'tests/oracle_corpus.py')
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)
corpus.replay_slo(pathlib.Path(sys.executable))
"#,
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .env("MERGEMASTER_BIN", env!("CARGO_BIN_EXE_mergemaster"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rates_round_the_binary_float_without_an_intermediate_rounding() {
    let (result, _) = report("rounded-rates");
    assert_eq!(result["checks"][0]["satisfied_rate"], json!(0.0063));
    assert_eq!(
        result["checks"][0]["produced_not_verified_rate"],
        json!(0.0187)
    );
}
