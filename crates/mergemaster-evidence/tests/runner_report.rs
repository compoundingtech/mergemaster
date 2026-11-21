//! Assertion-for-assertion replacement for scripts/fractal-test-report-test.
#[path = "../src/pinned_python.rs"]
mod pinned_python;
use chrono::{DateTime, Utc};
use mergemaster_evidence::evidence::runner_report::{percentile, run_at};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

fn fixture() -> Value {
    let mut fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/oracle/runner-report.json"
    ))
    .unwrap();
    let edges: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/oracle/runner-report-edges.json"
    ))
    .unwrap();
    fixture["cases"]
        .as_array_mut()
        .unwrap()
        .extend(edges["cases"].as_array().unwrap().iter().cloned());
    fixture
}
fn now() -> DateTime<Utc> {
    "2026-10-24T12:00:00Z".parse().unwrap()
}
fn run_case(case: &Value) -> (i32, String, String) {
    let root = tempfile::tempdir().unwrap();
    let replace = |text: &str| text.replace("${scratch}", root.path().to_str().unwrap());
    for (name, content) in case["files"].as_object().unwrap() {
        let path = root.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content.as_str().unwrap()).unwrap();
    }
    let argv: Vec<_> = case["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| replace(v.as_str().unwrap()))
        .collect();
    let observed = if !case["environment"].as_object().unwrap().is_empty() {
        // Exercise environment-based discovery through the real process boundary, without
        // changing the test runner's process-global environment. Only the wall clock differs.
        let output = Command::new(env!("CARGO_BIN_EXE_mergemaster"))
            .args([
                "evidence",
                "runner-report",
                "--since",
                "2026-10-23T12:00:00Z",
            ])
            .args(&argv)
            .envs(
                case["environment"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k, replace(v.as_str().unwrap()))),
            )
            .output()
            .unwrap();
        let mut report: Value = serde_json::from_slice(&output.stdout).unwrap();
        report["window"]["until"] = json!("2026-10-24T12:00:00Z");
        (
            output.status.code().unwrap(),
            format!("{}\n", serde_json::to_string_pretty(&report).unwrap()),
            String::from_utf8(output.stderr).unwrap(),
        )
    } else {
        run_at(&argv, now())
    };
    if case["id"]
        .as_str()
        .is_some_and(|id| id.starts_with("edge_arguments_"))
        && case["exit"] == 2
    {
        let cli = Command::new(env!("CARGO_BIN_EXE_mergemaster"))
            .args(["evidence", "runner-report"])
            .args(&argv)
            .output()
            .unwrap();
        assert_eq!(
            (
                cli.status.code().unwrap(),
                String::from_utf8(cli.stdout).unwrap(),
                String::from_utf8(cli.stderr).unwrap()
            ),
            observed,
            "native CLI argument boundary: {}",
            case["id"]
        );
    }
    assert_eq!(
        observed,
        (
            case["exit"].as_i64().unwrap() as i32,
            replace(case["stdout"].as_str().unwrap()),
            replace(case["stderr"].as_str().unwrap())
        ),
        "{}",
        case["id"]
    );
    observed
}
#[test]
fn integer_threshold_domain_is_an_intended_divergence() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/oracle/runner-report-integer-divergence.json"
    ))
    .unwrap();
    let case = &fixture["cases"][0];
    assert_eq!(case["exit"], 0);
    let python_report: Value = serde_json::from_str(case["stdout"].as_str().unwrap()).unwrap();
    assert_eq!(
        python_report["slo_s"].as_u64(),
        Some(9_223_372_036_854_775_808)
    );
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("runs.jsonl");
    fs::write(&path, "").unwrap();
    let native = Command::new(env!("CARGO_BIN_EXE_mergemaster"))
        .args([
            "evidence",
            "runner-report",
            "--slo-s",
            "9223372036854775808",
        ])
        .arg(path)
        .output()
        .unwrap();
    assert_eq!(
        native.status.code(),
        Some(case["native"]["exit"].as_i64().unwrap() as i32)
    );
    assert_eq!(
        String::from_utf8(native.stdout).unwrap(),
        case["native"]["stdout"].as_str().unwrap()
    );
    assert_eq!(
        String::from_utf8(native.stderr).unwrap(),
        case["native"]["stderr"].as_str().unwrap()
    );
}

fn case(prefix: &str, index: usize) -> Value {
    let id = format!("{prefix}_{index}");
    fixture()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap()
        .clone()
}
fn report(prefix: &str, index: usize) -> Value {
    serde_json::from_str(&run_case(&case(prefix, index)).1).unwrap()
}
#[test]
fn percentiles_are_nearest_rank() {
    let values: Vec<_> = (10..=100).step_by(10).map(|v| json!(v)).collect();
    assert_eq!(
        (percentile(&values, 0.5), percentile(&values, 0.9)),
        (json!(50), json!(90))
    );
    assert_eq!(percentile(&[json!(7)], 0.9), 7);
    assert_eq!(percentile(&[json!(300), json!(100), json!(200)], 0.9), 300);
    assert_eq!(
        percentile(&[json!(1), json!(2), json!(3), json!(4)], 0.5),
        2
    );
    assert_eq!(percentile(&[], 0.5), Value::Null);
    let r = report("percentiles_are_nearest_rank", 0);
    assert_eq!(
        (
            &r["count"],
            &r["p50_s"],
            &r["p90_s"],
            &r["max_s"],
            &r["within_slo"]
        ),
        (
            &json!(5),
            &json!(600),
            &json!(700),
            &json!(700),
            &json!(1.0)
        )
    );
    assert_eq!(r["breach"], false);
    assert_eq!(r["breach_reasons"], json!([]));
}
#[test]
fn only_full_warm_completed_runs_in_the_window_count_and_the_rest_are_counted_by_reason() {
    let prefix =
        "only_full_warm_completed_runs_in_the_window_count_and_the_rest_are_counted_by_reason";
    let r = report(prefix, 0);
    assert_eq!(r["count"], 2);
    assert_eq!(
        r["excluded"],
        json!({"not_full":1,"cold":2,"partial":1,"failed":1,"candidate":0})
    );
    assert_eq!(
        r["runs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["total_s"].clone())
            .collect::<Vec<_>>(),
        vec![json!(600), json!(610)]
    );
    let mut keys = r["runs"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort();
    assert_eq!(keys, vec!["ended", "host", "total_s", "tree"]);
    assert_eq!(report(prefix, 1)["count"], 2);
    assert_eq!(report(prefix, 2)["runs"][0]["total_s"], 650);
}
#[test]
fn breach_is_a_p90_over_the_objective_or_any_run_over_the_maximum() {
    let p = "breach_is_a_p90_over_the_objective_or_any_run_over_the_maximum";
    let within = report(p, 0);
    assert_eq!(within["p90_s"], 700);
    assert_eq!(within["breach"], false);
    assert_eq!(within["within_slo"], 0.9);
    let slow = report(p, 1);
    assert_eq!(slow["breach"], true);
    assert_eq!(
        slow["breach_reasons"],
        json!(["p90 800s is over the 720s objective"])
    );
    let spike = report(p, 2);
    assert_eq!(spike["p90_s"], 600);
    assert_eq!(spike["breach"], true);
    assert_eq!(
        spike["breach_reasons"],
        json!(["1 full warm run(s) over 900s (slowest 901s)"])
    );
    assert_eq!(report(p, 3)["breach"], false);
    let empty = report(p, 4);
    assert_eq!(empty["excluded"]["candidate"], 0);
    for key in ["p50_s", "p90_s", "max_s", "within_slo"] {
        assert_eq!(empty[key], Value::Null);
    }
    assert_eq!(empty["count"], 0);
    assert_eq!(empty["breach"], false);
}
#[test]
fn candidate_measurements_are_separate_from_every_slo_figure() {
    let p = "candidate_measurements_are_separate_from_every_slo_figure";
    let r = report(p, 0);
    assert_eq!(r["count"], 1);
    assert_eq!(r["p90_s"], 600);
    assert_eq!(r["max_s"], 600);
    assert_eq!(r["breach"], false);
    assert_eq!(r["excluded"]["candidate"], 2);
    assert_eq!(
        r["by_host"].as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["box-a"]
    );
    assert_eq!(r["slowest"][0]["mean_s"], 600.0);
    assert_eq!(
        r["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["head"].clone())
            .collect::<Vec<_>>(),
        vec![json!("a".repeat(40)); 2]
    );
    assert_eq!(r["candidates"][0]["exit"], 0);
    assert_eq!(r["candidates"][1]["exit"], 1);
    let (code, out, _) = run_case(&case(p, 1));
    assert_eq!(code, 0);
    assert!(out.contains("Candidate measurements (excluded from SLO figures):"));
    assert!(out.contains(&format!("{}: 5000s, exit 0", "a".repeat(40))));
}
#[test]
fn by_host_and_the_slowest_use_the_stages_when_a_run_has_them() {
    let r = report(
        "by_host_and_the_slowest_use_the_stages_when_a_run_has_them",
        0,
    );
    assert_eq!(
        r["by_host"],
        json!({"box-a":{"count":2,"p50_s":600,"p90_s":700,"max_s":700},"box-b":{"count":1,"p50_s":650,"p90_s":650,"max_s":650}})
    );
    let rows = r["slowest"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| json!([v["name"], v["kind"], v["mean_s"], v["p90_s"]]))
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        vec![
            json!(["linux-gate", "check", 500.0, 500]),
            json!(["tests", "stage", 450.0, 500]),
            json!(["typescript-client", "check", 200.0, 200]),
            json!(["clippy", "stage", 100.0, 100]),
            json!(["setup", "stage", 70.0, 80])
        ]
    );
}
#[test]
fn lines_that_are_not_records_are_counted_and_an_unreadable_file_is_an_error() {
    let p = "lines_that_are_not_records_are_counted_and_an_unreadable_file_is_an_error";
    let r = report(p, 0);
    assert_eq!(r["count"], 1);
    assert_eq!(r["unreadable"], 2);
    let (code, out, err) = run_case(&case(p, 1));
    assert_eq!(code, 1);
    assert_eq!(out, "");
    assert!(err.contains("cannot read the runs"));
    assert_eq!(run_case(&case(p, 2)).0, 2);
}
#[test]
fn several_files_are_read_together_and_the_default_is_st_test_s_own_file() {
    let p = "several_files_are_read_together_and_the_default_is_st_test_s_own_file";
    assert_eq!(
        report(p, 0)["by_host"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        vec!["box-a", "box-b"]
    );
    assert_eq!(report(p, 1)["max_s"], 640);
    assert_eq!(report(p, 2)["max_s"], 700);
}
#[test]
fn markdown_prints_the_table_and_the_breach_line() {
    let p = "markdown_prints_the_table_and_the_breach_line";
    let (code, out, _) = run_case(&case(p, 0));
    assert_eq!(code, 0);
    for text in [
        "2 counted (left out: 1 not_full)",
        "| all | 2 | 600s | 1000s | 1000s |",
        "| box-b | 1 | 1000s | 1000s | 1000s |",
        "| linux-gate (check) | 800.0s | 1000s |",
        "**Breach**: p90 1000s is over the 720s objective; 1 full warm run(s) over 900s (slowest 1000s)",
    ] {
        assert!(out.contains(text));
    }
    let (code, out, _) = run_case(&case(p, 1));
    assert_eq!(code, 0);
    assert!(out.contains("| all | 0 | - | - | - |"));
    assert!(out.contains("No full warm run in the window"));
    assert!(
        run_case(&case(p, 2))
            .1
            .contains("**Within the objective.**")
    );
}
#[test]
fn each_wait_is_its_own_line_over_every_run_in_the_window() {
    let p = "each_wait_is_its_own_line_over_every_run_in_the_window";
    let r = report(p, 0);
    assert_eq!(
        r["waits"],
        json!({"pool tree":{"count":2,"p50_s":10,"p90_s":30,"max_s":30},"build slot, tree free":{"count":1,"p50_s":5,"p90_s":5,"max_s":5},"lane burst":{"count":2,"p50_s":40,"p90_s":120,"max_s":120}})
    );
    assert_eq!(report(p, 1)["waits"], json!({}));
    let (code, out, _) = run_case(&case(p, 2));
    assert_eq!(code, 0);
    assert!(out.contains("| lane burst | 1 | 120s | 120s | 120s |"));
    assert!(!out.contains("| pool tree |"));
}
#[test]
fn a_record_st_test_writes_is_one_the_report_reads() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("written/runs.jsonl");
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output=pinned_python::command().args(["-B","-c",r#"import importlib.machinery, importlib.util, sys
loader=importlib.machinery.SourceFileLoader('runner',sys.argv[1]); module=importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name,loader)); loader.exec_module(module)
module.POOL_SETTINGS['ST_TEST_RUNS']=sys.argv[2]
module.record_run({'v':1,'ended':'2026-10-24T11:00:00Z','total_s':610,'full':True,'warm':True,'exit':0})
"#]).arg(repository.join("scripts/st-test")).arg(&path).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (code, out, err) = run_at(&[path.to_str().unwrap().into()], now());
    assert_eq!(code, 0, "{err}");
    let r: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(r["count"], 1);
    assert_eq!(r["unreadable"], 0);
    assert_eq!(r["runs"][0]["total_s"], 610);
}
#[test]
fn frozen_cli_bytes_match_the_independent_pinned_python() {
    for case in fixture()["cases"].as_array().unwrap() {
        run_case(case);
    }
    let output = pinned_python::command()
        .arg("-B")
        .args(["-c", "import runpy, sys; runpy.run_path(sys.argv[1])['replay_runner_report'](sys.executable)"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/oracle_corpus.py"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Replayed 24 frozen runner-report cases")
    );
}
