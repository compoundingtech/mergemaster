use super::workflow_job;
use serde_json::{Value, json};
#[test]
fn selected_workflow_bytes_and_failures_match_oracle() {
    let wrap = |jobs: &str| format!("name: fixture\non:\n  push:\n# top\njobs:\n{jobs}");
    let mut cases: Vec<(String, String)> = vec![
        ("name: no jobs\n".into(), "z".into()),
        (wrap(""), "z".into()),
        (
            wrap("  z:\n    needs: b\n  b:\n    needs: a\n  a:\n    run: a\n"),
            "z".into(),
        ),
        (wrap("  a:\n    run: old\n  a:\n    run: new\n"), "a".into()),
        (wrap("  z:\n    needs: missing\n"), "z".into()),
        (
            wrap("  ignored:\n    needs: missing\n  z:\n    run: z\n"),
            "z".into(),
        ),
        (wrap("  a:\n    needs: z\n  z:\n    needs: a\n"), "z".into()),
        (
            wrap("  z:\n    needs: a\n    needs: missing\n  a:\n    run: a\n"),
            "z".into(),
        ),
        (
            wrap(
                "  z:\n    needs:\n      - a\n      - 'b'\n    run: z\n  a:\n    run: a\n  b:\n    run: b\n",
            ),
            "z".into(),
        ),
        (
            wrap(
                "  z:\n    needs:\n      - a\n      - bad.name\n      - missing\n  a:\n    run: a\n",
            ),
            "z".into(),
        ),
        (
            wrap("  z:\n    run: z\n# associated with z\n\npermissions:\n  contents: read\n"),
            "z".into(),
        ),
        (
            wrap("  z:\n    run: z\njobs:\n  a:\n    run: a\n"),
            "z".into(),
        ),
    ];
    for needs in [
        "[a, b, a]",
        "[['a', \"b\"]]",
        "'a'",
        "[]",
        "''",
        "[ ]",
        "a # comment",
    ] {
        cases.push((
            wrap(&format!(
                "  z:\n    needs: {needs}\n  a:\n    run: a\n  b:\n    run: b\n"
            )),
            "z".into(),
        ));
    }
    for invalid in [
        "    run: before job\n",
        "   z:\n    run: z\n",
        "  z: value\n",
        "  z:\n   run: z\n",
        "  # indented comment\n",
        "  é:\n    run: z\n",
    ] {
        cases.push((wrap(invalid), "z".into()));
    }
    for ending in [
        "\n", "\r\n", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\u{85}", "\u{2028}",
        "\u{2029}",
    ] {
        cases.push((
            wrap("  z:\n    run: echo é😀\n").replace('\n', ending),
            "z".into(),
        ));
    }
    for trailing in ["", "\t", "\u{1f}", "\u{a0}"] {
        cases.push((
            wrap(&format!(
                "  z:{trailing}\n    needs:{trailing}a{trailing}\n  a:\n    run: a"
            )),
            "z".into(),
        ));
    }
    let actual: Vec<_> = cases
        .iter()
        .map(|(text, job)| {
            workflow_job(text, job)
                .map(|bytes| json!({"hex":bytes.map(hex::encode)}))
                .unwrap_or_else(|e| json!({"reason":e.reason}))
        })
        .collect();
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
        .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
    let script = r#"
import json, runpy, sys
o = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for text, job in json.loads(sys.argv[2]):
    try:
        selected = o['workflow_job'](text,job)
        results.append(dict(hex=selected.hex() if selected is not None else None))
    except o['Failure'] as e:
        results.append(dict(reason=e.reason))
print(json.dumps(results))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script, &root, &json!(cases).to_string()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual.len(), expected.len());
    for ((case, actual), expected) in cases.iter().zip(actual).zip(expected) {
        assert_eq!(actual, expected, "{case:?}");
    }
}
