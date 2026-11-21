//! Byte-level cases discovered by the post-port Python semantic sweep.
use super::*;
use std::io::Write;
use std::process::Stdio;

fn oracle(operation: &str, payload: &Value) -> Value {
    let source = PathBuf::from(std::env::var_os("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .join("scripts/evidence-flip-ready");
    let program = r#"
import datetime, importlib.machinery, importlib.util, json, sys
path, operation = sys.argv[1:]
loader = importlib.machinery.SourceFileLoader('flip_sweep_oracle', path)
module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(module)
payload = json.load(sys.stdin)
now = module.parse_time('2026-10-22T12:00:00Z')
if operation in ('presign', 'evaluate'):
    rows = payload
    for row in rows:
        row['created_at'] = module.parse_time(row['created_at'])
    result = module.presign_rates(rows, now) if operation == 'presign' else module.evaluate(rows, False, now)
    # Compare object encounter order as well as every serialized field.
    result = json.dumps(result, indent=2)
elif operation == 'preconditions':
    result = module.preconditions({'why_not': [], 'ready': True}, 'fractal-web', payload)
elif operation == 'doc':
    result = module.flip_doc(payload['text'], 'web', payload['entry'], '2026-10-23')
elif operation == 'policy':
    result = module.flip_policy(payload, 'web')[0]
elif operation == 'policy_preconditions':
    entry = json.loads(payload)['checks']['fractal-web']
    result = module.preconditions({'why_not': [], 'ready': True}, 'fractal-web', entry)
else:
    raise AssertionError(operation)
print(json.dumps(result))
"#;
    let mut child = crate::pinned_python::command()
        .args(["-B", "-c", program])
        .arg(source)
        .arg(operation)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(payload).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn now() -> DateTime<Utc> {
    parse_time("2026-10-22T12:00:00Z").unwrap()
}

fn row(id: u64, hours: i64) -> Row {
    let created = Some(now() - Duration::hours(hours));
    Row {
        check: "web".to_owned(),
        run: id,
        created,
        created_local: created,
        actor: "alice".to_owned(),
        base: String::new(),
        fields: json!({"check":"web", "outcome":"satisfied", "log":"ok", "pr":id.to_string(), "pr_head":id.to_string()}),
        real: Some("success".to_owned()),
        aggregate: false,
        members_red: Vec::new(),
        cancelled: false,
        old_base: None,
    }
}

fn recorded_rows(rows: &[Row]) -> Value {
    json!(
        rows.iter()
            .map(|row| json!({
                "check": row.check,
                "run": row.run,
                "created_at": row.created.map(iso),
                "actor": row.actor,
                "fields": row.fields,
                "real": row.real,
                "aggregate": row.aggregate,
                "members_red": row.members_red,
                "cancelled": row.cancelled,
                "old_base": row.old_base,
            }))
            .collect::<Vec<_>>()
    )
}

#[test]
fn presign_rounds_the_exact_binary_ratio_like_pinned_python() {
    // 1/80 is slightly above the decimal tie. 1/16 and 3/16 are exact
    // binary ties, rounding down and up respectively to the even decimal.
    for (signed, total, expected) in [
        (1, 80, 0.013),
        (3, 80, 0.037),
        (1, 16, 0.062),
        (3, 16, 0.188),
    ] {
        let rows: Vec<Row> = (0..total)
            .map(|id| {
                let mut row = row(id, 1);
                row.fields["trust_level"] = json!(if id < signed { "host" } else { "fleet" });
                row
            })
            .collect();
        let result = presign_rates(&rows, now());
        assert_eq!(result["alice"]["presigned_share"], json!(expected));
        assert_eq!(
            Value::String(json_pretty(&result).unwrap()),
            oracle("presign", &recorded_rows(&rows)),
            "{signed}/{total}"
        );
    }
}

#[test]
fn shard_input_truthiness_matches_every_json_kind() {
    for (value, expected) in [
        (Value::Null, false),
        (json!(false), false),
        (json!(0), false),
        (json!(0.0), false),
        (json!(-0.0), false),
        (json!(""), false),
        (json!([]), false),
        (json!({}), false),
        (json!(true), true),
        (json!(-1), true),
        (json!(0.5), true),
        (json!("false"), true),
        (json!([false]), true),
        (json!({"key":null}), true),
    ] {
        let entry = json!({"kinds":{"wrapper":{"input_order":{"kit_inputs":["true","false"]},"shard_inputs":value}}});
        let actual = preconditions(
            json!({"why_not":[],"ready":true}),
            "fractal-web",
            &entry,
            None,
        );
        assert_eq!(actual["ready"], expected, "{value}");
        assert_eq!(actual, oracle("preconditions", &entry), "{value}");
    }
}

#[test]
fn ignored_old_base_reasons_keep_first_chronological_encounter_order() {
    for reasons in [
        ["no_policy", "no-gate-at-base"],
        ["no-gate-at-base", "no_policy"],
    ] {
        let mut rows = [row(1, 2), row(2, 3), row(3, 1)];
        rows[1].old_base = Some(reasons[0].to_owned());
        rows[0].old_base = Some(reasons[1].to_owned());
        rows[1].fields["log"] = json!("-");
        rows[0].fields["log"] = json!("-");
        let actual = evaluate(&rows, false, now(), false, None).unwrap();
        assert_eq!(
            actual["old_base_lines"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            reasons
        );
        assert_eq!(
            Value::String(json_pretty(&actual).unwrap()),
            oracle("evaluate", &recorded_rows(&rows))
        );
    }
}

#[test]
fn doc_insertion_and_nonstring_cells_match_pinned_python() {
    let header = "### Which checks skip today\n\n| Check | enforce | events | sample | Since |\n| --- | --- | --- | --- | --- |\n";
    let false_row = "| `web` | false | - | 5 | - |\n";
    let true_row = "| `existing` | true | `pull_request` | 1 | old |\n";
    for body in [
        format!("{false_row}{true_row}\nAfter.\n"),
        format!("{true_row}{false_row}\nAfter.\n"),
        format!("{false_row}\nAfter.\n"),
        format!("{false_row}{true_row}| `last` | true | - | 1 | old |\n\nAfter.\n"),
    ] {
        for entry in [
            json!({"events":["pull_request"],"sample_one_in":1}),
            json!({"events":[true,null,1.0,["a"],{"k":1}],"sample_one_in":1.0}),
        ] {
            let text = format!("{header}{body}");
            let actual = flip_doc(&text, "web", &entry.to_string(), "2026-10-23").unwrap();
            let payload = json!({"text":text,"entry":entry});
            assert_eq!(Value::String(actual), oracle("doc", &payload));
        }
    }
}

#[test]
fn policy_json_loads_duplicate_keys_preserve_first_insertion_order() {
    let source = "{\n  \"version\": 1,\n  \"checks\": {\n    \"web\": {\n      \"enforce\": true,\n      \"events\": [],\n      \"enforce\": false,\n      \"metadata\": {\"z\": 1, \"a\": 2, \"z\": 3}\n    }\n  }\n}\n";
    let actual = flip_policy(source, "web").unwrap().0;
    assert_eq!(Value::String(actual), oracle("policy", &json!(source)));
}

#[test]
fn policy_metadata_and_consumed_truthiness_use_lossless_json_str_input() {
    for value in [
        "NaN",
        "Infinity",
        "-Infinity",
        "1e400",
        "1844674407370955161701",
        "\"\\ud800\"",
        "[]",
        "{}",
        "0.0",
    ] {
        let source = format!(
            "{{\n  \"metadata\": {value},\n  \"checks\": {{\n    \"web\": {{\n      \"enforce\": false,\n      \"metadata\": {value}\n    }}\n  }}\n}}\n"
        );
        let actual = flip_policy(&source, "web").unwrap().0;
        assert_eq!(
            Value::String(actual),
            oracle("policy", &json!(source)),
            "{value}"
        );
        assert_eq!(policy::checks(&source).unwrap()["web"]["enforce"], false);
        let source = format!(
            "{{\"metadata\":{value},\"checks\":{{\"fractal-web\":{{\"enforce\":false,\"kinds\":{{\"wrapper\":{{\"input_order\":{{\"kit_inputs\":[\"true\",\"false\"]}},\"shard_inputs\":{value}}}}}}}}}}"
        );
        let entries = policy::checks(&source).unwrap();
        let actual = preconditions(
            json!({"why_not":[],"ready":true}),
            "fractal-web",
            &entries["fractal-web"],
            None,
        );
        assert_eq!(
            actual,
            oracle("policy_preconditions", &json!(source)),
            "{value}"
        );
    }
}

#[test]
fn github_schema_rejects_values_instead_of_narrowing_or_dropping_them() {
    for (source, context) in [
        (r#"{"id":9007199254740993}"#, "id"),
        (r#"{"id":1844674407370955161701}"#, "id"),
        (r#"{"id":1.0}"#, "id"),
        (r#"{"id":true}"#, "id"),
        (r#"{"total_count":1e400}"#, "listing"),
        (r#"{"workflow_runs":[false]}"#, "listing"),
        (r#"{"jobs":null}"#, "page"),
        (r#"{"labels":[3]}"#, "release"),
        (r#"{"filename":{}}"#, "file"),
        (r#"{"actor":{"login":false}}"#, "run"),
        (r#"{"name":"\ud800"}"#, "gate"),
    ] {
        let error = parse_api(source)
            .and_then(|value| match context {
                "id" => api::number(value.get("id"), "workflow run id").map(|_| ()),
                "listing" => api::listing(&value),
                "page" => api::page(&value, "jobs"),
                "release" => api::job(&value, api::JobUse::Release),
                "file" => api::string(value.get("filename"), "PR file filename").map(|_| ()),
                "run" => api::run(&value, api::RunUse::Flip),
                _ => api::job(&value, api::JobUse::Flip),
            })
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("GitHub API") && error.contains("outside schema"),
            "{source}: {error}"
        );
    }
    assert_eq!(
        api::number(
            parse_api(r#"{"id":9007199254740991,"total_count":3}"#)
                .unwrap()
                .get("id"),
            "workflow run id"
        )
        .unwrap(),
        9_007_199_254_740_991
    );
}

#[test]
fn api_fields_are_validated_only_in_the_consuming_object_kind() {
    let metadata = json!({
        "labels":[{"name":"bug","id":123}],
        "name":false, "status":{}, "run_attempt":"not consumed", "filename":false
    });
    let mut pull = metadata.clone();
    pull["number"] = json!(17);
    assert_eq!(api::first_pull(&json!([pull])).unwrap(), Some(17));
    assert_eq!(api::first_pull(&json!([])).unwrap(), None);
    assert!(api::job(&metadata, api::JobUse::Release).is_err());
    let gate = json!({"name":"lint","status":"completed","labels":[{"name":"bug"}]});
    assert!(api::job(&gate, api::JobUse::Flip).is_ok());
    let release = json!({"labels":["macos-latest"],"name":false,"status":{},"run_attempt":"ignored","filename":false});
    assert!(api::job(&release, api::JobUse::Release).is_ok());
    let run =
        json!({"status":"completed","labels":[{"name":"bug"}],"filename":false,"started_at":false});
    assert!(api::run(&run, api::RunUse::Flip).is_ok());
    for malformed in [
        json!([{}]),
        json!([1]),
        json!([{"number":1.5}]),
        json!([{"number":"7"}]),
    ] {
        assert!(
            api::first_pull(&malformed)
                .unwrap_err()
                .to_string()
                .contains("outside schema")
        );
    }
}
