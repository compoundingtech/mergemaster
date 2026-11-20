use super::decode_json_bytes;
#[test]
fn legacy_statement_bytes_match_python_transport() {
    let cases = crate::oracle_digest::rows(include_bytes!(
        "../../../../../tests/fixtures/oracle/statement-core/bytes-transport/stdout.bin"
    ));
    assert_eq!(cases.as_array().unwrap().len(), 77);
    for case in cases.as_array().unwrap() {
        let bytes = crate::oracle_digest::bytes(&case["input"]);
        let actual_points = serde_json::to_value(decode_json_bytes(&bytes)).unwrap();
        crate::oracle_digest::assert_value(&actual_points, &case["points"]);
        let actual = super::super::statement::statement_of(&bytes, &"a".repeat(40));
        let depth = case["name"]
            .as_str()
            .unwrap()
            .strip_prefix("depth-")
            .and_then(|d| d.parse::<usize>().ok())
            .unwrap_or(0);
        if depth > super::super::statement_document::MAX_CONTAINER_DEPTH {
            assert!(case["statement"].as_bool().unwrap());
            assert_eq!(actual.unwrap_err().reason, "statement-too-deep");
        } else {
            assert_eq!(
                actual.unwrap().is_some(),
                case["statement"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}

#[test]
fn exact_decode_errors_match_python_detection_and_surrogatepass() {
    let fixture = crate::oracle_digest::rows(include_bytes!(
        "../../../../../tests/fixtures/oracle/statement-core/decode-errors/stdout.bin"
    ));
    let cases = fixture["cases"].as_array().unwrap();
    let expected = fixture["expected"].as_array().unwrap();
    for case in cases {
        let bytes = crate::oracle_digest::bytes(&case["input"]);
        let actual = match super::decode_json_bytes_exact(&bytes) {
            Ok(points) => serde_json::json!({"points":points}),
            Err(error) => serde_json::json!({"error":error.to_string()}),
        };
        crate::oracle_digest::assert_value(
            &actual,
            &expected[case["expected"].as_u64().unwrap() as usize],
        );
    }
    assert_eq!(cases.len(), 12_568);
}
