use super::*;
use serde_json::json;
#[test]
fn containers_match_python_oracle() {
    let cases = crate::oracle_digest::rows(include_bytes!(
        "../../../../../tests/fixtures/oracle/statement-core/containers/stdout.bin"
    ));
    assert_eq!(cases.as_array().unwrap().len(), 146);
    for case in cases.as_array().unwrap() {
        let bytes = crate::oracle_digest::bytes(&case["input"]);
        if case["depth"].as_u64().unwrap() > MAX_CONTAINER_DEPTH as u64 {
            assert_eq!(case["result_kind"], "ok"); // Explicit conservative divergence.
            assert_eq!(
                Document::from_bytes(&bytes).unwrap_err(),
                Error::NestingLimit
            );
            continue;
        }
        let actual = match Document::from_bytes(&bytes) {
            Err(Error::Syntax(e)) => json!([
                "syntax",
                e.kind.message(),
                e.pos,
                e.lineno,
                e.colno,
                e.to_string()
            ]),
            Err(e) => json!([match e {
                Error::Encoding => "encoding",
                _ => "invalid",
            }]),
            Ok(doc) => {
                let mut flat = Vec::new();
                let mut stack = vec![doc.root()];
                while let Some(node) = stack.pop() {
                    flat.push(match node {
                        Node::Array(v) => {
                            stack.extend(v.iter().rev().map(|id| doc.node(*id)));
                            json!(["array", v.len()])
                        }
                        Node::Object(v) => {
                            stack.extend(v.values().rev().map(|id| doc.node(*id)));
                            json!(["object", v.keys().collect::<Vec<_>>()])
                        }
                        Node::Null => json!(["null"]),
                        Node::Bool(v) => json!(["bool", v]),
                        Node::Integer(v) => json!(["integer", v]),
                        Node::Float(v) => json!(["float", format!("{:016x}", v.to_bits())]),
                        Node::String(v) => json!(["string", v]),
                    });
                }
                json!(["ok", flat])
            }
        };
        crate::oracle_digest::assert_value(&actual, &case["result"]);
    }
}
#[test]
fn container_limit_counts_arrays_objects_and_empty_roots() {
    for depth in [MAX_CONTAINER_DEPTH, MAX_CONTAINER_DEPTH + 1] {
        for (open, close, empty) in [("[", "]", "[]"), ("{\"k\":", "}", "{}")] {
            let bytes = format!(
                "{}{}{}",
                open.repeat(depth - 1),
                empty,
                close.repeat(depth - 1)
            );
            let parsed = Document::from_bytes(bytes.as_bytes());
            if depth == MAX_CONTAINER_DEPTH {
                assert!(parsed.is_ok());
            } else {
                assert_eq!(parsed.unwrap_err(), Error::NestingLimit);
            }
        }
    }
}
#[test]
fn sharing_retains_nested_values_and_surrogate_keys() {
    let text = format!(
        "{}{{\"\\ud800\":\"kept\"}}{}",
        "[".repeat(MAX_CONTAINER_DEPTH - 1),
        "]".repeat(MAX_CONTAINER_DEPTH - 1)
    );
    let original = std::sync::Arc::new(Document::from_bytes(text.as_bytes()).unwrap());
    let copy = std::sync::Arc::clone(&original);
    assert!(matches!(original.nodes.last(), Some(Node::String(v)) if v == &[107, 101, 112, 116]));
    let (Node::Object(a), Node::Object(b)) = (
        &original.nodes[MAX_CONTAINER_DEPTH - 1],
        &copy.nodes[MAX_CONTAINER_DEPTH - 1],
    ) else {
        panic!("object leaf");
    };
    assert_eq!(
        a.keys().next().unwrap().as_ptr(),
        b.keys().next().unwrap().as_ptr()
    );
    let (Node::Array(a), Node::Array(b)) = (original.root(), copy.root()) else {
        panic!("array root");
    };
    assert_eq!(a.as_ptr(), b.as_ptr());
}

#[test]
fn policy_depth_parameter_preserves_the_statement_default() {
    for depth in [128, 129, 256, 257] {
        let text = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(
            Document::from_bytes(text.as_bytes()).is_ok(),
            depth <= MAX_CONTAINER_DEPTH
        );
        assert!(Document::from_bytes_with_depth_limit(text.as_bytes(), None).is_ok());
    }
}

#[test]
fn json_text_input_never_uses_bytes_encoding_detection() {
    let cases: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/statement-core/text-encoding/stdout.bin"
    ))
    .unwrap();
    assert_eq!(cases.as_array().unwrap().len(), 16);
    for case in cases.as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let bytes: Vec<u8> = serde_json::from_value(case["bytes"].clone()).unwrap();
        assert_eq!(
            Document::from_text_with_depth_limit(text, None).is_ok(),
            case["str_ok"].as_bool().unwrap(),
            "{text:?}"
        );
        assert_eq!(
            Document::from_bytes(&bytes).is_ok(),
            case["bytes_ok"].as_bool().unwrap()
        );
    }
}

#[test]
fn uncapped_text_api_has_only_reachable_errors_and_identical_results() {
    let mut cases: Vec<String> = [
        "",
        "{}",
        "[]",
        "null",
        "-0",
        "-0.0",
        "1e999",
        "NaN",
        "{\"é🦀\": [1, \"\\ud800\", false]}",
        "{\"a\":1,\"a\":2}",
        "\u{feff}{}",
        "[1,]",
        "{\"a\":}",
        "\"\\q\"",
        "\"\\u123",
        "\0{\0}",
        "{\"a\" 1}",
        "1 2",
        "\"a\nb\"",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    cases.push("9".repeat(4301));
    cases.push(format!("{}0{}", "[".repeat(100_000), "]".repeat(100_000)));
    assert_eq!(cases.len(), 21);
    for text in cases {
        let narrow: Result<Document, TextError> = Document::from_text(&text);
        let legacy = Document::from_text_with_depth_limit(&text, None);
        match (narrow, legacy) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a.root, b.root);
                assert_eq!(format!("{:?}", a.nodes), format!("{:?}", b.nodes));
            }
            (Err(a), Err(b)) => {
                // Exhaustive: decoding and depth-limit errors cannot be represented.
                let equivalent = match a {
                    TextError::Syntax(error) => Error::Syntax(error),
                    TextError::IntegerLimit { digits } => Error::IntegerLimit { digits },
                };
                assert_eq!(equivalent, b);
            }
            other => panic!("text entrypoints differ: {other:?}"),
        }
    }
}

#[test]
fn policy_json_boundaries_and_text_helpers_match_real_oracle() {
    let rows = crate::oracle_digest::rows(include_bytes!(
        "../../../../../tests/fixtures/oracle/statement-core/policy-json-boundaries/stdout.bin"
    ));
    assert_eq!(rows.as_array().unwrap().len(), 14);
    for row in rows.as_array().unwrap() {
        let text = String::from_utf8(crate::oracle_digest::bytes(&row["input"])).unwrap();
        let raw = text.as_str();
        let resource = match row["resource"].as_str() {
            Some("SourceBytes") => Some(PolicyResource::SourceBytes),
            Some("ContainerDepth") => Some(PolicyResource::ContainerDepth),
            Some("Nodes") => Some(PolicyResource::Nodes),
            None => None,
            _ => panic!("unknown resource"),
        };
        if let Some(resource) = resource {
            assert_eq!(
                Document::from_policy_text(raw).unwrap_err(),
                PolicyTextError::Resource(resource)
            );
            let error =
                crate::evidence::legacy_policy::check_names::selected(raw, &[120]).unwrap_err();
            assert_eq!(
                error.resource,
                Some(crate::evidence::legacy_policy::SourceResource::PolicyJson(
                    resource
                ))
            );
            assert_eq!(
                error.origin,
                crate::evidence::legacy_policy::ErrorOrigin::Failure
            );
            assert_eq!(error.reason, "error");
            assert_eq!(error.detail.to_string(), resource.message());
        } else {
            let doc = Document::from_policy_text(raw).unwrap();
            assert_eq!(doc.nodes.len(), row["nodes"].as_u64().unwrap() as usize);
        }
    }
}
