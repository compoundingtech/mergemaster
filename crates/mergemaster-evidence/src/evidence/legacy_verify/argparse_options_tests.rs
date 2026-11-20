use super::*;
#[test]
fn declarations_match_complete_pinned_parser_metadata() {
    let actual: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/argparse/options/stdout.json"
    ))
    .unwrap();
    assert_eq!(actual["description"], DESCRIPTION);
    assert_eq!(actual["groups"], serde_json::json!(GROUPS));
    let expected: Vec<_> = OPTIONS.iter().map(|a| {
        let default = match a.default {
            DefaultValue::None => serde_json::Value::Null,
            DefaultValue::Text(text) => serde_json::json!(text),
            DefaultValue::False => serde_json::json!(false),
            DefaultValue::EmptyList => serde_json::json!([]),
        };
        serde_json::json!({"name":a.name,"aliases":a.aliases,"dest":a.dest,"metavar":a.metavar,"help":a.help,"action":format!("{:?}",a.action),"nargs":a.nargs,"default":default,"required":a.required,"group":a.group})
    }).collect();
    assert_eq!(actual["actions"], serde_json::json!(expected));
}
