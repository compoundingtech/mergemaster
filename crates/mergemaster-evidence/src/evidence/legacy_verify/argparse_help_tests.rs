use super::*;
#[test]
fn complete_help_matches_pinned_python_across_widths() {
    let rows = crate::oracle_digest::rows(include_bytes!(
        "../../../../../tests/fixtures/oracle/argparse/help/stdout.json"
    ));
    for row in rows.as_array().unwrap() {
        let rendered = help(
            TextRef::Str("evidence-verify"),
            row["width"].as_u64().unwrap() as usize,
        );
        crate::oracle_digest::assert_value(
            &serde_json::Value::String(rendered.text.to_string()),
            &row["help"],
        );
    }
}
