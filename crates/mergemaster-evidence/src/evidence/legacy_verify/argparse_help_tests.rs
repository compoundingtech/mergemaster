use super::*;
#[test]
fn complete_help_matches_pinned_python_across_widths() {
    let rows: Vec<serde_json::Value> = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/argparse/help/stdout.json"
    ))
    .unwrap();
    for row in rows {
        let rendered = help(
            TextRef::Str("evidence-verify"),
            row["width"].as_u64().unwrap() as usize,
        );
        assert_eq!(
            rendered.text.to_string(),
            row["help"],
            "width {}",
            row["width"]
        );
    }
}
