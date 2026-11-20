use super::*;
#[test]
fn usage_matches_pinned_formatter_widths_and_lossless_programs() {
    let rows: Vec<serde_json::Value> = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/argparse/usage/stdout.json"
    ))
    .unwrap();
    for row in rows {
        let prog: Vec<u32> = serde_json::from_value(row["prog"].clone()).unwrap();
        let expected: Vec<u32> = serde_json::from_value(row["usage"].clone()).unwrap();
        let rendered = usage(
            TextRef::Points(&prog),
            row["width"].as_u64().unwrap() as usize,
        );
        assert_eq!(
            rendered.text.borrowed().points().collect::<Vec<_>>(),
            expected,
            "{row}"
        );
        for range in rendered.interpolations {
            assert!(range.end <= expected.len());
            assert!(expected[range].iter().all(|point| prog.contains(point)));
        }
    }
}
