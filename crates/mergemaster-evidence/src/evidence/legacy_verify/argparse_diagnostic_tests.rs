use super::*;
#[test]
fn subprocess_streams_and_exit_match_pinned_python() {
    let rows: Vec<serde_json::Value> = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/argparse/diagnostic/stdout.json"
    ))
    .unwrap();
    assert!(rows.len() > 60);
    for row in rows {
        let argv: Vec<Vec<u32>> = serde_json::from_value(row["argv"].clone()).unwrap();
        let args: Vec<_> = argv.iter().map(|s| TextRef::Points(s)).collect();
        let result = streams(&args, TextRef::Str("evidence-verify"), 78).unwrap();
        if row["parsed"] == true {
            assert!(result.is_none(), "{row}");
            assert!(matches!(parse(&args), Ok(ParseOutcome::Parsed(_))), "{row}");
            continue;
        }
        let result = result.unwrap_or_else(|| panic!("unexpected success: {row}"));
        for (field, text) in [
            ("stdout", result.stdout.text),
            ("stderr", result.stderr.text),
        ] {
            let expected: Vec<u8> = serde_json::from_value(row[field].clone()).unwrap();
            let actual: Vec<u8> = text
                .borrowed()
                .points()
                .flat_map(|p| {
                    char::from_u32(p)
                        .map_or_else(|| format!("\\u{p:04x}"), |c| c.to_string())
                        .into_bytes()
                })
                .collect();
            assert_eq!(actual, expected, "{row}");
        }
        assert_eq!(result.exit, row["exit"].as_i64().unwrap() as i32, "{row}");
    }
}
#[test]
fn manually_constructed_option_indices_return_checked_errors() {
    for error in [
        ParseError::ExpectedArgument(usize::MAX),
        ParseError::Ambiguous(TextRef::Str("--x"), vec![usize::MAX]),
        ParseError::Conflict(0, usize::MAX),
    ] {
        assert!(error.message().is_err());
    }
}
