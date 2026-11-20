use super::*;
use serde_json::{Value, json};
#[test]
fn namespaces_defaults_appends_and_mutex_precedence_match_python() {
    let rows: Vec<Value> = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/argparse/parse/stdout.json"
    ))
    .unwrap();
    for row in rows {
        let points: Vec<Vec<u32>> = serde_json::from_value(row["argv"].clone()).unwrap();
        let argv: Vec<_> = points.iter().map(|p| TextRef::Points(p)).collect();
        match parse(&argv) {
            Ok(ParseOutcome::Parsed(args)) => {
                let mut actual = serde_json::Map::new();
                for (spec, values) in OPTIONS.iter().zip(&args.values) {
                    let points = |s: TextRef<'_>| s.points().collect::<Vec<_>>();
                    let value=match spec.action {
                        Action::Help=>continue,
                        Action::Flag=>json!(!values.is_empty()),
                        Action::Append=>json!(values.iter().copied().map(points).collect::<Vec<_>>()),
                        Action::Integer=>args.max_age.as_ref().map_or(Value::Null,|i|json!({"int":format!("{}{}",if i.negative {"-"} else {""},i.digits)})),
                        Action::Store=>values.last().copied().map_or(Value::Null,|s|json!(points(s))),
                    };
                    actual.insert(spec.dest.to_owned(), value);
                }
                assert_eq!(json!(actual), row["values"], "{row}");
            }
            Err(ParseError::Conflict(option, previous)) => assert_eq!(
                format!(
                    "argument {}: not allowed with argument {}",
                    OPTIONS[option].name, OPTIONS[previous].name
                ),
                row["error"],
                "{row}"
            ),
            Err(ParseError::Ambiguous(value, ids)) => {
                let names: Vec<_> = ids.iter().map(|id| OPTIONS[*id].name).collect();
                assert_eq!(
                    format!(
                        "ambiguous option: {} could match {}",
                        value,
                        names.join(", ")
                    ),
                    row["error"],
                    "{row}"
                );
            }
            _ => panic!("unexpected parser outcome: {row}"),
        }
    }
}
