use super::*;
use serde_json::json;
#[test]
fn python_json_primitive_tokens_match_oracle() {
    let cases: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/statement-core/primitive-tokens/stdout.bin"
    ))
    .unwrap();
    assert_eq!(cases.as_array().unwrap().len(), 51);
    for case in cases.as_array().unwrap() {
        let bytes: Vec<u8> = serde_json::from_value(case["bytes"].clone()).unwrap();
        let actual = Tokens::from_bytes(&bytes)
            .and_then(|t| t.collect::<Result<Vec<_>, _>>().ok())
            .filter(|t| t.len() == 1)
            .and_then(|mut t| match t.pop().unwrap() {
                Token::Null => Some(json!(["null"])),
                Token::Bool(b) => Some(json!(["bool", b])),
                Token::Integer(n) => Some(json!(["integer", if n == "-0" { "0" } else { &n }])),
                Token::Float(n) => Some(json!(["float", format!("{:016x}", n.to_bits())])),
                Token::String(s) => Some(json!(["string", s])),
                Token::Punctuation(_) => None,
            });
        assert_eq!(
            actual.unwrap_or(serde_json::Value::Null),
            case["value"],
            "{}",
            case["name"]
        );
    }
}
#[test]
fn token_boundaries_and_failure_are_explicit() {
    let t = Tokens::from_bytes(b"[{},:] ")
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(t.len(), 6);
    assert!(matches!(t[0], Token::Punctuation(b'[')));
    let mut bad = Tokens::from_bytes(b"?").unwrap();
    assert!(matches!(
        bad.next(),
        Some(Err(Error::Syntax(SyntaxError {
            kind: SyntaxKind::ExpectingValue,
            pos: 0,
            lineno: 1,
            colno: 1,
        })))
    ));
    assert!(bad.next().is_none());
    assert!(
        matches!(Tokens::from_bytes(b"-0").unwrap().next(),Some(Ok(Token::Integer(n))) if n=="-0")
    );
}

#[test]
fn scanner_syntax_and_number_boundaries_match_pinned_python() {
    let cases: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/statement-core/scanner-boundaries/stdout.bin"
    ))
    .unwrap();
    assert_eq!(cases.as_array().unwrap().len(), 65);
    for case in cases.as_array().unwrap() {
        let bytes: Vec<u8> = serde_json::from_value(case["bytes"].clone()).unwrap();
        let mut tokens = Tokens::from_bytes(&bytes).unwrap();
        let actual = match tokens.next().unwrap() {
            Ok(_) => json!(["ok", tokens.position()]),
            Err(Error::Syntax(e)) => json!([
                "syntax",
                e.kind.message(),
                e.pos,
                e.lineno,
                e.colno,
                e.to_string()
            ]),
            Err(error) => panic!("unexpected non-syntax error: {error:?}"),
        };
        assert_eq!(actual, case["result"], "bytes: {bytes:?}");
    }
}
