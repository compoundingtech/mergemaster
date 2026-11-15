use super::*;
use std::io::Write;
#[test]
fn integer_values_and_complete_argparse_diagnostics_match_python() {
    let mut cases: Vec<String> = [
        "",
        " ",
        "0",
        "-0",
        "+0",
        "123",
        "-42",
        "1_2",
        "_1",
        "1_",
        "1__2",
        "+ 1",
        "1.0",
        "1e3",
        "0x12",
        "1\n2",
        "١_２",
        "²",
        "\u{1c}1",
        "\u{85}-1\u{a0}",
        "'",
        "\"",
        "a'b\"c",
        "\tbad\r\n",
        "\\x1b",
        "\u{1b}",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for point in 0..0x110000 {
        if decimal(point).is_some() {
            cases.push(char::from_u32(point).unwrap().to_string());
        }
    }
    for point in [
        9, 10, 11, 12, 13, 28, 29, 30, 31, 32, 0x85, 0xa0, 0x1680, 0x2007, 0x2028, 0x202f, 0x205f,
        0x3000, 0x200b,
    ] {
        let c = char::from_u32(point).unwrap();
        cases.extend([format!("{c}+1{c}"), format!("1{c}2")]);
    }
    for count in [4299, 4300, 4301, 5000] {
        cases.extend([
            "0".repeat(count),
            "1".repeat(count),
            format!("{}x", "1".repeat(count)),
            "1_".repeat(count),
        ]);
    }
    let mut cases: Vec<Vec<u32>> = cases
        .iter()
        .map(|s| s.chars().map(u32::from).collect())
        .collect();
    cases.extend([
        vec![0xd800],
        vec![0xdc80],
        vec![39, 0xdfff, 34],
        vec![32, 0xdcff, 10],
    ]);
    let script = r#"
import argparse,json,sys
assert sys.version_info[:3]==(3,14,7)
p=argparse.ArgumentParser(exit_on_error=False); action=p.add_argument('--max-age',type=int)
r=[]
for points in json.load(sys.stdin):
 text=''.join(map(chr,points))
 try:
  v=p._get_value(action,text); r.append(dict(negative=v<0,digits=str(abs(v))))
 except argparse.ArgumentError as e:
  try: int(text)
  except ValueError as cause: kind='limit' if str(cause).startswith('Exceeds the limit') else 'literal'
  r.append(dict(error=kind,diagnostic=e.message,complete=str(e)))
print(json.dumps(r))
"#;
    let mut child = std::process::Command::new("python3")
        .args(["-c", script])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&cases).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let expected: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for (points, expected) in cases.iter().zip(expected) {
        let text = NormalizedText::from_points(points);
        let value = parse(text.borrowed());
        assert_eq!(value, parse(TextRef::Points(points)), "{points:?}");
        match value {
            Ok(value) => {
                assert_eq!(value.negative, expected["negative"], "{points:?}");
                assert_eq!(value.digits, expected["digits"], "{points:?}");
                assert_eq!(value.is_positive(), !value.negative && value.digits != "0");
            }
            Err(error) => {
                assert_eq!(
                    if matches!(error, IntegerError::DigitLimit { .. }) {
                        "limit"
                    } else {
                        "literal"
                    },
                    expected["error"],
                    "{points:?}"
                );
                let diagnostic = error.diagnostic(text.borrowed()).to_string();
                assert_eq!(diagnostic, expected["diagnostic"], "{points:?}");
                assert_eq!(
                    format!("argument --max-age: {diagnostic}"),
                    expected["complete"],
                    "{points:?}"
                );
                assert_eq!(
                    error.diagnostic(TextRef::Points(points)).to_string(),
                    diagnostic
                );
            }
        }
    }
}
