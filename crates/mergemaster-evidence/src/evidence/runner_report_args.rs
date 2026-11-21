//! Compatibility boundary for the pinned fractal-test-report argparse interface.
use super::legacy_verify::{
    argparse_int, python_digits::decimal, python_repr::Repr, value_inputs::TextRef,
};
use std::path::PathBuf;

#[derive(Debug)]
pub(super) struct Options {
    pub hours: f64,
    pub slo: i64,
    pub max: i64,
    pub since: Option<String>,
    pub markdown: bool,
    pub files: Vec<PathBuf>,
}

const FLAGS: [&str; 7] = [
    "-h",
    "--help",
    "--hours",
    "--since",
    "--slo-s",
    "--max-s",
    "--markdown",
];
const USAGE: &str = "usage: fractal-test-report [-h] [--hours HOURS] [--since SINCE]\n                           [--slo-s SLO_S] [--max-s MAX_S] [--markdown]\n                           [RUNS.jsonl ...]\n";
const HELP: &str = concat!(
    "\nHow long the per-PR suite takes on a dev box: scripts/fractal-test's own run\n",
    "records against the time objective.\n\n",
    "positional arguments:\n",
    "  RUNS.jsonl     default: the file scripts/fractal-test writes\n\n",
    "options:\n",
    "  -h, --help     show this help message and exit\n",
    "  --hours HOURS  the window, ending now (default 24)\n",
    "  --since SINCE  the window starts here instead (ISO 8601, UTC)\n",
    "  --slo-s SLO_S  the p90 objective in seconds (default 720)\n",
    "  --max-s MAX_S  no single full warm run may take longer (default 900)\n",
    "  --markdown     a short table instead of JSON\n",
);

type Early = (i32, String, String);

fn error(message: impl std::fmt::Display) -> Early {
    (
        2,
        String::new(),
        format!("{USAGE}fractal-test-report: error: {message}\n"),
    )
}

fn repr(text: &str) -> Repr<'_> {
    Repr(TextRef::Str(text))
}

#[derive(Debug)]
enum Token<'a> {
    Argument,
    Separator,
    Unknown,
    Option {
        flag: &'static str,
        explicit: Option<&'a str>,
    },
    Ambiguous(Vec<&'static str>),
}

// Python 3.14.7 uses the prefix regex r'-\.?\d', not a complete numeric
// literal, to distinguish option-like tokens from negative positionals.
fn negative_number(text: &str) -> bool {
    let Some(body) = text.strip_prefix('-') else {
        return false;
    };
    body.strip_prefix('.')
        .unwrap_or(body)
        .chars()
        .next()
        .is_some_and(|ch| decimal(u32::from(ch)).is_some())
}

fn classify(text: &str) -> Token<'_> {
    if text == "--" {
        return Token::Separator;
    }
    if !text.starts_with('-') || text == "-" {
        return Token::Argument;
    }
    let (key, explicit) = text
        .split_once('=')
        .map_or((text, None), |(a, b)| (a, Some(b)));
    if let Some(flag) = FLAGS.iter().copied().find(|flag| *flag == key) {
        return Token::Option { flag, explicit };
    }
    if text.starts_with("--") {
        let mut matches = FLAGS.iter().copied().filter(|flag| flag.starts_with(key));
        if let Some(first) = matches.next() {
            if let Some(second) = matches.next() {
                let mut ambiguous = vec![first, second];
                ambiguous.extend(matches);
                return Token::Ambiguous(ambiguous);
            }
            return Token::Option {
                flag: first,
                explicit,
            };
        }
    } else if let Some(tail) = text.strip_prefix("-h") {
        // The only short option is help. argparse processes a short cluster
        // before invoking help, so '-hx' is unrecognized, not a help request.
        return Token::Option {
            flag: "-h",
            explicit: Some(tail),
        };
    }
    if negative_number(text) || text.contains(' ') {
        Token::Argument
    } else {
        Token::Unknown
    }
}

// Python numeric constructors allow whitespace and underscores between digits.
fn numeric_text(text: &str) -> Option<String> {
    let text = text.trim();
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut previous_digit = false;
    while let Some(ch) = chars.next() {
        if ch == '_' {
            if !previous_digit
                || !chars
                    .peek()
                    .is_some_and(|c| decimal(u32::from(*c)).is_some())
            {
                return None;
            }
            previous_digit = false;
        } else {
            if let Some(digit) = decimal(u32::from(ch)) {
                previous_digit = true;
                result.push(char::from(b'0' + digit));
            } else {
                previous_digit = false;
                result.push(ch);
            }
        }
    }
    Some(result)
}

fn float(text: &str) -> Option<f64> {
    let text = numeric_text(text)?;
    let lower = text.to_ascii_lowercase();
    match lower.as_str() {
        "inf" | "+inf" | "infinity" | "+infinity" => Some(f64::INFINITY),
        "-inf" | "-infinity" => Some(f64::NEG_INFINITY),
        "nan" | "+nan" | "-nan" => Some(f64::NAN),
        _ => text.parse().ok(),
    }
}

pub(super) fn parse(argv: &[String]) -> Result<Options, Early> {
    let mut options = Options {
        hours: 24.0,
        slo: 720,
        max: 900,
        since: None,
        markdown: false,
        files: Vec::new(),
    };
    let mut extras = Vec::new();
    let mut positional_used = false;
    let mut index = 0;
    'arguments: while let Some(arg) = argv.get(index) {
        match classify(arg) {
            Token::Argument | Token::Separator => {
                // A nargs='*' positional consumes one contiguous group, not
                // every positional separated by options (parse_intermixed_args).
                if positional_used {
                    extras.push(arg.clone());
                    if arg == "--" {
                        extras.extend_from_slice(&argv[index + 1..]);
                        break;
                    }
                    index += 1;
                    continue;
                }
                positional_used = true;
                let mut separated = false;
                while let Some(value) = argv.get(index) {
                    if !separated {
                        match classify(value) {
                            Token::Separator => {
                                separated = true;
                                index += 1;
                                continue;
                            }
                            Token::Argument => {}
                            _ => break,
                        }
                    }
                    options.files.push(PathBuf::from(value));
                    index += 1;
                }
            }
            Token::Unknown => {
                extras.push(arg.clone());
                index += 1;
            }
            Token::Ambiguous(matches) => {
                return Err(error(format!(
                    "ambiguous option: {arg} could match {}",
                    matches.join(", ")
                )));
            }
            Token::Option { flag, explicit } => {
                if matches!(flag, "-h" | "--help" | "--markdown") {
                    if let Some(value) = explicit {
                        let mut value = value;
                        if flag == "-h" && !arg.starts_with("-h=") {
                            loop {
                                if value.is_empty() {
                                    return Err((0, format!("{USAGE}{HELP}"), String::new()));
                                }
                                if let Some(rest) = value.strip_prefix('=') {
                                    value = rest;
                                    break;
                                }
                                if value.starts_with('-') {
                                    break;
                                }
                                if let Some(rest) = value.strip_prefix('h') {
                                    value = rest;
                                } else {
                                    // Unknown tails of short clusters are reported
                                    // with their own leading dash.
                                    extras.push(format!("-{value}"));
                                    index += 1;
                                    continue 'arguments;
                                }
                            }
                        }
                        let name = if flag == "--markdown" {
                            flag
                        } else {
                            "-h/--help"
                        };
                        return Err(error(format!(
                            "argument {name}: ignored explicit argument {}",
                            repr(value)
                        )));
                    }
                    if flag != "--markdown" {
                        return Err((0, format!("{USAGE}{HELP}"), String::new()));
                    }
                    options.markdown = true;
                    index += 1;
                    continue;
                }
                let value = if let Some(value) = explicit {
                    value
                } else {
                    index += 1;
                    let Some(value) = argv
                        .get(index)
                        .filter(|v| matches!(classify(v), Token::Argument))
                    else {
                        return Err(error(format!("argument {flag}: expected one argument")));
                    };
                    value
                };
                match flag {
                    "--hours" => {
                        let Some(number) = float(value) else {
                            return Err(error(format!(
                                "argument {flag}: invalid float value: {}",
                                repr(value)
                            )));
                        };
                        options.hours = number;
                    }
                    "--slo-s" | "--max-s" => {
                        let number = argparse_int::parse(TextRef::Str(value)).ok().and_then(|v| {
                            if v.negative {
                                format!("-{}", v.digits).parse::<i64>().ok()
                            } else {
                                v.digits.parse::<i64>().ok()
                            }
                        });
                        let Some(number) = number else {
                            return Err(error(format!(
                                "argument {flag}: invalid int value: {}",
                                repr(value)
                            )));
                        };
                        if flag == "--slo-s" {
                            options.slo = number;
                        } else {
                            options.max = number;
                        }
                    }
                    _ => options.since = Some(value.to_owned()),
                }
                index += 1;
            }
        }
    }
    if extras.is_empty() {
        Ok(options)
    } else {
        Err(error(format!(
            "unrecognized arguments: {}",
            extras.join(" ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn matches_pinned_main_parser_without_reading_run_files() {
        let script = r#"
import argparse, contextlib, datetime, io, json, os, pathlib, runpy, sys, types
assert sys.version_info[:3] == (3, 14, 7)
source = pathlib.Path(os.environ.get('MERGEMASTER_PYTHON_ORACLE',
    '/nix/store/bbj5s0bmhsv4a9mjqb97x80r8dvkas45-source'))
oracle = runpy.run_path(str(source / 'scripts/fractal-test-report'))
sys.argv[0] = 'fractal-test-report'
os.environ['COLUMNS'] = '80'
os.environ['NO_COLOR'] = '1'
captured = None
class CapturingParser(argparse.ArgumentParser):
    def parse_args(self, *args, **kwargs):
        global captured
        captured = super().parse_args(*args, **kwargs)
        # main catches SystemExit, so successful parser observations stop before
        # semantic validation or any dependency on run files or environment.
        raise SystemExit(0)
oracle['main'].__globals__['argparse'] = types.SimpleNamespace(ArgumentParser=CapturingParser)
cases = [
    [], ['--help'], ['-h'], ['--he'], ['-hh'], ['-hhh'], ['-hx'], ['-hhx'],
    ['-h=bad'], ['-hbad'], ['-h--'], ['-hh=bad'],
    ['--help=false'], ['--he='], ['--markdown=false'], ['--mark=false'],
    ['--mar='], ['--markdown', 'false'], ['--m'], ['--s'], ['--s=value'],
    ['--h'], ['--hours'], ['--hours', '--markdown'], ['--hours', '--s'],
    ['--since', '--'], ['--slo-s='], ['--hours='], ['--since='],
    ['--hours', 'bad'], ['--slo-s', '1.0'], ['--max-s', '1e3'],
    ['--hours', '-1e3'], ['--hours=-1e3'], ['--hours', '-.5'],
    ['--hours', '-1.'], ['--hours', '-1'], ['--hours', '1_0.5_0'],
    ['--hours', '  +2.5  '], ['--slo-s', '  +0007  '],
    ['--hours', '١.٥'], ['--slo-s', '١_٢'], ['--hours', '1__2'],
    ['--hours', "a'b"], ['--hours', '\\tbad\\n'],
    ['--hours', 'nan'], ['--hours', 'INFINITY'], ['--hours', '-inf'],
    ['--hours=+Infinity'], ['--hours=1e9999'], ['--hours=-NaN'],
    ['--hours', '1', '--hours=2', '--slo-s', '3', '--slo=4', '--max', '5'],
    ['--since', 'first', '--since=last', '--markdown', '--markdown'],
    ['a', 'b'], ['a', '--hours', '2'], ['--hours', '2', 'a', 'b'],
    ['a', '--hours', '2', 'b'], ['a', '--markdown', 'b', 'c'],
    ['--bad', 'a'], ['a', '--bad', 'b'], ['--bad', '--help'],
    ['--bad', '--hours', 'bad'], ['--', '--help', 'a'],
    ['a', '--', '--help'], ['a', '--markdown', '--', 'b'],
    ['--markdown', '--', '-x', '--'], ['-', '', '-12', '-.2'],
    ['-a b'], ['--wat=1', 'a'], ['--hours=2', '--since=x', 'a'],
]
results = []
for argv in cases:
    captured = None
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = oracle['main'](argv, now=datetime.datetime(2026, 11, 1, tzinfo=datetime.timezone.utc))
    options = None
    if captured is not None:
        options = vars(captured).copy()
        options['hours'] = repr(options['hours'])
    results.append(dict(argv=argv, code=code, stdout=out.getvalue(), stderr=err.getvalue(), options=options))
print(json.dumps(results))
"#;
        let output = crate::pinned_python::command()
            .args(["-c", script])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        for case in cases {
            let argv: Vec<String> = case["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            match parse(&argv) {
                Err((code, stdout, stderr)) => {
                    assert!(case["options"].is_null(), "{case}");
                    assert_eq!(
                        json!([code, stdout, stderr]),
                        json!([case["code"], case["stdout"], case["stderr"]]),
                        "{case}"
                    );
                }
                Ok(options) => {
                    let expected = &case["options"];
                    assert!(!expected.is_null(), "{case}");
                    let hours = expected["hours"].as_str().unwrap();
                    let expected_hours = float(hours).unwrap();
                    assert!(
                        options.hours == expected_hours
                            || options.hours.is_nan() && expected_hours.is_nan(),
                        "{case}"
                    );
                    assert_eq!(
                        json!({
                            "slo_s": options.slo, "max_s": options.max,
                            "since": options.since, "markdown": options.markdown,
                            "files": options.files,
                        }),
                        json!({
                            "slo_s": expected["slo_s"], "max_s": expected["max_s"],
                            "since": expected["since"], "markdown": expected["markdown"],
                            "files": expected["files"],
                        }),
                        "{case}"
                    );
                }
            }
        }
    }
}
