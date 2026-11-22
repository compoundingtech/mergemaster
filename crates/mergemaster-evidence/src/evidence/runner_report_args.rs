//! Compatibility boundary for the pinned fractal-test-report argparse interface.
use super::argparse_compat::{
    Action, DefaultValue, Exit, OptionSpec, Parser, Value, float, integer,
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

const fn option(
    long: &'static str,
    metavar: Option<&'static str>,
    action: Action,
    default: DefaultValue,
) -> OptionSpec {
    OptionSpec {
        long,
        short: None,
        metavar,
        action,
        choices: &[],
        help: "",
        hidden: false,
        default,
    }
}

const PARSER: Parser = Parser {
    program: "fractal-test-report",
    description: "",
    options: &[
        OptionSpec {
            short: Some("-h"),
            ..option("--help", None, Action::Help, DefaultValue::None)
        },
        option(
            "--hours",
            Some("HOURS"),
            Action::Convert {
                name: "float",
                parse: float,
            },
            DefaultValue::Float(24.0),
        ),
        option("--since", Some("SINCE"), Action::Store, DefaultValue::None),
        option(
            "--slo-s",
            Some("SLO_S"),
            Action::Convert {
                name: "int",
                parse: integer,
            },
            DefaultValue::Int(720),
        ),
        option(
            "--max-s",
            Some("MAX_S"),
            Action::Convert {
                name: "int",
                parse: integer,
            },
            DefaultValue::Int(900),
        ),
        option("--markdown", None, Action::Flag, DefaultValue::Bool(false)),
    ],
};

fn early(exit: Exit) -> Early {
    if exit.code == 0 {
        return (0, format!("{USAGE}{HELP}"), String::new());
    }
    // Shared parsing owns diagnostics; keep this command's positional usage
    // and pinned help layout rather than the optional-only generated layout.
    let usage = PARSER.usage();
    let stderr = match exit.stderr.strip_prefix(&usage) {
        Some(diagnostic) => format!("{USAGE}{diagnostic}"),
        None => exit.stderr,
    };
    (exit.code, exit.stdout, stderr)
}

pub(super) fn parse(argv: &[String]) -> Result<Options, Early> {
    let (parsed, files) = PARSER.parse_positionals(argv).map_err(early)?;
    let mut values = parsed.values;
    let hours = match values.remove("--hours") {
        Some(Value::Float(value)) => value,
        _ => return Err(error("invalid --hours type")),
    };
    let slo = match values.remove("--slo-s") {
        Some(Value::Int(value)) => value,
        _ => return Err(error("invalid --slo-s type")),
    };
    let max = match values.remove("--max-s") {
        Some(Value::Int(value)) => value,
        _ => return Err(error("invalid --max-s type")),
    };
    let since = match values.remove("--since") {
        Some(Value::None) => None,
        Some(Value::String(value)) => Some(value),
        _ => return Err(error("invalid --since type")),
    };
    let markdown = match values.remove("--markdown") {
        Some(Value::Bool(value)) => value,
        _ => return Err(error("invalid --markdown type")),
    };
    Ok(Options {
        hours,
        slo,
        max,
        since,
        markdown,
        files: files.into_iter().map(PathBuf::from).collect(),
    })
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
    ['-xh'], ['--hours', 'bad', '--help'], ['--hours', '-h'],
    ['--slo-s', 'bad', '--help'], ['--slo-s', '-h'],
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
                    let Some(super::Value::Float(expected_hours)) = float(hours) else {
                        panic!("invalid oracle hours: {hours}");
                    };
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
