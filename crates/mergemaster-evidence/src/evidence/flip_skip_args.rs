//! Pinned evidence-flip-ready/evidence-skip-report argparse boundary.
use super::super::{
    argparse_compat::{Action, Exit as Early, OptionSpec, Parser as CompatParser},
    legacy_verify::python_digits::decimal,
};
use clap::Parser;

const fn option(
    long: &'static str,
    metavar: Option<&'static str>,
    action: Action,
    help: &'static str,
) -> OptionSpec {
    OptionSpec {
        long,
        short: None,
        metavar,
        action,
        choices: &[],
        help,
        hidden: false,
    }
}
const HELP: OptionSpec = OptionSpec {
    short: Some("-h"),
    ..option(
        "--help",
        None,
        Action::Help,
        "show this help message and exit",
    )
};
const REPO: OptionSpec = option("--repo", Some("REPO"), Action::Store, "");
const CACHE: OptionSpec = option("--cache", Some("CACHE"), Action::Store, "");
const NOW: OptionSpec = OptionSpec {
    hidden: true,
    ..option("--now", Some("NOW"), Action::Store, "")
};
const FLIP: CompatParser = CompatParser {
    program: "evidence-flip-ready",
    description: "Is a check ready to have its evidence skip turned on? The flip trigger, read from the gate's own decision lines.",
    options: &[
        HELP,
        REPO,
        CACHE,
        option(
            "--propose",
            None,
            Action::Flag,
            "open a flip pull request for each ready check",
        ),
        option(
            "--dry-run",
            None,
            Action::Flag,
            "with --propose: print the diff, change nothing",
        ),
        NOW,
    ],
};
const SKIP: CompatParser = CompatParser {
    program: "evidence-skip-report",
    description: "Which checks our pull request runs skipped, and why the others ran: a daily count for the per-PR suite.",
    options: &[
        HELP,
        REPO,
        option(
            "--hours",
            Some("HOURS"),
            Action::Convert {
                name: "float",
                parse: float,
            },
            "",
        ),
        option(
            "--actor",
            Some("ACTOR"),
            Action::Append,
            "keep runs started by this account (repeatable; default all)",
        ),
        option(
            "--receipts",
            Some("RECEIPTS"),
            Action::Append,
            "pre-push receipts (JSON lines with branch and agent)",
        ),
        CACHE,
        option("--markdown", None, Action::Flag, ""),
        NOW,
    ],
};
fn float(text: &str) -> Option<String> {
    // Python float accepts Unicode decimal digits and digit-separated underscores,
    // but not Rust's broader trim set (notably U+001C through U+001F).
    let text = text.trim_matches(|c: char| c.is_whitespace() && !matches!(c, '\u{1c}'..='\u{1f}'));
    let mut normalized = String::with_capacity(text.len());
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
        } else if let Some(digit) = decimal(u32::from(ch)) {
            normalized.push(char::from(b'0' + digit));
            previous_digit = true;
        } else {
            normalized.push(ch);
            previous_digit = false;
        }
    }
    let number = match normalized.to_ascii_lowercase().as_str() {
        "inf" | "+inf" | "infinity" | "+infinity" => Some(f64::INFINITY),
        "-inf" | "-infinity" => Some(f64::NEG_INFINITY),
        "nan" | "+nan" | "-nan" => Some(f64::NAN),
        _ => normalized.parse().ok(),
    }?;
    Some(number.to_string())
}
fn valid_repo(repo: &str) -> bool {
    let mut parts = repo.split('/');
    let valid = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    };
    parts.next().is_some_and(valid) && parts.next().is_some_and(valid) && parts.next().is_none()
}
#[derive(Parser)]
struct FlipArgs {
    #[command(flatten)]
    args: super::super::flip_ready::Args,
}
#[derive(Parser)]
struct SkipArgs {
    #[command(flatten)]
    args: super::super::skip_report::Args,
}
pub(super) fn flip(argv: &[String]) -> Result<super::super::flip_ready::Args, Early> {
    let args = FLIP.parse(argv)?;
    let repo = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--repo="))
        .unwrap_or("compoundingtech/fractal");
    if !valid_repo(repo)
        || (args.iter().any(|arg| arg == "--dry-run") && !args.iter().any(|arg| arg == "--propose"))
    {
        return Err(FLIP.error("bad --repo, or --dry-run without --propose"));
    }
    FlipArgs::try_parse_from(std::iter::once("evidence-flip-ready".to_owned()).chain(args))
        .map(|parsed| parsed.args)
        .map_err(|error| FLIP.error(error))
}
pub(super) fn skip(argv: &[String]) -> Result<super::super::skip_report::Args, Early> {
    let args = SKIP.parse(argv)?;
    SkipArgs::try_parse_from(std::iter::once("evidence-skip-report".to_owned()).chain(args))
        .map(|parsed| parsed.args)
        .map_err(|error| SKIP.error(error))
}
/// clap consumes an initial `--` marker before collecting trailing values.
/// Restore the process argv at this boundary so argparse can diagnose it too.
pub(super) fn process_argv(command: &str, fallback: Vec<String>) -> Vec<String> {
    let mut raw = std::env::args().skip(1);
    if raw.next().as_deref() == Some("evidence") && raw.next().as_deref() == Some(command) {
        raw.collect()
    } else {
        fallback
    }
}
pub(super) fn finish(early: Early) -> anyhow::Result<()> {
    use std::io::Write;
    std::io::stdout()
        .lock()
        .write_all(early.stdout.as_bytes())?;
    std::io::stderr()
        .lock()
        .write_all(early.stderr.as_bytes())?;
    if early.code != 0 {
        std::process::exit(early.code);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::path::PathBuf;

    const ORACLE: &str = r#"
import argparse, ast, json, os, re, sys
source, *argv = sys.argv[1:]
module = ast.parse(open(source).read(), filename=source)
__doc__ = ast.get_docstring(module)
main = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
end = next(i for i,n in enumerate(main.body) if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute) and n.value.func.attr == 'parse_args') + 1
exec(compile(ast.Module(body=main.body[:end], type_ignores=[]), source, 'exec'))
print(json.dumps(vars(args), ensure_ascii=True))
"#;

    fn compare_values(parser: &CompatParser, args: &[&str]) {
        let argv: Vec<_> = args.iter().map(|arg| (*arg).to_owned()).collect();
        let parsed = parser
            .parse(&argv)
            .unwrap_or_else(|exit| panic!("{}", exit.stderr));
        let flip = parser.program == FLIP.program;
        let mut actual = if flip {
            json!({"repo":"compoundingtech/fractal", "cache":"/argparse-cache/evidence-flip-ready", "propose":false, "dry_run":false})
        } else {
            json!({"repo":"compoundingtech/fractal", "cache":"/argparse-cache/evidence-flip-ready", "hours":24.0, "actor":[], "receipts":[], "markdown":false})
        };
        for arg in parsed {
            let (key, value) = arg
                .split_once('=')
                .map_or((arg.as_str(), None), |(key, value)| (key, Some(value)));
            let key = key.trim_start_matches("--").replace('-', "_");
            if matches!(key.as_str(), "actor" | "receipts") {
                actual[&key]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(value.unwrap()));
            } else if key == "hours" {
                actual[&key] = json!(value.unwrap().parse::<f64>().unwrap());
            } else {
                actual[&key] = value.map_or(Value::Bool(true), |value| json!(value));
            }
        }
        let source = PathBuf::from(std::env::var_os("MERGEMASTER_PYTHON_ORACLE").unwrap())
            .join("scripts")
            .join(parser.program);
        let output = crate::pinned_python::command()
            .args(["-c", ORACLE])
            .arg(source)
            .args(args)
            .env("XDG_CACHE_HOME", "/argparse-cache")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(actual, expected, "{} {args:?}", parser.program);
    }

    #[test]
    fn successful_stores_appends_flags_and_float_values_match_oracle() {
        let flip: &[&[&str]] = &[
            &[],
            &["--prop"],
            &["--prop", "--propose", "--dry", "--dry-run"],
            &["--repo=first/repo", "--rep", "last/repo"],
            &["--cache=first", "--c", ""],
            &["--repo=-a/-b"],
        ];
        for args in flip {
            compare_values(&FLIP, args);
        }
        let skip: &[&[&str]] = &[
            &[],
            &["--rec", "one"],
            &["--repo=one/two", "--rep=three/four"],
            &["--actor=a", "--a", "b", "--receipts=one", "--rec", "two"],
            &["--mark", "--markdown"],
            &["--cache=first", "--c="],
            &["--hours=1", "--hours=-24"],
            &["--hours", "-.5"],
            &["--hours", "-1e3"],
            &["--hours", "-١.٥"],
            &["--hours", " 1_2.٥e+1 "],
            &["--hours", "\u{a0}1\u{2003}"],
            &["--actor=", "--actor=-login", "--receipts=-file"],
        ];
        for args in skip {
            compare_values(&SKIP, args);
        }
    }
}
