//! Pinned evidence-flip-ready/evidence-skip-report argparse boundary.
use super::super::{
    argparse_compat::{
        Action, DefaultValue, Exit as Early, OptionSpec, Parser as CompatParser, Value,
    },
    legacy_verify::python_digits::decimal,
};

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
        default: match action {
            Action::Flag => DefaultValue::Bool(false),
            Action::Append => DefaultValue::List(&[]),
            _ => DefaultValue::None,
        },
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
const REPO: OptionSpec = OptionSpec {
    default: DefaultValue::String("compoundingtech/fractal"),
    ..option("--repo", Some("REPO"), Action::Store, "")
};
const CACHE: OptionSpec = OptionSpec {
    default: DefaultValue::Factory(cache_default),
    ..option("--cache", Some("CACHE"), Action::Store, "")
};
fn cache_default() -> Value {
    Value::String(
        super::super::flip_ready::cache_dir()
            .to_string_lossy()
            .into_owned(),
    )
}
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
        OptionSpec {
            default: DefaultValue::Int(24),
            ..option(
                "--hours",
                Some("HOURS"),
                Action::Convert {
                    name: "float",
                    parse: float,
                },
                "",
            )
        },
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
fn float(text: &str) -> Option<Value> {
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
    Some(Value::Float(number))
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
fn string(value: Option<Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) => Some(value),
        _ => None,
    }
}
fn strings(value: Option<Value>) -> Vec<String> {
    match value {
        Some(Value::List(values)) => values.into_iter().filter_map(|v| string(Some(v))).collect(),
        _ => Vec::new(),
    }
}
pub(super) fn flip(argv: &[String]) -> Result<super::super::flip_ready::Args, Early> {
    let parsed = FLIP.parse(argv)?;
    let cache = parsed.provided.contains("--cache");
    let mut values = parsed.values;
    let repo = string(values.remove("--repo")).ok_or_else(|| FLIP.error("missing --repo"))?;
    let propose = values.remove("--propose") == Some(Value::Bool(true));
    let dry_run = values.remove("--dry-run") == Some(Value::Bool(true));
    if !valid_repo(&repo) || (dry_run && !propose) {
        return Err(FLIP.error("bad --repo, or --dry-run without --propose"));
    }
    Ok(super::super::flip_ready::Args {
        repo,
        cache: if cache {
            string(values.remove("--cache")).map(Into::into)
        } else {
            None
        },
        propose,
        dry_run,
        now: string(values.remove("--now")),
    })
}
pub(super) fn skip(argv: &[String]) -> Result<super::super::skip_report::Args, Early> {
    let parsed = SKIP.parse(argv)?;
    let cache = parsed.provided.contains("--cache");
    let mut values = parsed.values;
    let repo = string(values.remove("--repo")).ok_or_else(|| SKIP.error("missing --repo"))?;
    // Integer defaults and explicit floats meet only at timedelta arithmetic;
    // neither command prints the raw hours value.
    let hours = match values.remove("--hours") {
        Some(Value::Int(value)) => value as f64,
        Some(Value::Float(value)) => value,
        _ => return Err(SKIP.error("invalid --hours type")),
    };
    Ok(super::super::skip_report::Args {
        repo,
        hours,
        actors: strings(values.remove("--actor")),
        receipts: strings(values.remove("--receipts"))
            .into_iter()
            .map(Into::into)
            .collect(),
        cache: if cache {
            string(values.remove("--cache")).map(Into::into)
        } else {
            None
        },
        markdown: values.remove("--markdown") == Some(Value::Bool(true)),
        now: string(values.remove("--now")),
    })
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
    use serde_json::Value as JsonValue;
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
        let mut actual = serde_json::Map::new();
        for (key, value) in parsed.values {
            if key == "--now" {
                continue;
            }
            let value = if key == "--cache" && !args.iter().any(|arg| arg.starts_with("--c")) {
                JsonValue::String("/argparse-cache/evidence-flip-ready".to_owned())
            } else {
                serde_json::to_value(value).unwrap()
            };
            actual.insert(key.trim_start_matches("--").replace('-', "_"), value);
        }
        let actual = JsonValue::Object(actual);
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
        let expected: JsonValue = serde_json::from_slice(&output.stdout).unwrap();
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
            &["--hours=24"],
            &["--hours=24.0"],
            &["--hours=1"],
            &["--hours=1.5"],
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
    #[test]
    fn non_string_defaults_retain_their_python_types() {
        const PARSER: CompatParser = CompatParser {
            program: "typed-defaults",
            description: "",
            options: &[
                OptionSpec {
                    default: DefaultValue::Int(24),
                    ..option(
                        "--integer",
                        None,
                        Action::Convert {
                            name: "float",
                            parse: float,
                        },
                        "",
                    )
                },
                OptionSpec {
                    default: DefaultValue::Float(24.0),
                    ..option(
                        "--float",
                        None,
                        Action::Convert {
                            name: "float",
                            parse: float,
                        },
                        "",
                    )
                },
                OptionSpec {
                    default: DefaultValue::String("24"),
                    ..option(
                        "--string",
                        None,
                        Action::Convert {
                            name: "float",
                            parse: float,
                        },
                        "",
                    )
                },
                OptionSpec {
                    default: DefaultValue::None,
                    ..option(
                        "--none",
                        None,
                        Action::Convert {
                            name: "float",
                            parse: float,
                        },
                        "",
                    )
                },
                OptionSpec {
                    default: DefaultValue::List(&[DefaultValue::Int(7)]),
                    ..option("--list", None, Action::Append, "")
                },
                OptionSpec {
                    default: DefaultValue::Bool(false),
                    ..option("--flag", None, Action::Flag, "")
                },
            ],
        };
        for args in [
            vec![],
            vec![
                "--integer=24",
                "--float=24",
                "--string=24.5",
                "--none=1.5",
                "--list=x",
                "--flag",
            ],
        ] {
            let argv: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
            let parsed = PARSER
                .parse(&argv)
                .unwrap_or_else(|exit| panic!("{}", exit.stderr));
            let actual = serde_json::to_value(parsed.values).unwrap();
            let output = crate::pinned_python::command()
                .args([
                    "-c",
                    r#"
import argparse,json
p=argparse.ArgumentParser()
for name,default in [('integer',24),('float',24.0),('string','24'),('none',None)]:
    p.add_argument('--'+name,type=float,default=default)
p.add_argument('--list',action='append',default=[7])
p.add_argument('--flag',action='store_true')
print(json.dumps({'--'+k:v for k,v in vars(p.parse_args()).items()}))
"#,
                ])
                .args(&args)
                .output()
                .unwrap();
            assert!(output.status.success());
            let expected: JsonValue = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(actual, expected, "{args:?}");
        }
    }
}
