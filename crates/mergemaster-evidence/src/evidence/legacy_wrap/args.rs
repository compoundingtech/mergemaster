//! Legacy argparse boundary, including the command's REMAINDER positional.
use super::super::argparse_compat::{Action, DefaultValue, OptionSpec, Parser, Value};
use super::super::legacy_verify::python_digits::decimal;

#[derive(Debug, PartialEq)]
pub(super) struct Args {
    pub check: String,
    pub change_id: Option<String>,
    pub attempt: String,
    pub signer: String,
    pub toolchain_sha256: Option<String>,
    pub keys: Option<String>,
    pub keys_from: String,
    pub verifier: String,
    pub push: Option<String>,
    pub lanes_from: Option<String>,
    pub aggregate: Option<String>,
    pub input: Vec<String>,
    pub input_file: Vec<String>,
    pub out: Option<String>,
    pub command: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub(super) struct Exit {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub(super) fn default_signer() -> String {
    "[\"st\", \"sekrets\", \"--\", \"mergemaster\", \"evidence\", \"legacy-sign\"]".to_owned()
}

const fn option(long: &'static str, metavar: &'static str, help: &'static str) -> OptionSpec {
    OptionSpec {
        long,
        short: None,
        metavar: Some(metavar),
        action: Action::Store,
        choices: &[],
        help,
        hidden: false,
        default: DefaultValue::None,
    }
}

const PARSER: Parser = Parser {
    program: "evidence-wrap",
    description: "",
    options: &[
        OptionSpec {
            long: "--help",
            short: Some("-h"),
            metavar: None,
            action: Action::Help,
            choices: &[],
            help: "show this help message and exit",
            hidden: false,
            default: DefaultValue::None,
        },
        option(
            "--check",
            "CHECK",
            "the required check this command stands for",
        ),
        option("--change-id", "CHANGE_ID", ""),
        OptionSpec {
            default: DefaultValue::String("1"),
            ..option("--attempt", "ATTEMPT", "")
        },
        option(
            "--signer",
            "SIGNER",
            "JSON argument vector of the signer (default: $EVIDENCE_SIGNER, else sekrets)",
        ),
        option(
            "--toolchain-sha256",
            "TOOLCHAIN_SHA256",
            "skip the nix evaluation and record this digest",
        ),
        option(
            "--keys",
            "KEYS",
            "allowed-signers file for the local verification (default: .st/evidence-keys on --keys-from)",
        ),
        OptionSpec {
            default: DefaultValue::String("origin/main"),
            ..option("--keys-from", "KEYS_FROM", "")
        },
        option(
            "--verifier",
            "VERIFIER",
            "trusted mergemaster binary (default: $MERGEMASTER_BIN, else PATH)",
        ),
        option("--push", "REMOTE", ""),
        option(
            "--lanes-from",
            "COMMIT",
            "hold the check to its lane in .st/required-lanes.json at this accepted base and record the lane definition digest",
        ),
        option(
            "--aggregate",
            "FILE",
            "record the facts in FILE instead of running a command",
        ),
        OptionSpec {
            action: Action::Append,
            default: DefaultValue::List(&[]),
            ..option(
                "--input",
                "NAME=VALUE",
                "record one more input the command depends on (a name this script does not set itself; repeatable)",
            )
        },
        OptionSpec {
            action: Action::Append,
            default: DefaultValue::List(&[]),
            ..option(
                "--input-file",
                "NAME=PATH",
                "record one more input read from PATH after the command ends (its distinct lines, comma-joined; repeatable)",
            )
        },
        option(
            "--out",
            "DIR",
            "write the pack and a summary here instead of importing and pushing",
        ),
    ],
};

const DESCRIPTION: &str = r#"Run one check once on this machine and ask the signer to record it as an evidence note.

  scripts/evidence-wrap --check linux-gate [--change-id github:OWNER/REPO#N] [--input NAME=VALUE]... [--input-file NAME=PATH]... [--push origin] -- COMMAND...

Run it from a clean checkout of the exact commit you are about to push. It runs COMMAND once
(output streams to your terminal), then sends the signer the facts it measured: the commit,
the command, its exit code, the sha256 of its exact output and an environment fingerprint
(flake.lock, the dev shell derivation, this script's own bytes, the system, the attempt). The
signer (scripts/evidence-sign, behind a sekrets grant; this script never sees the key)
recomputes the tree and flake.lock itself and signs. A failing command is recorded too: a
failure is a record, not a missing record. COMMAND keeps the caller's environment; the signer is
started without the loader and interpreter variables it refuses (LD_*, DYLD_*, PYTHON*,
GLIBC_TUNABLES, GCONV_PATH, NLSPATH) and with a fixed PATH.

The note is imported as refs/tags/evidence/<tree>/<record> in this checkout and, while gates on older bases
read only notes, as refs/notes/evidence/<tree>/<record> naming the same record. With --push REMOTE both are
also pushed, after scripts/evidence-verify accepts it. CI finds a note by its tree, so it only helps when the commit you push has the tree CI will test (a branch current with main).
A ref the remote answers with a bare `(failed)` is pushed again, up to 3 times; a refusal that gives a reason fails at once.

With --aggregate FILE nothing is run: FILE is JSON {"command": [...], "exit_code": N, "output": ANY,
"inputs": {name: string}} written by a job that summarizes other jobs (an aggregate gate). The
output digest is the sha256 of the canonical JSON of "output" (sorted keys, no spaces), and the
extra inputs are recorded next to the environment fingerprint. The note then says only what that
job knows, and the command names it as an aggregate.

With --out DIR the note is not imported or pushed: DIR/<record>.pack (the git objects) and
DIR/<record>.json (record, check, tree, commit, tier, exit code) are written for a later job to
publish. A job on a shallow checkout uses this, because the server refuses a push from one.
In --aggregate mode a dirty workspace does not stop the signature (the job has already run its
tests); it is recorded as the input workspace_clean instead.

--input-file NAME=PATH records an input the command itself reports, read after it ends: the sorted, distinct non-empty lines of
PATH joined by commas (a count and digest past 500 characters), or 'none' when PATH is missing or empty. fractal-test uses it for env_skips, the tests that skipped because this
host cannot run them (CI_TEST_ENV_SKIPS), so the note says which tests did not run here.

With EVIDENCE_PUSH_TOKEN set, --push uses it as an HTTP authorization header (never printed).

With --lanes-from BASE the check is held to its lane in .st/required-lanes.json at BASE (the accepted base): the command must be the
lane's argv, and the note records lane_definition_sha256, the digest of the lane as THIS tree defines it (the base's argv and paths, this
tree's bytes at those paths). For a tree that leaves the lane alone that is the digest the verifier recomputes from BASE; for a tree that
edits its lane it is the edited definition's, which only a level whose policy says by_level lane "tree" accepts (our hosts, since
2026-10-26: a lane edit is signed like any other change). It is the producer half of `evidence-verify --lanes-from`.

Take this script from the accepted base (main), not from the change under test.
"#;

fn usage() -> String {
    let mut out = "usage: evidence-wrap".to_owned();
    let indent = " ".repeat(out.len() + 1);
    let mut column = out.len();
    for part in PARSER
        .options
        .iter()
        .map(|spec| {
            let flag = spec.short.unwrap_or(spec.long);
            let label = spec
                .metavar
                .map_or_else(|| flag.to_owned(), |v| format!("{flag} {v}"));
            if spec.long == "--check" {
                label
            } else {
                format!("[{label}]")
            }
        })
        .chain(std::iter::once("...".to_owned()))
    {
        if column + 1 + part.len() > 78 {
            out.push('\n');
            out.push_str(&indent);
            column = indent.len();
        } else {
            out.push(' ');
            column += 1;
        }
        out.push_str(&part);
        column += part.len();
    }
    out.push('\n');
    out
}

fn error(message: impl std::fmt::Display) -> Exit {
    Exit {
        code: 2,
        stdout: String::new(),
        stderr: format!("{}evidence-wrap: error: {message}\n", usage()),
    }
}

fn compat_exit(exit: super::super::argparse_compat::Exit) -> Exit {
    if exit.code == 0 {
        let options = exit
            .stdout
            .split_once("\noptions:\n")
            .map_or("", |(_, options)| options);
        Exit {
            code: 0,
            stdout: format!(
                "{}\n{}\npositional arguments:\n  command\n\noptions:\n{options}",
                usage(),
                DESCRIPTION
            ),
            stderr: String::new(),
        }
    } else {
        Exit {
            code: exit.code,
            stdout: exit.stdout,
            stderr: exit.stderr.replacen(&PARSER.usage(), &usage(), 1),
        }
    }
}

enum Token<'a> {
    Value,
    Separator,
    Unknown,
    Option(&'static OptionSpec, Option<&'a str>),
}

fn token(text: &str) -> Result<Token<'_>, Exit> {
    if text == "--" {
        return Ok(Token::Separator);
    }
    let Some(number) = text.strip_prefix('-') else {
        return Ok(Token::Value);
    };
    if number.is_empty() {
        return Ok(Token::Value);
    }
    let (key, explicit) = text
        .split_once('=')
        .map_or((text, None), |(k, v)| (k, Some(v)));
    if let Some(spec) = PARSER
        .options
        .iter()
        .find(|s| s.long == key || s.short == Some(key))
    {
        return Ok(Token::Option(spec, explicit));
    }
    if text.starts_with("--") {
        let matches: Vec<_> = PARSER
            .options
            .iter()
            .filter(|s| s.long.starts_with(key))
            .collect();
        match matches.as_slice() {
            [spec] => return Ok(Token::Option(spec, explicit)),
            [] => {}
            _ => {
                return Err(error(format!(
                    "ambiguous option: {text} could match {}",
                    matches
                        .iter()
                        .map(|s| s.long)
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
    } else if let Some(rest) = text.strip_prefix("-h") {
        return Ok(Token::Option(&PARSER.options[0], Some(rest)));
    }
    // CPython 3.14 uses r'-\.?\d' without an end anchor, so digit-prefixed
    // spellings such as -1x and -1e3 are values. This parser declares no
    // negative-number-like options, so _has_negative_number_optionals is false.
    let candidate = number.strip_prefix('.').unwrap_or(number);
    let negative = candidate
        .chars()
        .next()
        .is_some_and(|c| decimal(u32::from(c)).is_some());
    Ok(if negative || text.contains(' ') {
        Token::Value
    } else {
        Token::Unknown
    })
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

pub(super) fn parse(argv: &[String]) -> Result<Args, Exit> {
    // argparse classifies all tokens before consuming REMAINDER. Thus an
    // ambiguous abbreviation even inside a command is rejected, unless -- hid it.
    for arg in argv {
        if matches!(token(arg)?, Token::Separator) {
            break;
        }
    }
    let mut prefix = Vec::new();
    let mut extras = Vec::new();
    let mut index = 0;
    let mut command = Vec::new();
    while let Some(arg) = argv.get(index) {
        match token(arg)? {
            Token::Separator => {
                command.extend_from_slice(&argv[index + 1..]);
                break;
            }
            Token::Value => {
                command.extend_from_slice(&argv[index..]);
                break;
            }
            Token::Unknown => extras.push(arg.clone()),
            Token::Option(spec, explicit) => {
                if matches!(spec.action, Action::Help) {
                    prefix.push(arg.clone());
                    // Help exits at its action, before required checks or extras.
                    return match PARSER.parse(&prefix) {
                        Err(exit) => Err(compat_exit(exit)),
                        Ok(_) => Err(error("help action did not exit")),
                    };
                }
                let value = if let Some(value) = explicit {
                    value
                } else {
                    index += 1;
                    let Some(value) = argv.get(index) else {
                        return Err(error(format!(
                            "argument {}: expected one argument",
                            spec.long
                        )));
                    };
                    if !matches!(token(value)?, Token::Value) {
                        return Err(error(format!(
                            "argument {}: expected one argument",
                            spec.long
                        )));
                    }
                    value
                };
                // Canonical explicit spelling lets the shared parser perform
                // stores/appends without reclassifying a negative value.
                prefix.push(format!("{}={value}", spec.long));
            }
        }
        index += 1;
    }
    let parsed = PARSER.parse(&prefix).map_err(compat_exit)?;
    if !parsed.provided.contains("--check") {
        return Err(error("the following arguments are required: --check"));
    }
    if !extras.is_empty() {
        return Err(error(format!(
            "unrecognized arguments: {}",
            extras.join(" ")
        )));
    }
    let mut values = parsed.values;
    let aggregate = string(values.remove("--aggregate"));
    let lanes_from = string(values.remove("--lanes-from"));
    let nonempty = |value: &Option<String>| value.as_ref().is_some_and(|v| !v.is_empty());
    if !command.is_empty() == nonempty(&aggregate) {
        return Err(error(
            "give either the command after -- or --aggregate FILE",
        ));
    }
    if nonempty(&lanes_from) && nonempty(&aggregate) {
        return Err(error(
            "--lanes-from is for a command this script runs, not --aggregate",
        ));
    }
    Ok(Args {
        check: string(values.remove("--check")).unwrap_or_default(),
        change_id: string(values.remove("--change-id")),
        attempt: string(values.remove("--attempt")).unwrap_or_default(),
        signer: string(values.remove("--signer")).unwrap_or_else(|| {
            std::env::var("EVIDENCE_SIGNER")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(default_signer)
        }),
        toolchain_sha256: string(values.remove("--toolchain-sha256")),
        keys: string(values.remove("--keys")),
        keys_from: string(values.remove("--keys-from")).unwrap_or_default(),
        verifier: string(values.remove("--verifier")).unwrap_or_else(|| {
            std::env::var("MERGEMASTER_BIN").unwrap_or_else(|_| "mergemaster".to_owned())
        }),
        push: string(values.remove("--push")),
        lanes_from,
        aggregate,
        input: strings(values.remove("--input")),
        input_file: strings(values.remove("--input-file")),
        out: string(values.remove("--out")),
        command,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Execute only the pinned parser prefix, never its Git/signing/lane code.
    // The verifier default/help follows the approved wave-2 native cutover.
    const ORACLE: &str = r#"
import argparse, ast, json, os, sys
from pathlib import Path
source, *argv = sys.argv[1:]
module = ast.parse(Path(source).read_text(), filename=source)
__doc__ = ast.get_docstring(module, clean=False)
HERE = Path(source).parent
DEFAULT_SIGNER = ['st', 'sekrets', '--', 'mergemaster', 'evidence', 'legacy-sign']
main = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
end = next(i for i,n in enumerate(main.body) if isinstance(n, ast.Try))
body = main.body[:end]
for node in ast.walk(ast.Module(body=body, type_ignores=[])):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'add_argument' and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == '--verifier':
        node.keywords = [ast.keyword(arg='default', value=ast.Constant(value='mergemaster')), ast.keyword(arg='help', value=ast.Constant(value='trusted mergemaster binary (default: $MERGEMASTER_BIN, else PATH)'))]
sys.argv = ['evidence-wrap']
exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])), source, 'exec'))
args.command = command
print(json.dumps(vars(args)))
"#;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn parser_failures_and_help_match_pinned_oracle() {
        let source = PathBuf::from(std::env::var_os("MERGEMASTER_PYTHON_ORACLE").unwrap())
            .join("scripts/evidence-wrap");
        let cases: &[&[&str]] = &[
            &[],
            &["--help"],
            &["-h"],
            &["-hhh"],
            &["--he"],
            &["--help=x"],
            &["-h=x"],
            &["--check"],
            &["--check", "--out"],
            &["--check", "-1"],
            &["--check", "-1.5"],
            &["--check", "-1x"],
            &["--check", "-x1"],
            &["--check", "-.5"],
            &["--check", "-1e3"],
            &["--check", "-1e2"],
            &["--unknown"],
            &["--check", "x"],
            &["--check", "x", "--"],
            &["--check", "x", "--aggregate", ""],
            &["--check", "x", "--aggregate", "file", "true"],
            &[
                "--check",
                "x",
                "--aggregate",
                "file",
                "--lanes-from",
                "main",
            ],
            &["--check", "x", "--unknown", "true"],
            &["--check", "x", "--in", "a=b"],
            &["--check", "x", "--in", "-1"],
            &["--check", "x", "--in", "-1.5"],
            &["--check", "x", "--in", "-1x"],
            &["--check", "x", "--in", "-x1"],
            &["--check", "x", "--in", "-.5"],
            &["--check", "x", "--in", "-1e3"],
            &["--check", "x", "true", "--in"],
            &["--check", "x", "--input"],
            &["--check", "x", "--input-file", "--help"],
        ];
        for case in cases {
            let actual = parse(&argv(case)).unwrap_err();
            let expected = crate::pinned_python::command()
                .args(["-c", ORACLE])
                .arg(&source)
                .args(*case)
                .env("COLUMNS", "80")
                .output()
                .unwrap();
            assert_eq!(actual.code, expected.status.code().unwrap(), "{case:?}");
            assert_eq!(actual.stdout.as_bytes(), expected.stdout, "stdout {case:?}");
            assert_eq!(actual.stderr.as_bytes(), expected.stderr, "stderr {case:?}");
        }
    }

    #[test]
    fn remainder_defaults_repeated_stores_and_appends() {
        let args = parse(&argv(&[
            "--chec",
            "first",
            "--check=last",
            "--attempt",
            "2",
            "--signer",
            "[]",
            "--change-id",
            "change",
            "--toolchain-sha256",
            "digest",
            "--keys",
            "keys",
            "--keys-from",
            "base",
            "--verifier",
            "verify",
            "--push",
            "origin",
            "--lanes-from",
            "main",
            "--out",
            "directory",
            "--input",
            "a=1",
            "--input=b=2",
            "--input-file",
            "x=one",
            "--input-file=y=two",
            "--",
            "sh",
            "-c",
            "--help",
        ]))
        .unwrap();
        assert_eq!(args.check, "last");
        assert_eq!(args.change_id.as_deref(), Some("change"));
        assert_eq!(args.attempt, "2");
        assert_eq!(args.signer, "[]");
        assert_eq!(args.toolchain_sha256.as_deref(), Some("digest"));
        assert_eq!(args.keys.as_deref(), Some("keys"));
        assert_eq!(args.keys_from, "base");
        assert_eq!(args.verifier, "verify");
        assert_eq!(args.push.as_deref(), Some("origin"));
        assert_eq!(args.lanes_from.as_deref(), Some("main"));
        assert_eq!(args.out.as_deref(), Some("directory"));
        assert_eq!(args.input, ["a=1", "b=2"]);
        assert_eq!(args.input_file, ["x=one", "y=two"]);
        assert_eq!(args.command, ["sh", "-c", "--help"]);
        let args = parse(&argv(&[
            "--check",
            "",
            "echo",
            "--check",
            "untouched",
            "--help",
        ]))
        .unwrap();
        assert_eq!(args.check, "");
        assert_eq!(args.attempt, "1");
        assert_eq!(args.keys_from, "origin/main");
        assert_eq!(args.command, ["echo", "--check", "untouched", "--help"]);
        assert!(args.input.is_empty());
        let args = parse(&argv(&["--check", "x", "--aggregate", "file"])).unwrap();
        assert_eq!(args.aggregate.as_deref(), Some("file"));
        assert!(args.command.is_empty());
    }
}
