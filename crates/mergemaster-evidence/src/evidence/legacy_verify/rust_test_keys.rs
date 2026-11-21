//! Native rust-test-keys subprocess compatibility, using the existing pinned key core.
//! Deliberate divergence: an explicit `--verifier` is refused with exit 2 because
//! projection is compiled into mergemaster, never loaded from a Python module.
//! Unhandled exceptions retain the traceback header, final exception line and
//! exit 1; omitting Python-only source frame lines is a deliberate divergence.
use super::{cli_adapter::Exit, crate_inputs::TreeSource, crate_keys::CrateKey};
use crate::evidence::{
    argparse_compat::{Action, DefaultValue, OptionSpec, Parser, Value},
    legacy_json,
    legacy_policy::{ErrorOrigin, PolicyError},
};
use std::{ffi::OsString, fmt::Write, path::Path};

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
const PARSER: Parser = Parser {
    program: "rust-test-keys",
    description: "The input key of each workspace crate's tests: what a per-crate signature is bound to (docs/per-crate-test-signing.md).",
    options: &[
        OptionSpec {
            short: Some("-h"),
            ..option(
                "--help",
                None,
                Action::Help,
                "show this help message and exit",
            )
        },
        OptionSpec {
            default: DefaultValue::String("."),
            ..option("--repo", Some("REPO"), Action::Store, "")
        },
        OptionSpec {
            default: DefaultValue::String("HEAD"),
            ..option(
                "--tree",
                Some("TREE"),
                Action::Store,
                "the tree to key (default HEAD)",
            )
        },
        option(
            "--inputs-from",
            Some("TREEISH"),
            Action::Store,
            "read .st/rust-test-inputs.json from here (the accepted base) instead of the tree",
        ),
        option(
            "--crate",
            Some("NAME"),
            Action::Append,
            "only this crate (repeatable)",
        ),
        option(
            "--paths",
            None,
            Action::Flag,
            "also print the declared paths",
        ),
        option("--json", None, Action::Flag, ""),
        option(
            "--verifier",
            Some("VERIFIER"),
            Action::Store,
            "the evidence-verify whose projection computes the key (default: the one next to this script)",
        ),
    ],
};

fn string(value: Option<Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) => Some(value),
        _ => None,
    }
}

fn refused(error: PolicyError) -> Exit {
    let (code, stderr) = match error.origin {
        ErrorOrigin::Failure => (2, format!("rust-test-keys: {}\n", error.detail)),
        // Native code has no Python source frames. Preserve the exception class,
        // exact final diagnostic line and unhandled-exception status instead.
        ErrorOrigin::Exception { class } => (
            1,
            format!(
                "Traceback (most recent call last):\n{class}: {}\n",
                error.detail
            ),
        ),
    };
    Exit {
        stdout: String::new(),
        stderr,
        code,
    }
}
fn key_json(key: &CrateKey, paths: bool, out: &mut String) -> std::fmt::Result {
    if paths {
        out.push_str("{\n  \"key\": ");
    }
    match &key.key {
        Some(key) => legacy_json::string(key, out)?,
        None => out.push_str("null"),
    }
    if paths {
        out.push_str(",\n  \"paths\": [");
        for (i, path) in key.paths.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("\n   ");
            legacy_json::codepoints(path.borrowed().points(), out)?;
        }
        if !key.paths.is_empty() {
            out.push_str("\n  ");
        }
        out.push_str("]\n }");
    }
    Ok(())
}

/// Same keying argv and wire formats as the pinned script. No sibling scripts are read.
pub fn run(argv: impl IntoIterator<Item = OsString>) -> anyhow::Result<Exit> {
    let args: Vec<String> = argv
        .into_iter()
        .map(|v| {
            v.into_string()
                .map_err(|_| anyhow::anyhow!("rust-test-keys: argv is not UTF-8"))
        })
        .collect::<Result<_, _>>()?;
    let parsed = match PARSER.parse(&args) {
        Ok(parsed) => parsed,
        Err(exit) => {
            return Ok(Exit {
                stdout: exit.stdout,
                stderr: exit.stderr,
                code: u8::try_from(exit.code)?,
            });
        }
    };
    if parsed.provided.contains("--verifier") {
        return Ok(Exit {
            stdout: String::new(),
            stderr: "rust-test-keys: --verifier is not supported; the projection is built into mergemaster\n".into(),
            code: 2,
        });
    }
    let mut values = parsed.values;
    let repo =
        string(values.remove("--repo")).ok_or_else(|| anyhow::anyhow!("missing --repo default"))?;
    let tree =
        string(values.remove("--tree")).ok_or_else(|| anyhow::anyhow!("missing --tree default"))?;
    let inputs = string(values.remove("--inputs-from"));
    let paths = values.remove("--paths") == Some(Value::Bool(true));
    let json = values.remove("--json") == Some(Value::Bool(true));
    let only = match values.remove("--crate") {
        Some(Value::List(items)) => items
            .into_iter()
            .filter_map(|v| string(Some(v)))
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    let keys = match (TreeSource {
        repo: Path::new(&repo),
        tree: &tree,
        no_lazy_fetch: false,
    })
    .keys_from(inputs.as_deref(), &only)
    {
        Ok(keys) => keys,
        Err(error) => return Ok(refused(error)),
    };
    let mut keys: Vec<_> = keys.into_iter().collect();
    keys.sort_by(|a, b| a.0.cmp(&b.0));
    let mut stdout = String::new();
    if json {
        stdout.push('{');
    }
    for (i, (name, key)) in keys.iter().enumerate() {
        if json {
            if i > 0 {
                stdout.push(',');
            }
            stdout.push_str("\n ");
            legacy_json::string(name, &mut stdout)?;
            stdout.push_str(": ");
            key_json(key, paths, &mut stdout)?;
        } else {
            write!(stdout, "{name}\t{}", key.key.as_deref().unwrap_or("None"))?;
            if paths {
                stdout.push('\t');
                for (i, path) in key.paths.iter().enumerate() {
                    if i > 0 {
                        stdout.push(',');
                    }
                    super::terminal_sink::value(path.borrowed(), &mut stdout)
                        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                }
            }
            stdout.push('\n');
        }
    }
    if json {
        if !keys.is_empty() {
            stdout.push('\n');
        }
        stdout.push_str("}\n");
    }
    Ok(Exit {
        stdout,
        stderr: String::new(),
        code: 0,
    })
}
