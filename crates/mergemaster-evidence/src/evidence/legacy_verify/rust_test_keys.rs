//! Native rust-test-keys subprocess compatibility, using the existing pinned key core.
//! `--verifier` is retained as a migration argument; projection is always compiled Rust.
use super::{cli_adapter::Exit, crate_inputs::TreeSource, crate_keys::CrateKey};
use crate::evidence::legacy_json;
use std::{ffi::OsString, fmt::Write, path::Path};

const USAGE: &str = "usage: rust-test-keys [-h] [--repo REPO] [--tree TREE] [--inputs-from TREEISH]\n                      [--crate NAME] [--paths] [--json] [--verifier VERIFIER]\n";
const HELP: &str = "\nThe input key of each workspace crate's tests: what a per-crate signature is\nbound to (docs/per-crate-test-signing.md).\n\noptions:\n  -h, --help            show this help message and exit\n  --repo REPO\n  --tree TREE           the tree to key (default HEAD)\n  --inputs-from TREEISH\n                        read .st/rust-test-inputs.json from here (the accepted\n                        base) instead of the tree\n  --crate NAME          only this crate (repeatable)\n  --paths               also print the declared paths\n  --json\n  --verifier VERIFIER   the evidence-verify whose projection computes the key\n                        (default: the one next to this script)\n";
const OPTIONS: [&str; 8] = [
    "--help",
    "--repo",
    "--tree",
    "--inputs-from",
    "--crate",
    "--paths",
    "--json",
    "--verifier",
];

fn diagnostic(message: String) -> Exit {
    Exit {
        stdout: String::new(),
        stderr: format!("{USAGE}rust-test-keys: error: {message}\n"),
        code: 2,
    }
}
fn option(arg: &str) -> Option<usize> {
    let name = arg.split('=').next().unwrap_or(arg);
    if name == "-h" {
        return Some(0);
    }
    // Every long option has a distinct initial, so nonempty prefixes are unique.
    // The bare `--` separator is handled before option lookup.
    name.starts_with("--")
        .then(|| OPTIONS.iter().position(|v| v.starts_with(name)))
        .flatten()
}
fn takes_value(id: usize) -> bool {
    matches!(id, 1 | 2 | 3 | 4 | 7)
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
    let (mut repo, mut tree, mut inputs) = (".", "HEAD", None);
    let (mut paths, mut json) = (false, false);
    let mut only = Vec::new();
    let mut unknown = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            unknown.extend(args[i..].iter().map(String::as_str));
            break;
        }
        let Some(id) = option(arg) else {
            unknown.push(arg);
            i += 1;
            continue;
        };
        let explicit = arg.split_once('=').map(|(_, value)| value);
        if !takes_value(id) {
            if let Some(value) = explicit {
                return Ok(diagnostic(format!(
                    "argument {}: ignored explicit argument {}",
                    if id == 0 { "-h/--help" } else { OPTIONS[id] },
                    super::python_repr::Repr(value.into())
                )));
            }
            if id == 0 {
                return Ok(Exit {
                    stdout: format!("{USAGE}{HELP}"),
                    stderr: String::new(),
                    code: 0,
                });
            }
            if id == 5 {
                paths = true;
            } else {
                json = true;
            }
        } else {
            let value = match explicit {
                Some(value) => value,
                None => {
                    i += 1;
                    let Some(value) = args
                        .get(i)
                        .filter(|v| !v.starts_with('-') || v.parse::<f64>().is_ok())
                    else {
                        return Ok(diagnostic(format!(
                            "argument {}: expected one argument",
                            OPTIONS[id]
                        )));
                    };
                    value
                }
            };
            match id {
                1 => repo = value,
                2 => tree = value,
                3 => inputs = Some(value),
                4 => only.push(value.to_owned()),
                _ => {}
            }
        }
        i += 1;
    }
    if !unknown.is_empty() {
        return Ok(diagnostic(format!(
            "unrecognized arguments: {}",
            unknown.join(" ")
        )));
    }
    let keys = match (TreeSource {
        repo: Path::new(repo),
        tree,
        no_lazy_fetch: false,
    })
    .keys_from(inputs, &only)
    {
        Ok(keys) => keys,
        Err(error) => {
            return Ok(Exit {
                stdout: String::new(),
                stderr: format!("rust-test-keys: {}\n", error.detail),
                code: 2,
            });
        }
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
