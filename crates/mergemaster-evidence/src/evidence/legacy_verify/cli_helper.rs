//! Small import replacements for extracted callers. Successful JSON data exits
//! zero (including false/null); usage exits 2; operational refusals exit 3 with
//! {reason, detail}. Pure text helpers read UTF-8 stdin, never checkout files.
use super::{
    cli_adapter::{Exit, decode},
    value_inputs::TextRef,
};
use crate::evidence::{
    legacy_output,
    legacy_policy::{PolicyError, normalized_text::NormalizedText},
};
use clap::{Parser, Subcommand};
use std::{ffi::OsString, io::Read, os::unix::ffi::OsStrExt, path::PathBuf};

#[derive(Parser)]
#[command(name = "legacy-evidence-verify-helper")]
struct Arguments {
    #[command(subcommand)]
    operation: Operation,
}
#[derive(Subcommand)]
enum Operation {
    /// Check declared CI inputs at every revision before comparing projections.
    CiInputs {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        revision: Vec<OsString>,
        #[arg(long)]
        input: Vec<OsString>,
    },
    UnresolvedCiInputs {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        tree: String,
        #[arg(long)]
        input: Vec<OsString>,
    },
    /// Return null or an array of canonical selected bytes.
    SelectPart {
        #[arg(long)]
        path: OsString,
        #[arg(long)]
        selector: OsString,
    },
    LaneRules {
        #[arg(long)]
        check: OsString,
    },
    /// Parse lane rules from stdin and compare their definition in two trees.
    LaneDefinition {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        base_tree: OsString,
        #[arg(long)]
        tree: OsString,
        #[arg(long)]
        check: OsString,
    },
}
fn text(value: &std::ffi::OsStr) -> NormalizedText {
    NormalizedText::from_points(&decode(value.as_bytes()))
}
fn texts(values: &[OsString]) -> Vec<NormalizedText> {
    values.iter().map(|value| text(value)).collect()
}
fn stdin_text(input: &mut impl Read) -> Result<String, PolicyError> {
    const LIMIT: u64 = 16 * 1024 * 1024;
    let mut bytes = Vec::new();
    input
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| super::crate_inputs::failure(error.to_string()))?;
    if bytes.len() as u64 > LIMIT {
        return Err(super::crate_inputs::failure("helper stdin exceeds 16 MiB"));
    }
    String::from_utf8(bytes).map_err(|_| super::crate_inputs::failure("helper stdin is not UTF-8"))
}
fn evaluate(
    operation: Operation,
    input: &mut impl Read,
    output: &mut String,
) -> Result<(), PolicyError> {
    let written = match operation {
        Operation::CiInputs {
            repo,
            revision,
            input,
        } => {
            let unchanged =
                super::ci_inputs::ci_inputs_unchanged(&repo, &texts(&input), &texts(&revision))?;
            legacy_output::write(output, |w| {
                w.object(|o| o.field_text("unchanged", |w| w.boolean(unchanged)))
            })
        }
        Operation::UnresolvedCiInputs { repo, tree, input } => {
            let inputs = texts(&input);
            let unresolved = super::ci_inputs::unresolved_ci_inputs(&repo, &tree, &inputs)?;
            legacy_output::write(output, |w| {
                w.array(|a| {
                    for item in unresolved {
                        a.item(|w| w.codepoints(item.borrowed().points()))?;
                    }
                    Ok(())
                })
            })
        }
        Operation::SelectPart { path, selector } => {
            let content = stdin_text(input)?;
            let path = text(&path);
            let selector = text(&selector);
            let selected = if let Some(job) = selector.borrowed().strip_prefix("jobs.") {
                super::workflow::workflow_job(&content, job)?
            } else {
                super::selection_json::select_json(&content, path.borrowed(), selector.borrowed())?
            };
            legacy_output::write(output, |w| match selected {
                None => w.null(),
                Some(bytes) => w.array(|a| {
                    for byte in bytes {
                        a.item(|w| w.integer(i128::from(byte)))?;
                    }
                    Ok(())
                }),
            })
        }
        Operation::LaneRules { check } => {
            let content = stdin_text(input)?;
            let check = text(&check);
            let rules = super::cli_lanes::LaneRules::parse(&content, check.borrowed())?;
            legacy_output::write(output, |w| {
                w.object(|o| {
                    o.field_text("argv", |w| {
                        w.array(|a| {
                            for arg in &rules.argv {
                                a.item(|w| w.codepoints(arg.borrowed().points()))?;
                            }
                            Ok(())
                        })
                    })?;
                    for (name, paths) in [
                        ("definition_paths", &rules.definition_paths),
                        ("tree_inputs", &rules.tree_inputs),
                        ("absent_paths", &rules.absent_paths),
                    ] {
                        o.field_text(name, |w| {
                            w.array(|a| {
                                for path in paths {
                                    a.item(|w| w.text(path))?;
                                }
                                Ok(())
                            })
                        })?;
                    }
                    o.field_text("ci_inputs", |w| match &rules.ci_inputs {
                        None => w.null(),
                        Some(paths) => w.array(|a| {
                            for path in paths {
                                a.item(|w| w.text(path))?;
                            }
                            Ok(())
                        }),
                    })
                })
            })
        }
        Operation::LaneDefinition {
            repo,
            base_tree,
            tree,
            check,
        } => {
            let content = stdin_text(input)?;
            let check = text(&check);
            let rules = super::cli_lanes::LaneRules::parse(&content, check.borrowed())?;
            let definition = super::cli_lane_definition::lane_definition(
                &repo,
                text(&base_tree).borrowed(),
                text(&tree).borrowed(),
                &rules,
            )?;
            legacy_output::write(output, |w| {
                w.object(|o| {
                    o.field_text("sha256", |w| w.text(&definition.sha256))?;
                    o.field_text("changed", |w| {
                        w.array(|a| {
                            for path in &definition.changed {
                                a.item(|w| w.codepoints(decode(path)))?;
                            }
                            Ok(())
                        })
                    })?;
                    o.field_text("tree_sha256", |w| w.text(&definition.tree_sha256))
                })
            })
        }
    };
    written.map_err(|error| super::crate_inputs::failure(error.to_string()))
}
/// This entry is independent of Python argparse: it is an explicit import API.
pub fn run(
    argv: impl IntoIterator<Item = OsString>,
    input: &mut impl Read,
) -> anyhow::Result<Exit> {
    let args = match Arguments::try_parse_from(
        std::iter::once(OsString::from("legacy-evidence-verify-helper")).chain(argv),
    ) {
        Ok(args) => args,
        Err(error) => {
            return Ok(Exit {
                stdout: if error.use_stderr() {
                    String::new()
                } else {
                    error.to_string()
                },
                stderr: if error.use_stderr() {
                    error.to_string()
                } else {
                    String::new()
                },
                code: if error.use_stderr() { 2 } else { 0 },
            });
        }
    };
    let mut stdout = String::new();
    let code = match evaluate(args.operation, input, &mut stdout) {
        Ok(()) => 0,
        Err(error) => {
            stdout.clear();
            legacy_output::write(&mut stdout, |w| {
                w.object(|o| {
                    o.field_text("reason", |w| w.text(error.reason))?;
                    o.field_text("detail", |w| {
                        let prefix = match error.origin {
                            crate::evidence::legacy_policy::ErrorOrigin::Exception { class } => {
                                format!("{class}: ")
                            }
                            _ => String::new(),
                        };
                        w.codepoints(
                            TextRef::Str(&prefix)
                                .points()
                                .chain(error.detail.borrowed().points()),
                        )
                    })
                })
            })?;
            3
        }
    };
    stdout.push('\n');
    Ok(Exit {
        stdout,
        stderr: String::new(),
        code,
    })
}

#[cfg(test)]
#[path = "cli_helper_tests.rs"]
mod tests;
