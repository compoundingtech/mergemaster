//! CLI argparse parity against definitions extracted from the immutable Python oracle.
#[path = "../src/pinned_python.rs"]
mod pinned_python;
use std::{
    path::PathBuf,
    process::{Command, Output},
};

const ORACLE: &str = r#"
import argparse, ast, os, re, sys
source, program, *argv = sys.argv[1:]
module = ast.parse(open(source).read(), filename=source)
__doc__ = ast.get_docstring(module)
main = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
end = next(i for i, node in enumerate(main.body) if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'parse_args') + 1
body = main.body[:end]
if program == 'evidence-flip-ready':
    body.append(main.body[end])
sys.argv[0] = program
exec(compile(ast.Module(body=body, type_ignores=[]), source, 'exec'))
sys.exit(99) # These cases must terminate at the argument boundary, not run GitHub.
"#;
fn compare(command: &str, args: &[&str]) {
    let program = format!("evidence-{command}");
    let source =
        PathBuf::from(std::env::var_os("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle source"))
            .join("scripts")
            .join(&program);
    let python = pinned_python::command()
        .args(["-c", ORACLE])
        .arg(source)
        .arg(&program)
        .args(args)
        .env("COLUMNS", "80")
        .env("NO_COLOR", "1")
        .env_remove("FORCE_COLOR")
        .output()
        .unwrap();
    assert_ne!(
        python.status.code(),
        Some(99),
        "nonterminal case {command} {args:?}"
    );
    let native = Command::new(
        std::env::var_os("CARGO_BIN_EXE_mergemaster")
            .expect("CARGO_BIN_EXE_mergemaster is set at test runtime"),
    )
    .args(["evidence", command])
    .args(args)
    .env("COLUMNS", "80")
    .env("NO_COLOR", "1")
    .env_remove("FORCE_COLOR")
    .output()
    .unwrap();
    same(&program, args, native, python);
}
fn same(program: &str, args: &[&str], native: Output, python: Output) {
    assert_eq!(
        native.status.code(),
        python.status.code(),
        "{program} {args:?}: native stderr={} oracle stderr={}",
        String::from_utf8_lossy(&native.stderr),
        String::from_utf8_lossy(&python.stderr)
    );
    assert_eq!(native.stdout, python.stdout, "{program} {args:?} stdout");
    assert_eq!(
        String::from_utf8_lossy(&native.stderr),
        String::from_utf8_lossy(&python.stderr),
        "{program} {args:?} stderr"
    );
}
#[test]
fn all_long_prefixes_and_equals_obey_argparse_resolution() {
    for (command, options) in [
        (
            "flip-ready",
            vec![
                ("--help", false),
                ("--repo", true),
                ("--cache", true),
                ("--propose", false),
                ("--dry-run", false),
            ],
        ),
        (
            "skip-report",
            vec![
                ("--help", false),
                ("--repo", true),
                ("--hours", true),
                ("--actor", true),
                ("--receipts", true),
                ("--cache", true),
                ("--markdown", false),
            ],
        ),
    ] {
        for (option, takes_value) in options {
            for end in 3..=option.len() {
                let prefix = &option[..end];
                let value = if option == "--hours" { "-2.5" } else { "value" };
                if takes_value {
                    compare(command, &[prefix, value, "--help"]);
                } else {
                    compare(command, &[prefix, "--help"]);
                }
                let explicit = format!("{prefix}={value}");
                compare(command, &[&explicit, "--help"]);
            }
        }
    }
}
#[test]
fn option_values_unknowns_duplicates_and_separator_match() {
    let common: &[&[&str]] = &[
        &["--help"],
        &["-h"],
        &["--hel"],
        &["-hh"],
        &["-hhh"],
        &["-hxyz"],
        &["-h=oops"],
        &["-h="],
        &["-h-"],
        &["-hh=oops"],
        &["--help=oops"],
        &["--wat"],
        &["--wat=1"],
        &["--wat", "value"],
        &["value"],
        &["-"],
        &[""],
        &["--"],
        &["--", "--help"],
        &["--", "--"],
        &["--repo", "--", "--help"],
        &["--=x"],
        &["--="],
        &["---help"],
        &["--n"],
        &["-r"],
        &["-help"],
        &["-repo"],
        &["--repo"],
        &["--cache"],
        &["--repo", "--wat"],
        &["--repo", "--help"],
        &["--repo", "--r"],
        &["--repo", "--repo=x/y"],
        &["--repo=-option", "--help"],
        &["--repo=", "--help"],
        &["--repo", "-1x", "--help"],
        &["--repo", "- option", "--help"],
        &["--repo", "--unknown value", "--help"],
        &["--repo", "a/b", "--repo", "c/d", "--help"],
        &["--cache", "first", "--cache=second", "--help"],
        &["--wat", "--help"],
        &["--help", "--wat"],
        &["value", "--help"],
        &["--help", "--repo"],
        &["--cache", "--help"],
        &["--repo=bad", "--wat"],
        &["--help", "--r"],
        &["--help", "--repo"],
        &["--repo", "-inf", "--help"],
    ];
    for command in ["flip-ready", "skip-report"] {
        for args in common {
            compare(command, args);
        }
    }
    for args in [
        vec!["--dry-run"],
        vec!["--dry-r", "--dry-run"],
        vec!["--repo=bad"],
        vec!["--repo="],
        vec!["--repo=a/b/c"],
        vec!["--repo=a/é"],
        vec!["--repo=a/b\n"],
        vec!["--repo=bad", "--repo=a/b", "--dry-run"],
        vec!["--repo=a/b", "--repo=bad"],
        vec!["--propose=yes"],
        vec!["--dry-run=false"],
        vec!["--prop", "--propose", "--dry", "--dry-run", "--help"],
        vec!["--dry-run", "--propose", "--help"],
        vec!["--dry-run", "--unknown"],
    ] {
        compare("flip-ready", &args);
    }
    for args in [
        vec!["--r"],
        vec!["--re"],
        vec!["--r=x"],
        vec!["--h"],
        vec!["--h=2"],
        vec!["--hours"],
        vec!["--actor"],
        vec!["--receipts"],
        vec!["--hours", "--h"],
        vec!["--hours", "-inf"],
        vec!["--hours", "-nan"],
        vec!["--hours", "-x"],
        vec!["--hours", "--help"],
        vec![
            "--actor=a",
            "--actor=b",
            "--rec=one",
            "--receipts=two",
            "--markdown",
            "--markdown",
            "--help",
        ],
        vec!["--repo=not/a/validated/repo", "--help"],
        vec!["--markdown=false"],
        vec!["--actor", "--re"],
    ] {
        compare("skip-report", &args);
    }
}
#[test]
fn python_float_conversion_and_failure_order_match() {
    for value in [
        "",
        "abc",
        "1__2",
        "_1",
        "1_",
        "0x1p2",
        "NaN(payload)",
        "\u{1c}1",
        "1\u{1f}",
        "--",
        "--h",
        "--unknown",
        "-inf",
        "-nan",
        "-Infinity",
        "-.e2",
        "-.٣x",
    ] {
        let explicit = format!("--hours={value}");
        compare("skip-report", &[&explicit, "--hours=2", "--unknown"]);
        compare("skip-report", &["--hours", value, "--unknown"]);
    }
    for value in [
        "-24",
        "-.5",
        "-1e3",
        "-1_0",
        "-١.٥",
        " 1_2.٥e+1 ",
        "\u{a0}1\u{2003}",
        "Infinity",
        "+inf",
        "-inf",
        "nan",
        "+NaN",
        "-NaN",
        "1e9999",
        "1.",
        ".1",
        "+.5",
        "-0",
        "-0.0",
    ] {
        let explicit = format!("--hours={value}");
        compare("skip-report", &[&explicit, "--help"]);
        if !matches!(value, "-inf" | "-NaN") {
            compare("skip-report", &["--hours", value, "--help"]);
        }
    }
    compare("skip-report", &["--hours=bad", "--help"]);
    compare("skip-report", &["--help", "--hours=bad"]);
    compare("skip-report", &["--unknown", "--hours=bad"]);
    compare("skip-report", &["--hours=bad", "--r"]);
    compare("skip-report", &["--r", "--hours=bad"]);
}
