//! Pinned evidence-keygen/evidence-log-watch argparse boundary.
use super::super::{
    argparse_compat::{Action, DefaultValue, Exit, OptionSpec, Parser, Value, float, integer},
    keygen::KeygenArgs,
    log_watch::LogWatchArgs,
};

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
const HELP: OptionSpec = OptionSpec {
    short: Some("-h"),
    metavar: None,
    action: Action::Help,
    ..option("--help", "", "show this help message and exit")
};
const KEYGEN: Parser = Parser {
    program: "evidence-keygen",
    description: "Create this host's evidence signing key and the signer configuration, and print the line to list the key.",
    options: &[
        HELP,
        option(
            "--name",
            "NAME",
            "an ALIAS in the signer, LEVEL/ALIAS; the line is for a public file, so never the real host or account name",
        ),
        OptionSpec {
            choices: &["host", "agent"],
            default: DefaultValue::String("host"),
            ..option(
                "--level",
                "{host,agent}",
                "the trust level the principal names (default host)",
            )
        },
        option(
            "--home",
            "HOME",
            "the home directory to use instead of this account's (for tests and special accounts)",
        ),
    ],
};
const WATCH: Parser = Parser {
    program: "evidence-log-watch",
    description: "Alert when the published evidence log stops moving: a stalled pull is a page within minutes, not a puzzle hours later.",
    options: &[
        HELP,
        option("--remote", "REMOTE", ""),
        option(
            "--state",
            "STATE",
            "directory for the small repository and the state file",
        ),
        option(
            "--notify",
            "NOTIFY",
            "JSON argv; the alert line is appended as its last argument",
        ),
        OptionSpec {
            action: Action::Convert {
                name: "int",
                parse: integer,
            },
            default: DefaultValue::Int(360),
            ..option("--max-age", "MAX_AGE", "")
        },
        OptionSpec {
            action: Action::Convert {
                name: "int",
                parse: integer,
            },
            default: DefaultValue::Int(3600),
            ..option("--repeat", "REPEAT", "")
        },
        OptionSpec {
            action: Action::Convert {
                name: "float",
                parse: float,
            },
            ..option("--now", "NOW", "")
        },
    ],
};
// Required options change both brackets and wrapping in argparse's usage line.
// The shared optional-only renderer cannot express that presentation.
const KEYGEN_USAGE: &str =
    "usage: evidence-keygen [-h] --name NAME [--level {host,agent}] [--home HOME]\n";
const WATCH_USAGE: &str = "usage: evidence-log-watch [-h] --remote REMOTE --state STATE --notify NOTIFY\n                          [--max-age MAX_AGE] [--repeat REPEAT] [--now NOW]\n";
fn required_usage(parser: &Parser, usage: &str, mut exit: Exit) -> Exit {
    let generated = parser.usage();
    for output in [&mut exit.stdout, &mut exit.stderr] {
        if output.starts_with(&generated) {
            output.replace_range(..generated.len(), usage);
        }
    }
    exit
}
fn string(value: Option<Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) => Some(value),
        _ => None,
    }
}
pub(super) fn keygen(argv: &[String]) -> Result<KeygenArgs, Exit> {
    let mut values = KEYGEN
        .parse_required(argv, &["--name"])
        .map_err(|exit| required_usage(&KEYGEN, KEYGEN_USAGE, exit))?
        .values;
    Ok(KeygenArgs {
        name: string(values.remove("--name")).ok_or_else(|| KEYGEN.error("missing --name"))?,
        level: string(values.remove("--level")).ok_or_else(|| KEYGEN.error("missing --level"))?,
        home: string(values.remove("--home")),
    })
}
pub(super) fn log_watch(argv: &[String]) -> Result<LogWatchArgs, Exit> {
    let mut values = WATCH
        .parse_required(argv, &["--remote", "--state", "--notify"])
        .map_err(|exit| required_usage(&WATCH, WATCH_USAGE, exit))?
        .values;
    let max_age = match values.remove("--max-age") {
        Some(Value::Int(value)) => value,
        _ => return Err(WATCH.error("invalid --max-age type")),
    };
    let repeat = match values.remove("--repeat") {
        Some(Value::Int(value)) => value,
        _ => return Err(WATCH.error("invalid --repeat type")),
    };
    let now = match values.remove("--now") {
        Some(Value::None) => None,
        Some(Value::Float(value)) => Some(value),
        _ => return Err(WATCH.error("invalid --now type")),
    };
    Ok(LogWatchArgs {
        remote: string(values.remove("--remote")).ok_or_else(|| WATCH.error("missing --remote"))?,
        state: string(values.remove("--state"))
            .ok_or_else(|| WATCH.error("missing --state"))?
            .into(),
        notify: string(values.remove("--notify")).ok_or_else(|| WATCH.error("missing --notify"))?,
        max_age,
        repeat,
        now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn keygen_abbreviations_repeats_and_choices() {
        let args = keygen(&argv(&[
            "--na",
            "first",
            "--name=last",
            "--l",
            "agent",
            "--ho",
            "",
        ]))
        .ok()
        .unwrap();
        assert_eq!(args.name, "last");
        assert_eq!(args.level, "agent");
        assert_eq!(args.home.as_deref(), Some(""));
        let exit = keygen(&argv(&["--name=a", "--level=no"])).err().unwrap();
        assert!(
            exit.stderr.ends_with(
                "argument --level: invalid choice: 'no' (choose from 'host', 'agent')\n"
            )
        );
    }

    #[test]
    fn watch_python_numbers_and_repeats() {
        let args = log_watch(&argv(&[
            "--rem",
            "url",
            "--st",
            "dir",
            "--not",
            "[]",
            "--max",
            "  +٣_٦٠  ",
            "--rep=-2",
            "--now=NaN",
            "--now=１_２.５",
        ]))
        .ok()
        .unwrap();
        assert_eq!(args.max_age, 360);
        assert_eq!(args.repeat, -2);
        assert_eq!(args.now, Some(12.5));
        let exit = log_watch(&argv(&["--now=wrong"])).err().unwrap();
        assert!(
            exit.stderr
                .ends_with("argument --now: invalid float value: 'wrong'\n")
        );
    }

    #[test]
    fn required_errors_and_help_order() {
        let exit = keygen(&[]).err().unwrap();
        assert!(
            exit.stderr
                .starts_with("usage: evidence-keygen [-h] --name NAME [--level {host,agent}]")
        );
        assert!(
            exit.stderr
                .ends_with("the following arguments are required: --name\n")
        );
        let exit = log_watch(&[]).err().unwrap();
        assert!(
            exit.stderr
                .ends_with("the following arguments are required: --remote, --state, --notify\n")
        );
        let exit = log_watch(&argv(&["--unknown", "--help"])).err().unwrap();
        assert_eq!(exit.code, 0);
        assert!(exit.stderr.is_empty());
        assert!(exit.stdout.contains("--remote REMOTE --state STATE"));
        assert!(exit.stdout.contains("--notify NOTIFY"));
        let exit = keygen(&argv(&["--", "--help"])).err().unwrap();
        assert_eq!(exit.code, 2);
        assert!(exit.stdout.is_empty());
    }
}
