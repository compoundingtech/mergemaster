use super::argparse_compat::{self as ap, Action, DefaultValue as D, OptionSpec, Parser, Value};
use std::path::PathBuf;

pub(super) struct Args {
    pub repository: String,
    pub run: Option<i64>,
    pub attempt: Option<i64>,
    pub limit: i64,
    pub artifact: Option<i64>,
    pub observer: String,
    pub checkout: PathBuf,
    pub keys: Option<String>,
    pub keys_from: String,
    pub verifier: String,
    pub state_dir: PathBuf,
    pub scratch: Option<PathBuf>,
    pub remote: Option<String>,
}
const fn option(
    long: &'static str,
    metavar: Option<&'static str>,
    action: Action,
    default: D,
    help: &'static str,
) -> OptionSpec {
    OptionSpec {
        long,
        short: None,
        metavar,
        action,
        default,
        help,
        choices: &[],
        hidden: false,
    }
}
const INT: Action = Action::Convert {
    name: "int",
    parse: ap::integer,
};
const OPTIONS: &[OptionSpec] = &[
    OptionSpec {
        short: Some("-h"),
        ..option(
            "--help",
            None,
            Action::Help,
            D::None,
            "show this help message and exit",
        )
    },
    option(
        "--repository",
        Some("REPOSITORY"),
        Action::Store,
        D::None,
        "",
    ),
    option(
        "--run",
        Some("RUN"),
        INT,
        D::None,
        "observe this one finished Workspace CI run",
    ),
    option(
        "--attempt",
        Some("ATTEMPT"),
        INT,
        D::None,
        "default: the run's latest attempt",
    ),
    option(
        "--poll",
        None,
        Action::Flag,
        D::Bool(false),
        "observe every recently finished merge-group Workspace CI run not yet done (for a timer)",
    ),
    option(
        "--limit",
        Some("LIMIT"),
        INT,
        D::Int(20),
        "with --poll: how many recent runs to look at",
    ),
    option(
        "--artifact",
        Some("ARTIFACT"),
        INT,
        D::None,
        "default: look up this attempt's source artifact",
    ),
    option(
        "--observer",
        Some("OBSERVER"),
        Action::Store,
        D::None,
        "JSON argument vector of the observer (default: $EVIDENCE_OBSERVER, else sekrets)",
    ),
    option(
        "--checkout",
        Some("CHECKOUT"),
        Action::Store,
        D::String("."),
        "a checkout of the default branch holding .st/evidence-keys",
    ),
    option(
        "--keys",
        Some("KEYS"),
        Action::Store,
        D::None,
        "allowed-signers file (default: --keys-from in --checkout)",
    ),
    option(
        "--keys-from",
        Some("KEYS_FROM"),
        Action::Store,
        D::String("HEAD"),
        "commit in --checkout holding .st/evidence-keys",
    ),
    option(
        "--verifier",
        Some("VERIFIER"),
        Action::Store,
        D::None,
        "pinned mergemaster binary",
    ),
    option(
        "--state-dir",
        Some("STATE_DIR"),
        Action::Store,
        D::None,
        "scratch repository and the list of runs already observed",
    ),
    option(
        "--scratch",
        Some("SCRATCH"),
        Action::Store,
        D::None,
        "scratch repository (default: STATE_DIR/scratch.git)",
    ),
    option(
        "--remote",
        Some("REMOTE"),
        Action::Store,
        D::None,
        "push the verified refs here (default: none)",
    ),
    option(
        "--publish",
        None,
        Action::Flag,
        D::Bool(false),
        "push to https://github.com/REPOSITORY.git",
    ),
];
const DESCRIPTION: &str = "Turn a finished Workspace CI run into signed evidence notes, then publish them.

Runs in the `Evidence observe` workflow on the signing runners, never on a pull request's
code. It does not run any check: it asks the protected observer (`st3 evidence observe-ci`,
behind a sekrets grant) to record what the run already did, imports the returned object
pack into a scratch repository, verifies every full-trust record with the pinned Rust verifier
against the accepted key list, and only then creates and pushes refs/tags/evidence/<tree>/<id> and, while gates on
older bases read only notes, refs/notes/evidence/<tree>/<id> naming the same record.

  exit 0  every record was imported (full records verified; degraded ones labelled as such),
          or the run was cancelled/skipped and has nothing to attest
  exit 1  a produced record did not verify, or the observer, import or push failed
  exit 2  usage error";
const PARSER: Parser = Parser {
    program: "ci-evidence-observe",
    description: "Turn a finished Workspace CI run into signed evidence notes, then publish them.",
    options: OPTIONS,
};
fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}
pub(super) fn parse(argv: &[String]) -> Result<Args, ap::Exit> {
    let parsed = PARSER.parse(argv).map_err(|mut exit| {
        if exit.code == 0
            && let Some((_, options)) = exit.stdout.split_once("\noptions:\n")
        {
            exit.stdout = format!("{}\n{DESCRIPTION}\n\noptions:\n{options}", PARSER.usage());
        }
        exit
    })?;
    let text = |key| match parsed.values.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    let int = |key| match parsed.values.get(key) {
        Some(Value::Int(n)) => Some(*n),
        _ => None,
    };
    let flag = |key| matches!(parsed.values.get(key), Some(Value::Bool(true)));
    let run = int("--run").filter(|n| *n != 0);
    if run.is_some() == flag("--poll") {
        return Err(PARSER.error("give exactly one of --run RUN or --poll"));
    }
    let repository = text("--repository")
        .or_else(|| env("GITHUB_REPOSITORY"))
        .unwrap_or_else(|| "compoundingtech/fractal".into());
    let remote = text("--remote")
        .filter(|s| !s.is_empty())
        .or_else(|| flag("--publish").then(|| format!("https://github.com/{repository}.git")));
    let state_dir = text("--state-dir")
        .or_else(|| env("EVIDENCE_OBSERVE_STATE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let root = env("XDG_STATE_HOME").map(PathBuf::from).unwrap_or_else(|| {
                PathBuf::from(env("HOME").unwrap_or_else(|| ".".into())).join(".local/state")
            });
            root.join("evidence-observe")
        });
    Ok(Args {
        repository,
        run,
        attempt: int("--attempt").filter(|n| *n != 0),
        limit: int("--limit").unwrap_or(20),
        artifact: int("--artifact").filter(|n| *n != 0),
        observer: text("--observer")
            .or_else(|| env("EVIDENCE_OBSERVER"))
            .unwrap_or_else(|| r#"["st","sekrets","--","st3","evidence","observe-ci"]"#.into()),
        checkout: PathBuf::from(text("--checkout").unwrap_or_else(|| ".".into())),
        keys: text("--keys").filter(|s| !s.is_empty()),
        keys_from: text("--keys-from").unwrap_or_else(|| "HEAD".into()),
        verifier: text("--verifier")
            .or_else(|| std::env::var("MERGEMASTER_BIN").ok())
            .unwrap_or_else(|| "mergemaster".into()),
        state_dir,
        scratch: text("--scratch")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
        remote,
    })
}
