//! Complete fixed argparse declarations from pinned evidence-verify main.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Store,
    Append,
    Flag,
    Help,
    Integer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultValue {
    None,
    Text(&'static str),
    False,
    EmptyList,
}
#[derive(Debug)]
pub struct OptionSpec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub dest: &'static str,
    pub metavar: Option<&'static str>,
    pub help: &'static str,
    pub action: Action,
    pub default: DefaultValue,
    pub nargs: Option<u8>,
    pub required: bool,
    pub group: Option<u8>,
}
pub const DESCRIPTION: &str =
    "Does a trusted, signed evidence note exist for this tree and this check?";
/// Requiredness of target, signer-source and shadow-log-source groups.
pub const GROUPS: &[bool] = &[true, false, false];
macro_rules! option {
    ($name:literal; $aliases:expr; $dest:literal; $metavar:expr; $help:literal; $action:ident; $default:expr; $group:expr) => {
        OptionSpec {
            name: $name,
            aliases: $aliases,
            dest: $dest,
            metavar: $metavar,
            help: $help,
            action: Action::$action,
            default: $default,
            nargs: match Action::$action {
                Action::Flag | Action::Help => Some(0),
                _ => None,
            },
            required: false,
            group: $group,
        }
    };
}
pub const OPTIONS: &[OptionSpec] = &[
    option!("--help"; &["-h", "--help"]; "help"; None; "show this help message and exit"; Help; DefaultValue::Text("==SUPPRESS=="); None),
    option!("--repo"; &["--repo"]; "repo"; Some("REPO"); ""; Store; DefaultValue::Text("."); None),
    option!("--tree"; &["--tree"]; "tree"; Some("TREE"); ""; Store; DefaultValue::None; Some(0)),
    option!("--revision"; &["--revision"]; "revision"; Some("REVISION"); ""; Store; DefaultValue::None; Some(0)),
    option!("--check"; &["--check"]; "check"; Some("CHECK"); ""; Store; DefaultValue::None; None),
    option!("--lanes-from"; &["--lanes-from"]; "lanes_from"; Some("COMMIT"); "also hold the check to its lane definition in .st/required-lanes.json at this accepted base: the lane's script blobs must be identical in the verified tree and the base (definition_changed) and the note must carry the base's digest (wrong_definition)"; Store; DefaultValue::None; None),
    option!("--lane-base"; &["--lane-base"]; "lane_base"; Some("COMMIT"); "hold the lane to its definition at this commit (a pull request's branch point, an ancestor of the base with the same lane file) instead of at the base: a tree that only lags main is not a lane edit"; Store; DefaultValue::None; None),
    option!("--require-all"; &["--require-all"]; "require_all"; None; "judge every check whose policy says `require` (needs --policy-from, --repository and keys); exit 1 only when a check in mode reject is not satisfied, exit 2 (decision error) when it could not decide"; Flag; DefaultValue::False; None),
    option!("--project"; &["--project"]; "project"; None; "print the input key of the tree for the check's declared paths and exit (needs no keys)"; Flag; DefaultValue::False; None),
    option!("--paths"; &["--paths"]; "paths"; Some("PATH[,PATH...]"); "with --project: declared paths instead of the policy's"; Store; DefaultValue::None; None),
    option!("--members"; &["--members"]; "members"; None; "a per-crate check: satisfied only when every workspace member of the tree has a satisfying note for its own key (needs --policy-from; accepts --lane-base; reads manifests without fetching; the keys come from scripts/rust-test-keys next to this script and .st/rust-test-inputs.json at the base). With --project: print the member keys and stop"; Flag; DefaultValue::False; None),
    option!("--crate-key"; &["--crate-key"]; "crate_key"; Some("CRATE=KEY"); "a per-crate check (docs/per-crate-test-signing.md): only records that signed this crate and this input key count, whichever tree they are for (scripts/rust-test-keys prints the keys)"; Store; DefaultValue::None; None),
    option!("--keys"; &["--keys"]; "keys"; Some("KEYS"); "allowed-signers file"; Store; DefaultValue::None; Some(1)),
    option!("--keys-from"; &["--keys-from"]; "keys_from"; Some("KEYS_FROM"); "read .st/evidence-keys from this commit (the accepted base)"; Store; DefaultValue::None; Some(1)),
    option!("--log-keys"; &["--log-keys"]; "log_keys"; Some("LOG_KEYS"); "allowed-signers file of the evidence log key: adds the log's shadow view (refs/evidence-log/main)"; Store; DefaultValue::None; Some(2)),
    option!("--log-keys-from"; &["--log-keys-from"]; "log_keys_from"; Some("COMMIT"); "read .st/evidence-log-key from this commit (none there: no log view)"; Store; DefaultValue::None; Some(2)),
    option!("--command"; &["--command"]; "command"; Some("COMMAND"); "JSON argument vector the record must have run"; Store; DefaultValue::None; None),
    option!("--run-input"; &["--run-input"]; "run_input"; Some("KEY=VALUE"); "this run's own value of an input the policy's input_order compares a record's value with (repeatable)"; Append; DefaultValue::EmptyList; None),
    option!("--kinds"; &["--kinds"]; "kinds"; Some("KINDS"); "comma-separated record kinds this check accepts (default: nix,wrapper,sekrets,observed)"; Store; DefaultValue::None; None),
    option!("--policy-from"; &["--policy-from"]; "policy_from"; Some("COMMIT"); "apply the skip policy .st/evidence-skip-policy.json read from this accepted base (needs --repository)"; Store; DefaultValue::None; None),
    option!("--repository"; &["--repository"]; "repository"; Some("REPOSITORY"); "OWNER/NAME, filled into the skip policy placeholders"; Store; DefaultValue::None; None),
    option!("--max-age"; &["--max-age"]; "max_age"; Some("SECONDS"); "reject a record observed longer ago than this, or claiming a future time"; Integer; DefaultValue::None; None),
    option!("--runner-prefix"; &["--runner-prefix"]; "runner_prefix"; Some("RUNNER_PREFIX"); "the record runner must start with this (e.g. github:org/repo/)"; Store; DefaultValue::None; None),
    option!("--trust-levels"; &["--trust-levels"]; "trust_levels"; Some("TRUST_LEVELS"); "comma-separated signer trust levels this check accepts"; Store; DefaultValue::None; None),
    option!("--prefer-levels"; &["--prefer-levels"]; "prefer_levels"; Some("LEVELS"); "comma-separated signer levels whose newest passing record decides instead of a newer pass from another level, unless a failing record is dated after it; every other rule still applies"; Store; DefaultValue::None; None),
    option!("--bind-input"; &["--bind-input"]; "bind_input"; Some("KEY=PATH"); "require the record's input KEY to equal the sha256 of PATH in the verified tree"; Append; DefaultValue::EmptyList; None),
];
#[cfg(test)]
#[path = "argparse_options_tests.rs"]
mod tests;
