//! Library-only main preflight, after argparse and before tree/policy/key reads.
//! No terminal sink or production policy caller is installed here.
use super::{
    statement_document::{Document, Node},
    value_inputs::TextRef,
};

#[derive(Default)]
pub struct Arguments<'a> {
    pub require_all: bool,
    pub project: bool,
    pub members: bool,
    pub check: Option<TextRef<'a>>,
    pub command: Option<TextRef<'a>>,
    pub kinds: Option<&'a str>,
    pub runner_prefix: Option<TextRef<'a>>,
    pub trust_levels: Option<&'a str>,
    /// Presence and positivity of argparse's unbounded integer, without narrowing.
    pub max_age_positive: Option<bool>,
    pub paths: Option<TextRef<'a>>,
    pub bind_input: &'a [TextRef<'a>],
    pub policy_from: Option<TextRef<'a>>,
    pub repository: Option<TextRef<'a>>,
    pub keys: Option<TextRef<'a>>,
    pub keys_from: Option<TextRef<'a>>,
    pub lane_base: Option<TextRef<'a>>,
    pub lanes_from: Option<TextRef<'a>>,
    pub prefer_levels: Option<&'a str>,
}

/// A preflight stderr diagnostic has exit status 2, not a verifier Failure.
/// These fixed messages contain no echoed values or control characters (#245).
pub fn validate(args: &Arguments<'_>) -> Result<(), &'static str> {
    let loose = args.command.is_some()
        || args.kinds.is_some()
        || args.runner_prefix.is_some()
        || args.trust_levels.is_some()
        || args.max_age_positive.is_some()
        || !args.bind_input.is_empty();
    if args.require_all {
        if args.policy_from.is_none()
            || args.repository.is_none()
            || loose
            || args.check.is_some()
            || args.paths.is_some()
            || args.project
        {
            return Err(
                "--require-all needs --policy-from and --repository and replaces --check, --project, --paths, --command, --kinds, --runner-prefix, --trust-levels, --max-age and --bind-input",
            );
        }
    } else if args.check.is_none() {
        return Err("--check is required");
    }
    let truthy = |text: Option<TextRef<'_>>| text.is_some_and(|s| s.points().next().is_some());
    if !args.project && !(truthy(args.keys) || truthy(args.keys_from)) {
        return Err("one of --keys or --keys-from is required");
    }
    if args.paths.is_some() && !args.project {
        return Err("--paths is only used with --project");
    }
    if let Some(command) = args.command {
        let doc = match command {
            TextRef::Str(s) => Document::from_text(s),
            TextRef::Points(p) => Document::from_points(p.to_vec()),
        };
        if !doc.is_ok_and(|doc| matches!(doc.root(), Node::Array(items) if !items.is_empty() && items.iter().all(|id| matches!(doc.node(*id), Node::String(_))))) {
            return Err("--command must be a JSON array of strings");
        }
    }
    if let Some(kinds) = args.kinds {
        let mut kinds = kinds.split(',').filter(|s| !s.is_empty()).peekable();
        if kinds.peek().is_none()
            || kinds.any(|k| !["nix", "wrapper", "sekrets", "observed"].contains(&k))
        {
            return Err("--kinds must be a comma-separated subset of nix,wrapper,sekrets,observed");
        }
    }
    if args.policy_from.is_some() {
        if args.repository.is_none() || loose {
            return Err(
                "--policy-from needs --repository and replaces --command, --kinds, --runner-prefix, --trust-levels, --max-age and --bind-input",
            );
        }
    } else if args.repository.is_some() {
        return Err("--repository is only used with --policy-from");
    }
    if args.lane_base.is_some() && !(truthy(args.lanes_from) || truthy(args.policy_from)) {
        return Err("--lane-base is only used with --lanes-from or --policy-from");
    }
    if args.max_age_positive == Some(false) {
        return Err("--max-age must be a positive number of seconds");
    }
    let empty_levels = |s: &str| !s.split(',').any(|s| !s.is_empty());
    if args
        .prefer_levels
        .is_some_and(|s| empty_levels(s) || args.members || args.require_all)
    {
        return Err(
            "--prefer-levels must name at least one level, and is not used with --members or --require-all",
        );
    }
    if args.trust_levels.is_some_and(empty_levels) {
        return Err("--trust-levels must name at least one level");
    }
    for item in args.bind_input {
        let mut points = item.points();
        let mut key = false;
        loop {
            match points.next() {
                Some(61) => break,
                Some(_) => key = true,
                None => return Err("--bind-input must be KEY=PATH"),
            }
        }
        if !key || points.next().is_none() {
            return Err("--bind-input must be KEY=PATH");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "cli_validation_tests.rs"]
mod tests;
