//! Original main's ordinary operation, entirely inside signer finally ownership.
use super::{
    argparse_parse::ParsedArguments,
    candidates::{LaneOnce, Levels},
    cli_dispatch::{check, path, with_signers},
    cli_options::Options,
    cli_verified::Outcome,
    configured::{self, Settings},
    judgment::{BindingPath, LaneDefinition, Provider},
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::PolicyError;
use std::path::Path;

pub(super) fn policy_error(e: super::Failure) -> PolicyError {
    PolicyError {
        resource: None,
        origin: e.origin,
        reason: e.reason,
        detail: e.detail,
    }
}
struct Source<'a> {
    git: configured::CliGitProvider<'a>,
    args: &'a ParsedArguments<'a>,
    lane: Option<LaneDefinition>,
}
impl Provider for Source<'_> {
    fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
        if let Some(base) = self.args.value("--policy-from").filter(|v| !v.equals("")) {
            let text = super::cli_config::lanes(self.git.repo, base)?;
            self.lane = super::cli_lane_for::lane_for(
                self.git.repo,
                self.git.tree.into(),
                Some((&text, base)),
                check(self.args).text(),
                self.args.value("--lane-base"),
            )?;
        }
        Ok(self.lane.as_ref())
    }
    fn blob_sha256(&mut self, path: BindingPath<'_>) -> Result<Option<String>, PolicyError> {
        self.git.blob_sha256(path)
    }
}
pub fn verify<T>(
    repo: &Path,
    tree: &str,
    args: &ParsedArguments<'_>,
    options: Options,
    emit: impl FnOnce(Outcome) -> T,
) -> Result<T, PolicyError> {
    with_signers(repo, args, |keys| {
        let base = args.value("--policy-from").filter(|v| !v.equals(""));
        let rules = base
            .map(|base| {
                super::policy_loader::load(repo, base, check(args))?
                    .into_rules(args.value("--repository").unwrap_or(TextRef::Str("")))
            })
            .transpose()?;
        let from = args.value("--lanes-from").filter(|v| !v.equals(""));
        let lanes = from
            .map(|base| super::cli_config::lanes(repo, base))
            .transpose()?;
        let mut run_inputs =
            super::run_inputs::RunInputs::parse(args.appended("--run-input").iter().copied())?;
        let values = super::base_input_values::base_input_values(
            repo,
            base.unwrap_or(TextRef::Str("")),
            rules.as_ref(),
        )?;
        run_inputs.merge_base(&values);
        let explicit = args
            .value("--log-keys")
            .filter(|v| !v.equals(""))
            .map(path)
            .transpose()?;
        let log_keys =
            super::cli_keys::log_keys(repo, explicit.as_deref(), args.value("--log-keys-from"))?;
        let parsed = args
            .value("--crate-key")
            .map(super::crate_key_argument::parse)
            .transpose()
            .map_err(policy_error)?
            .flatten();
        let binding = parsed.as_ref().map(|p| p.binding(repo, base)).transpose()?;
        let lane = super::cli_lane_for::lane_for(
            repo,
            tree.into(),
            lanes.as_deref().zip(from),
            check(args).text(),
            args.value("--lane-base"),
        )?;
        let bindings = options
            .bindings
            .into_iter()
            .map(|(key, points)| Ok((key, path(TextRef::Points(&points))?.into_owned())))
            .collect::<Result<Vec<_>, PolicyError>>()?;
        let unconfigured = super::judgment::Unconfigured {
            routing: super::routing::Unconfigured {
                kinds: &options.kinds,
                trust_levels: options.trust.as_deref(),
                runner_prefix: options.runner.as_deref(),
            },
            command: options.command.as_deref(),
            max_age: options.age,
            bindings: &bindings,
        };
        let settings = rules
            .as_ref()
            .map_or(Settings::Unconfigured(&unconfigured), Settings::Policy);
        let prefer: Vec<_> = options
            .prefer
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|p| TextRef::Points(p))
            .collect();
        let q = super::prefix::Request {
            repo,
            tree,
            check: check(args),
            keys,
            inputs: rules.as_ref().and_then(|r| r.header.inputs.as_deref()),
            crate_key: binding,
        };
        let mut judgment = super::ordering::CheckJudgment {
            clock: &mut super::inputs::SystemClock,
            run_inputs: &run_inputs,
            lane: lane.as_ref(),
            provider: LaneOnce::new(Source {
                git: configured::CliGitProvider { repo, tree },
                args,
                lane: None,
            }),
        };
        let log = log_keys.as_ref().map(|keys| super::log_view::Request {
            keys: keys.path(),
            now_micros: None,
        });
        let outcome = if args.value("--members").is_some() {
            Outcome::Members(super::members::verified_with_transport(
                &q,
                base,
                settings,
                &mut judgment,
                Levels::Policy(&prefer),
                log,
                configured::Transport::Cli,
            ))
        } else {
            Outcome::Single(configured::verify_with_transport(
                &q,
                settings,
                &mut judgment,
                Levels::Policy(&prefer),
                log,
                configured::Transport::Cli,
            ))
        };
        Ok(emit(outcome))
    })?
}
