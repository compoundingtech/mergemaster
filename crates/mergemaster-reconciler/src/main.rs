#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use mergemaster_reconciler::{
    Args, BootstrapConfig, BootstrapError, CONSUMERS, RealCapabilities, Reconciler, load_consumers,
};

fn run(args: Args) -> Result<i32> {
    let consumers = load_consumers(CONSUMERS, args.repo.as_deref(), args.pr)?;
    let environ: std::collections::BTreeMap<String, String> = std::env::vars().collect();
    let config = BootstrapConfig::new(
        environ.get("MERGEMASTER_APP_ID").map_or("", String::as_str),
        environ
            .get("MERGEMASTER_APP_PRIVATE_KEY")
            .map_or("", String::as_str),
        environ.get("GH_TOKEN").map_or("", String::as_str),
    )?;
    let workspace = environ.get("RUNNER_TEMP").map_or_else(
        || std::env::current_dir().map(|directory| directory.join("tmp/evidence-reconcile")),
        |path| Ok(std::path::PathBuf::from(path)),
    )?;
    let workspace = if workspace.is_absolute() {
        workspace
    } else {
        std::env::current_dir()?.join(workspace)
    };
    let mut reconciler = Reconciler::new(
        config,
        RealCapabilities::new()?,
        environ,
        workspace,
    )?;
    Ok(reconciler.run_all(&consumers, args.pr))
}

fn main() {
    let code = match run(Args::parse()) {
        Ok(code) => code,
        Err(error) => {
            if let Some(error) = error.downcast_ref::<BootstrapError>() {
                eprintln!("Evidence reconciliation configuration failed: {error}");
            } else {
                eprintln!(
                    "Evidence reconciliation failed; no credentials or response bodies logged."
                );
            }
            1
        }
    };
    std::process::exit(code);
}
