use clap::{Parser, Subcommand};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "mergemaster", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Import, inspect, and verify signed gate observations stored in Git notes.
    Evidence(mergemaster_evidence::evidence::cli::EvidenceArgs),
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Evidence(args) => mergemaster_evidence::evidence::cli::run(args),
    };
    let code = match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    };
    mergemaster_evidence::cli_output::finish(code)
}
