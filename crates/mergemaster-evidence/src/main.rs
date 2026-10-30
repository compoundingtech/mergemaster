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
    /// Decide whether BASE-authorized evidence satisfies an exact HEAD lane.
    Gate(mergemaster_evidence::gate::Args),
    #[command(hide = true)]
    GateVerifyRecord(mergemaster_evidence::gate::VerifyArgs),
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Evidence(args) => mergemaster_evidence::evidence::cli::run(args),
        Command::Gate(args) => mergemaster_evidence::gate::run(args),
        Command::GateVerifyRecord(args) => mergemaster_evidence::gate::verify_worker(args),
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
