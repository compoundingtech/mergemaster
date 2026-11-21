#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
use clap::{Parser, Subcommand};
use std::{io::Write, process::ExitCode};

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
    /// Report newer upstream commits touching extracted origin paths.
    ParityDrift(mergemaster_evidence::parity_drift::ParityDriftArgs),
    /// Measure and canonicalize executable producer manifests.
    Producers(mergemaster_evidence::producers::Args),
    #[command(hide = true)]
    GateVerifyRecord(mergemaster_evidence::gate::VerifyArgs),
}

fn main() -> ExitCode {
    let mut raw = std::env::args_os().skip(1);
    let command = raw.next();
    let helper = command
        .as_ref()
        .is_some_and(|v| v == "legacy-evidence-verify-helper");
    let result = match command.as_ref() {
        Some(v) if v == "legacy-evidence-verify" => {
            Some(mergemaster_evidence::evidence::legacy_verify::cli_dispatch::run(raw))
        }
        Some(v) if v == "legacy-rust-test-keys" => {
            Some(mergemaster_evidence::evidence::legacy_verify::rust_test_keys::run(raw))
        }
        Some(v) if v == "legacy-evidence-verify-helper" => Some(
            mergemaster_evidence::evidence::legacy_verify::cli_helper::run(
                raw,
                &mut std::io::stdin().lock(),
            ),
        ),
        _ => None,
    };
    if let Some(result) = result {
        let result = result.and_then(|exit| {
            std::io::stdout().lock().write_all(exit.stdout.as_bytes())?;
            std::io::stderr().lock().write_all(exit.stderr.as_bytes())?;
            Ok(exit.code)
        });
        return mergemaster_evidence::cli_output::finish(ExitCode::from(match result {
            Ok(code) => code,
            Err(error) => {
                eprintln!("{error:#}");
                if helper { 3 } else { 1 }
            }
        }));
    }
    let result = match Cli::parse().command {
        Command::Evidence(args) => mergemaster_evidence::evidence::cli::run(args),
        Command::Gate(args) => mergemaster_evidence::gate::run(args),
        Command::Producers(args) => mergemaster_evidence::producers::run(args),
        Command::GateVerifyRecord(args) => mergemaster_evidence::gate::verify_worker(args),
        Command::ParityDrift(args) => {
            return mergemaster_evidence::cli_output::finish(ExitCode::from(
                match mergemaster_evidence::parity_drift::run(args) {
                    Ok(code) => code,
                    Err(error) => {
                        eprintln!("{error:#}");
                        1
                    }
                },
            ));
        }
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
