//! Run a BASE-declared lane once, retaining its complete output and publishing its signed note.
use std::{
    fs, io::{Read, Seek, SeekFrom, Write}, path::{Path, PathBuf},
    process::{Command, Stdio},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Args;
use sha2::{Digest, Sha256};
use crate::gate::{config, git};
use super::signing::{Request, Response, measure_toolchain};

#[derive(Debug, Args)]
pub struct WrapArgs {
    #[arg(long)]
    pub check: String,
    #[arg(long)]
    pub base: String,
    /// Explicit JSON argv; no repository-provided signer or secret-manager fallback.
    #[arg(long)]
    pub signer: String,
    /// Account-local measurement and signing configuration, outside the checkout.
    #[arg(long)]
    pub config: PathBuf,
    /// Reuse a derivation realization; never assert a fresh test execution.
    #[arg(long)]
    pub reuse: bool,
    #[arg(last = true)]
    pub command: Vec<String>,
}

fn clean(repo: &Path, head: &str) -> Result<()> {
    ensure!(git::text(repo, &["rev-parse", "HEAD"])? == head, "HEAD changed during evidence collection");
    ensure!(super::signing::clean(repo)?,
        "evidence requires exact committed workspace bytes and no hidden, untracked or ignored inputs");
    Ok(())
}

fn input_git(repo: &Path, args: &[&str], input: &[u8]) -> Result<String> {
    let mut child = git::command(repo).args(args).stdin(Stdio::piped())
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().context("starting Git output storage")?;
    child.stdin.take().context("missing Git input")?.write_all(input)?;
    let output = child.wait_with_output()?;
    ensure!(output.status.success(), "Git output storage failed");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn execute(repo: &Path, argv: &[String], output: &fs::File, git: Option<&Path>) -> Result<std::process::ExitStatus> {
    let (mut launch, _home) = if let Some(git) = git {
        let (launch, home) = super::derivation::isolated(Path::new(&argv[0]), git)?;
        (launch, Some(home))
    } else { (Command::new(&argv[0]), None) };
    launch.args(&argv[1..]).current_dir(repo)
        .stdout(Stdio::from(output.try_clone()?)).stderr(Stdio::from(output.try_clone()?))
        .status().context("running evidence lane")
}

pub fn run_wrap(args: &WrapArgs) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    let repo = fs::canonicalize(git::text(&cwd, &["rev-parse", "--show-toplevel"])?)?;
    // Relative argv has the same meaning as the BASE lane only at the repository root.
    ensure!(fs::canonicalize(&cwd)? == repo, "run evidence wrap from the repository root");
    let head = git::text(&repo, &["rev-parse", "HEAD"])?;
    let tree = git::text(&repo, &["rev-parse", "HEAD^{tree}"])?;
    let policy = config::load(&repo, &args.base)?;
    let lane = policy.policy.lanes.get(&args.check).context("unknown BASE lane")?;
    ensure!(lane.nix_check.is_some() || (!args.reuse && args.command == lane.argv), "command must exactly equal BASE lane argv");
    let signer: Vec<String> = serde_json::from_str(&args.signer).context("--signer must be a JSON argv array")?;
    ensure!(!signer.is_empty() && !signer[0].is_empty() && signer.iter().all(|arg| !arg.contains('\0')), "invalid signer argv");
    clean(&repo, &head)?;
    let mut inputs = config::expected_inputs(&repo, &head, &args.check, lane, &policy.environment, &policy.environment_bytes)?;
    inputs.extend(measure_toolchain(&repo, &policy.environment, &args.config, &args.command, lane.nix_check.is_none())?);
    let nix_check = super::signing::derivation(&repo, &head, lane, &policy.environment, &args.config)?;
    let mut execution = if args.reuse { "reused" } else { "rebuild" };
    let mut command_mode = execution;
    let mut command = if let Some((derivation, _, _)) = &nix_check {
        let command = super::derivation::argv(&lane.argv[0], &derivation.path, execution)?;
        ensure!(args.command.is_empty() || args.command == command, "command differs from normalized derivation argv");
        command
    } else { args.command.clone() };
    for (key, value) in [("workspace_clean", "true"), ("untracked_files", "false"), ("attempt", "1")] {
        inputs.insert(key.into(), value.into());
    }
    inputs.insert("wrapper_sha256".into(), hex::encode(Sha256::digest(fs::read(std::env::current_exe()?)?)));

    // Both child descriptors share a single open file description, preserving combined bytes
    // without pipe deadlocks or lossy UTF-8 conversion. The command keeps the caller's env.
    let mut output_file = tempfile::tempfile()?;
    let git_tool = nix_check.as_ref().map(|(_, _, git)| git.as_path());
    let preparation = if let Some((derivation, nix, git)) = &nix_check {
        if !args.reuse && !derivation.valid(nix, git)? {
            let argv = super::derivation::argv(&lane.argv[0], &derivation.path, "reused")?;
            let status = execute(&repo, &argv, &output_file, git_tool)?;
            if status.success() { None } else {
                command = argv;
                command_mode = "reused";
                Some(status)
            }
        } else { None }
    } else { None };
    let status = if let Some(status) = preparation { status } else {
        execute(&repo, &command, &output_file, git_tool)?
    };
    if !status.success() && nix_check.is_some() { execution = "failed"; }
    output_file.seek(SeekFrom::Start(0))?;
    let mut output = Vec::new();
    output_file.read_to_end(&mut output)?;
    if nix_check.is_some() { super::derivation::refuse_ignored(&output)?; }
    {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&output)?;
        stdout.flush()?;
    }
    let output_sha256 = hex::encode(Sha256::digest(&output));
    let blob = input_git(&repo, &["hash-object", "-w", "--stdin"], &output)?;
    git::git(&repo, &["update-ref", &format!("refs/evidence-output/{output_sha256}"), &blob])?;
    clean(&repo, &head)?;
    let closures = measure_toolchain(&repo, &policy.environment, &args.config, &command, lane.nix_check.is_none())?;
    ensure!(closures.iter().all(|(key, value)| inputs.get(key) == Some(value)), "Nix closure changed during execution");
    let after = config::expected_inputs(&repo, &head, &args.check, lane, &policy.environment, &policy.environment_bytes)?;
    ensure!(after.iter().all(|(key, value)| inputs.get(key) == Some(value)), "lane inputs changed during execution");
    if let Some((derivation, nix, _)) = &nix_check { inputs.extend(derivation.claims(nix, execution, command_mode)?); }
    #[cfg(unix)]
    let exit_code = {
        use std::os::unix::process::ExitStatusExt;
        status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
    };
    #[cfg(not(unix))]
    let exit_code = status.code().unwrap_or(1);
    let request = Request { version: 1, repo: repo.clone(), base: args.base.clone(), head: head.clone(),
        check: args.check.clone(), command, exit_code,
        output: STANDARD.encode(output), inputs };
    let mut launch = Command::new(&signer[0]);
    launch.args(&signer[1..]).current_dir(&repo);
    git::sanitize(&mut launch);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("PYTHON") || matches!(name.as_ref(), "GLIBC_TUNABLES" | "GCONV_PATH" | "NLSPATH") {
            launch.env_remove(key);
        }
    }
    let mut child = launch.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().context("starting explicit evidence signer")?;
    child.stdin.take().context("missing signer input")?.write_all(&serde_json::to_vec(&request)?)?;
    let signed = child.wait_with_output()?;
    ensure!(signed.status.success(), "evidence signer refused: {}", String::from_utf8_lossy(&signed.stderr));
    let response: Response = serde_json::from_slice(&signed.stdout).context("invalid signer response")?;
    ensure!(config::full_commit(&response.record) && response.note_ref == format!("refs/notes/evidence/{tree}/{}", response.record),
        "signer returned an invalid evidence reference");
    let mut bundle = tempfile::NamedTempFile::new()?;
    bundle.write_all(&STANDARD.decode(&response.bundle).context("invalid signer bundle encoding")?)?;
    let bundle_path = bundle.path().to_str().context("bundle path is not UTF-8")?;
    git::git(&repo, &["bundle", "unbundle", bundle_path])?;
    ensure!(git::text(&repo, &["cat-file", "-t", &response.record])? == "commit", "signer record is not a commit");
    clean(&repo, &head)?;
    git::git(&repo, &["update-ref", &response.note_ref, &response.record])?;
    // Publication deliberately targets origin, never an argv/HEAD-provided remote.
    // Local file transport supports bare integration fixtures; SSH remains normal account auth.
    let pushed = git::command(&repo).env("GIT_ALLOW_PROTOCOL", "file:ssh:https")
        .args(["-c", "protocol.file.allow=always", "-c", "protocol.ssh.allow=always", "-c", "protocol.https.allow=always",
            "-c", "core.sshCommand=ssh", "push", "--", "origin", &format!("{}:{}", response.note_ref, response.note_ref)])
        .output().context("publishing evidence to origin")?;
    ensure!(pushed.status.success(), "evidence publication to origin failed");
    eprintln!("evidence record {}", response.record);
    Ok(exit_code)
}
