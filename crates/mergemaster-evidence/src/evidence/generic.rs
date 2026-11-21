//! Run a BASE-declared lane once, retaining its complete output and publishing its signed note.
use super::signing::{Request, Response, measure_toolchain};
use crate::gate::{config, git};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Args;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Temporary unavailability of the v2 wrapper's execution infrastructure.
#[derive(Debug)]
pub struct InfraUnavailable {
    pub class: InfraClass,
    pub detail: String,
}

#[derive(Clone, Copy, Debug)]
pub enum InfraClass {
    Interrupted,
    SignerUnavailable,
    PublishFailed,
}

impl InfraClass {
    pub const fn token(self) -> &'static str {
        match self {
            Self::Interrupted => "interrupted",
            Self::SignerUnavailable => "signer_unavailable",
            Self::PublishFailed => "publish_failed",
        }
    }
}

impl std::fmt::Display for InfraUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for InfraUnavailable {}

impl InfraUnavailable {
    fn new(class: InfraClass, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: detail.into(),
        }
    }
}

fn check_interruption(status: std::process::ExitStatus) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        // SIGPIPE is not external cancellation: a broken lane pipeline can be a defect.
        if let Some(signal @ (1 | 2 | 9 | 15)) = status.signal() {
            return Err(InfraUnavailable::new(
                InfraClass::Interrupted,
                format!("evidence lane interrupted by signal {signal}"),
            )
            .into());
        }
    }
    #[cfg(not(unix))]
    let _ = status;
    Ok(())
}

fn signer_io(error: std::io::Error) -> anyhow::Error {
    if matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof
    ) {
        InfraUnavailable::new(
            InfraClass::SignerUnavailable,
            format!("evidence signer pipe failed: {error}"),
        )
        .into()
    } else {
        error.into()
    }
}

#[derive(Debug, Args)]
pub struct WrapArgs {
    #[arg(long)]
    pub check: String,
    #[arg(long)]
    pub base: String,
    /// Optional signed repository identity, exactly owner/name.
    #[arg(long)]
    pub repository: Option<String>,
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

fn input_git(repo: &Path, args: &[&str], input: &[u8]) -> Result<String> {
    store_output(
        git::command(repo).args(args).stdin(Stdio::piped()),
        input,
        std::time::Duration::from_secs(600),
    )
}
fn store_output(
    command: &mut Command,
    input: &[u8],
    timeout: std::time::Duration,
) -> Result<String> {
    let output = git::deadline::GitChild::capture(command, Some(input), timeout)
        .context("starting Git output storage")?;
    ensure!(output.status.success(), "Git output storage failed");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
fn publish_output(command: &mut Command, timeout: std::time::Duration) -> Result<()> {
    let output = git::deadline::GitChild::capture(command, None, timeout).map_err(|error| {
        InfraUnavailable::new(
            InfraClass::PublishFailed,
            format!("publishing evidence to origin: {error:#}"),
        )
    })?;
    if !output.status.success() {
        return Err(InfraUnavailable::new(
            InfraClass::PublishFailed,
            format!(
                "evidence publication to origin failed: {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
        )
        .into());
    }
    Ok(())
}

/// Non-derivation launch. Only opted-in scripts and absolute Nix executables
/// supply a canonical bound path; all other commands retain normal PATH lookup.
fn direct(executable: Option<&Path>, argv: &[String]) -> Command {
    let Some(executable) = executable else {
        return Command::new(&argv[0]);
    };
    let mut command = Command::new(executable);
    #[cfg(unix)]
    std::os::unix::process::CommandExt::arg0(&mut command, &argv[0]);
    command
}

fn execute(
    repo: &Path,
    executable: Option<&Path>,
    argv: &[String],
    output: &fs::File,
    git: Option<&Path>,
) -> Result<std::process::ExitStatus> {
    let (mut launch, _home) = if let Some(git) = git {
        let (launch, home) = super::derivation::isolated(Path::new(&argv[0]), git)?;
        (launch, Some(home))
    } else {
        (direct(executable, argv), None)
    };
    launch
        .args(&argv[1..])
        .current_dir(repo)
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output.try_clone()?))
        .status()
        .context("running evidence lane")
}

pub fn run_wrap(args: &WrapArgs) -> Result<i32> {
    if let Some(repository) = args.repository.as_deref() {
        super::validate_repository(repository)?;
    }
    let cwd = std::env::current_dir()?;
    let repo = fs::canonicalize(git::text(&cwd, &["rev-parse", "--show-toplevel"])?)?;
    // Relative argv has the same meaning as the BASE lane only at the repository root.
    ensure!(
        fs::canonicalize(&cwd)? == repo,
        "run evidence wrap from the repository root"
    );
    let head = git::text(&repo, &["rev-parse", "HEAD"])?;
    let tree = git::text(&repo, &["rev-parse", "HEAD^{tree}"])?;
    let policy = config::load(&repo, &args.base)?;
    let lane = policy
        .policy
        .lanes
        .get(&args.check)
        .context("unknown BASE lane")?;
    ensure!(
        lane.nix_check.is_some() || (!args.reuse && args.command == lane.argv),
        "command must exactly equal BASE lane argv"
    );
    let signer: Vec<String> =
        serde_json::from_str(&args.signer).context("--signer must be a JSON argv array")?;
    ensure!(
        !signer.is_empty() && !signer[0].is_empty() && signer.iter().all(|arg| !arg.contains('\0')),
        "invalid signer argv"
    );
    let toolchain = measure_toolchain(
        &repo,
        &policy.environment,
        &args.config,
        &args.command,
        lane,
    )?;
    super::workspace::verify(&repo, &head, lane, true, Some(&toolchain))?;
    let mut inputs = config::expected_inputs(
        &repo,
        &head,
        &args.check,
        lane,
        &policy.environment,
        &policy.environment_bytes,
    )?;
    inputs.extend(toolchain.claims);
    let nix_check =
        super::signing::derivation(&repo, &head, lane, &policy.environment, &args.config)?;
    let mut execution = if args.reuse { "reused" } else { "rebuild" };
    let mut command_mode = execution;
    let mut command = if let Some((derivation, _, _)) = &nix_check {
        let command = super::derivation::argv(&lane.argv[0], &derivation.path, execution)?;
        ensure!(
            args.command.is_empty() || args.command == command,
            "command differs from normalized derivation argv"
        );
        command
    } else {
        args.command.clone()
    };
    for (key, value) in [
        ("workspace_clean", "true"),
        ("untracked_files", "false"),
        ("attempt", "1"),
    ] {
        inputs.insert(key.into(), value.into());
    }
    inputs.insert(
        "wrapper_sha256".into(),
        hex::encode(Sha256::digest(fs::read(std::env::current_exe()?)?)),
    );

    // Both child descriptors share a single open file description, preserving combined bytes
    // without pipe deadlocks or lossy UTF-8 conversion. The command keeps the caller's env.
    let mut output_file = tempfile::tempfile()?;
    let git_tool = nix_check.as_ref().map(|(_, _, git)| git.as_path());
    let preparation = if let Some((derivation, nix, git)) = &nix_check {
        if !args.reuse && !derivation.valid(nix, git)? {
            let argv = super::derivation::argv(&lane.argv[0], &derivation.path, "reused")?;
            let status = execute(&repo, None, &argv, &output_file, git_tool)?;
            check_interruption(status)?;
            if status.success() {
                None
            } else {
                command = argv;
                command_mode = "reused";
                Some(status)
            }
        } else {
            None
        }
    } else {
        None
    };
    let status = if let Some(status) = preparation {
        status
    } else {
        execute(
            &repo,
            toolchain.executable.as_deref(),
            &command,
            &output_file,
            git_tool,
        )?
    };
    check_interruption(status)?;
    if !status.success() && nix_check.is_some() {
        execution = "failed";
    }
    output_file.seek(SeekFrom::Start(0))?;
    let mut output = Vec::new();
    output_file.read_to_end(&mut output)?;
    if nix_check.is_some() {
        super::derivation::refuse_ignored(&output)?;
    }
    {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&output)?;
        stdout.flush()?;
    }
    let output_sha256 = hex::encode(Sha256::digest(&output));
    let blob = input_git(&repo, &["hash-object", "-w", "--stdin"], &output)?;
    git::git(
        &repo,
        &[
            "update-ref",
            &format!("refs/evidence-output/{output_sha256}"),
            &blob,
        ],
    )?;
    let after_toolchain =
        measure_toolchain(&repo, &policy.environment, &args.config, &command, lane)?;
    super::signing::verify_toolchain_claims(&after_toolchain.claims, &inputs)?;
    ensure!(
        after_toolchain.executable == toolchain.executable,
        "Nix executable changed during execution"
    );
    super::workspace::verify(&repo, &head, lane, false, Some(&after_toolchain))?;
    let after = config::expected_inputs(
        &repo,
        &head,
        &args.check,
        lane,
        &policy.environment,
        &policy.environment_bytes,
    )?;
    ensure!(
        after
            .iter()
            .all(|(key, value)| inputs.get(key) == Some(value)),
        "lane inputs changed during execution"
    );
    if let Some((derivation, nix, _)) = &nix_check {
        inputs.extend(derivation.claims(nix, execution, command_mode)?);
    }
    #[cfg(unix)]
    let exit_code = {
        use std::os::unix::process::ExitStatusExt;
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
    };
    #[cfg(not(unix))]
    let exit_code = status.code().unwrap_or(1);
    let request = Request {
        version: 1,
        repo: repo.clone(),
        repository: args.repository.clone(),
        base: args.base.clone(),
        head: head.clone(),
        check: args.check.clone(),
        command,
        exit_code,
        output: STANDARD.encode(output),
        inputs,
    };
    let mut launch = Command::new(&signer[0]);
    launch.args(&signer[1..]).current_dir(&repo);
    git::sanitize(&mut launch);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("PYTHON")
            || matches!(name.as_ref(), "GLIBC_TUNABLES" | "GCONV_PATH" | "NLSPATH")
        {
            launch.env_remove(key);
        }
    }
    let request_bytes = serde_json::to_vec(&request)?;
    let mut child = launch
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            InfraUnavailable::new(
                InfraClass::SignerUnavailable,
                format!("starting explicit evidence signer: {error}"),
            )
        })?;
    let input_result = child
        .stdin
        .take()
        .context("missing signer input")?
        .write_all(&request_bytes);
    let signed = child.wait_with_output().map_err(signer_io)?;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = signed.status.signal() {
            return Err(InfraUnavailable::new(
                InfraClass::SignerUnavailable,
                format!("evidence signer interrupted by signal {signal}"),
            )
            .into());
        }
    }
    ensure!(
        signed.status.success(),
        "evidence signer refused: {}",
        String::from_utf8_lossy(&signed.stderr)
    );
    // A completed policy refusal takes precedence over an early closed stdin.
    input_result.map_err(signer_io)?;
    let response: Response =
        serde_json::from_slice(&signed.stdout).context("invalid signer response")?;
    ensure!(
        config::full_commit(&response.record)
            && response.note_ref == format!("refs/notes/evidence/{tree}/{}", response.record),
        "signer returned an invalid evidence reference"
    );
    let mut bundle = tempfile::NamedTempFile::new()?;
    bundle.write_all(
        &STANDARD
            .decode(&response.bundle)
            .context("invalid signer bundle encoding")?,
    )?;
    let bundle_path = bundle.path().to_str().context("bundle path is not UTF-8")?;
    git::git(&repo, &["bundle", "unbundle", bundle_path])?;
    ensure!(
        git::text(&repo, &["cat-file", "-t", &response.record])? == "commit",
        "signer record is not a commit"
    );
    let publication_toolchain = measure_toolchain(
        &repo,
        &policy.environment,
        &args.config,
        &request.command,
        lane,
    )?;
    super::signing::verify_toolchain_claims(&publication_toolchain.claims, &request.inputs)?;
    ensure!(
        publication_toolchain.executable == toolchain.executable,
        "Nix executable changed during signing"
    );
    super::workspace::verify(&repo, &head, lane, false, Some(&publication_toolchain))?;
    git::git(&repo, &["update-ref", &response.note_ref, &response.record])?;
    // Failed publication leaves this immutable local ref behind. A retry runs the
    // lane and signer again; updating the same ref to the same record is harmless.
    // Publication deliberately targets origin, never an argv/HEAD-provided remote.
    // Local file transport supports bare integration fixtures; SSH remains normal account auth.
    publish_output(
        git::command(&repo)
            .env("GIT_ALLOW_PROTOCOL", "file:ssh:https")
            .args([
                "-c",
                "protocol.file.allow=always",
                "-c",
                "protocol.ssh.allow=always",
                "-c",
                "protocol.https.allow=always",
                "-c",
                "core.sshCommand=ssh",
                "push",
                "--",
                "origin",
                &format!("{}:{}", response.note_ref, response.note_ref),
            ]),
        std::time::Duration::from_secs(600),
    )?;
    eprintln!("evidence record {}", response.record);
    // Reserve the wrapper's temporary-unavailable code for typed infra errors.
    // The signed request above retains the lane's original exit code.
    Ok(if exit_code == 75 { 1 } else { exit_code })
}

#[cfg(all(test, unix))]
mod tests {
    use super::direct;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn script(path: &Path, marker: &str) {
        // Only the child opens the executable inode for writing; parallel test
        // forks in this parent can never inherit a writable shim descriptor.
        let content = format!("#!/bin/sh\necho {marker} \"$0\"\n");
        let status = std::process::Command::new("sh")
            .args([
                "-c",
                "printf '%s' \"$1\" > \"$2\" && chmod 755 \"$2\"",
                "shim-writer",
            ])
            .arg(&content)
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(std::fs::read(path).unwrap(), content.as_bytes());
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }

    #[test]
    fn bound_lane_runs_closure_binary_despite_path_shim() {
        let shim = tempfile::tempdir().unwrap();
        let closure = tempfile::tempdir().unwrap();
        std::fs::create_dir(closure.path().join("bin")).unwrap();
        script(&shim.path().join("lane-tool"), "shim");
        let measured = closure.path().join("bin/lane-tool");
        script(&measured, "closure");
        let argv = vec!["lane-tool".to_string()];
        let path = format!("{}:/usr/bin:/bin", shim.path().display());
        let run = |executable: Option<&Path>| {
            let output = direct(executable, &argv)
                .args(&argv[1..])
                .env("PATH", &path)
                .output()
                .unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap()
        };
        // Control: the shim really is first on PATH for an unbound launch.
        assert!(run(None).starts_with("shim "));
        // The bound launch executes the validated closure path, not the PATH shim.
        assert!(run(Some(&measured)).starts_with("closure "));
    }

    #[test]
    fn non_opted_in_package_lane_stays_path_resolved() {
        let shim = tempfile::tempdir().unwrap();
        script(&shim.path().join("bun"), "policy-wrapper");
        let argv = vec!["bun".to_owned(), "install".to_owned()];
        let output = direct(None, &argv)
            .args(&argv[1..])
            .env("PATH", shim.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .starts_with("policy-wrapper ")
        );
    }
    #[test]
    fn generic_git_deadlines_preserve_storage_and_publication_outcomes() {
        use std::{
            process::{Command, Stdio},
            time::Duration,
        };
        for status in [0, 7] {
            let mut command = Command::new("python3");
            command.args(["-c",
                "import sys;data=sys.stdin.buffer.read();sys.stdout.buffer.write(b' '+data+b'\\n');sys.exit(int(sys.argv[1]))",
                &status.to_string()]).stdin(Stdio::piped());
            let result = super::store_output(&mut command, b"stored", Duration::from_secs(600));
            if status == 0 {
                assert_eq!(result.unwrap(), "stored");
            } else {
                assert_eq!(result.unwrap_err().to_string(), "Git output storage failed");
            }
            let mut command = Command::new("python3");
            command.args([
                "-c",
                "import sys;sys.exit(int(sys.argv[1]))",
                &status.to_string(),
            ]);
            let result = super::publish_output(&mut command, Duration::from_secs(600));
            assert_eq!(result.is_ok(), status == 0);
            if let Err(error) = result {
                assert_eq!(
                    error
                        .downcast_ref::<super::InfraUnavailable>()
                        .unwrap()
                        .class
                        .token(),
                    "publish_failed"
                );
            }
        }
        for storing in [false, true] {
            let mut command = Command::new("python3");
            command
                .args(["-c", "import signal;signal.pause()"])
                .stdin(Stdio::piped());
            let error = if storing {
                super::store_output(&mut command, b"input", Duration::ZERO).unwrap_err()
            } else {
                super::publish_output(&mut command, Duration::ZERO).unwrap_err()
            };
            if storing {
                assert_eq!(
                    error.downcast_ref::<std::io::Error>().unwrap().kind(),
                    std::io::ErrorKind::TimedOut
                );
            } else {
                let infra = error.downcast_ref::<super::InfraUnavailable>().unwrap();
                assert_eq!(infra.class.token(), "publish_failed");
                assert!(infra.detail.contains("Git subprocess deadline exceeded"));
            }
        }
    }

    #[test]
    fn only_external_termination_signals_are_infrastructure() {
        use std::os::unix::process::ExitStatusExt;
        for signal in [1, 2, 9, 15] {
            let error =
                super::check_interruption(std::process::ExitStatus::from_raw(signal)).unwrap_err();
            let infra = error.downcast_ref::<super::InfraUnavailable>().unwrap();
            assert_eq!(infra.class.token(), "interrupted");
            assert!(infra.detail.ends_with(&format!("signal {signal}")));
        }
        // SIGILL, SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGPIPE are check failures.
        for signal in [4, 6, 7, 8, 11, 13] {
            super::check_interruption(std::process::ExitStatus::from_raw(signal)).unwrap();
        }
        super::check_interruption(std::process::ExitStatus::from_raw(75 << 8)).unwrap();
    }

    #[test]
    fn signer_pipe_failures_are_typed_but_other_io_errors_are_not() {
        use std::io::ErrorKind;
        for kind in [ErrorKind::BrokenPipe, ErrorKind::UnexpectedEof] {
            let error = super::signer_io(std::io::Error::from(kind));
            assert_eq!(
                error
                    .downcast_ref::<super::InfraUnavailable>()
                    .unwrap()
                    .class
                    .token(),
                "signer_unavailable"
            );
        }
        let error = super::signer_io(std::io::Error::from(ErrorKind::PermissionDenied));
        assert!(error.downcast_ref::<super::InfraUnavailable>().is_none());
    }
}
