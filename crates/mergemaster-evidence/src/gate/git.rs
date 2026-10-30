//! Read-only Git plumbing with ambient repository selectors and helpers disabled.
use std::{env, path::Path, process::{Command, Stdio}};
use anyhow::{Context, Result, ensure};

/// Also usable on the isolated evidence worker: its child Git processes inherit
/// these overrides without changing this process's environment.
pub fn sanitize(command: &mut Command) {
    for (key, _) in env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("GIT_") || name.starts_with("LD_") || name.starts_with("DYLD_") {
            command.env_remove(key);
        }
    }
    command.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_ALLOW_PROTOCOL", "")
        .env("LC_ALL", "C");
    let settings = [
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("core.untrackedCache", "false"),
        ("core.attributesFile", "/dev/null"),
        ("diff.external", ""),
        ("diff.trustExitCode", "false"),
        ("credential.helper", ""),
        ("core.askPass", "/bin/false"),
        ("core.sshCommand", "/bin/false"),
        ("protocol.allow", "never"),
        ("log.showSignature", "false"),
        ("core.pager", "cat"),
    ];
    command.env("GIT_CONFIG_COUNT", settings.len().to_string());
    for (index, (key, value)) in settings.iter().enumerate() {
        command.env(format!("GIT_CONFIG_KEY_{index}"), key)
            .env(format!("GIT_CONFIG_VALUE_{index}"), value);
    }
}

pub fn command(repo: &Path) -> Command {
    let mut command = Command::new("git");
    sanitize(&mut command);
    command.arg("-C").arg(repo).stdin(Stdio::null());
    command
}

pub fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = command(repo).args(args).output().context("running trusted Git plumbing")?;
    // Git diagnostics can contain candidate-controlled paths; do not forward them.
    ensure!(output.status.success(), "Git plumbing failed ({})", output.status);
    Ok(output.stdout)
}

pub fn text(repo: &Path, args: &[&str]) -> Result<String> {
    let mut value = String::from_utf8(git(repo, args)?).context("Git output is not UTF-8")?;
    value.truncate(value.trim_end().len());
    Ok(value)
}
