//! Pinned Git flake evaluation and explicit fresh-versus-reused realizations.
use std::{collections::BTreeMap, path::Path, process::Command};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use crate::gate::config::NixCheck;

pub struct Derivation { pub path: String, outputs: BTreeMap<String, String> }
fn command(nix: &Path, git: &Path) -> Command {
    let mut command = Command::new(nix);
    command.env_clear().env("LC_ALL", "C").env("PATH", git.parent().expect("absolute trusted git"));
    command.args(["--extra-experimental-features", "nix-command flakes", "--option", "allow-import-from-derivation", "false"]);
    command
}
impl Derivation {
    pub fn evaluate(nix: &Path, git: &Path, repo: &Path, head: &str, check: &NixCheck) -> Result<Self> {
        let source = url_source(repo, head)?;
        let output = command(nix, git).args(["eval", "--raw", "--no-write-lock-file", "--no-update-lock-file",
            &format!("{source}#{}.drvPath", check.attribute)]).output()?;
        ensure!(output.status.success(), "Nix check evaluation failed: {}", String::from_utf8_lossy(&output.stderr));
        let path = String::from_utf8(output.stdout)?;
        ensure!(crate::gate::config::nix_store_path(&path) && path.ends_with(".drv"), "invalid derivation path");
        let output = command(nix, git).args(["derivation", "show", &path]).output()?;
        ensure!(output.status.success(), "cannot inspect check derivation");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let outputs = value.get(&path).and_then(|v| v.get("outputs")).and_then(serde_json::Value::as_object).context("missing derivation outputs")?;
        let outputs = outputs.iter().map(|(name, value)| {
            let path = value.get("path").and_then(serde_json::Value::as_str).context("check requires static output paths")?;
            ensure!(crate::gate::config::nix_store_path(path), "invalid derivation output");
            Ok((name.clone(), path.to_owned()))
        }).collect::<Result<BTreeMap<_, _>>>()?;
        ensure!(!outputs.is_empty(), "check has no outputs");
        Ok(Self { path, outputs })
    }
    pub fn valid(&self, nix: &Path, git: &Path) -> Result<bool> {
        let output = command(nix, git).args(["path-info", "--json"]).args(self.outputs.values()).output()?;
        Ok(output.status.success())
    }
    pub fn prepare(&self, nix: &Path, git: &Path, reuse: bool) -> Result<()> {
        if !reuse && !self.valid(nix, git)? {
            let status = command(nix, git).args(["build", "--no-link", &format!("{}^*", self.path)]).status()?;
            ensure!(status.success(), "initial check realization failed");
        }
        Ok(())
    }
    pub fn claims(&self, nix: &Path, execution: &str) -> Result<BTreeMap<String, String>> {
        ensure!(matches!(execution, "rebuild" | "reused"), "invalid Nix execution mode");
        let outputs = self.outputs.iter().map(|(name, path)| {
            let closure = super::nix::measure(nix, path)?;
            Ok((name, path, closure.get(path).context("missing output NAR hash")?.clone()))
        }).collect::<Result<Vec<_>>>()?;
        Ok(BTreeMap::from([
            ("nix_derivation".into(), self.path.clone()),
            ("nix_outputs_sha256".into(), hex::encode(Sha256::digest(serde_json::to_vec(&outputs)?))),
            ("nix_execution".into(), execution.into()),
            ("nix_command_sha256".into(), command_digest(&argv(nix.to_str().context("Nix path is not UTF-8")?, &self.path, execution)?)?),
        ]))
    }
}
fn url_source(repo: &Path, head: &str) -> Result<String> {
    let path = repo.to_str().context("repository path is not UTF-8")?;
    let encoded: String = path.bytes().map(|b| if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
        char::from(b).to_string()
    } else { format!("%{b:02X}") }).collect();
    Ok(format!("git+file://{encoded}?rev={head}"))
}

pub fn argv(executable: &str, drv: &str, execution: &str) -> Result<Vec<String>> {
    ensure!(crate::gate::config::nix_store_path(drv) && drv.ends_with(".drv")
        && matches!(execution, "rebuild" | "reused"), "invalid derivation execution");
    let mut argv: Vec<String> = [executable, "--extra-experimental-features", "nix-command flakes",
        "--option", "allow-import-from-derivation", "false", "build", "--no-link", "--json", "--print-build-logs"]
        .into_iter().map(str::to_owned).collect();
    if execution == "rebuild" { argv.extend(["--option", "substitute", "false", "--rebuild"].map(str::to_owned)); }
    argv.push(format!("{drv}^*"));
    Ok(argv)
}

pub fn command_digest(argv: &[String]) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(argv)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn freshness_is_an_unconditional_rebuild_and_argv_is_bound() {
        let drv = "/nix/store/00000000000000000000000000000000-check.drv";
        let fresh = argv("/nix/store/nix/bin/nix", drv, "rebuild").unwrap();
        assert!(fresh.windows(2).any(|pair| pair == ["substitute", "false"]));
        assert!(fresh.iter().any(|arg| arg == "--rebuild"));
        let reused = argv("/nix/store/nix/bin/nix", drv, "reused").unwrap();
        assert!(!reused.iter().any(|arg| arg == "--rebuild"));
        assert_ne!(command_digest(&fresh).unwrap(), command_digest(&reused).unwrap());
        assert!(argv("nix", drv, "built").is_err());
        assert!(argv("nix", "../check.drv", "rebuild").is_err());
        assert_eq!(url_source(Path::new("/repo/a #b"), "abc").unwrap(), "git+file:///repo/a%20%23b?rev=abc");
    }
}
