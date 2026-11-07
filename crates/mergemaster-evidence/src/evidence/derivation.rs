//! Pinned evaluation and daemon-aware, local-only freshness proofs.
use crate::gate::config::NixCheck;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::Path,
    process::{Command, Output},
};

const SETTINGS: &[(&str, &str)] = &[
    ("accept-flake-config", "false"),
    ("pure-eval", "true"),
    ("allow-import-from-derivation", "false"),
    ("builders", ""),
    ("build-hook", ""),
    ("max-jobs", "1"),
];
pub struct Derivation {
    pub path: String,
    outputs: BTreeMap<String, String>,
    settings: BTreeMap<String, String>,
}
fn prefix(executable: &str) -> Vec<String> {
    let mut args = vec![
        executable.into(),
        "--extra-experimental-features".into(),
        "nix-command flakes".into(),
    ];
    for (name, value) in SETTINGS {
        args.extend(["--option".into(), (*name).into(), (*value).into()]);
    }
    args
}
/// The temporary HOME excludes saved trusted flake settings; no caller config survives.
pub(super) fn isolated(nix: &Path, git: &Path) -> Result<(Command, tempfile::TempDir)> {
    let home = tempfile::tempdir()?;
    let mut command = Command::new(nix);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", git.parent().context("trusted git parent")?)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("NIX_USER_CONF_FILES", "/dev/null")
        .env(
            "NIX_CONFIG",
            SETTINGS
                .iter()
                .map(|(key, value)| format!("{key} = {value}\n"))
                .collect::<String>(),
        );
    Ok((command, home))
}
fn run(nix: &Path, git: &Path, args: &[&str]) -> Result<Output> {
    let (mut command, _home) = isolated(nix, git)?;
    let output = command
        .args(&prefix(nix.to_str().context("Nix path UTF-8")?)[1..])
        .args(args)
        .output()?;
    refuse_ignored(&output.stderr)?;
    Ok(output)
}
pub(super) fn refuse_ignored(stderr: &[u8]) -> Result<()> {
    ensure!(
        !String::from_utf8_lossy(stderr).contains("ignoring the client-specified setting"),
        "Nix daemon ignored required execution settings"
    );
    Ok(())
}
fn settings(nix: &Path, git: &Path) -> Result<BTreeMap<String, String>> {
    let output = run(nix, git, &["config", "show", "--json"])?;
    ensure!(
        output.status.success(),
        "cannot inspect effective Nix settings"
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    for (key, expected) in SETTINGS {
        let actual = value
            .get(*key)
            .and_then(|entry| entry.get("value"))
            .context("required Nix setting missing")?;
        let text = if actual.as_array().is_some_and(Vec::is_empty) {
            String::new()
        } else {
            actual
                .as_str()
                .map_or_else(|| actual.to_string(), str::to_owned)
        };
        ensure!(text == *expected, "effective Nix setting differs: {key}");
    }
    let output = run(nix, git, &["store", "info", "--json"])?;
    ensure!(output.status.success(), "cannot inspect Nix store trust");
    let store: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let url = store
        .get("url")
        .and_then(serde_json::Value::as_str)
        .context("missing Nix store URL")?;
    if url.starts_with("daemon") {
        ensure!(
            store.get("trusted").and_then(serde_json::Value::as_bool) == Some(true),
            "fresh evidence requires a trusted Nix daemon client so execution overrides take effect"
        );
    } else {
        ensure!(
            url.starts_with("local"),
            "unsupported Nix store for execution evidence"
        );
    }
    let mut claims = BTreeMap::from([
        ("nix_settings_sha256".into(), settings_digest()?),
        ("nix_store".into(), url.to_owned()),
    ]);
    claims.insert(
        "nix_daemon_trusted".into(),
        store
            .get("trusted")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
            .to_string(),
    );
    Ok(claims)
}
impl Derivation {
    pub fn evaluate(
        nix: &Path,
        git: &Path,
        repo: &Path,
        head: &str,
        check: &NixCheck,
    ) -> Result<Self> {
        let settings = settings(nix, git)?;
        let source = url_source(repo, head)?;
        let output = run(
            nix,
            git,
            &[
                "eval",
                "--raw",
                "--no-write-lock-file",
                "--no-update-lock-file",
                &format!("{source}#{}.drvPath", check.attribute),
            ],
        )?;
        ensure!(
            output.status.success(),
            "Nix check evaluation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let path = String::from_utf8(output.stdout)?;
        ensure!(
            crate::gate::config::nix_store_path(&path) && path.ends_with(".drv"),
            "invalid derivation path"
        );
        let output = run(nix, git, &["derivation", "show", &path])?;
        ensure!(output.status.success(), "cannot inspect check derivation");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let outputs = parse_outputs(&value, &path)?;
        Ok(Self {
            path,
            outputs,
            settings,
        })
    }
    pub fn valid(&self, nix: &Path, git: &Path) -> Result<bool> {
        let paths: Vec<_> = self.outputs.values().map(String::as_str).collect();
        let mut args = vec!["path-info", "--json"];
        args.extend(paths);
        let output = run(nix, git, &args)?;
        if !output.status.success() {
            return Ok(false);
        }
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        Ok(self
            .outputs
            .values()
            .all(|path| registered(&value, path) && Path::new(path).exists()))
    }
    pub fn claims(
        &self,
        nix: &Path,
        execution: &str,
        command_mode: &str,
    ) -> Result<BTreeMap<String, String>> {
        ensure!(
            matches!(execution, "rebuild" | "reused" | "failed"),
            "invalid Nix execution mode"
        );
        let mut claims = self.settings.clone();
        claims.extend([
            ("nix_derivation".into(), self.path.clone()),
            ("nix_execution".into(), execution.into()),
            ("nix_command_mode".into(), command_mode.into()),
            (
                "nix_command_sha256".into(),
                command_digest(&argv(
                    nix.to_str().context("Nix path UTF-8")?,
                    &self.path,
                    command_mode,
                )?)?,
            ),
        ]);
        if execution != "failed" {
            ensure!(
                execution == command_mode,
                "Nix execution differs from command mode"
            );
            let outputs = self
                .outputs
                .iter()
                .map(|(name, path)| {
                    let closure = super::nix::measure(nix, path)?;
                    Ok((
                        name,
                        path,
                        closure
                            .get(path)
                            .context("missing output NAR hash")?
                            .clone(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            claims.insert(
                "nix_outputs_sha256".into(),
                hex::encode(Sha256::digest(serde_json::to_vec(&outputs)?)),
            );
        }
        Ok(claims)
    }
}
fn url_source(repo: &Path, head: &str) -> Result<String> {
    let path = repo.to_str().context("repository path is not UTF-8")?;
    let encoded: String = path
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    Ok(format!("git+file://{encoded}?rev={head}"))
}
pub fn argv(executable: &str, drv: &str, execution: &str) -> Result<Vec<String>> {
    ensure!(
        crate::gate::config::nix_store_path(drv)
            && drv.ends_with(".drv")
            && matches!(execution, "rebuild" | "reused"),
        "invalid derivation execution"
    );
    let mut argv = prefix(executable);
    argv.extend(
        [
            "--log-format",
            "internal-json",
            "build",
            "--no-link",
            "--json",
            "--print-build-logs",
        ]
        .map(str::to_owned),
    );
    if execution == "rebuild" {
        argv.extend(["--option", "substitute", "false", "--rebuild"].map(str::to_owned));
    }
    argv.push(format!("{drv}^*"));
    Ok(argv)
}
pub fn command_digest(argv: &[String]) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(argv)?)))
}
pub fn settings_digest() -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(SETTINGS)?)))
}

fn parse_outputs(value: &serde_json::Value, drv: &str) -> Result<BTreeMap<String, String>> {
    let basename = drv
        .strip_prefix("/nix/store/")
        .context("invalid derivation root")?;
    ensure!(
        value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .is_none_or(|version| (1..=4).contains(&version)),
        "unsupported derivation JSON envelope version"
    );
    let declarations = value.get("derivations").unwrap_or(value);
    let declaration = declarations
        .get(drv)
        .or_else(|| declarations.get(basename))
        .context("missing derivation declaration")?;
    ensure!(
        declaration
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .is_none_or(|version| (1..=4).contains(&version)),
        "unsupported derivation JSON version"
    );
    let outputs = declaration
        .get("outputs")
        .and_then(serde_json::Value::as_object)
        .context("missing derivation outputs")?;
    let outputs = outputs
        .iter()
        .map(|(name, value)| {
            let path = value
                .get("path")
                .and_then(serde_json::Value::as_str)
                .context("check requires static output paths")?;
            let path = if path.starts_with("/nix/store/") {
                path.to_owned()
            } else {
                format!("/nix/store/{path}")
            };
            ensure!(
                crate::gate::config::nix_store_path(&path),
                "invalid derivation output"
            );
            Ok((name.clone(), path))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(!outputs.is_empty(), "check has no outputs");
    Ok(outputs)
}

fn registered(value: &serde_json::Value, path: &str) -> bool {
    value
        .get(path)
        .or_else(|| {
            value
                .as_array()?
                .iter()
                .find(|entry| entry.get("path").and_then(serde_json::Value::as_str) == Some(path))
        })
        .is_some_and(|entry| {
            entry
                .get("narHash")
                .and_then(serde_json::Value::as_str)
                .is_some()
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn freshness_is_local_unconditional_rebuild_and_argv_bound() {
        let drv = "/nix/store/00000000000000000000000000000000-check.drv";
        let fresh = argv("/nix/store/nix/bin/nix", drv, "rebuild").unwrap();
        for pair in [
            ["substitute", "false"],
            ["builders", ""],
            ["build-hook", ""],
            ["max-jobs", "1"],
            ["accept-flake-config", "false"],
        ] {
            assert!(fresh.windows(2).any(|window| window == pair));
        }
        assert!(fresh.iter().any(|arg| arg == "--rebuild"));
        let reused = argv("/nix/store/nix/bin/nix", drv, "reused").unwrap();
        assert!(!reused.iter().any(|arg| arg == "--rebuild"));
        assert_ne!(
            command_digest(&fresh).unwrap(),
            command_digest(&reused).unwrap()
        );
        assert!(argv("nix", drv, "built").is_err());
        assert!(argv("nix", "../check.drv", "rebuild").is_err());
        assert!(
            refuse_ignored(b"warning: ignoring the client-specified setting 'builders'").is_err()
        );
        assert_eq!(
            url_source(Path::new("/repo/a #b"), "abc").unwrap(),
            "git+file:///repo/a%20%23b?rev=abc"
        );
    }
    #[test]
    fn versioned_derivation_paths_normalize_without_accepting_escapes() {
        let drv = "/nix/store/00000000000000000000000000000000-check.drv";
        let output = "11111111111111111111111111111111-check";
        let old =
            serde_json::json!({drv:{"outputs":{"out":{"path":format!("/nix/store/{output}")}}}});
        let new = serde_json::json!({"version":4,"derivations":{(drv.trim_start_matches("/nix/store/")):{"outputs":{"out":{"path":output}}}}});
        assert_eq!(
            parse_outputs(&old, drv).unwrap(),
            parse_outputs(&new, drv).unwrap()
        );
        let escape = serde_json::json!({drv:{"version":4,"outputs":{"out":{"path":"../escape"}}}});
        assert!(parse_outputs(&escape, drv).is_err());
    }
    #[test]
    fn successful_json_with_null_is_not_a_registered_output() {
        assert!(!registered(
            &serde_json::json!({"/nix/store/output":null}),
            "/nix/store/output"
        ));
        assert!(registered(
            &serde_json::json!({"/nix/store/output":{"narHash":"sha256-hash"}}),
            "/nix/store/output"
        ));
        assert!(!registered(&serde_json::json!([]), "/nix/store/output"));
    }
}
