//! Exercise startup diagnostics through the real binary without network or tools.
use std::{fs, process::Command};

const PRIVATE: &str = "private-key-canary-do-not-log";
const TOKEN: &str = "bootstrap-token-canary-do-not-log";
const ID_MISSING: &str = "MERGEMASTER_APP_ID is missing or empty; set the repository Actions variable to the GitHub App ID (not the installation ID).";
const ID_INVALID: &str = "MERGEMASTER_APP_ID must be a positive decimal integer within the u64 range; use the GitHub App ID (not the installation ID).";
const KEY_MISSING: &str = "MERGEMASTER_APP_PRIVATE_KEY is missing or empty; set the App private key secret in the mergemaster-check-publisher environment.";
const KEY_INVALID: &str = "MERGEMASTER_APP_PRIVATE_KEY must be a valid RSA PEM private key; replace the environment secret with the GitHub App private key.";
const TOKEN_MISSING: &str = "GH_TOKEN is missing or empty; supply the workflow token for public verifier bootstrap.";

fn preflight() -> Command {
    let workflow = include_str!("../../../.github/workflows/evidence-reconcile.yml");
    let step = workflow
        .split_once("      - name: Validate App bootstrap configuration\n")
        .unwrap().1
        .split_once("      - uses: actions/checkout@")
        .unwrap().0;
    let script = step.split_once("        run: |\n").unwrap().1
        .lines().map(|line| line.strip_prefix("          ").unwrap())
        .collect::<Vec<_>>().join("\n");
    let mut command = Command::new("bash");
    command.args(["--noprofile", "--norc", "-euo", "pipefail", "-c", &script]);
    command
}

fn reject(id: Option<&str>, key: Option<&str>, token: Option<&str>, expected: &str) {
    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("must-not-be-created");
    let mut binary = Command::new(env!("CARGO_BIN_EXE_mergemaster-reconciler"));
    binary.env_clear().env("PATH", "");
    let mut workflow = preflight();
    workflow.env_clear().env("PATH", std::env::var_os("PATH").unwrap());
    for mut command in [binary, workflow] {
        command.env("RUNNER_TEMP", &workspace).current_dir(directory.path());
        for (name, value) in [
            ("MERGEMASTER_APP_ID", id),
            ("MERGEMASTER_APP_PRIVATE_KEY", key),
            ("GH_TOKEN", token),
        ] {
            // Actions materializes absent variables/secrets as empty strings.
            command.env(name, value.unwrap_or(""));
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("Evidence reconciliation configuration failed: {expected}\n")
        );
        assert!(!workspace.exists(), "validation must precede workspace creation");
    }
}

#[test]
fn absent_empty_and_whitespace_configuration_names_the_required_setting() {
    for missing in [None, Some(""), Some(" \t\n")] {
        reject(missing, Some(PRIVATE), Some(TOKEN), ID_MISSING);
        reject(Some("123"), missing, Some(TOKEN), KEY_MISSING);
        reject(Some("123"), Some(PRIVATE), missing, TOKEN_MISSING);
    }
}

#[test]
fn invalid_app_ids_are_safe_and_precede_tool_discovery() {
    for invalid in [
        "0", "-1", "+1", "1.0", " 123", "123\n", "１２３",
        "18446744073709551616", "app-id-canary-do-not-log",
    ] {
        reject(Some(invalid), Some(PRIVATE), Some(TOKEN), ID_INVALID);
    }
}

#[test]
fn malformed_key_is_named_without_echoing_the_key_or_token() {
    for key in [PRIVATE, "-----BEGIN RSA PRIVATE KEY-----\nsecret-pem-canary\n-----END RSA PRIVATE KEY-----"] {
        reject(Some("123"), Some(key), Some(TOKEN), KEY_INVALID);
    }
}

#[test]
fn valid_configuration_preserves_safe_unexpected_error_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let key_path = directory.path().join("key.pem");
    let generated = Command::new("openssl")
        .args(["genrsa", "-out"])
        .arg(&key_path)
        .arg("2048")
        .output()
        .unwrap();
    assert!(generated.status.success());
    let key = fs::read_to_string(key_path).unwrap();
    for id in ["1", "000123", "18446744073709551615"] {
        let output = preflight()
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("MERGEMASTER_APP_ID", id)
            .env("MERGEMASTER_APP_PRIVATE_KEY", &key)
            .env("GH_TOKEN", TOKEN)
            .current_dir(directory.path())
            .output().unwrap();
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    // The maximum valid ID reaches tool discovery, not a configuration error.
    // An empty PATH guarantees no subprocess or GitHub request can execute.
    let output = Command::new(env!("CARGO_BIN_EXE_mergemaster-reconciler"))
        .env_clear()
        .env("PATH", "")
        .env("MERGEMASTER_APP_ID", u64::MAX.to_string())
        .env("MERGEMASTER_APP_PRIVATE_KEY", &key)
        .env("GH_TOKEN", TOKEN)
        .env("RUNNER_TEMP", directory.path().join("unused"))
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(String::from_utf8(output.stderr).unwrap(),
        "Evidence reconciliation failed; no credentials or response bodies logged.\n");
    assert!(!directory.path().join("unused").exists());
}
