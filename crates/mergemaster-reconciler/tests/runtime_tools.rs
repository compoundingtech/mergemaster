//! Exercise the production subprocess boundary with real Git SSH signatures.
//! The flake check supplies exactly the runtime tool set used by the wrapper.
use mergemaster_reconciler::{Capabilities, ProcessRequest, RealCapabilities};
use std::{collections::BTreeMap, fs, path::Path, process::Command};

fn run(directory: &Path, program: &str, args: &[&str]) {
    let output = Command::new(program)
        .args(args)
        .current_dir(directory)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_COUNT", "0")
        .output()
        .expect("fixture tool must execute");
    assert!(
        output.status.success(),
        "fixture setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn restricted_subprocess_path_verifies_a_real_ssh_signed_commit() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let key = root.join("signing-key");
    run(
        root,
        "ssh-keygen",
        &["-q", "-t", "ed25519", "-N", "", "-f", key.to_str().unwrap()],
    );
    let allowed = root.join("allowed-signers");
    fs::write(
        &allowed,
        format!(
            "fixture@example.test {}",
            fs::read_to_string(key.with_extension("pub")).unwrap()
        ),
    )
    .unwrap();
    run(root, "git", &["init", "--template="]);
    run(
        root,
        "git",
        &[
            "-c",
            "user.name=Reconciler Fixture",
            "-c",
            "user.email=fixture@example.test",
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("user.signingkey={}", key.display()),
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--allow-empty",
            "-S",
            "-m",
            "signed fixture",
        ],
    );

    let mut capabilities = RealCapabilities::new().unwrap();
    let result = capabilities
        .process(ProcessRequest {
            args: vec![
                "git".into(),
                "-c".into(),
                "gpg.format=ssh".into(),
                "-c".into(),
                "gpg.ssh.program=ssh-keygen".into(),
                "-c".into(),
                format!("gpg.ssh.allowedSignersFile={}", allowed.display()),
                "verify-commit".into(),
                "HEAD".into(),
            ],
            // No caller PATH may supply the verifier's signature tool. The production
            // adapter must restore its independently resolved trusted ssh-keygen dir.
            env: BTreeMap::from([
                ("PATH".into(), "/nonexistent-caller-path".into()),
                ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
                ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
                ("GIT_CONFIG_COUNT".into(), "0".into()),
            ]),
            cwd: Some(root.to_path_buf()),
            input: None,
        })
        .unwrap();
    assert_eq!(
        result.code, 0,
        "production subprocess PATH must support SSH signature verification"
    );
}
