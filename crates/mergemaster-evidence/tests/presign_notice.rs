//! Replay independent, frozen Python observations through the native CLI boundary.
use serde_json::Value;
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn presign_notice_frozen_stdout_summary_annotation_and_never_fails() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture: Value = serde_json::from_slice(
        &fs::read(root.join("tests/fixtures/oracle/presign-notice.json")).unwrap(),
    )
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let temporary = tempfile::tempdir().unwrap();
        let bin = temporary.path().join("bin");
        fs::create_dir(&bin).unwrap();
        for (name, source) in case["executables"].as_object().unwrap() {
            let path = bin.join(name);
            fs::write(&path, source.as_str().unwrap()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let summary = temporary.path().join("summary");
        fs::write(&summary, case["summary_initial"].as_str().unwrap()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_mergemaster"));
        command
            .args(["evidence", "presign-notice"])
            .current_dir(temporary.path())
            .env(
                "PATH",
                std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
                    &std::env::var_os("PATH").unwrap_or_default(),
                )))
                .unwrap(),
            )
            .env("GITHUB_STEP_SUMMARY", &summary);
        for name in ["LINES", "BASE_SHA", "REPOSITORY", "PR_NUMBER", "GH_TOKEN"] {
            command.env_remove(name);
        }
        for (name, value) in case["environment"].as_object().unwrap() {
            command.env(name, value.as_str().unwrap());
        }
        let done = command.output().unwrap();
        let expected = &case["expected"];
        let id = case["id"].as_str().unwrap();
        assert_eq!(
            done.status.code(),
            expected["exit_code"].as_i64().map(|code| code as i32),
            "{id}"
        );
        assert_eq!(
            done.stdout,
            expected["stdout"].as_str().unwrap().as_bytes(),
            "{id}: stdout"
        );
        assert_eq!(
            done.stderr,
            expected["stderr"].as_str().unwrap().as_bytes(),
            "{id}: stderr"
        );
        assert_eq!(
            fs::read(summary).unwrap(),
            expected["summary"].as_str().unwrap().as_bytes(),
            "{id}: summary"
        );
    }
}
