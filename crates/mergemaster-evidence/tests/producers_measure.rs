#![cfg(test)]
use serde_json::json;
use std::{fs, path::Path, process::Command};

const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const ASSET: &str = "mergemaster-linux";

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mergemaster"));
    command.args(["producers", "measure"]);
    command
}

fn release(root: &Path) -> Command {
    let mut command = command();
    command
        .arg("--release-asset")
        .arg(root.join("asset"))
        .arg("--sha256sums")
        .arg(root.join("SHA256SUMS"))
        .args([
            "--asset-name",
            ASSET,
            "--system",
            "x86_64-linux",
            "--mergemaster-revision",
            REVISION,
        ]);
    command
}

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("asset"), b"abc").unwrap();
    fs::write(
        root.path().join("SHA256SUMS"),
        format!("{DIGEST}  {ASSET}\n"),
    )
    .unwrap();
    root
}

fn entry(system: &str, flavor: &str, digest: &str) -> serde_json::Value {
    let mut provenance = json!({
        "package": ASSET,
        "mergemaster_revision": REVISION.to_ascii_uppercase(),
        "nix_output_path": null,
    });
    if flavor == "nix" {
        provenance["nix_output_path"] =
            json!("/nix/store/00000000000000000000000000000000-mergemaster");
    }
    json!({"system": system, "flavor": flavor, "executable_sha256": digest, "provenance": provenance})
}

#[test]
fn release_measurement_has_exact_canonical_bytes_and_check_detects_drift() {
    let root = fixture();
    let output = release(root.path()).output().unwrap();
    assert!(output.status.success(), "{:?}", output);
    let expected = format!(
        "{{\"producers\":[{{\"executable_sha256\":\"{DIGEST}\",\"flavor\":\"release\",\"provenance\":{{\"mergemaster_revision\":\"{REVISION}\",\"package\":\"{ASSET}\"}},\"system\":\"x86_64-linux\"}}],\"version\":1}}\n"
    );
    assert_eq!(output.stdout, expected.as_bytes());
    let manifest = root.path().join("producers.json");
    fs::write(&manifest, &output.stdout).unwrap();
    let checked = release(root.path())
        .arg("--check")
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(checked.status.success());
    assert_eq!(checked.stdout, output.stdout);
    fs::write(&manifest, expected.trim_end()).unwrap();
    let drift = release(root.path())
        .arg("--check")
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(!drift.status.success());
    assert!(drift.stdout.is_empty());
    assert!(String::from_utf8_lossy(&drift.stderr).contains("drift"));
}

#[test]
fn release_checksums_refuse_mismatch_missing_duplicate_and_malformed_lines() {
    let root = fixture();
    for sums in [
        format!("{}  {ASSET}\n", "0".repeat(64)),
        format!("{DIGEST}  another-asset\n"),
        format!("{DIGEST}  {ASSET}\n{DIGEST}  {ASSET}\n"),
        format!("{DIGEST} {ASSET}\n"),
        format!("{DIGEST}  {ASSET}\r\n"),
        format!("{DIGEST}  {ASSET}\nmalformed unrelated line\n"),
        String::new(),
        "é".repeat(40),
    ] {
        fs::write(root.path().join("SHA256SUMS"), sums).unwrap();
        let output = release(root.path()).output().unwrap();
        assert!(!output.status.success(), "{:?}", output);
        assert!(output.stdout.is_empty());
    }
    fs::write(
        root.path().join("SHA256SUMS"),
        format!("{DIGEST} *{ASSET}\n"),
    )
    .unwrap();
    assert!(release(root.path()).output().unwrap().status.success());
}

#[test]
fn merge_sorts_system_flavor_digest_and_all_object_keys() {
    let root = fixture();
    let low = "0".repeat(64);
    let high = "f".repeat(64);
    let entries = [
        entry("x86_64-linux", "release", DIGEST),
        entry("aarch64-linux", "release", &high),
        entry("aarch64-linux", "release", &low),
        entry("aarch64-linux", "nix", &high),
    ];
    let paths: Vec<_> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let path = root.path().join(format!("entry-{index}.json"));
            fs::write(
                &path,
                serde_json::to_vec_pretty(&json!({"version": 1, "producers": [entry]})).unwrap(),
            )
            .unwrap();
            path
        })
        .collect();
    let output = command().arg("--merge").args(&paths).output().unwrap();
    assert!(output.status.success(), "{:?}", output);
    let expected_entries = [
        format!(
            "{{\"executable_sha256\":\"{high}\",\"flavor\":\"nix\",\"provenance\":{{\"mergemaster_revision\":\"{REVISION}\",\"nix_output_path\":\"/nix/store/00000000000000000000000000000000-mergemaster\",\"package\":\"{ASSET}\"}},\"system\":\"aarch64-linux\"}}"
        ),
        format!(
            "{{\"executable_sha256\":\"{low}\",\"flavor\":\"release\",\"provenance\":{{\"mergemaster_revision\":\"{REVISION}\",\"package\":\"{ASSET}\"}},\"system\":\"aarch64-linux\"}}"
        ),
        format!(
            "{{\"executable_sha256\":\"{high}\",\"flavor\":\"release\",\"provenance\":{{\"mergemaster_revision\":\"{REVISION}\",\"package\":\"{ASSET}\"}},\"system\":\"aarch64-linux\"}}"
        ),
        format!(
            "{{\"executable_sha256\":\"{DIGEST}\",\"flavor\":\"release\",\"provenance\":{{\"mergemaster_revision\":\"{REVISION}\",\"package\":\"{ASSET}\"}},\"system\":\"x86_64-linux\"}}"
        ),
    ];
    let expected = format!(
        "{{\"producers\":[{}],\"version\":1}}\n",
        expected_entries.join(",")
    );
    assert_eq!(output.stdout, expected.as_bytes());
    let reversed = command()
        .arg("--merge")
        .args(paths.iter().rev())
        .output()
        .unwrap();
    assert!(reversed.status.success());
    assert_eq!(reversed.stdout, output.stdout);
    let duplicate = command()
        .arg("--merge")
        .arg(&paths[0])
        .arg(&paths[0])
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("duplicate"));
}

#[test]
fn nix_measurement_refuses_non_store_paths_without_a_production_bypass() {
    let root = fixture();
    fs::create_dir(root.path().join("bin")).unwrap();
    fs::write(root.path().join("bin/mergemaster"), b"not an executable").unwrap();
    let output = command()
        .arg("--nix-package")
        .arg(root.path())
        .args([
            "--system",
            "x86_64-linux",
            "--mergemaster-revision",
            REVISION,
            "--package",
            "inputs.mergemaster.packages.x86_64-linux.default",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("/nix/store"));
}

#[test]
fn invalid_manifest_unknown_fields_and_conflicting_modes_refuse() {
    let root = fixture();
    let path = root.path().join("entry.json");
    for manifest in [
        json!({"version": 2, "producers": [entry("x86_64-linux", "release", DIGEST)]}),
        json!({"version": 1, "producers": []}),
        json!({"version": 1, "producers": [entry("unsupported", "release", DIGEST)]}),
        json!({"version": 1, "producers": [entry("x86_64-linux", "release", DIGEST)], "extra": true}),
    ] {
        fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(
            !command()
                .arg("--merge")
                .arg(&path)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    assert!(
        !release(root.path())
            .arg("--merge")
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!command().output().unwrap().status.success());
    let help = command().arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("gh attestation verify"));
}
