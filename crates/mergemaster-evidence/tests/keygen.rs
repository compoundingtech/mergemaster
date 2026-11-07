#[test]
fn keygen_oracle_parity() {
    let driver =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/test-native-keygen.py");
    let status = std::process::Command::new("python3")
        .arg("-I")
        .arg(driver)
        .arg(env!("CARGO_BIN_EXE_mergemaster"))
        .status()
        .expect("run keygen compatibility oracle");
    assert!(
        status.success(),
        "keygen compatibility oracle failed: {status}"
    );
}
