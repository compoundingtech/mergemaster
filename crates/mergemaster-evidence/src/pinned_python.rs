//! One isolated, version-checked interpreter for Python oracle fixtures.
use std::{path::PathBuf, process::Command, sync::LazyLock};

/// Resolve and validate once, then isolate every oracle process from Python env/site settings.
pub(crate) fn command() -> Command {
    static INTERPRETER: LazyLock<PathBuf> = LazyLock::new(|| {
        let interpreter = PathBuf::from(
            std::env::var_os("MERGEMASTER_ORACLE_PYTHON")
                .expect("MERGEMASTER_ORACLE_PYTHON must name the pinned CPython 3.14.7 executable"),
        );
        assert!(
            interpreter.is_absolute(),
            "MERGEMASTER_ORACLE_PYTHON must be an absolute executable path"
        );
        let output = Command::new(&interpreter)
            .args([
                "-I",
                "-c",
                "import sys; assert sys.implementation.name == 'cpython', sys.implementation; assert sys.version_info[:3] == (3,14,7), sys.version; assert sys.flags.optimize == 0",
            ])
            .output()
            .expect("launch MERGEMASTER_ORACLE_PYTHON (CPython 3.14.7)");
        assert!(
            output.status.success(),
            "pinned Python: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        interpreter
    });
    let mut command = Command::new(&*INTERPRETER);
    command.arg("-I");
    command
}

/// Resolve the independent immutable rust-test-keys oracle source.
#[allow(
    dead_code,
    reason = "shared via #[path] into test targets; only some call it"
)]
pub(crate) fn keys_oracle() -> PathBuf {
    let root = PathBuf::from(
        std::env::var_os("MERGEMASTER_PYTHON_KEYS_ORACLE")
            .expect("MERGEMASTER_PYTHON_KEYS_ORACLE must name the pinned keys source root"),
    );
    assert!(
        root.is_absolute(),
        "MERGEMASTER_PYTHON_KEYS_ORACLE must be an absolute source root"
    );
    let script = root.join("scripts/rust-test-keys");
    assert!(
        script.is_file(),
        "missing pinned oracle: {}",
        script.display()
    );
    script
}

#[test]
fn isolated_oracle_ignores_python_optimization_and_search_path() {
    let output = command()
        .env("PYTHONOPTIMIZE", "2")
        .env("PYTHONPATH", "/nonexistent-oracle-module-path")
        .args(["-c", "import sys; assert sys.version_info[:3] == (3,14,7); assert sys.flags.optimize == 0; assert sys.flags.isolated == 1; assert '/nonexistent-oracle-module-path' not in sys.path; print('isolated')"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"isolated\n");
}
