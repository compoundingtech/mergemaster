//! One isolated, version-checked interpreter for Python oracle fixtures.
use std::{os::unix::ffi::OsStringExt, path::PathBuf, process::Command, sync::LazyLock};

/// Resolve and validate once, then isolate every oracle process from Python env/site settings.
pub(crate) fn command() -> Command {
    static INTERPRETER: LazyLock<PathBuf> = LazyLock::new(|| {
        let output = Command::new("python3")
            .args([
                "-I",
                "-c",
                "import os,sys; assert sys.version_info[:3] == (3,14,7), sys.version; assert sys.flags.optimize == 0; sys.stdout.buffer.write(os.fsencode(sys.executable))",
            ])
            .output()
            .expect("resolve pinned Python 3.14.7 in the repository shell");
        assert!(
            output.status.success(),
            "pinned Python: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output.stdout.is_empty(),
            "Python interpreter path is empty"
        );
        PathBuf::from(std::ffi::OsString::from_vec(output.stdout))
    });
    let mut command = Command::new(&*INTERPRETER);
    command.arg("-I");
    command
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
