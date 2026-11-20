#[path = "../src/pinned_python.rs"]
mod pinned_python;
use std::{
    fs,
    os::unix::{fs::{symlink, MetadataExt, PermissionsExt}, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    io::Write,
};
use tempfile::TempDir;

#[derive(Clone, Copy, Debug)]
enum Implementation { Oracle, Rust }

impl Implementation {
    fn command(self) -> Command {
        match self {
            Self::Oracle => {
                let mut command = pinned_python::command();
                command.arg(PathBuf::from(std::env::var_os("MERGEMASTER_PYTHON_ORACLE")
                    .expect("independent pinned oracle root")).join("scripts/evidence-keygen"));
                command
            }
            Self::Rust => {
                let mut command = Command::new(env!("CARGO_BIN_EXE_mergemaster"));
                command.args(["evidence", "keygen"]);
                command
            }
        }
    }
}

const BOTH: [Implementation; 2] = [Implementation::Oracle, Implementation::Rust];

fn run(implementation: Implementation, home: &Path, args: &[&str]) -> Output {
    implementation.command().args(args).arg("--home").arg(home)
        .env("HOME", home).output().unwrap()
}

fn success(output: &Output) {
    assert!(output.status.success(), "{output:?}");
}

fn refusal(output: &Output, code: i32, diagnostic: &str) {
    assert_eq!(output.status.code(), Some(code), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains(diagnostic), "{output:?}");
}

fn provision(implementation: Implementation, home: &Path) -> Output {
    let output = run(implementation, home, &["--name", "box-1"]);
    success(&output);
    output
}

fn mode(path: &Path) -> u32 { fs::metadata(path).unwrap().mode() & 0o777 }
fn chmod(path: &Path, mode: u32) { fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap(); }

// Contents, timestamps and full modes, including every scratch-repository file.
fn snapshot(path: &Path) -> Vec<(PathBuf, Vec<u8>, i64, i64, u32)> {
    let mut result = Vec::new();
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() { result.extend(snapshot(&path)); }
        else {
            let metadata = fs::metadata(&path).unwrap();
            result.push((path.clone(), fs::read(path).unwrap(), metadata.mtime(), metadata.mtime_nsec(), metadata.mode()));
        }
    }
    result.sort();
    result
}

#[test]
fn creates_private_key_scratch_and_signer_configuration() {
    for implementation in BOTH {
        let home = TempDir::new().unwrap();
        provision(implementation, home.path());
        let directory = home.path().join(".config/st");
        let key = directory.join("evidence-sign-key");
        assert_eq!(mode(&directory), 0o700);
        for name in ["evidence-sign-key", "evidence-sign.json"] { assert_eq!(mode(&directory.join(name)), 0o600); }
        let config: serde_json::Value = serde_json::from_slice(&fs::read(directory.join("evidence-sign.json")).unwrap()).unwrap();
        assert_eq!(config, serde_json::json!({"signer": "host/box-1", "ssh_key": key, "scratch_repo": directory.join("evidence-sign-scratch.git")}));
        for name in ["ssh_key", "scratch_repo"] { assert!(Path::new(config[name].as_str().unwrap()).is_absolute()); }
        assert!(directory.join("evidence-sign-scratch.git/HEAD").exists());
    }
}

#[test]
fn enrollment_line_verifies_a_real_signature() {
    for implementation in BOTH {
        let home = TempDir::new().unwrap();
        let output = provision(implementation, home.path());
        let line = String::from_utf8(output.stdout).unwrap();
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(&fields[..3], &["host/box-1", "namespaces=\"git\"", "ssh-ed25519"]);
        assert_eq!(fields.len(), 4);
        let allowed = home.path().join("allowed");
        let message = home.path().join("message");
        fs::write(&allowed, line).unwrap();
        fs::write(&message, "hello").unwrap();
        success(&Command::new("ssh-keygen").args(["-Y", "sign", "-q", "-f"])
            .arg(home.path().join(".config/st/evidence-sign-key")).args(["-n", "git"]).arg(&message).output().unwrap());
        let mut child = Command::new("ssh-keygen").args(["-Y", "verify", "-f"]).arg(allowed)
            .args(["-I", "host/box-1", "-n", "git", "-s"]).arg(home.path().join("message.sig"))
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"hello").unwrap();
        success(&child.wait_with_output().unwrap());
    }
}

#[test]
fn agent_principal_cannot_switch_levels() {
    for implementation in BOTH {
        let home = TempDir::new().unwrap();
        let output = run(implementation, home.path(), &["--name", "seat-one", "--level", "agent"]);
        success(&output);
        assert!(output.stdout.starts_with(b"agent/seat-one namespaces=\"git\" ssh-ed25519 "));
        let config: serde_json::Value = serde_json::from_slice(&fs::read(home.path().join(".config/st/evidence-sign.json")).unwrap()).unwrap();
        assert_eq!(config["signer"], "agent/seat-one");
        refusal(&run(implementation, home.path(), &["--name", "seat-one"]), 1, "differs");
        refusal(&run(implementation, home.path(), &["--name", "seat-one", "--level", "fleet"]), 2, "fleet");
    }
}

#[test]
fn repeat_is_byte_and_metadata_preserving() {
    for implementation in BOTH {
        let home = TempDir::new().unwrap();
        let first = provision(implementation, home.path());
        let directory = home.path().join(".config/st");
        let before = snapshot(&directory);
        let second = provision(implementation, home.path());
        assert_eq!(first.stdout, second.stdout);
        assert_eq!(before, snapshot(&directory));
    }
}

#[test]
fn conflicting_configuration_and_bad_names_are_refused() {
    for implementation in BOTH {
        let home = TempDir::new().unwrap();
        provision(implementation, home.path());
        let path = home.path().join(".config/st/evidence-sign.json");
        let before = fs::read(&path).unwrap();
        refusal(&run(implementation, home.path(), &["--name", "box-2"]), 1, "differs");
        assert_eq!(before, fs::read(path).unwrap());
        for bad in ["Box", "a/b", "", "-x", "a b", &"x".repeat(41)] {
            refusal(&run(implementation, home.path(), &[&format!("--name={bad}")]), 1, "must be lowercase");
        }
    }
}

#[test]
fn permissions_ignore_caller_umask() {
    for implementation in BOTH {
        let home = TempDir::new().unwrap();
        let mut command = implementation.command();
        command.args(["--name", "box-1", "--home"]).arg(home.path());
        // SAFETY: only the forked child changes its process mask before exec.
        unsafe { command.pre_exec(|| { libc::umask(0); Ok(()) }); }
        success(&command.output().unwrap());
        let directory = home.path().join(".config/st");
        assert_eq!(mode(&directory), 0o700);
        assert_eq!(mode(&home.path().join(".config")) & 0o077, 0);
        for name in ["evidence-sign-key", "evidence-sign.json"] { assert_eq!(mode(&directory.join(name)), 0o600); }
    }
}

#[test]
fn symlink_targets_are_never_followed_or_chmodded() {
    for implementation in BOTH {
        let home = TempDir::new().unwrap();
        let elsewhere = home.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::create_dir(home.path().join(".config")).unwrap();
        let directory = home.path().join(".config/st");
        symlink(&elsewhere, &directory).unwrap();
        refusal(&run(implementation, home.path(), &["--name", "box-1"]), 1, "symlink");
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
        fs::remove_file(&directory).unwrap();
        provision(implementation, home.path());
        for name in ["evidence-sign-key", "evidence-sign.json"] {
            let real = directory.join(name);
            let moved = elsewhere.join(name);
            fs::rename(&real, &moved).unwrap();
            symlink(&moved, &real).unwrap();
            let before = fs::metadata(&moved).unwrap().mode();
            refusal(&run(implementation, home.path(), &["--name", "box-1"]), 1, "symlink");
            assert_eq!(fs::metadata(&moved).unwrap().mode(), before);
            fs::remove_file(&real).unwrap();
            fs::rename(moved, real).unwrap();
        }
    }
}

#[test]
fn reuses_private_key_not_planted_public_key_and_never_repairs_it() {
    for implementation in BOTH {
        let home = TempDir::new().unwrap();
        let first = provision(implementation, home.path());
        let key = home.path().join(".config/st/evidence-sign-key");
        fs::write(key.with_extension("pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlantedPlantedPlantedPlantedPlantedPlantedPlan planted\n").unwrap();
        assert_eq!(provision(implementation, home.path()).stdout, first.stdout);
        chmod(&key, 0o644);
        refusal(&run(implementation, home.path(), &["--name", "box-1"]), 1, "mode 644");
        assert_eq!(mode(&key), 0o644);
        chmod(&key, 0o600);
        fs::write(key, "not a key\n").unwrap();
        refusal(&run(implementation, home.path(), &["--name", "box-1"]), 1, "failed");
    }
}

#[test]
fn home_requires_absolute_account_path_or_explicit_override() {
    for implementation in BOTH {
        let home = TempDir::new().unwrap();
        for bad in ["", "relative/dir"] {
            refusal(&implementation.command().args(["--name", "box-1"]).env("HOME", bad).output().unwrap(), 1, "HOME must be set to an absolute path");
        }
        let missing = implementation.command().args(["--name", "box-1"]).env_remove("HOME").output().unwrap();
        refusal(&missing, 1, "HOME must be set to an absolute path");
        assert!(!String::from_utf8_lossy(&missing.stderr).contains("Traceback"));
        refusal(&implementation.command().args(["--name", "box-1"]).env("HOME", home.path()).output().unwrap(), 1, "is not this account's home");
        assert!(!home.path().join(".config").exists());
        refusal(&implementation.command().args(["--name", "box-1", "--home", "relative"]).output().unwrap(), 1, "--home must be an absolute path");
    }
}

#[test]
fn name_is_required_without_creating_configuration() {
    for implementation in BOTH {
        let home = TempDir::new().unwrap();
        refusal(&run(implementation, home.path(), &[]), 2, "--name");
        assert!(!home.path().join(".config").exists());
    }
}

#[test]
fn wrong_file_kinds_preserve_existing_targets() {
    for implementation in BOTH {
        for (target, kind) in [("evidence-sign-scratch.git", "symlink"), ("evidence-sign-key", "directory"),
            ("evidence-sign-scratch.git", "file"), ("evidence-sign.json", "directory")] {
            let home = TempDir::new().unwrap();
            let directory = home.path().join(".config/st");
            fs::create_dir_all(&directory).unwrap();
            chmod(&directory, 0o700);
            let outside = home.path().join("outside");
            fs::create_dir(&outside).unwrap();
            let path = directory.join(target);
            match kind {
                "symlink" => symlink(&outside, &path).unwrap(),
                "directory" => fs::create_dir(&path).unwrap(),
                _ => fs::write(&path, "untouched").unwrap(),
            }
            refusal(&run(implementation, home.path(), &["--name", "box-1"]), 1, if kind == "symlink" { "symlink" } else { "kind of file" });
            assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
            if kind == "file" { assert_eq!(fs::read_to_string(path).unwrap(), "untouched"); }
        }
    }
}

#[test]
fn loose_directory_and_configuration_modes_are_not_repaired() {
    for implementation in BOTH {
        for (target, loose) in [("", 0o755), ("evidence-sign.json", 0o644)] {
            let home = TempDir::new().unwrap();
            provision(implementation, home.path());
            let path = home.path().join(".config/st").join(target);
            chmod(&path, loose);
            refusal(&run(implementation, home.path(), &["--name", "box-1"]), 1, if target.is_empty() { "chmod 700" } else { "mode 644" });
            assert_eq!(mode(&path), loose);
        }
    }
}

#[test]
fn cross_implementation_reuse_preserves_exact_output_and_all_files() {
    for (first, second) in [(Implementation::Oracle, Implementation::Rust), (Implementation::Rust, Implementation::Oracle)] {
        for (prefix, suffix) in [("", ""), ("", "/."), ("", "//"), ("/", ""), ("//", ""), ("", "/nested/..")] {
            let home = TempDir::new().unwrap();
            fs::create_dir(home.path().join("nested")).unwrap();
            let spelling = PathBuf::from(format!("{prefix}{}{suffix}", home.path().display()));
            let before = provision(first, &spelling);
            let directory = home.path().join(".config/st");
            let files = snapshot(&directory);
            let after = provision(second, &spelling);
            assert_eq!((after.status.code(), after.stdout, after.stderr), (before.status.code(), before.stdout, before.stderr));
            assert_eq!(files, snapshot(&directory));
        }
    }
}

#[test]
fn frozen_keygen_recordings_match_pinned_oracle_and_rust() {
    use base64::Engine;
    use sha1::{Digest, Sha1};
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/oracle/keygen.json"
    )).unwrap();
    let source = PathBuf::from(std::env::var_os("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .join(fixture["oracle"]["path"].as_str().unwrap());
    let bytes = fs::read(source).unwrap();
    let mut hash = Sha1::new();
    hash.update(format!("blob {}\0", bytes.len()));
    hash.update(bytes);
    assert_eq!(hex::encode(hash.finalize()), fixture["oracle"]["git_blob"]);
    for implementation in BOTH {
        let home = TempDir::new().unwrap();
        let directory = home.path().join(".config/st");
        fs::create_dir_all(&directory).unwrap();
        chmod(&directory, 0o700);
        let key = directory.join("evidence-sign-key");
        fs::write(&key, base64::engine::general_purpose::STANDARD.decode(
            fixture["public_test_private_key_base64"].as_str().unwrap()
        ).unwrap()).unwrap();
        chmod(&key, 0o600);
        for case in fixture["cases"].as_array().unwrap() {
            let id = case["id"].as_str().unwrap();
            if id == "agent-0" { fs::remove_file(directory.join("evidence-sign.json")).unwrap(); }
            let before = id.ends_with("-1").then(|| snapshot(&directory));
            let expand = |value: &str| value.replace("${home}", home.path().to_str().unwrap());
            let args: Vec<_> = case["argv"].as_array().unwrap().iter()
                .map(|value| expand(value.as_str().unwrap())).collect();
            let output = implementation.command().args(args)
                .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
                .stdin(Stdio::null()).output().unwrap();
            assert_eq!(output.status.code().map(i64::from), case["exit_code"].as_i64(), "{id}");
            assert_eq!(output.stdout, expand(case["stdout"].as_str().unwrap()).as_bytes(), "{id}");
            assert_eq!(output.stderr, expand(case["stderr"].as_str().unwrap()).as_bytes(), "{id}");
            assert_eq!(mode(&directory), 0o700);
            assert_eq!(mode(&key), 0o600);
            assert_eq!(mode(&directory.join("evidence-sign.json")), 0o600);
            if let Some(before) = before { assert_eq!(before, snapshot(&directory), "{id}"); }
        }
    }
}
