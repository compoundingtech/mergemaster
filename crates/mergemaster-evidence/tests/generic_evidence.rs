//! Real wrapper -> isolated signer -> origin -> Rust/Python verifier contracts, without Nix.
#![cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt, path::{Path, PathBuf}, process::{Command, Output}};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CHECK: &str = "full-check";

fn executable(program: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .filter(|directory| directory.is_absolute())
        .filter_map(|directory| fs::canonicalize(directory.join(program)).ok())
        .find(|path| fs::metadata(path).is_ok_and(|metadata|
            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0))
        .unwrap_or_else(|| panic!("a real {program} must be available"))
}
struct Fixture {
    root: tempfile::TempDir,
    repo: PathBuf,
    origin: PathBuf,
    config: PathBuf,
    dependency: PathBuf,
    counter: PathBuf,
    runtime: PathBuf,
    base: String,
    head: String,
}
impl Fixture {
    fn new(mode: &str, script: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let mut f = Self { repo, origin: root.path().join("origin.git"), config: root.path().join("sign.json"),
            dependency: root.path().join("dependency"), counter: root.path().join("executions"),
            runtime: executable("sh"), root, base: String::new(), head: String::new() };
        f.git(&["init", "-q"]);
        let key = f.root.path().join("key");
        let output = f.command("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        fs::write(&f.dependency, b"immutable external dependency\n").unwrap();
        // Supply only canonical trusted-tool directories, not agent/harness PATH wrappers.
        let tool_dirs: std::collections::BTreeSet<_> = ["git", "ssh-keygen"].into_iter()
            .map(|program| executable(program).parent().unwrap().to_path_buf()).collect();
        let signer_path = std::env::join_paths(tool_dirs).unwrap();
        fs::write(&f.config, json!({"version":1,"signer":"agent/fixture","ssh_key":key,
            "path":signer_path.to_str().unwrap(),
            "toolchain":{"runtime":f.runtime,"dependencies":{"fixture":f.dependency}}}).to_string()).unwrap();
        fs::set_permissions(&f.config, fs::Permissions::from_mode(0o600)).unwrap();
        f.write(".mergemaster/evidence-keys", format!("agent/fixture {}", fs::read_to_string(key.with_extension("pub")).unwrap()));
        f.write(".mergemaster/tool-pin.json", json!({"version":1,"repository":"compoundingtech/mergemaster","revision":"a".repeat(40)}).to_string());
        let artifact = |name: &str, path: &Path| json!({"name":name,"identity":format!("sha256:{}",hex::encode(Sha256::digest(fs::read(path).unwrap())))});
        let system = format!("{}-{}", std::env::consts::ARCH, if cfg!(target_os = "macos") { "darwin" } else { "linux" });
        f.write(".mergemaster/environment.json", json!({"version":1,"system":system,
            "toolchain":{"runtime":artifact("shell", &f.runtime),"dependencies":{"fixture":artifact("fixture", &f.dependency)}}}).to_string());
        f.write(".mergemaster/lanes.json", json!({"version":1,
            "pull_request":{"same_repository":true,"authors":{"mode":"none"},"base_relation":"ancestor"},
            "protected_paths":[],"lanes":{CHECK:{"argv":f.argv(),"definition_paths":["tools"],
                "trust_levels":["agent"],"mode":mode,"events":["pull_request"],
                "environment":{"manifest":".mergemaster/environment.json","paths":["tools","source.txt"]},
                "protected_edits":"reject","remediation_argv":["mergemaster","evidence","wrap"]}}}).to_string());
        f.write("tools/check", format!("printf x >> \"$TEST_COUNTER\"\n{script}\n"));
        f.write("source.txt", "base\n");
        f.base = f.commit();
        f.git(&["update-ref", "refs/heads/gate-base", &f.base]);
        f.write("source.txt", "candidate\n");
        f.head = f.commit();
        assert!(f.command("git").args(["init", "--bare", "-q"]).arg(&f.origin).output().unwrap().status.success());
        f.git(&["remote", "add", "origin", f.origin.to_str().unwrap()]);
        f.git(&["-c", "protocol.file.allow=always", "push", "-q", "origin", "HEAD:refs/heads/main"]);
        f
    }
    fn argv(&self) -> Vec<String> { vec![self.runtime.to_str().unwrap().into(), "tools/check".into()] }
    fn command(&self, executable: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut c = Command::new(executable);
        c.current_dir(&self.repo).env_clear().env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", self.root.path()).env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null").env("GITHUB_REPOSITORY", "fixture/repo")
            .env("TEST_COUNTER", &self.counter).env("LC_ALL", "C");
        c
    }
    fn git(&self, args: &[&str]) -> String {
        let out = self.command("git").args(["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"]).args(args).output().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim().into()
    }
    fn write(&self, path: &str, data: impl AsRef<[u8]>) {
        let path = self.repo.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }
    fn commit(&self) -> String {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", "fixture"]);
        self.git(&["rev-parse", "HEAD"])
    }
    fn wrap(&self, signer: Option<Value>, argv: Option<Vec<String>>) -> Output {
        let signer = signer.unwrap_or_else(|| json!([env!("CARGO_BIN_EXE_mergemaster"), "evidence", "sign", "--config", self.config]));
        self.command(env!("CARGO_BIN_EXE_mergemaster")).args(["evidence", "wrap", "--check", CHECK, "--base", &self.base, "--config"])
            .arg(&self.config).args(["--signer", &signer.to_string(), "--"]).args(argv.unwrap_or_else(|| self.argv())).output().unwrap()
    }
    fn gate(&self) -> Value {
        let output = self.command(env!("CARGO_BIN_EXE_mergemaster")).args(["gate", "--check", CHECK, "--base", &self.base,
            "--head", &self.head, "--format", "json"]).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn refs(&self) -> String { self.git(&["for-each-ref", "--format=%(refname)", "refs/notes/evidence/"]) }
    fn python(&self) -> Output {
        self.command("python3").arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/evidence-verify"))
            .args(["--repo"]).arg(&self.repo).args(["--revision", &self.head, "--check", CHECK, "--keys"])
            .arg(self.repo.join(".mergemaster/evidence-keys")).args(["--command", &json!(self.argv()).to_string(), "--trust-levels", "agent"])
            .output().unwrap()
    }
}

#[test]
fn wrap_sign_publish_skip_and_input_mutation_cannot_reuse_evidence() {
    for mode in ["required_evidence", "optional_fallback"] {
        let mut f = Fixture::new(mode, "printf 'stdout\\n'; printf 'stderr\\377\\n' >&2");
        assert!(!f.repo.join("flake.lock").exists());
        let output = f.wrap(None, None);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(output.stdout, b"stdout\nstderr\xff\n");
        assert_eq!(fs::read(&f.counter).unwrap(), b"x", "the lane must run exactly once");
        let decision = f.gate();
        assert_eq!(decision["decision"], "skip");
        assert_eq!(decision["outcome"], "satisfied");
        let reference = f.refs();
        assert_eq!(reference.lines().count(), 1);
        let remote = f.command("git").args(["--git-dir"]).arg(&f.origin).args(["show-ref", "--verify", &reference]).output().unwrap();
        assert!(remote.status.success(), "the default wrapper must publish to origin");
        let digest = hex::encode(Sha256::digest(&output.stdout));
        let stored = f.command("git").args(["cat-file", "blob", &format!("refs/evidence-output/{digest}")]).output().unwrap();
        assert!(stored.status.success());
        assert_eq!(stored.stdout, output.stdout);
        let python = f.python();
        assert!(python.status.success(), "Python compatibility: {} {}", String::from_utf8_lossy(&python.stdout), String::from_utf8_lossy(&python.stderr));
        f.write("source.txt", "mutated candidate input\n");
        f.head = f.commit();
        assert_eq!(f.gate()["decision"], if mode == "required_evidence" { "refuse" } else { "run" });
        assert!(!f.python().status.success());
    }
}

#[test]
fn command_failure_is_signed_and_keeps_exit_code_and_output() {
    let f = Fixture::new("required_evidence", "printf 'failed\\n' >&2; exit 7");
    let output = f.wrap(None, None);
    assert_eq!(output.status.code(), Some(7), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, b"failed\n");
    assert_eq!(fs::read(&f.counter).unwrap(), b"x");
    assert!(!f.refs().is_empty(), "failed checks must still be signed");
    assert_eq!(f.gate()["decision"], "refuse");
    assert!(!f.python().status.success());
}

#[test]
fn preconditions_fail_before_execution() {
    for case in ["dirty", "untracked", "runtime", "dependency", "config_mode", "argv", "missing_signer"] {
        let f = Fixture::new("required_evidence", "printf ok");
        let mut argv = None;
        match case {
            "dirty" => f.write("source.txt", "dirty"),
            "untracked" => f.write("untracked-input", "untracked"),
            "runtime" => {
                let mut value: Value = serde_json::from_slice(&fs::read(&f.config).unwrap()).unwrap();
                value["toolchain"]["runtime"] = json!(f.dependency);
                fs::write(&f.config, value.to_string()).unwrap();
            }
            "dependency" => fs::write(&f.dependency, "changed dependency").unwrap(),
            "config_mode" => fs::set_permissions(&f.config, fs::Permissions::from_mode(0o644)).unwrap(),
            "argv" => argv = Some(vec!["/bin/true".into()]),
            "missing_signer" => {
                let out = f.command(env!("CARGO_BIN_EXE_mergemaster")).args(["evidence", "wrap", "--check", CHECK,
                    "--base", &f.base, "--config"]).arg(&f.config).arg("--").args(f.argv()).output().unwrap();
                assert!(!out.status.success());
                assert!(!f.counter.exists());
                continue;
            }
            _ => unreachable!(),
        }
        let out = f.wrap(None, argv);
        assert!(!out.status.success(), "case {case}");
        assert!(!f.counter.exists(), "case {case} executed the command");
        assert!(f.refs().is_empty());
    }
}

#[test]
fn postconditions_and_signing_or_publication_fail_closed() {
    for case in ["dirty_after", "head_after", "dependency_after", "signer_failure", "invalid_response", "push_failure"] {
        let script = match case {
            "dirty_after" => "printf changed > source.txt",
            "head_after" => "git -c user.name=Fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit --allow-empty -q -m changed",
            "dependency_after" => "printf changed > \"$TEST_DEPENDENCY\"",
            _ => "printf 'original output\\n'",
        };
        let f = Fixture::new("required_evidence", script);
        let signer = match case {
            "signer_failure" => Some(json!(["/bin/false"])),
            "invalid_response" => Some(json!([f.runtime, "-c", "cat >/dev/null; printf '{}' "])),
            _ => None,
        };
        if case == "push_failure" { f.git(&["remote", "set-url", "origin", f.root.path().join("absent.git").to_str().unwrap()]); }
        // The lane inherits the real environment, including account-local dependency setup.
        let signer = signer.unwrap_or_else(|| json!([env!("CARGO_BIN_EXE_mergemaster"), "evidence", "sign", "--config", f.config]));
        let out = f.command(env!("CARGO_BIN_EXE_mergemaster")).env("TEST_DEPENDENCY", &f.dependency)
            .args(["evidence", "wrap", "--check", CHECK, "--base", &f.base, "--config"]).arg(&f.config)
            .args(["--signer", &signer.to_string(), "--"]).args(f.argv()).output().unwrap();
        assert!(!out.status.success(), "case {case}: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(fs::read(&f.counter).unwrap(), b"x", "case {case} must execute once");
        if matches!(case, "signer_failure" | "invalid_response" | "push_failure") { assert_eq!(out.stdout, b"original output\n"); }
        if case != "push_failure" { assert!(f.refs().is_empty(), "case {case} published evidence"); }
    }
}

#[test]
fn signer_independently_rejects_forged_requests_and_unsafe_configuration() {
    use std::{io::Write, process::Stdio};
    use mergemaster_evidence::gate::config::{load, expected_inputs};
    for case in ["digest", "argv", "malformed", "repo_config", "symlink_config", "loader", "dependency"] {
        let f = Fixture::new("required_evidence", "printf ok");
        let policy = load(&f.repo, &f.base).unwrap();
        let mut inputs = expected_inputs(&f.repo, &f.head, CHECK, &policy.policy.lanes[CHECK],
            &policy.environment, &policy.environment_bytes).unwrap();
        for (key, value) in [("workspace_clean", "true"), ("untracked_files", "false"), ("attempt", "1")] {
            inputs.insert(key.into(), value.into());
        }
        inputs.insert("wrapper_sha256".into(), "a".repeat(64));
        let mut request = json!({"version":1,"repo":f.repo,"base":f.base,"head":f.head,"check":CHECK,
            "command":f.argv(),"exit_code":0,"output":"","inputs":inputs});
        let mut config = f.config.clone();
        match case {
            "digest" => request["inputs"]["environment_sha256"] = json!("0".repeat(64)),
            "argv" => request["command"] = json!(["/bin/true"]),
            "repo_config" => {
                config = f.repo.join("local-sign.json");
                fs::copy(&f.config, &config).unwrap();
                // Keep the checkout clean so the location check is the only invalid precondition.
                f.git(&["add", "local-sign.json"]);
                f.git(&["commit", "-q", "-m", "local config"]);
                request["head"] = json!(f.git(&["rev-parse", "HEAD"]));
            }
            "symlink_config" => {
                config = f.root.path().join("symlink-sign.json");
                std::os::unix::fs::symlink(&f.config, &config).unwrap();
            }
            "dependency" => fs::write(&f.dependency, "dependency drift").unwrap(),
            _ => {}
        }
        let bytes = if case == "malformed" { b"{".to_vec() } else { serde_json::to_vec(&request).unwrap() };
        let mut command = f.command(env!("CARGO_BIN_EXE_mergemaster"));
        command.args(["evidence", "sign", "--config"]).arg(config);
        if case == "loader" { command.env("PYTHONPATH", "/untrusted"); }
        let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        // Loader/configuration refusal may close stdin before reading the request.
        if let Err(error) = child.stdin.take().unwrap().write_all(&bytes) {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success(), "signer accepted {case}");
        assert!(output.stdout.is_empty(), "signer returned a usable response for {case}");
        assert!(f.refs().is_empty());
        assert!(!f.counter.exists(), "signer must not execute the lane");
    }
}
