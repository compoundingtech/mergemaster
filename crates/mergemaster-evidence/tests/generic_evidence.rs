//! Real wrapper -> isolated signer -> origin -> Rust/Python verifier contracts, without Nix.
#![cfg(unix)]
#[path = "../src/pinned_python.rs"]
mod pinned_python;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const CHECK: &str = "full-check";

fn executable(program: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .filter(|directory| directory.is_absolute())
        .filter_map(|directory| fs::canonicalize(directory.join(program)).ok())
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
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
        let mut f = Self {
            repo,
            origin: root.path().join("origin.git"),
            config: root.path().join("sign.json"),
            dependency: root.path().join("dependency"),
            counter: root.path().join("executions"),
            runtime: executable("sh"),
            root,
            base: String::new(),
            head: String::new(),
        };
        f.git(&["init", "-q"]);
        let key = f.root.path().join("key");
        let output = f
            .command("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::write(&f.dependency, b"immutable external dependency\n").unwrap();
        // Supply only canonical trusted-tool directories, not agent/harness PATH wrappers.
        let tool_dirs: std::collections::BTreeSet<_> = ["git", "ssh-keygen"]
            .into_iter()
            .map(|program| executable(program).parent().unwrap().to_path_buf())
            .collect();
        let signer_path = std::env::join_paths(tool_dirs).unwrap();
        fs::write(
            &f.config,
            json!({"version":1,"signer":"agent/fixture","ssh_key":key,
            "path":signer_path.to_str().unwrap(),
            "toolchain":{"runtime":f.runtime,"dependencies":{"fixture":f.dependency}}})
            .to_string(),
        )
        .unwrap();
        fs::set_permissions(&f.config, fs::Permissions::from_mode(0o600)).unwrap();
        f.write(
            ".mergemaster/evidence-keys",
            format!(
                "agent/fixture {}",
                fs::read_to_string(key.with_extension("pub")).unwrap()
            ),
        );
        f.write(".mergemaster/tool-pin.json", json!({"version":1,"repository":"compoundingtech/mergemaster","revision":"a".repeat(40)}).to_string());
        let artifact = |name: &str, path: &Path| json!({"name":name,"identity":format!("sha256:{}",hex::encode(Sha256::digest(fs::read(path).unwrap())))});
        let system = format!(
            "{}-{}",
            std::env::consts::ARCH,
            if cfg!(target_os = "macos") {
                "darwin"
            } else {
                "linux"
            }
        );
        f.write(".mergemaster/environment.json", json!({"version":1,"systems":{system:
            {"runtime":artifact("shell", &f.runtime),"dependencies":{"fixture":artifact("fixture", &f.dependency)}}}}).to_string());
        f.write(".mergemaster/lanes.json", json!({"version":1,
            "pull_request":{"same_repository":true,"authors":{"mode":"none"},"base_relation":"ancestor"},
            "protected_paths":[],"lanes":{CHECK:{"argv":f.argv(),"definition_paths":["tools"],
                "trust_levels":["agent"],"mode":mode,"events":["pull_request"],
                "environment":{"manifest":".mergemaster/environment.json","paths":["tools","source.txt"]},
                "protected_edits":"reject","remediation_argv":["mergemaster","evidence","wrap"]}}}).to_string());
        f.write(
            "tools/check",
            format!("printf x >> \"$TEST_COUNTER\"\n{script}\n"),
        );
        f.write("source.txt", "base\n");
        f.base = f.commit();
        f.git(&["update-ref", "refs/heads/gate-base", &f.base]);
        f.write("source.txt", "candidate\n");
        f.head = f.commit();
        assert!(
            f.command("git")
                .args(["init", "--bare", "-q"])
                .arg(&f.origin)
                .output()
                .unwrap()
                .status
                .success()
        );
        f.git(&["remote", "add", "origin", f.origin.to_str().unwrap()]);
        f.git(&[
            "-c",
            "protocol.file.allow=always",
            "push",
            "-q",
            "origin",
            "HEAD:refs/heads/main",
        ]);
        f
    }
    fn argv(&self) -> Vec<String> {
        vec![self.runtime.to_str().unwrap().into(), "tools/check".into()]
    }
    fn command(&self, executable: impl AsRef<std::ffi::OsStr>) -> Command {
        self.configured(Command::new(executable))
    }
    fn oracle_command(&self) -> Command {
        self.configured(pinned_python::command())
    }
    fn configured(&self, mut c: Command) -> Command {
        c.current_dir(&self.repo)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", self.root.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GITHUB_REPOSITORY", "fixture/repo")
            .env("TEST_COUNTER", &self.counter)
            .env("LC_ALL", "C");
        c
    }
    fn git(&self, args: &[&str]) -> String {
        let out = self
            .command("git")
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
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
        self.wrap_repository(None, signer, argv)
    }
    fn wrap_repository(
        &self,
        repository: Option<&str>,
        signer: Option<Value>,
        argv: Option<Vec<String>>,
    ) -> Output {
        let signer = signer.unwrap_or_else(|| {
            json!([
                mergemaster_bin(),
                "evidence",
                "sign",
                "--config",
                self.config
            ])
        });
        let mut command = self.command(mergemaster_bin());
        command
            .args([
                "evidence", "wrap", "--check", CHECK, "--base", &self.base, "--config",
            ])
            .arg(&self.config);
        if let Some(repository) = repository {
            command.args(["--repository", repository]);
        }
        command
            .args(["--signer", &signer.to_string(), "--"])
            .args(argv.unwrap_or_else(|| self.argv()))
            .output()
            .unwrap()
    }
    fn gate(&self) -> Value {
        let output = self
            .command(mergemaster_bin())
            .args([
                "gate", "--check", CHECK, "--base", &self.base, "--head", &self.head, "--format",
                "json",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn refs(&self) -> String {
        self.git(&[
            "for-each-ref",
            "--format=%(refname)",
            "refs/notes/evidence/",
        ])
    }
    fn python(&self) -> Output {
        self.oracle_command()
            .arg(
                PathBuf::from(
                    std::env::var_os("MERGEMASTER_PYTHON_ORACLE")
                        .expect("MERGEMASTER_PYTHON_ORACLE must be set; run tests in nix develop"),
                )
                .join("scripts/evidence-verify"),
            )
            .args(["--repo"])
            .arg(&self.repo)
            .args(["--revision", &self.head, "--check", CHECK, "--keys"])
            .arg(self.repo.join(".mergemaster/evidence-keys"))
            .args([
                "--command",
                &json!(self.argv()).to_string(),
                "--trust-levels",
                "agent",
            ])
            .output()
            .unwrap()
    }
}

fn materialized_fixture(script: &str) -> Fixture {
    let mut f = Fixture::new("required_evidence", script);
    f.write(".gitignore", "node_modules/\n.build/\nignored/\n");
    let modules = f.root.path().join("modules");
    fs::create_dir_all(modules.join("fixture")).unwrap();
    fs::write(modules.join("fixture/index.js"), "fixture bytes\n").unwrap();
    let digest = mergemaster_evidence::evidence::workspace::tree_digest(&modules).unwrap();
    let mut policy: Value =
        serde_json::from_slice(&fs::read(f.repo.join(".mergemaster/lanes.json")).unwrap()).unwrap();
    policy["lanes"][CHECK]["inputs"] = json!({"node_modules":{"name":"fixture modules","identity":format!("tree-sha256:{digest}")}});
    policy["lanes"][CHECK]["scratch"] = json!([".build"]);
    f.write(".mergemaster/lanes.json", policy.to_string());
    f.base = f.commit();
    f.head = f.base.clone();
    f.write("node_modules/fixture/index.js", "fixture bytes\n");
    f
}

#[test]
fn workspace_binding_is_object_only_and_binds_the_base_declaration() {
    use mergemaster_evidence::gate::config::{expected_inputs, load};
    let f = materialized_fixture("printf ok");
    let mut policy = load(&f.repo, &f.base).unwrap();
    let expected = |lane: &mergemaster_evidence::gate::config::Lane| {
        expected_inputs(
            &f.repo,
            &f.head,
            CHECK,
            lane,
            &policy.environment,
            &policy.environment_bytes,
        )
        .unwrap()
    };
    let before = expected(&policy.policy.lanes[CHECK]);
    assert_eq!(before["workspace_binding"], "v2");
    assert_eq!(before["workspace_declaration_sha256"].len(), 64);
    // Verification is independent of provisioned files, unlike wrapper/signer measurement.
    fs::remove_dir_all(f.repo.join("node_modules")).unwrap();
    assert_eq!(expected(&policy.policy.lanes[CHECK]), before);
    let mut lane = policy.policy.lanes.remove(CHECK).unwrap();
    lane.scratch = vec!["other-output".into()];
    assert_ne!(
        expected(&lane)["workspace_declaration_sha256"],
        before["workspace_declaration_sha256"]
    );
}

#[test]
fn materialized_modules_and_empty_scratch_are_lane_bound_end_to_end() {
    let f = materialized_fixture("cat node_modules/fixture/index.js > .build/result; printf ok");
    let output = f.wrap(None, None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(f.repo.join(".build/result")).unwrap(),
        b"fixture bytes\n"
    );
    assert_eq!(f.gate()["decision"], "skip");
    assert!(f.python().status.success());
    // A subsequent attempt cannot consume the previous attempt's output.
    assert!(!f.wrap(None, None).status.success());
    assert_eq!(fs::read(&f.counter).unwrap(), b"x");
}

#[cfg(unix)]
#[test]
fn measured_symlink_modules_sign_and_verify_without_materializations() {
    use mergemaster_evidence::evidence::workspace::tree_digest_v2;
    use std::os::unix::fs::symlink;

    for absolute in [false, true] {
        let mut f =
            materialized_fixture("cat node_modules/pkg/index.js > .build/result; printf ok");
        f.write(
            ".gitignore",
            "node_modules\ndependencies\n.build/\nignored/\n",
        );
        let external_modules = f.root.path().join("modules");
        let external_dependencies = f.root.path().join("dependencies");
        fs::create_dir_all(external_dependencies.join("pkg")).unwrap();
        fs::write(
            external_dependencies.join("pkg/index.js"),
            "external package\n",
        )
        .unwrap();
        symlink("../dependencies/pkg", external_modules.join("pkg")).unwrap();
        fs::remove_dir_all(f.repo.join("node_modules")).unwrap();
        let modules_target = if absolute {
            fs::canonicalize(&external_modules).unwrap()
        } else {
            "../modules".into()
        };
        symlink(modules_target, f.repo.join("node_modules")).unwrap();
        symlink(&external_dependencies, f.repo.join("dependencies")).unwrap();
        let roots = vec![f.repo.join("node_modules"), f.repo.join("dependencies")];
        let mut policy: Value =
            serde_json::from_slice(&fs::read(f.repo.join(".mergemaster/lanes.json")).unwrap())
                .unwrap();
        for root in ["node_modules", "dependencies"] {
            let digest = tree_digest_v2(&f.repo.join(root), &roots).unwrap();
            policy["lanes"][CHECK]["inputs"][root] =
                json!({"name":root,"identity":format!("tree-sha256-v2:{digest}")});
        }
        f.write(".mergemaster/lanes.json", policy.to_string());
        f.base = f.commit();
        f.head = f.base.clone();
        let output = f.wrap(None, None);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(f.repo.join(".build/result")).unwrap(),
            b"external package\n"
        );
        // Both verifiers consume committed declarations and signed evidence only.
        fs::remove_file(f.repo.join("node_modules")).unwrap();
        fs::remove_file(f.repo.join("dependencies")).unwrap();
        fs::remove_dir_all(external_modules).unwrap();
        fs::remove_dir_all(external_dependencies).unwrap();
        fs::remove_dir_all(f.repo.join(".build")).unwrap();
        assert_eq!(f.gate()["decision"], "skip");
        assert!(f.python().status.success());
    }
}

#[test]
fn undeclared_inputs_mutations_and_signer_time_tampering_refuse() {
    for case in [
        "ignored",
        "untracked",
        "empty",
        "input",
        "scratch",
        "after",
        "outside",
        "signer",
    ] {
        let script = match case {
            "after" => "printf mutated > node_modules/fixture/index.js",
            "outside" => "mkdir -p ignored; printf output > ignored/result",
            _ => "printf ok > .build/result",
        };
        let f = materialized_fixture(script);
        match case {
            "ignored" => f.write("ignored/input", "hidden"),
            "untracked" => f.write("extra", "hidden"),
            "empty" => fs::create_dir(f.repo.join("empty")).unwrap(),
            "input" => f.write("node_modules/fixture/index.js", "changed"),
            "scratch" => f.write(".build/old", "old"),
            _ => {}
        }
        let signer = (case == "signer").then(|| {
            json!([
                f.runtime,
                "-c",
                "printf changed > node_modules/fixture/index.js; exec \"$@\"",
                "signer",
                mergemaster_bin(),
                "evidence",
                "sign",
                "--config",
                f.config
            ])
        });
        assert!(!f.wrap(signer, None).status.success(), "{case}");
        assert!(f.refs().is_empty(), "{case}");
        assert_eq!(
            f.counter.exists(),
            matches!(case, "after" | "outside" | "signer"),
            "{case}"
        );
    }
}

#[test]
fn repository_binding_is_signed_and_allowed_by_account_policy() {
    for restricted in [false, true] {
        let f = Fixture::new("required_evidence", "printf ok");
        if restricted {
            let mut config: Value = serde_json::from_slice(&fs::read(&f.config).unwrap()).unwrap();
            config["repositories"] = json!(["fixture/repo", "fixture/other"]);
            fs::write(&f.config, config.to_string()).unwrap();
        }
        let output = f.wrap_repository(Some("fixture/repo"), None, None);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&f.counter).unwrap(), b"x");
        let decision = f.gate();
        assert_eq!(decision["decision"], "skip");
        let reference = f.refs();
        assert_eq!(reference.lines().count(), 1);
        let record = f.git(&[
            "show",
            &format!("{reference}:{}", decision["tree"].as_str().unwrap()),
        ]);
        let statement: Value = serde_json::from_str(&record).unwrap();
        assert_eq!(statement["repository"], "fixture/repo");
        assert_eq!(statement["predicate"]["observed"]["runner"], "wrapper");
        assert!(statement["predicate"].get("repository").is_none());
    }
}

#[test]
fn signer_repository_allowlist_refuses_wrong_or_missing_binding() {
    for repository in [None, Some("fixture/other"), Some("Fixture/repo")] {
        let f = Fixture::new("required_evidence", "printf ok");
        let mut config: Value = serde_json::from_slice(&fs::read(&f.config).unwrap()).unwrap();
        config["repositories"] = json!(["fixture/repo"]);
        fs::write(&f.config, config.to_string()).unwrap();
        let output = f.wrap_repository(repository, None, None);
        assert!(!output.status.success(), "{repository:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("evidence signer refused"), "{stderr}");
        assert!(stderr.contains("repository"), "{stderr}");
        assert!(f.refs().is_empty(), "{repository:?}");
        assert_eq!(fs::read(&f.counter).unwrap(), b"x");
    }
}

#[test]
fn invalid_repository_binding_is_rejected_before_lane_execution() {
    for repository in ["", "fixture", "/repo", "fixture/", "fixture/repo/extra"] {
        let f = Fixture::new("required_evidence", "printf ok");
        let output = f.wrap_repository(Some(repository), None, None);
        assert!(!output.status.success(), "{repository:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("repository"), "{stderr}");
        assert!(!f.counter.exists(), "{repository:?}");
        assert!(f.refs().is_empty(), "{repository:?}");
    }
}

#[test]
fn wrap_sign_publish_skip_and_input_mutation_cannot_reuse_evidence() {
    for mode in ["required_evidence", "optional_fallback"] {
        let mut f = Fixture::new(mode, "printf 'stdout\\n'; printf 'stderr\\377\\n' >&2");
        assert!(!f.repo.join("flake.lock").exists());
        let output = f.wrap(None, None);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"stdout\nstderr\xff\n");
        assert_eq!(
            fs::read(&f.counter).unwrap(),
            b"x",
            "the lane must run exactly once"
        );
        let decision = f.gate();
        assert_eq!(decision["decision"], "skip");
        assert_eq!(decision["outcome"], "satisfied");
        let reference = f.refs();
        assert_eq!(reference.lines().count(), 1);
        let record = f
            .command("git")
            .args([
                "show",
                &format!("{reference}:{}", decision["tree"].as_str().unwrap()),
            ])
            .output()
            .unwrap();
        assert!(record.status.success());
        let statement: Value = serde_json::from_slice(&record.stdout).unwrap();
        assert_eq!(statement["predicate"]["observed"]["runner"], "wrapper");
        assert!(
            statement.get("repository").is_none(),
            "legacy wrappers must omit the optional signed repository"
        );
        let remote = f
            .command("git")
            .args(["--git-dir"])
            .arg(&f.origin)
            .args(["show-ref", "--verify", &reference])
            .output()
            .unwrap();
        assert!(
            remote.status.success(),
            "the default wrapper must publish to origin"
        );
        let digest = hex::encode(Sha256::digest(&output.stdout));
        let stored = f
            .command("git")
            .args([
                "cat-file",
                "blob",
                &format!("refs/evidence-output/{digest}"),
            ])
            .output()
            .unwrap();
        assert!(stored.status.success());
        assert_eq!(stored.stdout, output.stdout);
        let python = f.python();
        assert!(
            python.status.success(),
            "Python compatibility: {} {}",
            String::from_utf8_lossy(&python.stdout),
            String::from_utf8_lossy(&python.stderr)
        );
        f.write("source.txt", "mutated candidate input\n");
        f.head = f.commit();
        assert_eq!(
            f.gate()["decision"],
            if mode == "required_evidence" {
                "refuse"
            } else {
                "run"
            }
        );
        assert!(!f.python().status.success());
    }
}

#[test]
fn command_failure_is_signed_and_keeps_exit_code_and_output() {
    let f = Fixture::new("required_evidence", "printf 'failed\\n' >&2; exit 7");
    let output = f.wrap(None, None);
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"failed\n");
    assert_eq!(fs::read(&f.counter).unwrap(), b"x");
    assert!(!f.refs().is_empty(), "failed checks must still be signed");
    assert_eq!(f.gate()["decision"], "refuse");
    assert!(!f.python().status.success());
}

#[test]
fn externally_terminated_lanes_are_not_signed_or_stored() {
    for signal in ["HUP", "INT", "TERM", "KILL"] {
        let f = Fixture::new(
            "required_evidence",
            &format!("printf interrupted; kill -{signal} $$"),
        );
        let marker = f.root.path().join("signer-called");
        let output = f.wrap(
            Some(json!([
                f.runtime,
                "-c",
                "touch \"$1\"; exit 1",
                "signer",
                marker
            ])),
            None,
        );
        assert_eq!(output.status.code(), Some(75), "signal {signal}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr.lines().next(),
            Some("mergemaster: infra_unavailable class=interrupted")
        );
        assert!(stderr.contains("signal "));
        assert_eq!(fs::read(&f.counter).unwrap(), b"x");
        assert!(!marker.exists(), "interrupted lane contacted signer");
        assert!(f.refs().is_empty());
        assert!(
            f.git(&[
                "for-each-ref",
                "--format=%(refname)",
                "refs/evidence-output/"
            ])
            .is_empty()
        );
    }
}

#[test]
fn crash_and_resource_limit_signals_are_signed_with_signal_exit_codes() {
    for (signal, exit_code) in [("SEGV", 139), ("XCPU", 152), ("ALRM", 142)] {
        let f = Fixture::new(
            "required_evidence",
            &format!("ulimit -c 0; printf crashed; kill -{signal} $$"),
        );
        let output = f.wrap(None, None);
        assert_eq!(output.status.code(), Some(exit_code), "{signal}");
        assert_eq!(output.stdout, b"crashed");
        let record = f.refs();
        assert!(!record.is_empty());
        let tree = f.git(&["rev-parse", "HEAD^{tree}"]);
        let note = f.git(&["show", &format!("{record}:{tree}")]);
        let statement: Value = serde_json::from_str(&note).unwrap();
        assert_eq!(
            statement["predicate"]["observed"]["checks"][CHECK]["exit_code"],
            exit_code
        );
        assert_eq!(f.gate()["decision"], "refuse");
    }
}

#[test]
fn lane_exit_75_is_signed_but_wrapper_returns_1() {
    let f = Fixture::new("required_evidence", "printf failed; exit 75");
    let output = f.wrap(None, None);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"failed");
    assert_eq!(fs::read(&f.counter).unwrap(), b"x");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("infra_unavailable"));
    let record = f.refs();
    assert!(!record.is_empty());
    let tree = f.git(&["rev-parse", "HEAD^{tree}"]);
    let note = f.git(&["show", &format!("{record}:{tree}")]);
    let statement: Value = serde_json::from_str(&note).unwrap();
    assert_eq!(
        statement["predicate"]["observed"]["checks"][CHECK]["exit_code"],
        75
    );
    assert_eq!(f.gate()["decision"], "refuse");
}

#[test]
fn signer_unavailability_differs_from_explicit_policy_refusal() {
    for case in ["missing", "killed", "broken_pipe", "refusal"] {
        // A large request makes early stdin closure reliably break the write.
        let script = if case == "broken_pipe" {
            "printf '%01048576d' 0"
        } else {
            "printf ok"
        };
        let f = Fixture::new("required_evidence", script);
        let signer = match case {
            "missing" => json!([f.root.path().join("missing-signer")]),
            "killed" => json!([f.runtime, "-c", "cat >/dev/null; kill -TERM $$"]),
            "broken_pipe" => json!([f.runtime, "-c", "exec 0<&-; exit 0"]),
            "refusal" => json!([f.runtime, "-c", "cat >/dev/null; exit 1"]),
            _ => unreachable!(),
        };
        let output = f.wrap(Some(signer), None);
        if case == "refusal" {
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains("evidence signer refused"));
        } else {
            assert_eq!(output.status.code(), Some(75), "case {case}");
            assert_eq!(
                String::from_utf8_lossy(&output.stderr).lines().next(),
                Some("mergemaster: infra_unavailable class=signer_unavailable")
            );
        }
        assert!(f.refs().is_empty());
    }
}

#[test]
fn signer_refusal_wins_over_broken_stdin_but_not_signal_death() {
    for (ending, code) in [
        ("exit 1", 1),
        ("kill -SEGV $$", 75),
        ("kill -XCPU $$", 75),
        ("kill -ALRM $$", 75),
    ] {
        // Larger than the stdin pipe: this signer never reads stdin, forcing EPIPE.
        let f = Fixture::new("required_evidence", "printf '%01048576d' 0");
        let script = format!(
            "ulimit -c 0; exec 0<&-; printf 'policy denied\\n'; printf 'policy denied\\n' >&2; {ending}"
        );
        let output = f.wrap(Some(json!([f.runtime, "-c", script])), None);
        assert_eq!(output.status.code(), Some(code), "{ending}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if code == 1 {
            assert!(stderr.contains("evidence signer refused: policy denied"));
            assert!(!stderr.contains("infra_unavailable"));
        } else {
            assert_eq!(
                stderr.lines().next(),
                Some("mergemaster: infra_unavailable class=signer_unavailable")
            );
        }
        assert!(f.refs().is_empty());
    }
}

#[test]
fn preconditions_fail_before_execution() {
    for case in [
        "dirty",
        "untracked",
        "runtime",
        "dependency",
        "config_mode",
        "argv",
        "missing_signer",
    ] {
        let f = Fixture::new("required_evidence", "printf ok");
        let mut argv = None;
        match case {
            "dirty" => f.write("source.txt", "dirty"),
            "untracked" => f.write("untracked-input", "untracked"),
            "runtime" => {
                let mut value: Value =
                    serde_json::from_slice(&fs::read(&f.config).unwrap()).unwrap();
                value["toolchain"]["runtime"] = json!(f.dependency);
                fs::write(&f.config, value.to_string()).unwrap();
            }
            "dependency" => fs::write(&f.dependency, "changed dependency").unwrap(),
            "config_mode" => {
                fs::set_permissions(&f.config, fs::Permissions::from_mode(0o644)).unwrap()
            }
            "argv" => argv = Some(vec!["/bin/true".into()]),
            "missing_signer" => {
                let out = f
                    .command(mergemaster_bin())
                    .args([
                        "evidence", "wrap", "--check", CHECK, "--base", &f.base, "--config",
                    ])
                    .arg(&f.config)
                    .arg("--")
                    .args(f.argv())
                    .output()
                    .unwrap();
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
    for case in [
        "dirty_after",
        "head_after",
        "dependency_after",
        "signer_failure",
        "invalid_response",
        "push_failure",
    ] {
        let script = match case {
            "dirty_after" => "printf changed > source.txt",
            "head_after" => {
                "git -c user.name=Fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit --allow-empty -q -m changed"
            }
            "dependency_after" => "printf changed > \"$TEST_DEPENDENCY\"",
            _ => "printf 'original output\\n'",
        };
        let f = Fixture::new("required_evidence", script);
        let signer = match case {
            "signer_failure" => Some(json!([f.runtime, "-c", "cat >/dev/null; exit 1"])),
            "invalid_response" => Some(json!([f.runtime, "-c", "cat >/dev/null; printf '{}' "])),
            _ => None,
        };
        if case == "push_failure" {
            f.git(&[
                "remote",
                "set-url",
                "origin",
                f.root.path().join("absent.git").to_str().unwrap(),
            ]);
        }
        // The lane inherits the real environment, including account-local dependency setup.
        let signer = signer.unwrap_or_else(|| {
            json!([mergemaster_bin(), "evidence", "sign", "--config", f.config])
        });
        let out = f
            .command(mergemaster_bin())
            .env("TEST_DEPENDENCY", &f.dependency)
            .args([
                "evidence", "wrap", "--check", CHECK, "--base", &f.base, "--config",
            ])
            .arg(&f.config)
            .args(["--signer", &signer.to_string(), "--"])
            .args(f.argv())
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "case {case}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            fs::read(&f.counter).unwrap(),
            b"x",
            "case {case} must execute once"
        );
        if matches!(case, "signer_failure" | "invalid_response" | "push_failure") {
            assert_eq!(out.stdout, b"original output\n");
        }
        if case == "push_failure" {
            assert_eq!(out.status.code(), Some(75));
            assert_eq!(
                String::from_utf8_lossy(&out.stderr).lines().next(),
                Some("mergemaster: infra_unavailable class=publish_failed")
            );
            assert!(
                !f.refs().is_empty(),
                "local note remains after push failure"
            );
            // Retry re-executes rather than reusing the local note.
            f.git(&["remote", "set-url", "origin", f.origin.to_str().unwrap()]);
            let retried = f.wrap(None, None);
            assert!(retried.status.success());
            assert_eq!(fs::read(&f.counter).unwrap(), b"xx");
        } else {
            assert_eq!(out.status.code(), Some(1), "case {case}");
            assert!(f.refs().is_empty(), "case {case} published evidence");
        }
    }
}

#[test]
fn signer_independently_rejects_forged_requests_and_unsafe_configuration() {
    use mergemaster_evidence::gate::config::{expected_inputs, load};
    use std::{io::Write, process::Stdio};
    for case in [
        "digest",
        "argv",
        "malformed",
        "repo_config",
        "symlink_config",
        "loader",
        "dependency",
    ] {
        let f = Fixture::new("required_evidence", "printf ok");
        let policy = load(&f.repo, &f.base).unwrap();
        let mut inputs = expected_inputs(
            &f.repo,
            &f.head,
            CHECK,
            &policy.policy.lanes[CHECK],
            &policy.environment,
            &policy.environment_bytes,
        )
        .unwrap();
        for (key, value) in [
            ("workspace_clean", "true"),
            ("untracked_files", "false"),
            ("attempt", "1"),
        ] {
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
        let bytes = if case == "malformed" {
            b"{".to_vec()
        } else {
            serde_json::to_vec(&request).unwrap()
        };
        let mut command = f.command(mergemaster_bin());
        command.args(["evidence", "sign", "--config"]).arg(config);
        if case == "loader" {
            command.env("PYTHONPATH", "/untrusted");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Loader/configuration refusal may close stdin before reading the request.
        if let Err(error) = child.stdin.take().unwrap().write_all(&bytes) {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success(), "signer accepted {case}");
        assert!(
            output.stdout.is_empty(),
            "signer returned a usable response for {case}"
        );
        assert!(f.refs().is_empty());
        assert!(!f.counter.exists(), "signer must not execute the lane");
    }
}

fn mergemaster_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var_os("CARGO_BIN_EXE_mergemaster")
            .expect("CARGO_BIN_EXE_mergemaster is set at test runtime"),
    )
}
