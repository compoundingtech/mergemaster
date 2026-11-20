use super::*;
use serde_json::{Value, json};
fn python(script: &str, args: &[&std::ffi::OsStr]) -> Vec<Value> {
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
#[test]
fn committed_manifest_and_configuration_match_oracle() {
    if let Ok(repo) = std::env::var("MM_ALT_REPO") {
        let tree = std::env::var("MM_ALT_TREE").unwrap();
        let source = TreeSource {
            repo: Path::new(&repo),
            tree: &tree,
            no_lazy_fetch: true,
        };
        assert!(source.manifest("").unwrap().contains_key("package"));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    run(&["init"]);
    for (name, text) in [
        ("Cargo.toml", "[package]\nname='fixture'".into()),
        ("bad/Cargo.toml", "[a".into()),
        ("key/Cargo.toml", format!("{}=1", vec!["x"; 1001].join("."))),
        ("int/Cargo.toml", format!("x={}", "9".repeat(4301))),
        (
            "depth/Cargo.toml",
            format!("x={}0{}", "[".repeat(257), "]".repeat(257)),
        ),
        ("bytes/Cargo.toml", format!("#{}", " ".repeat(1_048_576))),
        (
            "nodes/Cargo.toml",
            format!("x=[{}]", vec!["0"; 262_143].join(",")),
        ),
        (".st/rust-test-inputs.json", "{}".into()),
    ] {
        let path = repo.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    std::fs::create_dir(repo.join("utf")).unwrap();
    std::fs::write(repo.join("utf/Cargo.toml"), b"\xff").unwrap();
    run(&["add", "."]);
    let old = run(&["write-tree"]);
    std::fs::create_dir(repo.join(".fractal")).unwrap();
    std::fs::write(repo.join(".fractal/rust-test-inputs.json"), b"malformed").unwrap();
    run(&["add", "."]);
    let new = run(&["write-tree"]);
    let oracle = crate::pinned_python::keys_oracle();
    let cases = python(
        r#"
import json,runpy,sys,types
m=types.SimpleNamespace(**runpy.run_path(sys.argv[1])); out=[]; repo=sys.argv[2]
for tree in sys.argv[3:]:
 for directory in ['','.','bad','utf','missing','key','int','depth','bytes','nodes']:
  try: m.manifest(repo,tree,directory); result=dict(ok=True)
  except Exception as e: result=dict(error=str(e),kind='Failure' if isinstance(e,m.Failure) else type(e).__name__)
  out.append(dict(tree=tree,directory=directory,result=result,config=m.config_path(repo,tree,m.INPUTS_PATH)))
print(json.dumps(out))
"#,
        &[
            oracle.as_os_str(),
            repo.as_os_str(),
            old.as_ref(),
            new.as_ref(),
        ],
    );
    for case in cases {
        let source = TreeSource {
            repo,
            tree: case["tree"].as_str().unwrap(),
            no_lazy_fetch: false,
        };
        let result = match source.manifest(case["directory"].as_str().unwrap()) {
            Ok(_) => json!({"ok":true}),
            Err(e) => {
                json!({"error":e.detail.to_string(),"kind":match e.origin { ErrorOrigin::Failure=>"Failure",ErrorOrigin::Exception{class}=>class }})
            }
        };
        if let Some(message) = match case["directory"].as_str().unwrap() {
            "depth" => Some("TOML container depth exceeds 256"),
            "bytes" => Some("TOML source exceeds 1048576 bytes"),
            "nodes" => Some("TOML node count exceeds 262144"),
            _ => None,
        } {
            assert_eq!(case["result"], json!({"ok":true})); // Approved #257 divergence.
            assert_eq!(
                result,
                json!({"kind":"Failure","error":format!("{}/Cargo.toml: {message}",case["directory"].as_str().unwrap())})
            );
            continue;
        }
        assert_eq!(result, case["result"]);
        assert_eq!(
            json!(source.config_path(INPUTS_PATH).unwrap()),
            case["config"]
        );
        assert_eq!(source.resolve().unwrap(), source.tree);
    }
    assert_eq!(
        TreeSource {
            repo,
            tree: "missing",
            no_lazy_fetch: false
        }
        .resolve()
        .unwrap_err()
        .detail
        .to_string(),
        "missing is not a tree"
    );
    let reader = tempfile::tempdir().unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(reader.path())
            .arg("init")
            .output()
            .unwrap()
            .status
            .success()
    );
    let out=Command::new(std::env::current_exe().unwrap()).args(["--exact","evidence::legacy_verify::crate_inputs::tests::committed_manifest_and_configuration_match_oracle"])
        .env("MM_ALT_REPO",reader.path()).env("MM_ALT_TREE",old).env("GIT_ALTERNATE_OBJECT_DIRECTORIES",repo.join(".git/objects")).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
