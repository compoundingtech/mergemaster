use super::*;
use serde_json::{Value, json};
use std::process::Command;

const REVISION: &str = "1234567890abcdef1234567890abcdef12345678";

struct Fixture {
    root: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            root: tempfile::tempdir().unwrap(),
        };
        fixture.git(&["init", "--quiet"]);
        fixture.git(&["config", "user.name", "Tool Pin Tests"]);
        fixture.git(&["config", "user.email", "tool-pin@example.invalid"]);
        fixture
    }
    fn path(&self) -> &Path {
        self.root.path()
    }
    fn git(&self, args: &[&str]) -> String {
        let result = Command::new("git")
            .arg("-C")
            .arg(self.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap().trim().into()
    }
    fn tree(&self, bytes: Option<&[u8]>) -> String {
        let directory = self.path().join(".mergemaster");
        std::fs::create_dir_all(&directory).unwrap();
        if let Some(bytes) = bytes {
            std::fs::write(directory.join("tool-pin.json"), bytes).unwrap();
        }
        self.git(&["add", "--all"]);
        self.git(&["write-tree"])
    }
    fn verify(&self, base: &str) -> Result<Value, PolicyError> {
        let mut output = String::new();
        verify(self.path(), TextRef::Str(base), &mut output)?;
        Ok(serde_json::from_str(&output).unwrap())
    }
}

fn running_identity() -> Value {
    let mut output = String::new();
    identity(&mut output).unwrap();
    serde_json::from_str(&output).unwrap()
}
fn pin(identity: &Value, revision: &str) -> Value {
    json!({
        "version": 1,
        "repository": identity["repository"],
        "revision": revision,
        "release": {
            "version": identity["version"],
            "sha256": identity["binary_sha256"]
        }
    })
}

#[test]
fn wave2_a2_identity_has_only_observable_release_fields() {
    let identity = running_identity();
    assert_eq!(identity.as_object().unwrap().len(), 3);
    assert_eq!(identity["repository"], "compoundingtech/mergemaster");
    assert_eq!(identity["version"], concat!("v", env!("CARGO_PKG_VERSION")));
    assert_eq!(
        identity["binary_sha256"],
        source::running_binary_sha256().unwrap()
    );
    assert_eq!(identity["binary_sha256"].as_str().unwrap().len(), 64);
    assert!(identity.get("revision").is_none());
}

#[test]
fn wave2_a2_nested_pin_roundtrips_from_base_tree_and_hashes_raw_bytes() {
    let fixture = Fixture::new();
    let identity = running_identity();
    let bytes = format!(
        "{}\n\n",
        serde_json::to_string_pretty(&pin(&identity, REVISION)).unwrap()
    );
    let tree = fixture.tree(Some(bytes.as_bytes()));
    // A treeish expression, rather than only a commit or raw object ID, is accepted.
    let base = fixture.git(&["commit-tree", &tree, "-m", "base"]);
    let head = fixture.git(&["commit-tree", &tree, "-p", &base, "-m", "head"]);
    fixture.git(&["update-ref", "refs/heads/pin-test", &head]);
    // The working tree must not supply the pin being verified.
    std::fs::write(
        fixture.path().join(".mergemaster/tool-pin.json"),
        b"invalid",
    )
    .unwrap();
    let verified = fixture.verify("refs/heads/pin-test~1^{tree}").unwrap();
    assert_eq!(
        verified,
        json!({
            "repository": identity["repository"],
            "revision": REVISION,
            "version": identity["version"],
            "binary_sha256": identity["binary_sha256"],
            "tool_pin_sha256": hex::encode(Sha256::digest(bytes.as_bytes()))
        })
    );
}

#[test]
fn wave2_a2_tool_pin_accepts_non_utf8_repository_and_base_arguments() {
    use std::ffi::OsString;
    use std::os::unix::{ffi::OsStringExt, fs::symlink};

    let fixture = Fixture::new();
    let bytes = serde_json::to_vec(&pin(&running_identity(), REVISION)).unwrap();
    let tree = fixture.tree(Some(&bytes));
    let raw_ref = OsString::from_vec(b"refs/tags/pin-\xff".to_vec());
    let status = Command::new("git")
        .arg("-C")
        .arg(fixture.path())
        .arg("update-ref")
        .arg(&raw_ref)
        .arg(&tree)
        .status()
        .unwrap();
    assert!(status.success());
    let alias = fixture
        .path()
        .join(OsString::from_vec(b"repo-\xff".to_vec()));
    symlink(fixture.path(), &alias).unwrap();
    let result = super::super::cli_helper::run(
        [
            OsString::from("verify-tool-pin"),
            OsString::from("--repo"),
            alias.into_os_string(),
            OsString::from("--base"),
            raw_ref,
        ],
        &mut &b""[..],
    )
    .unwrap();
    assert_eq!(result.code, 0, "{}", result.stdout);
    assert_eq!(
        serde_json::from_str::<Value>(&result.stdout).unwrap(),
        fixture.verify(&tree).unwrap()
    );
}

#[test]
fn wave2_a2_missing_malformed_and_flat_pins_fail_closed() {
    let fixture = Fixture::new();
    let empty_tree = fixture.tree(None);
    assert!(fixture.verify(&empty_tree).is_err());
    for bytes in [
        b"not JSON".as_slice(),
        b"{}".as_slice(),
        br#"{"repository":"compoundingtech/mergemaster","version":"v1.0.0","binary_sha256":"abc"}"#
            .as_slice(),
    ] {
        let tree = fixture.tree(Some(bytes));
        assert!(fixture.verify(&tree).is_err());
    }
}

#[test]
fn wave2_a2_unreadable_pin_object_and_invalid_treeish_fail_closed() {
    let fixture = Fixture::new();
    let bytes = serde_json::to_vec(&pin(&running_identity(), REVISION)).unwrap();
    let tree = fixture.tree(Some(&bytes));
    let blob = fixture.git(&["rev-parse", &format!("{tree}{PIN_SUFFIX}")]);
    let object = fixture
        .path()
        .join(".git/objects")
        .join(&blob[..2])
        .join(&blob[2..]);
    std::fs::remove_file(object).unwrap();
    assert!(fixture.verify(&tree).is_err());
    assert!(fixture.verify("no-such-base").is_err());
    assert!(fixture.verify("--help").is_err());
}

#[test]
fn wave2_a2_repository_version_digest_and_revision_validation_fail_closed() {
    let fixture = Fixture::new();
    let identity = running_identity();
    for field in ["repository", "version", "digest", "revision", "schema"] {
        let mut value = pin(&identity, REVISION);
        match field {
            "repository" => value["repository"] = json!("other/mergemaster"),
            "version" => value["release"]["version"] = json!("v999999.0.0"),
            "digest" => {
                let digest = identity["binary_sha256"].as_str().unwrap();
                let replacement = if digest.starts_with('0') { "1" } else { "0" };
                value["release"]["sha256"] = json!(format!("{replacement}{}", &digest[1..]));
            }
            "revision" => value["revision"] = json!("not-a-full-lowercase-revision"),
            "schema" => value["version"] = json!(2),
            _ => unreachable!(),
        }
        let tree = fixture.tree(Some(&serde_json::to_vec(&value).unwrap()));
        assert!(fixture.verify(&tree).is_err(), "accepted {field} mismatch");
    }
}

#[test]
fn wave2_a2_valid_revision_changes_are_provenance_not_binary_mismatch_detection() {
    let fixture = Fixture::new();
    let identity = running_identity();
    for revision in [REVISION, "ffffffffffffffffffffffffffffffffffffffff"] {
        let bytes = serde_json::to_vec(&pin(&identity, revision)).unwrap();
        let tree = fixture.tree(Some(&bytes));
        let verified = fixture.verify(&tree).unwrap();
        assert_eq!(verified["revision"], revision);
        assert_eq!(verified["binary_sha256"], identity["binary_sha256"]);
    }
}
