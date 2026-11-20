//! Opt-in capture of real differential-test observations for independent review.
use serde_json::{Value, json};
use std::io::Write;

pub(crate) fn capture(id: &str, input: Value, python: Value, rust: Value) {
    record(id, input, python, rust, None);
}

pub(crate) fn capture_python_patch(id: &str, input: Value, python: Value, local: Value) {
    record(id, input, python, Value::Null, Some(local));
}

fn record(id: &str, input: Value, python: Value, rust: Value, local: Option<Value>) {
    let Some(directory) = std::env::var_os("MERGEMASTER_WITNESS_DIRECTORY") else {
        return;
    };
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    );
    let path = std::path::PathBuf::from(directory).join(format!("{id}.json"));
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return,
        Err(error) => panic!("create divergence witness {id}: {error}"),
    };
    let thread = std::thread::current();
    let mut row = json!({"id": id, "test": thread.name(), "input": input,
                         "python": python, "rust": rust, "execution_status": "observed"});
    if let Some(local) = local {
        row["comparison"] = json!("python-local-patch");
        row["local_python"] = local;
    }
    serde_json::to_writer(&mut file, &row).unwrap();
    file.write_all(b"\n").unwrap();
    println!("MERGEMASTER_WITNESS_CAPTURED {id}");
}

/// Preserve actual fixture objects, including dangling/signed commits, for replay.
pub(crate) fn git_input(repo: &std::path::Path) -> Value {
    if std::env::var_os("MERGEMASTER_WITNESS_DIRECTORY").is_none() {
        return Value::Null;
    }
    let objects = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ])
        .output()
        .unwrap();
    assert!(objects.status.success(), "{:?}", objects.stderr);
    let mut child = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["pack-objects", "--stdout"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&objects.stdout)
        .unwrap();
    let pack = child.wait_with_output().unwrap();
    assert!(pack.status.success(), "{:?}", pack.stderr);
    let refs = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["show-ref", "--head"])
        .output()
        .unwrap();
    assert!(refs.status.success() || refs.status.code() == Some(1));
    json!({"pack_hex": hex::encode(pack.stdout), "refs_hex": hex::encode(refs.stdout)})
}
