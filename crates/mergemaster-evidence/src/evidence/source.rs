//! Retain the effective checkout as data; never execute candidate code or sign.
use super::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::DirBuilderExt,
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentity {
    pub repository: String,
    pub revision: String,
    pub release_version: String,
    pub binary_sha256: String,
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn parse_tool_pin(bytes: &[u8]) -> Result<ToolIdentity> {
    let pin: Value = serde_json::from_slice(bytes).context("tool pin JSON")?;
    ensure!(
        pin["version"] == 1 && pin["repository"] == "compoundingtech/mergemaster",
        "unsupported tool repository"
    );
    let revision = pin["revision"].as_str().context("tool revision")?;
    ensure!(lower_hex(revision, 40), "invalid tool revision");
    let version = pin["release"]["version"]
        .as_str()
        .context("release version")?;
    let mut parts = version
        .strip_prefix('v')
        .context("invalid release version")?
        .split('.');
    for _ in 0..3 {
        let part = parts.next().context("invalid release version")?;
        ensure!(
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
            "invalid release version"
        );
    }
    ensure!(parts.next().is_none(), "invalid release version");
    let digest = pin["release"]["sha256"]
        .as_str()
        .context("release digest")?;
    ensure!(lower_hex(digest, 64), "invalid release digest");
    Ok(ToolIdentity {
        repository: "compoundingtech/mergemaster".into(),
        revision: revision.into(),
        release_version: version.into(),
        binary_sha256: digest.into(),
    })
}

fn git_source(repo: &Path, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_NO_REPLACE_OBJECTS", "1");
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().context("launch source Git")?;
    if let Some(bytes) = input {
        child.stdin.take().context("Git input")?.write_all(bytes)?;
    }
    let done = child.wait_with_output()?;
    ensure!(
        done.status.success(),
        "source Git failed: {}",
        String::from_utf8_lossy(&done.stderr)
    );
    Ok(done.stdout)
}

fn text(repo: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git_source(repo, args, None)?)?
        .trim()
        .to_owned())
}

fn positive(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && !value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit()),
        "expected a positive decimal run/attempt identifier"
    );
    Ok(())
}

fn change_identity(
    repository: &str,
    event_name: &str,
    event: &Value,
    source: &str,
) -> Result<String> {
    let (owner, name) = repository.split_once('/').context("invalid repository")?;
    ensure!(
        [owner, name].iter().all(|p| !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))),
        "invalid repository"
    );
    ensure!(
        event["repository"]["full_name"] == repository,
        "event repository mismatch"
    );
    match event_name {
        "pull_request" => {
            let number = event["number"]
                .as_u64()
                .filter(|n| *n > 0)
                .context("invalid pull request identity")?;
            ensure!(
                event["pull_request"]["number"].as_u64() == Some(number),
                "invalid pull request identity"
            );
            Ok(format!("github:{repository}#{number}"))
        }
        "merge_group" => {
            let group = &event["merge_group"];
            let branch = group["head_ref"].as_str().context("merge group head ref")?;
            let entry = branch
                .strip_prefix("refs/heads/gh-readonly-queue/main/pr-")
                .context("unsupported merge group identity")?;
            let (number, suffix) = entry.split_once('-').context("queue entry identity")?;
            positive(number)?;
            ensure!(
                lower_hex(suffix, 40) && group["head_sha"] == source,
                "unsupported or mismatched merge group identity"
            );
            Ok(format!("github:{repository}#{number}"))
        }
        "workflow_dispatch" => Ok(format!("github:{repository}@{source}")),
        _ => bail!("unsupported workflow event"),
    }
}

fn file_digest(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        digest.update(&buffer[..size]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn environment(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing {name}"))
}

pub fn run() -> Result<()> {
    let repo = std::env::current_dir()?;
    let format = text(&repo, &["rev-parse", "--show-object-format"])?;
    let source = text(&repo, &["rev-parse", "--verify", "HEAD"])?;
    let tree = text(&repo, &["rev-parse", "HEAD^{tree}"])?;
    let length = match format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        _ => bail!("unsupported Git object format"),
    };
    ensure!(
        lower_hex(&source, length) && lower_hex(&tree, length),
        "expected full Git object IDs"
    );
    ensure!(
        source == environment("GITHUB_SHA")?,
        "checkout does not match the effective tested GITHUB_SHA"
    );
    let repository = environment("GITHUB_REPOSITORY")?;
    let event_name = environment("GITHUB_EVENT_NAME")?;
    let event: Value = serde_json::from_slice(&fs::read(environment("GITHUB_EVENT_PATH")?)?)?;
    let change_id = change_identity(&repository, &event_name, &event, &source)?;
    let run_id = environment("GITHUB_RUN_ID")?;
    let run_attempt = environment("GITHUB_RUN_ATTEMPT")?;
    positive(&run_id)?;
    positive(&run_attempt)?;
    let base = environment("BASE_SHA")?;
    ensure!(lower_hex(&base, length), "expected full BASE_SHA");
    let mut tool = parse_tool_pin(&git_source(
        &repo,
        &["show", &format!("{base}:.mergemaster/tool-pin.json")],
        None,
    )?)?;
    tool.binary_sha256 = file_digest(Path::new("/proc/self/exe"))?;
    let objects = git_source(
        &repo,
        &["rev-list", "--objects", "--no-object-names", &tree],
        None,
    )?;
    let destination = PathBuf::from(environment("RUNNER_TEMP")?).join("ci-evidence-source");
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    let pack_path = destination.join("source.pack");
    let pack = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pack_path)?;
    let mut child = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["pack-objects", "--stdout"])
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .stdin(Stdio::piped())
        .stdout(pack)
        .spawn()?;
    let mut input = child.stdin.take().context("pack input")?;
    writeln!(input, "{source}")?;
    input.write_all(&objects)?;
    drop(input);
    ensure!(child.wait()?.success(), "source pack creation failed");
    let receipt = observers::SourceReceipt {
        version: 2,
        repository,
        event: event_name,
        run_id,
        run_attempt,
        source,
        tree,
        object_format: format,
        change_id,
        tool,
        pack_sha256: file_digest(&pack_path)?,
        pack_bytes: fs::metadata(&pack_path)?.len(),
    };
    // Value::sort_all_objects recursively sorts despite serde_json preserve_order.
    let mut value = serde_json::to_value(&receipt)?;
    value.sort_all_objects();
    // All receipt strings are constrained to ASCII by the producer/pin schema.
    // Match json.dumps(sort_keys=True): no indent; ", " between items and ": " after keys.
    let mut bytes = Vec::new();
    value.serialize(&mut serde_json::Serializer::with_formatter(
        &mut bytes,
        ReceiptFormatter,
    ))?;
    let serialized = String::from_utf8(bytes)?;
    fs::write(destination.join("receipt.json"), format!("{serialized}\n"))?;
    crate::cli_println!("{serialized}");
    let mut summary = OpenOptions::new()
        .create(true)
        .append(true)
        .open(environment("GITHUB_STEP_SUMMARY")?)?;
    writeln!(
        summary,
        "Evidence source retained: {}, tree {}. This is provenance only; it asserts neither check success nor signing trust.",
        receipt.source, receipt.tree
    )?;
    Ok(())
}

struct ReceiptFormatter;

impl serde_json::ser::Formatter for ReceiptFormatter {
    fn begin_object_key<W: Write + ?Sized>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if !first {
            writer.write_all(b", ")?;
        }
        Ok(())
    }

    fn begin_object_value<W: Write + ?Sized>(&mut self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(b": ")
    }

    fn begin_array_value<W: Write + ?Sized>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if !first {
            writer.write_all(b", ")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_identity_rejects_ambiguous_events_and_bad_ids() {
        let event = serde_json::json!({"repository":{"full_name":"example/project"},"number":7,"pull_request":{"number":7}});
        for number in [
            serde_json::json!(true),
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!("7"),
            Value::Null,
        ] {
            let mut bad = event.clone();
            bad["number"] = number;
            assert!(change_identity("example/project", "pull_request", &bad, "source").is_err());
        }
        for repo in ["other/project", "../project", "example/project/extra"] {
            assert!(change_identity(repo, "pull_request", &event, "source").is_err());
        }
        for value in ["0", "-1", "01", "1\n", "1/2"] {
            assert!(positive(value).is_err());
        }
        assert!(change_identity("example/project", "push", &event, "source").is_err());
        assert_eq!(
            change_identity("example/project", "workflow_dispatch", &event, "source").unwrap(),
            "github:example/project@source"
        );
    }
}
