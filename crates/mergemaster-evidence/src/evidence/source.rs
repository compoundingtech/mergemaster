//! Retain the effective checkout as data; never execute candidate code or sign.
use super::legacy_verify::statement_document::{Document, Node};
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

fn event_get<'a>(
    document: &'a Document,
    node: Option<&Node>,
    key: &str,
) -> Result<Option<&'a Node>> {
    let Some(node) = node else {
        // The producer's nested .get(key, {}) uses an empty object when absent.
        return Ok(None);
    };
    let Node::Object(fields) = node else {
        bail!(
            "AttributeError: '{}' object has no attribute 'get'",
            event_type(node)
        );
    };
    Ok(fields.iter().find_map(|(name, id)| {
        name.iter()
            .copied()
            .eq(key.chars().map(u32::from))
            .then(|| document.node(*id))
    }))
}

fn event_type(node: &Node) -> &'static str {
    match node {
        Node::Null => "NoneType",
        Node::Bool(_) => "bool",
        Node::Integer(_) => "int",
        Node::Float(_) => "float",
        Node::String(_) => "str",
        Node::Array(_) => "list",
        Node::Object(_) => "dict",
    }
}

fn event_text_is(node: Option<&Node>, expected: &str) -> bool {
    matches!(node, Some(Node::String(points)) if points.iter().copied().eq(expected.chars().map(u32::from)))
}

fn event_integer_is(node: Option<&Node>, expected: &str) -> bool {
    match node {
        Some(Node::Integer(number)) => number == expected,
        Some(Node::Bool(value)) => *value && expected == "1",
        // Python compares ints and floats numerically, without rounding the int
        // to f64. Format the exact integral float instead of narrowing the int.
        Some(Node::Float(number)) if number.is_finite() && number.fract() == 0.0 => {
            format!("{number:.0}") == expected
        }
        _ => false,
    }
}

fn change_identity(
    repository: &str,
    event_name: &str,
    event: &Document,
    source: &str,
) -> Result<String> {
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    };
    let valid_repository = repository
        .split_once('/')
        .is_some_and(|(owner, name)| valid_part(owner) && valid_part(name));
    ensure!(valid_repository, "ValueError: invalid repository");
    let event_repository = event_get(event, Some(event.root()), "repository")?;
    ensure!(
        event_text_is(event_get(event, event_repository, "full_name")?, repository),
        "ValueError: event repository mismatch"
    );
    match event_name {
        "pull_request" => {
            let number = event_get(event, Some(event.root()), "number")?;
            let Some(Node::Integer(number)) = number else {
                bail!("ValueError: invalid pull request identity");
            };
            // Python ints remain arbitrary precision after json.loads(bytes).
            ensure!(
                !number.starts_with('-') && number != "0",
                "ValueError: invalid pull request identity"
            );
            let pull = event_get(event, Some(event.root()), "pull_request")?;
            ensure!(
                event_integer_is(event_get(event, pull, "number")?, number),
                "ValueError: invalid pull request identity"
            );
            Ok(format!("github:{repository}#{number}"))
        }
        "merge_group" => {
            let group = event_get(event, Some(event.root()), "merge_group")?;
            let branch = event_get(event, group, "head_ref")?;
            let points = match branch {
                None => &[][..],
                Some(Node::String(points)) => points.as_slice(),
                Some(node) => bail!(
                    "TypeError: expected string or bytes-like object, got '{}'",
                    event_type(node)
                ),
            };
            let prefix = b"refs/heads/gh-readonly-queue/main/pr-";
            ensure!(
                points.len() >= prefix.len()
                    && points
                        .iter()
                        .copied()
                        .zip(prefix.iter().copied().map(u32::from))
                        .all(|(a, b)| a == b),
                "ValueError: unsupported or mismatched merge group identity"
            );
            let entry = &points[prefix.len()..];
            let Some(separator) = entry.iter().position(|point| *point == u32::from(b'-')) else {
                bail!("ValueError: unsupported or mismatched merge group identity");
            };
            let number = &entry[..separator];
            let suffix = &entry[separator + 1..];
            // Match the ASCII regex directly against Python codepoints, never
            // converting an unpaired surrogate into a Rust string.
            ensure!(
                !number.is_empty()
                    && number[0] != u32::from(b'0')
                    && number
                        .iter()
                        .all(|point| (u32::from(b'0')..=u32::from(b'9')).contains(point))
                    && suffix.len() == 40
                    && suffix
                        .iter()
                        .all(|point| (u32::from(b'0')..=u32::from(b'9')).contains(point)
                            || (u32::from(b'a')..=u32::from(b'f')).contains(point))
                    && event_text_is(event_get(event, group, "head_sha")?, source),
                "ValueError: unsupported or mismatched merge group identity"
            );
            let mut identity = format!("github:{repository}#");
            identity.extend(number.iter().map(|point| char::from(*point as u8)));
            Ok(identity)
        }
        "workflow_dispatch" => Ok(format!("github:{repository}@{source}")),
        _ => bail!("ValueError: unsupported workflow event"),
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
    let event =
        super::legacy_verify::json_bytes::parse(&fs::read(environment("GITHUB_EVENT_PATH")?)?)
            .map_err(|error| match error.origin {
                super::legacy_policy::ErrorOrigin::Exception { class } => {
                    anyhow::anyhow!("{class}: {}", error.detail)
                }
                _ => error.into(),
            })?;
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
            let bad = super::legacy_verify::json_bytes::parse(&serde_json::to_vec(&bad).unwrap())
                .unwrap();
            assert!(change_identity("example/project", "pull_request", &bad, "source").is_err());
        }
        let event =
            super::legacy_verify::json_bytes::parse(&serde_json::to_vec(&event).unwrap()).unwrap();
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
