//! The cooperative v1 signer protocol, kept separate from the BASE-bound v2 signer.
use super::{legacy_json, legacy_request};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use legacy_request::Value;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::PathBuf,
};

mod tools;

const CONFIGURATION: &str = "configuration must have signer, ssh_key, scratch_repo (optionally path; for tests only test_clock)";

struct Config {
    signer: Value,
    key: PathBuf,
    scratch: PathBuf,
    path: Option<String>,
    test_clock: bool,
}

fn home(home: Option<std::ffi::OsString>) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let home = match home {
        Some(home) => home,
        None => {
            // SAFETY: getuid takes no pointers and only reads the process identity.
            super::keygen::recorded_home(unsafe { libc::getuid() })
                .map_err(|_| anyhow::anyhow!("Could not determine home directory."))?
                .into_os_string()
        }
    };
    let mut bytes = home.into_vec();
    let end = bytes
        .iter()
        .rposition(|byte| *byte != b'/')
        .map_or(0, |at| at + 1);
    Ok(if end == 0 {
        PathBuf::from("/")
    } else {
        bytes.truncate(end);
        std::ffi::OsString::from_vec(bytes).into()
    })
}

impl Config {
    fn load() -> Result<Self> {
        let path = home(std::env::var_os("HOME"))?.join(".config/st/evidence-sign.json");
        let bytes = std::fs::read(&path).with_context(|| format!("{}", path.display()))?;
        Self::parse(&bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let Value::Object(mut fields) = legacy_request::parse(bytes)? else {
            anyhow::bail!(CONFIGURATION);
        };
        ensure!(
            ["signer", "ssh_key", "scratch_repo"]
                .iter()
                .all(|key| fields.contains_key(*key))
                && fields.keys().all(|key| [
                    "signer",
                    "ssh_key",
                    "scratch_repo",
                    "path",
                    "test_clock"
                ]
                .contains(&key.as_str())),
            CONFIGURATION
        );
        let signer = fields.remove("signer").context(CONFIGURATION)?;
        ensure!(signer.is_string(), "invalid signer configuration");
        let key = PathBuf::from(
            fields
                .get("ssh_key")
                .and_then(Value::as_str)
                .context("invalid signer configuration")?,
        );
        let scratch = PathBuf::from(
            fields
                .get("scratch_repo")
                .and_then(Value::as_str)
                .context("invalid signer configuration")?,
        );
        let path = match fields.get("path").filter(|value| truthy(value)) {
            None => None,
            Some(Value::String(path)) => Some(path.clone()),
            _ => anyhow::bail!("invalid signer configuration"),
        };
        Ok(Self {
            signer,
            key,
            scratch,
            path,
            test_clock: matches!(fields.get("test_clock"), Some(Value::Bool(true))),
        })
    }

    fn validate(&self) -> Result<()> {
        let mut signer = self
            .signer
            .text_points()
            .context("invalid signer configuration")?
            .peekable();
        ensure!(
            signer.peek().is_some()
                && !signer.any(|point| {
                    char::from_u32(point).is_some_and(super::legacy_verify::projection_oid::space)
                })
                && self.key.is_absolute()
                && self.scratch.is_absolute(),
            "invalid signer configuration"
        );
        Ok(())
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.parse::<f64>() != Ok(0.0),
        Value::String(value) => !value.is_empty(),
        Value::SurrogateString(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        Value::SurrogateObject(value) => !value.is_empty(),
    }
}

/// Run with the legacy stderr prefix and exit status, rather than the v2 error renderer.
pub fn run() -> Result<()> {
    if let Err(error) = sign() {
        writeln!(std::io::stderr().lock(), "evidence-sign refused: {error}")?;
        std::process::exit(1);
    }
    Ok(())
}

fn text(bytes: Vec<u8>) -> Result<String> {
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

fn sign() -> Result<()> {
    tools::refuse_loader()?;
    let config = Config::load()?;
    let tools = tools::Tools::load(config.path.as_deref())?;
    config.validate()?;
    let mut bytes = Vec::new();
    std::io::stdin().lock().read_to_end(&mut bytes)?;
    let request = legacy_request::decode(&bytes)?;
    let checkout = std::env::current_dir()?;
    let commit = request["commit"]
        .as_str()
        .context("commit must be a string")?;
    let missing = String::from_utf8(tools.git(
        &checkout,
        &["rev-list", "--objects", "--missing=print", commit],
        None,
    )?)?
    .lines()
    .filter(|line| line.starts_with('?'))
    .count();
    ensure!(
        missing == 0,
        "{missing} missing objects before signing; hydrate the source repository in the caller first"
    );
    ensure!(
        text(tools.git(&checkout, &["cat-file", "-t", commit], None)?)? == "commit",
        "commit is not a commit in the caller's checkout"
    );
    let tree = text(tools.git(
        &checkout,
        &["rev-parse", &format!("{commit}^{{tree}}")],
        None,
    )?)?;
    let lock = tools.git(&checkout, &["show", &format!("{commit}:flake.lock")], None)?;
    ensure!(
        request["inputs"]["flake_lock_sha256"].as_str()
            == Some(hex::encode(Sha256::digest(lock)).as_str()),
        "flake_lock_sha256 does not match flake.lock in the commit"
    );
    if !config.scratch.exists() {
        tools.initialize(&config.scratch)?;
    }
    tools.git(
        &config.scratch,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            checkout.to_str().context("checkout path is not UTF-8")?,
            commit,
        ],
        None,
    )?;
    let producer = super::producer_digest()?;
    let now = if config.test_clock {
        std::env::var("EVIDENCE_SIGN_NOW")
            .ok()
            .filter(|s| !s.is_empty())
    } else {
        None
    }
    .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());
    let body = statement(&request, commit, &tree, &config.signer, producer, &now)?;
    let blob = text(tools.git(
        &config.scratch,
        &["hash-object", "-w", "--stdin"],
        Some(body.as_bytes()),
    )?)?;
    let notes = text(tools.git(
        &config.scratch,
        &["mktree"],
        Some(format!("100644 blob {blob}\t{tree}\n").as_bytes()),
    )?)?;
    let record = text(tools.git(
        &config.scratch,
        &[
            "-c",
            "user.name=Evidence signer",
            "-c",
            "user.email=signer@example.invalid",
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("user.signingKey={}", config.key.display()),
            "commit-tree",
            "-S",
            &notes,
            "-p",
            commit,
        ],
        Some(b"st gate observation v1\n"),
    )?)?;
    let mut objects = format!("{commit}\n").into_bytes();
    objects.extend(tools.git(
        &config.scratch,
        &["rev-list", "--objects", "--no-object-names", &tree],
        None,
    )?);
    writeln!(objects, "{record}")?;
    objects.extend(tools.git(
        &config.scratch,
        &[
            "rev-list",
            "--objects",
            "--no-object-names",
            &format!("{record}^{{tree}}"),
        ],
        None,
    )?);
    let pack = tools.git(
        &config.scratch,
        &["pack-objects", "--stdout"],
        Some(&objects),
    )?;
    let mut output = String::from("{\"record\": ");
    legacy_json::string(&record, &mut output)?;
    output.push_str(", \"tier\": \"full\", \"tree\": ");
    legacy_json::string(&tree, &mut output)?;
    output.push_str(", \"commit\": ");
    legacy_json::string(commit, &mut output)?;
    output.push_str(", \"object_pack_base64\": ");
    legacy_json::string(&STANDARD.encode(pack), &mut output)?;
    output.push_str("}\n");
    std::io::stdout().lock().write_all(output.as_bytes())?;
    Ok(())
}

// Preserve Python's insertion order and default separators; the existing encoder
// supplies its ASCII string escaping and retained integer lexemes.
fn json(value: &Value, output: &mut String) -> Result<()> {
    match value {
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push_str(", ");
                }
                json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    output.push_str(", ");
                }
                legacy_json::string(key, output)?;
                output.push_str(": ");
                json(value, output)?;
            }
            output.push('}');
        }
        _ => legacy_json::encode_integer(value, output),
    }
    Ok(())
}

fn statement(
    request: &Value,
    commit: &str,
    tree: &str,
    signer: &Value,
    producer: &str,
    now: &str,
) -> Result<String> {
    let mut body =
        String::from("{\"_type\": \"https://in-toto.io/Statement/v1\", \"subject\": [{\"name\": ");
    legacy_json::string(commit, &mut body)?;
    body.push_str(", \"digest\": {\"gitTree\": ");
    legacy_json::string(tree, &mut body)?;
    body.push_str("}}], \"predicateType\": \"https://compounding.tech/fractal/evidence/gate/v1\", \"predicate\": {\"schema_version\": 1, \"change_id\": ");
    json(&request["change_id"], &mut body)?;
    body.push_str(", \"signer\": ");
    json(signer, &mut body)?;
    body.push_str(", \"tier\": \"full\", \"re_attests\": null, \"producer_sha256\": ");
    legacy_json::string(producer, &mut body)?;
    body.push_str(", \"observed_at\": ");
    legacy_json::string(now, &mut body)?;
    body.push_str(", \"observed\": {\"kind\": \"tests\", \"runner\": ");
    legacy_json::string(
        request
            .get("runner")
            .and_then(Value::as_str)
            .unwrap_or("wrapper"),
        &mut body,
    )?;
    body.push_str(", \"checks\": {");
    let check = legacy_request::token(&request["check"])?;
    let check = match request["check"].as_number() {
        Some("NaN") => "NaN",
        Some(_) if check == "inf" => "Infinity",
        _ => &check,
    };
    legacy_json::string(check, &mut body)?;
    body.push_str(": {\"command\": ");
    json(&request["command"], &mut body)?;
    body.push_str(", \"exit_code\": ");
    json(&request["exit_code"], &mut body)?;
    body.push_str(", \"output_sha256\": ");
    json(&request["output_sha256"], &mut body)?;
    body.push_str("}}, \"inputs\": ");
    json(&request["inputs"], &mut body)?;
    body.push_str("}}}");
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonfinite_test_clock_keeps_the_real_clock_and_surrogate_signer() {
        for clock in ["NaN", "Infinity", "-Infinity"] {
            let raw = format!(
                r#"{{"signer":"fleet/\ud800","ssh_key":"/key","scratch_repo":"/scratch","test_clock":{clock}}}"#
            );
            let config = Config::parse(raw.as_bytes()).unwrap();
            config.validate().unwrap();
            assert!(!config.test_clock, "{clock}");
            let mut signer = String::new();
            json(&config.signer, &mut signer).unwrap();
            assert_eq!(signer, r#""fleet/\ud800""#);
        }
    }

    #[test]
    fn unset_and_empty_home_match_python_resolution() {
        for setting in [None, Some(std::ffi::OsString::new())] {
            let actual = home(setting.clone())
                .unwrap()
                .join(".config/st/evidence-sign.json");
            let mut command = crate::pinned_python::command();
            command.args([
                "-I",
                "-B",
                "-c",
                "from pathlib import Path; print(Path.home() / '.config/st/evidence-sign.json')",
            ]);
            command.env_remove("HOME");
            if let Some(setting) = &setting {
                command.env("HOME", setting);
            }
            let expected = command.output().unwrap();
            assert!(expected.status.success(), "{:?}", expected.stderr);
            assert_eq!(
                actual,
                PathBuf::from(String::from_utf8(expected.stdout).unwrap().trim()),
                "{setting:?}"
            );
        }
    }
}
