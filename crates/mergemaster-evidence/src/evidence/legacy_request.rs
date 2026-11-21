//! Validation of the copied signer's request protocol, independent of signing authority.
pub use super::legacy_json::Value;
use anyhow::{Context, Result, ensure};
use std::borrow::Cow;

/// Decode legacy JSON with locally retained number lexemes, then validate claims.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let request = super::legacy_json::parse(bytes)?;
    validate(&request)?;
    Ok(request)
}

const REQUIRED: [&str; 7] = [
    "commit",
    "check",
    "command",
    "exit_code",
    "output_sha256",
    "change_id",
    "inputs",
];
const INPUTS: [&str; 5] = [
    "flake_lock_sha256",
    "toolchain_sha256",
    "wrapper_sha256",
    "system",
    "attempt",
];

// Python's regex `$` accepts a single final newline; `fullmatch` does not.
fn end(value: &str) -> &str {
    value.strip_suffix('\n').unwrap_or(value)
}
fn token(value: &Value) -> Result<Cow<'_, str>> {
    match value {
        Value::String(s) => Ok(Cow::Borrowed(s)),
        Value::Number(n) => number_token(n),
        _ => Ok(Cow::Borrowed("")),
    }
}
fn number_token(number: &str) -> Result<Cow<'_, str>> {
    if !number.contains(['.', 'e', 'E']) {
        return Ok(Cow::Borrowed(if number == "-0" { "0" } else { number }));
    }
    let value: f64 = number.parse()?;
    if value.is_infinite() {
        let mut text = String::with_capacity(32);
        text.push_str(if value.is_sign_negative() {
            "-inf"
        } else {
            "inf"
        });
        return Ok(Cow::Owned(text));
    }
    Ok(Cow::Owned(float_token(value)?))
}
/// Python's finite-float repr; non-finite wire tokens belong to each caller.
pub(crate) fn float_token(value: f64) -> Result<String> {
    use std::fmt::Write;
    let mut text = String::with_capacity(32);
    write!(&mut text, "{value:e}")?;
    let e = text.rfind('e').ok_or(std::fmt::Error)?;
    let exponent: i32 = text[e + 1..].parse()?;
    // Python repr uses fixed notation at exponents -4..15, otherwise signed/padded exponents.
    if !(-4..16).contains(&exponent) {
        text.truncate(e + 1);
        write!(&mut text, "{exponent:+03}")?;
    } else {
        text.truncate(e);
        text.retain(|c| c != '.');
        let sign = usize::from(value.is_sign_negative());
        if exponent < 0 {
            text.insert_str(sign, "0.");
            for _ in 0..-exponent - 1 {
                text.insert(sign + 2, '0');
            }
        } else {
            let point = sign + exponent as usize + 1;
            while text.len() <= point {
                text.push('0');
            }
            text.insert(point, '.');
        }
    }
    Ok(text)
}
fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn base64(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"+/".contains(&c))
}
fn store(value: &str) -> bool {
    let Some((hash, name)) = end(value)
        .strip_prefix("/nix/store/")
        .and_then(|s| s.split_once('-'))
    else {
        return false;
    };
    hash.len() == 32
        && hash
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"+._?=-".contains(&c))
}
fn signature(value: &str) -> bool {
    let Some((name, encoded)) = end(value).split_once(':') else {
        return false;
    };
    let payload = encoded.trim_end_matches('=');
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        && encoded.len() - payload.len() <= 2
        && base64(payload)
}

// Git bindings and signing authority are checked separately.
fn validate(request: &Value) -> Result<()> {
    let fields = request.as_object().context("request must be an object")?;
    ensure!(
        REQUIRED.iter().all(|key| fields.contains_key(*key))
            && fields
                .keys()
                .all(|key| REQUIRED.contains(&key.as_str()) || key == "runner"),
        "unexpected or missing request keys"
    );
    let runner = request.get("runner").map_or(Some("wrapper"), Value::as_str);
    ensure!(
        matches!(runner, Some("wrapper" | "nix")),
        "runner must be one of: wrapper, nix"
    );
    let commit = token(&request["commit"])?;
    ensure!(
        hex(end(&commit), 40) || hex(end(&commit), 64),
        "commit must be a full object id"
    );
    let check = token(&request["check"])?;
    let name = end(&check);
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && (name.as_bytes()[0].is_ascii_lowercase() || name.as_bytes()[0].is_ascii_digit()),
        "check name must start with a lowercase letter or digit"
    );
    ensure!(
        name.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c)),
        "invalid check name"
    );
    let command = request["command"]
        .as_array()
        .context("command must be a nonempty argument vector")?;
    ensure!(
        command
            .first()
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
            && command.iter().all(Value::is_string),
        "command must be a nonempty argument vector"
    );
    ensure!(
        request["exit_code"].as_number().is_some_and(|n| n
            .strip_prefix('-')
            .unwrap_or(n)
            .bytes()
            .all(|c| c.is_ascii_digit())),
        "exit_code must be an integer"
    );
    ensure!(
        hex(end(&token(&request["output_sha256"])?), 64),
        "output_sha256 must be 64 lowercase hex digits"
    );
    let change = request["change_id"]
        .as_str()
        .context("change_id must be a short nonempty string")?;
    ensure!(
        change.chars().take(200).count() < 200
            && change
                .chars()
                .any(|c| !c.is_whitespace() && !('\u{1c}'..='\u{1f}').contains(&c)),
        "change_id must be a short nonempty string"
    );
    let inputs = request["inputs"]
        .as_object()
        .context("inputs must be an object")?;
    ensure!(
        INPUTS.iter().all(|key| inputs.contains_key(*key))
            && inputs.len() <= 40
            && inputs.values().all(|v| v
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.chars().take(501).count() <= 500)),
        "inputs must be short nonempty strings with required fingerprints"
    );
    for key in inputs.keys().filter(|key| !INPUTS.contains(&key.as_str())) {
        let name = end(key);
        ensure!(
            !name.is_empty()
                && name.len() <= 40
                && name.as_bytes()[0].is_ascii_lowercase()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'),
            "invalid input name"
        );
    }
    for key in &INPUTS[..3] {
        ensure!(
            inputs
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|s| hex(end(s), 64)),
            "{key} must be 64 lowercase hex digits"
        );
    }
    let attempt = inputs
        .get("attempt")
        .and_then(Value::as_str)
        .context("inputs must be short nonempty strings with required fingerprints")?;
    ensure!(
        (1..=4).contains(&attempt.len())
            && (b'1'..=b'9').contains(&attempt.as_bytes()[0])
            && attempt.bytes().all(|c| c.is_ascii_digit()),
        "attempt must be a small positive integer"
    );
    if runner == Some("nix") {
        validate_nix(request, &check, command, inputs)?;
    }
    Ok(())
}

fn validate_nix(
    request: &Value,
    check: &str,
    command: &[Value],
    inputs: &std::collections::BTreeMap<String, Value>,
) -> Result<()> {
    let input = |key: &str| inputs.get(key).and_then(Value::as_str).unwrap_or("");
    let system = command
        .get(2)
        .and_then(Value::as_str)
        .and_then(|s| s.strip_prefix(".#checks."))
        .and_then(|s| s.strip_suffix(check))
        .and_then(|s| s.strip_suffix('.'))
        .and_then(|s| s.split_once('-'));
    ensure!(
        request["check"].is_string()
            && command.len() == 3
            && command[0] == "nix"
            && command[1] == "build"
            && system.is_some_and(|(arch, os)| !arch.is_empty()
                && !os.is_empty()
                && arch
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
                && os.bytes().all(|c| c.is_ascii_lowercase())),
        "a nix record must be: nix build .#checks.<system>.<check>"
    );
    let drv = input("drv_path");
    ensure!(
        store(drv) && drv.ends_with(".drv"),
        "a nix record needs drv_path ending in .drv"
    );
    if !matches!(request["exit_code"].as_number(), Some("0" | "-0")) {
        ensure!(
            [
                "out_path",
                "nar_hash",
                "nar_size",
                "references",
                "nix_signatures"
            ]
            .iter()
            .all(|key| !inputs.contains_key(*key)),
            "a failed nix build records no output path"
        );
        return Ok(());
    }
    let out = input("out_path");
    ensure!(
        store(out)
            && drv
                .rsplit('/')
                .next()
                .and_then(|s| s.split_once('-'))
                .map(|(_, s)| s.strip_suffix(".drv"))
                == out
                    .rsplit('/')
                    .next()
                    .and_then(|s| s.split_once('-'))
                    .map(|(_, s)| Some(s)),
        "out_path must be named like drv_path without .drv"
    );
    ensure!(
        input("nar_hash")
            .strip_prefix("sha256-")
            .and_then(|s| s.strip_suffix('='))
            .is_some_and(|s| s.len() == 43 && base64(s)),
        "nar_hash must be sha256-<base64>"
    );
    let size = input("nar_size");
    ensure!(
        (1..=15).contains(&size.len()) && size.bytes().all(|c| c.is_ascii_digit()),
        "nar_size must be a decimal number"
    );
    let references = input("references");
    let mut previous = None;
    ensure!(
        references == "-"
            || references.split(',').all(
                |path| store(path) && previous.replace(path).is_none_or(|before| before < path)
            ),
        "references must be sorted distinct store paths or -"
    );
    ensure!(
        matches!(input("cache_hit"), "true" | "false"),
        "cache_hit must be true or false"
    );
    let signatures = input("nix_signatures");
    let unsigned = signatures == "none";
    ensure!(
        unsigned || signatures.split(',').all(signature),
        "nix_signatures must be name:base64 signatures or none"
    );
    ensure!(
        input("nix_unsigned") == if unsigned { "true" } else { "false" },
        "nix_unsigned contradicts signatures"
    );
    ensure!(
        input("nix_key_id")
            == if unsigned {
                "none"
            } else {
                signatures
                    .split_once(':')
                    .map_or(signatures, |(name, _)| name)
            },
        "nix_key_id must name the first signature key"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    #[test]
    fn legacy_requests_match_python_validation() {
        let cases: Vec<Value> = serde_json::from_slice(include_bytes!(
            "../../../../tests/fixtures/oracle/request-core/validation/stdout.bin"
        ))
        .unwrap();
        assert!(cases.len() > 100);
        for case in &cases {
            let raw = case["request_json"].as_str().unwrap();
            assert_eq!(
                super::decode(raw.as_bytes()).is_ok(),
                case["valid"].as_bool().unwrap(),
                "{}",
                case["label"]
            );
            if let Some(expected) = case["numeric_check"].as_str() {
                let request = super::super::legacy_json::parse(raw.as_bytes()).unwrap();
                assert_eq!(
                    super::token(&request["check"]).unwrap(),
                    expected,
                    "{}",
                    case["label"]
                );
            }
        }
        eprintln!(
            "{} legacy request cases matched the Python oracle",
            cases.len()
        );
    }
}
