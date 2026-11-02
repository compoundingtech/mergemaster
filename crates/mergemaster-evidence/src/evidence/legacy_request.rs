//! Validation of the copied signer's request protocol, independent of signing authority.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::borrow::Cow;

const REQUIRED: [&str; 7] = ["commit", "check", "command", "exit_code", "output_sha256", "change_id", "inputs"];
const INPUTS: [&str; 5] = ["flake_lock_sha256", "toolchain_sha256", "wrapper_sha256", "system", "attempt"];

// Python's regex `$` accepts a single final newline; `fullmatch` does not.
fn end(value: &str) -> &str { value.strip_suffix('\n').unwrap_or(value) }
fn token(value: &Value) -> Cow<'_, str> {
    match value { Value::String(s) => Cow::Borrowed(s), Value::Number(n) => Cow::Owned(n.to_string()), _ => Cow::Borrowed("") }
}
fn hex(value: &str, size: usize) -> bool {
    value.len() == size && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn base64(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|c| c.is_ascii_alphanumeric() || b"+/".contains(&c))
}
fn store(value: &str) -> bool {
    let Some((hash, name)) = end(value).strip_prefix("/nix/store/").and_then(|s| s.split_once('-')) else { return false };
    hash.len() == 32 && hash.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"+._?=-".contains(&c))
}
fn signature(value: &str) -> bool {
    let Some((name, encoded)) = end(value).split_once(':') else { return false };
    let payload = encoded.trim_end_matches('=');
    !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        && encoded.len() - payload.len() <= 2 && base64(payload)
}

/// Preserve the legacy signer's accepted request shape, including Nix output claims.
/// This validates claims only; Git bindings and signing authority are checked separately.
pub fn validate(request: &Value) -> Result<()> {
    let fields = request.as_object().context("request must be an object")?;
    ensure!(REQUIRED.iter().all(|key| fields.contains_key(*key))
        && fields.keys().all(|key| REQUIRED.contains(&key.as_str()) || key == "runner"), "unexpected or missing request keys");
    let runner = request.get("runner").map_or(Some("wrapper"), Value::as_str);
    ensure!(matches!(runner, Some("wrapper" | "nix")), "runner must be one of: wrapper, nix");
    let commit = token(&request["commit"]);
    ensure!(hex(end(&commit), 40) || hex(end(&commit), 64), "commit must be a full object id");
    let check = token(&request["check"]);
    let name = end(&check);
    ensure!(!name.is_empty() && name.len() <= 64
        && (name.as_bytes()[0].is_ascii_lowercase() || name.as_bytes()[0].is_ascii_digit()), "check name must start with a lowercase letter or digit");
    ensure!(name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c)), "invalid check name");
    let command = request["command"].as_array().context("command must be a nonempty argument vector")?;
    ensure!(command.first().and_then(Value::as_str).is_some_and(|s| !s.is_empty())
        && command.iter().all(Value::is_string), "command must be a nonempty argument vector");
    ensure!(request["exit_code"].as_number().is_some_and(|n| {
        let integer = n.to_string();
        integer.strip_prefix('-').unwrap_or(&integer).bytes().all(|c| c.is_ascii_digit())
    }), "exit_code must be an integer");
    ensure!(hex(end(&token(&request["output_sha256"])), 64), "output_sha256 must be 64 lowercase hex digits");
    let change = request["change_id"].as_str().context("change_id must be a short nonempty string")?;
    ensure!(change.chars().take(200).count() < 200
        && change.chars().any(|c| !c.is_whitespace() && !('\u{1c}'..='\u{1f}').contains(&c)), "change_id must be a short nonempty string");
    let inputs = request["inputs"].as_object().context("inputs must be an object")?;
    ensure!(INPUTS.iter().all(|key| inputs.contains_key(*key)) && inputs.len() <= 40
        && inputs.values().all(|v| v.as_str().is_some_and(|s| !s.is_empty() && s.chars().take(501).count() <= 500)), "inputs must be short nonempty strings with required fingerprints");
    for key in inputs.keys().filter(|key| !INPUTS.contains(&key.as_str())) {
        let name = end(key);
        ensure!(!name.is_empty() && name.len() <= 40 && name.as_bytes()[0].is_ascii_lowercase()
            && name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'), "invalid input name");
    }
    for key in &INPUTS[..3] {
        ensure!(hex(end(inputs[*key].as_str().unwrap()), 64), "{key} must be 64 lowercase hex digits");
    }
    let attempt = inputs["attempt"].as_str().unwrap();
    ensure!((1..=4).contains(&attempt.len()) && (b'1'..=b'9').contains(&attempt.as_bytes()[0])
        && attempt.bytes().all(|c| c.is_ascii_digit()), "attempt must be a small positive integer");
    if runner == Some("nix") { validate_nix(request, &check, command, inputs)?; }
    Ok(())
}

fn validate_nix(request: &Value, check: &str, command: &[Value], inputs: &serde_json::Map<String, Value>) -> Result<()> {
    let input = |key: &str| inputs.get(key).and_then(Value::as_str).unwrap_or("");
    let system = command.get(2).and_then(Value::as_str).and_then(|s| s.strip_prefix(".#checks."))
        .and_then(|s| s.strip_suffix(check)).and_then(|s| s.strip_suffix('.')).and_then(|s| s.split_once('-'));
    ensure!(request["check"].is_string() && command.len() == 3 && command[0] == "nix" && command[1] == "build"
        && system.is_some_and(|(arch, os)| !arch.is_empty() && !os.is_empty()
            && arch.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            && os.bytes().all(|c| c.is_ascii_lowercase())), "a nix record must be: nix build .#checks.<system>.<check>");
    let drv = input("drv_path");
    ensure!(store(drv) && drv.ends_with(".drv"), "a nix record needs drv_path ending in .drv");
    if request["exit_code"] != 0 {
        ensure!(["out_path", "nar_hash", "nar_size", "references", "nix_signatures"].iter().all(|key| !inputs.contains_key(*key)), "a failed nix build records no output path");
        return Ok(());
    }
    let out = input("out_path");
    ensure!(store(out) && drv.rsplit('/').next().and_then(|s| s.split_once('-')).map(|(_, s)| s.strip_suffix(".drv"))
        == out.rsplit('/').next().and_then(|s| s.split_once('-')).map(|(_, s)| Some(s)), "out_path must be named like drv_path without .drv");
    ensure!(input("nar_hash").strip_prefix("sha256-").and_then(|s| s.strip_suffix('='))
        .is_some_and(|s| s.len() == 43 && base64(s)), "nar_hash must be sha256-<base64>");
    let size = input("nar_size");
    ensure!((1..=15).contains(&size.len()) && size.bytes().all(|c| c.is_ascii_digit()), "nar_size must be a decimal number");
    let references = input("references");
    let mut previous = None;
    ensure!(references == "-" || references.split(',').all(|path| store(path)
        && previous.replace(path).is_none_or(|before| before < path)), "references must be sorted distinct store paths or -");
    ensure!(matches!(input("cache_hit"), "true" | "false"), "cache_hit must be true or false");
    let signatures = input("nix_signatures");
    let unsigned = signatures == "none";
    ensure!(unsigned || signatures.split(',').all(signature), "nix_signatures must be name:base64 signatures or none");
    ensure!(input("nix_unsigned") == if unsigned { "true" } else { "false" }, "nix_unsigned contradicts signatures");
    ensure!(input("nix_key_id") == if unsigned { "none" } else { signatures.split(':').next().unwrap() }, "nix_key_id must name the first signature key");
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use std::{path::Path, process::Command};

    #[test]
    fn legacy_requests_match_python_validation() {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/evidence-sign");
        let output = Command::new("python3").args(["-I", "-B", "-c", r#"
import copy, importlib.machinery, importlib.util, json, sys
loader = importlib.machinery.SourceFileLoader('oracle', sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
signer = importlib.util.module_from_spec(spec)
loader.exec_module(signer)
base = dict(commit='a'*40, check='gate', command=['true', ''], exit_code=0,
            output_sha256='b'*64, change_id='local:one',
            inputs=dict(flake_lock_sha256='c'*64, toolchain_sha256='d'*64,
                        wrapper_sha256='e'*64, system='x86_64-linux', attempt='1'))
cases = []
def add(label, request):
    try:
        signer.validate(request)
        valid = True
    except signer.Refused:
        valid = False
    cases.append(dict(label=label, request=request, valid=valid))
def change(label, path, value, source=base):
    request = copy.deepcopy(source)
    parent = request
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    add(label, request)
add('wrapper', base)
for field, values in {
    'commit': ['a'*64, 'a'*40+'\n', 'A'*40, 'a'*39, None],
    'check': ['0', 12, 'a'*64, 'a\n', 'A', 'a/b', 'a'*65],
    'command': [[], [''], ['ok', 1], ['ok', '\u0000']],
    'exit_code': [True, 1.0, '1', -1, 2**100],
    'output_sha256': ['a'*64+'\n', 'A'*64, 'a'*63],
    'change_id': ['', ' \u001c', 'é'*199, 'é'*200, None],
    'runner': ['wrapper', 'nix', 'unknown', None],
}.items():
    for index, value in enumerate(values):
        change(f'{field}-{index}', [field], value)
add('non-object', [])
request = copy.deepcopy(base); request['tier'] = 'full'; add('extra-top', request)
for field in base:
    request = copy.deepcopy(base); del request[field]; add('missing-'+field, request)
for field in base['inputs']:
    request = copy.deepcopy(base); del request['inputs'][field]; add('missing-input-'+field, request)
for value in [None, [], {}, 'inputs']:
    change('inputs-type', ['inputs'], value)
for key, values in {
    'attempt': ['0', '01', '10000', '1\n', '9999'],
    'system': ['', 'é'*500, 'é'*501, 1],
    'toolchain_sha256': ['A'*64, 'a'*64+'\n'],
    'wrapper_sha256': ['x', 'a'*64+'\n'],
    'flake_lock_sha256': ['x', 'a'*64+'\n'],
    'run_id': ['123', '', 1], 'Bad': ['x'], 'valid\n': ['x'],
}.items():
    for index, value in enumerate(values):
        change(f'input-{key}-{index}', ['inputs', key], value)
request = copy.deepcopy(base); request['inputs'].update({f'x{i}':'v' for i in range(36)}); add('too-many-inputs', request)
nix = copy.deepcopy(base)
nix.update(runner='nix', command=['nix', 'build', '.#checks.x86_64-linux.gate'])
nix['inputs'].update(drv_path='/nix/store/'+'a'*32+'-output.drv', out_path='/nix/store/'+'b'*32+'-output',
    nar_hash='sha256-'+'A'*43+'=', nar_size='123', references='-', cache_hit='false',
    nix_signatures='cache:'+'A'*86+'==', nix_unsigned='false', nix_key_id='cache')
add('nix-signed', nix)
for field in set(nix['inputs']) - set(base['inputs']):
    request = copy.deepcopy(nix); del request['inputs'][field]; add('missing-nix-'+field, request)
for key, values in {
    'drv_path': ['/tmp/output.drv', '/nix/store/'+'a'*32+'-output', '/nix/store/'+'A'*32+'-output.drv'],
    'out_path': ['/tmp/output', '/nix/store/'+'b'*32+'-other'],
    'nar_hash': ['sha256-'+'A'*42+'=', 'sha256-'+'A'*43+'=\n', 'sha256-'+'!'*43+'='],
    'nar_size': ['', '1\n', '1'*16, '0', '01'],
    'references': ['', '/tmp/path', '/nix/store/'+'a'*32+'-x\n'],
    'cache_hit': ['true', 'yes'],
    'nix_signatures': ['', 'cache:AAA===', ':AAA', 'cache:AAA\n', 'a:AA,b:BB'],
    'nix_unsigned': ['true'], 'nix_key_id': ['other'],
}.items():
    for index, value in enumerate(values):
        change(f'nix-{key}-{index}', ['inputs', key], value, nix)
for command in [['sh','-c','true'], ['nix','build','.#checks.x86_64-linux.other'],
                ['nix','build','.#checks.x/../gate'], ['nix','build','.#checks.x86_64-linux.gate','extra']]:
    change('nix-command', ['command'], command, nix)
refs = ['/nix/store/'+'a'*32+'-a', '/nix/store/'+'b'*32+'-b']
for value in [','.join(refs), ','.join(reversed(refs)), ','.join([refs[0]]*2)]:
    change('nix-references', ['inputs','references'], value, nix)
unsigned = copy.deepcopy(nix); unsigned['inputs'].update(nix_signatures='none', nix_unsigned='true', nix_key_id='none'); add('nix-unsigned', unsigned)
multiple = copy.deepcopy(nix); multiple['inputs'].update(nix_signatures='a:AA,b:BB', nix_key_id='a'); add('nix-multiple-keys', multiple)
failed = copy.deepcopy(nix); failed['exit_code'] = 1
add('failed-output', failed)
for field in ['out_path', 'nar_hash', 'nar_size', 'references', 'nix_signatures']:
    del failed['inputs'][field]
add('failed-no-output', failed)
for field in ['out_path', 'nar_hash', 'nar_size', 'references', 'nix_signatures']:
    change('failed-'+field, ['inputs',field], 'x', failed)
json.dump(cases, sys.stdout)
"#]).arg(script).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert!(cases.len() > 100);
        for case in cases {
            assert_eq!(super::validate(&case["request"]).is_ok(), case["valid"].as_bool().unwrap(), "{}", case["label"]);
        }
    }
}
