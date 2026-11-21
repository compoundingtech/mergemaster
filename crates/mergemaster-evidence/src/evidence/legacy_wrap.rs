//! Cooperative v1 wrapper. Deliberately separate from v2's infrastructure outcomes.
use super::{
    flip_skip_python::{splitlines, truthy},
    legacy_json,
    legacy_verify::{
        python_repr::Repr,
        statement_document::{Document, Node},
        value_inputs::TextRef,
    },
};
use crate::gate::git::deadline::GitChild;
use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine, alphabet,
    engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
mod args;
mod json;
mod transport;

const PACK_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

const RESERVED: [&str; 8] = [
    "flake_lock_sha256",
    "toolchain_sha256",
    "wrapper_sha256",
    "system",
    "attempt",
    "lane_definition_sha256",
    "workspace_clean",
    "untracked_files",
];

pub fn run(argv: &[String]) -> Result<()> {
    let secrets = transport::Redactor::from_env();
    let code = match args::parse(argv) {
        Err(exit) => {
            std::io::stdout()
                .lock()
                .write_all(secrets.text(&exit.stdout).as_bytes())?;
            std::io::stderr()
                .lock()
                .write_all(secrets.text(&exit.stderr).as_bytes())?;
            exit.code
        }
        Ok(args) => match wrap(args, &secrets) {
            Ok(code) => code,
            Err(error) => {
                writeln!(
                    std::io::stderr().lock(),
                    "evidence-wrap: {}",
                    secrets.text(&error.to_string())
                )?;
                1
            }
        },
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn git(args: &[&str]) -> Result<Vec<u8>> {
    Ok(transport::git(args, None)?.stdout)
}

// CPython sys.exit converts through signed long long before POSIX keeps eight bits.
fn process_status(integer: &str) -> i32 {
    match integer.parse::<i64>() {
        Ok(value) => (value & 0xff) as i32,
        Err(_) => 255,
    }
}
fn git_text(args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git(args)?)?
        .trim_matches(super::legacy_verify::projection_oid::space)
        .to_owned())
}
fn output(command: &mut Command) -> Result<std::process::Output> {
    command.output().map_err(|error| {
        anyhow::anyhow!(
            "{}",
            super::legacy_verify::projection_process_error::diagnostic(
                command,
                &error,
                false,
                std::time::Duration::ZERO
            )
        )
    })
}
fn capture(command: &mut Command, input: &[u8]) -> Result<std::process::Output> {
    let timeout = std::time::Duration::from_secs(300);
    GitChild::capture(command, Some(input), timeout).map_err(|error| {
        anyhow::anyhow!(
            "{}",
            super::legacy_verify::projection_process_error::diagnostic(
                command, &error, false, timeout
            )
        )
    })
}
fn read_text(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    std::fs::read_to_string(path).map_err(|error| {
        anyhow::anyhow!(
            "{}",
            super::legacy_verify::source_io::error(path.as_os_str(), &error).detail
        )
    })
}
fn config_path(base: &str, name: &str) -> Result<String> {
    let path = format!(".fractal/{name}");
    Ok(
        if git(&["ls-tree", "--full-tree", "-z", base, "--", &path])?.is_empty() {
            format!(".st/{name}")
        } else {
            path
        },
    )
}
fn dirty() -> Result<String> {
    git_text(&["status", "--porcelain"])
}
fn tracked_dirty() -> Result<String> {
    let changed = git_text(&["status", "--porcelain", "--untracked-files=no"])?;
    if !changed.is_empty() {
        return Ok(changed);
    }
    let flags = String::from_utf8(git(&["ls-files", "-v"])?)?;
    let hidden: Vec<_> = splitlines(&flags)
        .filter(|line| !line.starts_with("H "))
        .take(3)
        .collect();
    Ok(if hidden.is_empty() {
        String::new()
    } else {
        format!("index flags hide changes: {}", hidden.join(", "))
    })
}
fn required<'a>(document: &'a Document, key: &str) -> Result<&'a Node> {
    json::get(document, document.root(), key)
        .with_context(|| format!("{}", Repr(TextRef::Str(key))))
}
fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn oid(text: &str) -> bool {
    matches!(text.len(), 40 | 64)
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn toolchain(override_digest: Option<&str>, secrets: &transport::Redactor) -> Result<String> {
    if let Some(digest) = override_digest.filter(|s| !s.is_empty()) {
        return Ok(digest.to_owned());
    }
    let system = output(Command::new("nix").args([
        "eval",
        "--impure",
        "--raw",
        "--expr",
        "builtins.currentSystem",
    ]))?;
    let system_text = String::from_utf8(system.stdout)?;
    let drv = output(Command::new("nix").args([
        "eval",
        "--raw",
        "--no-update-lock-file",
        &format!(".#devShells.{}.default.drvPath", system_text.trim()),
    ]))?;
    let drv_text = String::from_utf8(drv.stdout)?;
    if !system.status.success() || !drv.status.success() || !drv_text.starts_with('/') {
        let detail = String::from_utf8(if drv.stderr.is_empty() {
            system.stderr
        } else {
            drv.stderr
        })?;
        let detail = secrets.text(&detail);
        let detail = detail.trim();
        let at = detail.char_indices().rev().nth(299).map_or(0, |(at, _)| at);
        bail!(
            "could not name the dev shell derivation (pass --toolchain-sha256 to override): {}",
            &detail[at..]
        );
    }
    Ok(hex::encode(Sha256::digest(drv_text.trim().as_bytes())))
}

struct LaneChild {
    child: std::process::Child,
    reaped: bool,
}
impl Drop for LaneChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn run_command(command: &[String]) -> Result<(i32, String)> {
    use std::os::unix::process::ExitStatusExt;
    let (mut reader, writer) = std::io::pipe()?;
    let error_writer = writer.try_clone()?;
    let mut launch = Command::new(&command[0]);
    launch
        .args(&command[1..])
        .stdout(Stdio::from(writer))
        .stderr(Stdio::from(error_writer));
    launch
        .env_remove("EVIDENCE_PUSH_TOKEN")
        .env_remove("EVIDENCE_SIGNER");
    let child = launch.spawn().map_err(|error| {
        anyhow::anyhow!(
            "{}",
            super::legacy_verify::projection_process_error::diagnostic(
                &launch,
                &error,
                false,
                std::time::Duration::ZERO
            )
        )
    })?;
    // Command retains its configured descriptors after spawn; close our writer
    // copies so EOF follows the child's final combined-output write.
    drop(launch);
    let mut child = LaneChild {
        child,
        reaped: false,
    };
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut stdout = std::io::stdout().lock();
    loop {
        let count = match reader.read(&mut buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            value => value?,
        };
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        stdout.write_all(&buffer[..count])?;
        stdout.flush()?;
    }
    let status = child.child.wait()?;
    child.reaped = true;
    Ok((
        status
            .code()
            .unwrap_or_else(|| -status.signal().unwrap_or(1)),
        hex::encode(hash.finalize()),
    ))
}

fn lane_inputs(
    args: &args::Args,
    base: &str,
    tree: &str,
    command: &[String],
    secrets: &transport::Redactor,
) -> Result<String> {
    let shown = git(&[
        "show",
        &format!("{base}:{}", config_path(base, "required-lanes.json")?),
    ])?;
    let helper = |operation: &str, extra: &[&str]| -> Result<Document> {
        let mut launch = Command::new(&args.verifier);
        launch
            .args(["legacy-evidence-verify-helper", operation])
            .args(extra)
            .stdin(Stdio::piped());
        let result = capture(&mut launch, &shown)?;
        if result.status.code() == Some(3) {
            let failure = json::parse(std::str::from_utf8(&result.stdout)?)?;
            bail!(
                "lane {}: {}: {}; nothing was signed",
                args.check,
                json::text(required(&failure, "reason")?)?,
                json::text(required(&failure, "detail")?)?
            );
        }
        ensure!(
            result.status.success(),
            "lane {}: helper exit {}; nothing was signed",
            args.check,
            result.status.code().unwrap_or(-1)
        );
        json::parse(std::str::from_utf8(&result.stdout)?)
    };
    let rules = helper("lane-rules", &["--check", &args.check])?;
    let base_tree = git_text(&[
        "rev-parse",
        "--verify",
        "--end-of-options",
        &format!("{base}^{{tree}}"),
    ])?;
    let definition = helper(
        "lane-definition",
        &[
            "--repo",
            ".",
            "--base-tree",
            &base_tree,
            "--tree",
            tree,
            "--check",
            &args.check,
        ],
    )?;
    let Node::Array(argv) = required(&rules, "argv")? else {
        bail!("invalid lane argv");
    };
    let declared: Vec<_> = argv
        .iter()
        .map(|id| json::text(rules.node(*id)))
        .collect::<Result<_>>()?;
    ensure!(
        command == declared,
        "the command is not the argv of lane {} at {base}; nothing was signed",
        args.check
    );
    if let Node::Array(changed) = required(&definition, "changed")?
        && !changed.is_empty()
    {
        let changed: Vec<_> = changed
            .iter()
            .take(5)
            .map(|id| json::text(definition.node(*id)))
            .collect::<Result<_>>()?;
        eprintln!(
            "{}",
            secrets.text(&format!(
                "evidence-wrap: this tree edits lane {} ({}); the note carries the edited definition's digest",
                args.check,
                changed.join(", ")
            ))
        );
    }
    json::text(required(&definition, "tree_sha256")?)
}

fn executable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    if !path.is_file() {
        return false;
    }
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: access only reads this live NUL-terminated path, matching
    // shutil.which's real-user executable-access check before signer launch.
    unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 }
}

fn signer_launch(encoded: &str) -> Result<Command> {
    let document = json::parse(encoded)?;
    let Node::Array(argv) = document.root() else {
        bail!("--signer must be a JSON array of strings");
    };
    ensure!(!argv.is_empty(), "--signer must be a JSON array of strings");
    let argv: Vec<_> = argv
        .iter()
        .map(|id| {
            json::text(document.node(*id))
                .map_err(|_| anyhow::anyhow!("--signer must be a JSON array of strings"))
        })
        .collect::<Result<_>>()?;
    let program = if argv[0].contains('/') {
        PathBuf::from(&argv[0])
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|path| path.join(&argv[0]))
            .find(|path| executable(path))
            .with_context(|| {
                format!("the signer {} is not on PATH", Repr(TextRef::Str(&argv[0])))
            })?
    };
    let program = if program.is_absolute() {
        program
    } else {
        std::env::current_dir()?.join(program)
    };
    let mut launch = Command::new(program);
    launch.args(&argv[1..]).stdin(Stdio::piped());
    launch
        .env_remove("EVIDENCE_PUSH_TOKEN")
        .env_remove("EVIDENCE_SIGNER");
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("LD_")
            || name.starts_with("DYLD_")
            || name.starts_with("PYTHON")
            || matches!(name.as_ref(), "GLIBC_TUNABLES" | "GCONV_PATH" | "NLSPATH")
        {
            launch.env_remove(key);
        }
    }
    launch.env("PATH", "/run/current-system/sw/bin:/usr/bin:/bin");
    Ok(launch)
}

fn wrap(args: args::Args, secrets: &transport::Redactor) -> Result<i32> {
    let top = git_text(&["rev-parse", "--show-toplevel"])?;
    std::env::set_current_dir(&top)?;
    let clean = dirty()?.is_empty();
    let aggregate = args.aggregate.as_deref().filter(|s| !s.is_empty());
    ensure!(
        clean || aggregate.is_some(),
        "the checkout is not clean: commit or remove changes first, the note is for the committed tree"
    );
    let commit = git_text(&["rev-parse", "HEAD"])?;
    let tree = git_text(&["rev-parse", "HEAD^{tree}"])?;
    let lock = git(&["show", "HEAD:flake.lock"])?;
    let system = output(Command::new("uname").arg("-sm"))?;
    let system = String::from_utf8(system.stdout)?;
    let words: Vec<_> = system.split_whitespace().collect();
    let system = if words.len() == 2 {
        format!("{}-{}", words[1], words[0]).to_lowercase()
    } else {
        "unknown".into()
    };
    let mut inputs = json::Inputs::new();
    json::set(
        &mut inputs,
        "flake_lock_sha256",
        &hex::encode(Sha256::digest(lock)),
    );
    json::set(
        &mut inputs,
        "toolchain_sha256",
        &toolchain(args.toolchain_sha256.as_deref(), secrets)?,
    );
    json::set(&mut inputs, "wrapper_sha256", super::producer_digest()?);
    json::set(&mut inputs, "system", &system);
    json::set(&mut inputs, "attempt", &args.attempt);
    for item in &args.input {
        let parsed = item.split_once('=');
        ensure!(
            parsed.is_some_and(|(name, value)| name_valid(name)
                && !value.is_empty()
                && json::input(&inputs, name).is_none()
                && !RESERVED.contains(&name)),
            "--input {}: NAME=VALUE with a lower-case name this script does not set itself, and a value",
            Repr(TextRef::Str(item))
        );
        let (name, value) = parsed.context("missing input separator")?;
        ensure!(
            name != "source_inputs" || oid(value),
            "--input source_inputs must be a git tree id"
        );
        json::set(&mut inputs, name, value);
    }
    let mut reported = indexmap::IndexMap::new();
    for item in &args.input_file {
        let parsed = item.split_once('=');
        ensure!(
            parsed.is_some_and(|(name, path)| name_valid(name)
                && !path.is_empty()
                && json::input(&inputs, name).is_none()
                && !RESERVED.contains(&name)
                && !reported.contains_key(name)),
            "--input-file {}: NAME=PATH with a lower-case name this script does not set itself, and a path",
            Repr(TextRef::Str(item))
        );
        let (name, path) = parsed.context("missing input file separator")?;
        reported.insert(name.to_owned(), PathBuf::from(path));
    }
    ensure!(
        aggregate.is_none() || reported.is_empty(),
        "--input-file is for a command this script runs, not --aggregate"
    );
    let mut command_json;
    let exit_json;
    let output_digest;
    let mut runner = None;
    if let Some(path) = aggregate {
        let facts = json::parse(&read_text(path)?)?;
        let known = [
            "command",
            "exit_code",
            "output",
            "output_sha256",
            "inputs",
            "runner",
        ];
        let Node::Object(fields) = facts.root() else {
            bail!(
                "--aggregate FILE must hold command, exit_code, exactly one of output or output_sha256, and optionally inputs"
            );
        };
        let has = |key| json::get(&facts, facts.root(), key).is_some();
        ensure!(
            fields.keys().all(|key| known
                .iter()
                .any(|name| key.iter().copied().eq(name.chars().map(u32::from))))
                && has("command")
                && has("exit_code")
                && has("output") != has("output_sha256"),
            "--aggregate FILE must hold command, exit_code, exactly one of output or output_sha256, and optionally inputs"
        );
        command_json = json::encoded(&facts, required(&facts, "command")?, false, false)?;
        exit_json = json::encoded(&facts, required(&facts, "exit_code")?, false, false)?;
        output_digest = if let Some(value) =
            json::get(&facts, facts.root(), "output_sha256").filter(|v| truthy(*v))
        {
            json::encoded(&facts, value, false, false)?
        } else {
            json::quote(&hex::encode(Sha256::digest(
                json::encoded(&facts, required(&facts, "output")?, true, true)?.as_bytes(),
            )))
        };
        if let Some(extra) = json::get(&facts, facts.root(), "inputs") {
            json::update_inputs(&mut inputs, &facts, extra)?;
        }
        let detail = tracked_dirty()?;
        ensure!(
            detail.is_empty(),
            "tracked files differ from the commit, so the tree that was tested is not the one named; nothing was signed ({})",
            splitlines(&detail)
                .next()
                .unwrap_or("")
                .chars()
                .take(200)
                .collect::<String>()
        );
        json::set(&mut inputs, "workspace_clean", "true");
        json::set(
            &mut inputs,
            "untracked_files",
            if clean { "false" } else { "true" },
        );
        if let Some(value) = json::get(&facts, facts.root(), "runner").filter(|v| truthy(*v)) {
            runner = Some(json::encoded(&facts, value, false, false)?);
        }
    } else {
        if let Some(base) = args.lanes_from.as_deref().filter(|s| !s.is_empty()) {
            json::set(
                &mut inputs,
                "lane_definition_sha256",
                &lane_inputs(&args, base, &tree, &args.command, secrets)?,
            );
        }
        let (exit, digest) = run_command(&args.command)?;
        command_json = String::from("[");
        for (index, arg) in args.command.iter().enumerate() {
            if index != 0 {
                command_json.push_str(", ");
            }
            legacy_json::emit_string(arg, |part| command_json.push_str(part));
        }
        command_json.push(']');
        exit_json = exit.to_string();
        output_digest = json::quote(&digest);
        for (name, path) in reported {
            let content = if path.exists() {
                read_text(path)?
            } else {
                String::new()
            };
            let lines: BTreeSet<_> = splitlines(&content)
                .map(|s| s.trim_matches(super::legacy_verify::projection_oid::space))
                .filter(|s| !s.is_empty())
                .collect();
            let mut value = lines.into_iter().collect::<Vec<_>>().join(",");
            if value.is_empty() {
                value = "none".into();
            }
            if value.chars().count() > 500 {
                value = format!(
                    "{} entries, sha256 {}",
                    value.bytes().filter(|b| *b == b',').count() + 1,
                    hex::encode(Sha256::digest(value.as_bytes()))
                );
            }
            json::set(&mut inputs, &name, &value);
        }
    }
    ensure!(
        git_text(&["rev-parse", "HEAD"])? == commit
            && (if aggregate.is_some() {
                tracked_dirty()?
            } else {
                dirty()?
            })
            .is_empty(),
        "the checkout changed while the command ran; nothing was signed"
    );
    let mut request = json::Fields::new();
    for (key, value) in [
        ("commit", json::quote(&commit)),
        ("check", json::quote(&args.check)),
        ("command", command_json),
        ("exit_code", exit_json.clone()),
        ("output_sha256", output_digest),
        (
            "change_id",
            json::quote(
                args.change_id
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(&format!("local:{commit}")),
            ),
        ),
        ("inputs", json::inputs(&inputs)?),
    ] {
        request.insert(key.into(), value);
    }
    if let Some(runner) = runner {
        request.insert("runner".into(), runner);
    }
    let payload = json::object(&request, false);
    let signed = capture(&mut signer_launch(&args.signer)?, payload.as_bytes())?;
    if !signed.status.success() {
        let detail = String::from_utf8_lossy(&signed.stderr);
        let detail = secrets.text(&detail);
        let detail = detail.trim_matches(super::legacy_verify::projection_oid::space);
        let at = detail.char_indices().rev().nth(499).map_or(0, |(at, _)| at);
        bail!("the signer refused: {}", &detail[at..]);
    }
    let answer = json::parse_bytes(&signed.stdout)?;
    let record = json::text(required(&answer, "record")?)?;
    ensure!(
        json::text_equals(json::get(&answer, answer.root(), "commit"), &commit)
            && json::text_equals(json::get(&answer, answer.root(), "tree"), &tree)
            && json::text_equals(json::get(&answer, answer.root(), "tier"), "full"),
        "the signer answered for a different commit, tree or tier"
    );
    let encoded_pack = json::text(required(&answer, "object_pack_base64")?)?;
    let pack = PACK_BASE64.decode(encoded_pack)?;
    let succeeded = matches!(exit_json.as_str(), "0" | "-0");
    let exit_code = process_status(&exit_json);
    let mut summary = json::Fields::new();
    if let Some(out) = args.out.as_deref().filter(|s| !s.is_empty()) {
        std::fs::create_dir_all(out)?;
        std::fs::write(Path::new(out).join(format!("{record}.pack")), pack)?;
        for (key, value) in [
            ("record", json::quote(&record)),
            ("check", json::quote(&args.check)),
            ("tree", json::quote(&tree)),
            ("commit", json::quote(&commit)),
            ("tier", json::quote("full")),
            ("exit_code", exit_json),
        ] {
            summary.insert(key.into(), value);
        }
        std::fs::write(
            Path::new(out).join(format!("{record}.json")),
            json::object(&summary, false),
        )?;
        eprintln!("{}", secrets.text(&json::object(&summary, true)));
        return Ok(exit_code);
    }
    transport::git(&["index-pack", "--stdin"], Some(&pack))?;
    let note = format!("refs/notes/evidence/{tree}/{record}");
    let tag = format!("refs/tags/evidence/{tree}/{record}");
    let mut refs = vec![tag.clone(), note.clone()];
    let source = json::input(&inputs, "source_inputs")
        .map(json::parse)
        .transpose()?;
    let key = source
        .as_ref()
        .map(|doc| json::text(doc.root()))
        .transpose()?;
    if let Some(key) = &key {
        refs.extend([
            format!("refs/tags/evidence/input/{}/{key}/{record}", args.check),
            format!("refs/notes/evidence-input/{}/{key}/{record}", args.check),
        ]);
    }
    for name in &refs {
        if git(&["for-each-ref", "--format=%(objectname)", name])?
            .iter()
            .all(u8::is_ascii_whitespace)
        {
            git(&["update-ref", name, &record, &"0".repeat(record.len())])?;
        }
    }
    for (key, value) in [
        ("record", json::quote(&record)),
        ("ref", json::quote(&note)),
        ("tag", json::quote(&tag)),
        ("tree", json::quote(&tree)),
        ("check", json::quote(&args.check)),
        ("exit_code", exit_json),
        ("verified", "false".into()),
        ("pushed", "false".into()),
    ] {
        summary.insert(key.into(), value);
    }
    let mut verified = false;
    if succeeded && Path::new(&args.verifier).exists() {
        let supplied_keys = args.keys.as_deref().filter(|s| !s.is_empty());
        let temporary_keys = if supplied_keys.is_none() {
            let shown = git(&[
                "show",
                &format!(
                    "{}:{}",
                    args.keys_from,
                    config_path(&args.keys_from, "evidence-keys")?
                ),
            ])?;
            let directory = std::env::var_os("TMPDIR").unwrap_or_else(|| "/tmp".into());
            let mut file = tempfile::Builder::new()
                .prefix("evidence-keys-")
                .tempfile_in(directory)?;
            file.write_all(&shown)?;
            Some(file)
        } else {
            None
        };
        let keys = match supplied_keys {
            Some(path) => Path::new(path),
            None => temporary_keys
                .as_ref()
                .context("missing verifier keys")?
                .path(),
        };
        let mut verify = Command::new(&args.verifier);
        verify
            .args([
                "legacy-evidence-verify",
                "--repo",
                ".",
                "--tree",
                &tree,
                "--check",
                &args.check,
                "--keys",
            ])
            .arg(keys);
        if let (Some(key), Some(encoded_crate)) = (&key, json::input(&inputs, "crate")) {
            let document = json::parse(encoded_crate)?;
            let krate = json::text(document.root())?;
            if !krate.is_empty()
                && (krate.as_bytes()[0].is_ascii_alphanumeric() || krate.as_bytes()[0] == b'_')
                && krate
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                verify.args(["--crate-key", &format!("{krate}={key}")]);
            }
        }
        let checked = output(&mut verify)?;
        verified = checked.status.success();
        summary.insert("verified".into(), verified.to_string());
        if !verified {
            let detail = String::from_utf8_lossy(&checked.stdout);
            let detail = secrets.text(&detail);
            let at = detail.char_indices().rev().nth(499).map_or(0, |(at, _)| at);
            summary.insert("verification".into(), json::quote(&detail[at..]));
        }
    }
    if let Some(remote) = args.push.as_deref().filter(|s| !s.is_empty()) {
        ensure!(
            !succeeded || verified,
            "not pushing: the note did not verify locally"
        );
        transport::push_refs(remote, &refs, secrets)?;
        summary.insert("pushed".into(), "true".into());
    }
    eprintln!("{}", secrets.text(&json::object(&summary, true)));
    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_integer_statuses_match_cpython_without_changing_success() {
        // Mergemaster measured CPython 3.14.10 sys.exit: i64 overflow -> 255;
        // values within i64 keep their low eight bits (including negative values).
        for (integer, status) in [
            ("9223372036854775808", 255),
            ("18446744073709551616", 255),
            ("4294967296", 0),
            ("256", 0),
            ("-1", 255),
            ("9223372036854775807", 255),
            ("-256", 0),
            ("-9223372036854775809", 255),
        ] {
            assert_eq!(process_status(integer), status, "{integer}");
            assert!(!matches!(integer, "0" | "-0"));
        }
    }

    #[test]
    fn pack_base64_allows_unused_trailing_bits_but_rejects_bad_alphabet_and_padding() {
        assert_eq!(PACK_BASE64.decode("/x==").unwrap(), [0xff]);
        assert_eq!(PACK_BASE64.decode("//9=").unwrap(), [0xff, 0xff]);
        for invalid in ["#w==", "/x=", "/x===", "AA=A"] {
            assert!(PACK_BASE64.decode(invalid).is_err(), "{invalid}");
        }
    }
}
