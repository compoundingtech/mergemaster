//! Git measurement isolation and the legacy wrapper's publication-only transport.
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use indexmap::IndexMap;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io::{self, Write},
    process::{Command, Output, Stdio},
    time::Duration,
};

use crate::gate::git::deadline::GitChild;

type Environment = BTreeMap<OsString, OsString>;
const GIT_TIMEOUT: Duration = Duration::from_secs(600);
const PUSH_TRIES: usize = 3;

pub(super) fn git(args: &[&str], input: Option<&[u8]>) -> Result<Output> {
    let done = git_status(args, input, &[], false)?;
    if !done.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            diagnostic_tail(&done.stderr)
        );
    }
    Ok(done)
}

pub(super) fn git_status(
    args: &[&str],
    input: Option<&[u8]>,
    extra: &[(String, String)],
    publication: bool,
) -> Result<Output> {
    let mut command = git_command(args, &std::env::vars_os().collect(), extra, publication);
    capture(&mut command, input)
}

fn git_command(
    args: &[&str],
    environ: &Environment,
    extra: &[(String, String)],
    publication: bool,
) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    for (name, value) in environ {
        let name_text = name.as_encoded_bytes();
        let transport = name_text.starts_with(b"GIT_CONFIG_")
            || [
                "GIT_SSH",
                "GIT_SSH_COMMAND",
                "GIT_SSH_VARIANT",
                "GIT_ASKPASS",
            ]
            .iter()
            .any(|allowed| name == OsStr::new(allowed));
        if !name_text.starts_with(b"GIT_") || (publication && transport) {
            command.env(name, value);
        }
    }
    command
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .envs(extra.iter().map(|(key, value)| (key, value)))
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.pager=cat",
        ])
        .args(args);
    command
}

fn capture(command: &mut Command, input: Option<&[u8]>) -> Result<Output> {
    // subprocess.run inherits stdin unless an input buffer was supplied.
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    GitChild::capture(command, input, GIT_TIMEOUT).map_err(|error| {
        anyhow::anyhow!(
            "{}",
            crate::evidence::legacy_verify::projection_process_error::diagnostic(
                command,
                &error,
                false,
                GIT_TIMEOUT
            )
        )
    })
}

fn whitespace(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

fn diagnostic_tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim_matches(whitespace);
    let start = text.char_indices().rev().nth(499).map_or(0, |(at, _)| at);
    text[start..].to_owned()
}

fn token_environment(token: &str, environ: &Environment) -> Result<Vec<(String, String)>> {
    if token.is_empty() {
        return Ok(Vec::new());
    }
    use crate::evidence::legacy_verify::{argparse_int, python_repr::Repr, value_inputs::TextRef};
    let raw = environ
        .get(OsStr::new("GIT_CONFIG_COUNT"))
        .map(|value| value.to_string_lossy())
        .unwrap_or("0".into());
    let integer = argparse_int::parse(TextRef::Str(&raw)).map_err(|error| match error {
        argparse_int::IntegerError::InvalidLiteral => anyhow::anyhow!("invalid literal for int() with base 10: {}", Repr(TextRef::Str(&raw))),
        argparse_int::IntegerError::DigitLimit { digits } => anyhow::anyhow!("Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"),
    })?;
    let count = if integer.negative {
        format!("-{}", integer.digits)
    } else {
        integer.digits.clone()
    };
    let mut digits = integer.digits.into_bytes();
    if integer.negative {
        for digit in digits.iter_mut().rev() {
            if *digit != b'0' {
                *digit -= 1;
                break;
            }
            *digit = b'9';
        }
    } else {
        let mut carry = true;
        for digit in digits.iter_mut().rev() {
            if *digit != b'9' {
                *digit += 1;
                carry = false;
                break;
            }
            *digit = b'0';
        }
        if carry {
            digits.insert(0, b'1');
        }
    }
    let digits = std::str::from_utf8(&digits)?.trim_start_matches('0');
    let next = if digits.is_empty() {
        "0".into()
    } else if integer.negative {
        format!("-{digits}")
    } else {
        digits.to_owned()
    };
    let header = STANDARD.encode(format!("x-access-token:{token}"));
    Ok(vec![
        ("GIT_CONFIG_COUNT".into(), next),
        (format!("GIT_CONFIG_KEY_{count}"), "http.extraheader".into()),
        (
            format!("GIT_CONFIG_VALUE_{count}"),
            format!("Authorization: Basic {header}"),
        ),
    ])
}

pub(super) fn push_refs(remote: &str, refs: &[String], token: &str) -> Result<()> {
    let result = (|| {
        let extra = token_environment(token, &std::env::vars_os().collect())?;
        push_with(
            remote,
            refs,
            |args| git_status(args, None, &extra, true),
            std::thread::sleep,
            &mut io::stderr().lock(),
        )
    })();
    result.map_err(|error: anyhow::Error| redact(error, token))
}

fn redact(error: anyhow::Error, token: &str) -> anyhow::Error {
    if token.is_empty() {
        error
    } else {
        anyhow::anyhow!(error.to_string().replace(token, "***"))
    }
}

fn push_with(
    remote: &str,
    refs: &[String],
    mut run: impl FnMut(&[&str]) -> Result<Output>,
    mut sleep: impl FnMut(Duration),
    diagnostics: &mut impl Write,
) -> Result<()> {
    let mut pending = refs.to_vec();
    for attempt in 1..=PUSH_TRIES {
        let specs: Vec<String> = pending
            .iter()
            .map(|name| format!("{name}:{name}"))
            .collect();
        let mut args = vec!["push", "--porcelain", remote];
        args.extend(specs.iter().map(String::as_str));
        let done = run(&args)?;
        if done.status.success() {
            return Ok(());
        }
        // Like Python's dict, preserve the first insertion order and the last reason.
        let stdout = String::from_utf8_lossy(&done.stdout);
        let mut refused = IndexMap::new();
        for line in stdout.split([
            '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
            '\u{2029}',
        ]) {
            let mut fields = line.split('\t');
            if !line.starts_with('!') {
                continue;
            }
            if let (Some(_), Some(names), Some(reason)) =
                (fields.next(), fields.next(), fields.next())
            {
                refused.insert(
                    names.split(':').next().unwrap_or("").to_owned(),
                    reason.trim_matches(whitespace),
                );
            }
        }
        if refused.is_empty() {
            bail!("push failed: {}", diagnostic_tail(&done.stderr));
        }
        if refused
            .values()
            .any(|reason| *reason != "[remote rejected] (failed)")
            || attempt == PUSH_TRIES
        {
            let shown = refused
                .iter()
                .map(|(name, reason)| format!("{name} {reason}"))
                .collect::<Vec<_>>()
                .join("; ");
            bail!("push failed (try {attempt} of {PUSH_TRIES}): {shown}");
        }
        writeln!(
            diagnostics,
            "evidence-wrap: {remote} answered {} ref(s) with a bare (failed); pushing them again ({} of {PUSH_TRIES})",
            refused.len(),
            attempt + 1
        )?;
        diagnostics.flush()?;
        sleep(Duration::from_secs(2 * attempt as u64));
        pending = refused.into_keys().collect();
    }
    bail!("push failed after {PUSH_TRIES} attempts")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn git_capture_spawn_errors_use_python_command_diagnostics() {
        let mut command = Command::new("/definitely-missing-legacy-wrap-git");
        let error = capture(&mut command, None).unwrap_err().to_string();
        assert_eq!(
            error,
            "[Errno 2] No such file or directory: '/definitely-missing-legacy-wrap-git'"
        );
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "collector deadline");
        assert_eq!(
            crate::evidence::legacy_verify::projection_process_error::diagnostic(
                &command,
                &timeout,
                true,
                GIT_TIMEOUT
            ),
            "Command '['/definitely-missing-legacy-wrap-git']' timed out after 600 seconds"
        );
    }

    fn environment(values: &[(&str, &str)]) -> Environment {
        values
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    fn output(success: bool, stdout: &str, stderr: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(if success { 0 } else { 256 }),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn measurement_scrubs_git_and_publication_keeps_only_transport() {
        let env = environment(&[
            ("HOME", "/home/test"),
            ("PATH", "/bin"),
            ("LC_ALL", "bad"),
            ("GIT_DIR", "/wrong"),
            ("GIT_WORK_TREE", "/wrong"),
            ("GIT_INDEX_FILE", "/wrong"),
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "remote.origin.pushurl"),
            ("GIT_CONFIG_VALUE_0", "https://example.invalid/repo"),
            ("GIT_CONFIG_GLOBAL", "/custom/config"),
            ("GIT_SSH", "ssh-custom"),
            ("GIT_SSH_COMMAND", "ssh -custom"),
            ("GIT_SSH_VARIANT", "ssh"),
            ("GIT_ASKPASS", "/askpass"),
            ("GIT_PAGER", "evil"),
            ("GIT_NO_REPLACE_OBJECTS", "0"),
            ("GIT_TERMINAL_PROMPT", "1"),
        ]);
        for publication in [false, true] {
            let command = git_command(&["status"], &env, &[], publication);
            let actual: Environment = command
                .get_envs()
                .map(|(key, value)| (key.to_owned(), value.unwrap().to_owned()))
                .collect();
            for name in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_PAGER"] {
                assert!(!actual.contains_key(OsStr::new(name)), "{name}");
            }
            for name in [
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0",
                "GIT_CONFIG_GLOBAL",
                "GIT_SSH",
                "GIT_SSH_COMMAND",
                "GIT_SSH_VARIANT",
                "GIT_ASKPASS",
            ] {
                assert_eq!(actual.contains_key(OsStr::new(name)), publication, "{name}");
            }
            for (key, value) in [
                ("LC_ALL", "C"),
                ("GIT_NO_REPLACE_OBJECTS", "1"),
                ("GIT_TERMINAL_PROMPT", "0"),
                ("HOME", "/home/test"),
            ] {
                assert_eq!(actual.get(OsStr::new(key)), Some(&OsString::from(value)));
            }
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                [
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.pager=cat",
                    "status",
                ]
                .map(OsStr::new)
            );
        }
        assert_eq!(GIT_TIMEOUT, Duration::from_secs(600));
    }

    #[test]
    fn retries_only_bare_failed_refs_with_exact_backoff_and_diagnostics() {
        let refs = vec!["refs/tags/a".into(), "refs/notes/b".into()];
        let mut calls = Vec::new();
        let mut sleeps = Vec::new();
        let mut diagnostics = Vec::new();
        push_with("origin", &refs, |args| {
            calls.push(args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>());
            Ok(match calls.len() {
                1 => output(false, "=\trefs/tags/a:refs/tags/a\t[up to date]\n!\trefs/notes/b:refs/notes/b\t[remote rejected] (failed)\n", ""),
                2 => output(false, "!\trefs/notes/b:refs/notes/b\t[remote rejected] (failed)\n", ""),
                _ => output(true, "", ""),
            })
        }, |duration| sleeps.push(duration), &mut diagnostics).unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[0],
            [
                "push",
                "--porcelain",
                "origin",
                "refs/tags/a:refs/tags/a",
                "refs/notes/b:refs/notes/b"
            ]
        );
        for call in &calls[1..] {
            assert_eq!(
                call,
                &["push", "--porcelain", "origin", "refs/notes/b:refs/notes/b"]
            );
        }
        assert_eq!(sleeps, [Duration::from_secs(2), Duration::from_secs(4)]);
        assert_eq!(
            String::from_utf8(diagnostics).unwrap(),
            concat!(
                "evidence-wrap: origin answered 1 ref(s) with a bare (failed); pushing them again (2 of 3)\n",
                "evidence-wrap: origin answered 1 ref(s) with a bare (failed); pushing them again (3 of 3)\n",
            )
        );
    }

    #[test]
    fn reasoned_refusals_and_transport_errors_never_retry() {
        for (stdout, stderr, expected) in [
            (
                "!\ta:a\t[remote rejected] (failed)\n!\tb:b\t[remote rejected] (pre-receive hook declined)\n",
                "",
                "push failed (try 1 of 3): a [remote rejected] (failed); b [remote rejected] (pre-receive hook declined)",
            ),
            ("", " network error \n", "push failed: network error"),
        ] {
            let mut calls = 0;
            let mut diagnostics = Vec::new();
            let error = push_with(
                "origin",
                &["a".into(), "b".into()],
                |_| {
                    calls += 1;
                    Ok(output(false, stdout, stderr))
                },
                |_| panic!("must not back off"),
                &mut diagnostics,
            )
            .unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert_eq!(calls, 1);
            assert!(diagnostics.is_empty());
        }
    }

    #[test]
    fn bare_failures_stop_at_three_and_preserve_refusal_order() {
        let mut calls = 0;
        let error = push_with(
            "origin",
            &["z".into(), "a".into()],
            |_| {
                calls += 1;
                Ok(output(
                    false,
                    "!\tz:z\t[remote rejected] (failed)\n!\ta:a\t[remote rejected] (failed)\n",
                    "",
                ))
            },
            |_| {},
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(calls, 3);
        assert_eq!(
            error.to_string(),
            "push failed (try 3 of 3): z [remote rejected] (failed); a [remote rejected] (failed)"
        );
    }

    fn run_in(
        repo: &std::path::Path,
        env: &Environment,
        args: &[&str],
        input: Option<&[u8]>,
        extra: &[(String, String)],
    ) -> Output {
        let mut command = git_command(args, env, extra, true);
        command.current_dir(repo);
        let done = capture(&mut command, input).unwrap();
        assert!(
            done.status.success(),
            "{}",
            String::from_utf8_lossy(&done.stderr)
        );
        done
    }

    #[test]
    fn https_overrides_token_header_and_configured_pushurl_survive_real_publication() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let sink = tmp.path().join("sink.git");
        let push_sink = tmp.path().join("push.git");
        std::fs::create_dir(&repo).unwrap();
        let mut env: Environment = std::env::vars_os()
            .filter(|(name, _)| !name.as_encoded_bytes().starts_with(b"GIT_"))
            .collect();
        env.insert("GIT_CONFIG_GLOBAL".into(), "/dev/null".into());
        env.insert("GIT_CONFIG_SYSTEM".into(), "/dev/null".into());
        run_in(&repo, &env, &["init", "-q"], None, &[]);
        for destination in [&sink, &push_sink] {
            run_in(
                &repo,
                &env,
                &["init", "-q", "--bare", destination.to_str().unwrap()],
                None,
                &[],
            );
        }
        let oid = run_in(
            &repo,
            &env,
            &["hash-object", "-w", "--stdin"],
            Some(b"record"),
            &[],
        );
        let oid = std::str::from_utf8(&oid.stdout).unwrap().trim();
        run_in(
            &repo,
            &env,
            &["update-ref", "refs/tags/evidence/test", oid],
            None,
            &[],
        );
        run_in(
            &repo,
            &env,
            &[
                "remote",
                "add",
                "https-sink",
                "https://evidence.invalid/repo",
            ],
            None,
            &[],
        );
        run_in(
            &repo,
            &env,
            &[
                "remote",
                "add",
                "pushurl-sink",
                "https://unreachable.invalid/fetch",
            ],
            None,
            &[],
        );
        let push_url = format!("file://{}", push_sink.display());
        run_in(
            &repo,
            &env,
            &["remote", "set-url", "--push", "pushurl-sink", &push_url],
            None,
            &[],
        );
        env.insert("GIT_CONFIG_COUNT".into(), "2".into());
        env.insert(
            "GIT_CONFIG_KEY_0".into(),
            format!("url.file://{}.insteadOf", sink.display()).into(),
        );
        env.insert(
            "GIT_CONFIG_VALUE_0".into(),
            "https://evidence.invalid/repo".into(),
        );
        env.insert("GIT_CONFIG_KEY_1".into(), "protocol.file.allow".into());
        env.insert("GIT_CONFIG_VALUE_1".into(), "always".into());
        let extra = token_environment("secret-token-xyz", &env).unwrap();
        assert_eq!(extra[0], ("GIT_CONFIG_COUNT".into(), "3".into()));
        assert_eq!(
            extra[1],
            ("GIT_CONFIG_KEY_2".into(), "http.extraheader".into())
        );
        assert_eq!(
            extra[2].1,
            format!(
                "Authorization: Basic {}",
                STANDARD.encode("x-access-token:secret-token-xyz")
            )
        );
        let command = git_command(&["push"], &env, &extra, true);
        assert!(
            !format!("{:?}", command.get_args().collect::<Vec<_>>()).contains("secret-token-xyz")
        );
        for remote in ["https-sink", "pushurl-sink"] {
            push_with(
                remote,
                &["refs/tags/evidence/test".into()],
                |args| {
                    let mut command = git_command(args, &env, &extra, true);
                    command.current_dir(&repo);
                    capture(&mut command, None)
                },
                |_| panic!("local publication must not retry"),
                &mut Vec::new(),
            )
            .unwrap();
        }
        for destination in [&sink, &push_sink] {
            let actual = run_in(
                destination,
                &env,
                &["rev-parse", "refs/tags/evidence/test"],
                None,
                &[],
            );
            assert_eq!(std::str::from_utf8(&actual.stdout).unwrap().trim(), oid);
        }
    }

    #[test]
    fn diagnostic_tail_matches_python_character_slicing() {
        let text = format!("\u{1c}{}end\u{1f}", "é".repeat(600));
        assert_eq!(
            diagnostic_tail(text.as_bytes()),
            format!("{}end", "é".repeat(497))
        );
        assert!(
            token_environment("", &environment(&[("GIT_CONFIG_COUNT", "invalid")]))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn token_errors_are_redacted_and_counts_use_python_integers() {
        assert_eq!(
            redact(
                anyhow::anyhow!("push failed: token-secret twice token-secret"),
                "token-secret"
            )
            .to_string(),
            "push failed: *** twice ***"
        );
        for (raw, count, next) in [
            (" +٠_٢ ", "2", "3"),
            ("-1", "-1", "0"),
            ("-10", "-10", "-9"),
            (
                "9999999999999999999999999999999999999999",
                "9999999999999999999999999999999999999999",
                "10000000000000000000000000000000000000000",
            ),
        ] {
            let extra =
                token_environment("secret", &environment(&[("GIT_CONFIG_COUNT", raw)])).unwrap();
            assert_eq!(extra[0].1, next);
            assert_eq!(extra[1].0, format!("GIT_CONFIG_KEY_{count}"));
        }
    }
}
