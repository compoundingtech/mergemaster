//! Read-only Git plumbing with ambient repository selectors and helpers disabled.
#[path = "git_deadline.rs"]
pub(crate) mod deadline;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Command, Stdio},
};

/// Also usable on the isolated evidence worker: its child Git processes inherit
/// these overrides without changing this process's environment.
pub fn sanitize(command: &mut Command) {
    for (key, _) in env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("GIT_") || name.starts_with("LD_") || name.starts_with("DYLD_") {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_ALLOW_PROTOCOL", "")
        .env("LC_ALL", "C");
    let settings = [
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("core.untrackedCache", "false"),
        ("core.attributesFile", "/dev/null"),
        ("diff.external", ""),
        ("diff.trustExitCode", "false"),
        ("credential.helper", ""),
        ("core.askPass", "/bin/false"),
        ("core.sshCommand", "/bin/false"),
        ("protocol.allow", "never"),
        ("log.showSignature", "false"),
        ("core.pager", "cat"),
    ];
    command.env("GIT_CONFIG_COUNT", settings.len().to_string());
    for (index, (key, value)) in settings.iter().enumerate() {
        command
            .env(format!("GIT_CONFIG_KEY_{index}"), key)
            .env(format!("GIT_CONFIG_VALUE_{index}"), value);
    }
}

pub fn command(repo: &Path) -> Command {
    let mut command = Command::new("git");
    sanitize(&mut command);
    command.arg("-C").arg(repo).stdin(Stdio::null());
    command
}

pub fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let mut child = deadline::GitChild::spawn(command(repo).args(args))
        .context("running trusted Git plumbing")?;
    let mut output = Vec::new();
    child.stdout()?.read_to_end(&mut output)?;
    let status = child.wait()?;
    // Git diagnostics can contain candidate-controlled paths; do not forward them.
    ensure!(status.success(), "Git plumbing failed ({status})");
    Ok(output)
}

/// Refuse oversized output without exposing a truncated result or Git diagnostics.
pub fn git_bounded(repo: &Path, args: &[&str], max_bytes: usize) -> Result<Vec<u8>> {
    collect_bounded(
        deadline::GitChild::spawn(command(repo).args(args))?,
        max_bytes,
    )
}
fn collect_bounded(mut child: deadline::GitChild, max_bytes: usize) -> Result<Vec<u8>> {
    let limit = u64::try_from(max_bytes)?
        .checked_add(1)
        .context("Git byte limit overflow")?;
    let mut bytes = Vec::new();
    child.stdout()?.take(limit).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= max_bytes,
        "Git output exceeds {max_bytes} bytes"
    );
    let status = child.wait()?;
    ensure!(status.success(), "Git plumbing failed ({status})");
    Ok(bytes)
}

pub fn text(repo: &Path, args: &[&str]) -> Result<String> {
    let mut value = String::from_utf8(git(repo, args)?).context("Git output is not UTF-8")?;
    value.truncate(value.trim_end().len());
    Ok(value)
}

/// One request at a time bounds buffering and avoids pipe-capacity deadlocks.
pub fn blob_digests(repo: &Path, ids: &BTreeSet<&str>) -> Result<BTreeMap<String, String>> {
    blobs(repo, ids, true)
}

pub fn validate_blobs(repo: &Path, ids: &BTreeSet<&str>) -> Result<()> {
    blobs(repo, ids, false).map(|_| ())
}
/// Stream committed blob bytes once per object, in request order, without one
/// process per file. Fails closed on a truncated body, a missing terminator,
/// or any absent/non-blob object.
pub fn blob_contents(
    repo: &Path,
    ids: &[String],
    timeout: std::time::Duration,
) -> Result<Vec<Vec<u8>>> {
    let child = deadline::GitChild::with_timeout(
        command(repo)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped()),
        timeout,
    )
    .context("running trusted Git plumbing")?;
    collect_blob_contents(child, ids)
}
fn collect_blob_contents(mut child: deadline::GitChild, ids: &[String]) -> Result<Vec<Vec<u8>>> {
    let bodies = (|| {
        let mut input = child.stdin()?;
        let mut output = BufReader::new(child.stdout()?);
        let mut bodies = Vec::with_capacity(ids.len());
        for id in ids {
            ensure!(super::config::full_commit(id), "invalid blob ID");
            writeln!(input, "{id}")?;
            input.flush()?;
            let size = blob_size(&mut output, id)?;
            let count: usize = size.try_into().context("Git blob size overflow")?;
            let mut body = vec![0; count];
            output.read_exact(&mut body).context("truncated Git blob")?;
            let mut newline = [0];
            output.read_exact(&mut newline)?;
            ensure!(&newline == b"\n", "invalid Git blob terminator");
            bodies.push(body);
        }
        Ok::<_, anyhow::Error>(bodies)
    })()?;
    let status = child.wait()?;
    ensure!(status.success(), "Git plumbing failed ({status})");
    Ok(bodies)
}

fn blob_size(output: &mut impl BufRead, id: &str) -> Result<u64> {
    let mut header = String::new();
    output.read_line(&mut header)?;
    ensure!(header.ends_with('\n'), "expected committed regular file");
    let fields: Vec<_> = header.split_whitespace().collect();
    ensure!(
        fields.len() == 3 && fields[0] == id && fields[1] == "blob",
        "expected committed regular file"
    );
    fields[2].parse().context("invalid Git blob size")
}

fn blobs(repo: &Path, ids: &BTreeSet<&str>, hash: bool) -> Result<BTreeMap<String, String>> {
    let child = deadline::GitChild::with_timeout(
        command(repo)
            .args(["cat-file", if hash { "--batch" } else { "--batch-check" }])
            .stdin(Stdio::piped()),
        std::time::Duration::from_secs(60),
    )
    .context("running trusted Git plumbing")?;
    collect_blobs(child, ids, hash)
}
fn collect_blobs(
    mut child: deadline::GitChild,
    ids: &BTreeSet<&str>,
    hash: bool,
) -> Result<BTreeMap<String, String>> {
    let digests = (|| {
        let mut input = child.stdin()?;
        let mut output = BufReader::new(child.stdout()?);
        let mut digests = BTreeMap::new();
        for id in ids {
            ensure!(super::config::full_commit(id), "invalid blob ID");
            writeln!(input, "{id}")?;
            input.flush()?;
            // Both batch modes require a complete header, including its newline.
            let size = blob_size(&mut output, id)?;
            if !hash {
                continue;
            }
            let mut bytes = (&mut output).take(size);
            let mut digest = Sha256::new();
            let mut buffer = [0; 8192];
            loop {
                let count = bytes.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
            }
            ensure!(bytes.limit() == 0, "truncated Git blob");
            let mut newline = [0];
            output.read_exact(&mut newline)?;
            ensure!(&newline == b"\n", "invalid Git blob terminator");
            digests.insert((*id).to_owned(), hex::encode(digest.finalize()));
        }
        Ok::<_, anyhow::Error>(digests)
    })()?;
    let status = child.wait()?;
    ensure!(status.success(), "Git plumbing failed ({status})");
    Ok(digests)
}

#[cfg(test)]
mod tests {
    use super::blob_size;

    #[test]
    fn batch_headers_require_newlines_in_both_modes() {
        let id = "a".repeat(40);
        for hash in [false, true] {
            let mut complete = format!("{id} blob 3\n").into_bytes();
            if hash {
                complete.extend_from_slice(b"abc\n");
            }
            assert_eq!(blob_size(&mut complete.as_slice(), &id).unwrap(), 3);
            let truncated = format!("{id} blob 3");
            let error = blob_size(&mut truncated.as_bytes(), &id).unwrap_err();
            assert_eq!(error.to_string(), "expected committed regular file");
            assert!(blob_size(&mut b"".as_slice(), &id).is_err());
        }
    }
    #[test]
    fn bounded_deadline_preserves_limits_status_and_timeout() {
        use super::{collect_bounded, deadline::GitChild};
        use std::{io::ErrorKind, process::Command, time::Duration};
        for (size, status, expected) in [(128, 0, true), (129, 0, false), (0, 7, false)] {
            let mut command = Command::new("python3");
            command.args([
                "-c",
                "import os,sys;os.write(1,b'x'*int(sys.argv[1]));sys.exit(int(sys.argv[2]))",
                &size.to_string(),
                &status.to_string(),
            ]);
            let result = collect_bounded(GitChild::spawn(&mut command).unwrap(), 128);
            assert_eq!(result.is_ok(), expected);
            if let Ok(bytes) = result {
                assert_eq!(bytes, vec![b'x'; size]);
            }
        }
        let mut command = Command::new("python3");
        command.args(["-c", "import signal;signal.pause()"]);
        let child = GitChild::with_timeout(&mut command, Duration::ZERO).unwrap();
        let error = collect_bounded(child, 128).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            ErrorKind::TimedOut
        );
    }
    #[test]
    fn native_batch_deadlines_preserve_framing_status_and_timeout() {
        use super::{collect_blob_contents, collect_blobs, deadline::GitChild};
        use std::{
            collections::BTreeSet,
            process::{Command, Stdio},
            time::Duration,
        };
        let ids = vec!["a".repeat(40), "b".repeat(40)];
        let keys: BTreeSet<_> = ids.iter().map(String::as_str).collect();
        for mode in ["contents", "hash", "check"] {
            for (fault, success) in [
                ("none", true),
                ("status", false),
                ("missing", false),
                ("header", false),
                ("truncated", false),
                ("terminator", false),
            ] {
                if mode == "check" && matches!(fault, "truncated" | "terminator") {
                    continue;
                }
                let mut command = Command::new("python3");
                command
                    .args([
                        "-c",
                        r"
import sys
for line in sys.stdin:
 oid=line.strip()
 if sys.argv[2]=='missing': print(oid+' missing',flush=True);continue
 if sys.argv[2]=='header': print('broken',flush=True);continue
 sys.stdout.write(oid+' blob 3\n');sys.stdout.flush()
 if sys.argv[1]!='check':
  sys.stdout.write('ab' if sys.argv[2]=='truncated' else
                   'abc!' if sys.argv[2]=='terminator' else 'abc\n')
  sys.stdout.flush()
  if sys.argv[2]=='truncated': break
sys.exit(7 if sys.argv[2]=='status' else 0)
",
                        mode,
                        fault,
                    ])
                    .stdin(Stdio::piped());
                let child = GitChild::spawn(&mut command).unwrap();
                let result = if mode == "contents" {
                    collect_blob_contents(child, &ids).map(|bodies| {
                        assert_eq!(bodies, vec![b"abc".to_vec(); 2]);
                    })
                } else {
                    collect_blobs(child, &keys, mode == "hash").map(|digests| {
                        assert_eq!(digests.len(), if mode == "hash" { 2 } else { 0 });
                    })
                };
                assert_eq!(result.is_ok(), success, "{mode}/{fault}: {result:?}");
            }
            for empty in [false, true] {
                let no_keys = BTreeSet::new();
                let mut command = Command::new("python3");
                command
                    .args(["-c", "import signal;signal.pause()"])
                    .stdin(Stdio::piped());
                let child = GitChild::with_timeout(&mut command, Duration::ZERO).unwrap();
                let error = if mode == "contents" {
                    collect_blob_contents(child, if empty { &[] } else { &ids }).unwrap_err()
                } else {
                    collect_blobs(child, if empty { &no_keys } else { &keys }, mode == "hash")
                        .unwrap_err()
                };
                assert_eq!(
                    error.downcast_ref::<std::io::Error>().unwrap().kind(),
                    std::io::ErrorKind::TimedOut
                );
            }
        }
    }

    #[test]
    fn native_batch_deadlines_read_actual_git_in_both_formats() {
        for format in ["sha1", "sha256"] {
            let repo = tempfile::tempdir().unwrap();
            super::git(
                repo.path(),
                &["init", "-q", &format!("--object-format={format}")],
            )
            .unwrap();
            std::fs::write(repo.path().join("blob"), b"abc").unwrap();
            let id = super::text(repo.path(), &["hash-object", "-w", "blob"]).unwrap();
            let ids = vec![id.clone(), id.clone()];
            let keys = std::collections::BTreeSet::from([id.as_str()]);
            if format == "sha256" {
                // Native policy's 40-hex domain is intentionally unchanged here.
                assert_eq!(
                    super::blob_contents(repo.path(), &ids, std::time::Duration::from_secs(300))
                        .unwrap_err()
                        .to_string(),
                    "invalid blob ID"
                );
                assert_eq!(
                    super::validate_blobs(repo.path(), &keys)
                        .unwrap_err()
                        .to_string(),
                    "invalid blob ID"
                );
                assert_eq!(
                    super::blob_digests(repo.path(), &keys)
                        .unwrap_err()
                        .to_string(),
                    "invalid blob ID"
                );
                continue;
            }
            assert_eq!(
                super::blob_contents(repo.path(), &ids, std::time::Duration::from_secs(300))
                    .unwrap(),
                vec![b"abc".to_vec(); 2]
            );
            super::validate_blobs(repo.path(), &keys).unwrap();
            assert_eq!(
                super::blob_digests(repo.path(), &keys).unwrap()[&id],
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }
    }
}
