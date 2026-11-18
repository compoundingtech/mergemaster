//! Python NamedTemporaryFile ownership for the CLI only; native callers stay unchanged.
use super::{
    cli_adapter::decode, crate_manifest_ops::exception, projection_process_error::os_diagnostic,
    python_repr::Repr, source_io, value_inputs::TextRef,
};
use crate::evidence::legacy_policy::PolicyError;
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
    sync::OnceLock,
};

// Cache successes only, as Python does; a failed directory search is retryable.
static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

pub struct TemporaryFile(tempfile::NamedTempFile);
impl TemporaryFile {
    pub fn new(suffix: &str) -> Result<Self, PolicyError> {
        let directory = match DIRECTORY.get() {
            Some(path) => path.clone(),
            None => {
                let path = directory()?;
                let _ = DIRECTORY.set(path.clone());
                path
            }
        };
        Self::in_directory(&directory, suffix)
    }
    fn in_directory(directory: &Path, suffix: &str) -> Result<Self, PolicyError> {
        let mut attempted = directory.to_owned();
        tempfile::Builder::new()
            .prefix("tmp")
            .suffix(suffix)
            .rand_bytes(8)
            .make_in(directory, |path| {
                attempted = path.to_owned();
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
            })
            .map(Self)
            .map_err(|e| source_io::error(attempted.as_os_str(), &e))
    }
    pub fn path(&self) -> &Path {
        self.0.path()
    }
    pub fn write_and_flush(&mut self, bytes: &[u8]) -> Result<(), PolicyError> {
        self.0
            .as_file_mut()
            .write_all(bytes)
            .and_then(|()| self.0.as_file_mut().flush())
            .map_err(|e| {
                let mut error = source_io::error(self.path().as_os_str(), &e);
                error.detail = os_diagnostic(&e, None).into();
                error
            })
    }
}
/// POSIX lexical abspath, including exactly two leading slashes and raw bytes.
pub(super) fn abspath(path: &Path) -> std::io::Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let bytes = joined.as_os_str().as_bytes();
    let mut parts = Vec::new();
    for part in bytes.split(|b| *b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    let mut result = if bytes.starts_with(b"//") && !bytes.starts_with(b"///") {
        b"//".to_vec()
    } else {
        b"/".to_vec()
    };
    for part in parts {
        if result.last() != Some(&b'/') {
            result.push(b'/');
        }
        result.extend_from_slice(part);
    }
    Ok(std::ffi::OsString::from_vec(result).into())
}
fn directory() -> Result<PathBuf, PolicyError> {
    let mut candidates: Vec<PathBuf> = ["TMPDIR", "TEMP", "TMP"]
        .into_iter()
        .filter_map(std::env::var_os)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .collect();
    candidates.extend(["/tmp", "/var/tmp", "/usr/tmp"].map(PathBuf::from));
    candidates.push(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    for candidate in &candidates {
        let Ok(absolute) = abspath(candidate) else {
            continue;
        };
        if let Ok(mut probe) = TemporaryFile::in_directory(&absolute, "")
            && probe.write_and_flush(b"blat").is_ok()
        {
            return Ok(absolute);
        }
    }
    let names = candidates
        .iter()
        .map(|p| format!("{}", Repr(TextRef::from(&decode(p.as_os_str())))))
        .collect::<Vec<_>>()
        .join(", ");
    Err(exception(
        "FileNotFoundError",
        format!("[Errno 2] No usable temporary directory found in [{names}]"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn files_match_python_mode_contents_suffix_and_failure_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let output = crate::pinned_python::command().args(["-c", r#"
import json,os,stat,sys,tempfile
with tempfile.NamedTemporaryFile(suffix='.keys',dir=sys.argv[1]) as f:
 f.write(b'key\x00\xff\n');f.flush()
 print(json.dumps([stat.S_IMODE(os.stat(f.name).st_mode),list(open(f.name,'rb').read()),f.name.endswith('.keys')]))
assert not os.listdir(sys.argv[1])
"#]).arg(directory.path()).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        for suffix in [".keys", ".log-keys", ""] {
            let mut path = PathBuf::new();
            let result: Result<(), PolicyError> = (|| {
                let mut file = TemporaryFile::in_directory(directory.path(), suffix)?;
                path = file.path().to_owned();
                file.write_and_flush(b"key\0\xff\n")?;
                assert_eq!(
                    serde_json::json!([
                        file.path().metadata().unwrap().permissions().mode() & 0o777,
                        std::fs::read(file.path()).unwrap(),
                        true
                    ]),
                    expected
                );
                assert!(
                    file.path()
                        .as_os_str()
                        .as_encoded_bytes()
                        .ends_with(suffix.as_bytes())
                );
                Err(exception("ValueError", "mid-run failure"))
            })();
            assert!(result.is_err());
            assert!(!path.exists());
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        }
        let writable = directory.path().join("writable");
        std::fs::create_dir(&writable).unwrap();
        for candidate in [
            writable.join("nonexistent/.."),
            PathBuf::from("writable/nonexistent/.."),
        ] {
            let python = crate::pinned_python::command()
                .args(["-c", "import json,os,tempfile;print(json.dumps(list(os.fsencode(tempfile.gettempdir()))))"])
                .env("TMPDIR", &candidate).current_dir(directory.path()).output().unwrap();
            assert!(python.status.success());
            let expected: Vec<u8> = serde_json::from_slice(&python.stdout).unwrap();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "evidence::legacy_verify::cli_tempfile::tests::directory_search_driver",
                    "--nocapture",
                ])
                .env("TMPDIR", &candidate)
                .env(
                    "MERGEMASTER_TEMP_EXPECTED",
                    serde_json::to_string(&expected).unwrap(),
                )
                .current_dir(directory.path())
                .output()
                .unwrap();
            assert!(
                child.status.success(),
                "{}",
                String::from_utf8_lossy(&child.stdout)
            );
            assert_eq!(std::fs::read_dir(&writable).unwrap().count(), 0);
        }
    }
    #[test]
    fn directory_search_driver() {
        let Ok(expected) = std::env::var("MERGEMASTER_TEMP_EXPECTED") else {
            return;
        };
        let expected: Vec<u8> = serde_json::from_str(&expected).unwrap();
        let file = TemporaryFile::new(".keys").unwrap();
        assert_eq!(
            file.path().parent().unwrap().as_os_str().as_bytes(),
            expected
        );
    }
}
