//! Account-local provisioning; scripts/evidence-keygen is the compatibility oracle.
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::{
    ffi::{CStr, OsStr},
    fs::{self, DirBuilder, FileType, Metadata, OpenOptions},
    io::{ErrorKind, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Args)]
pub struct KeygenArgs {
    /// Public alias, never a real host or account name.
    #[arg(long)]
    name: String,
    #[arg(long, default_value = "host", value_parser = ["host", "agent"])]
    level: String,
    /// Explicit absolute home override for special accounts and tests.
    #[arg(long)]
    home: Option<String>,
}

fn require(path: &Path, directory: bool, mode: Option<u32>, uid: u32) -> Result<Option<Metadata>> {
    let info = match fs::symlink_metadata(path) {
        Ok(info) => info,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let display = path.display();
    ensure!(
        !info.file_type().is_symlink(),
        "{display} is a symlink; refusing to follow it"
    );
    let kind: fn(&FileType) -> bool = if directory {
        FileType::is_dir
    } else {
        FileType::is_file
    };
    ensure!(
        kind(&info.file_type()),
        "{display} is not the kind of file expected"
    );
    ensure!(info.uid() == uid, "{display} belongs to another user");
    if let Some(mode) = mode {
        ensure!(
            info.mode() & 0o7777 == mode,
            "{display} has mode {:o}, not {mode:o}; fix it yourself, this script will not chmod an existing key",
            info.mode() & 0o7777
        );
    }
    Ok(Some(info))
}

fn run(program: &str, args: &[&OsStr]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    ensure!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn recorded_home(uid: u32) -> Result<PathBuf> {
    let mut buffer = vec![0u8; 4096];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: entry and buffer are writable for their stated sizes; result is
        // checked before reading entry, and pw_dir is copied before buffer drops.
        let code = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if code == libc::ERANGE {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        ensure!(
            code == 0 && !result.is_null(),
            "cannot find this account's home"
        );
        // SAFETY: successful getpwuid_r initializes entry and its NUL-terminated pw_dir.
        let home = unsafe { CStr::from_ptr(entry.assume_init().pw_dir) };
        return Ok(PathBuf::from(OsStr::from_bytes(home.to_bytes())));
    }
}

pub fn run_keygen(args: KeygenArgs) -> Result<()> {
    provision(args).context("evidence-keygen")
}

fn provision(args: KeygenArgs) -> Result<()> {
    let name = args.name.as_bytes();
    ensure!(
        !name.is_empty()
            && name.len() <= 40
            && (name[0].is_ascii_lowercase() || name[0].is_ascii_digit())
            && name
                .iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-'),
        "--name {:?} must be lowercase letters, digits and dashes, starting with one",
        args.name
    );
    // SAFETY: identity queries take no pointers; this single-threaded command
    // sets its process umask before creating any provisioning files.
    let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    ensure!(
        euid != 0,
        "refusing to run as root: run it as the user who will own the key"
    );
    unsafe {
        libc::umask(0o077);
    }
    let home = if let Some(home) = args.home.filter(|home| !home.is_empty()) {
        ensure!(home.starts_with('/'), "--home must be an absolute path");
        PathBuf::from(home)
    } else {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        ensure!(home.is_absolute(), "HOME must be set to an absolute path");
        let recorded = recorded_home(uid)?;
        ensure!(
            fs::canonicalize(&home).unwrap_or_else(|_| home.clone())
                == fs::canonicalize(&recorded).unwrap_or_else(|_| recorded.clone()),
            "HOME ({}) is not this account's home ({}); pass --home DIR to mean another",
            home.display(),
            recorded.display()
        );
        home
    };
    // Match pathlib lexically: discard "."/empty components, not ".." or symlinks.
    let spelling = home.as_os_str().as_bytes();
    let mut normalized = PathBuf::from(
        if spelling.starts_with(b"//") && !spelling.starts_with(b"///") {
            "//"
        } else {
            "/"
        },
    );
    normalized.extend(home.components().skip(1));
    let home = normalized;
    let directory = home.join(".config/st");
    let key = directory.join("evidence-sign-key");
    let scratch = directory.join("evidence-sign-scratch.git");
    let config = directory.join("evidence-sign.json");
    let signer = format!("{}/{}", args.level, args.name);
    let wanted = serde_json::json!({"signer": signer, "ssh_key": key, "scratch_repo": scratch});
    require(&directory, true, None, uid)?;
    if require(&config, false, Some(0o600), uid)?.is_some() {
        ensure!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&config)?)? == wanted,
            "{} exists and differs from {wanted}; remove it first if you mean to replace it",
            config.display()
        );
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)?;
    let info = require(&directory, true, None, uid)?.context("missing key directory")?;
    ensure!(
        info.mode() & 0o077 == 0,
        "{} is readable or writable by others; chmod 700 it yourself",
        directory.display()
    );
    if require(&key, false, Some(0o600), uid)?.is_none() {
        run(
            "ssh-keygen",
            &[
                OsStr::new("-q"),
                OsStr::new("-t"),
                OsStr::new("ed25519"),
                OsStr::new("-N"),
                OsStr::new(""),
                OsStr::new("-C"),
                OsStr::new(&signer),
                OsStr::new("-f"),
                key.as_os_str(),
            ],
        )?;
        require(&key, false, Some(0o600), uid)?;
    }
    let public = run(
        "ssh-keygen",
        &[OsStr::new("-y"), OsStr::new("-f"), key.as_os_str()],
    )?;
    let mut fields = public.split_whitespace();
    let algorithm = fields.next();
    let public_key = fields.next();
    ensure!(
        algorithm == Some("ssh-ed25519") && public_key.is_some(),
        "{} is not an ed25519 key",
        key.display()
    );
    if require(&scratch, true, None, uid)?.is_none() {
        run(
            "git",
            &[
                OsStr::new("init"),
                OsStr::new("-q"),
                OsStr::new("--bare"),
                scratch.as_os_str(),
            ],
        )?;
    }
    match fs::symlink_metadata(&config) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o600)
                .open(&config)?;
            writeln!(file, "{}", serde_json::to_string_pretty(&wanted)?)?;
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    crate::cli_println!(
        "{signer} namespaces=\"git\" ssh-ed25519 {}",
        public_key.context("missing public key")?
    );
    eprintln!(
        "signer {signer}; key {}; configuration {}",
        key.display(),
        config.display()
    );
    eprintln!("List the printed line in .st/evidence-keys with a pull request.");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn another_owner_is_refused_without_changing_the_directory() {
        use std::os::unix::fs::MetadataExt;
        let directory = tempfile::tempdir().unwrap();
        let before = directory.path().metadata().unwrap();
        let error = super::require(directory.path(), true, None, before.uid() + 1).unwrap_err();
        assert!(error.to_string().contains("belongs to another user"));
        let after = directory.path().metadata().unwrap();
        assert_eq!((before.uid(), before.mode()), (after.uid(), after.mode()));
    }
}
