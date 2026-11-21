//! Local measurement only: builds and release attestation verification belong to the workflow.
use crate::gate::config::{
    Producer, ProducerFlavor, ProducerManifest, ProducerProvenance, nix_store_path,
};
use anyhow::{Context, Result, ensure};
use clap::{Args as ClapArgs, Subcommand};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hash local executable bytes or merge previously measured manifests.
    /// Never executes the candidate binary or invokes Nix. Release attestation
    /// verification (gh attestation verify) must be performed by the workflow.
    Measure(Measure),
}

#[derive(ClapArgs)]
#[command(group(clap::ArgGroup::new("source").required(true).args(["nix_package", "release_asset", "merge"])))]
struct Measure {
    /// Realized top-level /nix/store output; measures bin/mergemaster.
    #[arg(long, requires_all = ["system", "mergemaster_revision", "package"])]
    nix_package: Option<PathBuf>,
    /// Published executable asset, already authenticated by the workflow.
    #[arg(long, requires_all = ["sha256sums", "asset_name", "system", "mergemaster_revision"])]
    release_asset: Option<PathBuf>,
    /// Strict GNU SHA256SUMS (lowercase digest, space, space or '*', asset name).
    #[arg(long, requires = "release_asset")]
    sha256sums: Option<PathBuf>,
    #[arg(long, requires = "release_asset")]
    asset_name: Option<String>,
    #[arg(long, conflicts_with = "merge")]
    system: Option<String>,
    /// Full source revision derived by the workflow from the resolved input.
    #[arg(long, conflicts_with = "merge")]
    mergemaster_revision: Option<String>,
    /// Stable consumer package attribute, not a derivation path.
    #[arg(long, requires = "nix_package")]
    package: Option<String>,
    /// Combine version-one manifests emitted by measurement; duplicates refuse.
    #[arg(long, num_args = 1.., value_name = "ENTRY_FILES")]
    merge: Vec<PathBuf>,
    /// Refuse unless this manifest is byte-identical to canonical output.
    #[arg(long, value_name = "MANIFEST")]
    check: Option<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Measure(args) => measure(args),
    }
}

fn measure(args: Measure) -> Result<()> {
    let mut producers = Vec::new();
    if let Some(out_path) = args.nix_package {
        let output = out_path.to_str().context("Nix output path must be UTF-8")?;
        ensure!(
            nix_store_path(output),
            "expected a top-level /nix/store output path"
        );
        producers.push(Producer {
            executable_sha256: hash_file(&out_path.join("bin/mergemaster"), true)?,
            flavor: ProducerFlavor::Nix,
            provenance: ProducerProvenance {
                mergemaster_revision: args.mergemaster_revision.context("missing revision")?,
                nix_output_path: Some(output.to_owned()),
                package: args.package.context("missing package")?,
            },
            system: args.system.context("missing system")?,
        });
    } else if let Some(asset) = args.release_asset {
        let name = args.asset_name.context("missing asset name")?;
        ensure!(
            !name.is_empty()
                && !name.contains(['/', '\\'])
                && !name.chars().any(char::is_whitespace),
            "asset name must be a plain filename without whitespace"
        );
        let sums_path = args.sha256sums.context("missing SHA256SUMS")?;
        let sums = fs::read_to_string(&sums_path)
            .with_context(|| format!("read {}", sums_path.display()))?;
        let checksums = parse_checksums(&sums)?;
        let expected = checksums
            .get(name.as_str())
            .context("asset missing from SHA256SUMS")?;
        let digest = hash_file(&asset, false)?;
        ensure!(digest == *expected, "release asset SHA256SUMS mismatch");
        producers.push(Producer {
            executable_sha256: digest,
            flavor: ProducerFlavor::Release,
            provenance: ProducerProvenance {
                mergemaster_revision: args.mergemaster_revision.context("missing revision")?,
                nix_output_path: None,
                package: name,
            },
            system: args.system.context("missing system")?,
        });
    } else {
        for path in args.merge {
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let manifest: ProducerManifest = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse {}", path.display()))?;
            manifest.validate()?;
            producers.extend(manifest.producers);
        }
    }
    let mut manifest = ProducerManifest {
        producers,
        version: 1,
    };
    for producer in &mut manifest.producers {
        producer
            .provenance
            .mergemaster_revision
            .make_ascii_lowercase();
    }
    manifest.validate()?;
    manifest.producers.sort_unstable_by(|left, right| {
        (&left.system, &left.flavor, &left.executable_sha256).cmp(&(
            &right.system,
            &right.flavor,
            &right.executable_sha256,
        ))
    });
    // Struct fields in the shared schema are declared in lexicographic order.
    let mut bytes = serde_json::to_vec(&manifest)?;
    bytes.push(b'\n');
    if let Some(path) = args.check {
        let committed = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        ensure!(
            committed == bytes,
            "producer manifest drift: {} differs from canonical measurement",
            path.display()
        );
    }
    std::io::stdout().lock().write_all(&bytes)?;
    Ok(())
}

fn hash_file(path: &Path, reject_symlink: bool) -> Result<String> {
    if reject_symlink {
        ensure!(
            fs::symlink_metadata(path)
                .with_context(|| format!("inspect {}", path.display()))?
                .file_type()
                .is_file(),
            "measured executable must be a regular file, not a symlink: {}",
            path.display()
        );
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    if reject_symlink {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file: File = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "measured path must be a regular file: {}",
        path.display()
    );
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn parse_checksums(sums: &str) -> Result<BTreeMap<&str, &str>> {
    let mut entries = BTreeMap::new();
    for line in sums.split_terminator('\n') {
        let bytes = line.as_bytes();
        ensure!(
            bytes.len() > 66
                && bytes[..64]
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
                && bytes[64] == b' '
                && matches!(bytes[65], b' ' | b'*')
                && !line[66..].contains(['\\', '\r'])
                && !line[66..].chars().any(char::is_control),
            "malformed SHA256SUMS line"
        );
        let (digest, name) = (&line[..64], &line[66..]);
        ensure!(
            entries.insert(name, digest).is_none(),
            "duplicate SHA256SUMS line for {name}"
        );
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::hash_file;
    use std::fs;

    #[test]
    fn nix_file_measurement_hashes_regular_bytes_and_refuses_directories() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("mergemaster");
        fs::write(&binary, b"abc").unwrap();
        assert_eq!(
            hash_file(&binary, true).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(hash_file(root.path(), true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn nix_file_measurement_refuses_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("mergemaster");
        fs::write(&binary, b"abc").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&binary, &link).unwrap();
        assert!(hash_file(&link, true).is_err());
    }
}
