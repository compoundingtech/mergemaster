//! Object-only signature loading. Verification is not selective-reuse admission.
use super::{Statement, v2};
use crate::gate::{
    config::{self, ReuseAuthority, ReuseRole},
    git,
};
use anyhow::{Context, Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, io::Write, path::Path};

const MAX_COMMIT_BYTES: usize = 16 * 1024;
const MAX_TREE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    InvalidId,
    Unavailable,
    Oversized,
    NonCommit,
    InvalidLayout,
    InvalidStatement,
    WrongSubject,
    WrongTree,
    WrongParent,
    AuthorityInvalid,
    Unverified,
    IssuerMismatch,
    NotRoot,
    V1Promotion,
}
impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "selective reuse object refusal: {self:?}")
    }
}
impl std::error::Error for Refusal {}
type LoadResult<T> = std::result::Result<T, Refusal>;

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum VerifiedStatement<R: v2::Receipt = v2::DaemonPolicyReceipt> {
    V1(Box<Statement>),
    V2(Box<v2::Statement<R>>),
}
#[derive(Debug, Serialize)]
pub struct VerifiedRecord<R: v2::Receipt = v2::DaemonPolicyReceipt> {
    pub version: u32,
    pub record: String,
    pub statement: VerifiedStatement<R>,
    pub verified_signer: Option<String>,
    pub verified_key_id: Option<String>,
}

fn object(repo: &Path, id: &str, kind: &str, limit: usize) -> LoadResult<Vec<u8>> {
    if !config::full_commit(id) {
        return Err(Refusal::InvalidId);
    }
    let actual =
        git::git_bounded(repo, &["cat-file", "-t", id], 32).map_err(|_| Refusal::Unavailable)?;
    if actual.strip_suffix(b"\n") != Some(kind.as_bytes()) {
        return Err(if kind == "commit" {
            Refusal::NonCommit
        } else {
            Refusal::InvalidLayout
        });
    }
    let size =
        git::git_bounded(repo, &["cat-file", "-s", id], 32).map_err(|_| Refusal::Unavailable)?;
    let size = std::str::from_utf8(&size)
        .ok()
        .and_then(|size| size.trim().parse::<usize>().ok())
        .ok_or(Refusal::Oversized)?;
    if size > limit {
        return Err(Refusal::Oversized);
    }
    git::git_bounded(repo, &["cat-file", kind, id], limit).map_err(|_| Refusal::Unavailable)
}
struct Note {
    bytes: Vec<u8>,
    path: String,
    parents: Vec<String>,
}
fn note(repo: &Path, id: &str) -> LoadResult<Note> {
    let commit = object(repo, id, "commit", MAX_COMMIT_BYTES)?;
    let commit = std::str::from_utf8(&commit).map_err(|_| Refusal::InvalidLayout)?;
    let header = commit.split_once("\n\n").ok_or(Refusal::InvalidLayout)?.0;
    let tree = header
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("tree "))
        .ok_or(Refusal::InvalidLayout)?;
    object(repo, tree, "tree", MAX_TREE_BYTES)?;
    let entries = git::git_bounded(repo, &["ls-tree", "-z", tree], MAX_TREE_BYTES)
        .map_err(|_| Refusal::InvalidLayout)?;
    let mut entries = entries.split(|b| *b == 0).filter(|entry| !entry.is_empty());
    let entry = entries.next().ok_or(Refusal::InvalidLayout)?;
    if entries.next().is_some() {
        return Err(Refusal::InvalidLayout);
    }
    let entry = std::str::from_utf8(entry).map_err(|_| Refusal::InvalidLayout)?;
    let (metadata, path) = entry.split_once('\t').ok_or(Refusal::InvalidLayout)?;
    let blob = metadata
        .strip_prefix("100644 blob ")
        .ok_or(Refusal::InvalidLayout)?;
    if !config::full_commit(path) {
        return Err(Refusal::InvalidLayout);
    }
    Ok(Note {
        bytes: object(repo, blob, "blob", v2::MAX_NOTE_BYTES)?,
        path: path.to_owned(),
        parents: header
            .lines()
            .filter_map(|line| line.strip_prefix("parent ").map(str::to_owned))
            .collect(),
    })
}
fn is_v2(bytes: &[u8]) -> LoadResult<bool> {
    // Probe only selects the decoder; the strict decoder still checks all members.
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| Refusal::InvalidStatement)?;
    Ok(value
        .get("predicateType")
        .and_then(serde_json::Value::as_str)
        == Some(v2::PREDICATE_TYPE))
}
fn binding<R: v2::Receipt>(repo: &Path, note: &Note, s: &v2::Statement<R>) -> LoadResult<()> {
    let subject = &s.subject[0]; // strict v2 decoder requires exactly one
    let commit = object(repo, &subject.name, "commit", MAX_COMMIT_BYTES).map_err(|error| {
        if error == Refusal::NonCommit {
            Refusal::WrongSubject
        } else {
            error
        }
    })?;
    let commit = std::str::from_utf8(&commit).map_err(|_| Refusal::WrongSubject)?;
    if commit.lines().next() != Some(format!("tree {}", subject.digest.git_tree).as_str()) {
        return Err(Refusal::WrongTree);
    }
    let tree_kind = git::git_bounded(repo, &["cat-file", "-t", &subject.digest.git_tree], 32)
        .map_err(|_| Refusal::Unavailable)?;
    if tree_kind != b"tree\n" {
        return Err(Refusal::WrongTree);
    }
    if note.path != subject.digest.git_tree {
        return Err(Refusal::WrongTree);
    }
    if note.parents != [subject.name.as_str()] {
        return Err(Refusal::WrongParent);
    }
    Ok(())
}

fn signature(repo: &Path, id: &str, keys: &Path) -> LoadResult<(String, String)> {
    let keys = std::fs::canonicalize(keys).map_err(|_| Refusal::Unverified)?;
    let revocations = tempfile::NamedTempFile::new().map_err(|_| Refusal::Unverified)?;
    let allowed = format!("gpg.ssh.allowedSignersFile={}", keys.display());
    let revoked = format!("gpg.ssh.revocationFile={}", revocations.path().display());
    let settings = [
        "-c",
        "gpg.format=ssh",
        "-c",
        "gpg.ssh.program=ssh-keygen",
        "-c",
        &allowed,
        "-c",
        &revoked,
    ];
    let mut args = settings.to_vec();
    args.extend(["verify-commit", id]);
    git::git_bounded(repo, &args, 4096).map_err(|_| Refusal::Unverified)?;
    args.truncate(settings.len());
    args.extend(["show", "-s", "--format=%G?%x00%GS%x00%GF", id]);
    let identity = git::git_bounded(repo, &args, 4096).map_err(|_| Refusal::Unverified)?;
    let identity = std::str::from_utf8(&identity)
        .map_err(|_| Refusal::Unverified)?
        .trim_end_matches('\n');
    let fields: Vec<_> = identity.split('\0').collect();
    if fields.len() != 3 || fields[0] != "G" || fields[1].is_empty() {
        return Err(Refusal::Unverified);
    }
    let hash = fields[2]
        .strip_prefix("SHA256:")
        .ok_or(Refusal::Unverified)?;
    let digest = STANDARD_NO_PAD
        .decode(hash)
        .map_err(|_| Refusal::Unverified)?;
    if digest.len() != 32 || STANDARD_NO_PAD.encode(&digest) != hash {
        return Err(Refusal::Unverified);
    }
    Ok((fields[1].to_owned(), fields[2].to_owned()))
}
fn verify_v2<R: v2::Receipt>(
    repo: &Path,
    id: &str,
    note: Note,
    authority: &ReuseAuthority,
) -> LoadResult<VerifiedRecord<R>> {
    let s = v2::decode_with_receipt::<R>(&note.bytes).map_err(|_| Refusal::InvalidStatement)?;
    binding(repo, &note, &s)?;
    let ReuseAuthority::Valid(policy) = authority else {
        return Err(Refusal::AuthorityInvalid);
    };
    let p = &s.predicate;
    let key = policy
        .authorities
        .iter()
        .find(|key| {
            key.key_id == p.issuer.key_id
                && key.role == ReuseRole::V2ServiceIssuer
                && key.repository == s.repository
                && key.endpoint_id == p.issuer.service_id
        })
        .ok_or(Refusal::AuthorityInvalid)?;
    // Recompute rather than accepting either the signed label or a supplied key ID.
    let encoded = key
        .public_key
        .strip_prefix("ssh-ed25519 ")
        .ok_or(Refusal::AuthorityInvalid)?;
    let blob = STANDARD
        .decode(encoded)
        .map_err(|_| Refusal::AuthorityInvalid)?;
    let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob)));
    if fingerprint != key.key_id {
        return Err(Refusal::AuthorityInvalid);
    }
    let mut keys = tempfile::NamedTempFile::new().map_err(|_| Refusal::Unverified)?;
    writeln!(
        keys,
        "{} namespaces=\"git\" {}",
        key.principal, key.public_key
    )
    .map_err(|_| Refusal::Unverified)?;
    keys.flush().map_err(|_| Refusal::Unverified)?;
    let (signer, key_id) = signature(repo, id, keys.path())?;
    if signer != key.principal || p.signer != key.principal || key_id != p.issuer.key_id {
        return Err(Refusal::IssuerMismatch);
    }
    Ok(VerifiedRecord {
        version: 2,
        record: id.to_owned(),
        statement: VerifiedStatement::V2(Box::new(s)),
        verified_signer: Some(signer),
        verified_key_id: Some(key_id),
    })
}

/// The caller supplies the current BASE policy, never historical root policy.
/// No discovery, refs, alias resolution, chain traversal or fetch is performed.
pub fn load_root(repo: &Path, id: &str, authority: &ReuseAuthority) -> LoadResult<VerifiedRecord> {
    root_with_receipt(repo, id, authority)
}
fn root_with_receipt<R: v2::Receipt>(
    repo: &Path,
    id: &str,
    authority: &ReuseAuthority,
) -> LoadResult<VerifiedRecord<R>> {
    let note = note(repo, id)?;
    if !is_v2(&note.bytes)? {
        return Err(Refusal::V1Promotion);
    }
    let verified = verify_v2(repo, id, note, authority)?;
    let VerifiedStatement::V2(s) = &verified.statement else {
        return Err(Refusal::V1Promotion);
    };
    if s.predicate.reused_from.is_some() {
        return Err(Refusal::NotRoot);
    }
    Ok(verified)
}

/// Used only by the sanitized gate worker. V2 ignores legacy allowed signers.
pub fn verify_record(
    repo: &Path,
    id: &str,
    keys: &Path,
    base: Option<&str>,
) -> Result<VerifiedRecord> {
    verify_with_receipt(repo, id, keys, base)
}
pub(crate) fn verify_with_receipt<R: v2::Receipt>(
    repo: &Path,
    id: &str,
    keys: &Path,
    base: Option<&str>,
) -> Result<VerifiedRecord<R>> {
    if super::record_is_v2(repo, id)? {
        let note = note(repo, id)?;
        let base = base.context("v2 requires current BASE authority")?;
        ensure!(config::full_commit(base), "v2 requires immutable BASE");
        let config = config::load(repo, base)?;
        return Ok(verify_v2(repo, id, note, &config.policy.reuse_authority)?);
    }
    let s = super::verify_record(repo, id, keys)?;
    let (signer, key_id) = if s.predicate.tier == super::TrustTier::Degraded {
        (None, None)
    } else {
        // The legacy verifier already proved principal equality. Fingerprint
        // reporting is optional metadata, never an additional v1 trust check.
        let key_id = signature(repo, id, keys).ok().map(|(_, key_id)| key_id);
        (s.predicate.signer.clone(), key_id)
    };
    Ok(VerifiedRecord {
        version: 1,
        record: id.to_owned(),
        statement: VerifiedStatement::V1(Box::new(s)),
        verified_signer: signer,
        verified_key_id: key_id,
    })
}

/// Legacy selection accepts only v1 worker envelopes. No v2 admission path exists.
pub(crate) fn legacy_worker_statement(bytes: &[u8], id: &str) -> Result<Option<Statement>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        version: u32,
        record: String,
        statement: serde_json::Value,
        verified_signer: serde_json::Value,
        verified_key_id: serde_json::Value,
    }
    struct MapOnly;
    impl<'de> serde::de::Visitor<'de> for MapOnly {
        type Value = Wire;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a verified statement envelope")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            map: M,
        ) -> std::result::Result<Wire, M::Error> {
            Wire::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let wire = serde::Deserializer::deserialize_map(&mut decoder, MapOnly)?;
    decoder.end()?;
    ensure!(
        wire.record == id
            && matches!(wire.version, 1 | 2)
            && [&wire.verified_signer, &wire.verified_key_id]
                .iter()
                .all(|value| value.is_null() || value.is_string()),
        "signature worker envelope"
    );
    // Unconditional production stop, independent of policy, flags and fixtures.
    // Disabled v2 observations never enter v1 selection or failure shadowing.
    if wire.version == 2 {
        return Ok(None);
    }
    Ok(Some(
        serde_json::from_value(wire.statement).context("signature worker v1 statement")?,
    ))
}

#[cfg(test)]
#[path = "verified_tests.rs"]
pub(crate) mod tests;
