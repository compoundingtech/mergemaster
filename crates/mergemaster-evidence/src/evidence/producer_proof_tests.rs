use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{EncodingKey, Header, encode, get_current_timestamp};
use serde_json::{Value, json};
use std::{io::Write, process::{Command, Stdio}, sync::LazyLock};

// Ephemeral test-only RSA key: never written to disk, never used for signing records.
static KEY: LazyLock<(EncodingKey, JwkSet, Vec<u8>)> = LazyLock::new(|| {
        let private = Command::new("openssl").args(["genrsa", "2048"]).output().unwrap();
        assert!(private.status.success());
        let mut public = Command::new("openssl").args(["rsa", "-modulus", "-noout"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        public.stdin.take().unwrap().write_all(&private.stdout).unwrap();
        let public = public.wait_with_output().unwrap();
        assert!(public.status.success());
        let modulus = String::from_utf8(public.stdout).unwrap();
        let n = URL_SAFE_NO_PAD.encode(hex::decode(modulus.trim().strip_prefix("Modulus=").unwrap()).unwrap());
        let jwks = serde_json::from_value(json!({"keys":[{"kty":"RSA","kid":"test","alg":"RS256","use":"sig","n":n,"e":"AQAB"}]})).unwrap();
        let mut pem = Command::new("openssl").args(["pkey", "-pubout"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        pem.stdin.take().unwrap().write_all(&private.stdout).unwrap();
        let pem = pem.wait_with_output().unwrap();
        assert!(pem.status.success());
        (EncodingKey::from_rsa_pem(&private.stdout).unwrap(), jwks, pem.stdout)
});

fn key() -> &'static (EncodingKey, JwkSet, Vec<u8>) { &KEY }

fn fixture() -> (Receipt, Expected, Value) {
    let hash = "a".repeat(64);
    let bindings: Bindings = serde_json::from_value(json!({
        "accepted_base":"b".repeat(40), "artifact_id":900, "artifact_sha256":hash,
        "candidate_sha":"c".repeat(40), "candidate_tree":"d".repeat(40), "check_run_id":200,
        "environment_sha256":hash, "job_id":300, "lane":"tests", "lane_sha256":hash,
        "owner_id":10, "recipe_sha256":hash, "repository":"example/project", "repository_id":20,
        "run_attempt":2, "run_id":100, "workflow_path":".github/workflows/payload.yml", "workflow_sha256":hash
    })).unwrap();
    let receipt = Receipt { action_keys: BTreeMap::from([("nix".into(), hash.clone())]), bindings: bindings.clone(),
        log_sha256: hash.clone(), manifest_sha256: hash, result: Outcome::Success, schema_version: 1 };
    let expected = Expected { bindings, job_workflow_ref: format!("example/project/.github/workflows/engine.yml@{}", "e".repeat(40)),
        job_workflow_sha: "e".repeat(40), oidc_sha: "f".repeat(40), event: "pull_request".into(), action_backends: vec!["nix".into()] };
    let now = get_current_timestamp();
    let claims = json!({"iss":ISSUER,"aud":format!("{AUDIENCE}{}", hex::encode(Sha256::digest(serde_json::to_vec(&receipt).unwrap()))),
        "iat":now,"nbf":now-1,"exp":now+300,"repository":"example/project","repository_id":"20","repository_owner_id":"10",
        "run_id":"100","run_attempt":"2","check_run_id":"200","event_name":"pull_request","sha":expected.oidc_sha,
        "job_workflow_ref":expected.job_workflow_ref,"job_workflow_sha":expected.job_workflow_sha});
    (receipt, expected, claims)
}

fn token(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test".into());
    encode(&header, claims, &key().0).unwrap()
}

#[test]
fn producer_proof_accepts_real_signature_and_rejects_wrong_bindings() {
    let (receipt, expected, claims) = fixture();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    assert!(verify(&bytes, &token(&claims), &key().1, &expected).is_ok());
    for (field, value, code) in [
        ("candidate_tree", json!("0".repeat(40)), "tree_mismatch"),
        ("run_attempt", json!(3), "wrong_attempt"),
        ("recipe_sha256", json!("0".repeat(64)), "wrong_recipe"),
        ("run_id", json!(999), "foreign_run"),
        ("job_id", json!(301), "wrong_job"),
        ("artifact_id", json!(901), "artifact_unbound"),
        ("artifact_sha256", json!("0".repeat(64)), "artifact_unbound"),
    ] {
        let mut wrong = serde_json::to_value(&expected.bindings).unwrap();
        wrong[field] = value;
        let mut policy = expected.clone();
        policy.bindings = serde_json::from_value(wrong).unwrap();
        assert!(verify(&bytes, &token(&claims), &key().1, &policy).unwrap_err().to_string().contains(code), "{field}");
    }
}

#[test]
fn producer_proof_refuses_forgery_expiry_and_unbound_job_or_workflow() {
    let (receipt, expected, claims) = fixture();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    for (field, value) in [
        ("check_run_id", json!("201")), ("run_attempt", json!("1")), ("run_id", json!("101")),
        ("repository_id", json!("21")), ("repository_owner_id", json!("11")),
        ("job_workflow_sha", json!("0".repeat(40))), ("job_workflow_ref", json!("untrusted@main")),
        ("sha", json!("0".repeat(40))), ("event_name", json!("push")),
        ("iss", json!("https://attacker.invalid")), ("aud", json!([claims["aud"]])),
        ("exp", json!(get_current_timestamp()-1)), ("iat", json!(get_current_timestamp()+300)),
        ("nbf", json!(get_current_timestamp()+300)),
    ] {
        let mut wrong = claims.clone();
        wrong[field] = value;
        assert!(verify(&bytes, &token(&wrong), &key().1, &expected).is_err(), "{field}");
    }
    let mut forged = token(&claims).into_bytes();
    let signature = forged.iter().rposition(|b| *b == b'.').unwrap()+1;
    forged[signature] = if forged[signature] == b'A' { b'B' } else { b'A' };
    assert!(verify(&bytes, std::str::from_utf8(&forged).unwrap(), &key().1, &expected).is_err());
    assert!(verify(&bytes, &token(&claims), &JwkSet { keys: vec![] }, &expected).is_err());
    let duplicate = JwkSet { keys: vec![key().1.keys[0].clone(), key().1.keys[0].clone()] };
    assert!(verify(&bytes, &token(&claims), &duplicate, &expected).is_err());
    let mut hs_header = Header::new(Algorithm::HS256);
    hs_header.kid = Some("test".into());
    let wrong_alg = encode(&hs_header, &claims, &EncodingKey::from_secret(&key().2)).unwrap();
    assert!(verify(&bytes, &wrong_alg, &key().1, &expected).is_err());
    let none = format!("{}.{}.", URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"test","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()));
    assert!(verify(&bytes, &none, &key().1, &expected).is_err());
    let mut unknown_header = Header::new(Algorithm::RS256);
    unknown_header.kid = Some("unknown".into());
    let unknown = encode(&unknown_header, &claims, &key().0).unwrap();
    assert!(verify(&bytes, &unknown, &key().1, &expected).is_err());
    let mut policy = expected.clone();
    policy.action_backends.push("buck2".into());
    assert!(verify(&bytes, &token(&claims), &key().1, &policy).is_err());
}

#[test]
fn producer_proof_requires_canonical_receipt_and_exact_authenticated_bytes() {
    let (receipt, expected, claims) = fixture();
    let mut bytes = serde_json::to_vec(&receipt).unwrap();
    bytes.push(b' ');
    assert!(verify(&bytes, &token(&claims), &key().1, &expected).is_err());
    let mut changed = receipt.clone();
    changed.result = Outcome::Failure;
    assert!(verify(&serde_json::to_vec(&changed).unwrap(), &token(&claims), &key().1, &expected).is_err());
    let canonical = String::from_utf8(serde_json::to_vec(&receipt).unwrap()).unwrap();
    for invalid in [canonical.replacen("{", "{\"schema_version\":1,", 1), canonical.replacen("{", "{\"unknown\":1,", 1)] {
        assert!(verify(invalid.as_bytes(), &token(&claims), &key().1, &expected).is_err());
    }
    let duplicate_map = canonical.replacen("\"action_keys\":{", "\"action_keys\":{\"nix\":\"duplicate\",", 1);
    assert!(verify(duplicate_map.as_bytes(), &token(&claims), &key().1, &expected).is_err());
    let mut future = receipt.clone();
    future.schema_version = 2;
    let future = serde_json::to_vec(&future).unwrap();
    assert!(verify(&future, &token(&claims), &key().1, &expected).is_err());
}
