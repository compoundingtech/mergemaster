//! Offline contracts backed by the recorded, credential-free GitHub observations.
use super::*;
use anyhow::{Result, bail};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    process::{Command, Stdio},
    sync::LazyLock,
};

const APP_ID: u64 = 12345;
const TOKEN: &str = "fixture-installation-token";
const BOOTSTRAP: &str = "fixture-bootstrap-token";
const LANE: &str = "graph-full-check";
const ASSET: &[u8] = b"fixture-pinned-verifier";
const ENROLLMENT: &str = include_str!("../../../iac/consumers.json");

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/evidence-reconcile.json"
    ))
    .unwrap()
}
fn head() -> String {
    fixture()["pull"]["head"]["sha"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn base() -> String {
    fixture()["base_ref"]["object"]["sha"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn consumer() -> Consumer {
    load_consumers(ENROLLMENT, Some("schickling/factory"), None)
        .unwrap()
        .remove(0)
}
fn decision() -> Value {
    json!({"version":1,"check":LANE,"base":base(),"head":head(),"decision":"skip",
           "outcome":"satisfied","report_only":false,"summary":"trusted signed evidence"})
}
fn output(code: i32, value: &Value) -> ProcessOutput {
    ProcessOutput {
        code,
        stdout: serde_json::to_vec(value).unwrap(),
    }
}
fn permissions() -> Value {
    json!({"checks":"write","contents":"read","pull_requests":"read","metadata":"read"})
}

#[derive(Debug)]
struct ApiCall {
    token: String,
    method: String,
    path: String,
    payload: Option<Value>,
}
struct FixtureCapabilities {
    pull: Value,
    branch: Value,
    checks: Vec<Value>,
    installation: Value,
    token_response: Value,
    installation_repositories: Vec<Value>,
    repository: Value,
    calls: Vec<ApiCall>,
    commands: Vec<ProcessRequest>,
    gates: Vec<ProcessRequest>,
    pin: Value,
    policy: Value,
    gate_code: i32,
    fail_factory: bool,
}
impl Default for FixtureCapabilities {
    fn default() -> Self {
        let f = fixture();
        let mut repository = f["repository"].clone();
        repository["owner"] = json!({"login":"schickling","id":1});
        Self {
            pull: f["pull"].clone(),
            branch: f["base_ref"].clone(),
            checks: vec![],
            installation: json!({"id":777,"app_id":APP_ID,"repository_selection":"selected","account":{"login":"schickling","id":1}}),
            token_response: json!({"token":TOKEN,"repositories":[f["repository"]],"permissions":permissions()}),
            installation_repositories: vec![f["repository"].clone()],
            repository,
            calls: vec![],
            commands: vec![],
            gates: vec![],
            pin: json!({"version":1,"repository":"compoundingtech/mergemaster","revision":"c".repeat(40),
                       "release":{"version":"v1.2.3","sha256":format!("{:x}",Sha256::digest(ASSET))}}),
            policy: json!({"version":1,"lanes":{
                "graph-full-check":{"mode":"required_evidence","events":["pull_request"]},
                "not-required":{"mode":"optional_fallback","events":["pull_request"]}}}),
            gate_code: 0,
            fail_factory: false,
        }
    }
}
impl Capabilities for FixtureCapabilities {
    fn api(
        &mut self,
        token: &str,
        method: &str,
        path: &str,
        payload: Option<&Value>,
    ) -> Result<Value> {
        self.calls.push(ApiCall {
            token: token.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            payload: payload.cloned(),
        });
        if self.fail_factory && path.starts_with("repos/schickling/factory") {
            bail!("fixture repository failure");
        }
        match (method, path) {
            ("GET", "repos/schickling/factory/installation") => Ok(self.installation.clone()),
            ("POST", "app/installations/777/access_tokens") => Ok(self.token_response.clone()),
            ("GET", "repos/schickling/factory") => Ok(self.repository.clone()),
            ("GET", "repos/schickling/factory/pulls/998") => Ok(self.pull.clone()),
            ("GET", "repos/schickling/factory/git/ref/heads/main") => Ok(self.branch.clone()),
            _ if method == "GET" && path.starts_with("installation/repositories?") => {
                let repositories = if token == "fixture-ptg-token" {
                    json!([{"id":1459778656_u64,"full_name":"schickling/ptg"}])
                } else {
                    json!(self.installation_repositories)
                };
                Ok(json!({"repositories":repositories}))
            }
            _ if method == "GET" && path.contains("/check-runs?") => {
                Ok(json!({"check_runs":self.checks}))
            }
            _ if (method == "POST" || method == "PATCH") && path.contains("/check-runs") => {
                Ok(json!({"id":91}))
            }
            ("GET", "repos/schickling/ptg/installation") => Ok(
                json!({"id":778,"app_id":APP_ID,"repository_selection":"selected","account":{"login":"schickling","id":1}}),
            ),
            ("POST", "app/installations/778/access_tokens") => Ok(
                json!({"token":"fixture-ptg-token","repositories":[{"id":1459778656_u64,"full_name":"schickling/ptg"}],"permissions":permissions()}),
            ),
            ("GET", "repos/schickling/ptg") => Ok(
                json!({"id":1459778656_u64,"full_name":"schickling/ptg","default_branch":"main","owner":{"login":"schickling","id":1}}),
            ),
            _ if method == "GET" && path.starts_with("repos/schickling/ptg/pulls?") => {
                Ok(json!([]))
            }
            _ => bail!("unexpected API call: {method} {path}"),
        }
    }
    fn process(&mut self, request: ProcessRequest) -> Result<ProcessOutput> {
        assert!(!request.env.contains_key("MERGEMASTER_APP_PRIVATE_KEY"));
        assert!(!request.args.iter().any(|arg| arg.contains("fixture-key")));
        let args = &request.args;
        if args.first().is_some_and(|arg| arg == "git") {
            assert_eq!(&args[1..3], ["-c", "core.hooksPath=/dev/null"]);
            let git = &args[3..];
            let text = match git.first().map(String::as_str) {
                Some("show") if git[1] == format!("{}:.mergemaster/lanes.json", base()) => {
                    self.policy.to_string()
                }
                Some("show") if git[1] == format!("{}:.mergemaster/tool-pin.json", base()) => {
                    self.pin.to_string()
                }
                Some("show") => panic!("non-BASE authorization read: {git:?}"),
                Some("rev-parse") => base(),
                _ => String::new(),
            };
            self.commands.push(request);
            return Ok(ProcessOutput {
                code: 0,
                stdout: text.into_bytes(),
            });
        }
        if args.starts_with(&["gh".into(), "release".into(), "download".into()]) {
            let destination = args[args.iter().position(|a| a == "--dir").unwrap() + 1].clone();
            std::fs::write(
                std::path::Path::new(&destination).join("mergemaster-x86_64-unknown-linux-musl"),
                ASSET,
            )?;
            self.commands.push(request);
            return Ok(ProcessOutput {
                code: 0,
                stdout: vec![],
            });
        }
        if args.starts_with(&["gh".into(), "attestation".into(), "verify".into()]) {
            self.commands.push(request);
            return Ok(ProcessOutput {
                code: 0,
                stdout: vec![],
            });
        }
        assert_eq!(args[1], "gate", "only the pinned verifier may execute");
        let flag = |name: &str| args[args.iter().position(|a| a == name).unwrap() + 1].clone();
        assert_eq!(flag("--base"), base());
        assert_eq!(flag("--head"), head());
        let event: Value = serde_json::from_slice(&std::fs::read(flag("--event-file"))?)?;
        assert_eq!(event["repository"]["full_name"], "schickling/factory");
        assert_eq!(event["repository"]["id"], 1398595057_u64);
        assert_eq!(event["pull_request"]["base"]["sha"], base());
        assert_eq!(
            request.env.get("GITHUB_REPOSITORY").unwrap(),
            "schickling/factory"
        );
        assert_eq!(request.env.get("GITHUB_TOKEN").unwrap(), TOKEN);
        assert_eq!(request.env.get("GH_TOKEN").unwrap(), TOKEN);
        let mut value = decision();
        value["check"] = json!(flag("--check"));
        self.gates.push(request);
        Ok(output(self.gate_code, &value))
    }
    fn jwt(&mut self, app_id: u64, key: &str) -> Result<String> {
        assert_eq!(app_id, APP_ID);
        assert_eq!(key, "fixture-key");
        Ok("fixture-app-jwt".to_owned())
    }
}
fn runtime() -> (Reconciler<FixtureCapabilities>, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let env = BTreeMap::from([(
        "MERGEMASTER_APP_PRIVATE_KEY".to_owned(),
        "fixture-key".to_owned(),
    )]);
    (
        Reconciler::new(
            &APP_ID.to_string(),
            "fixture-key",
            BOOTSTRAP,
            FixtureCapabilities::default(),
            env,
            directory.path().to_owned(),
        )
        .unwrap(),
        directory,
    )
}
fn check(id: u64) -> Value {
    json!({"id":id,"name":LANE,"head_sha":head(),"app":{"id":APP_ID},"status":"completed","conclusion":"failure"})
}
fn writes(runtime: &Reconciler<FixtureCapabilities>) -> Vec<&ApiCall> {
    runtime
        .capabilities
        .calls
        .iter()
        .filter(|c| c.method == "POST" || c.method == "PATCH")
        .collect()
}
fn publish(runtime: &mut Reconciler<FixtureCapabilities>, success: bool) -> Result<()> {
    runtime.publish(
        TOKEN,
        &consumer(),
        &fixture()["pull"],
        &base(),
        LANE,
        success,
        "verified signed evidence",
    )
}

#[test]
fn committed_numeric_repository_allowlist() {
    let entries = load_consumers(ENROLLMENT, None, None).unwrap();
    let values: Vec<Value> = entries
        .iter()
        .map(|entry| serde_json::to_value(entry).unwrap())
        .collect();
    assert_eq!(
        values
            .iter()
            .map(|v| (
                v["owner"].as_str().unwrap(),
                v["repository"].as_str().unwrap(),
                v["repositoryId"].as_u64().unwrap()
            ))
            .collect::<Vec<_>>(),
        vec![
            ("schickling", "factory", 1398595057),
            ("schickling", "ptg", 1459778656)
        ]
    );
    assert_eq!(
        load_consumers(ENROLLMENT, Some("schickling/factory"), None)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        load_consumers(ENROLLMENT, None, Some(998)).unwrap().len(),
        2
    );
}
#[test]
fn unknown_repository_and_invalid_pr_filter_fail_closed() {
    for repo in [
        "attacker/project",
        "https://github.com/schickling/factory",
        "../factory",
    ] {
        assert!(load_consumers(ENROLLMENT, Some(repo), None).is_err());
    }
    assert!(load_consumers(ENROLLMENT, None, Some(0)).is_err());
    for number in ["-1", "not-a-number"] {
        assert!(Args::try_parse_from(["mergemaster-reconciler", "--pr", number]).is_err());
    }
}
#[test]
fn required_lanes_are_selected_only_from_base_policy() {
    let policy = json!({"version":1,"lanes":{
        "required":{"mode":"required_evidence","events":["pull_request"]},
        "optional":{"mode":"optional_fallback","events":["pull_request"]},
        "push-only":{"mode":"required_evidence","events":["push"]}}});
    assert_eq!(required_lanes(&policy).unwrap(), vec!["required"]);
}
#[test]
fn gate_success_requires_exact_identity_and_accepted_decision() {
    for outcome in ["satisfied", "reused"] {
        let mut value = decision();
        value["outcome"] = json!(outcome);
        assert_eq!(
            gate_result(&output(0, &value), LANE, &base(), &head()),
            (true, "trusted signed evidence".to_owned())
        );
    }
    for (field, value) in [
        ("decision", json!("run")),
        ("decision", json!("refuse")),
        ("outcome", json!("rejected")),
        ("report_only", json!(true)),
        ("report_only", Value::Null),
    ] {
        let mut d = decision();
        d[field] = value;
        assert!(!gate_result(&output(0, &d), LANE, &base(), &head()).0);
    }
}
#[test]
fn unbound_or_malformed_gate_output_cannot_authorize_success() {
    for (field, value) in [
        ("version", json!(2)),
        ("head", json!("a".repeat(40))),
        ("base", json!("b".repeat(40))),
        ("check", json!("other-lane")),
        ("summary", json!(42)),
    ] {
        let mut d = decision();
        d[field] = value;
        assert!(!gate_result(&output(0, &d), LANE, &base(), &head()).0);
    }
    assert!(!gate_result(&output(1, &decision()), LANE, &base(), &head()).0);
    for stdout in [b"not json".to_vec(), b"[]".to_vec(), vec![]] {
        assert!(!gate_result(&ProcessOutput { code: 0, stdout }, LANE, &base(), &head()).0);
    }
}
#[test]
fn missing_check_is_created_on_explicit_head_with_app_token() {
    let (mut r, _directory) = runtime();
    publish(&mut r, true).unwrap();
    let w = writes(&r);
    assert_eq!(w.len(), 1);
    assert_eq!(
        (&*w[0].method, &*w[0].path),
        ("POST", "repos/schickling/factory/check-runs")
    );
    let p = w[0].payload.as_ref().unwrap();
    assert_eq!(p["name"], LANE);
    assert_eq!(p["head_sha"], head());
    assert_eq!(p["conclusion"], "success");
    assert_eq!(w[0].token, TOKEN);
}
#[test]
fn existing_name_head_app_is_patched_not_created() {
    let (mut r, _directory) = runtime();
    r.capabilities.checks = vec![check(91)];
    publish(&mut r, true).unwrap();
    let w = writes(&r);
    assert_eq!(w.len(), 1);
    assert_eq!(
        (&*w[0].method, &*w[0].path),
        ("PATCH", "repos/schickling/factory/check-runs/91")
    );
    assert_eq!(w[0].payload.as_ref().unwrap()["conclusion"], "success");
}
#[test]
fn other_app_head_or_lane_never_matches_existing_check() {
    for (field, value) in [
        ("app", json!({"id":APP_ID+1})),
        ("head_sha", json!("c".repeat(40))),
        ("name", json!("spoofed")),
    ] {
        let (mut r, _directory) = runtime();
        let mut c = check(91);
        c[field] = value;
        r.capabilities.checks = vec![c];
        assert!(publish(&mut r, true).is_err());
        assert!(writes(&r).is_empty());
    }
}
#[test]
fn failed_verification_patches_existing_green_to_failure() {
    let (mut r, _directory) = runtime();
    let mut c = check(91);
    c["conclusion"] = json!("success");
    r.capabilities.checks = vec![c];
    publish(&mut r, false).unwrap();
    let w = writes(&r);
    assert_eq!(w[0].method, "PATCH");
    assert_eq!(w[0].payload.as_ref().unwrap()["conclusion"], "failure");
}
#[test]
fn changed_head_base_closed_or_fork_never_publishes_success() {
    for case in 0..4 {
        let (mut r, _directory) = runtime();
        match case {
            0 => r.capabilities.pull["head"]["sha"] = json!("d".repeat(40)),
            1 => r.capabilities.branch["object"]["sha"] = json!("e".repeat(40)),
            2 => r.capabilities.pull["state"] = json!("closed"),
            _ => r.capabilities.pull["head"]["repo"]["full_name"] = json!("attacker/fork"),
        }
        assert!(publish(&mut r, true).is_err());
        assert!(writes(&r).is_empty());
    }
}
#[test]
fn mint_is_one_numeric_repository_and_narrow_permissions() {
    let (mut r, _directory) = runtime();
    assert_eq!(r.installation(&consumer()).unwrap(), TOKEN);
    let w = writes(&r);
    assert_eq!(w.len(), 1);
    assert_eq!(
        (&*w[0].method, &*w[0].path, &*w[0].token),
        (
            "POST",
            "app/installations/777/access_tokens",
            "fixture-app-jwt"
        )
    );
    assert_eq!(
        w[0].payload.as_ref().unwrap(),
        &json!({"repository_ids":[1398595057_u64],"permissions":{"checks":"write","contents":"read","pull_requests":"read"}})
    );
    assert_eq!(r.capabilities.calls.last().unwrap().token, TOKEN);
}
#[test]
fn wrong_app_or_installation_account_never_mints() {
    for (field, value) in [
        ("app_id", json!(APP_ID + 1)),
        ("account", json!({"login":"attacker","id":2})),
    ] {
        let (mut r, _directory) = runtime();
        r.capabilities.installation[field] = value;
        assert!(r.installation(&consumer()).is_err());
        assert!(writes(&r).is_empty());
    }
}
#[test]
fn overbroad_or_wrong_repository_token_is_rejected() {
    let repository = fixture()["repository"].clone();
    let mut wrong_id = repository.clone();
    wrong_id["id"] = json!(999);
    let mut wrong_name = repository.clone();
    wrong_name["full_name"] = json!("attacker/project");
    let mut actions = permissions();
    actions["actions"] = json!("write");
    let mut contents = permissions();
    contents["contents"] = json!("write");
    for (field, value) in [
        (
            "repositories",
            json!([repository,{"id":999,"full_name":"attacker/project"}]),
        ),
        ("repositories", json!([wrong_id])),
        ("repositories", json!([wrong_name])),
        ("permissions", actions),
        ("permissions", contents),
        ("permissions", json!({"checks":"write"})),
    ] {
        let (mut r, _directory) = runtime();
        r.capabilities.token_response[field] = value;
        assert!(r.installation(&consumer()).is_err());
    }
}
#[test]
fn live_repository_transfer_or_replacement_is_rejected() {
    for (field, value) in [
        ("id", json!(1398595058_u64)),
        ("full_name", json!("attacker/factory")),
        ("owner", json!({"login":"attacker","id":2})),
    ] {
        let (mut r, _directory) = runtime();
        r.capabilities.repository[field] = value;
        assert!(r.installation(&consumer()).is_err());
    }
}
#[test]
fn api_rejects_external_urls_and_path_traversal_before_transport() {
    let (mut r, _directory) = runtime();
    for path in [
        "https://attacker.invalid/repos/x/y",
        "repos/../attacker",
        "repos/x/y\nAuthorization: forged",
        "repos/x/y#fragment",
    ] {
        assert!(r.call(TOKEN, "GET", path, None).is_err());
    }
    assert!(r.capabilities.calls.is_empty());
}

// Only key generation uses OpenSSL. Runtime JWT signing is exercised through jsonwebtoken.
static RSA_KEY: LazyLock<(String, Vec<u8>)> = LazyLock::new(|| {
    let private = Command::new("openssl")
        .args(["genrsa", "2048"])
        .output()
        .unwrap();
    assert!(private.status.success());
    let mut public = Command::new("openssl")
        .args(["pkey", "-pubout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    public
        .stdin
        .take()
        .unwrap()
        .write_all(&private.stdout)
        .unwrap();
    let public = public.wait_with_output().unwrap();
    assert!(public.status.success());
    (String::from_utf8(private.stdout).unwrap(), public.stdout)
});
#[test]
fn jwt_uses_actual_rs256_library_signing_without_private_key_subprocess() {
    let (private, public) = &*RSA_KEY;
    let token = sign_jwt(APP_ID, private, 1_700_000_000).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(header, json!({"alg":"RS256","typ":"JWT"}));
    assert_eq!(
        claims,
        json!({"iss":APP_ID.to_string(),"iat":1_699_999_940_u64,"exp":1_700_000_540_u64})
    );
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_exp = false;
    let decoded = jsonwebtoken::decode::<Value>(
        &token,
        &jsonwebtoken::DecodingKey::from_rsa_pem(public).unwrap(),
        &validation,
    )
    .unwrap();
    assert_eq!(decoded.claims, claims);
    // Signing remains available even when every permitted subprocess tool is unusable.
    // Thus the real capability cannot delegate this private key to git/gh or a signer process.
    let mut capabilities = RealCapabilities {
        git: std::path::PathBuf::from("/nonexistent/fixture-git"),
        gh: std::path::PathBuf::from("/nonexistent/fixture-gh"),
        environ: BTreeMap::from([("PATH".to_owned(), String::new())]),
    };
    let actual = capabilities.jwt(APP_ID, private).unwrap();
    let actual = jsonwebtoken::decode::<Value>(
        &actual,
        &jsonwebtoken::DecodingKey::from_rsa_pem(public).unwrap(),
        &validation,
    )
    .unwrap();
    assert_eq!(actual.claims["iss"], APP_ID.to_string());
    assert!(!token.contains(private));
    assert!(sign_jwt(APP_ID, "not a private key", 1_700_000_000).is_err());
}
#[test]
fn base_only_authorization_and_no_candidate_checkout_or_execution() {
    let (mut r, _directory) = runtime();
    assert_eq!(r.reconcile_pull(TOKEN, &consumer(), 998).unwrap(), 0);
    let git: Vec<&[String]> = r
        .capabilities
        .commands
        .iter()
        .filter(|c| c.args[0] == "git")
        .map(|c| &c.args[3..])
        .collect();
    let checkout: Vec<&[String]> = git.iter().copied().filter(|a| a[0] == "checkout").collect();
    assert_eq!(
        checkout,
        vec![
            vec![
                "checkout".to_owned(),
                "--detach".to_owned(),
                "--force".to_owned(),
                base()
            ]
            .as_slice()
        ]
    );
    let show: Vec<&[String]> = git.iter().copied().filter(|a| a[0] == "show").collect();
    assert_eq!(
        show,
        vec![
            vec![
                "show".to_owned(),
                format!("{}:.mergemaster/lanes.json", base())
            ]
            .as_slice(),
            vec![
                "show".to_owned(),
                format!("{}:.mergemaster/tool-pin.json", base())
            ]
            .as_slice()
        ]
    );
    let fetch = git.iter().find(|a| a[0] == "fetch").unwrap();
    assert!(fetch.contains(&head()));
    assert!(fetch.contains(&"+refs/notes/evidence/*:refs/notes/evidence/*".to_owned()));
    assert_eq!(r.capabilities.gates.len(), 1);
    assert_eq!(
        writes(&r)[0].payload.as_ref().unwrap()["conclusion"],
        "success"
    );
    let attestation = r
        .capabilities
        .commands
        .iter()
        .find(|c| {
            c.args
                .starts_with(&["gh".into(), "attestation".into(), "verify".into()])
        })
        .unwrap();
    for flag in ["--source-digest", "--signer-digest"] {
        assert_eq!(
            attestation.args[attestation.args.iter().position(|a| a == flag).unwrap() + 1],
            "c".repeat(40)
        );
    }
    assert!(
        attestation
            .args
            .contains(&"--deny-self-hosted-runners".to_owned())
    );
    assert!(
        attestation
            .args
            .contains(&"compoundingtech/mergemaster/.github/workflows/release.yml".to_owned())
    );
    for command in r.capabilities.commands.iter().filter(|c| c.args[0] == "gh") {
        assert_eq!(command.env.get("GH_TOKEN").unwrap(), BOOTSTRAP);
    }
}
#[test]
fn nonzero_verifier_cannot_publish_claimed_success() {
    let (mut r, _directory) = runtime();
    r.capabilities.gate_code = 1;
    assert!(r.reconcile_pull(TOKEN, &consumer(), 998).unwrap() > 0);
    assert_eq!(
        writes(&r)[0].payload.as_ref().unwrap()["conclusion"],
        "failure"
    );
}
#[test]
fn bad_release_digest_posts_failure_without_running_verifier() {
    let (mut r, _directory) = runtime();
    r.capabilities.pin["release"]["sha256"] = json!("0".repeat(64));
    assert!(r.reconcile_pull(TOKEN, &consumer(), 998).unwrap() > 0);
    assert!(r.capabilities.gates.is_empty());
    assert_eq!(
        writes(&r)[0].payload.as_ref().unwrap()["conclusion"],
        "failure"
    );
    assert!(
        !r.capabilities.commands.iter().any(|c| c.args.starts_with(&[
            "gh".into(),
            "attestation".into(),
            "verify".into()
        ]))
    );
}
#[test]
fn repository_failure_does_not_skip_other_enrolled_work() {
    let (mut r, _directory) = runtime();
    r.capabilities.fail_factory = true;
    let entries = load_consumers(ENROLLMENT, None, None).unwrap();
    assert_eq!(r.run_all(&entries, None), 1);
    assert!(
        r.capabilities
            .calls
            .iter()
            .any(|c| c.path == "repos/schickling/factory/installation")
    );
    assert!(
        r.capabilities
            .calls
            .iter()
            .any(|c| c.path == "repos/schickling/ptg/installation")
    );
    assert!(
        r.capabilities
            .calls
            .iter()
            .any(|c| c.path.starts_with("repos/schickling/ptg/pulls?"))
    );
}
#[test]
fn hostless_main_only_serialized_schedule_and_manual_repair() {
    let workflow = include_str!("../../../.github/workflows/evidence-reconcile.yml");
    for contract in [
        "cron: '2-57/5 * * * *'",
        "workflow_dispatch:",
        "runs-on: ubuntu-24.04",
        "if: github.ref == 'refs/heads/main'",
        "environment: mergemaster-check-publisher",
        "group: evidence-reconcile",
        "cancel-in-progress: false",
        "persist-credentials: false",
    ] {
        assert!(
            workflow.contains(contract),
            "missing workflow contract: {contract}"
        );
    }
    let (before, run) = workflow
        .split_once("      - name: Reconcile enrolled evidence checks")
        .unwrap();
    assert!(!before.contains("MERGEMASTER_APP_PRIVATE_KEY"));
    assert!(
        run.contains("MERGEMASTER_APP_PRIVATE_KEY: ${{ secrets.MERGEMASTER_APP_PRIVATE_KEY }}")
    );
    assert!(before.contains("      - name: Build reconciler package"));
    assert!(before.contains("id: reconciler"));
    assert!(before.contains("nix build .#evidence-reconciler --no-link --print-out-paths"));
    assert!(before.contains("/bin/mergemaster-reconciler"));
    assert!(run.contains("RECONCILER_BINARY: ${{ steps.reconciler.outputs.binary }}"));
    assert!(run.contains("\"$RECONCILER_BINARY\" \"${args[@]}\""));
    for forbidden in [
        "checks: write",
        "contents: write",
        "self-hosted",
        "python",
        "reconciler/main.py",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "forbidden workflow contract: {forbidden}"
        );
    }
}

#[test]
fn unlisted_dispatch_repository_refuses_before_any_api_or_mint() {
    let (mut r, _directory) = runtime();
    assert!(load_consumers(ENROLLMENT, Some("attacker/project"), None).is_err());
    let mut unlisted = consumer();
    unlisted.owner = "attacker".to_owned();
    unlisted.repository = "project".to_owned();
    unlisted.repository_id = 999;
    assert!(r.installation(&unlisted).is_err());
    let mut replaced = consumer();
    replaced.repository_id = 999;
    assert!(r.installation(&replaced).is_err());
    assert!(r.capabilities.calls.is_empty());
    assert!(r.capabilities.commands.is_empty());
}

#[test]
fn all_missing_or_unknown_installation_selection_refuses_before_mint() {
    for selection in [Some("all"), None, Some("unknown")] {
        let (mut r, _directory) = runtime();
        if let Some(selection) = selection {
            r.capabilities.installation["repository_selection"] = json!(selection);
        } else {
            r.capabilities
                .installation
                .as_object_mut()
                .unwrap()
                .remove("repository_selection");
        }
        assert!(r.installation(&consumer()).is_err());
        assert!(writes(&r).is_empty());
    }
}

#[test]
fn installation_repository_listing_rejects_unlisted_numeric_ids() {
    for repository in [
        json!({"id":999,"full_name":"attacker/project"}),
        json!({"id":999,"full_name":"schickling/factory"}),
        json!({"id":1398595057_u64,"full_name":"attacker/project"}),
    ] {
        let (mut r, _directory) = runtime();
        r.capabilities.installation_repositories.push(repository);
        assert!(r.installation(&consumer()).is_err());
        let listing = r
            .capabilities
            .calls
            .iter()
            .find(|c| c.path.starts_with("installation/repositories?"))
            .unwrap();
        assert_eq!(listing.token, TOKEN);
        assert!(
            !r.capabilities
                .calls
                .iter()
                .any(|c| c.path == "repos/schickling/factory")
        );
        let mint = writes(&r);
        assert_eq!(mint.len(), 1);
        assert_eq!(
            mint[0].payload.as_ref().unwrap()["repository_ids"],
            json!([1398595057_u64])
        );
    }
}
