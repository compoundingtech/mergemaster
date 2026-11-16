#![forbid(unsafe_code)]
//! Reconcile BASE-authorized evidence without executing candidate source.

use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CONSUMERS: &str = include_str!("../../../iac/consumers.json");

#[derive(Debug, Parser)]
#[command(about = "Reconcile BASE-authorized evidence checks; never execute candidate source")]
pub struct Args {
    #[arg(long)]
    pub repo: Option<String>,
    #[arg(long)]
    pub pr: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Consumer {
    pub id: String,
    pub owner: String,
    pub repository: String,
    pub repository_id: u64,
    pub default_branch: String,
}

impl Consumer {
    fn name(&self) -> String {
        format!("{}/{}", self.owner, self.repository)
    }
    fn root(&self) -> String {
        format!("repos/{}", self.name())
    }
}

fn identity(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn oid(value: &Value) -> bool {
    value.as_str().is_some_and(|s| hex(s, 40))
}
fn positive(value: &Value) -> bool {
    value.as_u64().is_some_and(|v| v > 0)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("invalid response identity"))
}
fn quote(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write;
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

pub fn load_consumers(source: &str, repo: Option<&str>, pr: Option<u64>) -> Result<Vec<Consumer>> {
    let mut consumers: Vec<Consumer> = serde_json::from_str(source)?;
    ensure!(!consumers.is_empty(), "invalid consumer enrollment");
    let (mut ids, mut names, mut repositories) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for consumer in &consumers {
        ensure!(
            identity(&consumer.id) && identity(&consumer.owner) && identity(&consumer.repository),
            "invalid consumer identity"
        );
        ensure!(consumer.repository_id > 0, "invalid repository ID");
        ensure!(
            !consumer.default_branch.is_empty()
                && !consumer.default_branch.chars().any(|c| c < ' '),
            "invalid default branch"
        );
        ensure!(
            ids.insert(&consumer.id)
                && names.insert(consumer.name().to_lowercase())
                && repositories.insert(consumer.repository_id),
            "duplicate consumer enrollment"
        );
    }
    ensure!(pr != Some(0), "invalid PR filter");
    if let Some(repo) = repo.filter(|s| !s.is_empty()) {
        consumers.retain(|consumer| consumer.name() == repo);
        ensure!(consumers.len() == 1, "repository filter is not enrolled");
    }
    Ok(consumers)
}

pub fn required_lanes(policy: &Value) -> Result<Vec<String>> {
    ensure!(
        policy["version"].as_u64() == Some(1),
        "invalid BASE lane policy"
    );
    let lanes = policy["lanes"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid BASE lane policy"))?;
    let mut result = Vec::new();
    for (name, lane) in lanes {
        ensure!(
            !name.is_empty()
                && name.chars().count() <= 100
                && !name.chars().any(|c| c < ' ')
                && lane.is_object(),
            "invalid BASE lane"
        );
        let events = lane["events"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("invalid BASE lane events"))?;
        if lane["mode"] == "required_evidence" && events.iter().any(|event| event == "pull_request")
        {
            result.push(name.clone());
        }
    }
    Ok(result)
}

#[derive(Debug, Clone)]
pub struct ProcessRequest {
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<PathBuf>,
    pub input: Option<Vec<u8>>,
}
#[derive(Debug, Clone)]
pub struct ProcessOutput {
    pub code: i32,
    pub stdout: Vec<u8>,
}

pub fn gate_result(result: &ProcessOutput, check: &str, base: &str, head: &str) -> (bool, String) {
    let invalid = || {
        (
            false,
            "Verifier failed or returned an invalid decision; evidence is not accepted.".to_owned(),
        )
    };
    let Ok(value) = serde_json::from_slice::<Value>(&result.stdout) else {
        return invalid();
    };
    let Some(summary) = value["summary"].as_str() else {
        return invalid();
    };
    if value["version"].as_u64() != Some(1)
        || value["check"] != check
        || value["base"] != base
        || value["head"] != head
        || summary.chars().count() > 60000
        || !["skip", "refuse", "run"]
            .iter()
            .any(|s| value["decision"] == *s)
        || !["satisfied", "reused", "rejected", "no_note", "degraded"]
            .iter()
            .any(|s| value["outcome"] == *s)
    {
        return invalid();
    }
    (
        result.code == 0
            && value["decision"] == "skip"
            && (value["outcome"] == "satisfied" || value["outcome"] == "reused")
            && value["report_only"] == false,
        summary.to_owned(),
    )
}

/// The only external capabilities: authenticated API, trusted child execution, signing.
pub trait Capabilities {
    fn api(
        &mut self,
        token: &str,
        method: &str,
        path: &str,
        payload: Option<&Value>,
    ) -> Result<Value>;
    fn process(&mut self, request: ProcessRequest) -> Result<ProcessOutput>;
    fn jwt(&mut self, app_id: u64, key: &str) -> Result<String>;
}

pub fn sign_jwt(app_id: u64, key: &str, now: u64) -> Result<String> {
    #[derive(Serialize)]
    struct Claims {
        iat: u64,
        exp: u64,
        iss: String,
    }
    Ok(jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &Claims {
            iat: now.saturating_sub(60),
            exp: now + 540,
            iss: app_id.to_string(),
        },
        &jsonwebtoken::EncodingKey::from_rsa_pem(key.as_bytes())?,
    )?)
}

fn clean_environment(environ: &BTreeMap<String, String>, token: &str) -> BTreeMap<String, String> {
    let mut env: BTreeMap<_, _> = environ
        .iter()
        .filter(|(k, _)| {
            !k.starts_with("GIT_")
                && !k.starts_with("GH_")
                && !k.starts_with("MERGEMASTER_")
                && k.as_str() != "GITHUB_TOKEN"
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (k, v) in [
        ("GH_TOKEN", token),
        ("GITHUB_TOKEN", token),
        ("GH_HOST", "github.com"),
        ("GH_PROMPT_DISABLED", "1"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_SYSTEM", "/dev/null"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_CONFIG_COUNT", "0"),
        ("GIT_ATTR_NOSYSTEM", "1"),
    ] {
        env.insert(k.into(), v.into());
    }
    env
}

pub struct RealCapabilities {
    git: PathBuf,
    gh: PathBuf,
    ssh_keygen: PathBuf,
    environ: BTreeMap<String, String>,
}
impl RealCapabilities {
    pub fn new() -> Result<Self> {
        fn tool(name: &str) -> Result<PathBuf> {
            for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
                if directory.is_absolute() {
                    let candidate = directory.join(name);
                    if candidate.is_file() {
                        return Ok(candidate.canonicalize()?);
                    }
                }
            }
            bail!("trusted tool missing")
        }
        Ok(Self {
            git: tool("git")?,
            gh: tool("gh")?,
            ssh_keygen: tool("ssh-keygen")?,
            environ: std::env::vars().collect(),
        })
    }
}
impl Capabilities for RealCapabilities {
    fn api(
        &mut self,
        token: &str,
        method: &str,
        path: &str,
        payload: Option<&Value>,
    ) -> Result<Value> {
        let mut args = vec![
            "gh".into(),
            "api".into(),
            "--hostname".into(),
            "github.com".into(),
            "--method".into(),
            method.into(),
            "-H".into(),
            "Accept: application/vnd.github+json".into(),
            "-H".into(),
            "X-GitHub-Api-Version: 2022-11-28".into(),
            path.into(),
        ];
        let input = payload.map(serde_json::to_vec).transpose()?;
        if input.is_some() {
            args.extend(["--input".into(), "-".into()]);
        }
        let result = self.process(ProcessRequest {
            args,
            env: clean_environment(&self.environ, token),
            cwd: None,
            input,
        })?;
        ensure!(result.code == 0, "GitHub API request failed");
        serde_json::from_slice(&result.stdout)
            .map_err(|_| anyhow::anyhow!("invalid GitHub API response"))
    }
    fn process(&mut self, request: ProcessRequest) -> Result<ProcessOutput> {
        let config = tempfile::tempdir()?;
        let executable = match request.args.first().map(String::as_str) {
            Some("git") => &self.git,
            Some("gh") => &self.gh,
            Some(path) if Path::new(path).is_absolute() => Path::new(path),
            _ => bail!("invalid trusted executable"),
        };
        let mut command = Command::new(executable);
        command
            .args(&request.args[1..])
            .env_clear()
            .envs(&request.env)
            .env("GH_CONFIG_DIR", config.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // The verifier's own git/gh children must not resolve programs from its
        // BASE checkout or any relative/caller-controlled PATH entry.
        let trusted_path = std::env::join_paths([
            self.git.parent().expect("absolute tool path"),
            self.gh.parent().expect("absolute tool path"),
            self.ssh_keygen.parent().expect("absolute tool path"),
        ])?;
        command.env("PATH", trusted_path);
        if let Some(cwd) = request.cwd {
            command.current_dir(cwd);
        }
        let mut child = command
            .spawn()
            .map_err(|_| anyhow::anyhow!("trusted subprocess failed"))?;
        if let Some(input) = request.input {
            child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("subprocess stdin missing"))?
                .write_all(&input)?;
        }
        let output = child
            .wait_with_output()
            .map_err(|_| anyhow::anyhow!("trusted subprocess failed"))?;
        Ok(ProcessOutput {
            code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
        })
    }
    fn jwt(&mut self, app_id: u64, key: &str) -> Result<String> {
        sign_jwt(
            app_id,
            key,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        )
    }
}

pub struct Reconciler<C> {
    pub capabilities: C,
    pub app_id: u64,
    pub private_key: String,
    pub bootstrap_token: String,
    pub environ: BTreeMap<String, String>,
    pub workspace: PathBuf,
}
impl<C: Capabilities> Reconciler<C> {
    pub fn new(
        app_id: &str,
        key: &str,
        bootstrap: &str,
        capabilities: C,
        environ: BTreeMap<String, String>,
        workspace: PathBuf,
    ) -> Result<Self> {
        ensure!(
            !app_id.is_empty() && app_id.bytes().all(|c| c.is_ascii_digit()),
            "invalid App ID"
        );
        let app_id = app_id.parse::<u64>()?;
        ensure!(
            app_id > 0 && !key.is_empty() && !bootstrap.is_empty(),
            "App or bootstrap credentials missing"
        );
        fs::create_dir_all(&workspace)?;
        Ok(Self {
            capabilities,
            app_id,
            private_key: key.into(),
            bootstrap_token: bootstrap.into(),
            environ,
            workspace,
        })
    }
    pub fn environment(&self, token: &str) -> BTreeMap<String, String> {
        clean_environment(&self.environ, token)
    }
    fn call(
        &mut self,
        token: &str,
        method: &str,
        path: &str,
        payload: Option<&Value>,
    ) -> Result<Value> {
        ensure!(
            ["GET", "POST", "PATCH"].contains(&method)
                && (path.starts_with("repos/")
                    || path.starts_with("app/")
                    || (method == "GET" && path.starts_with("installation/repositories?")))
                && !path.contains(['\n', '\r', '#', '\\'])
                && !path.contains("://")
                && !path.split('/').any(|p| p == "." || p == ".."),
            "invalid API endpoint"
        );
        self.capabilities.api(token, method, path, payload)
    }
    fn pages(&mut self, token: &str, path: &str, key: Option<&str>) -> Result<Vec<Value>> {
        let mut result = Vec::new();
        for page in 1..=10000 {
            let value = self.call(
                token,
                "GET",
                &format!(
                    "{path}{}per_page=100&page={page}",
                    if path.contains('?') { '&' } else { '?' }
                ),
                None,
            )?;
            let items = key
                .map_or(&value, |key| &value[key])
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("invalid paginated API response"))?;
            result.extend(items.iter().cloned());
            if items.len() < 100 {
                return Ok(result);
            }
        }
        bail!("API pagination exceeded safety bound")
    }
    pub fn installation(&mut self, consumer: &Consumer) -> Result<String> {
        // Enrollment is compiled into this trusted executable, never caller supplied.
        let enrolled = load_consumers(CONSUMERS, None, None)?;
        ensure!(
            enrolled
                .iter()
                .any(|entry| entry.repository_id == consumer.repository_id
                    && entry.name() == consumer.name()
                    && entry.default_branch == consumer.default_branch),
            "repository is not enrolled"
        );
        let jwt = self.capabilities.jwt(self.app_id, &self.private_key)?;
        let installation = self.call(
            &jwt,
            "GET",
            &format!("{}/installation", consumer.root()),
            None,
        )?;
        ensure!(
            positive(&installation["id"])
                && installation["app_id"].as_u64() == Some(self.app_id)
                && installation["account"]["login"] == consumer.owner,
            "installation App/account mismatch"
        );
        ensure!(
            installation["repository_selection"] == "selected",
            "installation must select repositories explicitly"
        );
        let permissions = json!({"checks":"write","contents":"read","pull_requests":"read"});
        let value = self.call(
            &jwt,
            "POST",
            &format!("app/installations/{}/access_tokens", installation["id"]),
            Some(&json!({"repository_ids":[consumer.repository_id],"permissions":permissions})),
        )?;
        let token = text(&value, "token")?.to_owned();
        ensure!(!token.is_empty(), "installation token missing");
        let repositories = value["repositories"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("installation token repository scope mismatch"))?;
        ensure!(
            repositories.len() == 1
                && repositories[0]["id"].as_u64() == Some(consumer.repository_id)
                && repositories[0]["full_name"] == consumer.name(),
            "installation token repository scope mismatch"
        );
        let granted = value["permissions"]
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("installation token permissions mismatch"))?;
        ensure!(
            permissions
                .as_object()
                .expect("literal object")
                .iter()
                .all(|(k, v)| granted.get(k) == Some(v))
                && granted
                    .keys()
                    .all(|k| ["checks", "contents", "pull_requests", "metadata"]
                        .contains(&k.as_str()))
                && granted.get("metadata").is_none_or(|v| v == "read"),
            "installation token permissions mismatch"
        );
        // The API lists repositories exposed to this token, not the installation's
        // global membership. Never mint a broader token merely to inspect membership.
        let exposed = self.pages(&token, "installation/repositories", Some("repositories"))?;
        ensure!(
            exposed.len() == 1
                && exposed.iter().all(|repository| {
                    repository["id"].as_u64() == Some(consumer.repository_id)
                        && repository["full_name"] == consumer.name()
                        && enrolled.iter().any(|entry| {
                            repository["id"].as_u64() == Some(entry.repository_id)
                                && repository["full_name"] == entry.name()
                        })
                }),
            "installation repository exposure mismatch"
        );
        let live = self.call(&token, "GET", &consumer.root(), None)?;
        ensure!(
            live["id"].as_u64() == Some(consumer.repository_id)
                && live["full_name"] == consumer.name()
                && live["default_branch"] == consumer.default_branch
                && live["owner"]["login"] == consumer.owner
                && positive(&live["owner"]["id"])
                && live["owner"]["id"] == installation["account"]["id"],
            "live repository identity mismatch"
        );
        Ok(token)
    }
    pub fn observe(
        &mut self,
        token: &str,
        consumer: &Consumer,
        number: u64,
    ) -> Result<(Value, String)> {
        ensure!(number > 0, "invalid PR number");
        let pull = self.call(
            token,
            "GET",
            &format!("{}/pulls/{number}", consumer.root()),
            None,
        )?;
        ensure!(
            pull["number"].as_u64() == Some(number) && pull["state"] == "open",
            "PR is not open"
        );
        for side in ["base", "head"] {
            ensure!(
                pull[side]["repo"]["id"].as_u64() == Some(consumer.repository_id)
                    && pull[side]["repo"]["full_name"] == consumer.name(),
                "fork PR unsupported"
            );
        }
        let branch = text(&pull["base"], "ref")?;
        ensure!(
            oid(&pull["head"]["sha"]) && !branch.is_empty(),
            "invalid PR identity"
        );
        let accepted = self.call(
            token,
            "GET",
            &format!("{}/git/ref/heads/{}", consumer.root(), quote(branch)),
            None,
        )?;
        ensure!(
            accepted["ref"] == format!("refs/heads/{branch}")
                && accepted["object"]["type"] == "commit"
                && oid(&accepted["object"]["sha"]),
            "invalid accepted base branch"
        );
        let base = text(&accepted["object"], "sha")?.to_owned();
        Ok((pull, base))
    }
    fn recheck(
        &mut self,
        token: &str,
        consumer: &Consumer,
        pull: &Value,
        base: &str,
    ) -> Result<()> {
        let (current, accepted) = self.observe(
            token,
            consumer,
            pull["number"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("invalid PR number"))?,
        )?;
        ensure!(
            current["head"]["sha"] == pull["head"]["sha"]
                && current["base"]["ref"] == pull["base"]["ref"]
                && accepted == base,
            "live PR/head/base changed"
        );
        Ok(())
    }
    // Keep the authenticated identity and decision explicit at this write boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        &mut self,
        token: &str,
        consumer: &Consumer,
        pull: &Value,
        base: &str,
        check: &str,
        success: bool,
        summary: &str,
    ) -> Result<()> {
        let head = text(&pull["head"], "sha")?;
        let checks = self.pages(
            token,
            &format!(
                "{}/commits/{head}/check-runs?filter=all&app_id={}&check_name={}",
                consumer.root(),
                self.app_id,
                quote(check)
            ),
            Some("check_runs"),
        )?;
        let mut matches = BTreeSet::new();
        for value in checks {
            ensure!(
                value["name"] == check
                    && value["head_sha"] == head
                    && value["app"]["id"].as_u64() == Some(self.app_id)
                    && positive(&value["id"]),
                "check-run query identity mismatch"
            );
            matches.insert(value["id"].as_u64().expect("validated ID"));
        }
        let mut payload = json!({"name":check,"status":"completed","conclusion":if success {"success"} else {"failure"},"output":{"title":if success {"Evidence accepted"} else {"Evidence refused"},"summary":summary.chars().take(60000).collect::<String>()}});
        self.recheck(token, consumer, pull, base)?;
        if matches.is_empty() {
            payload["head_sha"] = json!(head);
            self.call(
                token,
                "POST",
                &format!("{}/check-runs", consumer.root()),
                Some(&payload),
            )?;
        } else {
            for id in matches {
                self.recheck(token, consumer, pull, base)?;
                self.call(
                    token,
                    "PATCH",
                    &format!("{}/check-runs/{id}", consumer.root()),
                    Some(&payload),
                )?;
            }
        }
        Ok(())
    }
    fn command(
        &mut self,
        args: Vec<String>,
        token: &str,
        cwd: Option<&Path>,
        extra: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>> {
        let mut env = self.environment(token);
        env.extend(extra.clone());
        let result = self.capabilities.process(ProcessRequest {
            args,
            env,
            cwd: cwd.map(Path::to_path_buf),
            input: None,
        })?;
        ensure!(result.code == 0, "trusted subprocess failed");
        Ok(result.stdout)
    }
    fn git(&mut self, args: &[&str], token: &str, repo: &Path) -> Result<Vec<u8>> {
        let auth = STANDARD.encode(format!("x-access-token:{token}"));
        let extra = BTreeMap::from([
            ("GIT_CONFIG_COUNT".into(), "1".into()),
            (
                "GIT_CONFIG_KEY_0".into(),
                "http.https://github.com/.extraheader".into(),
            ),
            (
                "GIT_CONFIG_VALUE_0".into(),
                format!("AUTHORIZATION: basic {auth}"),
            ),
        ]);
        let mut argv = vec!["git".into(), "-c".into(), "core.hooksPath=/dev/null".into()];
        argv.extend(args.iter().map(|s| (*s).into()));
        self.command(argv, token, Some(repo), &extra)
    }
    fn prepare(
        &mut self,
        token: &str,
        consumer: &Consumer,
        pull: &Value,
        base: &str,
        directory: &Path,
    ) -> Result<(PathBuf, Vec<String>)> {
        let repo = directory.join("repository");
        fs::create_dir(&repo)?;
        self.git(&["init", "--template="], token, &repo)?;
        self.git(
            &[
                "remote",
                "add",
                "origin",
                &format!("https://github.com/{}.git", consumer.name()),
            ],
            token,
            &repo,
        )?;
        self.git(
            &[
                "fetch",
                "--no-tags",
                "origin",
                base,
                text(&pull["head"], "sha")?,
                "+refs/notes/evidence/*:refs/notes/evidence/*",
                "+refs/tags/evidence/*:refs/tags/evidence/*",
            ],
            token,
            &repo,
        )?;
        let policy = serde_json::from_slice(&self.git(
            &["show", &format!("{base}:.mergemaster/lanes.json")],
            token,
            &repo,
        )?)?;
        Ok((repo, required_lanes(&policy)?))
    }
    fn verifier(&mut self, token: &str, repo: &Path, directory: &Path) -> Result<PathBuf> {
        let head = String::from_utf8(self.git(&["rev-parse", "HEAD"], token, repo)?)?;
        let pin: Value = serde_json::from_slice(&self.git(
            &[
                "show",
                &format!("{}:.mergemaster/tool-pin.json", head.trim()),
            ],
            token,
            repo,
        )?)?;
        ensure!(
            pin["version"].as_u64() == Some(1)
                && pin["repository"] == "compoundingtech/mergemaster"
                && oid(&pin["revision"]),
            "invalid BASE tool pin"
        );
        let version = text(&pin["release"], "version")?;
        let components: Vec<_> = version.strip_prefix('v').unwrap_or("").split('.').collect();
        ensure!(
            components.len() == 3
                && components
                    .iter()
                    .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                && pin["release"]["sha256"]
                    .as_str()
                    .is_some_and(|s| hex(s, 64)),
            "invalid BASE release pin"
        );
        let destination = directory.join("release");
        fs::create_dir(&destination)?;
        let binary = destination.join("mergemaster-x86_64-unknown-linux-musl");
        let bootstrap = self.bootstrap_token.clone();
        self.command(
            vec![
                "gh".into(),
                "release".into(),
                "download".into(),
                version.into(),
                "--repo".into(),
                "compoundingtech/mergemaster".into(),
                "--pattern".into(),
                "mergemaster-x86_64-unknown-linux-musl".into(),
                "--dir".into(),
                destination.to_string_lossy().into_owned(),
            ],
            &bootstrap,
            None,
            &BTreeMap::new(),
        )?;
        let metadata = fs::symlink_metadata(&binary)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "release asset missing"
        );
        let digest = format!("{:x}", Sha256::digest(fs::read(&binary)?));
        ensure!(
            pin["release"]["sha256"] == digest,
            "release digest mismatch"
        );
        self.command(
            vec![
                "gh".into(),
                "attestation".into(),
                "verify".into(),
                binary.to_string_lossy().into_owned(),
                "--repo".into(),
                "compoundingtech/mergemaster".into(),
                "--signer-digest".into(),
                text(&pin, "revision")?.into(),
                "--source-digest".into(),
                text(&pin, "revision")?.into(),
                "--signer-workflow".into(),
                "compoundingtech/mergemaster/.github/workflows/release.yml".into(),
                "--deny-self-hosted-runners".into(),
            ],
            &bootstrap,
            None,
            &BTreeMap::new(),
        )?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
        Ok(binary)
    }
    pub fn reconcile_pull(
        &mut self,
        token: &str,
        consumer: &Consumer,
        number: u64,
    ) -> Result<usize> {
        let (pull, base) = self.observe(token, consumer, number)?;
        let directory = tempfile::Builder::new()
            .prefix("pull-")
            .tempdir_in(&self.workspace)?;
        let (repo, lanes) = self.prepare(token, consumer, &pull, &base, directory.path())?;
        if lanes.is_empty() {
            return Ok(0);
        }
        let setup = (|| -> Result<(PathBuf, PathBuf)> {
            self.git(&["checkout", "--detach", "--force", &base], token, &repo)?;
            ensure!(
                String::from_utf8(self.git(&["rev-parse", "HEAD"], token, &repo)?)?.trim() == base,
                "checkout is not accepted BASE"
            );
            let binary = self.verifier(token, &repo, directory.path())?;
            let event = directory.path().join("event.json");
            let mut event_pull = pull.clone();
            event_pull["base"]["sha"] = json!(base);
            fs::write(
                &event,
                serde_json::to_vec(
                    &json!({"number":number,"pull_request":event_pull,"repository":pull["base"]["repo"]}),
                )?,
            )?;
            Ok((binary, event))
        })();
        let Ok((binary, event)) = setup else {
            for lane in lanes {
                let _ = self.publish(
                    token,
                    consumer,
                    &pull,
                    &base,
                    &lane,
                    false,
                    "BASE verifier setup failed; evidence is not accepted.",
                );
            }
            return Ok(1);
        };
        let mut errors = 0;
        for lane in lanes {
            let mut env = self.environment(token);
            env.insert("GITHUB_REPOSITORY".into(), consumer.name());
            let result = self.capabilities.process(ProcessRequest {
                args: vec![
                    binary.to_string_lossy().into_owned(),
                    "gate".into(),
                    "--check".into(),
                    lane.clone(),
                    "--base".into(),
                    base.clone(),
                    "--head".into(),
                    text(&pull["head"], "sha")?.into(),
                    "--event-file".into(),
                    event.to_string_lossy().into_owned(),
                    "--format".into(),
                    "json".into(),
                ],
                env,
                cwd: Some(repo.clone()),
                input: None,
            });
            let (success, summary) = match result {
                Ok(result) => gate_result(&result, &lane, &base, text(&pull["head"], "sha")?),
                Err(_) => (false, "Verifier failed; evidence is not accepted.".into()),
            };
            if !success {
                errors += 1;
            }
            if self
                .publish(token, consumer, &pull, &base, &lane, success, &summary)
                .is_err()
            {
                errors += 1;
            }
        }
        Ok(errors)
    }
    pub fn reconcile_consumer(
        &mut self,
        consumer: &Consumer,
        pr_filter: Option<u64>,
    ) -> Result<usize> {
        let token = self.installation(consumer)?;
        let pulls = match pr_filter {
            Some(number) => vec![json!({"number":number})],
            None => self.pages(
                &token,
                &format!("{}/pulls?state=open", consumer.root()),
                None,
            )?,
        };
        let mut errors = 0;
        for pull in pulls {
            let attempt = (|| -> Result<usize> {
                let number = pull["number"]
                    .as_u64()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| anyhow::anyhow!("invalid PR number"))?;
                let live = self.call(
                    &token,
                    "GET",
                    &format!("{}/pulls/{number}", consumer.root()),
                    None,
                )?;
                if live["head"]["repo"]["id"].as_u64() != Some(consumer.repository_id) {
                    return Ok(0);
                }
                self.reconcile_pull(&token, consumer, number)
            })();
            match attempt {
                Ok(count) => errors += count,
                Err(_) => {
                    errors += 1;
                    eprintln!("{}: PR reconciliation failed", consumer.name());
                }
            }
        }
        Ok(errors)
    }
    pub fn run_all(&mut self, consumers: &[Consumer], pr_filter: Option<u64>) -> i32 {
        let mut errors = 0;
        for consumer in consumers {
            match self.reconcile_consumer(consumer, pr_filter) {
                Ok(count) => errors += count,
                Err(_) => {
                    errors += 1;
                    eprintln!("{}: repository reconciliation failed", consumer.name());
                }
            }
        }
        println!("Evidence reconciliation completed: {errors} error(s).");
        i32::from(errors != 0)
    }
}

#[cfg(test)]
mod tests;
