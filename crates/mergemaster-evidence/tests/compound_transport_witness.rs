use mergemaster_evidence::gate;
use serde_json::{Value, json};
use std::path::Path;

#[allow(
    dead_code,
    reason = "shared capture helpers; this target uses native comparisons"
)]
#[path = "../src/evidence/legacy_verify/divergence_witnesses.rs"]
mod divergence_witnesses;
#[path = "../src/pinned_python.rs"]
mod pinned_python;
use divergence_witnesses::capture;
#[test]
fn compound_definition_and_bound_input_capture_native_selection() {
    use crate::gate::config::{expected_inputs, load};
    use sha2::Digest;
    let scratch = tempfile::tempdir().unwrap();
    let output = crate::pinned_python::command().args(["-c", r#"
import json,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]);repo=root/'repo';repo.mkdir()
def git(*args):
 return subprocess.check_output(['git','-C',str(repo),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false',*args]).decode().strip()
git('init','-q')
key=root/'key';subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
files={
 '.mergemaster/evidence-keys':'agent/fixture namespaces="git" '+key.with_suffix('.pub').read_text(),
 '.mergemaster/tool-pin.json':json.dumps(dict(version=1,repository='compoundingtech/mergemaster',revision='a'*40)),
 '.mergemaster/environment.json':json.dumps(dict(version=1,systems={'x86_64-linux':dict(runtime=dict(name='bun',identity='sha256:'+'a'*64),dependencies={})})),
 '.mergemaster/lanes.json':json.dumps(dict(version=1,pull_request=dict(same_repository=True,authors=dict(mode='none'),base_relation='ancestor'),protected_paths=['.mergemaster/'],lanes={'check':dict(argv=['tools/graph','check','--full'],definition_paths=['tools'],trust_levels=['agent'],mode='required_evidence',events=['pull_request'],environment=dict(manifest='.mergemaster/environment.json',paths=['tools','source.txt']),protected_edits='reject',remediation_argv=['mergemaster','evidence','wrap','--check','check'])})),
 'tools/graph':'fixture command, never executed\n','source.txt':'base\n'}
for name,text in files.items():
 p=repo/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
git('add','-A');git('commit','-q','-m','base');base=git('rev-parse','HEAD')
git('update-ref','refs/heads/gate-base',base)
(repo/'source.txt').write_text('candidate\n');git('add','-A');git('commit','-q','-m','candidate')
print(json.dumps(dict(repo=str(repo),key=str(key),keys=str(repo/'.mergemaster/evidence-keys'),base=base,head=git('rev-parse','HEAD'),tree=git('rev-parse','HEAD^{tree}'))))
"#]).arg(scratch.path()).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixture: Value = serde_json::from_slice(&output.stdout).unwrap();
    let repo = Path::new(fixture["repo"].as_str().unwrap());
    let base = fixture["base"].as_str().unwrap();
    let head = fixture["head"].as_str().unwrap();
    let config = load(repo, base).unwrap();
    let mut inputs = expected_inputs(
        repo,
        head,
        "check",
        &config.policy.lanes["check"],
        &config.environment,
        &config.environment_bytes,
    )
    .unwrap();
    inputs.insert(
        "wrapper_sha256".into(),
        hex::encode(sha2::Sha256::digest(b"fixture command, never executed\n")),
    );
    inputs.insert("workspace_clean".into(), "true".into());
    inputs.insert("untracked_files".into(), "false".into());
    inputs.insert("attempt".into(), "1".into());
    let definition = inputs["lane_definition_sha256"].clone();
    let statement = json!({
        "_type":"https://in-toto.io/Statement/v1","predicateType":"https://smalltalk.dev/evidence/gate/v1",
        "subject":[{"name":head,"digest":{"gitTree":fixture["tree"]}}],
        "predicate":{"schema_version":1,"change_id":"fixture","tier":"full","signer":"agent/fixture",
            "re_attests":null,"producer_sha256":"a".repeat(64),
            "observed_at":chrono::Utc::now().to_rfc3339(),
            "observed":{"kind":"tests","runner":"wrapper","inputs":inputs,"checks":{"check":{"command":["tools/graph","check","--full"],"exit_code":0,"output_sha256":"c".repeat(64)}}}}
    });
    let output = crate::pinned_python::command().args(["-c", r#"
import copy,datetime,json,os,runpy,subprocess,sys
f=json.loads(sys.argv[1]);s=json.loads(sys.argv[2]);definition=sys.argv[3]
def git(*args,data=None):
 return subprocess.check_output(['git','-C',f['repo'],'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',*args],input=data).decode().strip()
now=datetime.datetime.now(datetime.timezone.utc);records=[]
for seconds in [30,20]:
 item=copy.deepcopy(s);item['predicate']['observed_at']=(now-datetime.timedelta(seconds=seconds)).isoformat()
 if seconds==20:
  values=item['predicate']['observed']['inputs'];values['lane_definition_sha256']='0'*64;del values['wrapper_sha256']
 blob=git('hash-object','-w','--stdin',data=json.dumps(item).encode())
 tree=git('mktree',data=('100644 blob '+blob+'\t'+f['tree']+'\n').encode())
 record=git('-c','gpg.format=ssh','-c','gpg.ssh.program=ssh-keygen','-c','user.signingkey='+f['key'],'commit-tree','-S',tree,'-p',f['head'],data=b'record\n')
 git('update-ref','refs/notes/evidence/'+f['tree']+'/'+record,record);records.append(record)
v=runpy.run_path(os.environ['MERGEMASTER_PYTHON_ORACLE']+'/scripts/evidence-verify')
try:
 result=v['verify'](f['repo'],f['tree'],'check',f['keys'],['tools/graph','check','--full'],trust_levels=['agent'],lane=dict(sha256=definition,changed=[]),bind=[('wrapper_sha256','tools/graph')])
except v['Failure'] as error:
 result=dict(reason=error.reason,detail=error.detail,extra=error.extra)
print(json.dumps(dict(result=result,records=records)))
"#]).arg(fixture.to_string()).arg(statement.to_string()).arg(&definition).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let python: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(python["result"]["satisfied"], true, "{python}");
    assert_eq!(python["result"]["decided_by"], python["records"][0]);
    // The gate re-execs itself for signature verification. Use the production CLI,
    // not libtest, whose argument parser would turn every record into untrusted_signer.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mergemaster"))
        .current_dir(repo)
        .args([
            "gate", "--check", "check", "--base", base, "--head", head, "--format", "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    capture(
        "wrong-definition-plus-bound-input",
        json!({"statement":statement,"newer_mutation":{"lane_definition_sha256":"0".repeat(64),"remove":"wrapper_sha256"},"records":python["records"],"expected_definition":definition,"git":divergence_witnesses::git_input(repo),"keys_hex":hex::encode(std::fs::read(fixture["keys"].as_str().unwrap()).unwrap())}),
        python["result"].clone(),
        decision.clone(),
    );
    assert_eq!(decision["reason"], "wrong_input");
    assert_eq!(decision["record"], python["records"][1]);
    assert_eq!(decision["decision"], "refuse");
}
