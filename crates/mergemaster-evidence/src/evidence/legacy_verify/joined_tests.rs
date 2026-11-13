use super::super::{
    candidates::{Candidate, LaneOnce, Levels, Prepared},
    facts::DocumentFacts,
    judgment::{LaneDefinition, Provider, Unconfigured},
    ordering::CheckJudgment,
    result::Satisfied,
};
use super::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
    process::Command,
};

fn command(program: &str, home: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", home)
        .env("GNUPGHOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("LC_ALL", "C");
    command
}

#[test]
fn unconfigured_signed_git_selection_matches_the_whole_pinned_verifier() {
    let script = r#"
import hashlib,json,os,pathlib,runpy,subprocess,sys
from datetime import datetime,timezone
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify')); cases=[]
namespace=v['verified'].__globals__
for fmt in ['sha1','sha256']:
 root=pathlib.Path(sys.argv[2])/fmt; root.mkdir(); keys=root/'keys'; lines=[]
 for level in ['agent','host']:
  key=root/level; subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
  lines.append(level+'/fixture '+key.with_suffix('.pub').read_text())
 keys.write_text(''.join(lines))
 for name in ['satisfied','optional-command','wrong-command','wrong-bound','missing-blob','surrogate-key','wrong-lane','skip-lane','skip-level','prefer-host','shadow','untrusted','unsupported','too-old','empty-levels','no-lane']:
  repo=root/name; subprocess.run(['git','init','--bare','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
  def git(*args,data=None): return subprocess.check_output(['git','-C',str(repo),*args],input=data)
  git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
  def blob(data): return git('hash-object','-w','--stdin',data=data).decode().strip()
  def tree(data): return git('mktree','-z',data=data).decode().strip()
  content=b'bound content\n'; path=b'path-\xff'; digest=hashlib.sha256(content).hexdigest()
  current=tree(('100644 blob '+blob(content)+'\t').encode()+path+b'\0')
  subject=git('commit-tree',current,data=b'subject').decode().strip()
  binding='\ud800' if name=='surrogate-key' else 'bound'
  def record(label,level='agent',time='00:04:00',definition='base',exit=0):
   inputs={binding:'bad' if name=='wrong-bound' else digest,'lane_definition_sha256':definition,'i':'0'}
   value=dict(_type=v['STATEMENT_TYPE'],predicateType=v['PREDICATE_TYPE'],subject=[dict(name=subject,digest=dict(gitTree=current))],
    predicate=dict(schema_version=1,tier='full',change_id=label,signer=level+'/fixture',observed_at='2026-01-01T'+time+'Z',
     observed=dict(kind='tests',runner='other' if name=='unsupported' else 'wrapper',inputs=inputs,
      checks=dict(check=dict(command=['other'] if name in ['optional-command','wrong-command'] else ['true'],exit_code=exit,output_sha256='0'*64)))))
   note=tree(('100644 blob '+blob(json.dumps(value).encode())+'\t'+current+'\0').encode())
   args=['-c','gpg.format=ssh','-c','user.signingkey='+str(root/level),'commit-tree',note,'-p',subject]
   if name!='untrusted': args+=['-S']
   commit=git(*args,data=label.encode()).decode().strip(); git('update-ref','refs/tags/evidence/'+current+'/'+commit,commit)
  if name=='skip-lane': record('old',time='00:03:00'); record('new',definition='wrong')
  elif name=='skip-level': record('old',time='00:03:00'); record('new',level='host')
  elif name=='prefer-host': record('old',level='host',time='00:03:00'); record('new')
  elif name=='shadow': record('pass',level='host'); record('failure',time='00:04:30',exit=1)
  else: record('record',definition='wrong' if name=='wrong-lane' else 'base')
  command=None if name=='optional-command' else ['true']; age=10 if name=='too-old' else None
  levels=[] if name=='empty-levels' else ['agent'] if name=='skip-level' else None
  prefer=['host'] if name in ['prefer-host','shadow'] else []
  lane=None if name=='no-lane' else dict(sha256='base',changed=[],tree_sha256='tree')
  bound_path=os.fsdecode(b'missing-\xff' if name=='missing-blob' else path); calls=[]; original=namespace['blob_sha256']
  def read(repo,tree,path): calls.append(os.fsencode(path).hex()); return original(repo,tree,path)
  namespace['blob_sha256']=read
  try:
   expected=v['verified'](str(repo),current,'check',str(keys),command,kinds=['wrapper'],bind=[(binding,bound_path)],max_age=age,trust_levels=levels,prefer_levels=prefer,lane=lane,now=datetime(2026,1,1,0,5,tzinfo=timezone.utc))
   for key in ['tier','observed_at','matched_tree']: expected[key]=list(map(ord,expected[key]))
   expected['command']=[list(map(ord,arg)) for arg in expected['command']]
   expected['inputs']=[[list(map(ord,k)),list(map(ord,value))] for k,value in expected['inputs'].items()]
  except v['Failure'] as e: expected=dict(reason=e.reason,attempts=e.extra.get('attempts',0),decided_by=e.extra.get('decided_by'),skipped_newer=e.extra.get('skipped_newer',[]))
  finally: namespace['blob_sha256']=original
  cases.append(dict(name=fmt+'-'+name,repo=str(repo),tree=current,keys=str(keys),command=command,age=age,levels=levels,prefer=prefer,lane=lane,binding=list(map(ord,binding)),path=os.fsencode(bound_path).hex(),expected=expected,calls=calls))
print(json.dumps(cases))
"#;
    let oracle = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
    let root = tempfile::tempdir().unwrap();
    let output = command("python3", root.path())
        .args(["-c", script, &oracle])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 32);
    struct Git<'a> {
        repo: &'a Path,
        home: &'a Path,
        tree: &'a str,
        calls: &'a std::cell::RefCell<Vec<String>>,
    }
    impl Provider for Git<'_> {
        fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
            panic!("no policy-level lane")
        }
        fn blob_sha256(&mut self, path: &Path) -> Result<Option<String>, PolicyError> {
            self.calls
                .borrow_mut()
                .push(hex::encode(path.as_os_str().as_bytes()));
            let mut object = OsString::from(format!("{}:", self.tree));
            object.push(path);
            let output = command("git", self.home)
                .arg("-C")
                .arg(self.repo)
                .args(["cat-file", "blob"])
                .arg(object)
                .output()
                .unwrap();
            Ok(output
                .status
                .success()
                .then(|| hex::encode(Sha256::digest(output.stdout))))
        }
    }
    for case in cases {
        let repo = Path::new(case["repo"].as_str().unwrap());
        let tree = case["tree"].as_str().unwrap();
        let mut collector = CandidateCollector::for_check();
        let records = candidates(
            &mut collector,
            &Request {
                repo,
                tree,
                check: "check".into(),
                keys: case["keys"].as_str().unwrap(),
                inputs: None,
                crate_key: None,
            },
        );
        let kinds = vec!["wrapper".chars().map(u32::from).collect()];
        let command: Option<Vec<Vec<u32>>> = case["command"].as_array().map(|args| {
            args.iter()
                .map(|arg| arg.as_str().unwrap().chars().map(u32::from).collect())
                .collect()
        });
        let levels: Option<Vec<Vec<u32>>> = case["levels"].as_array().map(|args| {
            args.iter()
                .map(|arg| arg.as_str().unwrap().chars().map(u32::from).collect())
                .collect()
        });
        let prefer: Vec<Vec<u32>> = case["prefer"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap().chars().map(u32::from).collect())
            .collect();
        let bindings = vec![(
            serde_json::from_value(case["binding"].clone()).unwrap(),
            std::path::PathBuf::from(OsString::from_vec(
                hex::decode(case["path"].as_str().unwrap()).unwrap(),
            )),
        )];
        let options = Unconfigured {
            routing: super::super::routing::Unconfigured {
                kinds: &kinds,
                trust_levels: levels.as_deref(),
                runner_prefix: None,
            },
            command: command.as_deref(),
            max_age: case["age"]
                .as_u64()
                .map(super::super::inputs::AgeLimit::Seconds),
            bindings: &bindings,
        };
        let lane = (!case["lane"].is_null()).then(|| LaneDefinition {
            sha256: "base".into(),
            changed: vec![],
            tree_sha256: "tree".into(),
        });
        let calls = std::cell::RefCell::new(Vec::new());
        let mut judgment = CheckJudgment {
            now_micros: 1_767_225_900_000_000,
            run_inputs: &std::collections::BTreeMap::new(),
            lane: lane.as_ref(),
            provider: LaneOnce::new(Git {
                repo,
                home: root.path(),
                tree,
                calls: &calls,
            }),
        };
        let actual = match records {
            Err(error) => {
                json!({"reason":error.reason,"attempts":error.attempts,"decided_by":null,"skipped_newer":[]})
            }
            Ok(records) => {
                let prepared = Prepared::unconfigured(
                    &options,
                    records
                        .iter()
                        .map(|record| Candidate {
                            commit: &record.candidate.commit,
                            facts: DocumentFacts::for_check(
                                &record.candidate.statement,
                                &[99, 104, 101, 99, 107],
                                &record.principal,
                            )
                            .unwrap(),
                        })
                        .collect(),
                );
                let decision = judgment.select(&prepared, "check", Levels::Codepoints(&prefer));
                match Satisfied::from_decision(&prepared, &decision, tree, "check", None) {
                    Err(error) => {
                        json!({"reason":error.reason,"attempts":error.attempts,"decided_by":decision.walk.decided_by.map(|i| prepared.candidates[i].commit),"skipped_newer":decision.walk.skipped_newer})
                    }
                    Ok(result) => {
                        json!({"satisfied":result.satisfied,"tree":result.tree,"check":result.check,"record":result.record,"kind":result.kind,"signer":result.signer,"trust_level":result.trust_level,"tier":result.tier,"observed_at":result.observed_at,"command":result.command().collect::<Vec<_>>(),"inputs":result.inputs().collect::<Vec<_>>(),"attempts":result.attempts,"policy":result.policy,"max_age_s":result.max_age_s,"enforce":result.enforce,"match":result.r#match,"matched_tree":result.matched_tree,"source_inputs":result.source_inputs,"sample_one_in":result.sample_one_in,"events":result.events().map(|e| e.collect::<Vec<_>>()),"decided_by":result.decided_by,"skipped_newer":result.skipped_newer})
                    }
                }
            }
        };
        assert_eq!(actual, case["expected"], "{}", case["name"]);
        assert_eq!(
            json!(calls.borrow().as_slice()),
            case["calls"],
            "{}",
            case["name"]
        );
    }
}
