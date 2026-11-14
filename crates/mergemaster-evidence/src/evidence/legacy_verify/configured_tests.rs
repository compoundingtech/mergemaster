use super::*;
use crate::evidence::legacy_policy::PolicyDocument;
use serde_json::{Value, json};

#[test]
fn configured_required_checks_match_signed_git_oracle() {
    let script = r#"
import json,pathlib,runpy,subprocess,sys
from datetime import datetime,timezone
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]
for fmt in ['sha1','sha256']:
 root=pathlib.Path(sys.argv[2])/fmt; root.mkdir(); key=root/'key'
 subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
 keys=root/'keys'; keys.write_text('agent/fixture '+key.with_suffix('.pub').read_text())
 for points in ['check','\ud800','😀']:
  for name in ['satisfied','wrong-command','failed','shard-only','shard-filter','level-lane','projection','budget']:
   repo=root/(str(len(cases))+'-'+name); subprocess.run(['git','init','--bare','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
   def git(*args,data=None): return subprocess.check_output(['git','-C',str(repo),*args],input=data)
   git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
   def blob(data): return git('hash-object','-w','--stdin',data=data).decode().strip()
   def tree(data=b''): return git('mktree',data=data).decode().strip()
   current=tree(('100644 blob '+blob(b'content')+'\tinput\n').encode()); later=tree()
   subject=git('commit-tree',current,data=b'subject').decode().strip()
   def record(label,target=current,shard=False,wide=False):
    parent=subject if target==current else git('commit-tree',target,data=b'fresh subject').decode().strip()
    inputs={'n':'1','r':'0=success','crate':'fixture','source_inputs':'1'*len(current),'tests_run':'1'}
    if shard: inputs['i']='0'
    value=dict(_type=v['STATEMENT_TYPE'],predicateType=v['PREDICATE_TYPE'],subject=[dict(name=parent,digest=dict(gitTree=target))],
     predicate=dict(schema_version=1,tier='full',change_id=label,signer='agent/fixture',observed_at='2026-01-01T00:04:00Z',
      observed=dict(kind='tests',runner='wrapper',inputs=inputs,checks={points:dict(command=['other'] if name=='wrong-command' else ['true'],exit_code=1 if name=='failed' else 0,output_sha256='0'*64)})))
    if wide: value['extra']=[0]*500000
    data=json.dumps(value,separators=(',',':')).encode(); assert len(data)<=1048576
    note=tree(('100644 blob '+blob(data)+'\t'+target+'\n').encode())
    commit=git('-c','gpg.format=ssh','-c','user.signingkey='+str(key),'commit-tree','-S',note,'-p',parent,data=label.encode()).decode().strip()
    git('update-ref','refs/tags/evidence/'+target+'/'+commit,commit)
   record('good',shard=name=='shard-only')
   if name=='shard-filter': record('part',shard=True)
   if name=='budget':
    for i in range(3): record('wide'+str(i),wide=True)
    record('fresh',target=later)
   kind=dict(command=['true'])
   if name in ['shard-only','shard-filter']: kind['shard_inputs']=dict(count='n',results='r',index='i')
   if name=='level-lane': kind['by_level']={'agent':{'command':['true'],'events':['pull_request'],'lane':True}}
   entry=dict(trust_levels=['agent'],require='reject',kinds={'wrapper':kind})
   if name=='projection': entry['inputs']=['input']
   policy=json.dumps(dict(version=1,checks={points:entry})); rules=v['policy_rules'](policy,points,'fixture')
   def verify(target):
    try:
     result=v['verify'](str(repo),target,points,str(keys),None,rules=rules,now=datetime(2026,1,1,0,5,tzinfo=timezone.utc))
     bound=v['verify'](str(repo),target,points,str(keys),None,rules=rules,now=datetime(2026,1,1,0,5,tzinfo=timezone.utc),crate_key=('fixture','1'*len(current),True))
     return dict(record=result['record'],signer=result['signer'],tier=list(map(ord,result['tier'])),wire=json.dumps(result,indent=2),crate_wire=json.dumps(bound,indent=2))
    except v['Failure'] as e: return dict(reason=e.reason,attempts=e.extra.get('attempts',0))
   expected=verify(current)
   reason={'wrong-command':'wrong_command','failed':'check_failed','shard-only':'no_record','level-lane':'no_lane'}.get(name)
   assert expected.get('reason')==reason,(name,expected)
   if name=='budget':
    fresh=verify(later); assert 'record' in fresh,(name,fresh)
   cases.append(dict(repo=str(repo),tree=current,later=later,keys=str(keys),check=list(map(ord,points)),policy=policy,name=fmt+'/'+ascii(points)+'/'+name,expected=expected,budget=name=='budget'))
print(json.dumps(cases))
"#;
    let root = tempfile::tempdir().unwrap();
    let mut command = std::process::Command::new("python3");
    crate::gate::git::sanitize(&mut command);
    let output = command
        .env("HOME", root.path())
        .env("GNUPGHOME", root.path())
        .env("XDG_CONFIG_HOME", root.path())
        .args([
            "-c",
            script,
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap(),
        ])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 48);
    struct NoBindings;
    impl Provider for NoBindings {
        fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
            panic!("require_all has no level_lane callback")
        }
        fn blob_sha256(
            &mut self,
            _: crate::evidence::legacy_verify::judgment::BindingPath<'_>,
        ) -> Result<Option<String>, PolicyError> {
            panic!("fixture has no bound files")
        }
    }
    for case in cases {
        let check: Vec<u32> = serde_json::from_value(case["check"].clone()).unwrap();
        let rules = PolicyDocument::parse(case["policy"].as_str().unwrap(), check.as_slice())
            .unwrap()
            .into_rules("fixture")
            .unwrap();
        let mut clock = 1_767_225_900_000_000i64;
        let ignored_inputs = ["../not-the-policy-input".into()];
        let q = Request {
            repo: Path::new(case["repo"].as_str().unwrap()),
            tree: case["tree"].as_str().unwrap(),
            check: check.as_slice().into(),
            keys: case["keys"].as_str().unwrap(),
            inputs: Some(&ignored_inputs),
            crate_key: Some(super::super::collection::CrateBinding {
                name: "wrong-crate".into(),
                key: "wrong-key",
                needs_tests: false,
            }),
        };
        let result = required(&q, &rules, None, &mut clock, NoBindings);
        if case["budget"] == true {
            assert!(matches!(result,Err(e) if e.reason=="record-budget-exceeded"));
            let later = Request {
                tree: case["later"].as_str().unwrap(),
                ..q
            };
            assert!(required(&later, &rules, None, &mut clock, NoBindings).is_ok());
            continue;
        }
        let actual = match result {
            // Existing normalized oracle transport only, not CLI field presence.
            Err(e) => json!({"reason":e.reason,"attempts":e.attempts.unwrap_or(0)}),
            Ok(record) => {
                let facts = DocumentFacts::for_check(
                    &record.candidate.statement,
                    &check,
                    &record.principal,
                )
                .unwrap();
                let prepared = Prepared::new(
                    &rules,
                    vec![Candidate {
                        commit: &record.candidate.commit,
                        facts,
                    }],
                    q.check,
                )
                .unwrap();
                let decision = CheckJudgment {
                    clock: &mut clock,
                    run_inputs: &BTreeMap::new(),
                    lane: None,
                    provider: LaneOnce::new(RequiredProvider(NoBindings)),
                }
                .select(&prepared, q.check, Levels::Utf8(&[]));
                let view = super::super::result::Satisfied::from_decision(
                    &prepared, &decision, q.tree, q.check, None,
                )
                .unwrap();
                assert_eq!(view.check.codepoints().as_ref(), check);
                json!({"record":view.record,"signer":view.signer,"tier":view.tier})
            }
        };
        let mut expected = case["expected"].clone();
        expected.as_object_mut().unwrap().remove("wire");
        expected.as_object_mut().unwrap().remove("crate_wire");
        assert_eq!(actual, expected, "{}", case["name"]);
        let mut judgment = CheckJudgment {
            clock: &mut clock,
            run_inputs: &BTreeMap::new(),
            lane: None,
            provider: LaneOnce::new(RequiredProvider(NoBindings)),
        };
        let crate_key = "1".repeat(q.tree.len());
        for (binding, expected_wire) in [
            (None, "wire"),
            (
                Some(super::super::collection::CrateBinding {
                    name: "fixture".into(),
                    key: &crate_key,
                    needs_tests: true,
                }),
                "crate_wire",
            ),
        ] {
            let joined = retained(
                &Request {
                    crate_key: binding,
                    ..q
                },
                Settings::Policy(&rules),
                &mut judgment,
                Levels::Utf8(&[]),
            )
            .and_then(|note| {
                note.with_view(q.tree, q.check, |view| {
                    assert_eq!(view.record, note.record.candidate.commit);
                    assert_eq!(view.signer, note.record.principal);
                    let mut wire = String::new();
                    crate::evidence::legacy_output::write(&mut wire, |w| view.write_json(w))
                        .unwrap();
                    wire
                })
            });
            match joined {
                Ok(wire) => assert_eq!(
                    wire,
                    case["expected"][expected_wire].as_str().unwrap(),
                    "{}",
                    case["name"]
                ),
                Err(error) => {
                    assert_eq!(error.reason, case["expected"]["reason"]);
                    assert_eq!(error.attempts.unwrap_or(0), case["expected"]["attempts"]);
                }
            }
        }
    }
}

#[test]
fn malformed_manual_records_refuse_selected_check_preparation() {
    use crate::evidence::{
        legacy_policy::ErrorOrigin, legacy_verify::statement_document::Document,
    };
    let rules = PolicyDocument::parse(
        r#"{"version":1,"checks":{"check":{"trust_levels":["agent"],"require":"reject","kinds":{"wrapper":{"command":["true"]}}}}}"#,
        "check",
    )
    .unwrap()
    .into_rules("fixture")
    .unwrap();
    let check: Vec<u32> = "check".chars().map(u32::from).collect();
    let records = vec![TrustedCandidate {
        candidate: super::super::collection::Candidate {
            commit: "record".into(),
            statement: std::sync::Arc::new(Document::from_bytes(b"{}").unwrap()),
        },
        principal: "agent/fixture".into(),
    }];
    let error = prepare_records(&records, &rules, &check).err().unwrap();
    assert_eq!(error.origin, ErrorOrigin::Failure);
    assert_eq!(error.reason, "error");
    assert_eq!(error.detail.to_string(), "invalid validated statement");
    assert_eq!(error.attempts, None);
}

#[test]
fn selected_commit_absent_from_manual_records_refuses() {
    use crate::evidence::{
        legacy_policy::ErrorOrigin, legacy_verify::statement_document::Document,
    };
    let records = vec![TrustedCandidate {
        candidate: super::super::collection::Candidate {
            commit: "record".into(),
            statement: std::sync::Arc::new(Document::from_bytes(b"{}").unwrap()),
        },
        principal: "agent/fixture".into(),
    }];
    assert_eq!(record_position(&records, "record").unwrap(), 0);
    let error = record_position(&records, "absent").unwrap_err();
    assert_eq!(error.origin, ErrorOrigin::Failure);
    assert_eq!(error.reason, "error");
    assert_eq!(error.detail.to_string(), "invalid validated statement");
    assert_eq!(error.attempts, None);
}
