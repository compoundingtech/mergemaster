use super::*;
use crate::evidence::{
    legacy_policy::{PolicyDocument, PolicyError},
    legacy_verify::{
        candidates::{Candidate, LaneOnce, Levels},
        facts::DocumentFacts,
        judgment::{LaneDefinition, Provider},
        ordering::CheckJudgment,
        statement::statement_of,
    },
};
use serde_json::{Value, json};
#[test]
fn result_dictionary_fields_match_python() {
    let script = r#"
import ast,copy,itertools,json,runpy,sys
root=sys.argv[1]
ns=runpy.run_path(root+'/scripts/evidence-verify')
module=ast.parse(open(root+'/scripts/evidence-verify').read())
fn=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='verified')
fn.body=ast.parse('with_check = entries; input_key = source_inputs').body+[n for n in fn.body if n.lineno>=1012]
exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'<pinned-result>','exec'),ns)
check_events=[None,['merge_group','pull_request'],['merge_group'],['merge_group','pull_request'],None,['merge_group','pull_request']]
level_events=[None,['pull_request'],['pull_request'],None,['merge_group','pull_request'],['pull_request','merge_group']]
command=['run😀','quote"\\\n']
fixtures=[]
for mode,inputs,matched,source,separator in itertools.product(range(6),[None,{}, {'\ud800':'\udfff','face😀':'line\n','z':'tail'}],['a'*40,'b'*40],[None,'c'*64],['T','\ud800']):
    rule=dict(command=command)
    principal='agent/key'
    if level_events[mode] is not None:
        rule['by_level']={'host':dict(command=command,events=level_events[mode])}
        principal='host/key'
    entry=dict(trust_levels=['agent','host'],kinds=dict(wrapper=rule),max_age_s=60 if mode%2 else None,enforce=bool(mode%2),sample_one_in=mode+1)
    if check_events[mode] is not None: entry['events']=check_events[mode]
    policy=json.dumps(dict(version=1,checks=dict(unit=entry)))
    observed=dict(kind='tests',runner='wrapper',checks=dict(unit=dict(command=command,exit_code=0,output_sha256='0'*64)))
    if inputs is not None: observed['inputs']=inputs
    statement=dict(_type='https://in-toto.io/Statement/v1',predicateType='https://compounding.tech/fractal/evidence/gate/v1',subject=[dict(name=matched,digest=dict(gitTree=matched))],predicate=dict(schema_version=1,tier='full',change_id='change',signer=principal,observed_at='2026-01-01'+separator+'00:05:00Z',observed=observed))
    fixtures.append(dict(policy=policy,statement=json.dumps(statement),principal=principal,source=source,matched=matched))
failed=copy.deepcopy(fixtures[-1])
statement=json.loads(failed['statement'])
statement['predicate']['observed']['checks']['unit']['exit_code']=1
failed['statement']=json.dumps(statement)
fixtures.append(failed)
fixtures += [dict(fixture,policy=None,age=age) for fixture in list(fixtures) for age in (None,60)]
for fixture in fixtures:
    ns['entries']=[('record',json.loads(fixture['statement']),fixture['principal'])]
    ns['source_inputs']=fixture['source']
    rules=None if fixture['policy'] is None else ns['policy_rules'](fixture['policy'],'unit','owner/repo')
    try:
        result=ns['verified'](None,'a'*40,'unit',None,command if rules is not None else None,rules=rules,kinds=['wrapper'],max_age=fixture.get('age'),now=ns['parse_time']('2026-01-01T00:05:00Z'),run_inputs={})
        fixture['wire']=[]
        for name,mode in itertools.product(['unit','\ud800','face😀'],range(3)):
            wire=dict(result,check=name)
            if mode==0:
                wire.pop('decided_by',None);wire.pop('skipped_newer',None)
            elif mode==2: wire['skipped_newer']=['other host level_not_accepted']
            fixture['wire'].append(json.dumps(wire,indent=2))
        for key in ('tier','observed_at','matched_tree'): result[key]=list(map(ord,result[key]))
        result['command']=[list(map(ord,arg)) for arg in result['command']]
        result['inputs']=[[list(map(ord,k)),list(map(ord,v))] for k,v in result['inputs'].items()]
        fixture['expected']=result
    except ns['Failure'] as e: fixture['expected']=dict(reason=e.reason)
print(json.dumps(fixtures))
"#;
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
    let output = std::process::Command::new("python3")
        .args(["-c", script, &root])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixtures: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(fixtures.len(), 435);
    struct NoGit;
    impl Provider for NoGit {
        fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
            panic!("no lane required")
        }
        fn blob_sha256(&mut self, _: &std::path::Path) -> Result<Option<String>, PolicyError> {
            panic!("no bindings")
        }
    }
    let wire_names = [
        None,
        Some(&[0xd800][..]),
        Some(&[102, 97, 99, 101, 0x1f600][..]),
    ];
    let wire_skips = ["other host level_not_accepted".to_owned()];
    let mut wire_cases = 0;
    for fixture in fixtures {
        let policy = fixture["policy"].as_str().map(|policy| {
            PolicyDocument::parse(policy, "unit")
                .unwrap()
                .into_rules("owner/repo")
                .unwrap()
        });
        let document = statement_of(
            fixture["statement"].as_str().unwrap().as_bytes(),
            fixture["matched"].as_str().unwrap(),
        )
        .unwrap()
        .unwrap();
        let facts = DocumentFacts::for_check(
            &document,
            &[117, 110, 105, 116],
            fixture["principal"].as_str().unwrap(),
        )
        .unwrap();
        let candidates = vec![Candidate {
            commit: "record",
            facts,
        }];
        let kinds = vec!["wrapper".chars().map(u32::from).collect()];
        let options = super::super::judgment::Unconfigured {
            routing: super::super::routing::Unconfigured {
                kinds: &kinds,
                trust_levels: None,
                runner_prefix: None,
            },
            command: None,
            max_age: fixture["age"]
                .as_u64()
                .map(super::super::inputs::AgeLimit::Seconds),
            bindings: &[],
        };
        let prepared = match &policy {
            Some(policy) => Prepared::new(policy, candidates, "unit").unwrap(),
            None => Prepared::unconfigured(&options, candidates),
        };
        let decision = CheckJudgment {
            clock: &mut 1_767_225_900_000_000i64,
            run_inputs: &std::collections::BTreeMap::new(),
            lane: None,
            provider: LaneOnce::new(NoGit),
        }
        .select(&prepared, "unit", Levels::Utf8(&[]));
        if let Ok((_, routing)) = &decision.result {
            assert_eq!(routing.is_none(), policy.is_none());
        }
        let actual = match Satisfied::from_decision(
            &prepared,
            &decision,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "unit",
            fixture["source"].as_str(),
        ) {
            Err(error) => {
                assert!(std::ptr::eq(error, decision.result.as_ref().err().unwrap()));
                json!({"reason":error.reason})
            }
            Ok(mut result) => {
                let original = (result.decided_by, result.skipped_newer);
                for (index, name) in wire_names.iter().enumerate() {
                    for mode in 0..3 {
                        result.check = name.map_or_else(|| "unit".into(), Into::into);
                        result.decided_by = if mode == 0 { None } else { original.0 };
                        result.skipped_newer = match mode {
                            0 => None,
                            1 => original.1,
                            _ => Some(&wire_skips),
                        };
                        let mut bytes = String::new();
                        crate::evidence::legacy_output::write(&mut bytes, |w| result.write_json(w))
                            .unwrap();
                        assert_eq!(
                            bytes,
                            fixture["wire"][index * 3 + mode].as_str().unwrap(),
                            "{fixture}"
                        );
                        wire_cases += 1;
                    }
                }
                result.check = "unit".into();
                (result.decided_by, result.skipped_newer) = original;
                assert!(std::ptr::eq(result.tier, prepared.candidates[0].facts.tier));
                assert!(
                    result
                        .command()
                        .zip(prepared.candidates[0].facts.command())
                        .all(|(a, b)| std::ptr::eq(a, b))
                );
                json!({
                    "satisfied":result.satisfied,"tree":result.tree,"check":result.check.to_string(),"record":result.record,
                    "kind":result.kind,"signer":result.signer,"trust_level":result.trust_level,"tier":result.tier,
                    "observed_at":result.observed_at,"command":result.command().collect::<Vec<_>>(),
                    "inputs":result.inputs().collect::<Vec<_>>(),"attempts":result.attempts,"policy":result.policy,
                    "max_age_s":result.max_age_s,"enforce":result.enforce,"match":result.r#match,
                    "matched_tree":result.matched_tree,"source_inputs":result.source_inputs,"sample_one_in":result.sample_one_in,
                    "events":result.events().map(|events|events.collect::<Vec<_>>()),
                    "decided_by":result.decided_by,"skipped_newer":result.skipped_newer
                })
            }
        };
        assert_eq!(actual, fixture["expected"], "{fixture}");
    }
    assert_eq!(wire_cases, 3888);
}
