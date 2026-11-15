use super::*;
use crate::evidence::legacy_policy::PolicyDocument;
use serde_json::{Value, json};

#[test]
fn lossless_routing_matches_the_pinned_judge_prefix() {
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned Python oracle");
    let script = r#"
import ast, copy, json, pathlib, runpy, sys
path = pathlib.Path(sys.argv[1])/'scripts/evidence-verify'
v = runpy.run_path(str(path)); module = ast.parse(path.read_text())
verify = next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='verified')
judge = copy.deepcopy(next(n for n in verify.body if isinstance(n,ast.FunctionDef) and n.name=='judge'))
stop = next(i for i,n in enumerate(judge.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='moment' for t in n.targets))
judge.body = judge.body[:stop] + ast.parse("return dict(reason='satisfied', command=command, required=list(required_inputs), bind=bind, events=events)").body
v.update(command=None,kinds=(),bind=(),max_age=None,runner_prefix=None,trust_levels=None,lane=None,level_lane=None,check='check',attempts=7)
v['failed'] = lambda entry: entry[1]['predicate']['observed']['checks']['check']['exit_code'] != 0
exec(compile(ast.fix_missing_locations(ast.Module(body=[judge],type_ignores=[])),str(path),'exec'),v)
cases = []
for runner in ['wrapper','wrapper\ud800','github:','github:\ud800','github:\ufffd','github:🦀','nix','other']:
 for code in [0,1,-10**100]:
  for tier,part in [('full',False),('test',True)]:
   for prefix in [None,'github:\ufffd']:
    entry = dict(trust_levels=['agent'],kinds={kind:dict(command=['true'],shard_inputs=dict(count='n',results='r',index='i'),by_level={'agent':dict(command=['override'],required_inputs=['bound'],events=['merge_group'])}) for kind in ['wrapper','observed','nix']})
    if prefix is not None:
     for kind in entry['kinds'].values(): kind['runner_prefix'] = prefix
    policy = json.dumps(dict(version=1,checks=dict(check=entry))); v['rules'] = v['policy_rules'](policy,'check','owner/repo')
    statement = dict(predicate=dict(tier=tier,observed_at='2026-01-01T00:00:00Z',observed=dict(runner=runner,checks=dict(check=dict(exit_code=code,command=['true'])))))
    if part: statement['predicate']['observed']['inputs'] = {'i':'\ud800'}
    try: expected = v['judge'](('record',statement,'agent/alice'))
    except v['Failure'] as failure: expected = dict(reason=failure.reason,attempts=failure.extra['attempts'],detail=list(map(ord,failure.detail)))
    cases.append(dict(policy=policy,raw=json.dumps(statement),expected=expected))
# Valid policy ingress can omit a recognized runner's kind; unknown runners
# reach the same explicit refusal. Neither case may use a default kind or skip.
for runner in ['nix', 'github:owner/repo/job', 'unknown']:
    policy = json.dumps(dict(version=1,checks=dict(check=dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=['true']))))))
    v['rules'] = v['policy_rules'](policy,'check','owner/repo')
    statement = dict(predicate=dict(tier='full',observed_at='2026-01-01T00:00:00Z',observed=dict(runner=runner,checks=dict(check=dict(exit_code=0,command=['true'])))))
    try:
        v['judge'](('record',statement,'agent/alice'))
        raise AssertionError('unsupported kind was accepted')
    except v['Failure'] as failure:
        assert (failure.reason,failure.detail,failure.extra['attempts']) == ('unsupported_kind',f'runner {runner!r} is not one of ',7)
        expected = dict(reason=failure.reason,attempts=failure.extra['attempts'],detail=list(map(ord,failure.detail)))
    cases.append(dict(policy=policy,raw=json.dumps(statement),expected=expected))
def loose(runner, tier, code, kinds, levels, prefix, principal='agent/alice'):
    v['rules'] = None
    statement = dict(predicate=dict(tier=tier,observed_at='2026-01-01T00:00:00Z',observed=dict(runner=runner,inputs={'i':'part'},checks=dict(check=dict(exit_code=code,command=['true'])))))
    try: expected = v['judge'](('record',statement,principal),kinds=kinds,trust_levels=levels,runner_prefix=prefix)
    except v['Failure'] as failure: expected = dict(reason=failure.reason,attempts=failure.extra['attempts'],detail=list(map(ord,failure.detail)))
    points = lambda value: None if value is None else list(map(ord,value))
    cases.append(dict(policy=None,raw=json.dumps(statement),expected=expected,principal=principal,
                      kinds=[points(kind) for kind in kinds],levels=None if levels is None else [points(level) for level in levels],prefix=points(prefix)))
all_kinds = ['wrapper','observed','nix','sekrets']
for runner in ['wrapper','wrapper\ud800','github:','github:\ud800','github:\ufffd','github:🦀','nix','sekrets','other','\ud800']:
 for tier in ['full','test']:
  for code in [0,-10**100]:
   for kinds,levels,prefix in [(all_kinds,None,None),([],None,None),(['wrapper','observed','\ud800'],['agent'],None),(all_kinds,[],None),(all_kinds,['host','\ud800'],None),(all_kinds,None,'github:\ud800'),(all_kinds,None,''),(all_kinds,None,'github:\ufffd'),(all_kinds,None,'github:🦀')]:
    loose(runner,tier,code,kinds,levels,prefix)
for principal in ['host/alice','agent','']:
 for levels in [None,[],['host','agent','']]:
  loose('wrapper','full',0,all_kinds,levels,None,principal)
print(json.dumps(cases))
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script, &root])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 468);
    for case in cases {
        let doc = super::super::statement_document::Document::from_bytes(
            case["raw"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        let principal = case["principal"].as_str().unwrap_or("agent/alice");
        let facts = DocumentFacts::for_check(&doc, &[99, 104, 101, 99, 107], principal).unwrap();
        let actual = if case["policy"].is_null() {
            let kinds: Vec<Vec<u32>> = serde_json::from_value(case["kinds"].clone()).unwrap();
            let levels: Option<Vec<Vec<u32>>> = serde_json::from_value(case["levels"].clone()).unwrap();
            let prefix: Option<Vec<u32>> = serde_json::from_value(case["prefix"].clone()).unwrap();
            route_unconfigured(Unconfigured {
                kinds: &kinds, trust_levels: levels.as_deref(), runner_prefix: prefix.as_deref(),
            }, &facts, 7).map(|()| json!({"reason":"satisfied","command":null,"required":[],"bind":[],"events":null}))
        } else {
            let rules = PolicyDocument::parse(case["policy"].as_str().unwrap(), "check")
                .unwrap().into_rules("owner/repo").unwrap();
            route_document(&rules, &facts, 7).and_then(|routing| {
                routing.check_document_runner(facts.runner, 7)?;
                Ok(json!({"reason":"satisfied","command":routing.command_inputs.command,
                    "required":routing.command_inputs.required_inputs,"bind":routing.command_inputs.bind_inputs,
                    "events":routing.level.map(|level| &level.events)}))
            })
        }.unwrap_or_else(|failure| {
            assert_eq!(failure.origin, crate::evidence::legacy_policy::ErrorOrigin::Failure);
            json!({"reason":failure.reason,"attempts":failure.attempts,
                "detail":failure.detail.borrowed().points().collect::<Vec<_>>()})
        });
        assert_eq!(actual, case["expected"], "{case}");
    }
}

#[test]
fn policy_routes_always_supply_the_resolved_kind_and_level_inputs() {
    let policy = PolicyDocument::parse(
        r#"{"version":1,"checks":{"check":{"trust_levels":["agent","host"],
        "kinds":{"wrapper":{"command":["true"],
        "by_level":{"agent":{"command":["override"],"events":["pull_request"]}}}}}}}"#,
        "check",
    )
    .unwrap()
    .into_rules("owner/repo")
    .unwrap();
    let check = Check {
        command: vec!["true".into()],
        exit_code: 0,
        output_sha256: String::new(),
    };
    let inputs = BTreeMap::new();
    let doc = super::super::statement_document::Document::from_bytes(
        br#"{"predicate":{"tier":"full","observed_at":"2026-01-01T00:00:00Z",
        "observed":{"runner":"wrapper","checks":{"check":{"exit_code":0,"command":["true"]}}}}}"#,
    )
    .unwrap();
    for (principal, expected, overridden) in [
        ("agent/alice", "override", true),
        ("host/alice", "true", false),
    ] {
        let native = route(
            &policy,
            &RecordFacts {
                check_name: "check".into(),
                tier: TrustTier::Full,
                runner: "wrapper",
                principal,
                check: &check,
                inputs: &inputs,
            },
            7,
        )
        .unwrap();
        let facts = DocumentFacts::for_check(&doc, &[99, 104, 101, 99, 107], principal).unwrap();
        let document = route_document(&policy, &facts, 7).unwrap();
        for routing in [native, document] {
            assert!(std::ptr::eq(routing.kind, &policy.kinds[0].1));
            assert_eq!(routing.level.is_some(), overridden);
            assert_eq!(routing.command_inputs.command, [expected]);
        }
    }
}
