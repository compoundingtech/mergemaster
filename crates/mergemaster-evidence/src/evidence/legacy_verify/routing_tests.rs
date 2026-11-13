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
    except v['Failure'] as failure: expected = dict(reason=failure.reason,attempts=failure.extra['attempts'])
    cases.append(dict(policy=policy,raw=json.dumps(statement),expected=expected))
print(json.dumps(cases))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script, &root])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 96);
    for case in cases {
        let rules = PolicyDocument::parse(case["policy"].as_str().unwrap(), "check")
            .unwrap()
            .into_rules("owner/repo")
            .unwrap();
        let doc = super::super::statement_document::Document::from_bytes(
            case["raw"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        let facts =
            DocumentFacts::for_check(&doc, &[99, 104, 101, 99, 107], "agent/alice").unwrap();
        let actual = route_document(&rules, &facts, 7).and_then(|routing| {
            routing.check_document_runner(facts.runner, 7)?;
            Ok(json!({"reason":"satisfied","command":routing.command_inputs.command,
                "required":routing.command_inputs.required_inputs,"bind":routing.command_inputs.bind_inputs,
                "events":routing.level.map(|level| &level.events)}))
        }).unwrap_or_else(|failure| json!({"reason":failure.reason,"attempts":failure.attempts}));
        assert_eq!(actual, case["expected"], "{case}");
    }
}
