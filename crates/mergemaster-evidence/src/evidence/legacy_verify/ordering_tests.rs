use super::*;
use crate::evidence::{
    legacy_policy::{PolicyDocument, PolicyError},
    legacy_verify::{candidates::Candidate, facts::DocumentFacts, statement_document::Document},
};
use serde_json::{Value, json};
#[test]
fn candidate_walks_match_python() {
    let policy = r#"{"version":1,"checks":{"unit":{"trust_levels":["agent","host"],"kinds":{"wrapper":{"command":["true"],"bind_inputs":{"bound":"path"}}}}}}"#;
    let rules = PolicyDocument::parse(policy, "unit")
        .unwrap()
        .into_rules("owner/repo")
        .unwrap();
    struct HashSource(bool);
    impl Provider for HashSource {
        fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
            panic!("supplied lane")
        }
        fn blob_sha256(&mut self, _: &str) -> Result<Option<String>, PolicyError> {
            if self.0 {
                Err(PolicyError {
                    reason: "record-budget-exceeded",
                    detail: "provider refused".into(),
                })
            } else {
                Ok(Some("hash".into()))
            }
        }
    }
    let script = r#"
import ast,json,runpy,sys
root,policy=sys.argv[1],sys.argv[2]
ns=runpy.run_path(root+'/scripts/evidence-verify')
module=ast.parse(open(root+'/scripts/evidence-verify').read())
fn=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='verified')
fn.body=ast.parse('with_check = entries; input_key = None').body+[n for n in fn.body if 1012<=n.lineno<=1170]
fn.body+=ast.parse('''
try:
    if mode == 'shadow':
        failures=failed_after(with_check[0])
        found=max(failures,key=dated) if failures else None
    else:
        pair=first_valid(with_check)
        found=pair[0] if pair else None
    return ['ok',found[0] if found else None,None,skipped,attempts]
except Failure as e:
    return [e.reason,None,e.extra.get('decided_by'),e.extra.get('skipped_newer',[]),attempts]
except OverflowError:
    return ['error',None,None,skipped,attempts]
''').body
exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'<pinned-walk>','exec'),ns)
rules=ns['policy_rules'](policy,'unit','owner/repo')
def blob(*args):
    if ns['mode']=='provider':
        raise ns['Failure']('record-budget-exceeded','provider refused',attempts=len(ns['entries']))
    return 'hash'
ns['blob_sha256']=blob
# Entry: commit, timestamp, exit, level, definition, runner.
passing=['pass','2026-01-01T00:05:00Z',0,'agent','base','wrapper']
cases=[['provider',[passing,passing]]]
for level in ('agent','host','fleet'):
    for definition in ('base','wrong'):
        for runner in ('wrapper','unsupported'):
            other=['other','2026-01-01T00:06:00Z',0,level,definition,runner]
            cases.append(['walk',[other,other,passing]])
            cases.append(['walk',[other,other]])
for date in ('0001-01-01T00:01:59Z','0001-01-01T00:01:59.999999Z',
             '0001-01-01T00:01:59-12:00','0001-01-01T12:01:59+12:00',
             '0001-01-01T00:02:00Z'):
    for exit in (0,1):
        old=['old',date,0,'agent','base','wrapper']
        failure=['failure','2026-01-01T00:03:00Z',exit,'fleet','base','wrapper']
        cases.append(['shadow',[old,failure]])
for date in ('2026-01-01T00:02:59.999999Z','2026-01-01T00:03:00Z',
             '2026-01-01T00:03:00.000001Z','2026-01-01T00:05:00Z',
             '2026-01-01T12:03:00+12:00'):
    first=['first',date,-1,'fleet','base','wrapper']
    second=['second',date,-1,'host','base','wrapper']
    cases.append(['shadow',[passing,first,second]])
actual=[]
for mode,specs in cases:
    ns['mode']=mode
    ns['entries']=[(commit,dict(subject=[dict(digest=dict(gitTree='tree'))],predicate=dict(tier='full',observed_at=time,observed=dict(runner=runner,inputs=dict(lane_definition_sha256=definition,bound='hash'),checks=dict(unit=dict(exit_code=exit,command=['true']))))),level+'/key') for commit,time,exit,level,definition,runner in specs]
    actual.append(ns['verified'](None,'tree','unit',None,['true'],rules=rules,now=ns['parse_time']('2026-01-01T00:05:00Z'),lane=dict(sha256='base',changed=[],tree_sha256='tree'),run_inputs={}))
print(json.dumps([cases,actual]))
"#;
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
    let output = std::process::Command::new("python3")
        .args(["-c", script, &root, policy])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (cases, expected): (Vec<Value>, Vec<Value>) =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 40);
    let mut actual = Vec::new();
    for case in &cases {
        let entries = case[1].as_array().unwrap();
        let docs: Vec<_> = entries.iter().map(|e| Document::from_bytes(json!({"subject":[{"digest":{"gitTree":"tree"}}],"predicate":{"tier":"full","observed_at":e[1],"observed":{"runner":e[5],"inputs":{"lane_definition_sha256":e[4],"bound":"hash"},"checks":{"unit":{"exit_code":e[2],"command":["true"]}}}}}).to_string().as_bytes()).unwrap()).collect();
        let principals: Vec<_> = entries
            .iter()
            .map(|e| format!("{}/key", e[3].as_str().unwrap()))
            .collect();
        let candidates = docs
            .iter()
            .enumerate()
            .map(|(i, doc)| Candidate {
                commit: entries[i][0].as_str().unwrap(),
                facts: DocumentFacts::for_check(doc, &[117, 110, 105, 116], &principals[i])
                    .unwrap(),
            })
            .collect();
        let prepared = Prepared::new(&rules, candidates, "unit").unwrap();
        let mut walk = Walk::default();
        let result = if case[0] == "shadow" {
            latest_failure_after(&prepared, 0)
        } else {
            let lane = LaneDefinition {
                sha256: "base".into(),
                changed: vec![],
                tree_sha256: "tree".into(),
            };
            CheckJudgment {
                now_micros: 1_767_225_900_000_000,
                run_inputs: &BTreeMap::new(),
                lane: Some(&lane),
                provider: LaneOnce::new(HashSource(case[0] == "provider")),
            }
            .first_valid(
                &prepared,
                &(0..prepared.attempts()).collect::<Vec<_>>(),
                &mut walk,
            )
            .map(|found| found.map(|(i, _)| i))
        };
        actual.push(json!([
            result.as_ref().map_or_else(|e| e.reason, |_| "ok"),
            result.ok().flatten().map(|i| prepared.candidates[i].commit),
            walk.decided_by.map(|i| prepared.candidates[i].commit),
            walk.skipped_newer,
            prepared.attempts()
        ]));
    }
    for (i, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
        assert_eq!(actual, expected, "case {}", cases[i]);
    }
    assert_eq!(actual.len(), expected.len());
}
