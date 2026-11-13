use super::*;
use crate::evidence::{
    legacy_policy::{PolicyDocument, PolicyError},
    legacy_verify::{candidates::Candidate, facts::DocumentFacts, statement_document::Document},
};
use serde_json::{Value, json};
#[test]
fn candidate_walks_and_selection_match_python() {
    let policy = r#"{"version":1,"checks":{"unit":{"trust_levels":["agent","host"],"kinds":{"wrapper":{"command":["true"],"bind_inputs":{"bound":"path"}}}}}}"#;
    let rules = PolicyDocument::parse(policy, "unit")
        .unwrap()
        .into_rules("owner/repo")
        .unwrap();
    struct HashSource<'a>(bool, &'a std::cell::Cell<usize>);
    impl Provider for HashSource<'_> {
        fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
            panic!("supplied lane")
        }
        fn blob_sha256(&mut self, _: &std::path::Path) -> Result<Option<String>, PolicyError> {
            self.1.set(self.1.get() + 1);
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
import ast,copy,json,runpy,sys
root,policy=sys.argv[1],sys.argv[2]
ns=runpy.run_path(root+'/scripts/evidence-verify')
module=ast.parse(open(root+'/scripts/evidence-verify').read())
fn=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='verified')
selection=copy.deepcopy(fn)
selection.name='selection'
selection.body=ast.parse('with_check = entries; input_key = None').body+[n for n in selection.body if n.lineno>=1012]
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
exec(compile(ast.fix_missing_locations(ast.Module(body=[fn,selection],type_ignores=[])),'<pinned-walk>','exec'),ns)
rules=ns['policy_rules'](policy,'unit','owner/repo')
def blob(*args):
    ns['blob_reads']+=1
    if ns['mode'].endswith('provider'):
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
# Full ordering matrix: preferences, stable ties, fallback and conservative failures.
def entry(commit,seconds,exit=0,level='agent',definition='base',runner='wrapper'):
    return [commit,f'2026-01-01T00:{seconds//60:02}:{seconds%60:02}Z',exit,level,definition,runner]
for seconds in (179,180,181,300,301):
    for exit in (0,1):
        for level in ('agent','host','fleet'):
            for prefer in ([],['host'],['host','\ud800'],['\ud800'],['\ufffd'],['🦀'],['']):
                cases.append(['select',[passing,entry('other',seconds,exit,level)],prefer])
for field,value in ((4,'wrong'),(5,'unsupported'),(3,'fleet')):
    newer=entry('newer',400)
    newer[field]=value
    cases.extend([['select',[newer,passing],[]],['select',[newer,newer,passing],['agent']],['select',[newer],[]]])
for date in ('0001-01-01T00:01:59Z','0001-01-01T00:01:59-12:00',
             '0001-01-01T12:01:59+12:00','0001-01-01T00:02:00Z'):
    for exit in (0,1):
        cases.append(['select',[['old',date,0,'host','base','wrapper'],entry('new',300,exit)],['host']])
for entries in ([entry('a',300),entry('b',300)],[entry('b',300),entry('a',300)],
                [entry('a',300,1),entry('b',300,1)],[entry('b',300,1),entry('a',300,1)],
                [passing,entry('failure',300,1)],[entry('failure',300,1),passing]):
    cases.append(['select',entries,[]])
cases.extend([
    ['select',[passing,entry('obsolete',0,0,'host','base','unsupported'),entry('failure',60,1)],['host']],
    ['select',[entry('preferred',300,0,'host'),['old','0001-01-01T00:01:59Z',0,'host','base','wrapper'],entry('failure',60,1)],['host']],
    ['select',[entry('foreign',400,0,'fleet'),passing],['fleet']],
    ['select',[entry('foreign',300,0,'fleet'),entry('failure',180,1,'host')],[]],
    ['select-provider',[passing,passing],[]]])
cases += [[case[0].replace('select','select-unconfigured'),copy.deepcopy(case[1]),copy.deepcopy(case[2]),levels]
          for case in list(cases) if case[0].startswith('select') for levels in (None,[],['agent'],['fleet','\ud800'])]
actual=[]
for case in cases:
    mode,specs=case[:2]
    ns['mode']=mode
    ns['blob_reads']=0
    ns['entries']=[(commit,dict(subject=[dict(digest=dict(gitTree='tree'))],predicate=dict(tier='full',observed_at=time,observed=dict(runner=runner,inputs=dict(lane_definition_sha256=definition,bound='hash'),checks=dict(unit=dict(exit_code=exit,command=['true']))))),level+'/key') for commit,time,exit,level,definition,runner in specs]
    try:
        if mode.startswith('select'):
            result=ns['selection'](None,'tree','unit',None,['true'],rules=None if 'unconfigured' in mode else rules,kinds=['wrapper'],trust_levels=case[3] if 'unconfigured' in mode else None,bind=[('bound','path')],now=ns['parse_time']('2026-01-01T00:05:00Z'),lane=dict(sha256='base',changed=[],tree_sha256='tree'),run_inputs={},prefer_levels=case[2])
            verdict=['ok',result['record'],result.get('decided_by'),result.get('skipped_newer',[]),result['attempts']]
        else:
            verdict=ns['verified'](None,'tree','unit',None,['true'],rules=rules,now=ns['parse_time']('2026-01-01T00:05:00Z'),lane=dict(sha256='base',changed=[],tree_sha256='tree'),run_inputs={})
    except ns['Failure'] as e:
        verdict=[e.reason,None,e.extra.get('decided_by'),e.extra.get('skipped_newer',[]),len(specs)]
    except OverflowError:
        verdict=['error',None,None,[],len(specs)]
    actual.append(verdict+[ns['blob_reads']])
    if mode.startswith('select'): case[2] = [list(map(ord,level)) for level in case[2]]
    if 'unconfigured' in mode and case[3] is not None: case[3] = [list(map(ord,level)) for level in case[3]]
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
    assert_eq!(cases.len(), 1230);
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
        let unconfigured = case[0].as_str().unwrap().contains("unconfigured");
        let levels: Option<Vec<Vec<u32>>> =
            serde_json::from_value(case.get(3).cloned().unwrap_or(Value::Null)).unwrap();
        let kinds = vec!["wrapper".chars().map(u32::from).collect()];
        let command = vec!["true".chars().map(u32::from).collect()];
        let bindings = vec![(
            "bound".chars().map(u32::from).collect(),
            std::path::PathBuf::from("path"),
        )];
        let options = super::super::judgment::Unconfigured {
            routing: super::super::routing::Unconfigured {
                kinds: &kinds,
                trust_levels: levels.as_deref(),
                runner_prefix: None,
            },
            command: Some(&command),
            max_age: None,
            bindings: &bindings,
        };
        let prepared = if unconfigured {
            Prepared::unconfigured(&options, candidates)
        } else {
            Prepared::new(&rules, candidates, "unit").unwrap()
        };
        if unconfigured {
            assert_eq!(prepared.attempts(), entries.len());
        }
        let mut walk = Walk::default();
        let reads = std::cell::Cell::new(0);
        let result = if case[0] == "shadow" {
            latest_failure_after(&prepared, 0)
        } else {
            let lane = LaneDefinition {
                sha256: "base".into(),
                changed: vec![],
                tree_sha256: "tree".into(),
            };
            let mut judgment = CheckJudgment {
                clock: &mut 1_767_225_900_000_000i64,
                run_inputs: &BTreeMap::new(),
                lane: Some(&lane),
                provider: LaneOnce::new(HashSource(
                    case[0].as_str().unwrap().ends_with("provider"),
                    &reads,
                )),
            };
            if case[0].as_str().unwrap().starts_with("select") {
                let prefer: Vec<Vec<u32>> = serde_json::from_value(case[2].clone()).unwrap();
                let decision = judgment.select(&prepared, "unit", Levels::Codepoints(&prefer));
                let native: Option<Vec<String>> = prefer
                    .iter()
                    .map(|points| points.iter().map(|&point| char::from_u32(point)).collect())
                    .collect();
                if let Some(native) = native {
                    let native_reads = std::cell::Cell::new(0);
                    let mut native_judgment = CheckJudgment {
                        provider: LaneOnce::new(HashSource(
                            case[0].as_str().unwrap().ends_with("provider"),
                            &native_reads,
                        )),
                        ..judgment
                    };
                    let native = native_judgment.select(&prepared, "unit", Levels::Utf8(&native));
                    assert_eq!(
                        native.result.as_ref().map(|(i, _)| i).map_err(|e| e.reason),
                        decision
                            .result
                            .as_ref()
                            .map(|(i, _)| i)
                            .map_err(|e| e.reason)
                    );
                    assert_eq!(native.walk.decided_by, decision.walk.decided_by);
                    assert_eq!(native.walk.skipped_newer, decision.walk.skipped_newer);
                    assert_eq!(native_reads.get(), reads.get());
                }
                walk = decision.walk;
                decision.result.map(|(i, _)| Some(i))
            } else {
                judgment
                    .first_valid(
                        &prepared,
                        &(0..prepared.attempts()).collect::<Vec<_>>(),
                        &mut walk,
                    )
                    .map(|found| found.map(|(i, _)| i))
            }
        };
        if let Err(error) = &result {
            assert_eq!(error.exception, error.reason == "error", "{case}");
        }
        actual.push(json!([
            result.as_ref().map_or_else(|e| e.reason, |_| "ok"),
            result.ok().flatten().map(|i| prepared.candidates[i].commit),
            walk.decided_by.map(|i| prepared.candidates[i].commit),
            walk.skipped_newer,
            prepared.attempts(),
            reads.get()
        ]));
    }
    for (i, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
        assert_eq!(actual, expected, "case {}", cases[i]);
    }
    assert_eq!(actual.len(), expected.len());
}
