use super::*;
use crate::evidence::{legacy_policy::PolicyDocument, legacy_verify::statement_document::Document};
use serde_json::{Value, json};

#[test]
fn candidate_prelude_matches_python() {
    let policy = r#"{"version":1,"checks":{"unit":{"trust_levels":["agent"],"kinds":{
      "wrapper":{"command":["true"],"shard_inputs":{"count":"n","results":"r","index":"i"}},
      "nix":{"command":["true"],"trust_levels":["host"]}}}}}"#;
    let rules = PolicyDocument::parse(policy, "unit")
        .unwrap()
        .into_rules("owner/repo")
        .unwrap();
    let mut cases = Vec::new();
    for runner in ["wrapper", "nix", "unknown"] {
        for exit in ["0", "-1", "999999999999999999999999999999999999"] {
            for index in [None, Some(""), Some("0"), Some("\\ud800")] {
                let mut statement = json!({"predicate":{"tier":"full","observed_at":"2026-01-01T00:00:00Z",
                    "observed":{"runner":runner,"inputs":{},"checks":{"unit":{"exit_code":0,"command":["true"]}}}}});
                if let Some(index) = index {
                    statement["predicate"]["observed"]["inputs"]["i"] = json!(index);
                }
                let text = statement
                    .to_string()
                    .replace("\"exit_code\":0", &format!("\"exit_code\":{exit}"))
                    .replace("\\\\ud800", "\\ud800");
                // Duplicate entries preserve input order and count, including duplicate shard parts.
                cases.push(vec![text.clone(), text]);
            }
        }
    }
    cases.push(vec![
        cases[2][0].clone(),
        cases[0][0].clone(),
        cases[6][0].clone(),
    ]);
    let mut actual = Vec::new();
    for case in &cases {
        let docs: Vec<_> = case
            .iter()
            .map(|s| Document::from_bytes(s.as_bytes()).unwrap())
            .collect();
        let candidates = docs
            .iter()
            .enumerate()
            .map(|(i, document)| Candidate {
                commit: if i == 0 { "a" } else { "b" },
                facts: DocumentFacts::for_check(document, &[117, 110, 105, 116], "agent/key")
                    .unwrap(),
            })
            .collect();
        actual.push(match Prepared::new(&rules, candidates, "unit") {
            Ok(prepared) => {
                let Levels::Policy(accepted) = prepared.accepted_levels() else {
                    unreachable!()
                };
                json!({"commits":prepared.candidates.iter().map(|c| c.commit).collect::<Vec<_>>(),
                "attempts":prepared.attempts(),"accepted":accepted})
            }
            Err(failure) => {
                json!({"reason":failure.reason,"detail":failure.detail,"attempts":failure.attempts})
            }
        });
    }
    let script = r#"
import ast, json, runpy, sys
root, policy, cases = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
ns = runpy.run_path(root + '/scripts/evidence-verify')
rules = ns['policy_rules'](policy, 'unit', 'owner/repo')
module = ast.parse(open(root + '/scripts/evidence-verify').read())
verified = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'verified')
body = [n for n in verified.body if 1012 <= n.lineno <= 1048]
body += ast.parse("return dict(commits=[c[0] for c in with_check], attempts=attempts, accepted=sorted(accepted))").body
fn = ast.FunctionDef(name='probe', args=ast.arguments(posonlyargs=[], args=[ast.arg(arg=n) for n in ('with_check','rules','check')], kwonlyargs=[], kw_defaults=[], defaults=[]), body=body, decorator_list=[])
exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), '<pinned-prelude>', 'exec'), ns)
actual = []
for case in cases:
    entries = [('a' if i == 0 else 'b', json.loads(s), 'agent/key') for i,s in enumerate(case)]
    try: actual.append(ns['probe'](entries, rules, 'unit'))
    except ns['Failure'] as e: actual.append(dict(reason=e.reason, detail=str(e), attempts=e.extra['attempts']))
print(json.dumps(actual))
"#;
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned Python oracle");
    let output = std::process::Command::new("python3")
        .args([
            "-c",
            script,
            &root,
            policy,
            &serde_json::to_string(&cases).unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        actual,
        serde_json::from_slice::<Vec<Value>>(&output.stdout).unwrap()
    );
}

#[test]
fn lane_once_caches_success_and_absence_but_not_errors() {
    use std::{cell::Cell, rc::Rc};
    struct Source {
        calls: Rc<Cell<usize>>,
        mode: u8,
        lane: Option<LaneDefinition>,
    }
    impl Provider for Source {
        fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
            self.calls.set(self.calls.get() + 1);
            if self.mode == 1 {
                Err(PolicyError {
                    reason: "error",
                    detail: "lane refused".into(),
                })
            } else {
                Ok(self.lane.as_ref())
            }
        }
        fn blob_sha256(&mut self, _: &std::path::Path) -> Result<Option<String>, PolicyError> {
            self.calls.set(self.calls.get() + 1);
            Ok(None)
        }
    }
    for mode in [0, 1, 2] {
        let calls = Rc::new(Cell::new(0));
        let mut provider = LaneOnce::new(Source {
            calls: calls.clone(),
            mode,
            lane: (mode == 2).then(|| LaneDefinition {
                sha256: "base".into(),
                changed: vec![b"path".to_vec()],
                tree_sha256: "tree".into(),
            }),
        });
        assert_eq!(calls.get(), 0);
        for _ in 0..3 {
            let result = provider.level_lane();
            assert_eq!(result.is_err(), mode == 1);
            if mode == 2 {
                let lane = result.unwrap().unwrap();
                assert_eq!(
                    (&*lane.sha256, &lane.changed, &*lane.tree_sha256),
                    ("base", &vec![b"path".to_vec()], "tree")
                );
            }
        }
        assert_eq!(calls.get(), if mode == 1 { 3 } else { 1 });
        provider.blob_sha256(std::path::Path::new("a")).unwrap();
        provider.blob_sha256(std::path::Path::new("a")).unwrap();
        assert_eq!(calls.get(), if mode == 1 { 5 } else { 3 });
    }
}

#[test]
fn borrowed_level_views_match_pinned_membership() {
    let oracle = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
    let script = r#"
import ast, json, pathlib, sys
source=ast.parse((pathlib.Path(sys.argv[1])/'scripts/evidence-verify').read_text())
owner=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='verified')
accepted=next(n for n in owner.body if isinstance(n,ast.If) and n.lineno==1034)
preference=next(n for n in ast.walk(owner) if isinstance(n,ast.Compare) and n.lineno==1175 and isinstance(n.comparators[0],ast.Name) and n.comparators[0].id=='prefer_levels')
accept=compile(ast.Module(body=[accepted],type_ignores=[]),'pinned-accepted','exec')
prefer=compile(ast.Expression(body=preference),'pinned-preference','eval')
cases=[]
for levels in [None,[],['agent'],['agent','agent','host'],['\ud800'],['\ud800','\ufffd','🦀'],['','bad','host']]:
    ns=dict(rules=None,trust_levels=levels,prefer_levels=levels or [],level_of=lambda c:c)
    exec(accept,ns)
    for query in ['agent','host','fleet','','bad','\ufffd','🦀']:
        ns['c']=query
        cases.append(dict(levels=None if levels is None else [list(map(ord,s)) for s in levels],query=query,
                          accepted=ns['accepted'] is None or query in ns['accepted'],preferred=eval(prefer,ns)))
print(json.dumps(cases))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script, &oracle])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 49);
    for case in cases {
        let levels: Option<Vec<Vec<u32>>> = serde_json::from_value(case["levels"].clone()).unwrap();
        let query = case["query"].as_str().unwrap();
        let accepted = levels
            .as_deref()
            .map_or(Levels::Unrestricted, Levels::Codepoints);
        assert_eq!(json!(accepted.contains(query)), case["accepted"]);
        let preferred = Levels::Codepoints(levels.as_deref().unwrap_or(&[]));
        assert_eq!(json!(preferred.contains(query)), case["preferred"]);
        if let Some(points) = &levels {
            let native: Option<Vec<String>> = points
                .iter()
                .map(|points| points.iter().map(|&p| char::from_u32(p)).collect())
                .collect();
            if let Some(native) = native {
                let set = native.iter().map(String::as_str).collect();
                assert_eq!(
                    Levels::Utf8(&native).contains(query),
                    preferred.contains(query)
                );
                assert_eq!(
                    Levels::Policy(&set).contains(query),
                    preferred.contains(query)
                );
            }
        }
    }
}
