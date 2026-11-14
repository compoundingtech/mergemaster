use super::super::{inputs::AgeLimit, statement_document::Document};
use super::*;
use serde_json::{Value, json};
#[test]
fn unconfigured_judgment_matches_the_pinned_joined_guards() {
    use std::{
        ffi::OsString,
        os::unix::ffi::{OsStrExt, OsStringExt},
    };
    let oracle = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned Python oracle");
    let script = r#"
import ast, copy, json, os, pathlib, runpy, sys
from datetime import datetime, timezone
path=pathlib.Path(sys.argv[1])/'scripts/evidence-verify'; v=runpy.run_path(str(path))
owner=next(n for n in ast.parse(path.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='verified')
judge=copy.deepcopy(next(n for n in owner.body if isinstance(n,ast.FunctionDef) and n.name=='judge'))
judge.body[-1]=ast.parse("return dict(reason='satisfied')").body[0]
v.update(rules=None,command=None,kinds=(),bind=(),max_age=None,runner_prefix=None,trust_levels=None,lane=None,level_lane=None,check='check',attempts=7,repo='repo',tree='tree')
v['failed']=lambda entry: entry[1]['predicate']['observed']['checks']['check']['exit_code'] != 0
exec(compile(ast.fix_missing_locations(ast.Module(body=[judge],type_ignores=[])),str(path),'exec'),v)
cases=[]
variants=[('satisfied',{}),('no lane',dict(lane=None)),('optional command',dict(command=None,actual=['other'])),
 ('wrong command before lane',dict(actual=['other'],changed=['path'])),('failed before lane',dict(code=-10**100,changed=['path'])),
 ('age before lane',dict(age=1,changed=['path'])),('future before overflow',dict(observed='2026-01-01T00:02:06Z',age=10**100)),
 ('changed before binding',dict(changed=['path'],blobs={})),('wrong digest before binding',dict(inputs={'bound':'hash'},blobs={})),
 ('missing blob',dict(blobs={})),('missing input',dict(inputs={'lane_definition_sha256':'lane'})),
 ('empty input',dict(inputs={'lane_definition_sha256':'lane','bound':''})),('wrong input',dict(inputs={'lane_definition_sha256':'lane','bound':'wrong'})),
 ('ordered stop',dict(bindings=[('bound','path'),('missing','second'),('bound','never')],blobs={'path':'hash','second':'hash'})),
 ('surrogate key',dict(bindings=[('\ud800','path')],inputs={'lane_definition_sha256':'lane','\ud800':'hash'})),
 ('native bytes',dict(bindings=[('bound','path-\udcff')],blobs={'path-\udcff':'hash'})),
 ('runner before age',dict(prefix='other',age=1)),('tier before runner',dict(tier='test',prefix='other')),
 ('kind before level',dict(kinds=[],levels=[])),('level before runner',dict(levels=[],prefix='other')),
 ('no bindings',dict(bindings=[])),('provider failure',dict(error=True))]
for label,changes in variants:
    c=dict(command=['true'],actual=['true'],age=None,observed='2026-01-01T00:00:00Z',code=0,tier='full',kinds=['wrapper'],levels=None,prefix=None,bindings=[('bound','path')],inputs={'lane_definition_sha256':'lane','bound':'hash'},changed=[],blobs={'path':'hash'},error=False,lane=True)
    c.update(changes); lane=None if c['lane'] is None else dict(sha256='lane',changed=c['changed'],tree_sha256='tree')
    statement=dict(predicate=dict(tier=c['tier'],observed_at=c['observed'],observed=dict(runner='wrapper',inputs=c['inputs'],checks=dict(check=dict(exit_code=c['code'],command=c['actual'])))))
    calls=[]
    def blob(repo,tree,path):
        calls.append(os.fsencode(path).hex())
        if c['error']: raise v['Failure']('record-budget-exceeded','fixture transport refused',attempts=7)
        return c['blobs'].get(path)
    v.update(blob_sha256=blob,now=datetime(2026,1,1,0,0,5,tzinfo=timezone.utc))
    try: expected=v['judge'](('record',statement,'agent/alice'),command=c['command'],kinds=c['kinds'],bind=c['bindings'],max_age=c['age'],runner_prefix=c['prefix'],trust_levels=c['levels'],lane=lane)
    except v['Failure'] as e: expected=dict(reason=e.reason,attempts=e.extra['attempts'])
    except OverflowError: expected=dict(reason='error',attempts=7)
    points=lambda text: None if text is None else list(map(ord,text))
    cases.append(dict(label=label,raw=json.dumps(statement),expected=expected,calls=calls,lane=lane,error=c['error'],command=None if c['command'] is None else [points(s) for s in c['command']],age=c['age'],kinds=[points(s) for s in c['kinds']],levels=None if c['levels'] is None else [points(s) for s in c['levels']],prefix=points(c['prefix']),bindings=[(points(k),os.fsencode(p).hex()) for k,p in c['bindings']],blobs={os.fsencode(k).hex():v for k,v in c['blobs'].items()}))
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
    assert_eq!(cases.len(), 22);
    struct Source<'a> {
        case: &'a Value,
        calls: Vec<String>,
    }
    impl Provider for Source<'_> {
        fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
            panic!("no policy-level lane lookup")
        }
        fn blob_sha256(&mut self, path: &std::path::Path) -> Result<Option<String>, PolicyError> {
            let key = hex::encode(path.as_os_str().as_bytes());
            self.calls.push(key.clone());
            if self.case["error"] == true {
                return Err(PolicyError {
                    origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
                    reason: "record-budget-exceeded",
                    detail: "fixture transport refused".into(),
                });
            }
            Ok(self.case["blobs"][key].as_str().map(str::to_owned))
        }
    }
    for case in cases {
        let doc = Document::from_bytes(case["raw"].as_str().unwrap().as_bytes()).unwrap();
        let record =
            DocumentFacts::for_check(&doc, &[99, 104, 101, 99, 107], "agent/alice").unwrap();
        let kinds: Vec<Vec<u32>> = serde_json::from_value(case["kinds"].clone()).unwrap();
        let levels: Option<Vec<Vec<u32>>> = serde_json::from_value(case["levels"].clone()).unwrap();
        let prefix: Option<Vec<u32>> = serde_json::from_value(case["prefix"].clone()).unwrap();
        let command: Option<Vec<Vec<u32>>> =
            serde_json::from_value(case["command"].clone()).unwrap();
        let bindings = case["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                (
                    serde_json::from_value(pair[0].clone()).unwrap(),
                    std::path::PathBuf::from(OsString::from_vec(
                        hex::decode(pair[1].as_str().unwrap()).unwrap(),
                    )),
                )
            })
            .collect::<Vec<_>>();
        let lane = (!case["lane"].is_null()).then(|| LaneDefinition {
            sha256: "lane".into(),
            tree_sha256: "tree".into(),
            changed: case["lane"]["changed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().as_bytes().to_vec())
                .collect(),
        });
        let age = if case["age"].is_null() {
            None
        } else {
            Some(
                case["age"]
                    .as_u64()
                    .map_or(AgeLimit::Overflow, AgeLimit::Seconds),
            )
        };
        let mut provider = Source {
            case: &case,
            calls: Vec::new(),
        };
        let checked = judge_unconfigured(
            &Unconfigured {
                routing: super::super::routing::Unconfigured {
                    kinds: &kinds,
                    trust_levels: levels.as_deref(),
                    runner_prefix: prefix.as_deref(),
                },
                command: command.as_deref(),
                max_age: age,
                bindings: &bindings,
            },
            &record,
            &mut 1_767_225_605_000_000i64,
            lane.as_ref(),
            &mut provider,
            7,
        );
        if case["error"] == true {
            assert_eq!(
                checked.as_ref().unwrap_err().detail,
                "fixture transport refused"
            );
        }
        let actual = checked
            .map(|()| json!({"reason":"satisfied"}))
            .unwrap_or_else(|e| json!({"reason":e.reason,"attempts":e.attempts}));
        assert_eq!(actual, case["expected"], "{}", case["label"]);
        assert_eq!(json!(provider.calls), case["calls"], "{}", case["label"]);
    }
}
