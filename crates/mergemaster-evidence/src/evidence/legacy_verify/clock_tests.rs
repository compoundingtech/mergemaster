use super::*;
use crate::evidence::{
    legacy_policy::{ErrorOrigin, PolicyDocument},
    legacy_verify::{
        candidates::{Candidate, LaneOnce, Levels, Prepared},
        inputs::{ClockException, CurrentTime},
        ordering::CheckJudgment,
        statement_document::Document,
    },
};
use serde_json::{Value, json};
use std::{cell::RefCell, rc::Rc};

#[test]
fn judgment_clock_sampling_matches_python_phase_and_repeated_calls() {
    let script = r#"
import ast,copy,json,pathlib,runpy,sys
from datetime import datetime,timezone,timedelta
path=pathlib.Path(sys.argv[1])/'scripts/evidence-verify'; v=runpy.run_path(str(path))
owner=next(n for n in ast.parse(path.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='verified')
nodes=[copy.deepcopy(n) for n in owner.body if isinstance(n,ast.FunctionDef) and n.name in ['judge','lane_once']]
next(n for n in nodes if n.name=='judge').body[-1]=ast.parse("return 'satisfied'").body[0]
v.update(command=None,kinds=(),bind=(),max_age=None,runner_prefix=None,trust_levels=None,lane=None,now=None,run_inputs=None,check='check',attempts=1,repo='repo',tree='tree')
v['failed']=lambda entry: entry[1]['predicate']['observed']['checks']['check']['exit_code']!=0
exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(path),'exec'),v); cases=[]
for name in ['satisfied','tier','kind','level','lazy-error','no-lane','runner','command','blob','stepping','clock-error']:
 calls=[]; samples=[]; next_time=datetime(2026,1,1,0,0,1,tzinfo=timezone.utc)
 class Sample(datetime):
  @classmethod
  def now(cls,tz):
   global next_time
   calls.append('clock')
   if name=='clock-error': raise OverflowError('wall clock outside datetime range')
   delta=next_time-datetime(1970,1,1,tzinfo=timezone.utc)
   samples.append((delta.days*86400+delta.seconds)*1000000+delta.microseconds); value=next_time
   if name=='stepping': next_time+=timedelta(microseconds=1)
   return value
 def lookup():
  calls.append('lane')
  if name=='lazy-error': raise v['Failure']('error','lane failed')
  return None if name=='no-lane' else dict(sha256='lane',tree_sha256='tree',changed=[])
 def blob(repo,tree,path): calls.append('blob'); return None if name=='blob' else 'hash'
 kind=dict(command=['true'],by_level={'agent':dict(command=['true'],events=['pull_request'],lane=True,bind_inputs={'bound':'path'})})
 if name=='runner': kind['runner_prefix']='other'
 entry=dict(trust_levels=['agent'],kinds={'wrapper':kind})
 if name=='stepping': entry['max_age_s']=1
 policy=json.dumps(dict(version=1,checks={'check':entry}))
 v.update(rules=v['policy_rules'](policy,'check','fixture'),datetime=Sample,lanes=[],level_lane=lookup,blob_sha256=blob)
 raw=dict(predicate=dict(tier='test' if name=='tier' else 'full',observed_at='2026-01-01T00:00:00Z',observed=dict(
  runner='other' if name=='kind' else 'wrapper',inputs=dict(bound='hash',lane_definition_sha256='lane',event_name='pull_request'),
  checks={'check':dict(command=['other'] if name=='command' else ['true'],exit_code=0)})))
 principal='host/fixture' if name=='level' else 'agent/fixture'; expected=[]
 for _ in range(2 if name=='stepping' else 1):
  try: expected.append(v['judge'](('record',raw,principal)))
  except v['Failure'] as e: expected.append(e.reason)
  except OverflowError: expected.append('error') # pinned CLI exception normalization
 target={'tier':['untrusted_tier'],'kind':['unsupported_kind'],'level':['untrusted_level'],'lazy-error':['error'],'no-lane':['no_lane'],'runner':['wrong_runner'],'command':['wrong_command'],'blob':['wrong_input'],'stepping':['satisfied','too_old'],'clock-error':['error']}.get(name,['satisfied'])
 assert expected==target,(name,expected,calls)
 cases.append(dict(name=name,policy=policy,raw=json.dumps(raw),principal=principal,expected=expected,calls=calls,samples=samples))
print(json.dumps(cases))
"#;
    let output = std::process::Command::new("python3")
        .args([
            "-c",
            script,
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    struct Sampling {
        calls: Rc<RefCell<Vec<&'static str>>>,
        samples: Vec<i64>,
        next: i64,
        step: bool,
        fail: bool,
    }
    impl CurrentTime for Sampling {
        fn epoch_micros(&mut self) -> Result<i64, ClockException> {
            self.calls.borrow_mut().push("clock");
            if self.fail {
                return super::super::inputs::system_epoch_micros(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(253_402_300_800),
                );
            }
            self.samples.push(self.next);
            let now = self.next;
            self.next += i64::from(self.step);
            Ok(now)
        }
    }
    struct Source<'a> {
        calls: Rc<RefCell<Vec<&'static str>>>,
        name: &'a str,
        lane: LaneDefinition,
    }
    impl Provider for Source<'_> {
        fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
            self.calls.borrow_mut().push("lane");
            if self.name == "lazy-error" {
                return Err(PolicyError {
                    origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
                    reason: "error",
                    detail: "lane failed".into(),
                });
            }
            Ok((self.name != "no-lane").then_some(&self.lane))
        }
        fn blob_sha256(&mut self, _: &std::path::Path) -> Result<Option<String>, PolicyError> {
            self.calls.borrow_mut().push("blob");
            Ok((self.name != "blob").then(|| "hash".into()))
        }
    }
    assert_eq!(cases.len(), 11);
    let now = chrono::Utc::now();
    let mut native = Clock {
        observed_at: (now - chrono::Duration::days(1)).fixed_offset(),
        now,
    };
    assert_eq!(native.epoch_micros().unwrap(), now.timestamp_micros());
    let mut fixed = -62_135_596_800_000_000i64;
    assert_eq!(fixed.epoch_micros().unwrap(), fixed);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let policy = PolicyDocument::parse(case["policy"].as_str().unwrap(), "check")
            .unwrap()
            .into_rules("fixture")
            .unwrap();
        let doc = Document::from_bytes(case["raw"].as_str().unwrap().as_bytes()).unwrap();
        let facts = DocumentFacts::for_check(
            &doc,
            &[99, 104, 101, 99, 107],
            case["principal"].as_str().unwrap(),
        )
        .unwrap();
        let prepared = Prepared::new(
            &policy,
            vec![Candidate {
                commit: "record",
                facts,
            }],
            "check",
        )
        .unwrap();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut clock = Sampling {
            calls: calls.clone(),
            samples: Vec::new(),
            next: 1_767_225_601_000_000,
            step: name == "stepping",
            fail: name == "clock-error",
        };
        let mut judgment = CheckJudgment {
            clock: &mut clock,
            run_inputs: &std::collections::BTreeMap::new(),
            lane: None,
            provider: LaneOnce::new(Source {
                calls: calls.clone(),
                name,
                lane: LaneDefinition {
                    sha256: "lane".into(),
                    tree_sha256: "tree".into(),
                    changed: vec![],
                },
            }),
        };
        let actual: Vec<_> = (0..case["expected"].as_array().unwrap().len())
            .map(|_| {
                judgment
                    .select(&prepared, "check", Levels::Utf8(&[]))
                    .result
                    .inspect_err(|error| {
                        assert_eq!(
                            matches!(
                                error.origin,
                                ErrorOrigin::Exception {
                                    class: "OverflowError"
                                }
                            ),
                            name == "clock-error",
                            "{name}"
                        );
                        if name == "clock-error" {
                            assert_eq!(error.attempts, None);
                        }
                        assert!(serde_json::to_value(error).unwrap().get("origin").is_none());
                    })
                    .map(|_| "satisfied")
                    .unwrap_or_else(|e| e.reason)
            })
            .collect();
        assert_eq!(json!(actual), case["expected"], "{name}");
        assert_eq!(json!(*calls.borrow()), case["calls"], "{name}");
        assert_eq!(json!(clock.samples), case["samples"], "{name}");
    }
}

#[test]
fn system_clock_conversion_is_checked() {
    use super::super::inputs::system_epoch_micros;
    use std::time::{Duration, UNIX_EPOCH};
    for (instant, expected) in [
        (UNIX_EPOCH, 0),
        (UNIX_EPOCH - Duration::from_secs(1), -1_000_000),
        (UNIX_EPOCH - Duration::from_nanos(1), -1),
        (UNIX_EPOCH + Duration::from_nanos(1_999), 1),
        (
            UNIX_EPOCH - Duration::from_secs(62_135_596_800),
            -62_135_596_800_000_000,
        ),
        (
            UNIX_EPOCH + Duration::new(253_402_300_799, 999_999_999),
            253_402_300_799_999_999,
        ),
    ] {
        assert_eq!(system_epoch_micros(instant).unwrap(), expected);
    }
    for instant in [
        UNIX_EPOCH - Duration::new(62_135_596_800, 1),
        UNIX_EPOCH + Duration::from_secs(253_402_300_800),
        UNIX_EPOCH + Duration::from_secs(10_000_000_000_000),
    ] {
        assert_eq!(
            system_epoch_micros(instant).unwrap_err().class,
            "OverflowError"
        );
    }
}
