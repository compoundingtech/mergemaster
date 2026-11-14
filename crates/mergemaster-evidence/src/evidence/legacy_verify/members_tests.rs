use super::*;
use serde_json::Value;

#[test]
fn sorted_loop_refusals_match_the_pinned_oracle() {
    // Isolate the oracle's aggregation loop from record selection (which has
    // signed-Git differential fixtures of its own); execute the original body.
    let script = r#"
import ast,json,pathlib,sys,concurrent.futures,threading
source=ast.parse((pathlib.Path(sys.argv[1])/'scripts/evidence-verify').read_text())
node=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='verify_members')
class Failure(Exception):
 def __init__(self,reason,detail='',**extra): self.reason=reason; self.detail=detail; self.extra=extra
out=[]
for count in [1,2,12,13,20]:
 for mode in ['no_key','ordinary','exception']:
  names=[f'crate-{i:02}' for i in reversed(range(count))]
  members={n:None if mode=='no_key' else '1'*40 for n in names}
  def verified(*a):
   if mode=='exception': raise ValueError('conversion')
   raise Failure('no_record','not included in the aggregate')
  env=dict(concurrent=concurrent,threading=threading,Failure=Failure,member_keys=lambda *a:members,zero_test_crates=lambda *a:set(),verified=verified)
  exec(compile(ast.Module(body=[node],type_ignores=[]),'<oracle>','exec'),env)
  try: env['verify_members']('repo','tree','check','keys',None,None,None,None,None,None,None,None,None,None,'base')
  except Failure as e: result=dict(reason=e.reason,detail=e.detail,**e.extra)
  except ValueError as e: result=dict(exception=str(e))
  out.append(dict(names=names,mode=mode,result=result))
print(json.dumps(out))
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
    for case in cases {
        let mode = case["mode"].as_str().unwrap();
        let mut members: Vec<_> = case["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| {
                (
                    n.as_str().unwrap().to_owned(),
                    (mode != "no_key").then(|| "1".repeat(40)),
                    true,
                )
            })
            .collect();
        members.sort_by(|a, b| a.0.cmp(&b.0));
        let mut called = Vec::new();
        let result = collect::<()>(members, |name, _, needs_tests| {
            called.push(name.to_owned());
            assert!(needs_tests);
            Err(if mode == "exception" {
                Failure::exception("ValueError", "conversion")
            } else {
                Failure {
                    reason: "no_record",
                    detail: "not included in the aggregate".into(),
                    attempts: Some(9),
                    origin: ErrorOrigin::Failure,
                }
            })
        });
        match result {
            Err(Refusal::Uncovered(error)) => {
                assert_eq!(error.failure.reason, case["result"]["reason"]);
                assert_eq!(
                    error.failure.detail.borrowed().points().collect::<Vec<_>>(),
                    case["result"]["detail"]
                        .as_str()
                        .unwrap()
                        .chars()
                        .map(u32::from)
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    serde_json::to_value(&error.missing).unwrap(),
                    case["result"]["missing"]
                );
                assert_eq!(
                    error.members,
                    case["result"]["members"].as_u64().unwrap() as usize
                );
                assert_eq!(error.failure.attempts, None);
            }
            Err(Refusal::Verification(error)) => {
                assert_eq!(
                    error.origin,
                    ErrorOrigin::Exception {
                        class: "ValueError"
                    }
                );
                assert_eq!(called, ["crate-00"]);
            }
            Ok(_) => panic!("expected refusal"),
        }
        if mode == "no_key" {
            assert!(called.is_empty());
        }
        if mode == "ordinary" {
            assert!(called.windows(2).all(|w| w[0] < w[1]));
        }
    }
    let pass = collect(
        vec![("a".into(), Some("key".into()), false)],
        |_, _, tests| Ok(tests),
    )
    .unwrap();
    assert_eq!(pass.iter().collect::<Vec<_>>(), [("a", "key", &false)]);
}
