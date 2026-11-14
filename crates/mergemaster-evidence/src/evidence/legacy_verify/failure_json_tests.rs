use super::*;
use crate::evidence::{
    legacy_output,
    legacy_policy::{PolicyError, normalized_text::NormalizedText},
};

#[derive(serde::Deserialize)]
struct Fixture {
    check: Vec<u32>,
    reason: Option<Vec<u32>>,
    class: Option<String>,
    detail: Vec<u32>,
    attempts: Option<usize>,
    decided: Option<Vec<u32>>,
    skipped: Option<Vec<Vec<u32>>>,
    wire: String,
}
struct Fault(Option<super::super::inputs::ClockException>);
impl super::super::inputs::CurrentTime for Fault {
    fn epoch_micros(&mut self) -> Result<i64, super::super::inputs::ClockException> {
        Err(self.0.take().unwrap())
    }
}
#[test]
fn lossless_error_views_match_pinned_cli_handler_bytes() {
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
    let output = std::process::Command::new("python3").args(["-c", r#"
import ast,itertools,json,runpy,sys,types
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path)
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
def expression(kind):
 handler=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id==kind)
 return compile(ast.Expression(handler.body[1].value.args[0]),'<pinned-single-error>','eval')
failure_dump=expression('Failure');exception_dump=expression('Exception');cases=[]
names=['unit','','\ud800','\udfff','face😀'];details=['','line\nquote"\\','\ud800','\udfff','face😀','OverflowError: literal']
extras=[{},dict(attempts=0),dict(attempts=2),dict(attempts=2,decided_by='record',skipped_newer=[]),dict(decided_by='record',skipped_newer=['other level_not_accepted','\ud800😀'])]
def points(value): return None if value is None else list(map(ord,value))
for reason,check,detail,extra in itertools.product(['no_record','wrong_check','error','\ud800'],names,details,extras):
 failure=v['Failure'](reason,detail,**extra)
 wire=eval(failure_dump,dict(v,failure=failure,args=types.SimpleNamespace(check=check)))
 cases.append(dict(check=points(check),reason=points(reason),detail=points(detail),attempts=extra.get('attempts'),decided=points(extra.get('decided_by')),skipped=None if 'skipped_newer' not in extra else list(map(points,extra['skipped_newer'])),wire=wire))
for name,check,detail in itertools.product(['OverflowError','ValueError','Échec😀'],names,details):
 error=type(name,(Exception,),{})(detail)
 wire=eval(exception_dump,dict(v,error=error,args=types.SimpleNamespace(check=check)))
 cases.append(dict(check=points(check),class_=name,detail=points(detail),wire=wire))
for case in cases: case['class']=case.pop('class_',None)
print(json.dumps(cases))
"#, &root]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Fixture> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 690);
    let mut bridged = 0;
    for case in cases {
        let failure = super::super::Failure {
            reason: "fixture",
            detail: NormalizedText::Codepoints(case.detail),
            attempts: case.attempts,
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        };
        let policy = PolicyError {
            origin: failure.origin,
            reason: failure.reason,
            detail: failure.detail,
        };
        let skipped = case
            .skipped
            .as_ref()
            .map(|notes| notes.iter().map(|n| TextRef::Points(n)).collect::<Vec<_>>());
        let error = match (&case.reason, &case.class) {
            (Some(reason), None) => WireError::Failure {
                reason: TextRef::Points(reason),
                detail: policy.detail.borrowed(),
                extras: Extras {
                    attempts: case.attempts,
                    decided_by: case.decided.as_deref().map(TextRef::Points),
                    skipped_newer: skipped.as_deref(),
                },
            },
            (None, Some(class)) => WireError::Exception {
                class: TextRef::Str(class),
                detail: policy.detail.borrowed(),
            },
            _ => panic!("fixture provenance"),
        };
        let check = if case.check == [117, 110, 105, 116] {
            "unit".into()
        } else {
            case.check.as_slice().into()
        };
        let mut actual = String::new();
        legacy_output::write(&mut actual, |w| error.write_json(check, w)).unwrap();
        assert_eq!(actual, case.wire);
        let reason = ["no_record", "wrong_check", "error"]
            .into_iter()
            .find(|name| {
                case.reason
                    .as_deref()
                    .is_some_and(|points| points.iter().copied().eq(name.chars().map(u32::from)))
            });
        let class = ["OverflowError", "ValueError", "Échec😀"]
            .into_iter()
            .find(|name| case.class.as_deref() == Some(*name));
        if reason.is_some() || class.is_some() {
            let source = if let Some(class) = class {
                super::super::inputs::sample(&mut Fault(Some(
                    super::super::inputs::ClockException {
                        class,
                        detail: policy.detail,
                    },
                )))
                .unwrap_err()
            } else {
                super::super::Failure {
                    reason: reason.unwrap(),
                    detail: policy.detail,
                    attempts: case.attempts,
                    origin: ErrorOrigin::Failure,
                }
            };
            if class.is_some() {
                assert_eq!(source.attempts, None);
            }
            let mut actual = String::new();
            let view = WireError::from_failure(
                &source,
                case.decided
                    .as_deref()
                    .map(TextRef::Points)
                    .or(class.map(|_| TextRef::Str("ignored"))),
                skipped.as_deref().or(class.map(|_| &[][..])),
            );
            legacy_output::write(&mut actual, |w| view.write_json(check, w)).unwrap();
            assert_eq!(actual, case.wire);
            bridged += 1;
        }
    }
    assert_eq!(bridged, 540);
    let text = String::from("scalar 😀");
    let pointer = text.as_ptr();
    let scalar = NormalizedText::from(text);
    assert!(matches!(&scalar, NormalizedText::Scalar(value) if value.as_ptr() == pointer));
    assert_eq!(
        scalar,
        NormalizedText::Codepoints("scalar 😀".chars().map(u32::from).collect())
    );
    assert_ne!(
        NormalizedText::Codepoints(vec![0xd800]),
        NormalizedText::from("\\ud800")
    );
}
