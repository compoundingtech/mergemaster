use super::*;
use serde_json::{Value, json};

#[test]
fn crate_argument_matches_the_pinned_cli_branch_losslessly() {
    let script = r#"
import ast,json,pathlib,re,sys
assert sys.version_info[:3]==(3,14,7)
module=ast.parse(pathlib.Path(sys.argv[1]).read_text())
main=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='main')
branch=next(n for n in ast.walk(main) if isinstance(n,ast.If) and ast.unparse(n.test)=='args.crate_key')
# Execute the real parsing/refusal statements, not policy or Git loading.
body=branch.body[:2]
exec(compile(ast.Module(body=[n for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='OID' for t in n.targets)],type_ignores=[]),'oracle','exec'))
class Failure(Exception):
 def __init__(self,reason,detail): self.reason=reason; super().__init__(detail)
class Args: pass
cases=[]
values=['','x','x=','=0','x==','x='+40*'A','x='+39*'a','x='+41*'a','x='+63*'a','x='+65*'a','x='+40*'g','x='+40*'0'+'\n','x='+40*'a'+'=','x='+40*'a'+'\x00']
for name in ['x','😀','é','\ud800','\udcff','\x00','\n',"'",'"',"'\"\\\t\r",'x'*10000]:
 for key in ['a'*40,'0123456789abcdef'*4,'z'*40]: values.append(name+'='+key)
values += ['\ud800','\x1b[31m',"'\"\\\n",'\u2028','\u0378','😀']
for value in values:
 args=Args(); args.crate_key=value
 try:
  if value:
   exec(compile(ast.Module(body=body,type_ignores=[]),'oracle','exec'))
   expected={'name':list(map(ord,crate)),'key':key}
  else: expected=None
 except Failure as e: expected={'reason':e.reason,'detail':str(e)}
 cases.append({'argument':list(map(ord,value)),'expected':expected})
print(json.dumps(cases))
"#;
    let oracle = std::env::var_os("MERGEMASTER_PYTHON_ORACLE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .join("scripts/evidence-verify");
    let out = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(oracle)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    for case in &cases {
        let points: Vec<u32> = serde_json::from_value(case["argument"].clone()).unwrap();
        let check = |argument| {
            let actual = match parse(argument) {
                Ok(None) => Value::Null,
                Ok(Some(parsed)) => {
                    json!({"name":parsed.name.points().collect::<Vec<_>>(),"key":parsed.key})
                }
                Err(e) => {
                    assert_eq!(e.origin, ErrorOrigin::Failure);
                    assert_eq!(e.attempts, None);
                    json!({"reason":e.reason,"detail":e.detail.to_string()})
                }
            };
            assert_eq!(actual, case["expected"], "{case}");
        };
        check(TextRef::Points(&points));
        if let Some(text) = points
            .iter()
            .copied()
            .map(char::from_u32)
            .collect::<Option<String>>()
        {
            check(TextRef::Str(&text));
            if let Ok(Some(parsed)) = parse(TextRef::Str(&text)) {
                assert!(matches!(parsed.key, Cow::Borrowed(_)));
            }
        }
    }
    assert_eq!(cases.len(), 53);
}
