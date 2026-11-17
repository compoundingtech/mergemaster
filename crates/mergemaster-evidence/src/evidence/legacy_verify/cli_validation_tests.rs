use super::*;
use serde_json::Value;
#[test]
fn ordered_preflight_matches_actual_main_diagnostics() {
    let script = r#"
import ast,contextlib,io,json,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(sys.argv[1])/'scripts/evidence-verify'; v=runpy.run_path(str(p)); module=ast.parse(p.read_text())
main=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='main')
# Stop at the first post-preflight statement, before any I/O. Earlier bytes are unchanged.
stop=next(i for i,n in enumerate(main.body) if isinstance(n,ast.Assign) and ast.unparse(n.targets[0])=='keyfile')
main.body=main.body[:stop]+[ast.Return(value=ast.Constant(value=0))]
exec(compile(ast.fix_missing_locations(ast.Module(body=[main],type_ignores=[])),str(p),'exec'),v)
base={'check':'x','keys':'keyfile'}
cases=[{}, {'check':None}, {'keys':None}, {'paths':'x'}, {'command':'[]'}, {'command':'[1]'}, {'command':'["x", "\\ud800"]'}, {'command':'['}, {'kinds':''}, {'kinds':'ci'}, {'kinds':',nix,,observed,'}, {'policy_from':''}, {'repository':''}, {'lane_base':''}, {'max_age':'0'}, {'max_age':'-1'}, {'max_age':'1'}, {'prefer_levels':',,'}, {'prefer_levels':'host','members':True}, {'trust_levels':','}, {'bind_input':['=x']}, {'bind_input':['x=']}, {'bind_input':['x=y=z']}, {'require_all':True}, {'require_all':True,'check':None,'policy_from':'','repository':''}, {'project':True,'keys':None,'paths':''}]
# Every pair additionally locks down precedence among independent validation failures.
failures=[{'check':None},{'keys':None},{'paths':'x'},{'command':'null'},{'kinds':'bad'},{'policy_from':'base'},{'repository':'org/repo'},{'lane_base':'base'},{'max_age':'0'},{'prefer_levels':','},{'trust_levels':','},{'bind_input':['bad']}]
cases += [a|b for i,a in enumerate(failures) for b in failures[i+1:]]
results=[]
for change in cases:
 fields=base|change; argv=['--tree','a'*40]
 for k,val in fields.items():
  if val is None or val is False: continue
  flag='--'+k.replace('_','-')
  if val is True: argv.append(flag)
  elif isinstance(val,list):
   for item in val: argv += [flag,item]
  else: argv += [flag,val]
 out=io.StringIO(); err=io.StringIO()
 with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err): code=v['main'](argv)
 assert out.getvalue()==''
 results.append(dict(fields=fields,code=code,stderr=err.getvalue()))
print(json.dumps(results))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    for case in &cases {
        let f = &case["fields"];
        let text = |key: &str| f[key].as_str().map(TextRef::Str);
        let binds: Vec<_> = f["bind_input"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| TextRef::Str(v.as_str().unwrap()))
            .collect();
        let args = Arguments {
            check: text("check"),
            keys: text("keys"),
            command: text("command"),
            kinds: text("kinds"),
            runner_prefix: None,
            trust_levels: text("trust_levels"),
            max_age_positive: f["max_age"].as_str().map(|s| s.parse::<i64>().unwrap() > 0),
            paths: text("paths"),
            bind_input: &binds,
            policy_from: text("policy_from"),
            repository: text("repository"),
            keys_from: None,
            lane_base: text("lane_base"),
            lanes_from: None,
            prefer_levels: text("prefer_levels"),
            require_all: f["require_all"] == true,
            members: f["members"] == true,
            project: f["project"] == true,
        };
        let result = validate(&args);
        assert_eq!(if result.is_ok() { 0 } else { 2 }, case["code"], "{case}");
        assert_eq!(
            result.err().map_or_else(String::new, |s| format!("{s}\n")),
            case["stderr"],
            "{case}"
        );
    }
    assert_eq!(cases.len(), 92);
}
