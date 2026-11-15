use super::*;
use crate::evidence::{
    legacy_policy::{PolicyDocument, normalized_text::NormalizedText},
    legacy_verify::base_input_values::base_input_values,
};
use serde_json::{Value, json};
use std::path::Path;
#[test]
fn borrowed_pairs_and_accepted_base_merge_match_original_main() {
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import ast,json,os,pathlib,runpy,subprocess,sys,types
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify';v=runpy.run_path(str(p));module=ast.parse(p.read_text())
main=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='main')
def run_assignment(n):return isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='run_inputs' for t in n.targets)
body=next(n.body for n in ast.walk(main) if isinstance(n,ast.Try) and any(run_assignment(child) for child in n.body))
i=next(i for i,n in enumerate(body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='run_inputs' for t in n.targets))
code=compile(ast.fix_missing_locations(ast.Module(body=body[i:i+3],type_ignores=[])),'<original run-input main>','exec')
rows=[]
for fmt in ['sha1','sha256']:
 repo=pathlib.Path(sys.argv[1])/fmt;subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
 def git(*a,data=None):return subprocess.check_output(['git','-C',str(repo),*a],input=data).decode().strip()
 blob=git('hash-object','-w','--stdin',data=b'\0\xffbase');tree=git('mktree',data=('100644 blob '+blob+'\tfile\n').encode())
 policy=json.dumps(dict(version=1,checks=dict(check=dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=['run'],base_inputs={'source':'missing',chr(0xd800):'file'}),observed=dict(command=['run'],base_inputs={'source':'file','last':'missing'}))))))
 for with_rules in [False,True]:
  rules=v['policy_rules'](policy,'check','fixture') if with_rules else None
  pairs=[[],['a=one','b=two','a=last'],['source=caller','last=caller','z=keep'],[chr(0xd800)+'=caller','source=caller'],['a=','a=x=y'],['x=\0\n'+chr(0xd800)],['','later=x'],['=value'],['no-equals'],['quote\'"\n\0'+chr(0xd800)],['long'+chr(27)+'x'*10000]]
  for args in pairs:
   env=dict(v,args=types.SimpleNamespace(run_input=args,repo=str(repo),policy_from=tree),rules=rules)
   try:exec(code,env);expected=dict(values=[[list(map(ord,k)),list(map(ord,value))] for k,value in env['run_inputs'].items()])
   except v['Failure'] as e:expected=dict(reason=e.reason,origin='Failure',detail=list(map(ord,str(e))))
   rows.append(dict(repo=str(repo),tree=tree,policy=policy,with_rules=with_rules,args=[list(map(ord,a)) for a in args],expected=expected))
print(json.dumps(rows))
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 44);
    for row in rows {
        let args: Vec<Vec<u32>> = serde_json::from_value(row["args"].clone()).unwrap();
        let normalized: Vec<_> = args
            .iter()
            .map(|p| NormalizedText::from_points(p))
            .collect();
        let rules = PolicyDocument::parse(row["policy"].as_str().unwrap(), "check")
            .unwrap()
            .into_rules("fixture")
            .unwrap();
        for scalar in [false, true] {
            let pairs = args.iter().zip(&normalized).map(|(p, n)| {
                if scalar {
                    n.borrowed()
                } else {
                    TextRef::Points(p)
                }
            });
            let result = RunInputs::parse(pairs);
            let actual = match result {
                Ok(mut inputs) => {
                    let values = base_input_values(
                        Path::new(row["repo"].as_str().unwrap()),
                        TextRef::Str(row["tree"].as_str().unwrap()),
                        row["with_rules"].as_bool().unwrap().then_some(&rules),
                    )
                    .unwrap();
                    inputs.merge_base(&values);
                    for (key, value) in inputs.iter() {
                        assert!(inputs.get_text(key).unwrap().points().eq(value.points()));
                    }
                    json!({"values":inputs.iter().map(|(k,v)|[k.points().collect::<Vec<_>>(),v.points().collect::<Vec<_>>()]).collect::<Vec<_>>()})
                }
                Err(e) => {
                    json!({"origin":"Failure","reason":e.reason,"detail":e.detail.borrowed().points().collect::<Vec<_>>()})
                }
            };
            assert_eq!(actual, row["expected"], "{row}");
        }
    }
}
