use super::*;
#[test]
fn repository_substitution_preserves_original_codepoints() {
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify'
child='''import json,runpy,sys
v=runpy.run_path(sys.argv[1]); text,repository=json.load(sys.stdin); check='check'
k=v['policy_rules'](text,check,repository)['kinds']['wrapper']
def points(s): return list(map(ord,s))
print(json.dumps([list(map(points,k['command'])),points(k['runner_prefix']),list(map(points,k['by_level']['agent']['command']))],separators=(',',':')))
'''
rows=[]
for repository in ['org/repo','org/é','org/🦀','org/'+chr(0xdcff),'org/'+chr(0xdcc3)+chr(0xdca9),'org/{check}','org/\\\n\x1b', 'x'*10000]:
 for template in ['{repository}:{check}:{repository}','{check}/{repository}','literal']:
  text=json.dumps(dict(version=1,checks={'check':dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=[template,'{repository}'],runner_prefix=template,by_level=dict(agent=dict(command=[template,'{repository}'],events=['pull_request'])))))}))
  done=subprocess.run([sys.executable,'-I','-c',child,str(p)],input=json.dumps([text,repository]).encode(),capture_output=True)
  assert done.returncode==0 and not done.stderr
  rows.append([text,list(map(ord,repository)),list(done.stdout),list(done.stderr),done.returncode])
print(json.dumps(rows))
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    type Row = (String, Vec<u32>, Vec<u8>, Vec<u8>, i32);
    let rows: Vec<Row> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 24);
    for (text, repository, stdout, stderr, code) in rows {
        let evaluate = |repository| {
            let rules = PolicyDocument::parse(&text, "check")
                .unwrap()
                .into_rules(repository)
                .unwrap();
            let kind = &rules.kinds[0].1;
            let points = |s: &NormalizedText| s.borrowed().points().collect::<Vec<_>>();
            let result = (
                kind.inputs.command.iter().map(points).collect::<Vec<_>>(),
                points(kind.runner_prefix.as_ref().unwrap()),
                kind.by_level[0]
                    .1
                    .inputs
                    .command
                    .iter()
                    .map(points)
                    .collect::<Vec<_>>(),
            );
            let mut actual = serde_json::to_vec(&result).unwrap();
            actual.push(b'\n');
            assert_eq!(
                (actual, Vec::<u8>::new(), 0),
                (stdout.clone(), stderr.clone(), code)
            );
        };
        evaluate(TextRef::Points(&repository));
        if let Some(scalar) = repository
            .iter()
            .copied()
            .map(char::from_u32)
            .collect::<Option<String>>()
        {
            evaluate(TextRef::Str(&scalar));
        }
    }
}
