use super::*;
#[test]
fn raw_membership_bounds_and_short_circuits_match_oracle() {
    let script = r#"
import json,pathlib,runpy,subprocess,sys
oracle=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]
for fmt in ['sha1','sha256']:
 repo=pathlib.Path(sys.argv[2])/fmt
 subprocess.run(['git','init','--bare','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
 def git(*args,data=None): return subprocess.check_output(['git','-C',str(repo),*args],input=data)
 def blob(data): return git('hash-object','-w','--stdin',data=data).decode().strip()
 width=40 if fmt=='sha1' else 64; target='0'*width; note='1'*width
 def record(data,name=note,mode='100644'):
  tree=git('mktree',data=(mode+' blob '+blob(data)+'\t'+name+'\n').encode()).decode().strip()
  raw='tree '+tree+'\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\nraw\n'
  return git('hash-object','-t','commit','-w','--stdin',data=raw.encode()).decode().strip()
 def payload(checks): return json.dumps({'predicate':{'observed':{'checks':checks}}}).encode()
 def case(name,commits,refusal=None,check='check'):
  expected=oracle['other_trees_have'](str(repo),commits,target,check)
  cases.append(dict(repo=str(repo),tree=target,commits=commits,check=check,name=fmt+'-'+name,expected=expected,refusal=refusal))
 good=record(payload({'check':None})); false=record(payload({}))
 for name,body in [('object',payload({'check':None})),('array',payload([None,42,{},['check'],'check'])),('string',payload('precheckpost')),
  ('array-nonstrings',payload([True,{'check':1},['check'],0])),('scalar',payload(42)),('missing',b'{}'),('root-type',b'[]'),
  ('malformed',b'{'),('malformed-utf8',b'\xff'),('extra-data',payload({})+b'{}'),('utf16',payload({'check':0}).decode().encode('utf-16'))]:
  case(name,[record(body)])
 case('empty-check-substring',[record(payload(''))],check='')
 case('excluded-requested-tree',[record(payload({'check':0}),target)])
 case('invalid-note-name',[record(payload({'check':0}),'not-an-oid')])
 case('unvalidated-executable-note',[record(payload({'check':0}),mode='100755')])
 case('missing-object-and-malformed-then-match',['f'*width,record(b'{'),good])
 for depth in [256,257]:
  body=payload({'check':0})[:-1]+b',"extra":'+b'['*(depth-1)+b'0'+b']'*(depth-1)+b'}'
  case('depth-'+str(depth),[record(body)],None if depth==256 else 'stale-scan-too-deep')
 for size in [1048576,1048577]:
  data=payload({'check':0}); c=record(data+b' '*(size-len(data)))
  case('size-'+str(size),[c],None if size==1048576 else 'stale-scan-too-large')
  if size==1048577:
   case('match-before-oversize',[good,c])
   case('false-before-oversize',[false,c],'stale-scan-too-large')
 for size in [1048576,1048577]:
  tree_record=record(payload({}),'x'*(size-8-width//2))
  case('tree-size-'+str(size),[tree_record],None if size==1048576 else 'stale-scan-too-large')
  if size==1048577: case('match-before-oversize-tree',[good,tree_record],'stale-scan-too-large')
 case('no-records',[])
 case('no-match',[false])
print(json.dumps(cases))
"#;
    let root = tempfile::tempdir().unwrap();
    let oracle = std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap();
    let output = std::process::Command::new("python3")
        .args(["-c", script, &oracle])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for case in cases.as_array().unwrap() {
        let commits: Vec<_> = case["commits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect();
        let result = other_trees_have(
            Path::new(case["repo"].as_str().unwrap()),
            &commits,
            case["tree"].as_str().unwrap(),
            case["check"].as_str().unwrap(),
        );
        if let Some(reason) = case["refusal"].as_str() {
            assert_eq!(result.unwrap_err().reason, reason, "{}", case["name"]);
        } else {
            assert_eq!(
                result.unwrap(),
                case["expected"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}
#[test]
fn malformed_binary_tree_framing_is_an_error() {
    let tree = "0".repeat(40);
    for body in [b"no nul".as_slice(), b"nospace\0", b"100644 name\0short"] {
        assert_eq!(
            other_blobs(body, &tree, &mut Vec::new())
                .unwrap_err()
                .reason,
            "error"
        );
    }
}
