use super::run;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
type Row = (Vec<Vec<u8>>, Vec<u8>, u8);

#[test]
fn wave2_a2_record_and_signature_helpers_match_pinned_python_bytes() {
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
v=runpy.run_path(str(pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify'));root=pathlib.Path(sys.argv[1]);rows=[]
key=root/'signer';subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
keys=root/'keys';keys.write_text('agent/fixture '+key.with_suffix('.pub').read_text());wrong=root/'wrong';wrong.write_text('');revocations=root/'revocations';revocations.write_text('');revoked=root/'revoked';revoked.write_text(key.with_suffix('.pub').read_text())
def row(argv,operation):
 try:
  result=operation();code=0
 except v['Failure'] as error:
  result=dict(reason=error.reason,detail=error.detail);code=3
 except Exception as error:
  result=dict(reason='error',detail=type(error).__name__+': '+str(error));code=3
 # read-statement uses Python's default dumps, preserving all dictionary fields
 text=json.dumps(result) if code==0 and argv[0]=='read-statement' else json.dumps(result,indent=2)
 rows.append([list(map(lambda arg:list(os.fsencode(arg)),argv)),list((text+'\n').encode()),code])
for fmt in ['sha1','sha256']:
 repo=root/fmt;repo.mkdir()
 def git(*args,data=None):return subprocess.check_output(['git','-C',str(repo),*args],input=data,stderr=subprocess.PIPE).decode().strip()
 git('init','--object-format='+fmt);git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid');git('config','commit.gpgsign','false');git('config','core.hooksPath','/dev/null');(repo/'source').write_text('source');git('add','.');git('commit','-m','base');base=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
 value=dict(_type=v['STATEMENT_TYPE'],predicateType=v['PREDICATE_TYPE'],subject=[dict(name=base,digest=dict(gitTree=tree))],predicate=dict(schema_version=1,tier='full',change_id='fixture',signer='agent/fixture',observed_at='2026-01-01T00:00:00Z',observed=dict(kind='tests',runner='wrapper',inputs={},checks={'x':dict(command=['true'],exit_code=0,output_sha256='0'*64)})),unknown={'z':[1.5,float('nan'),10**120],'a':'\ud800','\udfff':-0.0})
 def note(blob,mode='100644',path=None,parent=base,sign=False,extra=False):
  oid=git('hash-object','-w','--stdin',data=blob);listing=(mode+' blob '+oid+'\t').encode()+(path if path is not None else tree.encode())+b'\n'
  if extra:listing+=('100644 blob '+oid+'\textra\n').encode()
  nt=git('mktree',data=listing)
  return git(*(['-c','gpg.format=ssh','-c','user.signingkey='+str(key)] if sign else []),'commit-tree',*(['-S'] if sign else []),nt,*(['-p',parent] if parent else []),data=b'note')
 signed=note(json.dumps(value).encode(),sign=True);unsigned=note(json.dumps(value).encode())
 variants=[(signed,None),(signed,tree),(signed,'0'*len(tree)),(unsigned,None),(note(b'not JSON'),None),(note(b'{}'),None),(note(json.dumps(value).encode(),mode='100755'),None),(note(json.dumps(value).encode(),extra=True),None),(note(json.dumps(value).encode(),parent=None),None),(note(json.dumps(value).encode(),path=b'\xff'),None),(note(json.dumps(value).encode('utf-16')),None)]
 bad=dict(value,predicateType='wrong');variants.append((note(json.dumps(bad).encode()),None));variants.append(('f'*len(tree),None))
 raw_ref=b'refs/tags/record-\xff';git('update-ref',raw_ref,signed)
 variants.append((os.fsdecode(raw_ref),None))
 for record,target in variants:
  argv=['read-statement','--repo',str(repo),'--record',record]+(['--tree',target] if target is not None else [])
  row(argv,lambda record=record,target=target:v['load'](str(repo),record,target))
 for record,allowed,revoke in [(signed,keys,revocations),(unsigned,keys,revocations),(signed,wrong,revocations),(signed,keys,revoked),(signed,keys,root/'absent-revocations'),(signed,root/'absent-keys',revocations),('f'*len(tree),keys,revocations)]:
  row(['signature','--repo',str(repo),'--record',record,'--keys',str(allowed),'--revocations',str(revoke)],lambda record=record,allowed=allowed,revoke=revoke:v['signature'](str(repo),record,str(allowed),str(revoke)))
print(json.dumps(rows))
"#;
    let root = tempfile::tempdir().unwrap();
    let output = crate::pinned_python::command()
        .args(["-B", "-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<Row> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 42);
    for (argv, stdout, code) in rows {
        let actual = run(argv.iter().cloned().map(OsString::from_vec), &mut &b""[..]).unwrap();
        assert_eq!(actual.code, code, "{argv:?}");
        assert_eq!(actual.stdout.as_bytes(), stdout, "{argv:?}");
        assert!(actual.stderr.is_empty(), "{argv:?}");
    }
}

#[test]
fn wave2_a2_new_operation_argv_and_envelopes() {
    let identity = run(["tool-identity"].map(OsString::from), &mut &b""[..]).unwrap();
    assert_eq!(identity.code, 0);
    let value: serde_json::Value = serde_json::from_str(&identity.stdout).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 3);
    assert!(value.get("revision").is_none());
    assert_eq!(value["version"], concat!("v", env!("CARGO_PKG_VERSION")));
    let policy = br#"{"version":1,"checks":{"x":{"trust_levels":["agent"],"kinds":{"wrapper":{"command":["{repository}","{check}"]}}}}}"#;
    let rules = run(
        ["policy-rules", "--check", "x", "--repository", "org/repo"].map(OsString::from),
        &mut &policy[..],
    )
    .unwrap();
    assert_eq!(rules.code, 0, "{}", rules.stdout);
    let value: serde_json::Value = serde_json::from_str(&rules.stdout).unwrap();
    assert_eq!(
        value["kinds"]["wrapper"]["command"],
        serde_json::json!(["org/repo", "x"])
    );
    for operation in [
        "verify-tool-pin",
        "policy-rules",
        "read-statement",
        "signature",
    ] {
        let usage = run([OsString::from(operation)], &mut &b""[..]).unwrap();
        assert_eq!(usage.code, 2, "{operation}");
        assert!(usage.stdout.is_empty());
    }
    let invalid = run(
        ["policy-rules", "--check", "x", "--repository", "org/repo"].map(OsString::from),
        &mut &b"{}"[..],
    )
    .unwrap();
    assert_eq!(invalid.code, 3);
    assert!(invalid.stderr.is_empty());
    let error: serde_json::Value = serde_json::from_str(&invalid.stdout).unwrap();
    assert_eq!(error.as_object().unwrap().len(), 2);
    assert_eq!(error["reason"], "error");
}
