use super::*;
use serde_json::{Value, json};
use std::process::Command;
#[test]
fn streamed_refs_match_oracle_without_whole_listing_retention() {
    if let Ok(expected) = std::env::var("MM_REF_EXPECTED") {
        let expected: Value = serde_json::from_str(&expected).unwrap();
        let prefix = expected["prefix"].as_str().unwrap().to_owned();
        for cli in [false, true] {
            let result = if !cli {
                refs(Path::new("."), std::slice::from_ref(&prefix))
                    .map(|ids| ids.into_iter().collect::<Vec<_>>())
            } else if expected["legacy"] == true {
                super::super::cli_discovery::legacy_refs(Path::new("."), 40)
            } else {
                super::super::cli_discovery::records_under(
                    Path::new("."),
                    &[prefix.clone(), prefix.clone()],
                )
            };
            let actual = match result {
                Ok(found) => json!({"found":found}),
                Err(error) => {
                    json!({"reason":error.reason,"detail":error.detail.to_string(),"origin":match error.origin {
                        crate::evidence::legacy_policy::ErrorOrigin::Failure => "Failure",
                        crate::evidence::legacy_policy::ErrorOrigin::Exception {class} => class,
                    }})
                }
            };
            assert_eq!(actual, expected[if cli { "cli" } else { "log" }]);
        }
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,os,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p if p.is_dir() else p.parent.parent
m=runpy.run_path(str(p/'scripts/evidence-verify'))
root=pathlib.Path(sys.argv[1]);shim=root/'git'
shim.write_text('#!'+sys.executable+'''\nimport os,sys
assert sys.argv[1:-1]==['-C','.','-c','gpg.format=ssh','-c','gpg.ssh.program=ssh-keygen','-c','commit.gpgSign=false','for-each-ref','--format=%(objectname) %(refname)']
assert sys.argv[-1] in [os.environ['MM_REF_PATTERN'],os.environ['MM_REF_PREFIX'].rstrip('/')]
with open(os.environ['MM_REF_DATA'],'rb') as f:
 while data:=f.read(65536):sys.stdout.buffer.write(data)
sys.stdout.buffer.flush()
if os.environ.get('MM_REF_STATUS')=='7':sys.stderr.buffer.write(b'fixture failure');sys.exit(7)
''');shim.chmod(0o700)
os.environ['PATH']=str(root)
prefix='refs/tags/evidence/'+'a'*40+'/'
def row(oid,prefix=prefix):return (oid+' '+prefix+oid).encode()
separators=['\n','\r','\r\n','\v','\f','\x1c','\x1d','\x1e','\x85','\u2028','\u2029']
samples=[(row('b'*40)+sep.encode()+row('c'*64),0) for sep in separators]
samples += [(row('b'*40)+b'\n'+row('b'*40),0),(b'x'*(67108864+1)+b'\n'+row('c'*64),0),(row('b'*40)+b'\n\xff',0),(b'prefix\n\xf1\x80\x80',0),(b'\xff',7),(b'wrong name\n',0)]
samples += [(row('c'*64)+b'\n'+row('b'*40)+b'\n'+row('c'*64),0)]
cases=[(prefix,data,status,False) for data,status in samples]
old='refs/notes/evidence/'
cases += [(old,row('c'*40,old)+b'\n'+row('b'*40,old),0,True),(old,row('d'*64,old),0,True)]
results=[]
for n,(prefix,data,status,legacy) in enumerate(cases):
 path=root/str(n);path.write_bytes(data)
 pattern=prefix+'?'*40 if legacy else prefix.rstrip('/')
 os.environ.update(MM_REF_DATA=str(path),MM_REF_STATUS=str(status),MM_REF_PATTERN=pattern,MM_REF_PREFIX=prefix)
 try:
  found=m['legacy_refs']('.',40) if legacy else m['records_under']('.', [prefix,prefix])
  expected=dict(log=dict(found=sorted(found)),cli=dict(found=found))
 except m['Failure'] as e:expected=dict(log=dict(reason=e.reason,detail=e.detail,origin='Failure'));expected['cli']=expected['log']
 except UnicodeDecodeError as e:expected=dict(log=dict(reason='error',detail=str(e),origin='UnicodeDecodeError'));expected['cli']=expected['log']
 expected.update(prefix=prefix,legacy=legacy)
 results.append(dict(path=str(path),status=str(status),pattern=pattern,prefix=prefix,expected=expected))
print(json.dumps(results))
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
    assert_eq!(rows.len(), 20);
    for row in rows {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "evidence::legacy_verify::log_view::ref_capture_tests::streamed_refs_match_oracle_without_whole_listing_retention", "--nocapture"])
            .env("PATH",root.path()).env("MM_REF_DATA",row["path"].as_str().unwrap()).env("MM_REF_STATUS",row["status"].as_str().unwrap())
            .env("MM_REF_PATTERN", row["pattern"].as_str().unwrap()).env("MM_REF_PREFIX", row["prefix"].as_str().unwrap())
            .env("MM_REF_EXPECTED",row["expected"].to_string()).output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
