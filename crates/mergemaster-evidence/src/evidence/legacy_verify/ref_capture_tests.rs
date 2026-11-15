use super::*;
use serde_json::{Value, json};
use std::process::Command;
#[test]
fn streamed_refs_match_oracle_without_whole_listing_retention() {
    if let Ok(expected) = std::env::var("MM_REF_EXPECTED") {
        let prefix = format!("refs/tags/evidence/{}/", "a".repeat(40));
        let actual = match refs(Path::new("."), &[prefix]) {
            Ok(found) => json!({"found":found}),
            Err(error) => {
                json!({"reason":error.reason,"detail":error.detail.to_string(),"origin":match error.origin {
                    crate::evidence::legacy_policy::ErrorOrigin::Failure => "Failure",
                    crate::evidence::legacy_policy::ErrorOrigin::Exception {class} => class,
                }})
            }
        };
        assert_eq!(actual, serde_json::from_str::<Value>(&expected).unwrap());
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
with open(os.environ['MM_REF_DATA'],'rb') as f:
 while data:=f.read(65536):sys.stdout.buffer.write(data)
sys.stdout.buffer.flush()
if os.environ.get('MM_REF_STATUS')=='7':sys.stderr.buffer.write(b'fixture failure');sys.exit(7)
''');shim.chmod(0o700)
os.environ['PATH']=str(root)
prefix='refs/tags/evidence/'+'a'*40+'/'
def row(oid):return (oid+' '+prefix+oid).encode()
separators=['\n','\r','\r\n','\v','\f','\x1c','\x1d','\x1e','\x85','\u2028','\u2029']
samples=[(row('b'*40)+sep.encode()+row('c'*64),0) for sep in separators]
samples += [(row('b'*40)+b'\n'+row('b'*40),0),(b'x'*(67108864+1)+b'\n'+row('c'*64),0),(row('b'*40)+b'\n\xff',0),(b'prefix\n\xf1\x80\x80',0),(b'\xff',7),(b'wrong name\n',0)]
results=[]
for n,(data,status) in enumerate(samples):
 path=root/str(n);path.write_bytes(data)
 os.environ.update(MM_REF_DATA=str(path),MM_REF_STATUS=str(status))
 try:expected=dict(found=sorted(m['records_under']('.', [prefix])))
 except m['Failure'] as e:expected=dict(reason=e.reason,detail=e.detail,origin='Failure')
 except UnicodeDecodeError as e:expected=dict(reason='error',detail=str(e),origin='UnicodeDecodeError')
 results.append(dict(path=str(path),status=str(status),expected=expected))
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
    assert_eq!(rows.len(), 17);
    for row in rows {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "evidence::legacy_verify::log_view::ref_capture_tests::streamed_refs_match_oracle_without_whole_listing_retention", "--nocapture"])
            .env("PATH",root.path()).env("MM_REF_DATA",row["path"].as_str().unwrap()).env("MM_REF_STATUS",row["status"].as_str().unwrap())
            .env("MM_REF_EXPECTED",row["expected"].to_string()).output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
