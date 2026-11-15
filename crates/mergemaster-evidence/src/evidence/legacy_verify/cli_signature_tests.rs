use super::*;
use crate::evidence::legacy_policy::ErrorOrigin;
use serde_json::{Value, json};

#[test]
fn signature_argv_environment_and_capture_match_oracle() {
    if let Ok(text) = std::env::var("MM_SIGNATURE_CASE") {
        let case: Value = serde_json::from_str(&std::fs::read_to_string(text).unwrap()).unwrap();
        let commit: Vec<u32> = serde_json::from_value(case[0].clone()).unwrap();
        let result = signature(
            Path::new("repo"),
            TextRef::Points(&commit),
            Path::new("allowed"),
            Path::new("revoked"),
        );
        if case[1] == true {
            let error = result.unwrap_err();
            assert_eq!(
                error.resource,
                Some(SourceResource::RawBlob(NormalizedText::Codepoints(commit)))
            );
            assert_eq!(error.origin, ErrorOrigin::Failure);
            assert_eq!(error.reason, "error");
            assert!(
                error.detail.borrowed().points().eq(case[2]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_u64().unwrap() as u32))
            );
        } else {
            let actual = match result {
                Ok((status, principal)) => json!(["ok", status, principal]),
                Err(error) => json!([
                    match error.origin {
                        ErrorOrigin::Failure => "Failure",
                        ErrorOrigin::Exception { class } => class,
                    },
                    error.reason,
                    error.detail.to_string()
                ]),
            };
            assert_eq!(actual, case[2]);
        }
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
m=runpy.run_path(os.environ['MERGEMASTER_PYTHON_ORACLE']+'/scripts/evidence-verify');root=pathlib.Path(sys.argv[1]);exe=sys.argv[2]
shim=root/'git'
shim.write_text('#!'+sys.executable+'\nimport json,os,sys\na=sys.argv[1:]\nassert a[:10]==["-C","repo","-c","gpg.format=ssh","-c","gpg.ssh.program=ssh-keygen","-c","commit.gpgSign=false","-c","gpg.ssh.allowedSignersFile=allowed"]\nassert a[10:]==["-c","gpg.ssh.revocationFile=revoked","show","-s","--format=%G?%x00%GS",os.environ["SPEC"]]\nassert os.environ["GIT_NO_REPLACE_OBJECTS"]=="1" and os.environ["LC_ALL"]=="C"\nassert os.environ["MM_INHERITED"]=="yes" and os.environ["GIT_NO_LAZY_FETCH"]=="inherited"\nsys.stdout.buffer.write(bytes.fromhex(os.environ["OUTPUT"]));sys.stderr.buffer.write(b"fatal\\n");sys.exit(int(os.environ["STATUS"]))\n')
shim.chmod(0o700);os.environ.update(PATH=str(root),MM_INHERITED='yes',GIT_NO_LAZY_FETCH='inherited')
for spec in ['HEAD',chr(0xdcc3)+chr(0xdca9),'bad\x00spec',chr(0xd800)]:
 for data,status in [(b'\nG\x00principal\n',0),(b'N',0),(b'G\x00a\x00b',0),(b'\xff',0),(b'',7),(b'x'*1048576,0),(b'x'*1048577,0)]:
  # NUL/unencodable env values cannot be installed: their argv encoding fails first.
  if '\x00' not in spec and chr(0xd800) not in spec:os.environ['SPEC']=spec
  os.environ.update(OUTPUT=data.hex(),STATUS=str(status))
  # Keep large payloads out of the environment: the shim reads a fixture file.
  payload=root/'payload';payload.write_bytes(data)
  original=shim.read_text();shim.write_text(original.replace('bytes.fromhex(os.environ["OUTPUT"])','open('+repr(str(payload))+',"rb").read()'));os.environ['OUTPUT']=''
  try:expected=['ok',*m['signature']('repo',spec,'allowed','revoked')]
  except m['Failure'] as e:expected=['Failure',e.reason,e.detail]
  except Exception as e:expected=[type(e).__name__,'error',str(e)]
  resource=len(data)>1048576 and '\x00' not in spec and chr(0xd800) not in spec
  if resource:
   assert expected[0]=='ok';expected=list(map(ord,spec+' exceeds 1048576 bytes'))
  case=[list(map(ord,spec)),resource,expected]
  casefile=root/'case.json';casefile.write_text(json.dumps(case))
  child=subprocess.run([exe,'--exact','evidence::legacy_verify::cli_signature::tests::signature_argv_environment_and_capture_match_oracle','--nocapture'],env=dict(os.environ,MM_SIGNATURE_CASE=str(casefile)),capture_output=True)
  assert child.returncode==0,(spec,len(data),status,expected,child.stdout,child.stderr)
  shim.write_text(original)
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .arg(root.path())
        .arg(std::env::current_exe().unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
