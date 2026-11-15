use crate::evidence::legacy_verify::cli_discovery::with_note_for;
use serde_json::{Value, json};
use std::path::Path;
#[test]
fn note_presence_matches_oracle_transport_and_header_bounds() {
    if let Ok(file) = std::env::var("MM_NOTE_CASE") {
        let case: Value = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        let commits: Vec<String> = serde_json::from_value(case[1].clone()).unwrap();
        let result = with_note_for(
            Path::new(case[0].as_str().unwrap()),
            &commits,
            case[2].as_str().unwrap(),
        );
        let actual = match result {
            Ok(found) => json!(["ok", found]),
            Err(e) => json!([
                match e.origin {
                    crate::evidence::legacy_policy::ErrorOrigin::Failure => "Failure",
                    crate::evidence::legacy_policy::ErrorOrigin::Exception { class } => class,
                },
                e.reason,
                e.detail.to_string()
            ]),
        };
        assert_eq!(actual, case[3]);
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
m=runpy.run_path(os.environ['MERGEMASTER_PYTHON_ORACLE']+'/scripts/evidence-verify');root=pathlib.Path(sys.argv[1]);exe=sys.argv[2]
def run(repo,commits,tree,over=False):
 try:expected=['ok',m['with_note_for'](repo,commits,tree)]
 except m['Failure'] as e:expected=['Failure',e.reason,e.detail]
 except Exception as e:expected=[type(e).__name__,'error',str(e)]
 if over:
  assert expected[0]=='ok';expected=['Failure','error','note Git header exceeds 138 bytes']
 case=root/'case.json';case.write_text(json.dumps([repo,commits,tree,expected]))
 child=subprocess.run([exe,'--exact','evidence::legacy_verify::projection_capture::notes::tests::note_presence_matches_oracle_transport_and_header_bounds','--nocapture'],env=dict(os.environ,MM_NOTE_CASE=str(case)),capture_output=True)
 assert child.returncode==0,(expected,child.stdout,child.stderr)
for fmt in ['sha1','sha256']:
 repo=str(root/fmt);subprocess.run(['git','init','-q','--bare','--object-format='+fmt,repo],check=True)
 def git(*args,data=None):return subprocess.check_output(['git','-C',repo,*args],input=data).decode().strip()
 tree=git('mktree',data=b'');blob=git('hash-object','-w','--stdin',data=b'note')
 noted=git('mktree',data=('100644 blob '+blob+'\t'+tree+'\n').encode())
 for commits in [[],[noted],[tree],[noted,tree,noted],['f'*len(tree),noted]]:run(repo,commits,tree)
shim=root/'git';payload=root/'payload'
shim.write_text('#!'+sys.executable+'\nimport os,sys\na=sys.argv[1:]\nassert a==["-C","repo","-c","gpg.format=ssh","-c","gpg.ssh.program=ssh-keygen","-c","commit.gpgSign=false","cat-file","--batch-check"]\nassert os.environ["GIT_NO_REPLACE_OBJECTS"]=="1" and os.environ["LC_ALL"]=="C"\nassert os.environ["MM_INHERITED"]=="yes" and os.environ["GIT_NO_LAZY_FETCH"]=="inherited"\nassert sys.stdin.buffer.read()==(os.environ["COMMIT"]+":"+os.environ["TREE"]+"\\n").encode()\nsys.stdout.buffer.write(open('+repr(str(payload))+',"rb").read());sys.stderr.write("fatal\\n");sys.exit(int(os.environ["STATUS"]))\n')
shim.chmod(0o700);os.environ.update(PATH=str(root),MM_INHERITED='yes',GIT_NO_LAZY_FETCH='inherited')
for width in [40,64]:
 c='a'*width;t='b'*width;os.environ.update(COMMIT=c,TREE=t)
 for data,status,over in [((c+':'+t+' missing\n').encode(),0,False),(b'x'*130+b' missing\n',0,True),((c+' blob 0\n').encode(),0,False),(b'\xff\n',0,False),(b'',7,False)]:
  payload.write_bytes(data);os.environ['STATUS']=str(status);run('repo',[c],t,over)
assert len(('a'*64+':'+'b'*64+' missing\n').encode())==138
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
