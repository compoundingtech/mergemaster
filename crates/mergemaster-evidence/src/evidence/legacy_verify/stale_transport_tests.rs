use super::*;
#[test]
fn stale_cli_uses_two_complete_oracle_batches_in_order() {
    if let Ok(status) = std::env::var("MM_STALE_STATUS") {
        let result = other_trees_have_cli(
            Path::new("repo"),
            &["a".repeat(64), "b".repeat(64)],
            &"0".repeat(64),
            "check",
        );
        if status == "0" {
            assert!(result.unwrap());
        } else {
            assert_eq!(
                result.unwrap_err().detail.to_string(),
                "git cat-file: fatal"
            );
        }
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
m=runpy.run_path(os.environ['MERGEMASTER_PYTHON_ORACLE']+'/scripts/evidence-verify');root=pathlib.Path(sys.argv[1]);exe=sys.argv[2]
shim=root/'git';counter=root/'counter'
shim.write_text('#!'+sys.executable+'\nimport os,pathlib,sys\np=pathlib.Path('+repr(str(counter))+')\nn=int(p.read_text()) if p.exists() else 0;p.write_text(str(n+1))\nassert sys.argv[1:]==["-C","repo","-c","gpg.format=ssh","-c","gpg.ssh.program=ssh-keygen","-c","commit.gpgSign=false","cat-file","--batch"]\nassert os.environ["LC_ALL"]=="C" and os.environ["GIT_NO_REPLACE_OBJECTS"]=="1"\nassert os.environ["GIT_NO_LAZY_FETCH"]=="inherited" and os.environ["MM_INHERITED"]=="yes"\ndata=sys.stdin.buffer.read()\ndef emit(body):sys.stdout.buffer.write(b"e"*64+b" blob "+str(len(body)).encode()+b"\\n"+body+b"\\n")\nif n==0:\n assert data==b"a"*64+b"^{tree}\\n"+b"b"*64+b"^{tree}\\n"\n for c in [b"c",b"d"]:emit(b"100644 "+b"1"*64+b"\\0"+bytes.fromhex(c.decode()*64))\nelse:\n assert n==1 and data==b"c"*64+b"\\n"+b"d"*64+b"\\n"\n emit(b\'{"predicate":{"observed":{"checks":{"check":0}}}}\');emit(b"x"*1048577)\n sys.stderr.write("fatal\\n");sys.exit(int(os.environ["MM_STALE_STATUS"]))\n')
shim.chmod(0o700);os.environ.update(PATH=str(root),MM_INHERITED='yes',GIT_NO_LAZY_FETCH='inherited')
for status in ['0','7']:
 os.environ['MM_STALE_STATUS']=status
 counter.unlink(missing_ok=True)
 try:expected=m['other_trees_have']('repo',['a'*64,'b'*64],'0'*64,'check')
 except m['Failure'] as e:expected=e.detail
 assert expected==(True if status=='0' else 'git cat-file: fatal'),expected
 assert counter.read_text()=='2';counter.unlink()
 child=subprocess.run([exe,'--exact','evidence::legacy_verify::stale::transport_tests::stale_cli_uses_two_complete_oracle_batches_in_order','--nocapture'],capture_output=True)
 assert child.returncode==0,(child.stdout,child.stderr)
 assert counter.read_text()=='2'
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
