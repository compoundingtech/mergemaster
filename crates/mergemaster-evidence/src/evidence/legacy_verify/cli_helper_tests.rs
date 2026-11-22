use super::*;

#[test]
fn wave2_helper_usage_and_input_failures_are_distinct() {
    let usage = run([OsString::from("select-part")], &mut &b""[..]).unwrap();
    assert_eq!(usage.code, 2);
    assert!(usage.stdout.is_empty());
    assert!(!usage.stderr.is_empty());
    for mut input in [&b"not JSON"[..], &b"\xff"[..]] {
        let refusal = run(
            ["select-part", "--path", "input.json", "--selector", "key"].map(OsString::from),
            &mut input,
        )
        .unwrap();
        assert_eq!(refusal.code, 3);
        assert!(refusal.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_str(&refusal.stdout).unwrap();
        assert_eq!(value["reason"], "error");
        assert!(value["detail"].as_str().is_some_and(|s| !s.is_empty()));
    }
}

#[test]
fn wave2_recorded_verifier_argv_match_frozen_and_pinned_bytes() {
    let script = r#"
import base64,json,os,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]);fixture=pathlib.Path(sys.argv[2]);manifest=json.loads((fixture/'manifest.json').read_text());recordings={r['id']:r for r in json.loads((fixture/'recordings.json').read_text())['cases']}
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify'
def git(*args,data=None):return subprocess.check_output(['git',*args],input=data,cwd=root,stderr=subprocess.PIPE).strip()
git('init','-q','--object-format=sha1','signed');git('-C','signed','index-pack','--stdin',data=base64.b64decode((fixture/'record.pack.base64').read_bytes()))
signed=manifest['signed_record'];git('-C','signed','update-ref','refs/notes/evidence/'+signed['tree']+'/'+signed['record'],signed['record'])
git('init','-q','--object-format=sha1','workspace')
for name,data in manifest['workspace_files'].items():
 path=root/'workspace'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data.encode())
git('-C','workspace','add','.');tree=git('-C','workspace','write-tree').decode()
raw=f'tree {tree}\nauthor Corpus <corpus@example.invalid> 1700000000 +0000\ncommitter Corpus <corpus@example.invalid> 1700000000 +0000\n\ncorpus\n'.encode()
commit=git('-C','workspace','hash-object','-t','commit','-w','--stdin',data=raw).decode();git('-C','workspace','update-ref','HEAD',commit)
rows=[]
for case in manifest['cases']:
 if case['oracle']!='verifier':continue
 argv=case['argv'].copy()
 for index,arg in enumerate(argv):
  if index and argv[index-1]=='--repo':argv[index]=str(root/arg)
  if index and argv[index-1]=='--keys':argv[index]=str(fixture/arg)
 done=subprocess.run([sys.executable,'-I','-B',str(p),*argv],capture_output=True)
 expected=recordings[case['id']]
 assert (done.stdout,done.stderr,done.returncode)==(base64.b64decode(expected['stdout_base64']),base64.b64decode(expected['stderr_base64']),expected['exit_code']),case['id']
 rows.append([[list(os.fsencode(s)) for s in argv],list(done.stdout),list(done.stderr),done.returncode])
print(json.dumps(rows))
"#;
    let root = tempfile::tempdir().unwrap();
    let fixture = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../../tests/fixtures/oracle/v1");
    let output = crate::pinned_python::command()
        .args(["-B", "-c", script])
        .arg(root.path())
        .arg(fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<super::super::cli_dispatch::tests::Row> =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 4);
    super::super::cli_dispatch::tests::compare(rows, "MM_DISPATCH_ALL");
}
