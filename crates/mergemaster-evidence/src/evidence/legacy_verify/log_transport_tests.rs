use super::*;
use std::os::unix::ffi::OsStringExt;
#[test]
fn no_lazy_matches_real_subprocess_status_bytes_environment_and_exceptions() {
    let fixture = tempfile::tempdir().unwrap();
    let script = r#"
import json,os,pathlib,runpy,stat,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify')); root=pathlib.Path(sys.argv[2]); original=subprocess.run
rows=[]
for case in ['nonzero','success','missing','denied','timeout','nul']:
 d=root/case; d.mkdir(); git=d/'git'
 if case not in ('missing','nul'):
  body='import signal; signal.pause()' if case=='timeout' else 'import json,os,sys; sys.stdout.buffer.write(json.dumps([sys.argv[1:],{k:os.environ.get(k) for k in ["GIT_NO_LAZY_FETCH","GIT_NO_REPLACE_OBJECTS","LC_ALL","MERGEMASTER_PYTHON_PARITY_ORACLE"]}],ensure_ascii=True).encode()); sys.stderr.buffer.write(b"err\\0\\xff"+b"x"*1048577); sys.exit('+('7' if case=='nonzero' else '0')+')'
  git.write_text('#!'+sys.executable+'\n'+body+'\n'); git.chmod(0 if case=='denied' else 0o755)
 args=['a\'"\n',os.fsdecode(b'raw\xff')]; repo=str(root/'repo')
 if case=='nul': args=['null\0arg']
 old=dict(os.environ); os.environ.update(PATH=str(d))
 def run(*a,**kw):
  if case=='timeout': kw['timeout']=0
  return original(*a,**kw)
 subprocess.run=run
 try:
  status,data=v['no_lazy'](repo,*args); expected=dict(status=status,data=list(data))
 except Exception as e: expected=dict(class_name=type(e).__name__,detail=str(e))
 finally: subprocess.run=original; os.environ.clear(); os.environ.update(old)
 rows.append(dict(path=str(d),repo=repo,args=[list(os.fsencode(a)) for a in args],timeout=case=='timeout',**expected))
print(json.dumps(rows))
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_PARITY_ORACLE").unwrap())
        .arg(fixture.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for row in rows {
        let args: Vec<Vec<u8>> = serde_json::from_value(row["args"].clone()).unwrap();
        let args: Vec<_> = args.into_iter().map(std::ffi::OsString::from_vec).collect();
        let args: Vec<_> = args.iter().map(|a| a.as_os_str()).collect();
        let result = read_with(
            Path::new(row["repo"].as_str().unwrap()),
            &args,
            if row["timeout"] == true {
                Duration::ZERO
            } else {
                Duration::from_secs(60)
            },
            Some(OsStr::new(row["path"].as_str().unwrap())),
        );
        match result {
            Ok(out) => {
                assert_eq!(
                    out.status.code().unwrap(),
                    row["status"].as_i64().unwrap() as i32,
                    "{row}"
                );
                let expected: Vec<u8> = serde_json::from_value(row["data"].clone()).unwrap();
                assert_eq!(out.stdout, expected, "{row}");
            }
            Err(error) => {
                let crate::evidence::legacy_policy::ErrorOrigin::Exception { class } = error.origin
                else {
                    panic!("Failure: {row}")
                };
                assert_eq!(class, row["class_name"], "{row}");
                assert_eq!(error.detail.to_string(), row["detail"], "{row}");
            }
        }
    }
}
