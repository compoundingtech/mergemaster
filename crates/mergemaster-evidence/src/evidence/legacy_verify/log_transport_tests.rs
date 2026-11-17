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
            SourceResource::RawBlob("fixture".into()),
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
#[test]
fn no_lazy_sources_stop_at_limit_with_exact_raw_specs() {
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import hashlib,json,os,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p/'scripts/evidence-verify' if p.is_dir() else p
v=runpy.run_path(str(p));root=pathlib.Path(sys.argv[1]);rows=[]
for fmt in ['sha1','sha256']:
 repo=root/fmt;subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
 def git(*a,data=None):return subprocess.check_output(['git','-C',str(repo),*a],input=data).decode().strip()
 for size in [1048576,1048577]:
  data=b'x'*size;blob=git('hash-object','-w','--stdin',data=data)
  tree=git('mktree',data=('100644 blob '+blob+'\tlog\n100644 blob '+blob+'\té\n').encode());spec=tree+':log'
  code,out=v['no_lazy'](str(repo),'cat-file','blob',spec)
  assert code==0 and out==data and v['log_lines'](str(repo),tree,'log','test')==set()
  assert v['log_lines'](str(repo),tree,'\udcc3\udca9','test')==set()
  rows.append(dict(repo=str(repo),tree=tree,size=size,spec=spec,args=['cat-file','blob',spec],status=code,digest=hashlib.sha256(out).hexdigest()))
for size in [1048576,1048577]:
 for status in [0,7]:
  shim=root/f'shim-{size}-{status}';shim.mkdir();program=shim/'git'
  program.write_text('#!'+sys.executable+f'''
import os,sys
assert sys.argv[3:7]==['-c','gpg.format=ssh','-c','gpg.ssh.program=ssh-keygen']
assert os.environ['GIT_NO_LAZY_FETCH']=='1' and os.environ['GIT_NO_REPLACE_OBJECTS']=='1' and os.environ['LC_ALL']=='C'
os.write(2,b'e'*1048577);os.write(1,b'x'*{size});raise SystemExit({status})
''');program.chmod(0o700);os.environ['PATH']=str(shim)
  for args in [['rev-parse','--verify','HEAD^{commit}'],['show','-s','--format=%G?%x00%GS%x00%s','HEAD']]:
   code,out=v['no_lazy']('.',*args)
   assert code==status and len(out)==size
   rows.append(dict(repo='.',size=size,spec=args[-1],args=args,status=code,digest=hashlib.sha256(out).hexdigest(),shim=str(shim)))
print(json.dumps(rows))
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 12);
    for row in rows {
        let args: Vec<&OsStr> = row["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| OsStr::new(s.as_str().unwrap()))
            .collect();
        let resource = SourceResource::RawBlob(row["spec"].as_str().unwrap().into());
        let result = read_with(
            Path::new(row["repo"].as_str().unwrap()),
            &args,
            Duration::from_secs(60),
            row["shim"].as_str().map(OsStr::new),
            resource.clone(),
        );
        if row["size"] == SOURCE_BYTES {
            use sha2::{Digest, Sha256};
            let out = result.unwrap();
            assert_eq!(
                out.status.code().unwrap(),
                row["status"].as_i64().unwrap() as i32
            );
            assert_eq!(
                format!("{:x}", Sha256::digest(out.stdout)),
                row["digest"].as_str().unwrap()
            );
        } else {
            let error = result.err().unwrap();
            assert_eq!(error.resource, Some(resource.clone()));
            assert_eq!(error.detail, resource.detail());
            assert_eq!(
                error.origin,
                crate::evidence::legacy_policy::ErrorOrigin::Failure
            );
        }
        if let Some(tree) = row["tree"].as_str() {
            let result = super::super::log_lines::read(
                Path::new(row["repo"].as_str().unwrap()),
                tree,
                "log",
                "test",
            );
            if row["size"] == SOURCE_BYTES {
                assert!(result.unwrap().is_empty());
            } else {
                assert_eq!(result.unwrap_err().resource, Some(resource));
            }
            let result = super::super::log_lines::read(
                Path::new(row["repo"].as_str().unwrap()),
                tree,
                super::super::value_inputs::TextRef::Points(&[0xdcc3, 0xdca9]),
                "test",
            );
            if row["size"] == SOURCE_BYTES {
                assert!(result.unwrap().is_empty());
            } else {
                use crate::evidence::legacy_policy::normalized_text::NormalizedText;
                let spec: Vec<u32> = tree
                    .chars()
                    .map(u32::from)
                    .chain([58, 0xdcc3, 0xdca9])
                    .collect();
                let error = result.unwrap_err();
                assert_eq!(
                    error.resource,
                    Some(SourceResource::RawBlob(NormalizedText::Codepoints(
                        spec.clone()
                    )))
                );
                let expected: Vec<u32> = spec
                    .into_iter()
                    .chain(" exceeds 1048576 bytes".chars().map(u32::from))
                    .collect();
                assert!(error.detail.borrowed().points().eq(expected));
            }
        }
    }
}
