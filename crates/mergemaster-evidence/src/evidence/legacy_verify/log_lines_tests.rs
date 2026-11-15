use super::*;
use std::process::Command;
#[test]
fn log_lines_matches_real_git_bytes_gc_whitespace_and_oid_shapes() {
    let fixture = tempfile::tempdir().unwrap();
    let script = r#"
import json,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify')); root=pathlib.Path(sys.argv[2]); rows=[]
for fmt in ['sha1','sha256']:
 repo=root/fmt; subprocess.run(['git','init','-q','--object-format='+fmt,str(repo)],check=True)
 def git(*a,data=None): return subprocess.check_output(['git','-C',str(repo),*a],input=data).decode().strip()
 a='a'*40; b='b'*64
 cases=[b'',b'record '+a.encode()+b' check x y z',b'record '+b.encode()+b' check x y z\n',b'record '+a.encode()+b' other x y z',b'record '+a.encode()+b' check x y',b'record '+a.encode()+b' check x y z extra']
 for sep in ['\n','\r','\r\n','\v','\f','\x1c','\x1d','\x1e','\x85','\u2028','\u2029']:
  cases.append(('record '+a+' check x y z'+sep+'gc reset'+sep+'record '+b+' check x y z').encode())
 for ws in [' ','\t','\x1f','\u00a0','\u2003']:
  cases.append(ws.join(['record',a,'check','x','y','z']).encode())
 for id in [a.upper(),a+'a',a[:-1],b+'b','g'*40]: cases.append(('record '+id+' check x y z').encode())
 cases += [('record '+a+' check x y z\ngc\n').encode(),('record '+a+' check x y z\n gc reset\n').encode(),('record '+a+' check x y z\ngc \nrecord '+b+' check x y z\ngc final').encode(),b'\xff\nrecord '+a.encode()+b' check x y z']
 for index,data in enumerate(cases):
  blob=git('hash-object','-w','--stdin',data=data); tree=git('mktree',data=('100644 blob '+blob+'\tlog\n').encode())
  rows.append(dict(repo=str(repo),head=tree,path='log',check='check',expected=sorted(v['log_lines'](str(repo),tree,'log','check'))))
 rows.append(dict(repo=str(repo),head=tree,path='absent',check='check',expected=[]))
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
        let actual = read(
            Path::new(row["repo"].as_str().unwrap()),
            row["head"].as_str().unwrap(),
            row["path"].as_str().unwrap(),
            row["check"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            row["expected"],
            "{row}"
        );
    }
}
