use super::*;

#[test]
fn signatures_match_python_oracle() {
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); root=pathlib.Path(sys.argv[2]); cases=[]
for fmt in ['sha1','sha256']:
 repo=root/fmt
 subprocess.run(['git','init','--bare','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
 def git(*args,data=None):
  return subprocess.check_output(['git','-C',str(repo),*args],input=data)
 git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
 key=root/(fmt+'-key')
 subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
 public=key.with_suffix('.pub').read_text().strip()
 keys=root/(fmt+'-allowed'); keys.write_text('fixture@example.invalid '+public+'\n')
 revoked=root/(fmt+'-revoked'); revoked.write_text('')
 empty=root/(fmt+'-empty'); empty.write_text('')
 revoking=root/(fmt+'-revoking'); revoking.write_text(public+'\n')
 missing=root/(fmt+'-missing')
 tree=git('mktree',data=b'').decode().strip()
 unsigned=git('commit-tree',tree,data=b'record marker\n').decode().strip()
 signed=git('-c','gpg.format=ssh','-c','gpg.ssh.program=ssh-keygen','-c','user.signingkey='+str(key),'commit-tree','-S',tree,data=b'record marker\n').decode().strip()
 raw=git('cat-file','commit',signed).replace(b'record marker',b'forged marker')
 forged=git('hash-object','-t','commit','-w','--stdin',data=raw).decode().strip()
 # Hostile local executables/format must not override the verifier's fixed SSH path.
 git('config','gpg.format','openpgp'); git('config','gpg.ssh.program','false')
 git('replace',unsigned,signed)
 def add(name,commit,allowed=keys,revocations=revoked):
  try: result=list(o['signature'](str(repo),commit,str(allowed),str(revocations)))
  except o['Failure']: result=None
  cases.append(dict(name=fmt+'-'+name,repo=str(repo),commit=commit,keys=str(allowed),revocations=str(revocations),expected=result))
 add('trusted',signed); add('unsigned-replacement',unsigned); add('forged',forged)
 add('unknown',signed,empty); add('missing-allowed',signed,missing)
 add('revoked',signed,keys,revoking); add('missing-revocations',signed,keys,missing)
 add('missing-commit','f'*len(signed))
 # Principal text is returned verbatim; it is not statement-signer authorization.
 aliases=root/(fmt+'-aliases'); aliases.write_text('one,two '+public+'\n')
 add('aliases',signed,aliases)
print(json.dumps(cases))
"#;
    let oracle = std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap();
    let root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new("python3")
        .args(["-c", script, &oracle])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for case in cases {
        let actual = signature(
            Path::new(case["repo"].as_str().unwrap()),
            case["commit"].as_str().unwrap(),
            case["keys"].as_str().unwrap(),
            case["revocations"].as_str().unwrap(),
        );
        if case["expected"].is_null() {
            assert_eq!(actual.unwrap_err().reason, "error", "{}", case["name"]);
        } else {
            let (status, principal) = actual.unwrap();
            assert_eq!(
                serde_json::json!([status, principal]),
                case["expected"],
                "{}",
                case["name"]
            );
        }
    }
}
