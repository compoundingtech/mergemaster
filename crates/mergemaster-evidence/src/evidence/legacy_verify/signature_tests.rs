use super::*;

#[test]
fn signatures_match_python_oracle() {
    match std::process::Command::new("/bin/false").status() {
        Ok(status) => assert!(!status.success()),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
    }
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
 add('revoked',signed,keys,revoking)
 add('missing-revocations',signed,keys,missing); cases[-1]['revocation_refusal']=True
 directory=root/(fmt+'-directory'); directory.mkdir()
 unreadable=root/(fmt+'-unreadable'); unreadable.write_text(''); unreadable.chmod(0)
 dangling=root/(fmt+'-dangling'); dangling.symlink_to(missing)
 linked=root/(fmt+'-linked'); linked.symlink_to(revoked)
 for name,path in [('directory',directory),('unreadable',unreadable),('dangling',dangling)]:
  add('revocations-'+name,signed,keys,path); cases[-1]['revocation_refusal']=True
 add('revocations-valid-symlink',signed,keys,linked)
 relative=repo/'local-revocations'; relative.write_text('')
 add('revocations-relative',signed,keys,pathlib.Path('local-revocations'))
 add('missing-commit','f'*len(signed))
 # Principal text is returned verbatim; it is not statement-signer authorization.
 aliases=root/(fmt+'-aliases'); aliases.write_text('one,two '+public+'\n')
 add('aliases',signed,aliases)
 marker=root/(fmt+'-marker'); program=root/(fmt+'-fake-gpg')
 program.write_text('#!/bin/sh\n: > \"'+str(marker)+'\"\nprintf \"[GNUPG:] NEWSIG\\\\n[GNUPG:] GOODSIG 0123456789ABCDEF forged@example.invalid\\\\n[GNUPG:] VALIDSIG '+('A'*40)+' 2026-01-01 1 0 4 0 1 10 00 '+('A'*40)+'\\\\n[GNUPG:] TRUST_FULLY 0 pgp\\\\n\"\n')
 program.chmod(0o700)
 for setting in ['gpg.program','gpg.openpgp.program','gpg.x509.program']:
  git('config',setting,str(program))
 for kind,header in [('pgp','PGP SIGNATURE'),('x509','SIGNED MESSAGE')]:
  raw=git('--no-replace-objects','cat-file','commit',unsigned).replace(b'\n\n',('\ngpgsig -----BEGIN '+header+'-----\n fake\n -----END '+header+'-----\n\n').encode(),1)
  fake=git('hash-object','-t','commit','-w','--stdin',data=raw).decode().strip()
  add('hostile-'+kind,fake)
  cases[-1].update(marker=str(marker),python_invoked=marker.exists())
  marker.unlink(missing_ok=True)
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
        if let Some(marker) = case["marker"].as_str() {
            assert_eq!(
                case["python_invoked"],
                case["expected"][0] == "G",
                "{}",
                case["name"]
            );
            assert!(!Path::new(marker).exists());
        }
        let actual = signature(
            Path::new(case["repo"].as_str().unwrap()),
            case["commit"].as_str().unwrap(),
            case["keys"].as_str().unwrap(),
            case["revocations"].as_str().unwrap(),
        );
        if case["revocation_refusal"] == true {
            let error = actual.unwrap_err();
            assert_eq!(error.reason, "error", "{}", case["name"]);
            assert!(error.detail.contains("revocation"), "{}", case["name"]);
        } else if let Some(marker) = case["marker"].as_str() {
            let (status, _) = actual.unwrap();
            assert_ne!(status, "G", "{}", case["name"]);
            assert!(!Path::new(marker).exists(), "{}", case["name"]);
        } else if case["expected"].is_null() {
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

#[test]
fn missing_revocations_refuse_before_git_or_revision_validation() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    let error = signature(
        root.path(),
        "not-an-oid",
        "unused",
        missing.to_str().unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.reason, "error");
    assert!(error.detail.contains("revocation file is unavailable"));
}
