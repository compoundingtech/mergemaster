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
 cases[-1]['checked_path']=str(relative)
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
 # Git resolves relative policy paths from the worktree root, not -C's subdirectory.
 git('update-ref','refs/heads/fixture',signed)
 work=root/(fmt+'-work')
 subprocess.run(['git','clone','--quiet','--no-checkout',str(repo),str(work)],check=True)
 nested=work/'nested'; nested.mkdir()
 bare_repo=repo
 for name,top,child in [('root-empty-sub-revoked','',public+'\n'),('root-revoked-sub-empty',public+'\n',''),('root-missing-sub-empty',None,'')]:
  if top is not None: (work/name).write_text(top)
  (nested/name).write_text(child)
  repo=nested
  add(name,signed,keys,pathlib.Path(name))
  cases[-1]['checked_path']=str(work/name)
  if top is None: cases[-1]['revocation_refusal']=True
 repo=work
 ordinary=work/'ordinary'; ordinary.write_text('')
 add('worktree-relative',signed,keys,pathlib.Path('ordinary'))
 cases[-1]['checked_path']=str(ordinary)
 repo=nested
 absolute=work/'absolute'; absolute.write_text(public+'\n')
 add('nested-absolute',signed,keys,absolute)
 cases[-1]['checked_path']=str(absolute)
 repo=bare_repo/'objects'
 bare_policy=bare_repo/'bare-policy'; bare_policy.write_text(public+'\n')
 child_policy=repo/'bare-policy'; child_policy.write_text('')
 add('bare-subdirectory-relative',signed,keys,pathlib.Path('bare-policy'))
 cases[-1]['checked_path']=str(child_policy)
 add('bare-subdirectory-missing',signed,keys,pathlib.Path('missing-bare-policy'))
 cases[-1].update(checked_path=str(repo/'missing-bare-policy'),revocation_refusal=True)
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
        if let Some(expected) = case["checked_path"].as_str() {
            assert_eq!(
                revocation_path(
                    Path::new(case["repo"].as_str().unwrap()),
                    Path::new(case["revocations"].as_str().unwrap())
                )
                .unwrap(),
                Path::new(expected),
                "{}",
                case["name"]
            );
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
            assert!(
                error.detail.to_string().contains("revocation"),
                "{}",
                case["name"]
            );
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
    assert!(
        error
            .detail
            .to_string()
            .contains("revocation file is unavailable")
    );
}
