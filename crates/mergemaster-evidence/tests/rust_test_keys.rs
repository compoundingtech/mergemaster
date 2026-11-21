#[path = "../src/pinned_python.rs"]
mod pinned_python;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
struct Case {
    argv: Vec<String>,
    stdout: String,
    stderr: String,
    code: u8,
    #[serde(default)]
    traceback: bool,
}

#[test]
fn crate_keys_cli_bytes_match_pinned_python() {
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,pathlib,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
root=pathlib.Path(sys.argv[1]); tool=sys.argv[2]; verifier=pathlib.Path(sys.argv[3])/'scripts/evidence-verify'
cases=[]
def record(argv, project=False):
 oracle_argv=argv+(['--verifier',str(verifier)] if project else [])
 done=subprocess.run([sys.executable,'-I',tool,*oracle_argv],capture_output=True,text=True)
 cases.append(dict(argv=argv,stdout=done.stdout,stderr=done.stderr,code=done.returncode,traceback=done.stderr.startswith('Traceback (most recent call last):\n')))
def key(argv): record(argv, project=True)
for algorithm in ['sha1','sha256']:
 repo=root/algorithm; repo.mkdir()
 def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
 def write(path,text):
  p=repo/path; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(text)
 git('init','--object-format='+algorithm)
 write('Cargo.toml','[workspace]\nmembers=["crates/*"]\n[workspace.dependencies]\nb={path="crates/b"}\n[patch.crates-io]\npatched={path="vendor/patched"}\n[package]\nname="root"\n')
 write('crates/a/Cargo.toml','[package]\nname="a"\n[dependencies]\nb={workspace=true}\n[dev-dependencies]\nhelper={path="../../helper"}\n[target.\'cfg(unix)\'.build-dependencies]\nb={path="../b"}\n')
 write('crates/b/Cargo.toml','[package]\nname="b"\n')
 write('helper/Cargo.toml','[package]\nname="helper"\n[dev-dependencies]\na={path="../crates/a"}\n')
 for path in ['src/lib.rs','crates/a/src/lib.rs','crates/b/src/lib.rs','helper/src/lib.rs','vendor/patched/src/lib.rs','extra/é.txt']:
  write(path,'// source\n')
 write('.st/rust-test-inputs.json',json.dumps({'global':['Cargo.toml','absent'],'crates':{'a':{'extra':['extra/é.txt']},'b':{'extra':[]},'root':{'extra':[]}}}))
 git('add','.'); base=git('write-tree')
 write('.fractal/rust-test-inputs.json',json.dumps({'global':[],'crates':{}}))
 write('extra/é.txt','candidate\n'); git('add','.'); tree=git('write-tree')
 common=['--repo',str(repo),'--tree',tree]
 for selected in [[],['--inputs-from',base],['--inputs-from',base,'--crate','a'],['--inputs-from',base,'--crate','root','--crate','b','--crate','b'],['--crate','missing','--crate','other'],['--inputs-from','absent']]:
  for output in [[],['--json'],['--paths'],['--json','--paths']]: key(common+selected+output)
 key(common+['--tree','absent'])
 key(['--repo='+str(repo),'--tree='+tree,'--inputs-from='+base,'--cra=a','--j','--paths'])
 for value in ['-','-1.5','-not a tree','tree with space','-x']: key(common+['--tree',value])
 key(['--repo',str(repo),'--tree',tree,'--i',base,'--cr','a','--j','--p'])
 # Root packages key their source paths, never the whole repository implicitly.
 write('Cargo.toml','[package]\nname="empty"\n'); write('.fractal/rust-test-inputs.json',json.dumps({'crates':{'empty':{'extra':[]}}}))
 git('add','.'); empty=git('write-tree')
 # Existing src is removed from the index only; key computation never reads worktree files.
 git('rm','--cached','src/lib.rs'); empty=git('write-tree')
 for output in [[],['--json'],['--paths'],['--json','--paths']]: key(['--repo',str(repo),'--tree',empty]+output)
 write('Cargo.toml','[workspace]\nmembers=1\n'); git('add','.'); malformed=git('write-tree')
 key(['--repo',str(repo),'--tree',malformed])
 # The loaded verifier's Failure is distinct from the key script's Failure.
 write('Cargo.toml','[package]\nname="a"\n')
 write('.fractal/rust-test-inputs.json',json.dumps({'crates':{'a':{'extra':['bad.json::foo']}}}))
 for content in [b'\xff',b'not JSON']:
  (repo/'bad.json').write_bytes(content); git('add','.'); selected=git('write-tree')
  key(['--repo',str(repo),'--tree',selected])
  assert cases[-1]['code']==1 and cases[-1]['stderr'].splitlines()[-1].startswith('evidence_verify_for_rust_test_keys.Failure: ')
 write('.fractal/rust-test-inputs.json',json.dumps({'crates':{'a':{'extra':['missing.json::foo']}}}))
 git('add','.'); selected=git('write-tree')
 key(['--repo',str(repo),'--tree',selected])
for argv in [['--help'],['-h'],['--unknown'],['--repo'],['--tree','--json'],['--crate'],['--paths=yes'],['--json='],['--help=x'],['--'],['positional'],['--wat','--help'],['--crate','-1'],['--repo','--'],['--tree=absent'],['-hh'],['-h','--json'],['--json','-h'],['--json=1']]: record(argv)
# Explicit native contract: arbitrary Python projection modules cannot be selected.
for option in ['--verifier','--v']:
 cases.append(dict(argv=[option,str(root/'nonexistent-verifier')],stdout='',stderr='rust-test-keys: --verifier is not supported; the projection is built into mergemaster\n',code=2))
print(json.dumps(cases))
"#;
    let output = pinned_python::command()
        .args(["-c", script])
        .arg(root.path())
        .arg(pinned_python::keys_oracle())
        .arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Case> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 101);
    for case in cases {
        let actual = Command::new(env!("CARGO_BIN_EXE_mergemaster"))
            .arg("legacy-rust-test-keys")
            .args(&case.argv)
            .output()
            .unwrap();
        if case.traceback {
            assert_eq!(actual.status.code(), Some(i32::from(case.code)));
            assert_eq!(actual.stdout, case.stdout.as_bytes());
            let stderr = std::str::from_utf8(&actual.stderr).unwrap();
            assert!(stderr.starts_with("Traceback (most recent call last):\n"));
            assert_eq!(stderr.lines().last(), case.stderr.lines().last());
            continue;
        }
        assert_eq!(
            (actual.status.code(), actual.stdout, actual.stderr),
            (
                Some(i32::from(case.code)),
                case.stdout.into_bytes(),
                case.stderr.into_bytes()
            ),
            "argv={:?}",
            case.argv
        );
    }
}
