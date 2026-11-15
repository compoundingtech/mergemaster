use super::*;
use serde_json::{Value, json};
use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
#[test]
fn key_and_log_preparation_match_original_main_and_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let scratch = root.path().join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    let out = crate::pinned_python::command().args(["-c", r#"
import ast,json,os,pathlib,runpy,stat,subprocess,sys,tempfile,types
root=pathlib.Path(sys.argv[1]);tempfile.tempdir=str(root/'scratch');repo=root/'repo';repo.mkdir()
v=runpy.run_path(sys.argv[2]+'/scripts/evidence-verify')
module=ast.parse(pathlib.Path(sys.argv[2]+'/scripts/evidence-verify').read_text())
main=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='main')
body=next(n for n in main.body if isinstance(n,ast.Try) and n.finalbody).body
key=next(n for n in body if isinstance(n,ast.If) and ast.unparse(n.test)=='args.keys_from')
log=[n for n in body if n.lineno in (1615,1616)]
def git(*args):return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
git('init');trees=[]
for layout in ['.st','.fractal']:
 p=repo/layout;p.mkdir(exist_ok=True)
 (p/'evidence-keys').write_bytes(b'keys\x00\xff\n');(p/'evidence-log-key').write_bytes(b'logs\x00\xff\n')
 git('add','.');trees.append(git('write-tree'))
git('read-tree','--empty');empty=git('write-tree')
explicit=root/'explicit'
explicit.write_bytes(b'explicit');raw=os.fsdecode(os.fsencode(root)+b'/raw\xff');open(raw,'wb').write(b'raw')
link=root/'link';link.symlink_to(explicit)
cases=[]
for mode,from_,path in [('keys',None,str(explicit)),('keys',None,str(link)),('keys',None,raw),('keys',None,str(root)),('keys',None,str(root/'missing')),('keys',None,'null\x00path')]+[(m,t,str(explicit)) for m in ['keys','log'] for t in trees+[empty,'missing']]+[('log',None,str(explicit)),('log',None,''),('log',empty,str(root/'not-found'))]:
 args=types.SimpleNamespace(repo=str(repo),keys=path,keys_from=from_,log_keys=path,log_keys_from=from_)
 scope=dict(v,args=args,keyfile=None)
 try:
  exec(compile(ast.Module(body=[key] if mode=='keys' else log,type_ignores=[]),'oracle','exec'),scope)
  name=scope['keys' if mode=='keys' else 'log_keys'];f=scope.get('keyfile') if mode=='keys' else scope.get('logfile')
  expected={'none':True} if name is None else ({'temporary':True,'bytes':list(open(name,'rb').read()),'mode':stat.S_IMODE(os.stat(name).st_mode),'suffix':'.keys' if mode=='keys' else '.log-keys'} if f else {'path':list(os.fsencode(name))})
 except v['Failure'] as e:expected={'class':'Failure','detail':str(e)}
 except Exception as e:expected={'class':type(e).__name__,'detail':str(e)}
 finally:
  for name in ['keyfile','logfile']:
   if scope.get(name):scope[name].close()
 assert not os.listdir(root/'scratch')
 cases.append(dict(mode=mode,base=from_,path=list(os.fsencode(path)),expected=expected,repo=str(repo)))
print(json.dumps(cases))
"#]).arg(root.path()).arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap()).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "evidence::legacy_verify::cli_keys::tests::preparation_driver",
            "--nocapture",
        ])
        .env(
            "MERGEMASTER_KEY_CASES",
            std::str::from_utf8(&out.stdout).unwrap(),
        )
        .env("TMPDIR", &scratch)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
    let file = TemporaryFile::new(".keys").unwrap();
    let path = file.path().to_owned();
    std::fs::remove_file(&path).unwrap();
    let expected = crate::pinned_python::command()
        .args([
            "-c",
            "import os,sys;print(str(FileNotFoundError(2,os.strerror(2),sys.argv[1])))",
        ])
        .arg(&path)
        .output()
        .unwrap();
    assert!(expected.status.success());
    let error = file.close().unwrap_err();
    assert_eq!(
        error.origin,
        crate::evidence::legacy_policy::ErrorOrigin::Exception {
            class: "FileNotFoundError"
        }
    );
    assert_eq!(
        error.detail.to_string(),
        std::str::from_utf8(&expected.stdout).unwrap().trim_end()
    );
}
#[test]
fn preparation_driver() {
    let Ok(cases) = std::env::var("MERGEMASTER_KEY_CASES") else {
        return;
    };
    let cases: Vec<Value> = serde_json::from_str(&cases).unwrap();
    for case in cases {
        let bytes: Vec<u8> = serde_json::from_value(case["path"].clone()).unwrap();
        let path = Path::new(OsStr::from_bytes(&bytes));
        let repo = Path::new(case["repo"].as_str().unwrap());
        let base = case["base"].as_str().map(TextRef::Str);
        let result = if case["mode"] == "keys" {
            signers(repo, path, base).map(Some)
        } else {
            log_keys(repo, Some(path), base)
        };
        let actual = match result {
            Ok(None) => json!({"none":true}),
            Ok(Some(keys)) => {
                let actual = match &keys {
                    Keys::Existing(p) => json!({"path":p.as_os_str().as_bytes()}),
                    Keys::Temporary(f) => {
                        json!({"temporary":true,"bytes":std::fs::read(f.path()).unwrap(),"mode":f.path().metadata().unwrap().permissions().mode() & 0o777,"suffix":if case["mode"]=="keys" {".keys"} else {".log-keys"}})
                    }
                };
                let path = keys.path().to_owned();
                let temporary = matches!(keys, Keys::Temporary(_));
                keys.close().unwrap();
                if temporary {
                    assert!(!path.exists());
                }
                actual
            }
            Err(e) => {
                json!({"class":match e.origin {crate::evidence::legacy_policy::ErrorOrigin::Failure=>"Failure",crate::evidence::legacy_policy::ErrorOrigin::Exception {class}=>class},"detail":e.detail.to_string()})
            }
        };
        assert_eq!(actual, case["expected"], "{case}");
        assert_eq!(
            std::fs::read_dir(std::env::var_os("TMPDIR").unwrap())
                .unwrap()
                .count(),
            0
        );
    }
}
