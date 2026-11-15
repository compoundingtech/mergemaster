use super::*;
use std::{
    io::Write,
    os::{fd::AsRawFd, unix::ffi::OsStringExt},
    process::Command,
};
#[test]
fn subprocess_driver() {
    let Some(root) = std::env::var_os("MM_ADAPTER_DRIVER") else {
        return;
    };
    let root = std::path::Path::new(&root);
    let stdout = std::fs::File::create(root.join("stdout")).unwrap();
    let stderr = std::fs::File::create(root.join("stderr")).unwrap();
    // SAFETY: both source descriptors remain live through process exit.
    assert!(unsafe { libc::dup2(stdout.as_raw_fd(), 1) } >= 0);
    assert!(unsafe { libc::dup2(stderr.as_raw_fd(), 2) } >= 0);
    let argv: Vec<Vec<u8>> =
        serde_json::from_slice(&std::fs::read(root.join("argv")).unwrap()).unwrap();
    let owned: Vec<_> = argv
        .into_iter()
        .map(|v| decode(&std::ffi::OsString::from_vec(v)))
        .collect();
    let argv: Vec<_> = owned.iter().map(|v| v.borrowed()).collect();
    match prepare(&argv, width()).unwrap() {
        Err(exit) => {
            std::io::stdout().write_all(exit.stdout.as_bytes()).unwrap();
            std::io::stderr().write_all(exit.stderr.as_bytes()).unwrap();
            std::process::exit(i32::from(exit.code));
        }
        Ok(parsed) => {
            let values: Vec<Vec<Vec<u32>>> = parsed
                .values
                .iter()
                .map(|v| v.iter().map(|s| s.points().collect()).collect())
                .collect();
            std::io::stdout()
                .write_all(serde_json::to_string(&values).unwrap().as_bytes())
                .unwrap();
            std::process::exit(0);
        }
    }
}
#[test]
fn subprocess_ingress_matches_pinned_parser() {
    let script = r#"
import ast,json,os,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']); p=p/'scripts/evidence-verify' if p.is_dir() else p
v=runpy.run_path(str(p)); m=ast.parse(p.read_text()); f=next(n for n in m.body if isinstance(n,ast.FunctionDef) and n.name=='main')
f.body=f.body[:next(i for i,n in enumerate(f.body) if isinstance(n,ast.Try))]
f.body += [ast.Return(value=ast.Name(id='parser',ctx=ast.Load()))]
exec(compile(ast.fix_missing_locations(ast.Module(body=[f],type_ignores=[])),str(p),'exec'),v)
parser=v['main']([])
cases=[[],['--help'],['--tree'],['--tree','a'*40,'--unknown'],['--tree','a'*40,'--unknown'+chr(0xdcff)],['--tr'],['--tree','a'*40,'--max-age','no'],['--tree','a'*40,'--max-age','9'*4301],['--tree','a'*40,'--revision','HEAD']]
rows=[]
for columns in ['80','20','0','-1','garbage','  +９_０  ']:
 for argv in cases:
  env=dict(os.environ,COLUMNS=columns,NO_COLOR='1'); env.pop('FORCE_COLOR',None)
  done=subprocess.run([sys.executable,str(p),*argv],env=env,capture_output=True)
  # Approved #245 interpolation divergence: only this raw-byte unknown argument needs escaping.
  err=done.stderr.replace(b'--unknown\xff',b'--unknown\\udcff')
  rows.append([columns,[list(os.fsencode(s)) for s in argv],list(done.stdout),list(err),done.returncode])
for argv in [['--tree','a'*40],['--revision','HEAD','--check',chr(0xdcff),'--run-input','x=1','--run-input','x=2','--project']]:
 ns=parser.parse_args(argv); values=[]
 for action in parser._actions:
  value=getattr(ns,action.dest,None)
  if value is None or value is False: items=[]
  elif value is True: items=['']
  elif isinstance(value,list): items=value
  else: items=[value]
  values.append([[ord(c) for c in s] for s in items])
 rows.append(['80',[list(os.fsencode(s)) for s in argv],list(json.dumps(values,separators=(',',':')).encode()),[],0])
print(json.dumps(rows))
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    type OracleRow = (String, Vec<Vec<u8>>, Vec<u8>, Vec<u8>, i32);
    let rows: Vec<OracleRow> = serde_json::from_slice(&output.stdout).unwrap();
    for (columns, argv, stdout, stderr, code) in rows {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("argv"), serde_json::to_vec(&argv).unwrap()).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "evidence::legacy_verify::cli_adapter::tests::subprocess_driver",
                "--nocapture",
            ])
            .env("MM_ADAPTER_DRIVER", root.path())
            .env("COLUMNS", &columns)
            .output()
            .unwrap();
        assert_eq!(status.status.code(), Some(code), "{columns} {argv:?}");
        assert_eq!(
            std::fs::read(root.path().join("stdout")).unwrap(),
            stdout,
            "{columns} {argv:?}"
        );
        assert_eq!(
            std::fs::read(root.path().join("stderr")).unwrap(),
            stderr,
            "{columns} {argv:?}"
        );
    }
}
