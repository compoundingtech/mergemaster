use super::*;
use std::{
    io::Write,
    os::{
        fd::AsRawFd,
        unix::ffi::{OsStrExt, OsStringExt},
    },
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
    if std::env::var_os("MM_DISPATCH_ALL").is_some() {
        let exit =
            super::super::cli_dispatch::run(argv.into_iter().map(std::ffi::OsString::from_vec))
                .unwrap();
        std::io::stdout().write_all(exit.stdout.as_bytes()).unwrap();
        std::io::stderr().write_all(exit.stderr.as_bytes()).unwrap();
        std::process::exit(i32::from(exit.code));
    }
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
            if std::env::var_os("MM_PREFLIGHT_ONLY").is_some() {
                match parsed.preflight() {
                    Ok(()) => std::process::exit(0),
                    Err(message) => {
                        writeln!(std::io::stderr(), "{message}").unwrap();
                        std::process::exit(2);
                    }
                }
            }
            if std::env::var_os("MM_TREE_ONLY").is_some()
                || std::env::var_os("MM_PROJECT_ONLY").is_some()
                || std::env::var_os("MM_REQUIRED_ONLY").is_some()
                || std::env::var_os("MM_ORDINARY_ONLY").is_some()
            {
                use super::super::{binding_path::encode, cli_dispatch};
                if let Err(message) = parsed.preflight() {
                    writeln!(std::io::stderr(), "{message}").unwrap();
                    std::process::exit(2);
                }
                let bytes = encode(parsed.value("--repo").unwrap(), 0, true).unwrap();
                let repo = std::path::Path::new(std::ffi::OsStr::from_bytes(&bytes));
                let exit = match cli_dispatch::resolve_tree(repo, &parsed) {
                    Ok(tree) if std::env::var_os("MM_ORDINARY_ONLY").is_some() => {
                        let options = super::super::cli_options::Options::read(&parsed).unwrap();
                        match super::super::cli_ordinary::verify(
                            repo,
                            &tree,
                            &parsed,
                            options,
                            |outcome| {
                                let mut stdout = String::new();
                                outcome
                                    .write(&tree, cli_dispatch::check(&parsed), &mut stdout)
                                    .unwrap()
                                    .unwrap();
                                stdout.push('\n');
                                Exit {
                                    stdout,
                                    stderr: String::new(),
                                    code: u8::from(!outcome.satisfied()),
                                }
                            },
                        ) {
                            Ok(exit) => exit,
                            Err(error) => cli_dispatch::refusal(&parsed, &error).unwrap(),
                        }
                    }
                    Ok(tree) if std::env::var_os("MM_REQUIRED_ONLY").is_some() => {
                        match cli_dispatch::required(repo, &tree, &parsed, |result| {
                            let code = u8::from(
                                result.decision == super::super::require_all::Decision::Reject,
                            );
                            let mut stdout = String::new();
                            crate::evidence::legacy_output::write(&mut stdout, |w| {
                                result.write_json(w)
                            })
                            .unwrap();
                            stdout.push('\n');
                            Exit {
                                stdout,
                                stderr: String::new(),
                                code,
                            }
                        }) {
                            Ok(exit) => exit,
                            Err(error) => cli_dispatch::refusal(&parsed, &error).unwrap(),
                        }
                    }
                    Ok(tree) => {
                        match cli_dispatch::project(repo, &tree, &parsed, |project| {
                            let mut stdout = String::new();
                            crate::evidence::legacy_output::write(&mut stdout, |w| {
                                project.write_json(w)
                            })
                            .unwrap();
                            stdout.push('\n');
                            Exit {
                                stdout,
                                stderr: String::new(),
                                code: 0,
                            }
                        }) {
                            Ok(exit) => exit,
                            Err(error) => cli_dispatch::refusal(&parsed, &error).unwrap(),
                        }
                    }
                    Err(error) => cli_dispatch::refusal(&parsed, &error).unwrap(),
                };
                std::io::stdout().write_all(exit.stdout.as_bytes()).unwrap();
                std::io::stderr().write_all(exit.stderr.as_bytes()).unwrap();
                std::process::exit(i32::from(exit.code));
            }
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
  done=subprocess.run([sys.executable,'-I',str(p),*argv],env=env,capture_output=True)
  # Resolved #245 raw-byte interpolation contract: pinned Python and Rust escape alike.
  rows.append([columns,[list(os.fsencode(s)) for s in argv],list(done.stdout),list(done.stderr),done.returncode])
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
    let output = crate::pinned_python::command()
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
#[test]
fn ordered_preflight_subprocess_matches_pinned_main() {
    let script = r#"
import ast,json,os,pathlib,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
source="""import ast,os,pathlib,runpy,sys
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p/'scripts/evidence-verify' if p.is_dir() else p
v=runpy.run_path(str(p));m=ast.parse(p.read_text());f=next(n for n in m.body if isinstance(n,ast.FunctionDef) and n.name=='main')
f.body=f.body[:next(i for i,n in enumerate(f.body) if isinstance(n,ast.Assign) and ast.unparse(n.targets[0])=='keyfile')]+[ast.Return(value=ast.Constant(value=0))]
exec(compile(ast.fix_missing_locations(ast.Module(body=[f],type_ignores=[])),str(p),'exec'),v)
sys.argv[0]='evidence-verify';sys.exit(v['main'](sys.argv[1:]))
"""
base=['--tree','a'*40,'--check','x','--keys','keyfile']
variants=[[],['--command','[]'],['--command','[1]'],['--kinds',chr(0xdcff)],['--kinds',',nix,,observed,'],['--trust-levels',chr(0xdcff)],['--trust-levels',','],['--prefer-levels',chr(0xdcff)],['--prefer-levels',chr(0xdcff),'--members'],['--policy-from',''],['--lane-base',''],['--max-age','0'],['--max-age','9'*4300],['--bind-input','=x'],['--bind-input','x='],['--bind-input','x=y=z'],['--require-all']]
variants += [a+b for i,a in enumerate(variants[1:]) for b in variants[i+2:]]
rows=[]
for extra in variants:
 argv=base+extra;env=dict(os.environ,NO_COLOR='1');env.pop('FORCE_COLOR',None)
 done=subprocess.run([sys.executable,'-I','-c',source,*argv],capture_output=True,env=env)
 rows.append([[list(os.fsencode(s)) for s in argv],list(done.stdout),list(done.stderr),done.returncode])
print(json.dumps(rows))
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    type OracleRow = (Vec<Vec<u8>>, Vec<u8>, Vec<u8>, i32);
    let rows: Vec<OracleRow> = serde_json::from_slice(&output.stdout).unwrap();
    for (argv, stdout, stderr, code) in rows {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("argv"), serde_json::to_vec(&argv).unwrap()).unwrap();
        let done = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "evidence::legacy_verify::cli_adapter::tests::subprocess_driver",
                "--nocapture",
            ])
            .env("MM_ADAPTER_DRIVER", root.path())
            .env("MM_PREFLIGHT_ONLY", "1")
            .output()
            .unwrap();
        assert_eq!(done.status.code(), Some(code), "{argv:?}");
        assert_eq!(
            std::fs::read(root.path().join("stdout")).unwrap(),
            stdout,
            "{argv:?}"
        );
        assert_eq!(
            std::fs::read(root.path().join("stderr")).unwrap(),
            stderr,
            "{argv:?}"
        );
    }
}

#[test]
fn capture_raw_unknown_argument_divergence() {
    if std::env::var_os("MERGEMASTER_WITNESS_DIRECTORY").is_none() {
        return;
    }
    let script = r#"
import json, os, pathlib, subprocess, sys
p = pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']) / 'scripts/evidence-verify'
env = dict(os.environ, COLUMNS='80', NO_COLOR='1'); env.pop('FORCE_COLOR', None)
done = subprocess.run([sys.executable, '-I', str(p), '--tree', 'a'*40, b'--unknown\xff'], env=env, capture_output=True)
print(json.dumps(dict(stdout=list(done.stdout), stderr=list(done.stderr), exit_code=done.returncode)))
"#;
    let oracle = crate::pinned_python::command()
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(oracle.status.success(), "{:?}", oracle.stderr);
    let python: serde_json::Value = serde_json::from_slice(&oracle.stdout).unwrap();
    let argv = vec![
        b"--tree".to_vec(),
        vec![b'a'; 40],
        b"--unknown\xff".to_vec(),
    ];
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("argv"), serde_json::to_vec(&argv).unwrap()).unwrap();
    let done = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "evidence::legacy_verify::cli_adapter::tests::subprocess_driver",
            "--nocapture",
        ])
        .env("MM_ADAPTER_DRIVER", root.path())
        .env("COLUMNS", "80")
        .output()
        .unwrap();
    let rust = serde_json::json!({
        "stdout": std::fs::read(root.path().join("stdout")).unwrap(),
        "stderr": std::fs::read(root.path().join("stderr")).unwrap(),
        "exit_code": done.status.code()
    });
    super::super::divergence_witnesses::capture(
        "cli-raw-byte-unknown-argument",
        serde_json::json!({"argv_bytes": argv, "columns": "80"}),
        python,
        rust,
    );
}
