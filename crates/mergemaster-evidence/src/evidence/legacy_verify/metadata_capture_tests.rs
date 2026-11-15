use super::super::{source_resource::SOURCE_BYTES, toml::Value};
use super::*;
#[test]
fn metadata_capture_bounds_both_readers_and_config_stderr() {
    if let Ok(case) = std::env::var("MM_METADATA_CASE") {
        let size: usize = std::env::var("MM_METADATA_SIZE").unwrap().parse().unwrap();
        let source = TreeSource {
            repo: Path::new("."),
            tree: "HEAD~1",
            no_lazy_fetch: false,
        };
        let result = if case == "members" {
            source
                .expand_members(Some(&Value::Array(vec![Value::String("crates/*".into())])))
                .map(|names| {
                    assert_eq!(names.len(), 1);
                    assert_eq!(names[0].len(), size);
                })
        } else {
            source
                .config_path(INPUTS_PATH)
                .map(|path| assert!(path.is_none()))
        };
        if size > SOURCE_BYTES {
            let error = result.unwrap_err();
            assert_eq!(
                error.resource,
                Some(SourceResource::RawBlob("HEAD~1".into()))
            );
            assert_eq!(error.detail, "HEAD~1 exceeds 1048576 bytes");
            assert_eq!(error.origin, ErrorOrigin::Failure);
            assert_eq!(error.reason, "error");
        } else if case == "stderr" {
            let error = result.unwrap_err();
            assert!(error.resource.is_none());
            assert_eq!(
                error.detail.to_string(),
                format!(
                    "cannot resolve configuration at HEAD~1: {}",
                    "e".repeat(size)
                )
            );
        } else {
            result.unwrap();
        }
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p if p.is_dir() else p.parent.parent
m=runpy.run_path(str(p/'tests/fixtures/fractal/scripts/rust-test-keys'))
shim=pathlib.Path(sys.argv[1]);program=shim/'git'
program.write_text('#!'+sys.executable+'''\nimport os
size=int(os.environ['MM_METADATA_SIZE']);case=os.environ['MM_METADATA_CASE']
if case=='stderr':
 os.write(2,b'e'*size);raise SystemExit(1)
if case!='quiet-config':os.write(2,b'e'*1048577)
os.write(1,b'x'*size)
''');program.chmod(0o700)
os.environ['PATH']=str(shim)
for case in ['config','members','stderr']:
 for size in [1048576,1048577]:
  os.environ.update(MM_METADATA_CASE=case,MM_METADATA_SIZE=str(size))
  if case=='members':
   got=m['expand_members']('.', 'HEAD~1',['crates/*']);assert got==['x'*size]
  elif case=='config':assert m['config_path']('.', 'HEAD~1',m['INPUTS_PATH']) is None
  else:
   try:m['config_path']('.', 'HEAD~1',m['INPUTS_PATH']);assert False
   except m['Failure'] as e:assert str(e)=='cannot resolve configuration at HEAD~1: '+'e'*size
print(json.dumps(str(shim)))
"#;
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shim: String = serde_json::from_slice(&out.stdout).unwrap();
    for case in ["config", "members", "stderr"] {
        for size in [SOURCE_BYTES, SOURCE_BYTES + 1] {
            // Config stdout cases discard noise here; stderr boundaries are exercised separately.
            let driver_case = if case == "config" {
                "quiet-config"
            } else {
                case
            };
            let out = Command::new(std::env::current_exe().unwrap()).args(["--exact", "evidence::legacy_verify::crate_inputs::metadata_capture_tests::metadata_capture_bounds_both_readers_and_config_stderr", "--nocapture"])
                .env("PATH", &shim).env("MM_METADATA_CASE", driver_case).env("MM_METADATA_SIZE",size.to_string()).output().unwrap();
            assert!(
                out.status.success(),
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
#[test]
fn metadata_overflow_does_not_join_descendant_pipe_holders() {
    let root = tempfile::tempdir().unwrap();
    for stream in ["1", "2"] {
        let pid = root.path().join(stream);
        let mut command = Command::new("python3");
        command.args([
            "-c",
            r"
import os,pathlib,subprocess,sys
child=subprocess.Popen([sys.executable,'-c','import signal;signal.alarm(10);signal.pause()'])
pathlib.Path(sys.argv[1]).write_text(str(child.pid))
os.write(int(sys.argv[2]),b'x'*1048577)
",
            pid.to_str().unwrap(),
            stream,
        ]);
        let started = std::time::Instant::now();
        let result = super::super::manifest_capture::metadata(
            &mut command,
            SourceResource::RawBlob("HEAD~1".into()),
            true,
        );
        let elapsed = started.elapsed();
        let pid = std::fs::read_to_string(pid).unwrap();
        assert!(
            Command::new("kill")
                .args(["-KILL", &pid])
                .status()
                .unwrap()
                .success()
        );
        assert!(elapsed < std::time::Duration::from_secs(5));
        let error = result.unwrap_err();
        assert_eq!(
            error.resource,
            Some(SourceResource::RawBlob("HEAD~1".into()))
        );
        assert_eq!(error.detail, "HEAD~1 exceeds 1048576 bytes");
        assert_eq!(error.origin, ErrorOrigin::Failure);
    }
}
