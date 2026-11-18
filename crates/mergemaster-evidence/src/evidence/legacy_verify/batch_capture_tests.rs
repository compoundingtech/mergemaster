use super::*;
#[test]
fn raw_frames_bound_retention_and_reap_after_large_discarded_tail() {
    let root = tempfile::tempdir().unwrap();
    let id = "a".repeat(64);
    for (size, keep, status, expected) in [
        (1048576, true, 0, None),
        (1048577, true, 0, Some("stale-scan-too-large")),
        (16777216, false, 0, None),
        (16777216, false, 7, Some("error")),
    ] {
        let pidfile = root.path().join("pid");
        let mut command = crate::pinned_python::command();
        command.stdin(std::process::Stdio::piped());
        command
            .args([
                "-c",
                r#"
import os,sys
open(sys.argv[1],'w').write(str(os.getpid()))
sys.stdin.buffer.read()
i=b'a'*64
os.write(1,i+b' blob 0\n\n')
n=int(sys.argv[2]);os.write(1,i+b' blob '+str(n).encode()+b'\n')
while n:
 c=min(n,65536);os.write(1,b'x'*c);n-=c
os.write(1,b'\n');sys.exit(int(sys.argv[3]))
"#,
            ])
            .arg(&pidfile)
            .arg(size.to_string())
            .arg(status.to_string());
        let mut calls = 0;
        let result = read(&mut command, &[id.clone(), id.clone()], |body| {
            calls += 1;
            assert!(body.len() <= 1048576);
            Ok(keep)
        });
        if let Some(reason) = expected {
            assert_eq!(result.unwrap_err().reason, reason);
        } else {
            result.unwrap();
        }
        assert_eq!(calls, if keep && size == 1048576 { 2 } else { 1 });
        #[cfg(target_os = "linux")]
        {
            let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().parse().unwrap();
            // SAFETY: observation only; the collector must already have reaped this child.
            assert_eq!(
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
                -1
            );
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }
    }
    for length in [128, 129] {
        let mut command = crate::pinned_python::command();
        command.stdin(std::process::Stdio::piped());
        command.args(["-c", "import sys;sys.stdin.read();sys.stdout.write('a'*64+' blob 0'+' '*(int(sys.argv[1])-72)+'\\n\\n')"]).arg(length.to_string());
        let result = read(&mut command, std::slice::from_ref(&id), |_| Ok(true));
        if length == 128 {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err().reason, "stale-scan-header-too-large");
        }
    }
}
