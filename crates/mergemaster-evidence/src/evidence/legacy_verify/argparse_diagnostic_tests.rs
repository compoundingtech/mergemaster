use super::*;
#[test]
fn subprocess_streams_and_exit_match_pinned_python() {
    let script = r#"
import argparse,json,os,pathlib,re,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
oracle=str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify')
base=['--tree','x']; samples=[[],['--help'],['-h'],['-hh'],['-hx'],['-h=foo'],['-h-'],['--help=x'],['--tr'],['--tree'],['--tree','--tr'],['--tree=x','--revision=y'],['--revision=x','--tree=y'],base+['--unknown'],base+['--unknown','--max-age','bad'],base+['--max-age','bad'],base+['--max-age','1'*4301],base+['--project=yes'],base+['--'],base+['foo','bar']]
v=runpy.run_path(oracle); captured=[]; original=argparse.ArgumentParser.parse_args
argparse.ArgumentParser.parse_args=lambda self,argv:captured.append(self)
try: v['main']([])
except AttributeError: pass
finally: argparse.ArgumentParser.parse_args=original
for a in captured[0]._actions:
 flag=a.option_strings[-1]
 samples += [base+[flag+'='],base+[flag+'=x'],base+[flag],base+[flag,'--unknown']]
for group in captured[0]._mutually_exclusive_groups:
 a,b=group._group_actions
 samples += [base+[a.option_strings[-1],'a',b.option_strings[-1],'b'],base+[b.option_strings[-1],'b',a.option_strings[-1],'a']]
samples += [base+['--unknown'+c] for c in ['\x1b[31m\r\x07\x85é','\udc80','\n','\\']]
# Invoke the actual script, intercepting parse_args only after original parsing
# to stop successful namespaces before any Git/preflight operations.
wrapper='''
import argparse,runpy,sys
class Parsed(Exception): pass
p=argparse.ArgumentParser.parse_args
def parse(self,argv):
 p(self,argv)
 raise Parsed()
argparse.ArgumentParser.parse_args=parse
sys.argv=[sys.argv[1]]+sys.argv[2:]
try: runpy.run_path(sys.argv[0],run_name="__main__")
except Parsed: sys.exit(99)
'''
rows=[]
for argv in samples:
 env=dict(os.environ,NO_COLOR='1',TERM='dumb',COLUMNS='80'); env.pop('FORCE_COLOR',None)
 r=subprocess.run([sys.executable,'-c',wrapper,oracle]+argv,env=env,capture_output=True)
 assert r.returncode in (0,2,99),(argv,r.stderr)
 rows.append(dict(argv=[list(map(ord,s)) for s in argv],parsed=r.returncode==99,stdout=list(r.stdout),stderr=list(r.stderr),exit=r.returncode))
 if argv in ([],['--help']):
  colored=dict(env,FORCE_COLOR='1',TERM='xterm'); colored.pop('NO_COLOR')
  c=subprocess.run([sys.executable,'-c',wrapper,oracle]+argv,env=colored,capture_output=True)
  assert b'\x1b[' in c.stdout+c.stderr
  strip=lambda s:re.sub(rb'\x1b\[[0-9;]*m',b'',s)
  assert (strip(c.stdout),strip(c.stderr),c.returncode)==(r.stdout,r.stderr,r.returncode)
assert len(rows)==len(samples)
print(json.dumps(rows))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_PARITY_ORACLE").unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert!(rows.len() > 60);
    for row in rows {
        let argv: Vec<Vec<u32>> = serde_json::from_value(row["argv"].clone()).unwrap();
        let args: Vec<_> = argv.iter().map(|s| TextRef::Points(s)).collect();
        let result = streams(&args, TextRef::Str("evidence-verify"), 78).unwrap();
        if row["parsed"] == true {
            assert!(result.is_none(), "{row}");
            assert!(matches!(parse(&args), Ok(ParseOutcome::Parsed(_))), "{row}");
            continue;
        }
        let result = result.unwrap_or_else(|| panic!("unexpected success: {row}"));
        for (field, text) in [
            ("stdout", result.stdout.text),
            ("stderr", result.stderr.text),
        ] {
            let expected: Vec<u8> = serde_json::from_value(row[field].clone()).unwrap();
            let actual: Vec<u8> = text
                .borrowed()
                .points()
                .flat_map(|p| {
                    char::from_u32(p)
                        .map_or_else(|| format!("\\u{p:04x}"), |c| c.to_string())
                        .into_bytes()
                })
                .collect();
            assert_eq!(actual, expected, "{row}");
        }
        assert_eq!(result.exit, row["exit"].as_i64().unwrap() as i32, "{row}");
    }
}
#[test]
fn manually_constructed_option_indices_return_checked_errors() {
    for error in [
        ParseError::ExpectedArgument(usize::MAX),
        ParseError::Ambiguous(TextRef::Str("--x"), vec![usize::MAX]),
        ParseError::Conflict(0, usize::MAX),
    ] {
        assert!(error.message().is_err());
    }
}
