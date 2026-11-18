use super::*;
use crate::evidence::legacy_policy::normalized_text::NormalizedText;
use serde_json::{Value, json};
#[test]
fn per_value_escaping_matches_pinned_repr_without_truncation() {
    let script = r#"
import json,sys
assert sys.version_info[:3]==(3,14,7)
def escape(s): return ''.join(repr(c)[1:-1] if ord(c)<32 or 127<=ord(c)<=159 or 0xd800<=ord(c)<=0xdfff or c=='\\' else c for c in s)
samples=[''.join(map(chr,range(256))),''.join(map(chr,range(0xd800,0xe000))),"quotes'\"é🦀\\n",'\0\\\n\ud800'*5000]
print(json.dumps([dict(points=list(map(ord,s)),expected=escape(s)) for s in samples]))
"#;
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    for row in rows {
        let points: Vec<u32> = serde_json::from_value(row["points"].clone()).unwrap();
        let mut actual = String::new();
        value(TextRef::Points(&points), &mut actual).unwrap();
        assert_eq!(actual, row["expected"].as_str().unwrap());
    }
}
#[test]
fn safe_argparse_streams_escape_values_but_preserve_structural_newlines() {
    let script = r#"
import argparse,contextlib,io,json,runpy,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); captured=[]; original=argparse.ArgumentParser.parse_args
argparse.ArgumentParser.parse_args=lambda self,argv:captured.append(self)
try: v['main']([])
except AttributeError: pass
finally: argparse.ArgumentParser.parse_args=original
p=captured[0]; p.color=False
p._get_formatter=lambda:argparse.HelpFormatter(prog=p.prog,width=78)
def escape(s): return ''.join(repr(c)[1:-1] if ord(c)<32 or 127<=ord(c)<=159 or 0xd800<=ord(c)<=0xdfff or c=='\\' else c for c in s)
rows=[]
for prog in ['PROG-END','PROG\n\t\x1b[31m\r\x07\x7f\x85\ud800\\END']:
 p.prog=prog
 for mode in ['help','missing','unknown','integer','explicit']:
  arg='--unknown-\n\t\x1b\x85\udcff\\END'; bad='bad\n\t\x1b\ud800\\END'
  argv={'help':['--help'],'missing':[],'unknown':['--tree','x',arg],'integer':['--tree','x','--max-age',bad],'explicit':['--help='+bad]}[mode]
  out=io.StringIO(); err=io.StringIO()
  with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
   try: p.parse_args(argv); raise AssertionError('expected exit')
   except SystemExit as e: code=e.code
  replacements=[(prog,escape(prog))]
  if mode=='unknown': replacements.append((arg,escape(arg)))
  if mode=='integer':
   diagnostic='invalid int value: '+repr(bad); replacements.append((diagnostic,escape(diagnostic)))
  if mode=='explicit': replacements.append((repr(bad),escape(repr(bad))))
  streams=[]
  for text in [out.getvalue(),err.getvalue()]:
   for raw,safe in replacements: text=text.replace(raw,safe)
   streams.append(text)
  rows.append(dict(prog=list(map(ord,prog)),argv=[list(map(ord,a)) for a in argv],stdout=streams[0],stderr=streams[1],exit=code))
print(json.dumps(rows))
"#;
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows.len(), 10);
    for row in rows {
        let prog: Vec<u32> = serde_json::from_value(row["prog"].clone()).unwrap();
        let argv: Vec<Vec<u32>> = serde_json::from_value(row["argv"].clone()).unwrap();
        let argv: Vec<_> = argv.iter().map(|s| TextRef::Points(s)).collect();
        let result = super::super::argparse_diagnostic::streams(&argv, TextRef::Points(&prog), 78)
            .unwrap()
            .unwrap();
        for (name, rendered) in [("stdout", result.stdout), ("stderr", result.stderr)] {
            let original = rendered.text.clone();
            let mut actual = String::new();
            rendered.write_terminal(&mut actual).unwrap();
            assert_eq!(actual, row[name].as_str().unwrap(), "{row}");
            assert_eq!(rendered.text, original);
            assert!(
                !actual
                    .chars()
                    .any(|c| c != '\n' && (c < ' ' || ('\u{7f}'..='\u{9f}').contains(&c)))
            );
        }
        assert_eq!(json!(result.exit), row["exit"]);
    }
}
#[test]
fn caller_constructed_sink_inputs_refuse_without_panics() {
    for ranges in [
        vec![std::ops::Range { start: 2, end: 1 }],
        std::iter::once(0..4).collect(),
        vec![1..2, 0..1],
    ] {
        let text = RenderedHelp {
            text: "abc".into(),
            interpolations: ranges,
        };
        assert_eq!(
            text.write_terminal(&mut String::new()),
            Err(Error::InvalidRange)
        );
    }
    let text = RenderedHelp {
        text: "é".into(),
        interpolations: std::iter::once(0..2).collect(),
    };
    assert_eq!(
        text.write_terminal(&mut String::new()),
        Err(Error::InvalidRange)
    );
    let text = RenderedHelp {
        text: "\x1b".into(),
        interpolations: vec![],
    };
    assert_eq!(
        text.write_terminal(&mut String::new()),
        Err(Error::UnsafeLiteral)
    );
    assert_eq!(
        value(TextRef::Points(&[0x110000]), &mut String::new()),
        Err(Error::InvalidCodepoint)
    );
    let text = RenderedHelp {
        text: NormalizedText::Codepoints(vec![0x110000]),
        interpolations: vec![],
    };
    assert_eq!(
        text.write_terminal(&mut String::new()),
        Err(Error::InvalidCodepoint)
    );
}
