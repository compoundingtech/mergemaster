use super::*;
#[test]
fn usage_matches_pinned_formatter_widths_and_lossless_programs() {
    let script = r#"
import argparse,json,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify'))
rows=[]
def capture(self,argv):
 for width in [0,1,10,20,30,40,60,78,100,200,1000]:
  for prog in ['evidence-verify','','é😀','x'*90,'x\ny','x\n\n\ny','\udc80']:
   self.prog=prog
   self.formatter_class=lambda prog:argparse.HelpFormatter(prog,width=width)
   rows.append(dict(width=width,prog=list(map(ord,prog)),usage=list(map(ord,self.format_usage()))))
 print(json.dumps(rows)); raise SystemExit(0)
argparse.ArgumentParser.parse_args=capture
v['main']([])
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
    for row in rows {
        let prog: Vec<u32> = serde_json::from_value(row["prog"].clone()).unwrap();
        let expected: Vec<u32> = serde_json::from_value(row["usage"].clone()).unwrap();
        let rendered = usage(
            TextRef::Points(&prog),
            row["width"].as_u64().unwrap() as usize,
        );
        assert_eq!(
            rendered.text.borrowed().points().collect::<Vec<_>>(),
            expected,
            "{row}"
        );
        for range in rendered.interpolations {
            assert!(range.end <= expected.len());
            assert!(expected[range].iter().all(|point| prog.contains(point)));
        }
    }
}
