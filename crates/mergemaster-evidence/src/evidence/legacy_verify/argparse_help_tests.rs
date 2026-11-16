use super::*;
#[test]
fn complete_help_matches_pinned_python_across_widths() {
    let script = r#"
import argparse,json,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify'))
rows=[]
def capture(self,argv):
 for width in list(range(0,120))+[150,200,1000]:
  self.prog='evidence-verify'
  self.formatter_class=lambda prog:argparse.HelpFormatter(prog,width=width)
  rows.append(dict(width=width,help=self.format_help()))
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
        let rendered = help(
            TextRef::Str("evidence-verify"),
            row["width"].as_u64().unwrap() as usize,
        );
        assert_eq!(
            rendered.text.to_string(),
            row["help"],
            "width {}",
            row["width"]
        );
    }
}
