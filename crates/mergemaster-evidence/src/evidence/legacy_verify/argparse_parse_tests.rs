use super::*;
use serde_json::{Value, json};
#[test]
fn namespaces_defaults_appends_and_mutex_precedence_match_python() {
    let script = r#"
import argparse,json,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify')); original=argparse.ArgumentParser.parse_args; captured=[]
def capture(self,argv): captured.append(self); raise SystemExit(0)
argparse.ArgumentParser.parse_args=capture; v['main']([]); argparse.ArgumentParser.parse_args=original
p=captured[0]; p.exit_on_error=False; base=['--tree','x']; samples=[base,['--revision','HEAD'],['--tr','x'],['--tree','-1suffix'],['--tree','-.５suffix'],['--tree','\udc80']]
samples += [base+['--max-age',s] for s in ['-0','+١_２','1'*4300]]
for a in p._actions:
 if a.dest not in ('help','tree','revision','max_age'): samples.append(base+[a.option_strings[-1]]*(2 if a.nargs==0 else 1)+([] if a.nargs==0 else ['first',a.option_strings[-1],'second']))
for group in p._mutually_exclusive_groups:
 a,b=group._group_actions; prefix=[] if group.required else base
 samples += [prefix+[first.option_strings[-1],'a',second.option_strings[-1],'b'] for first,second in [(a,b),(b,a)]]
def tag(x): return {'int':str(x)} if type(x) is int else list(map(ord,x)) if isinstance(x,str) else [list(map(ord,s)) for s in x] if isinstance(x,list) else x
rows=[]
for argv in samples:
 try: expected={'values':{k:tag(x) for k,x in vars(original(p,argv)).items()}}
 except argparse.ArgumentError as e: expected={'error':str(e)}
 rows.append(dict(argv=[list(map(ord,s)) for s in argv],**expected))
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
    let rows: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    for row in rows {
        let points: Vec<Vec<u32>> = serde_json::from_value(row["argv"].clone()).unwrap();
        let argv: Vec<_> = points.iter().map(|p| TextRef::Points(p)).collect();
        match parse(&argv) {
            Ok(ParseOutcome::Parsed(args)) => {
                let mut actual = serde_json::Map::new();
                for (spec, values) in OPTIONS.iter().zip(&args.values) {
                    let points = |s: TextRef<'_>| s.points().collect::<Vec<_>>();
                    let value=match spec.action {
                        Action::Help=>continue,
                        Action::Flag=>json!(!values.is_empty()),
                        Action::Append=>json!(values.iter().copied().map(points).collect::<Vec<_>>()),
                        Action::Integer=>args.max_age.as_ref().map_or(Value::Null,|i|json!({"int":format!("{}{}",if i.negative {"-"} else {""},i.digits)})),
                        Action::Store=>values.last().copied().map_or(Value::Null,|s|json!(points(s))),
                    };
                    actual.insert(spec.dest.to_owned(), value);
                }
                assert_eq!(json!(actual), row["values"], "{row}");
            }
            Err(ParseError::Conflict(option, previous)) => assert_eq!(
                format!(
                    "argument {}: not allowed with argument {}",
                    OPTIONS[option].name, OPTIONS[previous].name
                ),
                row["error"],
                "{row}"
            ),
            Err(ParseError::Ambiguous(value, ids)) => {
                let names: Vec<_> = ids.iter().map(|id| OPTIONS[*id].name).collect();
                assert_eq!(
                    format!(
                        "ambiguous option: {} could match {}",
                        value,
                        names.join(", ")
                    ),
                    row["error"],
                    "{row}"
                );
            }
            _ => panic!("unexpected parser outcome: {row}"),
        }
    }
}
