use super::*;
#[test]
fn declarations_match_complete_pinned_parser_metadata() {
    let script = r#"
import argparse,json,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify'))
def capture(self,argv):
 actions=[]
 for a in self._actions:
  action='Integer' if a.type is int else {'_HelpAction':'Help','_StoreAction':'Store','_StoreTrueAction':'Flag','_AppendAction':'Append'}[type(a).__name__]
  actions.append(dict(name=a.option_strings[-1],aliases=a.option_strings,dest=a.dest,metavar=None if action in ('Help','Flag') else a.metavar or a.dest.upper(),help=a.help or '',action=action,nargs=a.nargs,default=a.default,required=a.required,group=next((i for i,g in enumerate(self._mutually_exclusive_groups) if a in g._group_actions),None)))
 print(json.dumps(dict(description=self.description,actions=actions,groups=[g.required for g in self._mutually_exclusive_groups])))
 raise SystemExit(0)
argparse.ArgumentParser.parse_args=capture
v['main']([])
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_PARITY_ORACLE").unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual["description"], DESCRIPTION);
    assert_eq!(actual["groups"], serde_json::json!(GROUPS));
    let expected: Vec<_> = OPTIONS.iter().map(|a| {
        let default = match a.default {
            DefaultValue::None => serde_json::Value::Null,
            DefaultValue::Text(text) => serde_json::json!(text),
            DefaultValue::False => serde_json::json!(false),
            DefaultValue::EmptyList => serde_json::json!([]),
        };
        serde_json::json!({"name":a.name,"aliases":a.aliases,"dest":a.dest,"metavar":a.metavar,"help":a.help,"action":format!("{:?}",a.action),"nargs":a.nargs,"default":default,"required":a.required,"group":a.group})
    }).collect();
    assert_eq!(actual["actions"], serde_json::json!(expected));
}
