use super::*;
use serde_json::{Value as Json, json};
fn owned(value: &Json) -> Value {
    match value {
        Json::Bool(value) => Value::Bool(*value),
        Json::Array(items) => Value::Array(items.iter().map(owned).collect()),
        Json::Object(items) => Value::Table(
            items
                .iter()
                .map(|(key, value)| (key.clone(), owned(value)))
                .collect(),
        ),
        _ => panic!("invalid fixture value"),
    }
}
fn snapshot(value: &Value) -> Json {
    match value {
        Value::Bool(value) => json!(value),
        Value::Array(items) => Json::Array(items.iter().map(snapshot).collect()),
        Value::Table(items) => table_snapshot(items),
        _ => panic!("invalid fixture value"),
    }
}
fn table_snapshot(items: &Table) -> Json {
    Json::Object(
        items
            .iter()
            .map(|(key, value)| (key.clone(), snapshot(value)))
            .collect(),
    )
}
#[test]
fn nested_dictionary_mutations_match_pinned_tomllib() {
    let script = r#"
import copy,json,sys,tomllib._parser as p
assert sys.version_info[:3]==(3,14,7)
seeds=[{}, {'a':True}, {'a':{}}, {'a':[]}, {'a':[True]}, {'a':[{},True]}, {'a':[True,{}]}, {'a':[{}]}, {'a':[{'b':True},{}]}, {'a':{'b':[]}}, {'a':[[{}]]}]
paths=[(),('a',),('a','b'),('a','b','c'),('new','deep'),('',),('🦀',)]
nests=[]
for seed in seeds:
 n=p.NestedDict(); n.dict=copy.deepcopy(seed); steps=[]
 for key in paths:
  for op,access in [('nest',False),('nest',True),('append',True)]:
   if op=='append' and not key: continue
   try:
    result=n.get_or_create_nest(key,access_lists=access) if op=='nest' else n.append_nest_to_list(key)
    expected=dict(ok=True)
    if op=='nest': expected['value']=copy.deepcopy(result)
   except (KeyError,IndexError): expected=dict(ok=False)
   steps.append(dict(op=op,key=key,access=access,expected=expected,data=copy.deepcopy(n.dict)))
 nests.append(dict(seed=seed,steps=steps))
print(json.dumps(nests))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Json> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 11);
    for case in cases {
        let mut seed = owned(&case["seed"]);
        let Value::Table(data) = &mut seed else {
            panic!("invalid seed")
        };
        let mut nested = NestedDict {
            data: std::mem::take(data),
        };
        assert_eq!(case["steps"].as_array().unwrap().len(), 20);
        for step in case["steps"].as_array().unwrap() {
            let key: Vec<String> = serde_json::from_value(step["key"].clone()).unwrap();
            let actual = if step["op"] == "append" {
                json!({"ok":nested.append_nest(&key).is_some()})
            } else {
                nested
                    .nest(&key, step["access"].as_bool().unwrap())
                    .map_or_else(
                        || json!({"ok":false}),
                        |table| json!({"ok":true,"value":table_snapshot(table)}),
                    )
            };
            assert_eq!(actual, step["expected"], "{step}");
            assert_eq!(table_snapshot(&nested.data), step["data"], "{step}");
        }
        assert!(nested.append_nest(&[]).is_none());
    }
}
