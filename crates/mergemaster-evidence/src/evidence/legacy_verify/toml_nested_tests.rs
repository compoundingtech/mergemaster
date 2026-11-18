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
fn table_snapshot(items: &Table) -> Json {
    let mut nodes = vec![json!(["table", items.keys().collect::<Vec<_>>()])];
    let mut pending: Vec<_> = items.values().rev().collect();
    while let Some(value) = pending.pop() {
        match value {
            Value::Bool(b) => nodes.push(json!(["bool", b])),
            Value::Array(items) => {
                nodes.push(json!(["array", items.len()]));
                pending.extend(items.iter().rev());
            }
            Value::Table(items) => {
                nodes.push(json!(["table", items.keys().collect::<Vec<_>>()]));
                pending.extend(items.values().rev());
            }
            _ => panic!("invalid fixture value"),
        }
    }
    json!(nodes)
}
#[test]
fn nested_dictionary_mutations_match_pinned_tomllib() {
    let script = r#"
import copy,json,sys,tomllib._parser as p
assert sys.version_info[:3]==(3,14,7)
seeds=[{}, {'a':True}, {'a':{}}, {'a':[]}, {'a':[True]}, {'a':[{},True]}, {'a':[True,{}]}, {'a':[{}]}, {'a':[{'b':True},{}]}, {'a':{'b':[]}}, {'a':[[{}]]}]
paths=[(),('a',),('a','b'),('a','b','c'),('new','deep'),('',),('🦀',)]
def snapshot(root):
 pending=[root]; nodes=[]
 while pending:
  value=pending.pop()
  if isinstance(value,dict):
   nodes.append(['table',list(value)]); pending.extend(reversed(list(value.values())))
  elif isinstance(value,list):
   nodes.append(['array',len(value)]); pending.extend(reversed(value))
  else:
   assert type(value) is bool
   nodes.append(['bool',value])
 return nodes
nests=[]
for seed in seeds:
 n=p.NestedDict(); n.dict=copy.deepcopy(seed); steps=[]
 for key in paths:
  for op,access in [('nest',False),('nest',True),('append',True)]:
   if op=='append' and not key: continue
   try:
    result=n.get_or_create_nest(key,access_lists=access) if op=='nest' else n.append_nest_to_list(key)
    expected=dict(ok=True)
    if op=='nest': expected['value']=snapshot(result)
   except (KeyError,IndexError) as e: expected=dict(ok=False,kind=type(e).__name__)
   steps.append(dict(op=op,key=key,access=access,expected=expected,data=snapshot(n.dict)))
 nests.append(dict(seed=seed,steps=steps))
print(json.dumps(nests))
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
    let cases: Vec<Json> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 11);
    let mut key_errors = 0;
    let mut index_errors = 0;
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
            // Option erases the class by design: toml_document.rs maps both
            // nest/append failures to "Cannot overwrite a value".
            let mut expected = step["expected"].clone();
            if let Some(kind) = expected.as_object_mut().unwrap().remove("kind") {
                match kind.as_str().unwrap() {
                    "KeyError" => key_errors += 1,
                    "IndexError" => index_errors += 1,
                    other => panic!("unexpected oracle exception {other}"),
                }
                assert_eq!(actual, json!({"ok":false}), "{step}");
            }
            assert_eq!(actual, expected, "{step}");
            assert_eq!(table_snapshot(&nested.data), step["data"], "{step}");
        }
        assert!(nested.append_nest(&[]).is_none());
    }
    assert!(key_errors > 0);
    assert!(index_errors > 0);
}
