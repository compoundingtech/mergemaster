use super::*;
use serde_json::json;
fn snapshot(v: &Value) -> serde_json::Value {
    let mut pending = vec![v];
    let mut nodes = Vec::new();
    while let Some(value) = pending.pop() {
        match value {
            Value::String(s) => nodes.push(json!(["string", s])),
            Value::Bool(b) => nodes.push(json!(["bool", b])),
            Value::Integer(i) => nodes.push(json!(["int", i])),
            Value::Array(items) => {
                nodes.push(json!(["array", items.len()]));
                pending.extend(items.iter().rev());
            }
            Value::Table(table) => {
                nodes.push(json!(["table", table.keys().collect::<Vec<_>>()]));
                pending.extend(table.values().rev());
            }
            other => panic!("unexpected fixture value {other:?}"),
        }
    }
    json!(nodes)
}
#[test]
fn documents_match_pinned_tomllib() {
    let script = r#"
import json,sys,tomllib,itertools
assert sys.version_info[:3]==(3,14,7)
parts=['a=1','a.b=1','a={b=1}','a=[1]','[a]','[a.b]','[[a]]','[[a.b]]','b=2','"é"=true']
samples=['','\ufeffa=1','🦀=1','a=1 b=2','[a','[[a]','[a]\nx={a=1,}','# comment\r\na = [1, #x\r\n2,]\n']
samples += ['\n'.join(p) for p in itertools.product(parts,repeat=2)]
samples += ['[[a]]\nx=1\n[a.b]\ny=2\n[[a]]\nx=3\n[a.b]\ny=4','a.b.c=1\na.b.d=2\n[a]\nx=3','[a.b]\nx=1\n[a]\ny=2']
for token in ['[package]\nname="é"\nversion="1"\n','[[bin]]\nname="x"\npath="src/main.rs"\n']:
 samples.extend(token[:i] for i in range(len(token)+1))
quote_cases=[('a='+quote*3+'text'+quote*count+tail,count) for quote in ['"',"'"] for count in range(3,8) for tail in ['', '\nb=2', ' trailing']]
samples += [raw for raw,count in quote_cases]
six_quotes={raw for raw,count in quote_cases if count==6}
cases=[]
def snapshot(root):
 pending=[root]; nodes=[]
 while pending:
  value=pending.pop()
  if isinstance(value,dict):
   nodes.append(['table',list(value)]); pending.extend(reversed(list(value.values())))
  elif isinstance(value,list):
   nodes.append(['array',len(value)]); pending.extend(reversed(value))
  elif type(value) is bool: nodes.append(['bool',value])
  elif type(value) is int: nodes.append(['int',str(value)])
  else:
   assert type(value) is str
   nodes.append(['string',value])
 return nodes
for raw in samples:
 try: expected=dict(value=snapshot(tomllib.loads(raw)))
 except Exception as e: expected=dict(error=str(e),kind=type(e).__name__)
 if raw in six_quotes:
  assert expected==dict(error='Expected newline or end of document after a statement (at line 1, column 15)',kind='TOMLDecodeError')
 cases.append(dict(raw=raw,expected=expected,six_quotes=raw in six_quotes))
print(json.dumps(cases))
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
    let cases: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let mut six_quote_rejections = 0;
    for case in &cases {
        let actual = match parse(case["raw"].as_str().unwrap()) {
            Ok(table) => json!({"value":snapshot(&Value::Table(table))}),
            Err(e) => json!({"error":e.to_string(),"kind":e.kind.class()}),
        };
        assert_eq!(actual, case["expected"], "{case}");
        if case["six_quotes"] == true {
            assert_eq!(
                actual,
                json!({"error":"Expected newline or end of document after a statement (at line 1, column 15)","kind":"TOMLDecodeError"})
            );
            six_quote_rejections += 1;
        }
    }
    assert_eq!(cases.len(), 210);
    assert_eq!(six_quote_rejections, 6);
}
#[test]
fn deeply_nested_document_is_iterative() {
    let depth = 100_000;
    let mut text = String::from("selected=");
    for _ in 0..depth {
        text.push_str("[{a=");
    }
    text.push('0');
    for _ in 0..depth {
        text.push_str("}]");
    }
    let error = parse(&text).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Resource(Resource::ContainerDepth));
    assert_eq!(error.to_string(), "TOML container depth exceeds 256");
    // The resource refusal is deterministic; CPython's recursion boundary is not.
}
#[test]
fn node_boundaries_match_oracle_below_limit() {
    let script = r#"
import json,sys,tomllib
assert sys.version_info[:3]==(3,14,7)
rows=[]
for prefix,suffix,overhead in [('x=[',']',2),('x={a.b=[',']}',4),('[a.b]\nx=[',']',4),('[[a.b]]\nx=[',']',5)]:
 for extra in [0,1]:
  raw=prefix+','.join(['0']*(262144-overhead+extra))+suffix
  pending=[tomllib.loads(raw)]; count=0
  while pending:
   value=pending.pop(); count+=1
   if isinstance(value,dict): pending.extend(value.values())
   elif isinstance(value,list): pending.extend(value)
   else: assert type(value) is int and value==0
  assert count==262144+extra and len(raw.encode())<1048576
  rows.append([raw,count])
print(json.dumps(rows))
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
    let rows: Vec<(String, usize)> = serde_json::from_slice(&output.stdout).unwrap();
    for (raw, expected) in rows {
        if expected > 262_144 {
            let error = parse(&raw).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Resource(Resource::Nodes));
            assert_eq!(error.to_string(), "TOML node count exceeds 262144");
        } else {
            let root = Value::Table(parse(&raw).unwrap());
            let mut pending = vec![&root];
            let mut count = 0;
            while let Some(value) = pending.pop() {
                count += 1;
                match value {
                    Value::Table(table) => pending.extend(table.values()),
                    Value::Array(items) => pending.extend(items),
                    Value::Integer(i) => assert_eq!(i, "0"),
                    _ => panic!("unexpected node"),
                }
            }
            assert_eq!(count, expected);
        }
    }
}
#[test]
fn source_and_container_limits_match_oracle_below_bounds() {
    let script = r#"
import json,sys,tomllib
assert sys.version_info[:3]==(3,14,7)
rows=[]
for depth in [0,1,255,256,257]:
 for opening,closing in [('[',']'),('{a=','}'),('[{a=','}]')]:
  count=depth if opening!='[{a=' else depth//2
  raw='x='+opening*count+'0'+closing*count
  value=tomllib.loads(raw)['x']; seen=0
  while isinstance(value,(list,dict)):
   seen+=1; value=value[0] if isinstance(value,list) else value['a']
  assert seen==(count if opening!='[{a=' else count*2) and value==0
  rows.append([raw,seen])
for extra in [0,1]:
 raw='x=0\n#'+'é'*((1048576-5)//2)+' '*(extra+1)
 assert len(raw.encode())==1048576+extra and tomllib.loads(raw)=={'x':0}
 rows.append([raw,-1])
print(json.dumps(rows))
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
    let rows: Vec<(String, i64)> = serde_json::from_slice(&output.stdout).unwrap();
    for (raw, depth) in rows {
        let expected = if raw.len() > 1_048_576 {
            Some(Resource::SourceBytes)
        } else if depth > 256 {
            Some(Resource::ContainerDepth)
        } else {
            None
        };
        match (parse(&raw), expected) {
            (Err(error), Some(resource)) => {
                assert_eq!(error.kind, ErrorKind::Resource(resource));
                assert_eq!(error.to_string(), resource.error().to_string());
            }
            (Ok(table), None) => {
                let mut value = &table["x"];
                for _ in 0..depth.max(0) {
                    value = match value {
                        Value::Array(items) => &items[0],
                        Value::Table(items) => &items["a"],
                        _ => panic!("container expected"),
                    };
                }
                assert!(matches!(value, Value::Integer(i) if i=="0"));
            }
            (actual, expected) => panic!("unexpected resource outcome {actual:?} {expected:?}"),
        }
    }
}
#[test]
fn full_document_numeric_rounding_matches_tomllib_bits() {
    let script = r#"
import json,struct,sys,tomllib
assert sys.version_info[:3]==(3,14,7)
samples=['1e309','-1e309','2.2250738585072011e-308','4.9e-324','1e-400','9007199254740993','1.00000000000000011102230246251565404236316680908203125']
rows=[]
for token in samples:
 value=tomllib.loads('value='+token)['value']
 expected={'integer':str(value)} if type(value) is int else {'bits':struct.pack('>d',value).hex()}
 rows.append(dict(token=token,expected=expected))
assert rows[0]['expected']=={'bits':'7ff0000000000000'}
assert rows[1]['expected']=={'bits':'fff0000000000000'}
assert rows[3]['expected']=={'bits':'0000000000000001'}
assert rows[4]['expected']=={'bits':'0000000000000000'}
assert rows[5]['expected']=={'integer':'9007199254740993'}
assert rows[6]['expected']=={'bits':'3ff0000000000000'}
print(json.dumps(rows))
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
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows.len(), 7);
    for row in rows {
        let table = parse(&format!("value={}", row["token"].as_str().unwrap())).unwrap();
        let actual = match &table["value"] {
            Value::Float(number) => json!({"bits":format!("{:016x}", number.to_bits())}),
            Value::Integer(number) => json!({"integer":number}),
            value => panic!("unexpected numeric value {value:?}"),
        };
        assert_eq!(actual, row["expected"], "{row}");
    }
}

#[test]
fn document_flag_timing_and_combined_two_thousand_parts_match_tomllib() {
    let script = r#"
import json,sys,tomllib
assert sys.version_info[:3]==(3,14,7)
samples=['[a]\nb.c=1\n[a.b]','[a]\nb.c=1\n[a.b.c]','a.b.c=1\n[a.b]','[a.b]\nc=1\n[a]\nb.d=1']
samples.append('['+'.'.join('h'+str(i) for i in range(1000))+']\n'+'.'.join('k'+str(i) for i in range(1000))+'=1')
rows=[]
for raw in samples:
 try:
  pending=[tomllib.loads(raw)]; nodes=[]
  while pending:
   value=pending.pop()
   if isinstance(value,dict):
    nodes.append(['table',list(value)]); pending.extend(reversed(list(value.values())))
   else:
    assert type(value) is int
    nodes.append(['int',str(value)])
  expected=dict(nodes=nodes)
 except Exception as e: expected=dict(error=str(e),kind=type(e).__name__)
 rows.append(dict(raw=raw,expected=expected))
assert len(rows[-1]['expected']['nodes'])==2001
assert rows[-1]['expected']['nodes'][-1]==['int','1']
print(json.dumps(rows))
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
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows.len(), 5);
    for row in rows {
        let actual = match parse(row["raw"].as_str().unwrap()) {
            Err(e) => json!({"error":e.to_string(),"kind":e.kind.class()}),
            Ok(table) => {
                let root = Value::Table(table);
                let mut pending = vec![&root];
                let mut nodes = Vec::new();
                while let Some(value) = pending.pop() {
                    match value {
                        Value::Table(table) => {
                            nodes.push(json!(["table", table.keys().collect::<Vec<_>>()]));
                            pending.extend(table.values().rev());
                        }
                        Value::Integer(n) => nodes.push(json!(["int", n])),
                        _ => panic!("unexpected timing fixture value"),
                    }
                }
                json!({"nodes":nodes})
            }
        };
        assert_eq!(actual, row["expected"], "{row}");
    }
}
