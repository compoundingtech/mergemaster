use super::*;
use serde_json::json;
#[test]
fn containers_match_python_oracle() {
    let script = r#"
import json,runpy,struct,sys
j=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')['json']
cases=[b'-0',b'',b'[]',b'{}',b'[{},[],true,null,1.5]',b'{"b":1,"a":2,"b":3}',
 b'{"x":[],"x":{}}',br'{"\ud800":1,"\ud800":2,"\udfff":3}',
 br'{"x":[NaN,Infinity,-Infinity,"\ud800"]}',b'[1,]',b'{"a":1,}',
 b'[1 2]',b'{"a" 1}',b'{"a":}',b'{1:2}',b'[,1]',b'{,}',b'[}',b'{]',
 b'[',b'{"a":',b'[truefalse]',b'01',b'{}[]',b'null?',b'[]x',b'[]\xff',
 b'{} '+b'9'*4301,b' [0] \t\r\n',b'"hello"',b'false']
for depth in [2000,50000]: cases.append(b'['*depth+b'0'+b']'*depth)
cases.append(b'{"k":'*2000+b'null'+b'}'*2000)
results=[]
for blob in cases:
 depth=0
 try:
  value=j.loads(blob); flat=[]; stack=[(value,1)]
  while stack:
   v,d=stack.pop()
   if isinstance(v,(list,dict)): depth=max(depth,d)
   if isinstance(v,list): flat.append(['array',len(v)]); stack.extend((c,d+1) for c in reversed(v))
   elif isinstance(v,dict):
    flat.append(['object',[list(map(ord,k)) for k in v]]); stack.extend((c,d+1) for c in reversed(v.values()))
   elif v is None: flat.append(['null'])
   elif isinstance(v,bool): flat.append(['bool',v])
   elif isinstance(v,int): flat.append(['integer',str(v)])
   elif isinstance(v,float): flat.append(['float',struct.pack('>d',v).hex()])
   else: flat.append(['string',list(map(ord,v))])
  result=['ok',flat]
 except j.JSONDecodeError as e: result=['extra' if e.msg=='Extra data' else 'invalid']
 except UnicodeError: result=['encoding']
 except RecursionError: result=['recursion']
 results.append(dict(bytes=list(blob),result=result,depth=depth))
print(json.dumps(results))
"#;
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle required");
    let output = std::process::Command::new("python3")
        .args(["-c", script, &root])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for (index, case) in cases.as_array().unwrap().iter().enumerate() {
        let bytes: Vec<u8> = serde_json::from_value(case["bytes"].clone()).unwrap();
        if case["depth"].as_u64().unwrap() > MAX_CONTAINER_DEPTH as u64 {
            assert_eq!(case["result"][0], "ok"); // Explicit conservative divergence.
            assert_eq!(
                Document::from_bytes(&bytes).unwrap_err(),
                Error::NestingLimit
            );
            continue;
        }
        let actual = match Document::from_bytes(&bytes) {
            Err(e) => json!([match e {
                Error::Encoding => "encoding",
                Error::ExtraData => "extra",
                _ => "invalid",
            }]),
            Ok(doc) => {
                let mut flat = Vec::new();
                let mut stack = vec![doc.root()];
                while let Some(node) = stack.pop() {
                    flat.push(match node {
                        Node::Array(v) => {
                            stack.extend(v.iter().rev().map(|id| doc.node(*id)));
                            json!(["array", v.len()])
                        }
                        Node::Object(v) => {
                            stack.extend(v.values().rev().map(|id| doc.node(*id)));
                            json!(["object", v.keys().collect::<Vec<_>>()])
                        }
                        Node::Null => json!(["null"]),
                        Node::Bool(v) => json!(["bool", v]),
                        Node::Integer(v) => json!(["integer", v]),
                        Node::Float(v) => json!(["float", format!("{:016x}", v.to_bits())]),
                        Node::String(v) => json!(["string", v]),
                    });
                }
                json!(["ok", flat])
            }
        };
        assert_eq!(actual, case["result"], "fixture {index}");
    }
}
#[test]
fn container_limit_counts_arrays_objects_and_empty_roots() {
    for depth in [MAX_CONTAINER_DEPTH, MAX_CONTAINER_DEPTH + 1] {
        for (open, close, empty) in [("[", "]", "[]"), ("{\"k\":", "}", "{}")] {
            let bytes = format!(
                "{}{}{}",
                open.repeat(depth - 1),
                empty,
                close.repeat(depth - 1)
            );
            let parsed = Document::from_bytes(bytes.as_bytes());
            if depth == MAX_CONTAINER_DEPTH {
                assert!(parsed.is_ok());
            } else {
                assert_eq!(parsed.unwrap_err(), Error::NestingLimit);
            }
        }
    }
}
