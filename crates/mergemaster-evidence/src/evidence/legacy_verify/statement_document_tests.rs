use super::*;
use serde_json::json;
#[test]
fn containers_match_python_oracle() {
    let script = r#"
import json,runpy,struct,sys
assert sys.version_info[:3] == (3,14,7), sys.version
j=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')['json']
cases=[b'-0',b'',b'[]',b'{}',b'[{},[],true,null,1.5]',b'{"b":1,"a":2,"b":3}',
 b'{"x":[],"x":{}}',br'{"\ud800":1,"\ud800":2,"\udfff":3}',
 br'{"x":[NaN,Infinity,-Infinity,"\ud800"]}',b'[1,]',b'{"a":1,}',
 b'[1 2]',b'{"a" 1}',b'{"a":}',b'{1:2}',b'[,1]',b'{,}',b'[}',b'{]',
 b'[',b'{"a":',b'[truefalse]',b'01',b'{}[]',b'null?',b'[]x',b'[]\xff',
 b'{} '+b'9'*4301,b' [0] \t\r\n',b'"hello"',b'false']
# Syntax fixtures exercise the accelerated scanner used by the pinned oracle.
texts=[' ', '\n\t', '{', '{ ', '[ ', '{"a"', '{"a" ', '{"a": ',
 '[1', '[1 ', '[1,', '{"a":1,', '[1, ]', '{"a":1, }',
 '{"a":}', '{"a": ]', '{"a",1}', '{"a":1 "b":2}', '{"a":1 "',
 '{?', '{1', '{NaN', '{9'+'9'*4300, '[1 "',
 '"', '"abc', '"abc\\', '"\\q"', '"\\u"', '"\\u12"',
 '"\\u12g4"', '"\\u１２３４"', '"\\ud800\\u12g4"',
 '"a\nb"', '"a\x00b"', '"a\tb"', '["🌍",\n {"é": ?}]',
 '["🌍",\n {"é" ?}]', '["🌍",\n 1, ]', '"🌍" ?',
 '"\ud800" ?', '["\udfff",\n?]', '"🌍\\q"', '"🌍\\u12g4"',
 '0.', '0.e1', '1e', '1e+', '1e-', '-1.e2', '-',
 '-NaN', '--1', '+1', '00', '-01', '[01]', '[1.]', '[1e+]',
 '{"a":1e}', '[truefalse]', 'null?', '[] "unterminated',
 '{"a":1} '+'9'*4301, '\u00a0null']
for control in range(32): texts.append('"🌍'+chr(control)+'"')
for text in ['"🌍" ?', '["é",\n?]', '"\\ud800\\u12g4"']:
 for encoding in ['utf-8-sig','utf-16-le','utf-16-be','utf-32-le','utf-32-be']:
  cases.append(text.encode(encoding,'surrogatepass'))
cases.extend(text.encode('utf-8','surrogatepass') for text in texts)
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
 except j.JSONDecodeError as e: result=['syntax',e.msg,e.pos,e.lineno,e.colno,str(e)]
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
            Err(Error::Syntax(e)) => json!([
                "syntax",
                e.kind.message(),
                e.pos,
                e.lineno,
                e.colno,
                e.to_string()
            ]),
            Err(e) => json!([match e {
                Error::Encoding => "encoding",
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
#[test]
fn sharing_retains_nested_values_and_surrogate_keys() {
    let text = format!(
        "{}{{\"\\ud800\":\"kept\"}}{}",
        "[".repeat(MAX_CONTAINER_DEPTH - 1),
        "]".repeat(MAX_CONTAINER_DEPTH - 1)
    );
    let original = std::sync::Arc::new(Document::from_bytes(text.as_bytes()).unwrap());
    let copy = std::sync::Arc::clone(&original);
    assert!(matches!(original.nodes.last(), Some(Node::String(v)) if v == &[107, 101, 112, 116]));
    let (Node::Object(a), Node::Object(b)) = (
        &original.nodes[MAX_CONTAINER_DEPTH - 1],
        &copy.nodes[MAX_CONTAINER_DEPTH - 1],
    ) else {
        panic!("object leaf");
    };
    assert_eq!(
        a.keys().next().unwrap().as_ptr(),
        b.keys().next().unwrap().as_ptr()
    );
    let (Node::Array(a), Node::Array(b)) = (original.root(), copy.root()) else {
        panic!("array root");
    };
    assert_eq!(a.as_ptr(), b.as_ptr());
}

#[test]
fn policy_depth_parameter_preserves_the_statement_default() {
    for depth in [128, 129, 256, 257] {
        let text = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(
            Document::from_bytes(text.as_bytes()).is_ok(),
            depth <= MAX_CONTAINER_DEPTH
        );
        assert!(Document::from_bytes_with_depth_limit(text.as_bytes(), None).is_ok());
    }
}

#[test]
fn json_text_input_never_uses_bytes_encoding_detection() {
    let output = std::process::Command::new("python3")
        .args([
            "-c",
            r#"
import json,sys
assert sys.version_info[:3]==(3,14,7)
cases=[]
for base in ['{}','0','"x"']:
 for encoding in ['utf-16-le','utf-16-be','utf-32-le','utf-32-be']:
  blob=base.encode(encoding);cases.append((blob.decode('latin1'),blob))
for text in ['{}','\ufeff{}','"\ufeff"',r'"\u0000"']:
 cases.append((text,text.encode()))
out=[]
for text,blob in cases:
 def accepts(value):
  try: json.loads(value);return True
  except ValueError:return False
 out.append(dict(text=text,bytes=list(blob),str_ok=accepts(text),bytes_ok=accepts(blob)))
print(json.dumps(out))
"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.as_array().unwrap().len(), 16);
    for case in cases.as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let bytes: Vec<u8> = serde_json::from_value(case["bytes"].clone()).unwrap();
        assert_eq!(
            Document::from_text_with_depth_limit(text, None).is_ok(),
            case["str_ok"].as_bool().unwrap(),
            "{text:?}"
        );
        assert_eq!(
            Document::from_bytes(&bytes).is_ok(),
            case["bytes_ok"].as_bool().unwrap()
        );
    }
}

#[test]
fn uncapped_text_api_has_only_reachable_errors_and_identical_results() {
    let mut cases: Vec<String> = [
        "",
        "{}",
        "[]",
        "null",
        "-0",
        "-0.0",
        "1e999",
        "NaN",
        "{\"é🦀\": [1, \"\\ud800\", false]}",
        "{\"a\":1,\"a\":2}",
        "\u{feff}{}",
        "[1,]",
        "{\"a\":}",
        "\"\\q\"",
        "\"\\u123",
        "\0{\0}",
        "{\"a\" 1}",
        "1 2",
        "\"a\nb\"",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    cases.push("9".repeat(4301));
    cases.push(format!("{}0{}", "[".repeat(100_000), "]".repeat(100_000)));
    assert_eq!(cases.len(), 21);
    for text in cases {
        let narrow: Result<Document, TextError> = Document::from_text(&text);
        let legacy = Document::from_text_with_depth_limit(&text, None);
        match (narrow, legacy) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a.root, b.root);
                assert_eq!(format!("{:?}", a.nodes), format!("{:?}", b.nodes));
            }
            (Err(a), Err(b)) => {
                // Exhaustive: decoding and depth-limit errors cannot be represented.
                let equivalent = match a {
                    TextError::Syntax(error) => Error::Syntax(error),
                    TextError::IntegerLimit { digits } => Error::IntegerLimit { digits },
                };
                assert_eq!(equivalent, b);
            }
            other => panic!("text entrypoints differ: {other:?}"),
        }
    }
}

#[test]
fn policy_json_boundaries_and_text_helpers_match_real_oracle() {
    let script = r#"
import json,runpy,sys
assert sys.version_info[:3]==(3,14,7)
j=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')['json']; rows=[]
def add(raw,resource=None,nodes=None):
 j.loads(raw) # Real oracle accepts every below/above-bound fixture.
 rows.append(dict(raw=raw,resource=resource,nodes=nodes))
for extra in [0,1]:
 raw='"'+'é'*524287+'"'+(' '*extra)
 assert len(raw.encode())==1048576+extra
 add(raw,'SourceBytes' if extra else None,1)
 for opening,closing,empty in [('[',']','[]'),('{"k":','}','{}'),('[{"k":','}]','[]')]:
  depth=256+extra
  if opening=='[{"k":':
   pairs=(depth-1)//2; raw=opening*pairs+('[' if depth%2==0 else '')+empty+(']' if depth%2==0 else '')+closing*pairs
  else: raw=opening*(depth-1)+empty+closing*(depth-1)
  pending=[(j.loads(raw),1)]; observed=0
  while pending:
   value,d=pending.pop()
   if isinstance(value,(list,dict)):
    observed=max(observed,d); pending.extend((v,d+1) for v in (value.values() if isinstance(value,dict) else value))
  assert observed==depth
  add(raw,'ContainerDepth' if extra else None,depth)
 for prefix,suffix,item,overhead in [('[',']','0',1),('[',']','[]',1),('{"x":[','],"x":0}','0',3)]:
  raw=prefix+','.join([item]*(262144-overhead+extra))+suffix
  assert len(raw.encode())<1048576
  add(raw,'Nodes' if extra else None,262144+extra)
print(json.dumps(rows))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 14);
    for row in rows {
        let raw = row["raw"].as_str().unwrap();
        let resource = match row["resource"].as_str() {
            Some("SourceBytes") => Some(PolicyResource::SourceBytes),
            Some("ContainerDepth") => Some(PolicyResource::ContainerDepth),
            Some("Nodes") => Some(PolicyResource::Nodes),
            None => None,
            _ => panic!("unknown resource"),
        };
        if let Some(resource) = resource {
            assert_eq!(
                Document::from_policy_text(raw).unwrap_err(),
                PolicyTextError::Resource(resource)
            );
            let error =
                crate::evidence::legacy_policy::check_names::selected(raw, &[120]).unwrap_err();
            assert_eq!(
                error.resource,
                Some(crate::evidence::legacy_policy::SourceResource::PolicyJson(
                    resource
                ))
            );
            assert_eq!(
                error.origin,
                crate::evidence::legacy_policy::ErrorOrigin::Failure
            );
            assert_eq!(error.reason, "error");
            assert_eq!(error.detail.to_string(), resource.message());
        } else {
            let doc = Document::from_policy_text(raw).unwrap();
            assert_eq!(doc.nodes.len(), row["nodes"].as_u64().unwrap() as usize);
        }
    }
}
