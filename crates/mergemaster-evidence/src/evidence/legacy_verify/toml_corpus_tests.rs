use super::*;
use serde_json::json;
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn snapshot(value: &Value) -> serde_json::Value {
    match value {
        Value::String(s) => json!(["str", s]),
        Value::Bool(b) => json!(["bool", b]),
        Value::Integer(i) => {
            let clean = i.replace('_', "");
            let integer = if let Some(raw) = clean.strip_prefix("0x") {
                i128::from_str_radix(raw, 16)
            } else if let Some(raw) = clean.strip_prefix("0o") {
                i128::from_str_radix(raw, 8)
            } else if let Some(raw) = clean.strip_prefix("0b") {
                i128::from_str_radix(raw, 2)
            } else {
                clean.parse()
            };
            json!(["int", integer.map_or(clean, |v| v.to_string())])
        }
        Value::Float(f) => json!(["float", format!("{:016x}", f.to_bits())]),
        Value::Date(d) => json!(["date", [d.year, d.month, d.day]]),
        Value::Time(t) => json!(["time", [t.hour, t.minute, t.second, t.microsecond]]),
        Value::DateTime {
            date: d,
            time: t,
            offset_minutes: o,
        } => json!([
            "datetime",
            [
                d.year,
                d.month,
                d.day,
                t.hour,
                t.minute,
                t.second,
                t.microsecond
            ],
            o
        ]),
        Value::Array(a) => json!(["list", a.iter().map(snapshot).collect::<Vec<_>>()]),
        Value::Table(t) => json!([
            "dict",
            t.iter()
                .map(|(k, v)| (k.clone(), snapshot(v)))
                .collect::<serde_json::Map<_, _>>()
        ]),
    }
}
#[test]
fn cargo_shapes_and_error_corpus_match_tomllib() {
    let script = r#"
import datetime,itertools,json,struct,sys,tomllib
assert sys.version_info[:3]==(3,14,7)
def snap(v):
 if isinstance(v,dict): return ['dict',{k:snap(x) for k,x in v.items()}]
 if isinstance(v,list): return ['list',list(map(snap,v))]
 if isinstance(v,bool): return ['bool',v]
 if isinstance(v,int): return ['int',str(v)]
 if isinstance(v,float): return ['float',struct.pack('>d',v).hex()]
 if isinstance(v,datetime.datetime):
  offset=v.utcoffset()
  return ['datetime',[v.year,v.month,v.day,v.hour,v.minute,v.second,v.microsecond],None if offset is None else int(offset.total_seconds()/60)]
 if isinstance(v,datetime.date): return ['date',[v.year,v.month,v.day]]
 if isinstance(v,datetime.time): return ['time',[v.hour,v.minute,v.second,v.microsecond]]
 return ['str',v]
samples=json.load(sys.stdin)
samples+=['''[workspace]
members=["crates/*", "."]
exclude=["old"]
resolver="2"
[workspace.dependencies]
lib={path="lib",features=["x"],default-features=false}
[patch.crates-io]
lib={path="patched"}
[target.'cfg(unix)'.dependencies]
lib.workspace=true
[[bin]]
name="app"
path="src/main.rs"
[[bin]]
name="other"
[package.metadata.docs.rs]
all-features=true
''']
tokens=['true','false','0','-0','+12','0xCA_FE','0o755','0b10_01','1_000','9'*100,'1.0','-0.0','1e999','-1e999','nan','-nan','+inf','1979-05-27','07:32:00.9999999','1979-05-27T07:32:00Z','1979-05-27 07:32:00-01:30','"é🦀"',"'''a\nb'''",'"""a\n\\   \n b"""','[1,{a.b=[true]}]','{a.b=1,a.c=2}']
for token in tokens:
 samples+=['x='+token,'x=['+token+',]','x={a='+token+'}']
invalid=['','01','1_','+','1.','1e','0x','0x_1','True','none','1999-02-29','"\\q"','"\\uD800"','"\\U00110000"',"'a\nb'",'[1 2]','[1,,2]','{a=1,}','{a=1,a=2}','{a=[],a.b=2}','{a.b=1,a.b.c=2}']
for token in invalid:
 for prefix in ['x=','"🦀é"=','\r\n#é\r\nx=']:
  samples.append(prefix+token)
samples+=['a=1\na=2','[a]\n[a]','[[a]]\n[a]','a.b=1\n[a.b]','a={}\n[a.b]','a=[{}]\n[[a]]','[a]\nb=1\n[a.b]','[[a]]\nx=1\n[[a]]\nx=2','a.b.c=1\na.b.d=2','["é" . "🦀"]\nx=1','#\x00','x=1\x00','x="\x00"','\ufeff','[a] x=1','[[]]']
cases=[]
for raw in samples:
 try: expected=dict(value=snap(tomllib.loads(raw)))
 except Exception as e: expected=dict(error=str(e),kind=type(e).__name__)
 cases.append(dict(raw=raw,expected=expected))
print(json.dumps(cases))
"#;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifests = [
        std::fs::read_to_string(root.join("Cargo.toml")).unwrap(),
        std::fs::read_to_string(root.join("crates/mergemaster-evidence/Cargo.toml")).unwrap(),
    ];
    let mut child = Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&manifests).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for case in &cases {
        let actual = match parse(case["raw"].as_str().unwrap()) {
            Ok(t) => json!({"value":snapshot(&Value::Table(t))}),
            Err(e) => json!({"error":e.to_string(),"kind":e.kind.class()}),
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert_eq!(cases.len(), 160);
}
