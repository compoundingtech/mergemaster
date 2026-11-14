use super::super::{facts::DocumentFacts, statement_document::Node};
use super::*;
use serde_json::{Value, json};
fn tagged(doc: &Document, node: &Node) -> Value {
    match node {
        Node::Null => json!(["null"]),
        Node::Bool(value) => json!(["bool", value]),
        Node::Integer(decimal) => json!(["int", decimal]),
        Node::Float(value) => json!(["float", value.to_bits()]),
        Node::String(points) => json!(["str", points]),
        Node::Array(ids) => json!([
            "list",
            ids.iter()
                .map(|id| tagged(doc, doc.node(*id)))
                .collect::<Vec<_>>()
        ]),
        Node::Object(entries) => json!([
            "dict",
            entries
                .iter()
                .map(|(key, id)| json!([key, tagged(doc, doc.node(*id))]))
                .collect::<Vec<_>>()
        ]),
    }
}
#[test]
fn observed_records_and_cached_fact_views_preserve_the_entire_python_document() {
    let script = r#"
import copy,json,os,pathlib,runpy,struct,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]
def tagged(v):
 if v is None: return ['null']
 if isinstance(v,bool): return ['bool',v]
 if isinstance(v,int): return ['int',str(v)]
 if isinstance(v,float): return ['float',struct.unpack('>Q',struct.pack('>d',v))[0]]
 if isinstance(v,str): return ['str',[ord(c) for c in v]]
 if isinstance(v,list): return ['list',[tagged(x) for x in v]]
 return ['dict',[[[ord(c) for c in k],tagged(x)] for k,x in v.items()]]
for fmt in ['sha1','sha256']:
 repo=pathlib.Path(sys.argv[2])/fmt
 subprocess.run(['git','init','--bare','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
 def git(*args,data=None): return subprocess.check_output(['git','-C',str(repo),*args],input=data)
 def commit(tree,parents=()):
  raw='tree '+tree+'\n'+''.join('parent '+p+'\n' for p in parents)+'author A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\nrecord\n'
  return git('hash-object','-t','commit','-w','--stdin',data=raw.encode()).decode().strip()
 tree=git('mktree',data=b'').decode().strip(); subject=commit(tree)
 check='check\ud800\x00😀'; key='input\udfff\x00😀'
 valid={'_type':o['STATEMENT_TYPE'],'predicateType':o['PREDICATE_TYPE'],'subject':[{'name':subject,'digest':{'gitTree':tree}}],
 'predicate':{'schema_version':1,'change_id':'change\ud800','tier':'full','signer':None,'observed_at':'2026-01-01T00:00:00Z',
 'observed':{'kind':'tests','runner':'observed','inputs':{key:'value\udcff\x00😀'},'checks':{check:{'command':['test','\ud800','\x00','😀'],'exit_code':0,'output_sha256':'a'*64}}}}}
 extras=['null','true','false','1234567890123456789012345678901234567890','-0','-0.0','1.25','1e309','-Infinity','NaN','"\\ud800\\udfff\\u0000😀"','{"\\ud800":[null,true,9999999999999999999999999,-0.0],"x":1,"x":2}','[[{"\\udfff":"\\ud800"}]]']
 for extra in extras:
  for encoding in ['utf-8','utf-16','utf-32']:
   text=json.dumps(valid)[:-1]+',"extra":'+extra+'}'
   blob=git('hash-object','-w','--stdin',data=text.encode(encoding)).decode().strip()
   record_tree=git('mktree',data=f'100644 blob {blob}\t{tree}\n'.encode()).decode().strip(); record=commit(record_tree,[subject])
   doc=o['read_statement'](str(repo),record,tree); assert doc is not None
   loaded=o['load'](str(repo),record,tree); assert tagged(doc)==tagged(loaded)
   observed=doc['predicate']['observed']
   cases.append(dict(repo=str(repo),record=record,tree=tree,document=tagged(doc),check=[ord(c) for c in check],command=[[ord(c) for c in s] for s in observed['checks'][check]['command']],inputs=[[[ord(c) for c in k],[ord(c) for c in v]] for k,v in observed['inputs'].items()]))
print(json.dumps(cases))
"#;
    let oracle = std::env::var_os("MERGEMASTER_PYTHON_ORACLE").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let out = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(oracle)
        .arg(temp.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    let mut cache = RecordCache::for_check();
    for case in &cases {
        let repo = Path::new(case["repo"].as_str().unwrap());
        let record = case["record"].as_str().unwrap();
        let tree = case["tree"].as_str().unwrap();
        let document = read_statement(repo, record, Some(tree)).unwrap().unwrap();
        assert_eq!(tagged(&document, document.root()), case["document"]);
        let loaded = cache.load(repo, record, Some(tree)).unwrap().unwrap();
        assert_eq!(tagged(&loaded, loaded.root()), case["document"]);
        let again = cache.load(repo, record, Some(tree)).unwrap().unwrap();
        assert!(Arc::ptr_eq(&loaded, &again));
        let check: Vec<u32> = serde_json::from_value(case["check"].clone()).unwrap();
        let facts = DocumentFacts::for_check(&loaded, &check, "host/test").unwrap();
        assert_eq!(json!(facts.check_name), case["check"]);
        assert_eq!(json!(facts.command().collect::<Vec<_>>()), case["command"]);
        assert_eq!(
            json!(facts.inputs.unwrap().iter().collect::<Vec<_>>()),
            case["inputs"]
        );
        assert_eq!(
            facts.runner,
            "observed".chars().map(u32::from).collect::<Vec<_>>()
        );
        assert_eq!(facts.exit_code, "0");
    }
    assert_eq!(cases.len(), 78);
}
