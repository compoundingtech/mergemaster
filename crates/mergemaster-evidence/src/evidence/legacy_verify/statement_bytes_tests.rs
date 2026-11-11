use super::decode_json_bytes;
#[test]
fn legacy_statement_bytes_match_python_transport() {
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned Python oracle required");
    let script = r#"
import copy,json,runpy,sys
oracle=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
tree='a'*40
valid={'_type':oracle['STATEMENT_TYPE'],'predicateType':oracle['PREDICATE_TYPE'],
 'subject':[{'name':'b'*40,'digest':{'gitTree':tree}}],
 'predicate':{'schema_version':1,'change_id':'change🌍','tier':'full','signer':None,
 'observed_at':'2026-01-01T00:00:00Z','observed':{'kind':'tests','runner':'wrapper',
 'checks':{'check':{'command':[''],'exit_code':0,'output_sha256':'c'*64}}}}}
text=json.dumps(valid,ensure_ascii=False)
cases=[]
for encoding in ['utf-8','utf-8-sig','utf-16','utf-16-le','utf-16-be','utf-32','utf-32-le','utf-32-be']:
 cases.append(('valid-'+encoding,text.encode(encoding)))
for encoding,bom in [('utf-16-be',b'\xfe\xff'),('utf-32-be',b'\0\0\xfe\xff')]:
 cases.append(('valid-bom-'+encoding,bom+text.encode(encoding)))
boundary=json.dumps('x'+''.join(map(chr,[0,0x7f,0x80,0x7ff,0x800,0xd7ff,0xd800,0xdbff,0xdc00,0xdfff,0xe000,0xffff,0x10000,0x10ffff])),ensure_ascii=False)
for encoding in ['utf-8','utf-16-le','utf-16-be','utf-32-le','utf-32-be']:
 cases.append(('boundaries-'+encoding,boundary.encode(encoding,'surrogatepass')))
for name,value in [('surrogate-value','\ud800'),('surrogate-key','\udfff'),('nan',float('nan')),('infinity',float('inf')),('negative-infinity',-float('inf'))]:
 v=copy.deepcopy(valid)
 if name=='surrogate-key': v[value]='kept'
 else: v['extra']=value
 for encoding in ['utf-8','utf-16-le','utf-32-be']:
  cases.append((name+'-'+encoding,json.dumps(v,ensure_ascii=False).encode(encoding,'surrogatepass')))
for name,data in {
 'empty':'','utf8-bom-only':'efbbbf','utf16-bom-only':'fffe','utf32-bom-only':'fffe0000',
 'short-be':'0030','short-le':'3000','three-byte-nul':'003030','four-byte-nul':'00003030',
 'odd-utf16':'fffe30','truncated-utf32':'fffe00003000','utf32-too-large':'fffe000000001100',
 'utf8-overlong':'c080','utf8-overlong-three':'e08080','utf8-overlong-four':'f0808080',
 'utf8-too-large':'f4908080','utf8-truncated':'f09f8c','utf8-continuation':'80',
 'utf8-high-surrogate':'eda080','utf8-low-surrogate':'edbfbf','utf8-surrogate-pair':'eda080edb080',
 'utf16-high-surrogate':'fffe00d8','utf16-low-surrogate':'fffeffdf','utf16-pair':'fffe00d800dc',
 'utf16-unpaired-then-ascii':'fffe00d86100','utf32-surrogate':'0000feff0000d800',
 'utf8-double-bom':'efbbbfefbbbf','utf16-double-bom':'fffefffe','utf32-double-bom':'fffe0000fffe0000'
}.items(): cases.append((name,bytes.fromhex(data)))
for count in [4300,4301]: cases.append(('integer-'+str(count),(text[:-1]+',"extra":'+'9'*count+'}').encode()))
for depth in [101,256,257,497,498,2001]: cases.append(('depth-'+str(depth),(text[:-1]+',"extra":'+'['*(depth-1)+'0'+']'*(depth-1)+'}').encode()))
for field in ['change_id','signer','runner','command','inputs','checks','observed_at']:
 v=copy.deepcopy(valid); p=v['predicate']; o=p['observed']
 if field=='observed_at': p[field]='2026-01-01\ud80012:30Z'
 elif field in ['change_id','signer']: p[field]='\ud800'
 elif field=='command': o['checks']['check'][field]=['\ud800','']
 elif field=='inputs': o[field]={'\ud800':'\udfff'}
 elif field=='checks': o[field]={'\udfff':o[field]['check']}
 else: o[field]='\ud800'
 cases.append(('guard-surrogate-'+field,json.dumps(v).encode()))
for suffix in ['x','{}',',','\u00a0']:
 cases.append(('extra-'+repr(suffix),(text+suffix).encode()))
results=[]
for name,blob in cases:
 try: points=list(map(ord,blob.decode(json.detect_encoding(blob),'surrogatepass')))
 except UnicodeError: points=None
 try: statement=oracle['statement_of'](blob,tree) is not None
 except Exception as e: statement=type(e).__name__
 results.append(dict(name=name,bytes=list(blob),points=points,statement=statement))
print(json.dumps(results))
"#;
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
    for case in cases.as_array().unwrap() {
        let bytes: Vec<u8> = serde_json::from_value(case["bytes"].clone()).unwrap();
        let expected: Option<Vec<u32>> = serde_json::from_value(case["points"].clone()).unwrap();
        assert_eq!(decode_json_bytes(&bytes), expected, "{}", case["name"]);
        let actual = super::super::statement::statement_of(&bytes, &"a".repeat(40));
        let depth = case["name"]
            .as_str()
            .unwrap()
            .strip_prefix("depth-")
            .and_then(|d| d.parse::<usize>().ok())
            .unwrap_or(0);
        if depth > super::super::statement_document::MAX_CONTAINER_DEPTH {
            assert!(case["statement"].as_bool().unwrap());
            assert_eq!(actual.unwrap_err().reason, "statement-too-deep");
        } else {
            assert_eq!(
                actual.unwrap().is_some(),
                case["statement"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}
