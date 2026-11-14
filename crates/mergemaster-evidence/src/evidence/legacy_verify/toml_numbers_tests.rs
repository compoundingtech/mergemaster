use super::*;
use serde_json::{Value as Json, json};
#[test]
fn numeric_prefixes_match_pinned_tomllib_without_narrowing_integers() {
    let script = r#"
import json,struct,sys,tomllib._parser as p
assert sys.version_info[:3]==(3,14,7) and sys.get_int_max_str_digits()==4300
samples=[sign+integer+fraction+exponent for sign in ['','+','-'] for integer in ['0','00','1','01','1_0','1__0','9','9_',''] for fraction in ['','.','.0','.01','.1_2','._1','.1_'] for exponent in ['','e','e+','e-','e0','E+10','e1_0','e_1']]
samples+=['inf','-inf','+inf','nan','-nan','+nan','Inf','NaN']
samples += [prefix+digits for prefix in ['0x','0o','0b'] for digits in ['0','1','1_0','_1','9','f','F','1__0','1_','']]
samples += ['9'*4300,'9'*4301,'0x'+'f'*5000,'0b'+'1'*5000,'1e99999','-1e-99999','9_'*4300+'9']
cases=[]
for token in samples:
 for prefix in ['', '🦀 ']:
  text=prefix+token; start=len(prefix)
  try:
   match=p.RE_NUMBER.match(text,start)
   if match: end=match.end(); value=p.match_to_number(match,float)
   else:
    special=next((s for s in ['inf','nan','-inf','+inf','-nan','+nan'] if text.startswith(s,start)),None)
    if special is None: cases.append(dict(text=text,start=start,expected=None)); continue
    end=start+len(special); value=float(special)
   expected=dict(pos=end,kind='float',bits=struct.pack('>d',value).hex()) if isinstance(value,float) else dict(pos=end,kind='int',token=text[start:end])
  except ValueError as e: expected=dict(error=str(e),kind=type(e).__name__)
  cases.append(dict(text=text,start=start,expected=expected))
print(json.dumps(cases))
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
    assert_eq!(cases.len(), 3114);
    for case in cases {
        let src = Source::new(case["text"].as_str().unwrap());
        let actual = match &src.number(case["start"].as_u64().unwrap() as usize) {
            Ok(None) => Json::Null,
            Ok(Some((pos, Value::Integer(token)))) => json!({"pos":pos,"kind":"int","token":token}),
            Ok(Some((pos, Value::Float(number)))) => {
                json!({"pos":pos,"kind":"float","bits":format!("{:016x}",number.to_bits())})
            }
            Ok(_) => panic!("numeric scanner returned a non-number"),
            Err(e) => json!({"error":e.to_string(),"kind":e.kind.class()}),
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
}
