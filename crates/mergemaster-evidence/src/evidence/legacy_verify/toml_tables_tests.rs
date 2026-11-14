use super::*;
use serde_json::{Value as Json, json};

fn path(value: &Json) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn namespaces_match_pinned_python() {
    let script = r#"
import copy,json,sys,tomllib._parser as p
assert sys.version_info[:3]==(3,14,7)
keys=[(),('a',),('a','b'),('a','b','c'),('a','other'),('x',),('',),('🦀',)]
f=p.Flags(); flags=[]
def flag_step(op,key=(),flag=0,recursive=False):
 if op=='set': f.set(key,flag,recursive=recursive)
 elif op=='pending': f.add_pending(key,flag)
 elif op=='unset': f.unset_all(key)
 else: f.finalize_pending()
 flags.append(dict(op=op,key=key,flag=flag,recursive=recursive,
                   expected=[[f.is_(k,t) for t in (0,1)] for k in keys]))
for recursive in (False,True):
 for flag in (0,1):
  flag_step('set',('a','b'),flag,recursive)
  flag_step('set',('a',),1-flag,recursive)
  flag_step('unset',('a','b'))
  flag_step('unset',('a',))
flag_step('unset',('absent','child'))
for key in keys[1:]:
 flag_step('pending',key,0)
 flag_step('pending',key,0)
flag_step('unset',('a',))
flag_step('finalize')
flag_step('finalize')
flag_step('unset',('a',))
flag_step('set',('a',),1,True)
flag_step('pending',('a','b'),0)
flag_step('unset',('a',))
flag_step('finalize')
print(json.dumps(dict(keys=keys,flags=flags)))
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
    let fixture: Json = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(fixture["flags"].as_array().unwrap().len(), 39);
    let mut flags = Flags::default();
    for step in fixture["flags"].as_array().unwrap() {
        let key = path(&step["key"]);
        let flag = if step["flag"] == 0 {
            Flag::Frozen
        } else {
            Flag::ExplicitNest
        };
        match step["op"].as_str().unwrap() {
            "set" => flags.set(&key, flag, step["recursive"].as_bool().unwrap()),
            "pending" => flags.add_pending(&key, flag),
            "unset" => flags.unset_all(&key),
            "finalize" => flags.finalize_pending(),
            _ => panic!("invalid flag operation"),
        }
        let actual: Vec<_> = fixture["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| {
                let key = path(key);
                [
                    flags.is(&key, Flag::Frozen),
                    flags.is(&key, Flag::ExplicitNest),
                ]
            })
            .collect();
        assert_eq!(json!(actual), step["expected"], "{step}");
    }
    flags.set(&[], Flag::Frozen, true);
    flags.unset_all(&[]);
    flags.add_pending(&[], Flag::ExplicitNest);
    flags.finalize_pending();
    assert!(!flags.is(&[], Flag::Frozen));
    assert!(!flags.is(&[], Flag::ExplicitNest));
}
