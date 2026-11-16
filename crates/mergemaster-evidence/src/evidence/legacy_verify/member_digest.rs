//! Oracle's combined member sampling key. SHA-1 is parity, not security.
use sha1::{Digest, Sha1};

/// Members must already be sorted by crate name, as verify_members iterates them.
/// Stream UTF-8 `crate=key` lines with separators, never a final newline or an
/// allocated joined buffer. Git SHA1/SHA256 keys are both hashed with SHA-1 here.
pub fn combined_sorted_key<'a>(members: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut hash = Sha1::new();
    for (i, (name, key)) in members.into_iter().enumerate() {
        if i != 0 {
            hash.update(b"\n");
        }
        hash.update(name.as_bytes());
        hash.update(b"=");
        hash.update(key.as_bytes());
    }
    hex::encode(hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    #[test]
    fn combined_key_vectors_match_oracle_join_and_python_hashlib() {
        let script = r#"
import ast,hashlib,json,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(sys.argv[1])/'scripts/evidence-verify'; module=ast.parse(p.read_text())
f=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='verify_members')
expression=next(n.value for n in f.body if isinstance(n,ast.Assign) and ast.unparse(n.targets[0])=='combined')
code=compile(ast.Expression(expression),str(p),'eval'); cases=[]
for members in [{},{'a':'a'*40},{'z':'b'*64,'a':'a'*40,'é😀':'c'*40},{'😀':'f'*64,'é':'e'*64,'a':'d'*64}]:
 joined='\n'.join(f'{crate}={key}' for crate,key in sorted(members.items()))
 expected=eval(code,dict(hashlib=hashlib,members=members))
 assert expected==hashlib.sha1(joined.encode()).hexdigest()
 cases.append(dict(pairs=sorted(members.items()),joined=joined,expected=expected))
print(json.dumps(cases))
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
        let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        for case in &cases {
            let pairs: Vec<_> = case["pairs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| (p[0].as_str().unwrap(), p[1].as_str().unwrap()))
                .collect();
            let joined = pairs
                .iter()
                .map(|(n, k)| format!("{n}={k}"))
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(joined, case["joined"]);
            assert_eq!(combined_sorted_key(pairs), case["expected"]);
        }
        assert_eq!(cases.len(), 4);
        assert_eq!(
            combined_sorted_key([]),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }
}
