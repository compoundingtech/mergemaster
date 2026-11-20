use super::*;
use crate::evidence::legacy_policy::ErrorOrigin;
use serde_json::Value as Json;
#[test]
fn closure_caps_charge_uncached_manifests_before_reads_and_preserve_cache_hits() {
    let repo = tempfile::tempdir().unwrap();
    let script = r#"
import importlib.machinery,importlib.util,json,pathlib,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
l=importlib.machinery.SourceFileLoader('keys',sys.argv[1]);s=importlib.util.spec_from_loader('keys',l);m=importlib.util.module_from_spec(s);l.exec_module(m)
repo=pathlib.Path(sys.argv[2])
def git(*a):return subprocess.check_output(['git','-C',str(repo),*a],stderr=subprocess.PIPE).decode().strip()
def put(name,text):
 p=repo/name/'Cargo.toml';p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
git('init')
for i in range(1051):put('c'+str(i),'[dependencies]\nx={path="../c'+str(i+1)+'"}' if i<1050 else '')
for i in range(1024):put('leaf'+str(i),'')
for count in [1024,1025]:put('wide'+str(count),'[dependencies]\n'+'\n'.join('x'+str(i)+'={path="../leaf'+str(i)+'"}' for i in range(count-1)))
put('bad','target=1');put('cycle','[dependencies]\nx={path="../cycle"}')
git('add','.');tree=git('write-tree')
# Measurement only: never assert a CPython stack boundary in the acceptance matrix.
seen=[];original=m.manifest
def measured(*args):seen.append(args[2]);return original(*args)
m.manifest=measured
try:m.closure(repo,tree,'c0',{},{});measurement=dict(outcome='accepted',manifests=len(seen))
except RecursionError:measurement=dict(outcome='RecursionError',manifests=len(seen),recursionlimit=sys.getrecursionlimit())
m.manifest=original
# Boundary oracle acceptance must not depend on the interpreter's default stack depth.
sys.setrecursionlimit(10000)
rows=[]
for name in ['c795','c794','wide1024','wide1025','cycle']:
 cache={};m.closure(repo,tree,name,{},cache)
 rows.append(dict(name=name,count=len(cache),paths=sorted(cache[name])))
print(json.dumps(dict(tree=tree,measurement=measurement,rows=rows)))
"#;
    let oracle = crate::pinned_python::keys_oracle();
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .arg(oracle)
        .arg(repo.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixture: Json = serde_json::from_slice(&output.stdout).unwrap();
    eprintln!("CLOSURE_ORACLE_MEASUREMENT {}", fixture["measurement"]);
    let source = TreeSource {
        repo: repo.path(),
        tree: fixture["tree"].as_str().unwrap(),
        no_lazy_fetch: true,
    };
    for row in fixture["rows"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let mut cache = ClosureCache::default();
        let result = source.closure(name, None, &mut cache);
        let resource = match name {
            "c794" => Some(SourceResource::PathDependencyDepth),
            "wide1025" => Some(SourceResource::PathDependencyCrates),
            _ => None,
        };
        if let Some(resource) = resource {
            let error = result.unwrap_err();
            assert_eq!(error.origin, ErrorOrigin::Failure);
            assert_eq!(error.reason, "error");
            assert_eq!(error.detail, resource.detail());
            assert_eq!(error.resource, Some(resource));
            assert_eq!(cache.entries.len(), if name == "c794" { 256 } else { 1024 });
        } else {
            result.unwrap();
            assert_eq!(cache.entries.len(), row["count"].as_u64().unwrap() as usize);
            assert_eq!(
                serde_json::json!(cache.paths(name).unwrap().iter().collect::<Vec<_>>()),
                row["paths"]
            );
        }
        // Already cached roots are not read or charged, even after a capped partial walk.
        source.closure(name, None, &mut cache).unwrap();
    }
    let mut cache = ClosureCache::default();
    source.closure("wide1024", None, &mut cache).unwrap();
    source.closure("leaf0", None, &mut cache).unwrap();
    let error = source.closure("bad", None, &mut cache).unwrap_err();
    assert_eq!(error.resource, Some(SourceResource::PathDependencyCrates));
    assert!(!cache.entries.contains_key("bad"));
    let mut cache = ClosureCache::default();
    assert!(
        source
            .closure("bad", None, &mut cache)
            .unwrap_err()
            .resource
            .is_none()
    );
    assert!(cache.entries.contains_key("bad"));
    source.closure("bad", None, &mut cache).unwrap();
    // A cached deep tail avoids descent: the resulting reachable set can exceed depth256.
    let mut cache = ClosureCache::default();
    source.closure("c795", None, &mut cache).unwrap();
    source.closure("c794", None, &mut cache).unwrap();
    assert_eq!(cache.paths("c794").unwrap().len(), 257);
}
