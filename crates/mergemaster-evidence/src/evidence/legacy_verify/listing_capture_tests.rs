use super::super::{
    selection,
    source_resource::{LISTING_BYTES, SourceResource},
};
use super::*;
#[test]
fn whole_listings_stop_at_sixty_four_mib_with_exact_tree_identity() {
    let tree = "a".repeat(40);
    if let Ok(case) = std::env::var("MM_LISTING_CASE") {
        let size: usize = std::env::var("MM_LISTING_SIZE").unwrap().parse().unwrap();
        let result = match case.as_str() {
            "selector" => selection::selector_item(Path::new("."), &tree, ".st/x.json::x")
                .map(|got| assert!(got.is_none())),
            "exists" => selection::selected_content(Path::new("."), &tree, "x.json::x")
                .map(|got| assert_eq!(got.unwrap(), b"{}")),
            _ => project(Path::new("."), &tree, &[".".into(), "!excluded".into()])
                .map(|got| assert!(got.is_none())),
        };
        if size > LISTING_BYTES {
            let error = result.unwrap_err();
            assert_eq!(
                error.resource,
                Some(SourceResource::TreeListing(tree.clone().into()))
            );
            assert_eq!(
                error.detail.to_string(),
                format!("{tree} exceeds 67108864 bytes")
            );
            assert_eq!(
                error.origin,
                crate::evidence::legacy_policy::ErrorOrigin::Failure
            );
            assert_eq!(error.reason, "error");
        } else {
            result.unwrap();
        }
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import os,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p if p.is_dir() else p.parent.parent
m=runpy.run_path(str(p/'scripts/evidence-verify'))
shim=pathlib.Path(sys.argv[1]);program=shim/'git'
program.write_text('#!'+sys.executable+'''\nimport os,sys
if 'show' in sys.argv:os.write(1,b'{"x":{}}')
else:
 header=b'100644 blob '+b'a'*40+b'\\texcluded/'
 os.write(1,header)
 remaining=int(os.environ['MM_LISTING_SIZE'])-len(header)-1
 while remaining:
  sent=os.write(1,b'x'*min(65536,remaining));remaining-=sent
 os.write(1,b'\\0')
''');program.chmod(0o700)
os.environ['PATH']=str(shim)
for size in [67108864,67108865]:
 os.environ['MM_LISTING_SIZE']=str(size)
 assert m['project']('.', 'a'*40,['.','!excluded']) is None
 assert m['selector_item']('.', 'a'*40,'.st/x.json::x') is None
 assert m['selected_content']('.', 'a'*40,'x.json::x')==b'{}'
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for case in ["project", "selector", "exists"] {
        for size in [LISTING_BYTES, LISTING_BYTES + 1] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "evidence::legacy_verify::projection::listing_capture_tests::whole_listings_stop_at_sixty_four_mib_with_exact_tree_identity", "--nocapture"])
                .env("PATH", root.path()).env("MM_LISTING_CASE", case).env("MM_LISTING_SIZE", size.to_string()).output().unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
