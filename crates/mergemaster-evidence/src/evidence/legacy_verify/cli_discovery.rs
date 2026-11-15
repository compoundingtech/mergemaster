//! CLI ref discovery preserves oracle row and prefix order without whole listings.
use crate::evidence::legacy_policy::{PolicyError, check_names::CheckName};
use indexmap::IndexSet;
use std::path::Path;

pub fn records_under(repo: &Path, prefixes: &[String]) -> Result<Vec<String>, PolicyError> {
    let mut found = IndexSet::new();
    for prefix in prefixes {
        found.extend(super::projection::read_ref_ids_with_pattern::<
            IndexSet<String>,
        >(repo, prefix, prefix.trim_end_matches('/'))?);
    }
    Ok(found.into_iter().collect())
}
pub fn legacy_refs(repo: &Path, width: usize) -> Result<Vec<String>, PolicyError> {
    let prefix = "refs/notes/evidence/";
    super::projection::read_ref_ids_with_pattern::<IndexSet<String>>(
        repo,
        prefix,
        &format!("{prefix}{}", "?".repeat(width)),
    )
    .map(|ids| ids.into_iter().collect())
}
pub fn tree_refs(repo: &Path, tree: &str) -> Result<Vec<String>, PolicyError> {
    records_under(
        repo,
        &[
            format!("refs/tags/evidence/{tree}/"),
            format!("refs/notes/evidence/{tree}/"),
        ],
    )
}
pub fn input_refs<'a>(
    repo: &Path,
    check: impl Into<CheckName<'a>>,
    key: &str,
) -> Result<Vec<String>, PolicyError> {
    super::discovery::input_refs_with(repo, check.into(), key, records_under)
}
/// One oracle batch-check; only complete lowercase OIDs may enter its echo rows.
pub fn with_note_for<'a>(
    repo: &Path,
    commits: &'a [String],
    tree: &str,
) -> Result<Vec<&'a str>, PolicyError> {
    if commits.is_empty() {
        return Ok(Vec::new());
    }
    for value in std::iter::once(tree).chain(commits.iter().map(String::as_str)) {
        crate::evidence::oid(value).map_err(|e| super::crate_inputs::failure(e.to_string()))?;
    }
    let mut input = Vec::with_capacity(commits.len() * (tree.len() + 66));
    for commit in commits {
        input.extend_from_slice(commit.as_bytes());
        input.push(b':');
        input.extend_from_slice(tree.as_bytes());
        input.push(b'\n');
    }
    let mut command = super::projection::projection_command(repo, &["cat-file", "--batch-check"])?;
    let present = super::projection_capture::note_presence(&mut command, &input, commits.len())?;
    Ok(commits
        .iter()
        .zip(present)
        .filter_map(|(c, found)| found.then_some(c.as_str()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    #[test]
    fn ordered_ref_indexes_match_real_git_oracle() {
        let root = tempfile::tempdir().unwrap();
        let script = r#"
import json,os,pathlib,runpy,subprocess,sys
m=runpy.run_path(os.environ['MERGEMASTER_PYTHON_ORACLE']+'/scripts/evidence-verify');cases=[]
for fmt in ['sha1','sha256']:
 repo=pathlib.Path(sys.argv[1])/fmt;subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
 def git(*args,data=None):return subprocess.check_output(['git','-C',str(repo),*args],input=data).decode().strip()
 tree=git('mktree',data=b'')
 ids=[git('hash-object','-t','commit','-w','--stdin',data=('tree '+tree+'\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\n'+str(n)).encode()) for n in range(3)]
 tags='refs/tags/evidence/'+tree+'/';notes='refs/notes/evidence/'+tree+'/'
 inputs='refs/tags/evidence/input/check/'+tree+'/'
 for prefix,objects in [(tags,ids[:2]),(notes,ids[1:]),('refs/notes/evidence/',ids),(inputs,ids[:1]),('refs/notes/evidence-input/check/'+tree+'/',ids[1:])]:
  for oid in objects:git('update-ref',prefix+oid,oid)
 # A ref with the right-shaped suffix but the wrong target must be ignored.
 git('update-ref',tags+'f'*len(tree),ids[0])
 for mode,arg,extra in [(0,[notes,tags,notes],None),(0,[],None),(1,len(tree),None),(2,tree,None),(2,'0'*len(tree),None),(3,'check',tree),(3,'bad check',tree),(3,'check','bad'),(3,chr(0xd800),tree)]:
  result=([m['records_under'],m['legacy_refs'],m['tree_refs']][mode](str(repo),arg) if mode<3 else m['input_refs'](str(repo),arg,extra))
  cases.append([str(repo),mode,list(map(ord,arg)) if mode==3 else arg,extra,result])
 assert any(c[1]==3 and c[4] for c in cases)
print(json.dumps(cases))
"#;
        let output = crate::pinned_python::command()
            .args(["-c", script])
            .arg(root.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        for case in cases {
            let repo = Path::new(case[0].as_str().unwrap());
            let actual = match case[1].as_u64().unwrap() {
                0 => records_under(
                    repo,
                    &serde_json::from_value::<Vec<String>>(case[2].clone()).unwrap(),
                ),
                1 => legacy_refs(repo, case[2].as_u64().unwrap() as usize),
                2 => tree_refs(repo, case[2].as_str().unwrap()),
                _ => {
                    let points: Vec<u32> = serde_json::from_value(case[2].clone()).unwrap();
                    input_refs(repo, points.as_slice(), case[3].as_str().unwrap())
                }
            };
            assert_eq!(json!(actual.unwrap()), case[4]);
        }
    }
}
