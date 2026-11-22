use super::*;
use serde_json::{Value, json};

#[test]
fn validates_whole_batch_and_refuses_nested_batches() {
    for text in [
        "",
        "{}",
        "null",
        "[NaN]",
        "[[\"--help\"],[1]]",
        "[\"--tree\"]",
        "[[true]]",
    ] {
        let answer = run(text.as_bytes()).unwrap();
        assert_eq!(answer.code, 2, "{text}");
        assert!(answer.stdout.is_empty());
        assert_eq!(
            answer.stderr,
            "--batch reads a JSON array of argument vectors, each an array of strings, on standard input\n"
        );
    }
    assert_eq!(run(b"[]").unwrap().stdout, "[]\n");
    let answer = run(br#"[["--batch"],["--batch","--help"],["--help"],[]]"#).unwrap();
    assert_eq!(answer.code, 0);
    assert!(answer.stderr.is_empty());
    let rows: Value = serde_json::from_str(&answer.stdout).unwrap();
    for row in &rows.as_array().unwrap()[..2] {
        assert_eq!(
            row,
            &json!({"exit":2,"stdout":"","stderr":"--batch cannot be nested\n"})
        );
    }
    assert_eq!(rows[2]["exit"], 0);
    assert_eq!(rows[3]["exit"], 2);
    // Batch-only dispatch is exact and leading: argparse itself is unchanged.
    for args in [["--batch", "--help"], ["--batch", "--batch"]] {
        let exit = super::super::cli_dispatch::run(args.map(std::ffi::OsString::from)).unwrap();
        assert_eq!(exit.code, 2);
        assert_eq!(
            exit.stderr,
            "--batch takes no other argument: each run's arguments come on standard input\n"
        );
    }
}

#[test]
fn lossless_json_arguments_keep_single_run_diagnostics() {
    let answer = run(
        br#"[["--tree","HEAD","--check","\udcff"],["--tree","HEAD","--check","\ud800"],["--help"]]"#,
    )
    .unwrap();
    let rows: Value = serde_json::from_str(&answer.stdout).unwrap();
    for (index, point) in [0xdcff, 0xd800].into_iter().enumerate() {
        let check = [point];
        let expected = super::super::cli_dispatch::run_arguments(&[
            TextRef::Str("--tree"),
            TextRef::Str("HEAD"),
            TextRef::Str("--check"),
            TextRef::Points(&check),
        ])
        .unwrap();
        assert_eq!(
            rows[index],
            json!({"exit":expected.code,"stdout":expected.stdout,"stderr":expected.stderr})
        );
    }
    assert_eq!(rows[2]["exit"], 0);
}

#[test]
fn raw_batch_stdin_uses_surrogateescape_inside_strings_only() {
    use std::{
        ffi::OsString,
        io::Write as _,
        os::unix::ffi::OsStringExt,
        process::{Command, Stdio},
    };
    if let Ok(case) = std::env::var("MM_RAW_BATCH_DRIVER") {
        let answer = super::super::cli_dispatch::run([OsString::from("--batch")]).unwrap();
        assert!(answer.stderr.is_empty() || case == "outside");
        match case.as_str() {
            "inside" => {
                assert_eq!(answer.code, 0);
                assert_eq!(
                    answer.stdout,
                    "[{\"exit\": 2, \"stdout\": \"\", \"stderr\": \"one of --keys or --keys-from is required\\n\"}]\n"
                );
                assert!(answer.stderr.is_empty());
            }
            "outside" => {
                assert_eq!(answer.code, 2);
                assert!(answer.stdout.is_empty());
                assert_eq!(
                    answer.stderr,
                    "--batch reads a JSON array of argument vectors, each an array of strings, on standard input\n"
                );
            }
            "echo" => {
                let standalone = super::super::cli_dispatch::run(
                    [
                        b"--tree".as_slice(),
                        b"HEAD",
                        b"--check",
                        b"\xff",
                        b"--keys",
                        b"unused",
                    ]
                    .map(|bytes| OsString::from_vec(bytes.to_vec())),
                )
                .unwrap();
                let rows: Value = serde_json::from_str(&answer.stdout).unwrap();
                assert_eq!(answer.code, 0);
                assert_eq!(
                    rows,
                    json!([{"exit":standalone.code,"stdout":standalone.stdout,"stderr":standalone.stderr}])
                );
                assert!(answer.stdout.contains(r"\\udcff"), "{}", answer.stdout);
            }
            _ => panic!("unknown raw batch test case"),
        }
        return;
    }
    for (case, input) in [
        (
            "inside",
            b"[[\"--tree\",\"HEAD\",\"--check\",\"\xff\"]]".as_slice(),
        ),
        ("outside", b"[[\"--help\"],\xff]".as_slice()),
        (
            "echo",
            b"[[\"--tree\",\"HEAD\",\"--check\",\"\xff\",\"--keys\",\"unused\"]]".as_slice(),
        ),
    ] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "evidence::legacy_verify::cli_batch::tests::raw_batch_stdin_uses_surrogateescape_inside_strings_only",
                "--nocapture",
            ])
            .env("MM_RAW_BATCH_DRIVER", case)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn capture_batch_surface_divergence() {
    let python = crate::pinned_python::command().arg("-c").arg(
        "import os,subprocess,sys; p=subprocess.run([sys.executable,'-I',os.environ['MERGEMASTER_PYTHON_ORACLE']+'/scripts/evidence-verify','--batch','--help'],capture_output=True); import json; print(json.dumps(dict(exit=p.returncode,stdout=p.stdout.decode(),stderr=p.stderr.decode())))"
    ).output().unwrap();
    assert!(python.status.success(), "{:?}", python.stderr);
    let python: Value = serde_json::from_slice(&python.stdout).unwrap();
    let rust = super::super::cli_dispatch::run(["--batch", "--help"].map(std::ffi::OsString::from))
        .unwrap();
    let rust = json!({"exit":rust.code,"stdout":rust.stdout,"stderr":rust.stderr});
    assert_ne!(python, rust);
    super::super::divergence_witnesses::capture(
        "verifier-multi-check-batch",
        json!({"argv":["--batch","--help"]}),
        python,
        rust,
    );
}

#[test]
fn signed_batch_matches_standalone_and_reuses_only_immutable_facts() {
    if let Some(root) = std::env::var_os("MM_BATCH_DRIVER") {
        let root = std::path::PathBuf::from(root);
        let input = std::fs::read(root.join("input")).unwrap();
        let answer = run(&input).unwrap();
        assert_eq!(answer.code, 0);
        assert!(answer.stderr.is_empty());
        std::fs::write(root.join("answer"), answer.stdout).unwrap();
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import datetime,json,os,pathlib,runpy,shutil,subprocess,sys
root=pathlib.Path(sys.argv[1]);exe=sys.argv[2];source=pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify';v=runpy.run_path(str(source));repo=root/'repo';repo.mkdir()
def git(*a,data=None):return subprocess.check_output(['git','-C',str(repo),*a],input=data,stderr=subprocess.PIPE).decode().strip()
git('init');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid');git('config','maintenance.auto','false');git('config','gc.auto','0')
key=root/'ci';foreign=root/'foreign'
for p in [key,foreign]:subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(p)],check=True)
trusted='machine/ci '+key.with_suffix('.pub').read_text();(repo/'.st').mkdir();(repo/'.st/evidence-keys').write_text(trusted)
lanes=dict(version=1,lanes={'unit':dict(argv=['make','test'],definition_paths=['run.sh'])});(repo/'.st/required-lanes.json').write_text(json.dumps(lanes));(repo/'run.sh').write_text('one')
def step(name,content):
 (repo/name).write_text(content);git('add','.');git('commit','-m','step');return git('rev-parse','HEAD'),git('rev-parse','HEAD^{tree}')
base,_=step('code','base');main,_=step('run.sh','main');revoked,_=step('.st/evidence-keys','');git('checkout','--detach',base)
commit,tree=step('code','branch');digest=v['lane_for'](str(repo),tree,(json.dumps(lanes),main),'unit',base)['sha256']
def note(commit,tree,key,check='unit',exit=0,sign=True):
 statement=dict(_type=v['STATEMENT_TYPE'],predicateType=v['PREDICATE_TYPE'],subject=[dict(name=commit,digest=dict(gitTree=tree))],predicate=dict(schema_version=1,tier='full',change_id='fixture',signer='machine/ci',observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),observed=dict(kind='tests',runner='nix',inputs={'lane_definition_sha256':digest},checks={check:dict(command=['make','test'],exit_code=exit,output_sha256='0'*64)})))
 blob=git('hash-object','-w','--stdin',data=json.dumps(statement).encode());nt=git('mktree',data=('100644 blob '+blob+'\t'+tree+'\n').encode());record=git('-c','gpg.format=ssh','-c','user.signingkey='+str(key),'commit-tree',*(['-S'] if sign else []),nt,'-p',commit,data=b'note');git('update-ref','refs/tags/evidence/'+tree+'/'+record,record);return record
first=note(commit,tree,key);second=note(commit,tree,key,'lint',1)
c,t=step('code','unsigned');third=note(c,t,key,sign=False);unsigned=t
c,t=step('code','foreign');fourth=note(c,t,foreign);foreign_tree=t
_,bare=step('code','bare')
def unit(t=tree,b=main):return ['--repo',str(repo),'--tree',t,'--check','unit','--keys-from',b]
lane=['--lanes-from',main,'--command','["make", "test"]'];good=unit()+lane+['--lane-base',base]
runs=[good,unit(unsigned),unit(b=revoked),unit(foreign_tree),unit()+lane,unit()+['--check','lint'],unit()+['--check','absent'],unit(bare),good,unit(b=revoked)+lane+['--lane-base',base],['--repo',str(repo),'--tree',tree,'--keys-from',main],unit()+['--members']]
expected=[]
for argv in runs:
 done=subprocess.run([sys.executable,'-I',str(source),*argv],capture_output=True);expected.append(dict(exit=done.returncode,stdout=done.stdout.decode(),stderr=done.stderr.decode()))
assert [r['exit'] for r in expected[:11]]==[0,1,1,1,1,1,1,1,0,1,2],expected
assert [json.loads(r['stdout']).get('reason') for r in expected[:10]]==[None,'bad_signature','untrusted_signer','untrusted_signer','definition_changed','check_failed','wrong_check','no_record',None,'untrusted_signer']
(root/'input').write_text(json.dumps(runs));shim=root/'shim';shim.mkdir();real=shutil.which('git');count=root/'count'
(shim/'git').write_text('#!'+sys.executable+'\nimport os,sys\na=sys.argv[1:]\nif "--format=%G?%x00%GS" in a or ("ls-tree" in a and a[-1] in '+repr([first,second,third,fourth])+'):\n with open('+repr(str(count))+',"a") as f:f.write(("signature" if "--format=%G?%x00%GS" in a else "statement")+"\\n")\nos.execv('+repr(real)+',['+repr(real)+',*a])\n');(shim/'git').chmod(0o700)
env=dict(os.environ,MM_BATCH_DRIVER=str(root),PATH=str(shim)+os.pathsep+os.environ['PATH'])
child=subprocess.run([exe,'--exact','evidence::legacy_verify::cli_batch::tests::signed_batch_matches_standalone_and_reuses_only_immutable_facts','--nocapture'],env=env,capture_output=True)
assert child.returncode==0,(child.stdout,child.stderr)
answers=json.loads((root/'answer').read_text());assert answers==expected,(answers,expected)
counts=count.read_text().splitlines();assert counts.count('signature')==6,counts # two good records against two key lists, unsigned, foreign
assert counts.count('statement')==4,counts # four immutable records, across all questions
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .arg(root.path())
        .arg(std::env::current_exe().unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
