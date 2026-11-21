//! Receipt/text/formatting parity against the immutable evidence-skip-report.
#[path = "../src/pinned_python.rs"]
mod pinned_python;

use std::path::Path;

const DIFFERENTIAL: &str = r#"
import copy, datetime, json, os, pathlib, shutil, subprocess, sys, tempfile
repository, binary, suite = sys.argv[1:]
repository = pathlib.Path(repository)
fixture = json.loads((repository / 'tests/fixtures/oracle/skip-report.json').read_text())
base = fixture['cases'][0]
source = pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE']) / 'scripts/evidence-skip-report'

def compare(label, receipt=b'', mutate=lambda api: None, expected_seat=None, expected_minutes=None, expected_error=False):
    with tempfile.TemporaryDirectory(prefix='mergemaster-skip-parity-') as temporary:
        root = pathlib.Path(temporary)
        for tool in ('git','gh'):
            executable = root / tool
            executable.write_text('#!' + sys.executable + '\n' + fixture['shim'].replace("{'number': 17}", "{'number': api.get('fallback_number',17)}"))
            executable.chmod(0o700)
        api = copy.deepcopy(base['api'])
        mutate(api)
        (root/'api.json').write_text(json.dumps(api))
        (root/'receipts').write_bytes(receipt)
        environment = dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'],
                           FLIP_SKIP_API=str(root/'api.json'), FLIP_SKIP_CALLS=str(root/'calls'))
        for markdown in (False, True):
            arguments = ['--repo','org/repo','--cache',str(root/'cache'),
                         *[arg.replace('${root}',str(root)) for arg in base['argv']]]
            if markdown: arguments.append('--markdown')
            observations = []
            for implementation in ('python','native'):
                shutil.rmtree(root/'cache',ignore_errors=True)
                (root/'calls').write_text('')
                if expected_error and implementation == 'python': continue
                invocation = ([sys.executable,'-I','-B','-c',fixture['launcher'],str(source),fixture['now'],str(root),*arguments]
                              if implementation=='python' else [binary,'evidence','skip-report','--now',fixture['now'],*arguments])
                done = subprocess.run(invocation,cwd=root,env=environment,capture_output=True)
                context = (suite,label,markdown,implementation)
                if expected_error:
                    assert done.returncode != 0, (context,done.stdout,done.stderr)
                    assert b'outside schema' in done.stderr, (context,done.stderr)
                    continue
                assert done.returncode == 0, (context,done.returncode,done.stdout,done.stderr)
                assert done.stderr == b'', (context,done.stderr)
                if not markdown:
                    report = json.loads(done.stdout)
                    if expected_seat is not None:
                        assert report['not_signed'][0]['seat'] == expected_seat, (context,report)
                    if expected_minutes is not None:
                        assert report['release_surface']['minutes'] == expected_minutes, (context,report)
                observations.append(done.stdout)
            if not expected_error:
                assert observations[0] == observations[1], (suite,label,markdown,observations)

if suite == 'receipts':
    for literal in ('null','false','0','-0','0.0','-0.0','[]','{}','""'):
        receipt = ('{"branch":"feature","agent":"kept"}\n{"branch":"feature","agent":'+literal+'}\n').encode()
        compare('falsey-agent-'+literal,receipt,expected_seat='kept')
    for literal in ('true','[null,false,true]','{"z":true,"a":[false,null]}','1.0','1e-5','1e16',
                    'NaN','Infinity','-Infinity','1e400','184467440737095516160000',
                    '{"z":1,"a":2,"z":3}', json.dumps(["a'b", "x\ny", "\ud800"])):
        # NaN intentionally uses raw-byte equality, not NaN != NaN JSON equality.
        compare('lossless-agent-'+literal,('{"branch":"feature","agent":'+literal+'}\n').encode())
    for literal in ('null','false','0','0.0','[]','{}','""'):
        compare('falsey-branch-'+literal,('{"branch":"feature","agent":"kept"}\n{"branch":'+literal+',"agent":"ignored"}\n').encode(),expected_seat='kept')
    for separator in ('\n','\r','\r\n','\v','\f','\x1c','\x1d','\x1e','\x85','\u2028','\u2029'):
        compare('splitlines-'+repr(separator),('{"branch":"feature","agent":"first"}'+separator+'{"branch":"feature","agent":"last"}'+separator).encode(),expected_seat='last')
    compare('replacement-maximal-subsequences',b'{"branch":"feature","agent":"\xed\xa0\x80\xf0\x90\x80x\xff"}\n',expected_seat='\ufffd\ufffd\ufffd\ufffdx\ufffd')
    compare('str-input-BOM-not-auto-detected',b'{"branch":"feature","agent":"kept"}\n\xef\xbb\xbf{"branch":"feature","agent":"wrong"}\n',expected_seat='kept')
    compare('integer-digit-limit-keeps-earlier',b'{"branch":"feature","agent":"kept"}\n{"branch":"feature","agent":'+b'9'*4301+b'}\n',expected_seat='kept')
elif suite == 'release':
    for minutes in (0.05,0.15,0.25,0.35,0.75,1.25,1.75,2.25,123456.5,123457.5,999999.5,999999.95,1000000.0,1234567.5):
        def mutate(api):
            start = datetime.datetime(2020,1,1,tzinfo=datetime.timezone.utc)
            end = start + datetime.timedelta(minutes=minutes)
            job = copy.deepcopy(api['jobs']['3'][0])
            job.update(started_at=start.isoformat(),completed_at=end.isoformat(),labels=['macos-latest'])
            api['jobs']['3'] = [job]
        compare('round-and-six-significant-'+str(minutes),mutate=mutate,expected_minutes=round(minutes,1))
elif suite == 'config':
    for exotic in (float('nan'),float('inf'),10**80,'\ud800'):
        def mutate(api):
            api['policy']['metadata'] = {'unknown':exotic}
            api['lanes']['metadata'] = {'definition_paths': [], 'unknown':exotic}
        compare('unknown-exotic-'+repr(exotic),mutate=mutate)
    for falsey in (None,False,0,0.0,[],{},''):
        def mutate(api):
            for lane in api['lanes'].values(): lane['definition_paths'] = falsey
        compare('falsey-definition-paths-'+repr(falsey),mutate=mutate)
    for paths in ('xy', {'z':None,'a':True}):
        def mutate(api):
            for lane in api['lanes'].values(): lane['definition_paths'] = paths
        compare('iterable-definition-paths-'+repr(paths),mutate=mutate)
elif suite == 'schema':
    for number in (9007199254740993, True, 1.5, '17'):
        def mutate(api):
            api['fallback_number'] = number
            for run in api['runs']: run['pull_requests'] = []
        compare('fallback-number-'+repr(number),mutate=mutate,expected_error=True)
    for filename in (None, False, 12, {'path':'x'}, '\ud800'):
        def mutate(api): api['files'] = [filename]
        compare('filename-'+repr(filename),mutate=mutate,expected_error=True)
else:
    raise AssertionError(suite)
"#;

fn differential(suite: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = pinned_python::command()
        .args(["-B", "-c", DIFFERENTIAL])
        .arg(root)
        .arg(env!("CARGO_BIN_EXE_mergemaster"))
        .arg(suite)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{suite}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn receipts_match_python_truthiness_lossless_json_str_utf8_and_splitlines() {
    differential("receipts");
}
#[test]
fn release_minutes_match_python_round_exact_ties_and_general_format() {
    differential("release");
}
#[test]
fn config_json_keeps_exotic_metadata_and_python_iterable_truthiness() {
    differential("config");
}

#[test]
fn github_pull_and_file_fields_reject_out_of_schema_values_without_narrowing() {
    differential("schema");
}
