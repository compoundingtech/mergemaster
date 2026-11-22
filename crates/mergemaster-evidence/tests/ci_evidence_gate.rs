#[path = "../src/pinned_python.rs"]
mod pinned_python;

#[test]
fn gate_decisions_match_python_with_real_shallow_repositories() {
    let output = pinned_python::command()
        .args(["-B", "-c", DRIVER])
        .arg(env!("CARGO_BIN_EXE_mergemaster"))
        .arg(
            std::path::Path::new(&std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
                .join("../../scripts/ci-evidence-gate"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

const DRIVER: &str = r#"
import hashlib, importlib.machinery, importlib.util, json, os, pathlib, shutil, stat, subprocess, sys, unittest
from unittest import mock
binary, gate = sys.argv[1:]
root = pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])
loader = importlib.machinery.SourceFileLoader('gate_oracle_tests', str(root / 'scripts/ci-evidence-gate-test'))
spec = importlib.util.spec_from_loader(loader.name, loader)
oracle = importlib.util.module_from_spec(spec)
loader.exec_module(oracle)
os.environ['MERGEMASTER_BIN'] = binary
original = oracle.EndToEnd.run_gate
run = subprocess.run
identity = json.loads(run([binary, 'legacy-evidence-verify-helper', 'tool-identity'],
                          capture_output=True, check=True).stdout)
binary_sha256 = hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()
assert identity['binary_sha256'] == binary_sha256
commit_base = oracle.EndToEnd.commit_base
def pinned_commit_base(self, *args, **kwargs):
    revision = commit_base(self, *args, **kwargs)
    pin = {'version': 1, 'repository': identity['repository'], 'revision': revision,
           'release': {'version': identity['version'], 'sha256': binary_sha256}}
    destination = self.f.repo / '.mergemaster/tool-pin.json'
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(pin))
    self.f.git('add', '.mergemaster/tool-pin.json')
    self.f.git('commit', '-q', '-m', 'pin the fixture verifier binary')
    return self.f.git('rev-parse', 'HEAD')
def native(command, *positional, **options):
    if len(command) > 1 and str(command[1]) == str(root / 'scripts/ci-evidence-gate'):
        command = [command[0], gate, *command[2:]]
    return run(command, *positional, **options)
calls = 0
# shutil.copy preserves Nix-store read-only modes. The oracle reuses fixture
# destinations across subtests, so make owned copies writable after each copy,
# retaining their executable bits and leaving immutable source bytes untouched.
copy = shutil.copy
def writable_copy(*args, **kwargs):
    destination = copy(*args, **kwargs)
    path = pathlib.Path(destination)
    path.chmod(path.stat().st_mode | stat.S_IWUSR)
    return destination
def compare(self, *args, **kwargs):
    global calls
    expected, expected_outputs = original(self, *args, **kwargs)
    base = args[0] if args else kwargs['base']
    pin_bytes = run(['git', '-C', str(self.f.repo), 'show', f'{base}:.mergemaster/tool-pin.json'],
                    capture_output=True, check=True).stdout
    with mock.patch.object(subprocess, 'run', side_effect=native):
        actual, outputs = original(self, *args, **kwargs)
    # Only these two identity fields change; compare every other decision field.
    self.assertEqual(expected['verifier_sha256'],
                     hashlib.sha256((root / 'scripts/evidence-verify').read_bytes()).hexdigest())
    expected['verifier_sha256'] = binary_sha256
    expected['tool_pin_sha256'] = hashlib.sha256(pin_bytes).hexdigest()
    expected.pop('gate_sha256', None)
    actual.pop('gate_sha256', None)
    # The two sequential runs can cross a wall-clock second.
    expected_age, actual_age = expected.pop('age_s'), actual.pop('age_s')
    if expected_age != '-':
        self.assertNotEqual(actual_age, '-', (actual, expected))
        self.assertGreaterEqual(int(actual_age), int(expected_age))
    else:
        self.assertEqual(actual_age, expected_age)
    self.assertEqual(actual, expected)
    for key in ('skip', 'refuse', 'record'):
        self.assertEqual(outputs[key], expected_outputs[key])
    calls += 1
    return actual, outputs
oracle.EndToEnd.run_gate = compare
class ToolPinMismatch(oracle.EndToEnd):
    def test_wrong_binary_digest_is_unavailable(self):
        self.commit_base()
        destination = self.f.repo / '.mergemaster/tool-pin.json'
        pin = json.loads(destination.read_text())
        pin['release']['sha256'] = '0' * 64 if binary_sha256 != '0' * 64 else '1' * 64
        destination.write_text(json.dumps(pin))
        self.f.git('add', '.mergemaster/tool-pin.json')
        self.f.git('commit', '-q', '-m', 'mismatched fixture verifier digest')
        base = self.f.git('rev-parse', 'HEAD')
        with mock.patch.object(subprocess, 'run', side_effect=native):
            fields, outputs = original(self, base)
        self.assertEqual((fields['decision'], fields['outcome'], outputs['skip']),
                         ('run', 'unavailable', 'false'))
        self.assertEqual(fields['verifier_sha256'], '-')
        self.assertEqual(fields['tool_pin_sha256'], '-')
names = [
    'test_queue_reuses_an_equal_tree_on_a_different_commit_then_runs_a_changed_tree',
    'test_queue_invalid_signature_or_principal_runs_and_never_refuses',
    'test_no_note_then_degraded_then_a_trusted_note_skips_then_a_stranger_does_not',
    'test_the_subject_commit_is_absent_in_the_shallow_clone_and_the_skip_still_holds',
    'test_a_note_that_does_not_cover_the_check_never_skips',
    'test_a_newer_failure_or_a_conflicting_record_never_skips',
    'test_a_statement_edited_after_signing_never_skips',
    'test_forks_unknown_heads_and_other_events_never_skip_even_with_a_valid_note',
]
with mock.patch.object(shutil, 'copy', side_effect=writable_copy), \
        mock.patch.object(oracle.EndToEnd, 'commit_base', pinned_commit_base):
    suite = unittest.TestSuite(oracle.EndToEnd(name) for name in names)
    suite.addTest(ToolPinMismatch('test_wrong_binary_digest_is_unavailable'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
assert result.wasSuccessful()
assert calls >= len(names), calls
print('Compared', calls, 'real gate decisions against the pinned Python gate')
"#;
