#[test]
fn python_oracle_parity() {
    let root = std::env::var_os("MERGEMASTER_PYTHON_PARITY_ORACLE")
        .expect("MERGEMASTER_PYTHON_PARITY_ORACLE must be set; run tests in nix develop");
    let status = std::process::Command::new("python3")
        .args(["-I", "-B", "-c", DRIVER])
        .arg(root)
        .arg(env!("CARGO_BIN_EXE_mergemaster"))
        .status()
        .expect("run unchanged Python oracle against Rust");
    assert!(status.success(), "differential suite failed: {status}");
}

const DRIVER: &str = r#"
import importlib.machinery, importlib.util, json, subprocess, sys, unittest
from pathlib import Path
root, binary = Path(sys.argv[1]), sys.argv[2]
loader = importlib.machinery.SourceFileLoader('oracle_tests', str(root / 'scripts/parity-drift-test'))
spec = importlib.util.spec_from_loader(loader.name, loader)
oracle = importlib.util.module_from_spec(spec)
loader.exec_module(oracle)
original = oracle.DriftTest.run_guard

def compare(self, *args, raw=False):
    expected = subprocess.run(['python3', str(root / 'scripts/parity-drift'),
        '--fractal-repo', str(self.repo), '--provenance', str(self.provenance), *args],
        env=self.env, capture_output=True, text=True) if raw else original(self, *args)
    actual = subprocess.run([binary, 'parity-drift', '--fractal-repo', str(self.repo),
        '--provenance', str(self.provenance), *args], env=self.env, capture_output=True, text=True)
    self.assertEqual(actual.returncode, expected.returncode, actual.stderr)
    self.assertEqual(actual.stdout, expected.stdout)
    if expected.stdout:
        self.assertEqual(json.loads(actual.stdout), json.loads(expected.stdout))
    return expected

oracle.DriftTest.run_guard = compare

class AdditionalHistories(oracle.DriftTest):
    def test_python_splitlines_boundaries(self):
        boundaries = ['\n', '\r', '\r\n', '\v', '\f', '\x1c', '\x1d', '\x1e',
                      '\x85', '\u2028', '\u2029']
        self.commit('scripts/st-test', 'mapped')
        for boundary in boundaries:
            with self.subTest(boundary=repr(boundary)):
                self.provenance.write_text(f'# Commit: {self.base}\n'
                    f'scripts/unmapped\told{boundary}scripts/st-test\told{boundary}')
                self.assertEqual(compare(self, raw=True).returncode, 1)
        # These are whitespace, but not Python line boundaries.
        for boundary in ['\x1f', '\t', '\u00a0']:
            self.provenance.write_text(f'# Commit: {self.base}\n'
                f'scripts/unmapped\told{boundary}scripts/st-test\told\n')
            self.assertEqual(compare(self, raw=True).returncode, 0)

    def test_python_splitlines_in_subjects_and_fixture_manifests(self):
        fixture = self.root / 'tests/fixtures/fractal/nested/PROVENANCE'
        fixture.parent.mkdir(parents=True)
        for boundary in ['\n', '\r', '\r\n', '\v', '\f', '\x1c', '\x1d', '\x1e',
                         '\x85', '\u2028', '\u2029']:
            with self.subTest(boundary=repr(boundary)):
                fixture.write_text(f'original_path\tblob{boundary}'
                    f'.st/policy.json\told{boundary}')
                self.commit('.st/policy.json', f'left{boundary}right{boundary}')
                self.assertEqual(compare(self, raw=True).returncode, 1)

    def test_watermark_uses_universal_newlines_not_unicode_boundaries(self):
        for boundary in ['\n', '\r', '\r\n', '\u2028', '\x85', '\v']:
            self.provenance.write_text(f'prefix{boundary}# Commit: {self.base}\n'
                'scripts/st-test\told\n')
            result = compare(self, raw=True)
            self.assertEqual(result.returncode, 0 if boundary in ['\n', '\r', '\r\n'] else 1)

    def test_option_like_ref_is_not_an_option(self):
        for ref in ['--help', '--quiet', '--show-toplevel', '--output=unexpected']:
            result = self.run_guard('--ref=' + ref)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
        self.assertFalse((self.repo / 'unexpected').exists())

    def test_help_documents_provenance_default(self):
        result = subprocess.run([binary, 'parity-drift', '--help'],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        help_text = ' '.join(result.stdout.split())
        for text in ['scripts/PROVENANCE', 'Git top level', 'current directory',
                     'error if the work tree or inventory is missing']:
            self.assertIn(text, help_text)

    def test_default_from_caller_subdirectory(self):
        self.provenance = self.repo / 'scripts/PROVENANCE'
        self.provenance.write_text(f'# Commit: {self.base}\nscripts/st-test\told\n')
        self.commit('scripts/st-test', 'default drift')
        expected = original(self)
        actual = subprocess.run([binary, 'parity-drift', '--fractal-repo', str(self.repo)],
            cwd=self.repo / 'scripts', env=self.env, capture_output=True, text=True)
        self.assertEqual(actual.returncode, expected.returncode, actual.stderr)
        self.assertEqual(actual.stdout, expected.stdout)

    def test_missing_default_names_provenance_option(self):
        for cwd in [self.root, self.repo / 'scripts']:
            actual = subprocess.run([binary, 'parity-drift', '--fractal-repo', str(self.repo)],
                cwd=cwd, env=self.env, capture_output=True, text=True)
            self.assertEqual(actual.returncode, 1)
            self.assertEqual(actual.stdout, '')
            self.assertIn('--provenance', actual.stderr)

    def test_reverted_and_untrusted_source(self):
        marker = self.root / 'executed'
        self.commit('scripts/st-test', '#!/bin/sh\ntouch ' + str(marker))
        self.commit('scripts/st-test', 'baseline')
        self.assertEqual(self.run_guard().returncode, 1)
        self.assertEqual(self.run_guard('--report-only').returncode, 0)
        self.assertFalse(marker.exists(), 'upstream source must never execute')

    def test_stale_and_rewritten_history(self):
        newer = self.commit('scripts/st-test', 'newer')
        self.provenance.write_text(f'# Commit: {newer}\nscripts/st-test\told\n')
        self.assertEqual(self.run_guard('--ref', self.base, '--report-only').returncode, 1)
        tree = self.git('rev-parse', 'HEAD^{tree}')
        rewritten = self.git('commit-tree', tree, '-m', 'rewritten root')
        self.assertEqual(self.run_guard('--ref', rewritten, '--report-only').returncode, 1)
        self.assertEqual(self.run_guard('--ref', 'missing-ref').returncode, 1)

    def test_unicode_subject_and_latest_port(self):
        port = self.commit('scripts/st-test', 'ported')
        self.provenance.write_text(f'# Commit: {self.base}\n# Port: {self.base}\n# Port: {port}\nscripts/st-test\told\n')
        self.commit('scripts/st-test', 'caf\u00e9 \U0001f680')
        self.assertEqual(self.run_guard().returncode, 1)

    def test_malformed_provenance(self):
        for text in ['', '# Commit: nope\nscripts/st-test\told\n',
                     f'# Commit: {self.base}\n',
                     '# Commit: ' + 'A' * 40 + '\nscripts/st-test\told\n']:
            self.provenance.write_text(text)
            self.assertEqual(self.run_guard('--report-only').returncode, 1)

suite = unittest.defaultTestLoader.loadTestsFromTestCase(AdditionalHistories)
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(not result.wasSuccessful())
"#;
