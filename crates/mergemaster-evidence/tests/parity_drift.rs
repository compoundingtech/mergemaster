#[test]
fn python_oracle_parity() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
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

def compare(self, *args):
    expected = original(self, *args)
    actual = subprocess.run([binary, 'parity-drift', '--fractal-repo', str(self.repo),
        '--provenance', str(self.provenance), *args], env=self.env, capture_output=True, text=True)
    self.assertEqual(actual.returncode, expected.returncode, actual.stderr)
    self.assertEqual(actual.stdout, expected.stdout)
    if expected.stdout:
        self.assertEqual(json.loads(actual.stdout), json.loads(expected.stdout))
    return expected

oracle.DriftTest.run_guard = compare

class AdditionalHistories(oracle.DriftTest):
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
