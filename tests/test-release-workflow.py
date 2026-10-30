#!/usr/bin/env python3
"""Offline release contracts; hosted PR builds exercise both real musl targets."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / '.github/workflows/release.yml').read_text()
TARGETS = ('aarch64-unknown-linux-musl', 'x86_64-unknown-linux-musl')


def job(name):
    match = re.search(rf'^  {name}:\n(.*?)(?=^  [\w-]+:\n|\Z)', WORKFLOW,
                      re.MULTILINE | re.DOTALL)
    if not match:
        raise AssertionError(f'Missing job {name}')
    return match[1]


def script(name):
    # The workflow owns its shell steps inline; exercise those exact bytes.
    match = re.search(rf'^      - name: {re.escape(name)}\n(.*?)(?=^      - |\Z)',
                      WORKFLOW, re.MULTILINE | re.DOTALL)
    if not match:
        raise AssertionError(f'Missing step {name}')
    body = match[1].split('        run: |\n', 1)[1]
    return ''.join(line[10:] for line in body.splitlines(keepends=True))


class ReleaseWorkflowTests(unittest.TestCase):
    def test_pull_requests_and_dispatch_build_without_publishing(self):
        triggers = WORKFLOW.split('\npermissions:', 1)[0]
        self.assertIn('  pull_request:\n', triggers)
        self.assertIn('  workflow_dispatch:\n', triggers)
        self.assertNotIn('pull_request_target', WORKFLOW)
        self.assertNotIn('workflow_run', WORKFLOW)
        self.assertIn('\npermissions:\n  contents: read\n', WORKFLOW)
        self.assertNotIn('    if:', job('build'))
        self.assertNotIn('    if:', job('bundle'))
        self.assertIn("    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')\n",
                      job('publish'))
        for name in ('build', 'bundle'):
            body = job(name)
            self.assertNotIn('attest-build-provenance', body)
            self.assertNotIn('gh release', body)
            self.assertNotIn('write', body)
            self.assertNotIn('secrets.', body)

    def test_version_tag_validation(self):
        command = script('Validate release tag')
        for tag in ('v0.1.0', 'v1.2.3', 'v100.20.300'):
            with self.subTest(tag=tag):
                result = subprocess.run(['bash', '-c', command],
                                        env=dict(os.environ, RELEASE_TAG=tag),
                                        capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
        for tag in ('v01.2.3', 'v1.02.3', 'v1.2.03', 'v1.2', 'v1.2.3-rc1',
                    'v1.2.3.4', '1.2.3', 'v1.2.3\nevil', 'v1.2.3; echo unsafe'):
            with self.subTest(tag=tag):
                result = subprocess.run(['bash', '-c', command],
                                        env=dict(os.environ, RELEASE_TAG=tag),
                                        capture_output=True)
                self.assertNotEqual(result.returncode, 0)
        self.assertIn("if: github.event_name == 'push'", job('build'))

    def test_native_musl_builds_are_locked_and_smoke_tested(self):
        build = job('build')
        self.assertRegex(build, r'runner: ubuntu-24\.04\n\s+target: x86_64-unknown-linux-musl')
        self.assertRegex(build, r'runner: ubuntu-24\.04-arm\n\s+target: aarch64-unknown-linux-musl')
        self.assertIn('target-feature=+crt-static', build)
        self.assertIn('linker=musl-gcc', build)
        self.assertIn('--locked --release --target "$TARGET"', build)
        self.assertIn('--package mergemaster-evidence --bin mergemaster', build)
        smoke = script('Verify static linking and smoke test')
        self.assertIn('readelf --program-headers', smoke)
        self.assertIn('readelf --dynamic', smoke)
        self.assertIn('INTERP', smoke)
        self.assertIn('NEEDED', smoke)
        self.assertIn('"$binary" --help', smoke)
        self.assertIn('"$binary" --version', smoke)

    def test_checksums_cover_exact_release_assets(self):
        with tempfile.TemporaryDirectory(prefix='mergemaster-release-') as directory:
            root = Path(directory)
            for target in TARGETS:
                (root / f'mergemaster-{target}').write_bytes(target.encode())
            subprocess.run(['bash', '-c', script('Generate SHA256SUMS')],
                           cwd=root, check=True, capture_output=True)
            entries = (root / 'SHA256SUMS').read_text().splitlines()
            self.assertEqual([line.split()[1] for line in entries],
                             [f'mergemaster-{target}' for target in TARGETS])
            self.assertTrue(all(re.fullmatch(r'[a-f0-9]{64}  mergemaster-[\w-]+', line)
                                for line in entries))
            (root / f'mergemaster-{TARGETS[0]}').write_bytes(b'corrupted')
            result = subprocess.run(['sha256sum', '--check', '--strict', 'SHA256SUMS'],
                                    cwd=root, capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_publisher_attests_without_executing_release_code(self):
        publish = job('publish')
        self.assertIn('    needs: bundle\n', publish)
        for permission in ('contents', 'id-token', 'attestations'):
            self.assertIn(f'      {permission}: write\n', publish)
        self.assertNotIn('actions/checkout', publish)
        self.assertNotIn('cargo ', publish)
        self.assertNotIn('rustup ', publish)
        self.assertIn('subject-path: dist/*', publish)
        self.assertIn('name: release-assets', publish)
        self.assertLess(publish.index('Attest binaries'), publish.index('gh release create'))
        self.assertIn('--verify-tag --target "$RELEASE_COMMIT"', publish)
        self.assertIn('RELEASE_COMMIT: ${{ github.sha }}', publish)
        for target in TARGETS:
            self.assertIn(f'dist/mergemaster-{target}', publish)
        self.assertIn('dist/SHA256SUMS', publish)

    def test_all_actions_have_immutable_commit_pins(self):
        references = re.findall(r'uses: (\S+)', WORKFLOW)
        self.assertGreaterEqual(len(references), 6)
        for reference in references:
            self.assertRegex(reference, r'^[\w-]+/[\w-]+@[a-f0-9]{40}$')


if __name__ == '__main__':
    unittest.main()
