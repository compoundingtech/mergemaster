#!/usr/bin/env python3
"""Focused clock and tiny signed-corpus acceptance (only stdlib/git/ssh-keygen)."""
import contextlib
from datetime import timedelta
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from clock_adapter import instant, load
import driver

AT = '2024-01-02T03:04:05+00:00'  # deliberately nowhere near wall time
FRACTAL = Path(os.environ['FRACTAL_SCRIPTS']).resolve()
MM = Path(os.environ['MM_SCRIPTS']).resolve()


def fixture_module():
    loader = importlib.machinery.SourceFileLoader('proof_fixture', str(MM / 'evidence-verify-test'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    module.NOW = instant(AT)
    return module


class ClockAdapter(unittest.TestCase):
    def setUp(self):
        self.fixtures = fixture_module()
        self.f = self.fixtures.Fixture()
        self.addCleanup(self.f.tmp.cleanup)
        self.f.git('config', 'core.hooksPath', '/dev/null')
        self.f.git('config', 'commit.gpgsign', 'false')
        self.key = self.f.key('ci', 'machine/ci1')
        self.stage = tempfile.TemporaryDirectory(dir='/var/tmp', prefix='mm-proof-test-')
        self.addCleanup(self.stage.cleanup)
        self.root = Path(self.stage.name)
        log_key = self.f.key('log')
        self.log_keys = self.root / 'log-keys'
        self.log_keys.write_text(f'log/evidence namespaces="git" {log_key.with_suffix(".pub").read_text()}')
        policy = {'version': 1, 'checks': {name: {'trust_levels': ['machine'], 'max_age_s': 60,
                  'require': 'reject', 'kinds': {'nix': {'command': ['make', 'test']}}}
                  for name in ('unit', 'rust-tests')}}
        files = {'.st/evidence-skip-policy.json': json.dumps(policy),
                 '.st/evidence-keys': self.f.keys.read_text(),
                 '.st/evidence-log-key': self.log_keys.read_text(),
                 '.st/rust-test-inputs.json': json.dumps({'version': 1, 'global': ['Cargo.toml'],
                     'crates': {'example': {'extra': []}}}),
                 'Cargo.toml': '[workspace]\nmembers = ["example"]\n',
                 'example/Cargo.toml': '[package]\nname = "example"\nversion = "0.1.0"\n',
                 'example/src/lib.rs': '#[test] fn works() {}\n',
                 'scripts/rust-test-keys': (FRACTAL / 'rust-test-keys').read_text()}
        for name, content in files.items():
            path = self.f.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.commit, self.tree = self.f.commit('signed fixture')
        self.staged = {}
        for name, source in [('fractal', FRACTAL), ('mergemaster', MM)]:
            target = self.root / name
            shutil.copytree(source, target)
            # Authorized accepted-BASE policy helper, NOT an MM oracle modification.
            (target / 'rust-test-keys').write_bytes((FRACTAL / 'rust-test-keys').read_bytes())
            self.staged[name] = target
        module = load(self.staged['fractal'] / 'evidence-verify', AT)
        crate_key = module.member_keys(str(self.f.repo), self.tree, self.commit)['example']
        self.unit = self.f.note(self.commit, self.tree, self.key, 'machine/ci1')
        self.member = self.f.note(self.commit, self.tree, self.key, 'machine/ci1', check='rust-tests',
                                  inputs={'crate': 'example', 'source_inputs': crate_key, 'tests_run': '1'})
        log = self.fixtures.EvidenceLogView()
        log.f, log.tree = self.f, self.tree
        log.log_key = log_key
        log.log([(self.unit, 0)], at=instant(AT))

    def invoke(self, scripts, flags, at=AT):
        module = load(scripts / 'evidence-verify', at)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = module.main(['--repo', str(self.f.repo), '--revision', self.commit,
                                '--keys-from', self.commit, '--policy-from', self.commit,
                                '--repository', 'org/repo', *flags])
        return code, json.loads(out.getvalue())

    def test_both_clocks_cover_verify_members_aggregate_and_log_view(self):
        for name, scripts in self.staged.items():
            with self.subTest(implementation=name):
                for flags in (['--check', 'unit'], ['--check', 'rust-tests', '--members'], ['--require-all']):
                    code, result = self.invoke(scripts, flags)
                    self.assertEqual(code, 0, result)
                    self.assertTrue(result['satisfied'], result)
                    late_code, late = self.invoke(scripts, flags, (instant(AT) + timedelta(days=2)).isoformat())
                    self.assertEqual(late_code, 1, late)
                    self.assertFalse(late['satisfied'], late)
                flags = ['--check', 'unit', '--log-keys', str(self.log_keys)]
                code, result = self.invoke(scripts, flags)
                self.assertEqual((code, result['log'], result['log_age_s']), (0, 'ok', 0), result)
                _, late = self.invoke(scripts, flags, (instant(AT) + timedelta(days=2)).isoformat())
                self.assertEqual(late['log'], 'stale', late)

    def test_members_requires_explicit_accepted_base_helper(self):
        isolated = self.root / 'without-helper'
        isolated.mkdir()
        shutil.copyfile(MM / 'evidence-verify', isolated / 'evidence-verify')
        code, value = self.invoke(isolated, ['--check', 'rust-tests', '--members'])
        self.assertEqual((code, value['reason']), (1, 'error'))
        self.assertIn('rust-test-keys is not next to', value['detail'])

    def test_tiny_signed_corpus_and_exactly_one_injected_diff(self):
        manifest = self.root / 'archive.manifest'
        refs = driver.git(self.f.repo, 'for-each-ref', '--format=%(objectname) %(refname)', *driver.PREFIXES)
        manifest.write_bytes(b''.join(line + b'\n' for line in sorted(refs.splitlines())))
        digest = driver.sha(manifest.read_bytes())

        def replay(output, scripts=MM, expected=0):
            command = [sys.executable, str(Path(driver.__file__)), 'replay-shard', '--scratch-root', str(output),
                       '--repo', str(self.f.repo), '--manifest', str(manifest), '--manifest-sha256', digest,
                       '--fractal-scripts', str(FRACTAL), '--mergemaster-scripts', str(scripts),
                       '--clock', AT, '--base', self.commit, '--repository', 'org/repo', '--selection', 'pilot']
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            for name in ('decisions.jsonl', 'diffs.jsonl', 'lane-summary.json', 'coverage.json'):
                self.assertTrue((output / name).is_file())
            return command

        good = self.root / 'good'
        command = replay(good)
        self.assertEqual((good / 'diffs.jsonl').read_text(), '')
        coverage = json.loads((good / 'coverage.json').read_text())
        self.assertEqual(coverage['completed_record_checks'], 2)
        self.assertEqual(coverage['unresolved_cases'], 0)
        decisions = [json.loads(line) for line in (good / 'decisions.jsonl').read_text().splitlines()]
        aggregates = [r for r in decisions if r['lane'] == '__aggregate__']
        self.assertEqual(len(aggregates), 2)
        for row in aggregates:
            self.assertEqual(row['normalized']['satisfied_checks'], ['rust-tests', 'unit'])
        before = (good / 'decisions.jsonl').read_bytes()
        subprocess.run(command, check=True, capture_output=True)
        self.assertEqual((good / 'decisions.jsonl').read_bytes(), before)
        bad = self.root / 'injected'
        shutil.copytree(MM, bad)
        path = bad / 'evidence-verify'
        text = path.read_text()
        # Mutation confined to disposable test oracle. Exactly the unit single-check path changes.
        needle = "result = verify(args.repo, tree, args.check, keys, command, kinds, bind, args.max_age, args.runner_prefix,"
        self.assertEqual(text.count(needle), 1)
        text = text.replace("        print(json.dumps(result, indent=2))\n        return 0\n    except Failure", "        if args.check == 'unit':\n            result['satisfied'] = False\n        print(json.dumps(result, indent=2))\n        return 0\n    except Failure")
        self.assertNotEqual(text, path.read_text())
        path.write_text(text)
        changed = self.root / 'changed'
        replay(changed, bad, expected=1)
        self.assertEqual(len((changed / 'diffs.jsonl').read_text().splitlines()), 1)
        print('tiny signed pilot: good=0 diffs, injected=1 diff, record_checks=2, unresolved=0',
              file=sys.stderr)
        mismatch = command.copy()
        mismatch[mismatch.index('--manifest-sha256') + 1] = '0' * 64
        refused = subprocess.run(mismatch, capture_output=True, text=True)
        self.assertEqual(refused.returncode, 2)
        self.assertIn('manifest sha256 mismatch', refused.stderr)
        if os.environ.get('PROOF_TEST_RECEIPT'):
            destination = Path(os.environ['PROOF_TEST_RECEIPT'])
            shutil.copytree(good, destination / 'good', dirs_exist_ok=True)
            shutil.copytree(changed, destination / 'injected', dirs_exist_ok=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
