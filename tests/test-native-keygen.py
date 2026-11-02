#!/usr/bin/env python3
"""Run every unchanged keygen oracle assertion against both CLI implementations."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts/evidence-keygen'
NATIVE = [sys.argv[1], 'evidence', 'keygen']
ORACLE = [sys.executable, '-I', str(SCRIPT)]
loader = importlib.machinery.SourceFileLoader('keygen_oracle', str(SCRIPT) + '-test')
spec = importlib.util.spec_from_loader(loader.name, loader)
oracle = importlib.util.module_from_spec(spec)
loader.exec_module(oracle)
real_run = subprocess.run


def native_run(command, *args, **kwargs):
    # This includes direct subprocess calls in the HOME tests, not just the helper.
    if command[:3] == ORACLE:
        command = NATIVE + command[3:]
    return real_run(command, *args, **kwargs)


class ExtraParity(unittest.TestCase):
    def test_refusals_preserve_existing_files(self):
        for command in (ORACLE, NATIVE):
            for target, kind in (('evidence-sign-scratch.git', 'symlink'),
                                 ('evidence-sign-key', 'directory'),
                                 ('evidence-sign-scratch.git', 'file'),
                                 ('evidence-sign.json', 'directory')):
                with self.subTest(command=command, target=target, kind=kind), tempfile.TemporaryDirectory() as home:
                    directory = Path(home) / '.config/st'
                    directory.mkdir(parents=True, mode=0o700)
                    outside = Path(home) / 'outside'
                    outside.mkdir()
                    path = directory / target
                    if kind == 'symlink':
                        path.symlink_to(outside)
                    elif kind == 'directory':
                        path.mkdir()
                    else:
                        path.write_text('untouched')
                    done = real_run(command + ['--name', 'box-1', '--home', home], capture_output=True, text=True)
                    self.assertEqual(done.returncode, 1, done.stderr)
                    self.assertEqual(done.stdout, '')
                    self.assertIn('symlink' if kind == 'symlink' else 'kind of file', done.stderr)
                    self.assertEqual(list(outside.iterdir()), [])
                    if kind == 'file':
                        self.assertEqual(path.read_text(), 'untouched')

    def test_loose_directory_and_config_modes_are_not_repaired(self):
        for command in (ORACLE, NATIVE):
            for target, mode in (('', 0o755), ('evidence-sign.json', 0o644)):
                with self.subTest(command=command, target=target), tempfile.TemporaryDirectory() as home:
                    args = command + ['--name', 'box-1', '--home', home]
                    self.assertEqual(real_run(args, capture_output=True).returncode, 0)
                    path = Path(home) / '.config/st' / target
                    path.chmod(mode)
                    done = real_run(args, capture_output=True, text=True)
                    self.assertEqual(done.returncode, 1, done.stderr)
                    self.assertEqual(done.stdout, '')
                    self.assertEqual(path.stat().st_mode & 0o777, mode)

    def test_script_and_native_reuse_the_same_files_and_exact_enrollment_output(self):
        for first, second, prefix, suffix in ((a, b, p, s) for a, b in ((ORACLE, NATIVE), (NATIVE, ORACLE)) for p, s in (('', ''), ('', '/.'), ('', '//'), ('/', ''), ('//', ''), ('', '/nested/..'))):
            with self.subTest(first=first), tempfile.TemporaryDirectory() as home:
                (Path(home) / 'nested').mkdir()
                args = ['--name', 'box-1', '--home', prefix + home + suffix]
                before = real_run(first + args, capture_output=True, text=True)
                self.assertEqual(before.returncode, 0, before.stderr)
                directory = Path(home) / '.config/st'
                snapshot = {path: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
                            for path in directory.rglob('*') if path.is_file()}
                after = real_run(second + args, capture_output=True, text=True)
                self.assertEqual((after.returncode, after.stdout, after.stderr),
                                 (0, before.stdout, before.stderr))
                self.assertEqual(snapshot, {path: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
                                            for path in directory.rglob('*') if path.is_file()})


if os.geteuid() == 0:
    # The unchanged oracle suite intentionally requires an ordinary account.
    raise SystemExit('Run keygen parity as a non-root account')
runner = unittest.TextTestRunner(verbosity=2)
results = []
for native in (False, True):
    print('native' if native else 'oracle', file=sys.stderr, flush=True)
    with patch.object(subprocess, 'run', native_run if native else real_run):
        results.append(runner.run(unittest.defaultTestLoader.loadTestsFromTestCase(oracle.Keygen)))
results.append(runner.run(unittest.defaultTestLoader.loadTestsFromTestCase(ExtraParity)))
raise SystemExit(0 if all(result.wasSuccessful() for result in results) else 1)
