#!/usr/bin/env python3
"""Replay pinned log consumers against signed local fixtures, retaining a private receipt."""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from clock_adapter import instant
from driver import HERE, PINS, encoded, git, normalize, save, sha

BLOBS = {'evidence-log': '73e22e8252a1ceab4eba0324a0063c97f1d75b18',
         'evidence-log-watch': 'f580ed13fe4f8130ec936dfeefb64f6c3b97b2f1',
         'evidence-verify': '5ed6ade05b64b65825d4f6e6da812db1263c6148',
         'evidence-verify-test': '08d11cc7ba5e8a3d5ffb59fadb9eb49238aec95f'}
LOG = 'refs/evidence-log/main'


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def bare(path):
    subprocess.run(['git', 'init', '-q', '--bare', str(path)], check=True, capture_output=True)
    for key, value in [('core.hooksPath', '/dev/null'), ('gc.auto', '0'), ('maintenance.auto', 'false')]:
        git(path, 'config', key, value)


def load_support(scripts):
    loader = importlib.machinery.SourceFileLoader('consumer_signed_fixture', str(scripts / 'evidence-verify-test'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


def source_receipt(sources):
    result = {}
    for name, scripts in sources.items():
        result[name] = {'commit': PINS[name], 'scripts': {}}
        for filename, expected in BLOBS.items():
            data = (scripts / filename).read_bytes()
            oid = subprocess.run(['git', 'hash-object', '--stdin'], input=data,
                                 capture_output=True, check=True).stdout.decode().strip()
            require(oid == expected, f'{name}/{filename}: not the pinned source blob')
            result[name]['scripts'][filename] = {'blob': oid, 'sha256': sha(data)}
    return result


class Replay:
    def __init__(self, root, scripts, implementation, fixture, clock):
        self.root, self.scripts, self.implementation = root, scripts, implementation
        self.fixture, self.clock = fixture, clock
        self.work = root / 'work'
        self.remote, self.host = self.work / 'remote.git', self.work / 'host.git'
        self.state, self.sent = self.work / 'watch-state', self.work / 'notifications.jsonl'
        self.output = root / implementation
        self.output.mkdir()
        self.rows = []
        self.signer = ['ssh-keygen', '-q', '-Y', 'sign', '-n', 'git', '-f', str(fixture['log_key'])]
        self.notify = [sys.executable, '-c',
                       'import json,sys;open(sys.argv[1],"a").write(json.dumps(sys.argv[2])+"\\n")', str(self.sent)]

    def snapshot(self):
        result = {'notifications': [json.loads(line) for line in self.sent.read_text().splitlines()] if self.sent.exists() else [],
                  'watch_state': json.loads((self.state / 'watch.json').read_text()) if (self.state / 'watch.json').exists() else None}
        for name, repo in [('remote', self.remote), ('host', self.host)]:
            result[name + '_refs'] = git(repo, 'for-each-ref', '--format=%(objectname) %(refname)',
                                         'refs/tags/evidence/', 'refs/evidence-log/', 'refs/evidence-copy/').decode().splitlines()
            head = git(repo, 'rev-parse', '--verify', LOG, check=False)
            if head.returncode == 0:
                result[name + '_log_signature'] = git(repo, '-c', f'gpg.ssh.allowedSignersFile={self.fixture["log_keys"]}',
                                                       '-c', 'gpg.ssh.revocationFile=/dev/null',
                                                       'show', '-s', '--format=%G?%x00%GS', LOG).decode().strip()
                paths = git(repo, 'ls-tree', '-r', '--name-only', LOG).decode().splitlines()
                result[name + '_log_files'] = {path: git(repo, 'cat-file', 'blob', f'{LOG}:{path}').decode() for path in paths}
        result['watch_rebuilt_copies'] = len(list(self.state.glob('head.git.broken-*'))) if self.state.exists() else 0
        return result

    def invoke(self, case, path, command, expected, fields=None):
        done = subprocess.run(command, capture_output=True, timeout=60,
                              env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1',
                                   'GIT_TERMINAL_PROMPT': '0', 'SSH_AUTH_SOCK': ''})
        artifact = self.output / case
        artifact.mkdir()
        (artifact / 'stdout').write_bytes(done.stdout)
        (artifact / 'stderr').write_bytes(done.stderr)
        lines = done.stdout.decode().splitlines()
        require(bool(lines), f'{case}: missing JSON: {done.stderr.decode(errors="replace")}')
        is_watch = Path(command[1]).name == 'evidence-log-watch'
        value = json.loads(lines[-1] if is_watch else '\n'.join(lines))
        require(done.returncode == expected, f'{case}: exit {done.returncode}, expected {expected}: {value}, {done.stderr!r}')
        for key, expected_value in (fields or {}).items():
            require(value.get(key) == expected_value, f'{case}: {key}={value.get(key)!r}, expected {expected_value!r}')
        require(value.get('reason') != 'error', f'{case}: equal infrastructure errors cannot pass')
        snapshot = self.snapshot()
        payload = dict(value)
        payload['consumer_snapshot'] = snapshot
        if Path(command[1]).name != 'clock_adapter.py':
            payload['decision'] = ('stalled' if value.get('stalled') else 'ok') if is_watch else ('missing' if expected == 4 else 'ok')
        payload['stderr'] = done.stderr.decode()
        if is_watch:
            payload['emitted_lines'] = lines[:-1]
        effective_clock = (instant(command[command.index('--at') + 1]) if '--at' in command else
                           datetime.fromtimestamp(float(command[command.index('--now') + 1]), timezone.utc))
        row = {'case': case, 'path': path, 'argv': command, 'clock': effective_clock.isoformat(),
               'exit_status': done.returncode, 'normalized': normalize(done.returncode, payload),
               'stdout_sha256': sha(done.stdout), 'stderr_sha256': sha(done.stderr),
               'expected_exit': expected, 'expected_fields': fields or {}, 'assertions': 'PASS'}
        save(artifact / 'decision.json', row)
        self.rows.append(row)
        return value

    def pull(self, case, seconds, expected=0, fields=None, extra=(), mode='pull', path='restoration'):
        return self.invoke(case, path, [sys.executable, str(self.scripts / 'evidence-log'), mode,
            '--repo', str(self.host), '--signer', json.dumps(self.signer), '--log-keys', str(self.fixture['log_keys']),
            '--now', str(int(self.clock.timestamp()) + seconds), *extra], expected, fields)

    def watch(self, case, seconds, expected, fields, path='notification'):
        return self.invoke(case, path, [sys.executable, str(self.scripts / 'evidence-log-watch'),
            '--remote', str(self.remote), '--state', str(self.state), '--notify', json.dumps(self.notify),
            '--now', str(int(self.clock.timestamp()) + seconds), '--repeat', '3600'], expected, fields)

    def view(self, case, seconds, expected=0, fields=None, path='log-view'):
        return self.invoke(case, path, [sys.executable, str(HERE / 'clock_adapter.py'),
            '--at', (self.clock + timedelta(seconds=seconds)).isoformat(),
            '--script', str(self.scripts / 'evidence-verify'), '--', '--repo', str(self.remote),
            '--revision', self.fixture['subject'], '--check', 'unit', '--keys-from', self.fixture['subject'],
            '--log-keys', str(self.fixture['log_keys'])], expected, fields)

    def run(self):
        # Both implementations reuse identical absolute argv/ref/key paths and initial objects.
        if self.work.exists():
            shutil.rmtree(self.work)
        self.work.mkdir()
        shutil.copytree(self.root / 'seed.git', self.remote)
        bare(self.host)
        git(self.host, 'remote', 'add', 'origin', str(self.remote))
        self.pull('bootstrap-signed-log', 0, fields={'added': 2, 'published': True},
                  extra=('--publish',), path='log-view')
        require(self.snapshot()['remote_log_signature'] == 'G\x00log/evidence', 'log must be signed by accepted key')
        self.view('fresh-signed-log-view', 0, fields={'satisfied': True, 'record': self.fixture['passed'], 'log': 'ok', 'log_age_s': 0})
        self.view('stale-signed-log-view', 1200, fields={'satisfied': True, 'log': 'stale', 'log_age_s': 1200})
        self.watch('watch-fresh', 0, 0, {'stalled': False, 'notified': False})
        self.watch('watch-stalled-notification', 400, 1, {'stalled': True, 'notified': True})
        self.watch('watch-notification-deduplicated', 520, 1, {'stalled': True, 'notified': False})
        self.watch('watch-repeat-notification', 4000, 1, {'stalled': True, 'notified': True})
        self.pull('publish-recovered-heartbeat', 4100, fields={'published': True}, extra=('--publish',), path='notification')
        self.watch('watch-recovery-notification', 4100, 0, {'stalled': False, 'notified': True})
        require(len(self.snapshot()['notifications']) == 3, 'only stall, repeat and recovery notifications may be recorded')
        watched = git(self.state / 'head.git', 'rev-parse', 'refs/evidence-log/watched').decode().strip()
        damaged = self.state / 'head.git' / 'objects' / watched[:2] / watched[2:]
        damaged.parent.mkdir(exist_ok=True)
        if damaged.exists():
            damaged.chmod(0o644)
        damaged.write_bytes(b'')
        self.watch('watch-damaged-copy-restoration', 4101, 0,
                   {'stalled': False, 'notified': False, 'head': watched}, path='restoration')
        require(self.snapshot()['watch_rebuilt_copies'] == 1, 'damaged watch copy must be rebuilt once')
        missing_ref = self.fixture['failed_ref']
        git(self.remote, 'update-ref', '-d', missing_ref)
        self.pull('deleted-record-alarm', 4200, expected=4, fields={'missing': [missing_ref]})
        self.pull('restore-deleted-record', 4200, expected=4, fields={'missing': [missing_ref], 'restored': True}, extra=('--restore',))
        require(git(self.remote, 'rev-parse', missing_ref).decode().strip() == self.fixture['failed'], 'restore must recover exact signed OID')
        self.pull('restoration-readback', 4200, fields={'missing': []})
        self.view('restored-log-view', 4200, fields={'satisfied': True, 'log': 'ok'})
        # Change only a synthetic remote's signed log tip to a rogue signature; no production writer exists here.
        good = git(self.remote, 'rev-parse', LOG).decode().strip()
        tree = git(self.remote, 'rev-parse', f'{good}^{{tree}}').decode().strip()
        rogue = git(self.remote, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    '-c', 'gpg.format=ssh', '-c', f'user.signingKey={self.fixture["rogue_key"]}',
                    'commit-tree', '-S', tree, '-m', f'evidence-log v1 as_of={self.clock.isoformat()} added=0 gc=0 missing=0').decode().strip()
        git(self.remote, 'update-ref', LOG, rogue)
        self.view('untrusted-log-key-view', 4200, fields={'satisfied': True, 'log': 'unsigned'})
        git(self.remote, 'update-ref', LOG, good)
        # Exercise the consumer's GC log/read protocol, NOT evidence-gc --apply or real object GC.
        plan = self.work / 'gc-plan.json'
        plan.write_bytes(encoded({'trees': [self.fixture['tree']], 'keys': [], 'plan_sha256': 'f' * 64,
                                  'delete': [self.fixture['passed_ref'], missing_ref]}))
        self.pull('gc-log-checkpoint', 4300, fields={'gc_paths': 1, 'copies_dropped': 2},
                  mode='gc', extra=('--plan', str(plan), '--publish'), path='gc-read')
        git(self.remote, 'update-ref', '-d', self.fixture['passed_ref'])
        git(self.remote, 'update-ref', '-d', missing_ref)
        self.pull('gc-deletions-not-an-alarm', 4400, fields={'missing': []}, path='gc-read')
        result = self.view('gc-shadow-read', 4400, expected=1, fields={'satisfied': False, 'reason': 'no_record', 'log': 'ok'}, path='gc-read')
        require(result['log_missing'] == 0, 'GC lines must suppress missing-record alarms')
        git(self.remote, 'update-ref', self.fixture['renewed_ref'], self.fixture['renewed'])
        self.pull('record-after-gc-checkpoint', 4500, fields={'added': 1, 'missing': []},
                  extra=('--publish',), path='gc-read')
        self.view('record-after-gc-shadow-read', 4500, fields={'satisfied': True, 'record': self.fixture['renewed'], 'log': 'ok'}, path='gc-read')
        return self.rows


def run(args):
    os.umask(0o077)
    root = Path(args.scratch_root).resolve()
    require(Path('/var/tmp') in root.parents, 'consumer fixture scratch root must be under /var/tmp')
    require(not root.exists(), 'use a fresh fixture scratch root; no existing receipt is overwritten')
    clock = instant(args.clock)
    os.environ['GIT_AUTHOR_DATE'] = clock.isoformat()
    os.environ['GIT_COMMITTER_DATE'] = clock.isoformat()
    sources = {'fractal': Path(args.fractal_scripts).resolve(), 'mergemaster': Path(args.mergemaster_scripts).resolve()}
    sources_receipt = source_receipt(sources)
    root.mkdir(parents=True)
    private = root / 'fixture-private'
    private.mkdir()
    tempfile.tempdir = str(private)
    support = load_support(sources['fractal'])
    support.NOW = clock
    fixture = support.Fixture(layout='tag')
    try:
        f = fixture
        f.git('config', 'core.hooksPath', '/dev/null')
        f.git('config', 'commit.gpgsign', 'false')
        f.git('checkout', '-q', '-b', 'main')
        key = f.key('ci', 'machine/ci1')
        log_key, rogue_key = f.key('log-key'), f.key('rogue-key')
        (f.repo / '.st').mkdir()
        (f.repo / '.st/evidence-keys').write_text(f.keys.read_text())
        subject, tree = f.commit('consumer synthetic subject')
        passed = f.note(subject, tree, key, 'machine/ci1', seconds=-120)
        failed = f.note(subject, tree, key, 'machine/ci1', check='other', exit_code=1, seconds=-60)
        renewed = f.note(subject, tree, key, 'machine/ci1', seconds=-10)
        renewed_ref = f.ref_of[renewed]
        f.git('update-ref', '-d', renewed_ref)
        f.git('update-ref', 'refs/proof/fixture-renewed', renewed)
        # No alternates or mutable shared store. Both executions start from this exact local seed.
        subprocess.run(['git', 'clone', '-q', '--bare', '--no-hardlinks', str(f.repo), str(root / 'seed.git')], check=True)
        for name, value in [('core.hooksPath', '/dev/null'), ('gc.auto', '0'), ('maintenance.auto', 'false')]:
            git(root / 'seed.git', 'config', name, value)
        public = root / 'log-keys'
        public.write_text(f'log/evidence namespaces="git" {log_key.with_suffix(".pub").read_text()}')
        data = {'subject': subject, 'tree': tree, 'passed': passed, 'failed': failed, 'renewed': renewed,
                'passed_ref': f.ref_of[passed], 'failed_ref': f.ref_of[failed], 'renewed_ref': renewed_ref,
                'log_key': log_key, 'rogue_key': rogue_key, 'log_keys': public}
        pairs = {name: Replay(root, scripts, name, data, clock).run() for name, scripts in sources.items()}
        old = {row['case']: row for row in pairs['fractal']}
        new = {row['case']: row for row in pairs['mergemaster']}
        require(old.keys() == new.keys(), 'case sets differ')
        diffs = [{'case': case, 'path': old[case]['path'], 'fractal': old[case]['normalized'],
                  'mergemaster': new[case]['normalized']} for case in old if old[case]['normalized'] != new[case]['normalized']]
        (root / 'diffs.jsonl').write_bytes(b''.join(encoded(row) + b'\n' for row in diffs))
        paths = {path: {'status': 'PASS' if not any(d['path'] == path for d in diffs) else 'DIFF',
                        'cases': [case for case in old if old[case]['path'] == path],
                        'diff_count': sum(d['path'] == path for d in diffs)}
                 for path in ('log-view', 'notification', 'restoration', 'gc-read')}
        receipt = {'claim': 'synthetic signed consumer fixture parity, not archive D GO', 'clock': clock.isoformat(),
                   'invocation': sys.argv, 'runtime': {'python': sys.version,
                       'git': subprocess.run(['git', '--version'], capture_output=True, text=True, check=True).stdout.strip()},
                   'sources': sources_receipt, 'fixture_subject': subject, 'fixture_tree': tree,
                   'record_oids': [passed, failed, renewed], 'cases': len(old), 'diff_count': len(diffs), 'paths': paths,
                   'clock_contract': {'evidence-verify': 'datetime adapter --at',
                                      'evidence-log': 'native --now on every invocation',
                                      'evidence-log-watch': 'native --now on every invocation'},
                   'driver_sha256': sha(Path(__file__).read_bytes()), 'normalizer_sha256': sha((HERE / 'driver.py').read_bytes()),
                   'adapter_sha256': sha((HERE / 'clock_adapter.py').read_bytes()),
                   'allowlist_sha256': sha((HERE / 'allowlist.json').read_bytes()),
                   'notifications': 'recording argv only; no external notification sent',
                   'gc_scope': 'synthetic signed gc log checkpoints and ref-deletion reads only; no evidence-gc --apply or object GC',
                   'not_run': ['real Phase A archive replay', 'dev5 admission/pilot', 'production notifications/signing/restoration/GC',
                               'native Rust replay (outside approved scope)', 'full exhaustive corpus execution']}
        receipt['products'] = {str(path.relative_to(root)): sha(path.read_bytes())
                               for directory in ('fractal', 'mergemaster') for path in sorted((root / directory).rglob('*')) if path.is_file()}
        receipt['products']['diffs.jsonl'] = sha((root / 'diffs.jsonl').read_bytes())
        receipt['products']['log-keys'] = sha(public.read_bytes())
        save(root / 'receipt.json', receipt)
        print(json.dumps({'receipt': str(root / 'receipt.json'), 'cases': len(old), 'diffs': len(diffs), 'paths': paths}, sort_keys=True))
        return 1 if diffs else 0
    finally:
        fixture.tmp.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('scratch-root', 'fractal-scripts', 'mergemaster-scripts', 'clock'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        return run(args)
    except (AssertionError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(2, str(error) + '\n')


if __name__ == '__main__':
    sys.exit(main())
