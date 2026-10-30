#!/usr/bin/env python3
"""Exercise the embedded base-trusted publisher and the real Genie workflow output."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'genie/generic-evidence.ts').read_text().split('String.raw`', 1)[1].split('\n`', 1)[0] + '\n'
HEAD, BASE = 'a' * 40, 'b' * 40
REPO = 'example/project'


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.pull = {'number': 3, 'state': 'open', 'head': {'sha': HEAD, 'repo': {'full_name': REPO}},
                     'base': {'ref': 'main', 'repo': {'full_name': REPO}}}
        event = self.path / 'event.json'
        event.write_text(json.dumps({'pull_request': self.pull}))
        self.environment = patch.dict(os.environ, GITHUB_REPOSITORY=REPO, GITHUB_EVENT_NAME='pull_request_target',
            GITHUB_EVENT_PATH=str(event), RUNNER_TEMP=str(self.path), HEAD_SHA=HEAD, BASE_SHA=BASE,
            GH_TOKEN='read-only', CHECK='graph-full-check', GATE_OUTCOME='success', GATE_SKIP='true',
            APP_TOKEN='app-only', APP_OUTCOME='success')
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.ns = {'__name__': 'publisher_test'}
        exec(compile(SOURCE, 'embedded-publisher', 'exec'), self.ns)
        self.check = {'id': 7, 'name': 'validate', 'head_sha': HEAD, 'status': 'completed', 'conclusion': 'success',
                      'app': {'slug': 'github-actions'}, 'details_url': f'https://github.com/{REPO}/actions/runs/8/job/9'}
        self.run = {'id': 8, 'repository': {'full_name': REPO}, 'workflow_id': 123,
                    'path': '.github/workflows/validate.yml', 'head_sha': HEAD, 'event': 'pull_request'}
        self.job = {'id': 9, 'run_id': 8, 'name': 'validate', 'head_sha': HEAD, 'status': 'completed',
                    'conclusion': 'success', 'check_run_url': f'https://api.github.com/repos/{REPO}/check-runs/7'}
        self.calls, self.posts, self.commands = [], [], []
        self.stale = False
        self.ns['api'] = self.api
        self.ns['command'] = self.command
        self.pin = {'version': 1, 'repository': 'compoundingtech/mergemaster', 'revision': 'c' * 40,
                    'release': {'version': 'v1.2.3', 'sha256': hashlib.sha256(b'binary').hexdigest()}}
        self.fetch = patch('subprocess.run')
        self.fetch.start()
        self.addCleanup(self.fetch.stop)
        self.decision = {'version': 1, 'check': 'graph-full-check', 'base': BASE, 'head': HEAD,
                         'decision': 'skip', 'outcome': 'satisfied', 'summary':
                         'this PR changes the validate workflow; validate ran the changed file'}
        self.save_decision()

    def save_decision(self):
        (self.path / 'generic-evidence-decision.json').write_text(json.dumps(self.decision))

    def command(self, *args):
        self.commands.append(args)
        if args[:3] == ('git', 'rev-parse', 'HEAD'):
            return BASE
        if args[:2] == ('git', 'show'):
            return json.dumps(self.pin)
        if args[:3] == ('gh', 'release', 'download'):
            (self.path / 'generic-evidence-release/mergemaster-x86_64-unknown-linux-musl').write_bytes(b'binary')
        return ''

    def api(self, endpoint, payload=None):
        self.calls.append(endpoint)
        if payload is not None:
            self.posts.append((copy.deepcopy(payload), os.environ['GH_TOKEN']))
            return {'id': 100}
        if endpoint.endswith('/pulls/3'):
            return self.pull
        if '/git/ref/heads/' in endpoint:
            return {'object': {'sha': HEAD if self.stale else BASE}}
        if '/reviews?' in endpoint:
            return [] if 'page=2' in endpoint else [dict(id=1, user={'login': 'schickling', 'id': 42}, state='APPROVED',
                                                        commit_id=HEAD, submitted_at='2026-10-30T00:00:00Z')] * 100
        if '/check-runs?' in endpoint:
            return {'check_runs': [] if 'page=2' in endpoint else [self.check] * 100}
        if '/jobs?' in endpoint:
            return {'jobs': [] if 'page=2' in endpoint else [self.job] * 100}
        if endpoint.endswith('/actions/runs/8'):
            return self.run
        raise AssertionError(endpoint)

    def test_exact_api_join_and_pagination(self):
        self.ns['prepare']()
        evidence = json.loads((self.path / 'generic-hosted-evidence.json').read_text())
        self.assertEqual(evidence['head'], HEAD)
        self.assertEqual(evidence['reviews'][0]['user'], {'login': 'schickling'})
        self.assertEqual(evidence['checks'][0]['workflow_run'], {key: self.run[key]
                         for key in ('id', 'workflow_id', 'path', 'head_sha', 'event')})
        self.assertEqual(len([url for url in self.calls if 'page=2' in url]), 3)
        self.assertTrue(any('--source-digest' in args and '--signer-workflow' in args for args in self.commands))

    def test_same_named_check_cannot_invent_run_identity(self):
        self.run.update(workflow_id=999, path='.github/workflows/spoof.yml')
        self.ns['prepare']()
        evidence = json.loads((self.path / 'generic-hosted-evidence.json').read_text())
        self.assertEqual(evidence['checks'][0]['workflow_run']['workflow_id'], 999)
        self.assertEqual(evidence['checks'][0]['workflow_run']['path'], '.github/workflows/spoof.yml')

    def test_job_check_mismatch_is_fatal(self):
        self.job['check_run_url'] += '0'
        with self.assertRaisesRegex(RuntimeError, 'identity mismatch'):
            self.ns['prepare']()

    def test_digest_mismatch_never_fetches_candidate(self):
        self.pin['release']['sha256'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'digest mismatch'):
            self.ns['prepare']()
        subprocess.run.assert_not_called()

    def test_success_exact_head_app_token_and_changed_workflow_summary(self):
        self.ns['finalize']()
        payload, token = self.posts[0]
        self.assertEqual((payload['head_sha'], payload['conclusion'], token), (HEAD, 'success', 'app-only'))
        self.assertIn('this PR changes the validate workflow; validate ran the changed file', payload['output']['summary'])

    def test_refusal_preserves_changed_workflow_summary(self):
        self.decision.update(decision='run', outcome='rejected')
        self.save_decision()
        os.environ['GATE_SKIP'] = 'false'
        with self.assertRaisesRegex(RuntimeError, 'evidence refused'):
            self.ns['finalize']()
        self.assertEqual(self.posts[0][0]['conclusion'], 'failure')
        self.assertIn(self.decision['summary'], self.posts[0][0]['output']['summary'])

    def test_stale_base_and_incomplete_gate_never_publish_success(self):
        for mutate in (lambda: setattr(self, 'stale', True), lambda: os.environ.update(GATE_SKIP='false'),
                       lambda: os.environ.update(GATE_OUTCOME='failure'), lambda: os.environ.update(APP_OUTCOME='failure')):
            self.stale = False
            os.environ.update(GATE_SKIP='true', GATE_OUTCOME='success', APP_OUTCOME='success')
            mutate()
            with self.assertRaisesRegex(RuntimeError, 'evidence refused'):
                self.ns['finalize']()
            self.assertEqual(self.posts[-1][0]['conclusion'], 'failure')

    def test_app_placeholder_cannot_fall_back_to_workflow_token(self):
        os.environ['APP_TOKEN'] = ''
        with self.assertRaisesRegex(RuntimeError, 'not configured'):
            self.ns['finalize']()
        self.assertEqual(self.posts, [])


def golden():
    fixture = ROOT / 'tests/fixtures/generic-evidence'
    with tempfile.TemporaryDirectory(prefix='generic-adapter-') as scratch:
        work = Path(scratch)
        workflows = work / '.github/workflows'
        workflows.mkdir(parents=True)
        (work / 'genie').symlink_to(ROOT / 'genie', target_is_directory=True)
        (work / 'repos').mkdir()
        (work / 'repos/effect-utils').symlink_to(Path(os.environ['MERGEMASTER_EFFECT_UTILS']), target_is_directory=True)
        shutil.copy2(fixture / 'generic.yml.genie.ts', workflows / 'generic.yml.genie.ts')
        subprocess.run(['git', '-c', 'init.templateDir=', 'init', '--quiet', str(work)], check=True)
        subprocess.run(['genie'], cwd=work, check=True, env=dict(os.environ, HOME=scratch))
        actual = yaml.load((workflows / 'generic.yml').read_text(), Loader=yaml.BaseLoader)
        publisher = actual['jobs']['generic-evidence']
        for index, mode in ((1, 'prepare'), (4, 'finalize')):
            script = publisher['steps'][index]['run']
            expected = f"python3 - {mode} <<'GENERIC_EVIDENCE_PY'\n{SOURCE}\nGENERIC_EVIDENCE_PY"
            assert script.rstrip('\n') == expected, 'generated helper must be exactly base-embedded source'
            publisher['steps'][index]['run'] = script.replace(SOURCE, '<BASE-TRUSTED-PUBLISHER>\n').rstrip('\n')
        for job in actual['jobs'].values():
            for step in job['steps']:
                if 'run' in step:
                    step['run'] = step['run'].rstrip('\n')
        expected = yaml.load((fixture / 'generic.yml').read_text(), Loader=yaml.BaseLoader)
        assert actual == expected, 'Generic generated workflow differs from semantic YAML golden'


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PublisherTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    golden()
