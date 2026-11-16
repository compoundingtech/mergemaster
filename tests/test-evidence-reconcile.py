#!/usr/bin/env python3
"""Offline reconciler contracts; fixture observations contain no credentials."""
import base64
import copy
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('evidence_reconcile', str(ROOT / 'reconciler/main.py'))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = module
loader.exec_module(module)
FIXTURE = json.loads((ROOT / 'tests/fixtures/evidence-reconcile.json').read_text())
CONSUMER = {'id': 'graph', 'owner': 'schickling', 'repository': 'factory',
            'repositoryId': 1398595057, 'defaultBranch': 'main'}
APP_ID = 12345
HEAD = FIXTURE['pull']['head']['sha']
BASE = FIXTURE['base_ref']['object']['sha']
TOKEN = 'fixture-installation-token'
PERMISSIONS = {'checks': 'write', 'contents': 'read', 'pull_requests': 'read', 'metadata': 'read'}


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        directory = ROOT / 'tmp'
        directory.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='evidence-reconcile-test-', dir=directory)
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)


class EnrollmentTests(unittest.TestCase):
    def test_committed_numeric_repository_allowlist(self):
        consumers = module.load_consumers(ROOT / 'iac/consumers.json')
        self.assertEqual([(entry['owner'], entry['repository'], entry['repositoryId']) for entry in consumers],
                         [('schickling', 'factory', 1398595057), ('schickling', 'ptg', 1459778656)])
        self.assertEqual(module.load_consumers(ROOT / 'iac/consumers.json', repo='schickling/factory'), [CONSUMER])
        self.assertEqual(len(module.load_consumers(ROOT / 'iac/consumers.json', pr=998)), 2)

    def test_unknown_repository_and_invalid_pr_filter_fail_closed(self):
        for repo in ('attacker/project', 'https://github.com/schickling/factory', '../factory'):
            with self.subTest(repo=repo), self.assertRaises(Exception):
                module.load_consumers(ROOT / 'iac/consumers.json', repo=repo)
        for number in ('0', '-1', 'not-a-number'):
            with self.subTest(pr=number), self.assertRaises(Exception):
                module.load_consumers(ROOT / 'iac/consumers.json', pr=number)

    def test_required_lanes_are_selected_only_from_base_policy(self):
        policy = {'version': 1, 'lanes': {
            'required': {'mode': 'required_evidence', 'events': ['pull_request']},
            'optional': {'mode': 'optional_fallback', 'events': ['pull_request']},
            'push-only': {'mode': 'required_evidence', 'events': ['push']},
        }}
        self.assertEqual(module.required_lanes(policy), ['required'])


class DecisionTests(unittest.TestCase):
    def decision(self, **updates):
        return {'version': 1, 'check': 'graph-full-check', 'base': BASE, 'head': HEAD,
                'decision': 'skip', 'outcome': 'satisfied', 'report_only': False,
                'summary': 'trusted signed evidence', **updates}

    def result(self, returncode=0, **updates):
        return subprocess.CompletedProcess(['verifier'], returncode, json.dumps(self.decision(**updates)))

    def test_gate_success_requires_exact_identity_and_accepted_decision(self):
        for outcome in ('satisfied', 'reused'):
            success, summary = module.gate_result(self.result(outcome=outcome), 'graph-full-check', BASE, HEAD)
            self.assertTrue(success)
            self.assertEqual(summary, 'trusted signed evidence')
        for update in ({'decision': 'run'}, {'decision': 'refuse'}, {'outcome': 'rejected'},
                       {'report_only': True}, {'report_only': None}):
            with self.subTest(update=update):
                success, _ = module.gate_result(self.result(**update), 'graph-full-check', BASE, HEAD)
                self.assertFalse(success)

    def test_unbound_or_malformed_gate_output_cannot_authorize_success(self):
        for update in ({'version': 2}, {'head': 'a' * 40}, {'base': 'b' * 40},
                       {'check': 'other-lane'}, {'summary': 42}):
            with self.subTest(update=update):
                success, _ = module.gate_result(self.result(**update), 'graph-full-check', BASE, HEAD)
                self.assertFalse(success)
        self.assertFalse(module.gate_result(self.result(returncode=1), 'graph-full-check', BASE, HEAD)[0])


class PublisherFixture(WorkspaceTests):
    def setUp(self):
        super().setUp()
        self.pull = copy.deepcopy(FIXTURE['pull'])
        self.branch = copy.deepcopy(FIXTURE['base_ref'])
        self.checks = []
        self.calls = []
        self.runtime = module.Reconciler(APP_ID, 'fixture-key-not-a-real-pem', 'fixture-bootstrap-token',
                                         workspace=self.workspace)
        self.api = module.Api('fixture-installation-token', request=self.request)

    def request(self, method, path, payload, token):
        self.calls.append((method, path, copy.deepcopy(payload), token))
        if method == 'GET' and path == 'repos/schickling/factory/pulls/998':
            return self.pull
        if method == 'GET' and path == 'repos/schickling/factory/git/ref/heads/main':
            return self.branch
        if method == 'GET' and '/check-runs?' in path:
            return {'check_runs': self.checks}
        if method in ('POST', 'PATCH') and '/check-runs' in path:
            return {'id': 91}
        raise AssertionError((method, path))

    def check(self, identifier=91, **updates):
        return {'id': identifier, 'name': 'graph-full-check', 'head_sha': HEAD, 'app': {'id': APP_ID},
                'status': 'completed', 'conclusion': 'failure', **updates}

    def publish(self, success=True):
        return self.runtime.publish(self.api, CONSUMER, copy.deepcopy(FIXTURE['pull']), BASE,
                                    'graph-full-check', success, 'verified signed evidence')

    def writes(self):
        return [call for call in self.calls if call[0] in ('POST', 'PATCH')]


class PublicationTests(PublisherFixture):
    def test_missing_check_is_created_on_explicit_head_with_app_token(self):
        self.publish()
        writes = self.writes()
        self.assertEqual(len(writes), 1)
        method, path, payload, token = writes[0]
        self.assertEqual((method, path), ('POST', 'repos/schickling/factory/check-runs'))
        self.assertEqual((payload['name'], payload['head_sha'], payload['conclusion']),
                         ('graph-full-check', HEAD, 'success'))
        self.assertEqual(token, 'fixture-installation-token')

    def test_existing_name_head_app_is_patched_not_created(self):
        self.checks = [self.check()]
        self.publish()
        self.assertEqual([(method, path) for method, path, _, _ in self.writes()],
                         [('PATCH', 'repos/schickling/factory/check-runs/91')])
        self.assertEqual(self.writes()[0][2]['conclusion'], 'success')

    def test_other_app_head_or_lane_never_matches_existing_check(self):
        self.checks = [self.check(1, app={'id': APP_ID + 1}), self.check(2, head_sha='c' * 40),
                       self.check(3, name='spoofed')]
        with self.assertRaisesRegex(module.ReconcileError, 'identity mismatch'):
            self.publish()
        self.assertEqual(self.writes(), [])

    def test_failed_verification_patches_existing_green_to_failure(self):
        self.checks = [self.check(conclusion='success')]
        self.publish(False)
        self.assertEqual(self.writes()[0][0], 'PATCH')
        self.assertEqual(self.writes()[0][2]['conclusion'], 'failure')

    def test_changed_head_base_closed_or_fork_never_publishes_success(self):
        mutations = [lambda: self.pull['head'].update(sha='d' * 40),
                     lambda: self.branch['object'].update(sha='e' * 40),
                     lambda: self.pull.update(state='closed'),
                     lambda: self.pull['head']['repo'].update(full_name='attacker/fork')]
        for mutate in mutations:
            self.pull = copy.deepcopy(FIXTURE['pull'])
            self.branch = copy.deepcopy(FIXTURE['base_ref'])
            self.calls.clear()
            mutate()
            with self.subTest(mutate=mutate), self.assertRaises(module.ReconcileError):
                self.publish()
            self.assertEqual(self.writes(), [])


class TokenTests(WorkspaceTests):
    def setUp(self):
        super().setUp()
        self.calls = []
        self.install = {'id': 777, 'app_id': APP_ID, 'account': {'login': 'schickling', 'id': 1}}
        self.token_response = {'token': TOKEN, 'repositories': [copy.deepcopy(FIXTURE['repository'])],
                               'permissions': dict(PERMISSIONS)}
        self.repository = {**FIXTURE['repository'], 'owner': {'login': 'schickling', 'id': 1}}
        self.runtime = module.Reconciler(APP_ID, 'fixture-key', 'fixture-bootstrap',
                                         api_factory=lambda token: module.Api(token, self.request),
                                         workspace=self.workspace)
        self.runtime.jwt = lambda: 'fixture-app-jwt'

    def request(self, method, path, payload, token):
        self.calls.append((method, path, copy.deepcopy(payload), token))
        if (method, path) == ('GET', 'repos/schickling/factory/installation'):
            return self.install
        if (method, path) == ('POST', 'app/installations/777/access_tokens'):
            return self.token_response
        if (method, path) == ('GET', 'repos/schickling/factory'):
            return self.repository
        raise AssertionError((method, path))

    def test_mint_is_one_numeric_repository_and_narrow_permissions(self):
        api = self.runtime.installation(CONSUMER)
        self.assertEqual(api.token, TOKEN)
        minted = [call for call in self.calls if call[0] == 'POST']
        self.assertEqual(minted, [('POST', 'app/installations/777/access_tokens',
                                  {'repository_ids': [1398595057],
                                   'permissions': {'checks': 'write', 'contents': 'read', 'pull_requests': 'read'}},
                                  'fixture-app-jwt')])
        self.assertEqual(self.calls[-1][3], TOKEN)

    def test_wrong_app_or_installation_account_never_mints(self):
        for field, value in (('app_id', APP_ID + 1), ('account', {'login': 'attacker', 'id': 2})):
            original = copy.deepcopy(self.install)
            self.install[field] = value
            self.calls.clear()
            with self.subTest(field=field), self.assertRaises(module.ReconcileError):
                self.runtime.installation(CONSUMER)
            self.assertFalse(any(method == 'POST' for method, _, _, _ in self.calls))
            self.install = original

    def test_overbroad_or_wrong_repository_token_is_rejected(self):
        cases = [
            {'repositories': [FIXTURE['repository'], {'id': 999, 'full_name': 'attacker/project'}]},
            {'repositories': [{**FIXTURE['repository'], 'id': 999}]},
            {'repositories': [{**FIXTURE['repository'], 'full_name': 'attacker/project'}]},
            {'permissions': {**PERMISSIONS, 'actions': 'write'}},
            {'permissions': {**PERMISSIONS, 'contents': 'write'}},
            {'permissions': {'checks': 'write'}},
        ]
        for changes in cases:
            original = copy.deepcopy(self.token_response)
            self.token_response.update(changes)
            with self.subTest(changes=changes), self.assertRaises(module.ReconcileError):
                self.runtime.installation(CONSUMER)
            self.token_response = original

    def test_live_repository_transfer_or_replacement_is_rejected(self):
        self.repository['id'] += 1
        with self.assertRaisesRegex(module.ReconcileError, 'identity mismatch'):
            self.runtime.installation(CONSUMER)

    def test_api_rejects_external_urls_and_path_traversal_before_transport(self):
        api = module.Api(TOKEN, self.request)
        for path in ('https://attacker.invalid/repos/x/y', 'repos/../attacker',
                     'repos/x/y\nAuthorization: forged', 'repos/x/y#fragment'):
            with self.subTest(path=path), self.assertRaises(module.ReconcileError):
                api.call('GET', path)
        self.assertEqual(self.calls, [])

    def test_jwt_delegates_rs256_to_openssl_and_removes_private_file(self):
        paths = []
        def execute(args, **kwargs):
            self.assertEqual(args[:4], ['openssl', 'dgst', '-sha256', '-sign'])
            key = Path(args[4])
            paths.append(key)
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            self.assertEqual(key.read_text(), 'fixture-key')
            self.assertNotIn('fixture-key', ' '.join(args))
            self.assertNotIn('MERGEMASTER_APP_PRIVATE_KEY', kwargs['env'])
            return subprocess.CompletedProcess(args, 0, b'fixture-signature')
        runtime = module.Reconciler(APP_ID, 'fixture-key', 'fixture-bootstrap', run=execute,
                                    environ={'MERGEMASTER_APP_PRIVATE_KEY': 'fixture-key'},
                                    workspace=self.workspace)
        with patch.object(module.time, 'time', return_value=1700000000):
            token = runtime.jwt()
        header, claims, _ = [base64.urlsafe_b64decode(part + '=' * (-len(part) % 4))
                             for part in token.split('.')]
        self.assertEqual(json.loads(header), {'alg': 'RS256', 'typ': 'JWT'})
        self.assertEqual(json.loads(claims), {'iss': str(APP_ID), 'iat': 1699999940, 'exp': 1700000540})
        self.assertTrue(paths)
        self.assertFalse(any(path.exists() for path in paths))


class BaseVerifierTests(PublisherFixture):
    def setUp(self):
        super().setUp()
        self.commands, self.gates = [], []
        self.asset = b'fixture-pinned-verifier'
        self.pin = {'version': 1, 'repository': 'compoundingtech/mergemaster', 'revision': 'c' * 40,
                    'release': {'version': 'v1.2.3', 'sha256': hashlib.sha256(self.asset).hexdigest()}}
        self.policy = {'version': 1, 'lanes': {
            'graph-full-check': {'mode': 'required_evidence', 'events': ['pull_request']},
            'not-required': {'mode': 'optional_fallback', 'events': ['pull_request']},
        }}
        self.returncode = 0
        self.runtime.command = self.command
        self.runtime.run = self.gate

    def command(self, args, token, cwd=None, data=None, binary=False, extra_env=None):
        self.commands.append((args, token, cwd, extra_env))
        if args[0] == 'git':
            self.assertEqual(args[1:3], ['-c', 'core.hooksPath=/dev/null'])
            git = args[3:]
            if git == ['show', BASE + ':.mergemaster/lanes.json']:
                return json.dumps(self.policy)
            if git == ['show', BASE + ':.mergemaster/tool-pin.json']:
                return json.dumps(self.pin)
            if git == ['rev-parse', 'HEAD']:
                return BASE
            if git[0] == 'show':
                self.fail('Non-BASE authorization read: ' + repr(git))
            return ''
        if args[:3] == ['gh', 'release', 'download']:
            destination = Path(args[args.index('--dir') + 1])
            (destination / 'mergemaster-x86_64-unknown-linux-musl').write_bytes(self.asset)
            return ''
        if args[:3] == ['gh', 'attestation', 'verify']:
            return ''
        self.fail('Unexpected subprocess: ' + repr(args))

    def gate(self, args, **kwargs):
        self.gates.append((args, kwargs))
        self.assertEqual(args[1], 'gate')
        self.assertEqual(args[args.index('--base') + 1], BASE)
        self.assertEqual(args[args.index('--head') + 1], HEAD)
        event = json.loads(Path(args[args.index('--event-file') + 1]).read_text())
        self.assertEqual(event['repository']['full_name'], 'schickling/factory')
        self.assertEqual(event['repository']['id'], CONSUMER['repositoryId'])
        self.assertEqual(event['pull_request']['base']['sha'], BASE)
        self.assertEqual(kwargs['env']['GITHUB_REPOSITORY'], 'schickling/factory')
        self.assertEqual(kwargs['env']['GITHUB_TOKEN'], TOKEN)
        self.assertEqual(kwargs['env']['GH_TOKEN'], TOKEN)
        self.assertNotIn('MERGEMASTER_APP_PRIVATE_KEY', kwargs['env'])
        value = {'version': 1, 'check': args[args.index('--check') + 1], 'head': HEAD, 'base': BASE,
                 'decision': 'skip', 'outcome': 'satisfied', 'report_only': False,
                 'summary': 'existing pinned verifier accepted signed evidence'}
        return subprocess.CompletedProcess(args, self.returncode, json.dumps(value))

    def test_base_only_authorization_and_no_candidate_checkout_or_execution(self):
        self.assertEqual(self.runtime.reconcile_pull(self.api, CONSUMER, 998), 0)
        git_calls = [args[3:] for args, _, _, _ in self.commands if args[0] == 'git']
        self.assertEqual([args for args in git_calls if args[0] == 'checkout'],
                         [['checkout', '--detach', '--force', BASE]])
        self.assertEqual([args for args in git_calls if args[0] == 'show'],
                         [['show', BASE + ':.mergemaster/lanes.json'],
                          ['show', BASE + ':.mergemaster/tool-pin.json']])
        fetch = next(args for args in git_calls if args[0] == 'fetch')
        self.assertIn(HEAD, fetch)
        self.assertIn('+refs/notes/evidence/*:refs/notes/evidence/*', fetch)
        self.assertEqual(len(self.gates), 1)
        self.assertEqual(self.writes()[0][2]['conclusion'], 'success')
        attestation = next(args for args, _, _, _ in self.commands if args[:3] == ['gh', 'attestation', 'verify'])
        self.assertIn('--deny-self-hosted-runners', attestation)
        self.assertEqual(attestation[attestation.index('--source-digest') + 1], self.pin['revision'])
        self.assertEqual(attestation[attestation.index('--signer-digest') + 1], self.pin['revision'])
        bootstrap = [token for args, token, _, _ in self.commands if args[0] == 'gh']
        self.assertTrue(all(token == 'fixture-bootstrap-token' for token in bootstrap))

    def test_nonzero_verifier_cannot_publish_claimed_success(self):
        self.returncode = 1
        self.assertGreater(self.runtime.reconcile_pull(self.api, CONSUMER, 998), 0)
        self.assertEqual(self.writes()[0][2]['conclusion'], 'failure')

    def test_bad_release_digest_posts_failure_without_running_verifier(self):
        self.pin['release']['sha256'] = '0' * 64
        self.assertGreater(self.runtime.reconcile_pull(self.api, CONSUMER, 998), 0)
        self.assertEqual(self.gates, [])
        self.assertEqual(self.writes()[0][2]['conclusion'], 'failure')
        self.assertFalse(any(args[:3] == ['gh', 'attestation', 'verify'] for args, _, _, _ in self.commands))

    def test_repository_failure_does_not_skip_other_enrolled_work(self):
        entries = module.load_consumers(ROOT / 'iac/consumers.json')
        with patch.object(self.runtime, 'reconcile_consumer', side_effect=[module.ReconcileError('fixture'), 0]) as run:
            self.assertEqual(self.runtime.run_all(entries), 1)
        self.assertEqual(run.call_count, 2)


class WorkflowTests(unittest.TestCase):
    def test_hostless_main_only_serialized_schedule_and_manual_repair(self):
        workflow = (ROOT / '.github/workflows/evidence-reconcile.yml').read_text()
        for contract in ("cron: '2-57/5 * * * *'", 'workflow_dispatch:', 'runs-on: ubuntu-24.04',
                         "if: github.ref == 'refs/heads/main'", 'environment: mergemaster-check-publisher',
                         'group: evidence-reconcile', 'cancel-in-progress: false', 'persist-credentials: false'):
            self.assertIn(contract, workflow)
        before_run, run_step = workflow.split('      - name: Reconcile enrolled evidence checks', 1)
        self.assertNotIn('MERGEMASTER_APP_PRIVATE_KEY', before_run)
        self.assertIn('MERGEMASTER_APP_PRIVATE_KEY: ${{ secrets.MERGEMASTER_APP_PRIVATE_KEY }}', run_step)
        self.assertNotIn('checks: write', workflow)
        self.assertNotIn('contents: write', workflow)
        self.assertNotIn('self-hosted', workflow)


if __name__ == '__main__':
    unittest.main()
