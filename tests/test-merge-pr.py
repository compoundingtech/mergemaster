#!/usr/bin/env python3
"""Run with python3 tests/test-merge-pr.py; no network or daemon required."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('merge_pr', str(ROOT / 'scripts/merge-pr'))
spec = importlib.util.spec_from_loader(loader.name, loader)
gate = importlib.util.module_from_spec(spec)
loader.exec_module(gate)
HEAD, BASE, MERGE, TREE = ('a' * 40, 'b' * 40, 'c' * 40, 'd' * 40)
CI_BASE, CI_MERGE = 'e' * 40, 'f' * 40
REF, SECOND = 'message/1111111111111111', 'message/2222222222222222'


def message(ref=REF, sender='agent/reviewer', body=None, index=1, title='GO compoundingtech/mergemaster#376'):
    return {'subject': ref, 'from': sender, 'to': gate.ACTOR, 'title': title,
            'content': HEAD if body is None else body, 'created_index': index}


class GateTests(unittest.TestCase):
    def setUp(self):
        (ROOT / 'tmp').mkdir(exist_ok=True)
        self.common = tempfile.TemporaryDirectory(prefix='merge-pr-lock-', dir=ROOT / 'tmp')
        self.addCleanup(self.common.cleanup)
        self.main_tip = BASE
        self.post_parents = f'{BASE} {HEAD}'
        self.post_tree = TREE
        self.tested_commit = MERGE
        self.tested_tree = TREE
        self.diffs = {}
        self.merge_bases = {}
        self.other_runs = []
        self.pr = {'state': 'open', 'draft': False, 'mergeable': True, 'base': {'ref': 'main'},
                   'head': {'sha': HEAD}, 'user': {'login': 'shared-bot'}, 'merge_commit_sha': MERGE}
        self.run = {'id': 12, 'head_sha': HEAD, 'pull_requests': [{'number': 376}],
                    'run_attempt': 1, 'status': 'completed', 'conclusion': 'success', 'html_url': 'https://ci/12'}
        self.check = {'name': 'checks', 'head_sha': HEAD, 'status': 'completed', 'conclusion': 'success', 'html_url': 'https://checks/1'}
        self.files = 'src/main.rs\0'
        self.raced = False
        self.merge_calls = []
        self.merge_status = 200
        self.merge_response = {'status': 'merged', 'details': {'sha': MERGE}}
        self.poll_responses = []
        self.poll_calls = []
        self.pending = {'status': 'pending', 'details': {
            'uuid': '11111111-1111-1111-1111-111111111111',
            'expected_head_sha': HEAD, 'merge_method': 'merge', 'merge_action': 'direct_merge'}}
        self.messages = [message(), message(SECOND, 'agent/second', index=2)]
        self.jobs = [{'status': 'completed', 'conclusion': 'success', 'runner_group_name': 'GitHub Actions'}]
        agent = ('schickling-assistant', 'agent@example.invalid')
        self.commit_rows = [(HEAD, *agent, *agent)]
        self.merge_rows = [(MERGE, *agent, *agent)]

    def mock_command(self, *args, binary=False, allow_conflict=False):
        if args[:2] == ('gh', 'api'):
            path = args[2].removeprefix(f'repos/{gate.REPO}/')
            if path == 'pulls/376/merge-async':
                self.merge_calls.append(args)
                self.assertTrue(allow_conflict)
                self.assertIn('--include', args)
                return f'HTTP/2.0 {self.merge_status} Response\r\nContent-Type: application/json\r\n\r\n{json.dumps(self.merge_response)}'
            if path.startswith('pulls/376/merge-async/'):
                self.poll_calls.append(path)
                self.assertEqual(path, f'pulls/376/merge-async/{self.pending["details"]["uuid"]}')
                return json.dumps(self.poll_responses.pop(0))
            if path == 'pulls/376':
                data = self.pr
            elif path == 'git/ref/heads/main':
                data = {'object': {'sha': self.main_tip}}
            elif path.startswith('actions/runs/12/attempts/') and '/jobs?' in path:
                data = {'jobs': self.jobs}
            elif path.startswith('commits/'):
                data = {'check_runs': [self.check]}
            elif path.startswith('actions/workflows/'):
                data = {'workflow_runs': [self.run]}
            elif path.startswith('actions/runs?head_sha='):
                data = {'workflow_runs': [self.run, *self.other_runs]}
            elif path == 'actions/runs/12/logs':
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, 'w') as archive:
                    archive.writestr('checks/checkout.txt', f'##[group]Getting Git version info\ncheckout refs/remotes/pull/376/merge\n[command]/usr/bin/git log -1 --format=%H\n2026-01-01T00:00:00Z {self.tested_commit}\n')
                return buffer.getvalue()
            else:
                raise AssertionError(args)
            return json.dumps(data)
        if args[:3] == ('st', 'conversations', 'ls'):
            return json.dumps([] if '--archive' in args else self.messages)
        if args[0] == 'git':
            if args[1] == 'ls-remote':
                return f'{BASE}\trefs/heads/main\n{HEAD}\trefs/pull/376/head\n{MERGE}\trefs/pull/376/merge'
            if args[1] == 'fetch':
                return ''
            if args[1] == 'log':
                revision = args[-2]
                if revision == f'{BASE}..{HEAD}':
                    rows = self.commit_rows
                elif revision == f'{MERGE}^!':
                    rows = self.merge_rows
                else:
                    raise AssertionError(args)
                return '\n'.join('\x1f'.join(row) for row in rows)
            if args[1] == 'merge-base':
                return self.merge_bases.get(args[-2:], args[-2])
            if args[1] == 'show':
                if args[-1] == CI_MERGE:
                    return f'{CI_BASE} {HEAD}'
                return self.post_parents if self.merge_calls or self.pr['state'] == 'closed' else f'{BASE} {HEAD}'
            if args[1] == 'merge-tree':
                return TREE
            if args[1] == 'rev-parse':
                if args[2] == '--git-common-dir':
                    return self.common.name
                if args[2] == f'{CI_MERGE}^{{tree}}':
                    return self.tested_tree
                return self.post_tree if self.merge_calls or self.pr['state'] == 'closed' else TREE
            if args[1] == 'diff':
                if args[-2:] in self.diffs:
                    return self.diffs[args[-2:]]
                return self.files if args[-2:] == (BASE, HEAD) else ('src/main.rs\0' if self.raced else '')
        raise AssertionError(args)

    def run_gate(self, *extra):
        output = io.StringIO()
        with patch.object(gate, 'command', self.mock_command), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = gate.main(['376', '--author-agent', gate.ACTOR, '--go-head', HEAD, '--go-ref', REF, *extra])
        return code, output.getvalue()

    def run_verification(self, *extra):
        self.pr['state'] = 'closed'
        output = io.StringIO()
        with patch.object(gate, 'command', side_effect=self.mock_command) as calls, \
                patch.object(gate, 'run_gate', side_effect=AssertionError('verification must not run merge gates')), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = gate.main(['376', '--go-head', HEAD, '--verify-merged', MERGE,
                              '--verify-base', BASE, *extra])
        self.assertFalse(any(call.args[:3] == ('st', 'conversations', 'ls') for call in calls.call_args_list))
        self.assertEqual(self.merge_calls, [])
        return code, output.getvalue()

    def assert_recovery_commands(self, output):
        endpoint = f'repos/{gate.REPO}/pulls/376/merge-async/{self.pending["details"]["uuid"]}'
        self.assertIn(f'gh api {endpoint}', output)
        self.assertIn(f'MERGE_SHA=$(gh api {endpoint} --jq \'select(.status == "merged") | .details.sha\')', output)
        self.assertIn(f'scripts/merge-pr 376 --go-head {HEAD} --verify-base {BASE} --verify-merged "$MERGE_SHA"', output)
        self.assertIn('never merges or automatically reverts', output)

    def test_verify_completed_merge_without_approvals_or_merge_request(self):
        code, output = self.run_verification()
        self.assertEqual(code, 0, output)
        self.assertIn(f'PASS post-merge: merge={MERGE}', output)

    def test_verify_completed_merge_checks_parents_tree_and_pr_commit(self):
        for field, value in (('post_parents', f'{CI_BASE} {HEAD}'), ('post_tree', HEAD),
                             ('merge_commit_sha', CI_MERGE)):
            with self.subTest(field=field):
                self.post_parents, self.post_tree = f'{BASE} {HEAD}', TREE
                self.pr['merge_commit_sha'] = MERGE
                if field == 'merge_commit_sha':
                    self.pr[field] = value
                else:
                    setattr(self, field, value)
                code, output = self.run_verification()
                self.assertEqual(code, 1, output)
                self.assertIn('POST-MERGE MISMATCH', output)

    def test_verify_completed_merge_checks_casefolded_authorship(self):
        original = self.merge_rows[0]
        for field in (1, 3):
            with self.subTest(field=field):
                row = list(original)
                row[field] = 'jOhAnNeS sChIcKlInG'
                self.merge_rows = [tuple(row)]
                code, output = self.run_verification()
                self.assertEqual(code, 1, output)
                self.assertIn('HUMAN AUTHORSHIP IN NEW MAIN MERGE COMMIT', output)

    def test_verification_requires_original_full_sha_inputs(self):
        for extra in (['--verify-base', ''], ['--verify-base', BASE[:8]],
                      ['--go-head', HEAD[:8]], ['--verify-merged', ''], ['--dry-run']):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                self.run_verification(*extra)
            self.assertEqual(raised.exception.code, 2)

    def test_human_names_refuse_case_insensitively(self):
        original = self.commit_rows[0]
        for field in (1, 3):
            for name in ('johannes schickling', 'JOHANNES SCHICKLING', 'jOhAnNeS sChIcKlInG'):
                with self.subTest(field=field, name=name):
                    row = list(original)
                    row[field] = name
                    self.commit_rows = [tuple(row)]
                    code, output = self.run_gate()
                    self.assertEqual(code, 1, output)
                    self.assertIn('FAIL no-human-authorship', output)
                    self.assertEqual(self.merge_calls, [])

    def test_async_unexpected_poll_status_prints_recovery(self):
        self.merge_status = 202
        self.merge_response = self.pending
        self.poll_responses = [{'status': 'unexpected', 'details': {}}]
        with patch.object(gate.time, 'sleep'):
            code, output = self.run_gate()
        self.assertEqual(code, 1, output)
        self.assertIn('async merge status=unexpected', output)
        self.assert_recovery_commands(output)

    def test_async_poll_read_failure_prints_recovery(self):
        self.merge_status = 202
        self.merge_response = self.pending
        original = self.mock_command
        def fail_poll(*args, **kwargs):
            if args[:2] == ('gh', 'api') and '/merge-async/' in args[2]:
                raise RuntimeError('result read unavailable')
            return original(*args, **kwargs)
        with patch.object(self, 'mock_command', fail_poll), patch.object(gate.time, 'sleep'):
            code, output = self.run_gate()
        self.assertEqual(code, 1, output)
        self.assertIn('result read unavailable', output)
        self.assert_recovery_commands(output)

    def test_dry_run_and_guarded_merge(self):
        code, output = self.run_gate('--dry-run')
        self.assertEqual(code, 0, output)
        self.assertIn('PASS ci-base-overlap', output)
        self.assertEqual(self.merge_calls, [])
        self.assertEqual(self.run_gate()[0], 0)
        self.assertEqual(self.merge_calls[0][3:], (
            '--method', 'PUT', '-f', f'sha={HEAD}', '-f', 'merge_method=merge',
            '-f', 'merge_action=direct_merge', '--include'))

    def test_async_accepted_pending_then_merged(self):
        self.merge_status = 202
        self.merge_response = self.pending
        self.poll_responses = [self.pending, {'status': 'merged', 'details': {'sha': MERGE}}]
        with patch.object(gate.time, 'sleep') as sleep:
            code, output = self.run_gate()
        self.assertEqual(code, 0, output)
        self.assertIn('PASS post-merge', output)
        self.assertEqual(len(self.poll_calls), 2)
        self.assertEqual(sleep.call_args_list, [unittest.mock.call(3), unittest.mock.call(3)])

    def test_async_already_merged_verifies_matching_commit(self):
        code, output = self.run_gate()
        self.assertEqual(code, 0, output)
        self.assertIn(f'PASS post-merge: merge={MERGE}', output)
        self.assertEqual(self.poll_calls, [])

    def test_async_failed_enqueued_and_unknown_refuse(self):
        for status in ('failed', 'enqueued', 'unknown'):
            with self.subTest(status=status):
                self.merge_response = {'status': status, 'details': {'message': 'merge refused'}}
                code, output = self.run_gate()
                self.assertEqual(code, 1, output)
                self.assertIn(f'async merge status={status}', output)
                self.assertIn('merge refused', output)
                self.assertNotIn('PASS post-merge', output)

    def test_async_pending_failure_refuses(self):
        self.merge_status = 202
        self.merge_response = self.pending
        self.poll_responses = [{'status': 'failed', 'details': {'message': 'head changed'}}]
        with patch.object(gate.time, 'sleep'):
            code, output = self.run_gate()
        self.assertEqual(code, 1, output)
        self.assertIn('head changed', output)

    def test_async_conflicting_request_options_refuse(self):
        self.merge_status = 409
        for field, value in (('expected_head_sha', BASE), ('merge_method', 'squash'),
                             ('merge_action', 'merge_queue')):
            with self.subTest(field=field):
                self.merge_response = {'status': 'pending', 'details': {**self.pending['details'], field: value}}
                code, output = self.run_gate()
                self.assertEqual(code, 1, output)
                self.assertIn('does not match approved head/method/action', output)
                self.assertEqual(self.poll_calls, [])

    def test_async_matching_conflict_resumes_polling(self):
        self.merge_status = 409
        self.merge_response = self.pending
        self.poll_responses = [{'status': 'merged', 'details': {'sha': MERGE}}]
        with patch.object(gate.time, 'sleep'):
            code, output = self.run_gate()
        self.assertEqual(code, 0, output)
        self.assertEqual(len(self.poll_calls), 1)

    def test_async_deadline_exceeded(self):
        self.merge_status = 202
        self.merge_response = self.pending
        self.poll_responses = [self.pending]
        with patch.object(gate.time, 'monotonic', side_effect=[0, 0, 3, 600]), patch.object(gate.time, 'sleep'):
            code, output = self.run_gate()
        self.assertEqual(code, 1, output)
        self.assertIn('async merge deadline exceeded', output)
        self.assertIn('merge may still complete', output)
        self.assert_recovery_commands(output)
        self.assertEqual(len(self.poll_calls), 1)

    def test_async_merge_commit_must_match_pr_commit(self):
        self.merge_response = {'status': 'merged', 'details': {'sha': CI_MERGE}}
        code, output = self.run_gate()
        self.assertEqual(code, 1, output)
        self.assertIn('POST-MERGE MISMATCH', output)
        self.assertIn('differs from async merge commit', output)

    def test_async_merged_without_commit_refuses(self):
        self.merge_response = {'status': 'merged', 'details': {}}
        code, output = self.run_gate()
        self.assertEqual(code, 1, output)
        self.assertIn('did not identify a full merge commit SHA', output)

    def test_open_downstack_base_refuses(self):
        self.pr['base']['ref'] = 'open-downstack-branch'
        code, output = self.run_gate()
        self.assertEqual(code, 1, output)
        self.assertIn('FAIL ready', output)
        self.assertEqual(self.merge_calls, [])

    def test_final_snapshot_rechecks_downstack_base(self):
        original = self.mock_command
        reads = 0
        def retarget(*args, **kwargs):
            nonlocal reads
            if args[:3] == ('gh', 'api', f'repos/{gate.REPO}/pulls/376'):
                reads += 1
                if reads == 2:
                    self.pr['base']['ref'] = 'open-downstack-branch'
            return original(*args, **kwargs)
        with patch.object(self, 'mock_command', retarget):
            code, output = self.run_gate()
        self.assertEqual(code, 1, output)
        self.assertIn('FAIL final-snapshot', output)
        self.assertEqual(self.merge_calls, [])

    def test_async_http_conflict_body_survives_gh_nonzero_exit(self):
        response = f'HTTP/2.0 409 Conflict\r\nContent-Type: application/json\r\n\r\n{json.dumps(self.pending)}'
        completed = gate.subprocess.CompletedProcess([], 1, response.encode(), b'gh: conflict (HTTP 409)')
        with patch.object(gate.subprocess, 'run', return_value=completed):
            self.assertEqual(gate.api('pulls/376/merge-async', allow_conflict=True), self.pending)
            with self.assertRaisesRegex(RuntimeError, 'HTTP 409'):
                gate.command('gh', 'api', 'ordinary-read')

    def test_async_other_http_errors_refuse(self):
        for status in (400, 403, 500):
            with self.subTest(status=status):
                completed = gate.subprocess.CompletedProcess(
                    [], 1, f'HTTP/2.0 {status} Error\r\n\r\n{{}}'.encode(), b'gh: refused')
                with patch.object(gate.subprocess, 'run', return_value=completed):
                    with self.assertRaisesRegex(RuntimeError, 'refused'):
                        gate.api('pulls/376/merge-async', allow_conflict=True)

    def test_agent_identities_pass_before_and_after_merge(self):
        code, output = self.run_gate()
        self.assertEqual(code, 0, output)
        self.assertIn('PASS no-human-authorship', output)
        self.assertIn('PASS post-merge', output)
        self.assertEqual(len(self.merge_calls), 1)

    def test_agent_noreply_identity_is_not_human(self):
        agent = ('schickling-assistant', '261620128+schickling-assistant@users.noreply.github.com')
        self.commit_rows = [(HEAD, *agent, *agent)]
        self.merge_rows = [(MERGE, *agent, *agent)]
        code, output = self.run_gate()
        self.assertEqual(code, 0, output)
        self.assertIn('PASS no-human-authorship', output)

    def test_human_author_refuses_even_in_non_head_commit(self):
        for field, value in [(1, gate.HUMAN_NAME), (2, gate.HUMAN_EMAIL), (2, 'Schickling.J@Gmail.com'),
                             (2, 'schickling@users.noreply.github.com'),
                             (2, '1567498+Schickling@users.noreply.github.com')]:
            with self.subTest(field=field, value=value):
                row = list(self.commit_rows[0])
                row[0] = CI_BASE
                row[field] = value
                self.commit_rows = [self.commit_rows[0], tuple(row)]
                code, output = self.run_gate()
                self.assertEqual(code, 1, output)
                self.assertIn('FAIL no-human-authorship', output)
                self.assertIn(CI_BASE, output)
                self.assertIn('re-author on a new signed branch with the agent identity, or land by squash, as Manager decides', output)
                self.assertEqual(self.merge_calls, [])

    def test_human_committer_refuses(self):
        original = self.commit_rows[0]
        for field, value in [(3, gate.HUMAN_NAME), (4, gate.HUMAN_EMAIL), (4, 'SCHICKLING.J@GMAIL.COM')]:
            with self.subTest(field=field, value=value):
                row = list(original)
                row[field] = value
                self.commit_rows = [tuple(row)]
                code, output = self.run_gate()
                self.assertEqual(code, 1, output)
                self.assertIn('FAIL no-human-authorship', output)
                self.assertIn(HEAD, output)
                self.assertEqual(self.merge_calls, [])

    def test_human_merge_author_or_committer_reports_coord(self):
        original = self.merge_rows[0]
        for field, value in [(1, gate.HUMAN_NAME), (2, gate.HUMAN_EMAIL),
                             (3, gate.HUMAN_NAME), (4, gate.HUMAN_EMAIL)]:
            with self.subTest(field=field):
                self.merge_calls.clear()
                row = list(original)
                row[field] = value
                self.merge_rows = [tuple(row)]
                code, output = self.run_gate()
                self.assertEqual(code, 1, output)
                self.assertEqual(len(self.merge_calls), 1)
                self.assertIn('HUMAN AUTHORSHIP IN NEW MAIN MERGE COMMIT', output)
                self.assertIn(MERGE, output)
                self.assertIn('post on COORD', output)

    def test_post_merge_mismatch_reported_before_merge_authorship(self):
        self.post_tree = HEAD
        self.merge_rows = [(MERGE, gate.HUMAN_NAME, gate.HUMAN_EMAIL, gate.HUMAN_NAME, gate.HUMAN_EMAIL)]
        code, output = self.run_gate()
        self.assertEqual(code, 1, output)
        self.assertIn('merged parents/tree differ from validated merge', output)
        self.assertNotIn('HUMAN AUTHORSHIP IN NEW MAIN MERGE COMMIT', output)

    def test_author_argument_required_and_other_authors_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            gate.main(['376', '--go-head', HEAD, '--go-ref', REF])
        self.assertEqual(raised.exception.code, 2)
        code, output = self.run_gate('--dry-run', '--author-agent', 'agent/other-author')
        self.assertEqual(code, 1)
        self.assertIn('PRs by other agents: no verified author binding yet; merge them manually under review', output)

    def test_author_cannot_supply_second_go(self):
        self.files = '.github/workflows/ci.yml\0'
        self.messages[1]['from'] = gate.ACTOR
        code, output = self.run_gate('--dry-run', '--second-go-ref', SECOND)
        self.assertEqual(code, 1)
        self.assertIn('FAIL sensitive-second-go', output)

    def test_author_self_addressed_no_go_blocks_until_author_clears_it(self):
        withdrawal = message('message/3333333333333333', gate.ACTOR, HEAD, 3,
                             title='NO-GO compoundingtech/mergemaster#376')
        self.messages.append(withdrawal)
        code, output = self.run_gate()
        self.assertEqual(code, 1)
        self.assertIn('FAIL binding-verdicts', output)
        self.assertEqual(self.merge_calls, [])
        self.messages.append(message('message/4444444444444444', 'agent/other', HEAD, 4))
        self.assertEqual(self.run_gate('--dry-run')[0], 1)
        self.messages.append(message('message/5555555555555555', gate.ACTOR, HEAD, 5))
        self.assertEqual(self.run_gate('--dry-run')[0], 0)
        self.messages[0]['content'] = BASE
        self.assertEqual(self.run_gate('--dry-run')[0], 1)

    def test_exclusive_common_dir_lock_covers_execution(self):
        def locked_run(args):
            with (Path(self.common.name) / 'merge-pr.lock').open('a') as contender:
                with self.assertRaises(BlockingIOError):
                    gate.fcntl.flock(contender.fileno(), gate.fcntl.LOCK_EX | gate.fcntl.LOCK_NB)
            return 0
        with patch.object(gate, 'run_gate', side_effect=locked_run):
            self.assertEqual(self.run_gate('--dry-run')[0], 0)
        with (Path(self.common.name) / 'merge-pr.lock').open('a') as contender:
            gate.fcntl.flock(contender.fileno(), gate.fcntl.LOCK_EX | gate.fcntl.LOCK_NB)

    def test_last_main_read_refuses_before_merge(self):
        self.main_tip = HEAD
        code, output = self.run_gate()
        self.assertEqual(code, 1)
        self.assertIn('main changed immediately before merge', output)
        self.assertEqual(self.merge_calls, [])

    def test_post_merge_detects_other_writer_window(self):
        self.post_parents = f'{HEAD} {HEAD}'
        code, output = self.run_gate()
        self.assertEqual(code, 1)
        self.assertEqual(len(self.merge_calls), 1)
        self.assertIn('POST-MERGE MISMATCH: revert or fresh CI required', output)
        self.assertIn(f'git revert -m 1 {MERGE}', output)
        self.assertIn(f'validated_base={BASE}', output)

    def test_post_merge_tree_mismatch_and_unreadable_commit_fail(self):
        for tree, commit in [(HEAD, MERGE), (TREE, None)]:
            self.merge_calls.clear()
            self.post_tree = tree
            self.pr['merge_commit_sha'] = commit
            code, output = self.run_gate()
            self.assertEqual(code, 1)
            self.assertIn('POST-MERGE MISMATCH: revert or fresh CI required', output)

    def test_author_wrong_head_and_no_go_refuse(self):
        for row in [message(sender=gate.ACTOR), message(body=BASE), message(title='NO-GO compoundingtech/mergemaster#376')]:
            self.messages[0] = row
            code, output = self.run_gate('--dry-run')
            self.assertEqual(code, 1, output)
            self.assertIn('FAIL source-go', output)
        self.assertEqual(self.merge_calls, [])

    def test_latest_no_go_blocks_until_same_sender_go(self):
        self.messages.append(message('message/3333333333333333', 'agent/blocker', BASE, 3,
                                     title='NO-GO compoundingtech/mergemaster#376'))
        self.assertEqual(self.run_gate('--dry-run')[0], 1)
        self.messages.append(message('message/4444444444444444', 'agent/blocker', HEAD, 4))
        self.assertEqual(self.run_gate('--dry-run')[0], 0)

    def test_old_head_go_neither_counts_nor_blocks(self):
        self.messages[1]['content'] = f'GO {BASE}'
        self.assertEqual(self.run_gate('--dry-run')[0], 0)
        self.files = '.github/workflows/ci.yml\0'
        self.assertEqual(self.run_gate('--dry-run', '--second-go-ref', SECOND)[0], 1)

    def test_sensitive_files_require_distinct_named_second(self):
        self.files = '.github/workflows/ci.yml\0iac/index.ts\0'
        self.assertEqual(self.run_gate('--dry-run')[0], 1)
        self.assertEqual(self.run_gate('--dry-run', '--second-go-ref', REF)[0], 1)
        self.assertEqual(self.run_gate('--dry-run', '--second-go-ref', SECOND)[0], 0)

    def test_casual_content_verdicts_never_count(self):
        for title in ['mergemaster #376 NO-GO fix', 'Re: #376 merger', 'Plan for compoundingtech/mergemaster#376']:
            self.messages[0].update(title=title, content=f'merge after GO at {HEAD}')
            self.assertEqual(self.run_gate('--dry-run')[0], 1)

    def test_abbreviated_or_missing_head_is_ignored(self):
        for body in [HEAD[:8], HEAD[:39], '', 'GO', HEAD + 'a']:
            self.messages[0]['content'] = body
            self.assertEqual(self.run_gate('--dry-run')[0], 1)
        row = message(body=HEAD[:8], title='NO-GO compoundingtech/mergemaster#376')
        self.assertEqual(gate.verdicts([row], 376, HEAD), {})

    def test_subject_prefixes_and_suffixes(self):
        for title in ['SOURCE GO compoundingtech/mergemaster#376',
                      'Re: GO compoundingtech/mergemaster#376',
                      'Re: SOURCE GO compoundingtech/mergemaster#376: reviewed',
                      'GO compoundingtech/mergemaster#376 approved']:
            self.messages[0]['title'] = title
            self.assertEqual(self.run_gate('--dry-run')[0], 0)
        for title in ['GO compoundingtech/mergemaster#3760', 'GO compoundingtech/mergemaster#376x',
                      'FYI GO compoundingtech/mergemaster#376', 'GO other/repo#376']:
            self.messages[0]['title'] = title
            self.assertEqual(self.run_gate('--dry-run')[0], 1)

    def test_exact_reviewer_subject_with_sha_only_content(self):
        self.messages[0].update(title='GO compoundingtech/mergemaster#376', content=HEAD)
        self.assertEqual(self.run_gate('--dry-run')[0], 0)
        self.messages[0]['title'] = 'NO-GO compoundingtech/mergemaster#376'
        self.assertEqual(self.run_gate('--dry-run')[0], 1)

    def test_content_words_do_not_change_subject_verdict(self):
        self.messages[0].update(title='GO compoundingtech/mergemaster#376', content=f'Previously NO-GO; fixed at {HEAD}')
        self.assertEqual(self.run_gate('--dry-run')[0], 0)

    def test_absent_ref_fails_without_marking_message_read(self):
        with self.assertRaisesRegex(RuntimeError, 'absent'):
            gate.approval(REF, {}, [], 376, HEAD)

    def test_archive_reference_resolves_without_read_command(self):
        row = self.messages[0]
        with patch.object(gate, 'command', side_effect=[json.dumps([]), json.dumps([row])]) as calls:
            rows = gate.mailbox()
            self.assertEqual(gate.approval(REF, gate.verdicts(rows, 376, HEAD), rows, 376, HEAD), 'agent/reviewer')
        self.assertTrue(all(call.args[:3] == ('st', 'conversations', 'ls') for call in calls.call_args_list))

    def test_help_explains_reviewer_form_and_gate_details(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            gate.main(['--help'])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn('GO compoundingtech/mergemaster#N', output.getvalue())
        self.assertIn('first parent is CI base', output.getvalue())
        self.assertNotIn('/home/', output.getvalue())
        self.assertIn('Fractal message sender (same-uid asserted identity)', output.getvalue())
        self.assertIn('not a malicious same-uid agent', output.getvalue())

    def test_archived_verdicts_are_not_hidden(self):
        row = message(sender='agent/blocker', body=HEAD, index=3, title='NO-GO compoundingtech/mergemaster#376')
        with patch.object(gate, 'command', side_effect=[json.dumps(self.messages), json.dumps([row])]):
            latest = gate.verdicts(gate.mailbox(), 376, HEAD)
            self.assertTrue(latest['agent/blocker'][0])

    def test_check_conclusions_and_rerun_reasons(self):
        for status, conclusion in [('queued', None), ('completed', 'failure'), ('completed', 'neutral'), ('completed', 'cancelled')]:
            self.check.update(status=status, conclusion=conclusion)
            self.assertEqual(self.run_gate('--dry-run')[0], 1)
        self.check.update(status='completed', conclusion='skipped')
        self.run['run_attempt'] = 2
        self.assertEqual(self.run_gate('--dry-run')[0], 1)
        self.assertEqual(self.run_gate('--dry-run', '--rerun-reason', ' ')[0], 1)
        self.assertEqual(self.run_gate('--dry-run', '--rerun-reason', 'runner outage')[0], 0)

    def test_rerun_of_any_workflow_requires_reason(self):
        self.other_runs = [{'head_sha': HEAD, 'run_attempt': 2, 'html_url': 'https://release/13'}]
        code, output = self.run_gate('--dry-run')
        self.assertEqual(code, 1)
        self.assertIn('FAIL workflow-attempts', output)
        self.assertIn('https://release/13', output)
        self.assertEqual(self.run_gate('--dry-run', '--rerun-reason', 'release runner outage')[0], 0)

    def test_sensitive_paths_use_three_dot_pr_diff(self):
        branch_point = '0' * 40
        self.merge_bases[(BASE, HEAD)] = branch_point
        self.files = '.github/changed-only-on-main.yml\0'
        self.diffs[(branch_point, HEAD)] = 'src/pr.rs\0'
        self.assertEqual(self.run_gate('--dry-run')[0], 0)
        self.files = 'src/pr.rs\0'
        self.diffs[(branch_point, HEAD)] = '.github/pr-change.yml\0'
        code, output = self.run_gate('--dry-run')
        self.assertEqual(code, 1)
        self.assertIn('FAIL sensitive-second-go', output)

    def test_overlap_uses_three_dot_pr_side(self):
        branch_point = '0' * 40
        self.tested_commit = CI_MERGE
        self.merge_bases[(CI_BASE, HEAD)] = branch_point
        self.diffs[(CI_BASE, BASE)] = 'main-only.rs\0'
        self.diffs[(CI_BASE, HEAD)] = 'main-only.rs\0src/pr.rs\0'
        self.diffs[(branch_point, HEAD)] = 'src/pr.rs\0'
        self.assertEqual(self.run_gate('--dry-run')[0], 0)

    def test_self_hosted_jobs_refuse(self):
        self.jobs[0]['runner_group_name'] = 'private'
        self.assertEqual(self.run_gate('--dry-run')[0], 1)

    def test_overlap_refuses_even_green_ci(self):
        self.raced = True
        code, output = self.run_gate('--dry-run')
        self.assertEqual(code, 1, output)
        self.assertIn('FAIL ci-base-overlap', output)

    def test_ci_tested_tree_must_match_merge_tree_at_ci_base(self):
        self.tested_commit = CI_MERGE
        self.tested_tree = HEAD
        code, output = self.run_gate('--dry-run')
        self.assertEqual(code, 1)
        self.assertIn('FAIL ci-base-overlap', output)
        self.assertIn('differs from local merge-tree', output)

    def test_overlap_uses_pr_changes_from_ci_base_not_current_main(self):
        self.tested_commit = CI_MERGE
        self.files = 'src/other.rs\0'
        self.diffs[(CI_BASE, BASE)] = 'shared.rs\0'
        self.diffs[(CI_BASE, HEAD)] = 'shared.rs\0src/other.rs\0'
        code, output = self.run_gate('--dry-run')
        self.assertEqual(code, 1)
        self.assertIn("overlap=['shared.rs']", output)

    def test_nonoverlapping_ci_base_advance_is_allowed(self):
        self.tested_commit = CI_MERGE
        self.diffs[(CI_BASE, BASE)] = 'unrelated.rs\0'
        self.diffs[(CI_BASE, HEAD)] = self.files
        with patch.object(gate, 'merge_tree', wraps=gate.merge_tree) as merges:
            code, output = self.run_gate('--dry-run')
        self.assertEqual(code, 0, output)
        merges.assert_any_call(CI_BASE, HEAD, CI_MERGE)

    def test_draft_conflict_closed_and_changed_head_refuse(self):
        for field, value in [('draft', True), ('mergeable', False), ('mergeable', None), ('state', 'closed')]:
            old = self.pr[field]
            self.pr[field] = value
            self.assertEqual(self.run_gate('--dry-run')[0], 1)
            self.pr[field] = old
        self.pr['head']['sha'] = BASE
        self.assertEqual(self.run_gate('--dry-run')[0], 1)

    def test_github_comments_not_binding(self):
        with self.assertRaises(RuntimeError):
            gate.approval('12345', {}, [], 376, HEAD)

    def test_pages_include_old_check_attempts(self):
        with patch.object(gate, 'api', side_effect=[{'check_runs': [self.check] * 100}, {'check_runs': [self.check]}]) as mock:
            self.assertEqual(len(gate.pages('checks?filter=all', 'check_runs')), 101)
            self.assertIn('page=2', mock.call_args.args[0])

    def test_no_merge_when_unreadable(self):
        with patch.object(gate, 'command', side_effect=RuntimeError('offline')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(['376', '--author-agent', gate.ACTOR, '--go-head', HEAD, '--go-ref', REF]), 1)
        self.assertEqual(self.merge_calls, [])


class GitFixtureTests(unittest.TestCase):
    def test_real_merge_tree_first_parent_overlap_and_rename(self):
        scratch = ROOT / 'tmp'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='merge-pr-test-', dir=scratch) as directory:
            old = os.getcwd()
            os.chdir(directory)
            try:
                gate.git('init', '-q')
                def commit(files, parent=None, second=None):
                    for name, value in files.items():
                        Path(name).write_text(value)
                    gate.git('add', '.')
                    tree = gate.git('write-tree')
                    args = ['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit-tree', tree, '-m', 'fixture']
                    if parent:
                        args += ['-p', parent]
                    if second:
                        args += ['-p', second]
                    return gate.command(*args)
                base = commit({'one': 'base\n', 'two': 'base\n'})
                head = commit({'one': 'PR\n'}, base)
                gate.git('read-tree', '--reset', '-u', base)
                main = commit({'two': 'main\n'}, base)
                tree = gate.git('merge-tree', '--write-tree', main, head)
                gate.git('read-tree', '--reset', '-u', tree)
                merge = commit({}, main, head)
                self.assertEqual(gate.parents(merge), [main, head])
                identities = gate.commit_identities(f'{base}..{merge}')
                self.assertEqual({row[0] for row in identities}, {head, main, merge})
                self.assertTrue(all(row[1:] == ('Fixture', 'fixture@example.invalid',
                                               'Fixture', 'fixture@example.invalid') for row in identities))
                self.assertEqual([row[0] for row in gate.commit_identities(f'{merge}^!')], [merge])
                self.assertEqual(gate.merge_tree(main, head, merge), tree)
                self.assertEqual(gate.changed(base, main) & gate.changed(base, head), set())
                overlap = commit({'one': 'another\n'}, main)
                self.assertEqual(gate.changed(base, overlap) & gate.changed(base, head), {'one'})
                with self.assertRaises(RuntimeError):
                    gate.merge_tree(overlap, head, merge)
                gate.git('read-tree', '--reset', '-u', head)
                Path('one').rename('renamed')
                gate.git('add', '-A')
                renamed = commit({}, head)
                self.assertEqual(gate.changed(head, renamed), {'one', 'renamed'})
            finally:
                os.chdir(old)


if __name__ == '__main__':
    unittest.main()
