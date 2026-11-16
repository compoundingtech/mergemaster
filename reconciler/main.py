#!/usr/bin/env python3
"""Reconcile BASE-authorized evidence checks; never execute candidate source.

Only the verified public release is executable. Hosted approval evidence is not
collected: policies requiring it fail closed in gate, without actions:read.
The central workflow serializes publication; external_id is not a uniqueness lock.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote
from urllib.request import Request


class ReconcileError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ReconcileError(message)


def positive_id(value):
    return type(value) is int and value > 0


def oid(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}', value) is not None


def load_consumers(path, repo=None, pr=None):
    consumers = json.loads(Path(path).read_text())
    require(isinstance(consumers, list) and consumers, 'invalid consumer enrollment')
    seen_ids, seen_names, seen_repositories = set(), set(), set()
    for consumer in consumers:
        require(isinstance(consumer, dict) and set(consumer) ==
                {'id', 'owner', 'repository', 'repositoryId', 'defaultBranch'}, 'invalid consumer fields')
        for key in ('id', 'owner', 'repository'):
            require(isinstance(consumer[key], str) and
                    re.fullmatch(r'[A-Za-z0-9_.-]+', consumer[key]) is not None and
                    consumer[key] not in ('.', '..'), 'invalid consumer identity')
        require(positive_id(consumer['repositoryId']), 'invalid repository ID')
        require(isinstance(consumer['defaultBranch'], str) and consumer['defaultBranch'] and
                not any(ord(c) < 32 for c in consumer['defaultBranch']), 'invalid default branch')
        name = f"{consumer['owner']}/{consumer['repository']}".lower()
        require(consumer['id'] not in seen_ids and name not in seen_names and
                consumer['repositoryId'] not in seen_repositories, 'duplicate consumer enrollment')
        seen_ids.add(consumer['id'])
        seen_names.add(name)
        seen_repositories.add(consumer['repositoryId'])
    require(pr is None or positive_id(pr), 'invalid PR filter')
    if repo:
        consumers = [c for c in consumers if f"{c['owner']}/{c['repository']}" == repo]
        require(len(consumers) == 1, 'repository filter is not enrolled')
    return consumers


def required_lanes(policy):
    require(isinstance(policy, dict) and type(policy.get('version')) is int and
            policy['version'] == 1 and isinstance(policy.get('lanes'), dict), 'invalid BASE lane policy')
    result = []
    for name, lane in policy['lanes'].items():
        require(isinstance(name, str) and name and len(name) <= 100 and
                not any(ord(c) < 32 for c in name) and isinstance(lane, dict), 'invalid BASE lane')
        require(isinstance(lane.get('events'), list), 'invalid BASE lane events')
        if lane.get('mode') == 'required_evidence' and 'pull_request' in lane['events']:
            result.append(name)
    return result


def gate_result(result, check, base, head):
    try:
        value = json.loads(result.stdout)
        require(isinstance(value, dict) and type(value.get('version')) is int and value['version'] == 1
                and value.get('check') == check and value.get('base') == base and value.get('head') == head,
                'invalid gate identity')
        require(isinstance(value.get('summary'), str) and len(value['summary']) <= 60000,
                'invalid gate summary')
        require(value.get('decision') in ('skip', 'refuse', 'run') and
                value.get('outcome') in ('satisfied', 'reused', 'rejected', 'no_note', 'degraded'),
                'invalid gate decision')
        success = (result.returncode == 0 and value['decision'] == 'skip' and
                   value['outcome'] in ('satisfied', 'reused') and value.get('report_only') is False)
        return success, value['summary']
    except (ValueError, TypeError, ReconcileError):
        return False, 'Verifier failed or returned an invalid decision; evidence is not accepted.'


class Api:
    """Fixed-host API transport; injected request receives method/path/payload/token."""
    def __init__(self, token, request=None):
        self.token = token
        self.request = request or self._request

    @staticmethod
    def _request(method, path, payload, token):
        request = Request('https://api.github.com/' + path,
                          data=None if payload is None else json.dumps(payload).encode(), method=method,
                          headers={'Authorization': 'Bearer ' + token,
                                   'Accept': 'application/vnd.github+json',
                                   'X-GitHub-Api-Version': '2022-11-28',
                                   'Content-Type': 'application/json', 'User-Agent': 'mergemaster-reconciler'})
        # urllib redirects could forward authorization to another host. Refuse them.
        from urllib.request import HTTPRedirectHandler, build_opener
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        try:
            with build_opener(NoRedirect).open(request, timeout=60) as response:
                return json.load(response)
        except Exception:
            raise ReconcileError('GitHub API request failed') from None

    def call(self, method, path, payload=None):
        require(method in ('GET', 'POST', 'PATCH') and isinstance(path, str) and
                path.startswith(('repos/', 'app/')) and not any(c in path for c in ('\n', '\r', '#', '\\'))
                and '://' not in path and not any(p in ('.', '..') for p in path.split('/')),
                'invalid API endpoint')
        return self.request(method, path, payload, self.token)

    def pages(self, path, key=None):
        result = []
        for page in range(1, 10001):
            value = self.call('GET', path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
            items = value if key is None else value[key]
            require(isinstance(items, list), 'invalid paginated API response')
            result.extend(items)
            if len(items) < 100:
                return result
        raise ReconcileError('API pagination exceeded safety bound')


class Reconciler:
    def __init__(self, app_id, private_key, bootstrap_token, api_factory=Api,
                 run=subprocess.run, environ=None, workspace=None):
        require(str(app_id).isdigit() and int(app_id) > 0, 'invalid App ID')
        require(bool(private_key) and bool(bootstrap_token), 'App or bootstrap credentials missing')
        self.app_id = int(app_id)
        self.private_key = private_key
        self.bootstrap_token = bootstrap_token
        self.api_factory = api_factory
        self.run = run
        self.environ = dict(os.environ if environ is None else environ)
        self.workspace = Path(workspace or self.environ.get('RUNNER_TEMP') or
                              Path(__file__).resolve().parents[1] / 'tmp/evidence-reconcile')
        self.workspace.mkdir(parents=True, exist_ok=True)

    def environment(self, token):
        env = {k: v for k, v in self.environ.items() if not
               (k.startswith(('GIT_', 'GH_', 'MERGEMASTER_')) or k == 'GITHUB_TOKEN')}
        env.update(GH_TOKEN=token, GITHUB_TOKEN=token, GH_HOST='github.com', GH_PROMPT_DISABLED='1',
                   GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM='/dev/null',
                   GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
                   GIT_CONFIG_COUNT='0', GIT_ATTR_NOSYSTEM='1')
        return env

    def command(self, args, token, cwd=None, data=None, binary=False, extra_env=None):
        env = self.environment(token)
        env.update(extra_env or {})
        result = self.run(args, input=data, capture_output=True, check=False,
                          text=not binary, env=env, cwd=cwd)
        require(result.returncode == 0, 'trusted subprocess failed')
        return result.stdout

    def jwt(self):
        def encode(value):
            return base64.urlsafe_b64encode(value).rstrip(b'=')
        now = int(time.time())
        signing = b'.'.join(encode(json.dumps(v, separators=(',', ':')).encode()) for v in
                            ({'alg': 'RS256', 'typ': 'JWT'},
                             {'iat': now - 60, 'exp': now + 540, 'iss': str(self.app_id)}))
        with tempfile.TemporaryDirectory(prefix='jwt-', dir=self.workspace) as directory:
            key = Path(directory) / 'private-key.pem'
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(self.private_key)
            signature = self.command(['openssl', 'dgst', '-sha256', '-sign', str(key)],
                                     '', data=signing, binary=True)
        return (signing + b'.' + encode(signature)).decode()

    def installation(self, consumer):
        name = f"{consumer['owner']}/{consumer['repository']}"
        root = 'repos/' + name
        app = self.api_factory(self.jwt())
        installation = app.call('GET', root + '/installation')
        require(positive_id(installation.get('id')) and installation.get('app_id') == self.app_id and
                installation.get('account', {}).get('login') == consumer['owner'],
                'installation App/account mismatch')
        permissions = {'checks': 'write', 'contents': 'read', 'pull_requests': 'read'}
        value = app.call('POST', f"app/installations/{installation['id']}/access_tokens",
                         {'repository_ids': [consumer['repositoryId']], 'permissions': permissions})
        require(isinstance(value.get('token'), str) and value['token'], 'installation token missing')
        repositories = value.get('repositories')
        require(isinstance(repositories, list) and len(repositories) == 1 and
                repositories[0].get('id') == consumer['repositoryId'] and
                repositories[0].get('full_name') == name, 'installation token repository scope mismatch')
        granted = value.get('permissions', {})
        require(all(granted.get(k) == v for k, v in permissions.items()) and
                set(granted) <= set(permissions) | {'metadata'} and
                granted.get('metadata', 'read') == 'read', 'installation token permissions mismatch')
        api = self.api_factory(value['token'])
        live = api.call('GET', root)
        require(live.get('id') == consumer['repositoryId'] and live.get('full_name') == name and
                live.get('default_branch') == consumer['defaultBranch'] and
                live.get('owner', {}).get('login') == consumer['owner'] and
                positive_id(live.get('owner', {}).get('id')) and
                live['owner']['id'] == installation['account'].get('id'), 'live repository identity mismatch')
        return api

    def observe(self, api, consumer, number):
        require(positive_id(number), 'invalid PR number')
        name = f"{consumer['owner']}/{consumer['repository']}"
        root = 'repos/' + name
        pull = api.call('GET', f'{root}/pulls/{number}')
        require(pull.get('number') == number and pull.get('state') == 'open', 'PR is not open')
        for side in ('base', 'head'):
            require(pull.get(side, {}).get('repo', {}).get('id') == consumer['repositoryId'] and
                    pull[side]['repo'].get('full_name') == name, 'fork PR unsupported')
        require(oid(pull['head'].get('sha')) and isinstance(pull['base'].get('ref'), str) and
                pull['base']['ref'], 'invalid PR identity')
        branch = api.call('GET', f"{root}/git/ref/heads/{quote(pull['base']['ref'], safe='')}")
        require(branch.get('ref') == 'refs/heads/' + pull['base']['ref'] and
                branch.get('object', {}).get('type') == 'commit' and oid(branch['object'].get('sha')),
                'invalid accepted base branch')
        return pull, branch['object']['sha']

    def recheck(self, api, consumer, pull, base):
        current, accepted = self.observe(api, consumer, pull['number'])
        require(current['head']['sha'] == pull['head']['sha'] and
                current['base']['ref'] == pull['base']['ref'] and accepted == base,
                'live PR/head/base changed')

    def publish(self, api, consumer, pull, base, check, success, summary):
        name = f"{consumer['owner']}/{consumer['repository']}"
        root = 'repos/' + name
        head = pull['head']['sha']
        checks = api.pages(f'{root}/commits/{head}/check-runs?filter=all&app_id={self.app_id}'
                           f'&check_name={quote(check, safe="")}', 'check_runs')
        matches = []
        for value in checks:
            require(value.get('name') == check and value.get('head_sha') == head and
                    value.get('app', {}).get('id') == self.app_id and positive_id(value.get('id')),
                    'check-run query identity mismatch')
            matches.append(value['id'])
        payload = {'name': check, 'status': 'completed', 'conclusion': 'success' if success else 'failure',
                   'output': {'title': 'Evidence accepted' if success else 'Evidence refused',
                              'summary': summary[:60000]}}
        self.recheck(api, consumer, pull, base)
        if matches:
            # Repair all historical duplicates as well as reusing the existing ID.
            for check_id in sorted(set(matches)):
                self.recheck(api, consumer, pull, base)
                api.call('PATCH', f'{root}/check-runs/{check_id}', payload)
        else:
            api.call('POST', root + '/check-runs', dict(payload, head_sha=head))

    def prepare(self, api, consumer, pull, base, directory):
        repo = Path(directory) / 'repository'
        repo.mkdir()
        token = api.token
        auth = base64.b64encode(('x-access-token:' + token).encode()).decode()
        extra = {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'http.https://github.com/.extraheader',
                 'GIT_CONFIG_VALUE_0': 'AUTHORIZATION: basic ' + auth}
        def git(*args):
            return self.command(['git', '-c', 'core.hooksPath=/dev/null', *args], token,
                                cwd=repo, extra_env=extra)
        git('init', '--template=')
        name = f"{consumer['owner']}/{consumer['repository']}"
        git('remote', 'add', 'origin', 'https://github.com/' + name + '.git')
        git('fetch', '--no-tags', 'origin', base, pull['head']['sha'],
            '+refs/notes/evidence/*:refs/notes/evidence/*', '+refs/tags/evidence/*:refs/tags/evidence/*')
        # Read authorization before checkout: a malformed pin cannot hide lane failures.
        policy = json.loads(git('show', base + ':.mergemaster/lanes.json'))
        lanes = required_lanes(policy)
        return repo, git, lanes

    def verifier(self, git, directory):
        base = git('rev-parse', 'HEAD').strip()
        pin = json.loads(git('show', base + ':.mergemaster/tool-pin.json'))
        require(type(pin.get('version')) is int and pin['version'] == 1 and
                pin.get('repository') == 'compoundingtech/mergemaster' and oid(pin.get('revision')),
                'invalid BASE tool pin')
        release = pin.get('release', {})
        require(isinstance(release.get('version'), str) and
                re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', release['version']) and
                isinstance(release.get('sha256'), str) and
                re.fullmatch(r'[0-9a-f]{64}', release['sha256']), 'invalid BASE release pin')
        asset = 'mergemaster-x86_64-unknown-linux-musl'
        destination = Path(directory) / 'release'
        destination.mkdir()
        self.command(['gh', 'release', 'download', release['version'], '--repo', pin['repository'],
                      '--pattern', asset, '--dir', str(destination)], self.bootstrap_token)
        binary = destination / asset
        require(not binary.is_symlink() and binary.is_file(), 'release asset missing')
        with binary.open('rb') as stream:
            require(hashlib.file_digest(stream, 'sha256').hexdigest() == release['sha256'],
                    'release digest mismatch')
        self.command(['gh', 'attestation', 'verify', str(binary), '--repo', pin['repository'],
                      '--signer-digest', pin['revision'], '--source-digest', pin['revision'],
                      '--signer-workflow', pin['repository'] + '/.github/workflows/release.yml',
                      '--deny-self-hosted-runners'], self.bootstrap_token)
        binary.chmod(0o700)
        return binary

    def reconcile_pull(self, api, consumer, number):
        pull, base = self.observe(api, consumer, number)
        errors = 0
        with tempfile.TemporaryDirectory(prefix='pull-', dir=self.workspace) as directory:
            repo, git, lanes = self.prepare(api, consumer, pull, base, directory)
            if not lanes:
                return 0
            try:
                git('checkout', '--detach', '--force', base)
                require(git('rev-parse', 'HEAD').strip() == base, 'checkout is not accepted BASE')
                binary = self.verifier(git, directory)
                event = Path(directory) / 'event.json'
                # Both PR metadata and the accepted tip came from authenticated APIs.
                event_pull = dict(pull, base=dict(pull['base'], sha=base))
                event.write_text(json.dumps({'number': number, 'pull_request': event_pull,
                                             'repository': pull['base']['repo']}))
            except Exception:
                for lane in lanes:
                    try:
                        self.publish(api, consumer, pull, base, lane, False,
                                     'BASE verifier setup failed; evidence is not accepted.')
                    except Exception:
                        pass
                return 1
            for lane in lanes:
                success, summary = False, 'Verifier failed; evidence is not accepted.'
                try:
                    env = self.environment(api.token)
                    env['GITHUB_REPOSITORY'] = f"{consumer['owner']}/{consumer['repository']}"
                    # Actor/run metadata remains the truthful central workflow identity.
                    result = self.run([str(binary), 'gate', '--check', lane, '--base', base,
                                       '--head', pull['head']['sha'], '--event-file', str(event),
                                       '--format', 'json'], capture_output=True, check=False,
                                      input=None, text=True, cwd=repo, env=env)
                    success, summary = gate_result(result, lane, base, pull['head']['sha'])
                    if not success:
                        errors += 1
                except Exception:
                    errors += 1
                try:
                    self.publish(api, consumer, pull, base, lane, success, summary)
                except Exception:
                    errors += 1
        return errors

    def reconcile_consumer(self, consumer, pr_filter=None):
        api = self.installation(consumer)
        name = f"{consumer['owner']}/{consumer['repository']}"
        pulls = ([{'number': pr_filter}] if pr_filter is not None else
                 api.pages(f'repos/{name}/pulls?state=open'))
        errors = 0
        for pull in pulls:
            try:
                number = pull.get('number')
                require(positive_id(number), 'invalid PR number')
                # Authenticated observation, not a caller-controlled fork URL.
                live = api.call('GET', f'repos/{name}/pulls/{number}')
                if live.get('head', {}).get('repo', {}).get('id') != consumer['repositoryId']:
                    continue
                errors += self.reconcile_pull(api, consumer, number)
            except Exception:
                errors += 1
                print(f'{name}: PR reconciliation failed', file=sys.stderr)
        return errors

    def run_all(self, consumers, pr_filter=None):
        errors = 0
        for consumer in consumers:
            try:
                errors += self.reconcile_consumer(consumer, pr_filter)
            except Exception:
                errors += 1
                print(f"{consumer['owner']}/{consumer['repository']}: repository reconciliation failed", file=sys.stderr)
        print(f'Evidence reconciliation completed: {errors} error(s).')
        return 1 if errors else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default=None)
    parser.add_argument('--pr', type=int, default=None)
    args = parser.parse_args()
    try:
        consumers = load_consumers(Path(__file__).resolve().parents[1] / 'iac/consumers.json',
                                   args.repo, args.pr)
        reconciler = Reconciler(os.environ.get('MERGEMASTER_APP_ID', ''),
                                os.environ.get('MERGEMASTER_APP_PRIVATE_KEY', ''),
                                os.environ.get('GH_TOKEN', ''))
        return reconciler.run_all(consumers, args.pr)
    except Exception:
        print('Evidence reconciliation configuration failed; no credentials or response bodies logged.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
