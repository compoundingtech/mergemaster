import type { WorkflowObject } from './evidence.ts'

export interface GenericEvidenceOptions {
  readonly check: string
  readonly checkout: string
  readonly runner?: string
  /** PR C' supplies a pinned App-token action with id app-token and output token. */
  readonly appTokenStep?: WorkflowObject
}

// Embedded in the base-controlled workflow, never loaded from the candidate tree.
// All API endpoints are constructed locally; no PR-supplied URLs are followed.
export const genericEvidencePublisher = String.raw`import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(*args):
    return subprocess.check_output(args, text=True)


def api(endpoint, payload=None):
    args = ['gh', 'api', '--hostname', 'github.com', '-H', 'Accept: application/vnd.github+json',
            '-H', 'X-GitHub-Api-Version: 2022-11-28', endpoint]
    if payload is not None:
        args += ['--method', 'POST', '--input', '-']
    return json.loads(subprocess.check_output(args, input=None if payload is None else json.dumps(payload), text=True))


def pages(endpoint, key=None):
    result = []
    for page in range(1, 10001):
        value = api(endpoint + ('&' if '?' in endpoint else '?') + f'per_page=100&page={page}')
        items = value if key is None else value[key]
        require(isinstance(items, list), 'invalid paginated API response')
        result.extend(items)
        if len(items) < 100:
            return result
    raise RuntimeError('API pagination exceeded safety bound')


repository = os.environ['GITHUB_REPOSITORY']
require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'invalid repository')
require(os.environ['GITHUB_EVENT_NAME'] == 'pull_request_target', 'publisher requires pull_request_target')
event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
pull = event['pull_request']
number = pull['number']
require(type(number) is int and number > 0, 'invalid pull request number')
head = os.environ['HEAD_SHA']
base = os.environ['BASE_SHA']
require(re.fullmatch(r'[0-9a-f]{40}', head) and re.fullmatch(r'[0-9a-f]{40}', base), 'invalid commit')
root = f'repos/{repository}'
temporary = Path(os.environ['RUNNER_TEMP'])
decision_file = temporary / 'generic-evidence-decision.json'


def recheck():
    current = api(f'{root}/pulls/{number}')
    require(current['state'] == 'open' and current['head']['sha'] == head
            and current['head']['repo']['full_name'] == repository
            and current['base']['repo']['full_name'] == repository
            and current['base']['ref'] == pull['base']['ref'], 'live PR changed or fork unsupported')
    branch = api(f"{root}/git/ref/heads/{quote(pull['base']['ref'], safe='')}")
    require(branch['object']['sha'] == base, 'live base changed')


def prepare():
    recheck()
    require(command('git', 'rev-parse', 'HEAD').strip() == base, 'checkout must be accepted base')
    pin = json.loads(command('git', 'show', f'{base}:.mergemaster/tool-pin.json'))
    require(pin['version'] == 1 and pin['repository'] == 'compoundingtech/mergemaster', 'unsupported tool repository')
    require(re.fullmatch(r'[0-9a-f]{40}', pin['revision']), 'invalid tool revision')
    release = pin['release']
    require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', release['version']), 'invalid release version')
    require(re.fullmatch(r'[0-9a-f]{64}', release['sha256']), 'invalid release digest')
    asset = 'mergemaster-x86_64-unknown-linux-musl'
    destination = temporary / 'generic-evidence-release'
    destination.mkdir()
    command('gh', 'release', 'download', release['version'], '--repo', pin['repository'],
            '--pattern', asset, '--dir', str(destination))
    binary = destination / asset
    with binary.open('rb') as source:
        require(hashlib.file_digest(source, 'sha256').hexdigest() == release['sha256'], 'release digest mismatch')
    # Mandatory on hosted runners: provenance binds the binary to both the pinned
    # source revision and the release workflow, not merely to a release tag/name.
    command('gh', 'attestation', 'verify', str(binary), '--repo', pin['repository'],
            '--signer-digest', pin['revision'], '--source-digest', pin['revision'],
            '--signer-workflow', pin['repository'] + '/.github/workflows/release.yml',
            '--deny-self-hosted-runners')
    binary.chmod(0o700)
    # Candidate objects are data only. No checkout, hooks, build, or candidate script.
    authorization = base64.b64encode(('x-access-token:' + os.environ['GH_TOKEN']).encode()).decode()
    subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', 'fetch', '--no-tags', 'origin', head,
                    '+refs/notes/evidence/*:refs/notes/evidence/*', '+refs/tags/evidence/*:refs/tags/evidence/*'],
                   check=True, env=dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_CONFIG_COUNT='1',
                   GIT_CONFIG_KEY_0='http.https://github.com/.extraheader',
                   GIT_CONFIG_VALUE_0='AUTHORIZATION: basic ' + authorization))
    reviews = pages(f'{root}/pulls/{number}/reviews')
    checks = pages(f'{root}/commits/{head}/check-runs?filter=all', 'check_runs')
    joined = []
    runs = {}
    for check in checks:
        if check.get('app', {}).get('slug') != 'github-actions':
            continue
        match = re.fullmatch(r'https://github\.com/' + re.escape(repository)
                             + r'/actions/runs/([0-9]+)/job/([0-9]+)(?:\?[^#]*)?', check.get('details_url') or '')
        if match is None:
            continue
        run_id, job_id = map(int, match.groups())
        if run_id not in runs:
            run = api(f'{root}/actions/runs/{run_id}')
            require(run['id'] == run_id and run['repository']['full_name'] == repository, 'run identity mismatch')
            jobs = pages(f'{root}/actions/runs/{run_id}/jobs?filter=latest', 'jobs')
            runs[run_id] = (run, {job['id']: job for job in jobs})
        run, jobs = runs[run_id]
        job = jobs.get(job_id)
        if job is None:
            continue  # An obsolete attempt cannot authorize the latest run.
        require(job['run_id'] == run_id and job['check_run_url'] ==
                f"https://api.github.com/{root}/check-runs/{check['id']}"
                and job['name'] == check['name'] and job['head_sha'] == check['head_sha']
                and job['status'] == check['status'] and job['conclusion'] == check['conclusion'],
                'job/check identity mismatch')
        require(run['head_sha'] == head and check['head_sha'] == head, 'evidence head mismatch')
        joined.append({'name': check['name'], 'head_sha': check['head_sha'],
                       'status': check['status'], 'conclusion': check['conclusion'],
                       'workflow_run': {key: run[key] for key in ('id', 'workflow_id', 'path', 'head_sha', 'event')}})
    evidence = {'version': 1, 'repository': repository, 'head': head,
                'reviews': [{**{key: review[key] for key in ('id', 'state', 'commit_id', 'submitted_at')},
                             'user': {'login': review['user']['login']}}
                            for review in reviews], 'checks': joined}
    (temporary / 'generic-hosted-evidence.json').write_text(json.dumps(evidence))
    recheck()


def finalize():
    success = False
    summary = 'Verifier did not complete successfully; evidence is not accepted.'
    try:
        decision = json.loads(decision_file.read_text())
        require(decision['version'] == 1 and decision['check'] == os.environ['CHECK']
                and decision['base'] == base and decision['head'] == head, 'invalid gate identity')
        require(isinstance(decision['summary'], str) and len(decision['summary']) <= 60000, 'invalid gate summary')
        summary = decision['summary']
        require(os.environ.get('GATE_OUTCOME') == 'success' and os.environ.get('GATE_SKIP') == 'true', 'gate did not pass')
        require(os.environ.get('APP_OUTCOME') == 'success', 'App token step did not pass')
        require(decision['decision'] == 'skip' and decision['outcome'] == 'satisfied', 'gate refused')
        recheck()  # Last mutable-authority observation before publishing success.
        success = True
    except Exception:
        summary += '\n\nVerifier failed or live HEAD/base changed; evidence is not accepted.'
    token = os.environ.get('APP_TOKEN', '')
    require(bool(token), 'GitHub App token is not configured; refusing to publish')
    # Only the explicit App token may publish the required named check.
    os.environ['GH_TOKEN'] = token
    api(f'{root}/check-runs', {'name': os.environ['CHECK'], 'head_sha': head,
        'status': 'completed', 'conclusion': 'success' if success else 'failure',
        'output': {'title': 'Evidence accepted' if success else 'Evidence refused', 'summary': summary}})
    require(success, 'evidence refused')


if __name__ == '__main__':
    {'prepare': prepare, 'finalize': finalize}[sys.argv[1]]()
`

const publisherScript = (mode: 'prepare' | 'finalize'): string =>
  `python3 - ${mode} <<'GENERIC_EVIDENCE_PY'\n${genericEvidencePublisher}\nGENERIC_EVIDENCE_PY`

/** Base-only publisher. A separate pull_request job must run the unprivileged validation. */
export const genericEvidenceRequiredJob = ({ check, checkout, runner = 'ubuntu-24.04', appTokenStep }: GenericEvidenceOptions): WorkflowObject => ({
  name: 'generic-evidence-publisher',
  if: "github.event_name == 'pull_request_target'",
  'runs-on': runner,
  'timeout-minutes': 15,
  permissions: { contents: 'read', actions: 'read', checks: 'read', 'pull-requests': 'read', attestations: 'read' },
  defaults: { run: { shell: 'bash' } },
  env: {
    CHECK: check,
    BASE_SHA: '${{ github.event.pull_request.base.sha }}',
    HEAD_SHA: '${{ github.event.pull_request.head.sha }}',
    GH_TOKEN: '${{ github.token }}',
    GITHUB_TOKEN: '${{ github.token }}',
    GH_PROMPT_DISABLED: '1',
  },
  steps: [
    { name: 'Check out accepted base only', uses: checkout, with: {
      ref: '${{ github.event.pull_request.base.sha }}', 'persist-credentials': false, 'fetch-depth': 0,
    } },
    { name: 'Fetch pinned verifier and authenticated hosted evidence', run: publisherScript('prepare') },
    { name: 'Evaluate base-controlled evidence policy', id: 'gate', run: [
      '"$RUNNER_TEMP/generic-evidence-release/mergemaster-x86_64-unknown-linux-musl" gate',
      '  --check "$CHECK" --base "$BASE_SHA" --head "$HEAD_SHA"',
      '  --event-file "$GITHUB_EVENT_PATH" --hosted-evidence "$RUNNER_TEMP/generic-hosted-evidence.json"',
      '  --format json --github-output "$GITHUB_OUTPUT" > "$RUNNER_TEMP/generic-evidence-decision.json"',
    ].join(' \\\n') },
    // PR C' replaces only this placeholder, never with the workflow GITHUB_TOKEN.
    { ...(appTokenStep ?? {
      name: 'GitHub App token not configured (PR C\')',
      run: 'echo "GitHub App token is not configured; refusing to publish" >&2\nexit 1',
    }), id: 'app-token', if: 'always()' },
    { name: 'Publish exact-HEAD check with strict finalization', if: 'always()', env: {
      APP_TOKEN: '${{ steps.app-token.outputs.token }}', GATE_OUTCOME: '${{ steps.gate.outcome }}',
      GATE_SKIP: '${{ steps.gate.outputs.skip }}',
      APP_OUTCOME: '${{ steps.app-token.outcome }}',
    }, run: publisherScript('finalize') },
  ],
})
