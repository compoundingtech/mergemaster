#!/usr/bin/env python3
"""Render extracted adapters; retain parity except trusted native notice/source/verifier cutovers."""
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(os.environ['MERGEMASTER_FRACTAL_FIXTURE'])
EFFECT_UTILS = Path(os.environ['MERGEMASTER_EFFECT_UTILS'])
IMPORT = "import { evidenceGateJobs as makeGateJobs, evidencePresignNoticeJob, evidenceSourceJob, evidenceAggregateSigningJob, evidenceRustTestSigningJob, evidenceObserveJob, signedTreeJob } from '../../genie/evidence.ts'\n"
# These are the original fixture's references, not actions used by this repository's CI.
ACTIONS = "const adapterActions = { checkout: 'actions/checkout@v4', uploadArtifact: 'actions/upload-artifact@v4', downloadArtifact: 'actions/download-artifact@v4' }\n"


def source_block(source, anchor, end, following):
    anchors = list(re.finditer(r'^' + re.escape(anchor) + r'[^\n]*\n', source, re.M))
    assert len(anchors) == 1, f'{anchor!r}: expected one anchor, found {len(anchors)}'
    start, body = anchors[0].start(), anchors[0].end()
    boundary = re.search(r'^' + re.escape(following), source[body:], re.M)
    assert boundary, f'{anchor!r}: missing following boundary {following!r}'
    # Bound the search so a missing closer cannot consume the next job's closer.
    closers = list(re.finditer(r'^' + re.escape(end) + r'\n',
                               source[body:body + boundary.start()], re.M))
    assert len(closers) == 1, f'{anchor!r}: expected one closing line {end!r}, found {len(closers)}'
    return start, body + closers[0].end()


def replace_block(source, anchor, end, following, replacement):
    start, stop = source_block(source, anchor, end, following)
    return source[:start] + replacement + source[stop:]


def signing_needs(source, anchor, following):
    start, stop = source_block(source, anchor, '    },', following)
    needs = re.findall(r'^      needs: (.+),$', source[start:stop], re.M)
    assert len(needs) == 1, f'{anchor!r}: expected one needs line, found {len(needs)}'
    return needs[0]


def job_blocks(text):
    matches = list(re.finditer(r'^  ([a-zA-Z0-9_-]+):\n', text, re.M))
    return {match[1]: text[match.start():matches[i + 1].start() if i + 1 < len(matches) else len(text)]
            for i, match in enumerate(matches)}


def generate(work, workflows, scratch):
    subprocess.run(['genie'], cwd=work, check=True, env=dict(os.environ, HOME=scratch))
    # Exercise the post-generation formatter explicitly: genie's fallback hides
    # formatter failures, which would otherwise look like adapter byte drift.
    for name in ('fleet', 'evidence-observe', 'signed-tree'):
        target = workflows / f'{name}.yml'
        formatted = subprocess.run(['oxfmt', '--stdin-filepath', str(target.relative_to(work))],
                                   input=target.read_bytes(), capture_output=True, cwd=work,
                                   env=dict(os.environ, HOME=scratch, PWD=str(work)))
        assert formatted.returncode == 0 and formatted.stdout, formatted.stderr.decode()
        target.chmod(0o644)
        target.write_bytes(formatted.stdout)


NOTICE_FALLBACK = 'evidence-presign-notice: not at the base yet, or it could not run; nothing to say'


def notice_migration(actual, expected):
    actual_job = yaml.load(actual, Loader=yaml.BaseLoader)
    expected_job = yaml.load(expected, Loader=yaml.BaseLoader)
    key, = actual_job
    assert list(expected_job) == [key]
    actual_step = actual_job[key]['steps'][1]
    expected_step = expected_job[key]['steps'][1]
    script = actual_step.pop('run').rstrip('\n')
    old_script = expected_step.pop('run')
    assert actual_job == expected_job, 'Notice metadata, environment or permissions changed'
    assert actual_job[key]['permissions'] == {'contents': 'read', 'pull-requests': 'read'}
    assert 'python3' in old_script and 'python3' not in script
    assert script.endswith("|| echo '" + NOTICE_FALLBACK + "'")
    assert 'provision_evidence_tool && "$MERGEMASTER" evidence presign-notice' in script
    for fragment in (
        'git show "$BASE_SHA:.mergemaster/tool-pin.json"',
        'gh release download "$release_version" --repo compoundingtech/mergemaster',
        '--pattern mergemaster-x86_64-unknown-linux-musl',
        'sha256sum --check --status',
        'gh attestation verify "$MERGEMASTER" --repo compoundingtech/mergemaster',
        '--signer-digest "$revision" --source-digest "$revision"',
        '--signer-workflow compoundingtech/mergemaster/.github/workflows/release.yml',
        '--deny-self-hosted-runners',
    ):
        assert fragment in script, f'Missing trusted provisioning boundary: {fragment}'
    return script


def source_migration(actual, expected, notice_script):
    actual_job = yaml.load(actual, Loader=yaml.BaseLoader)
    expected_job = yaml.load(expected, Loader=yaml.BaseLoader)
    assert list(actual_job) == list(expected_job) == ['evidence-source']
    actual_step = actual_job['evidence-source']['steps'][1]
    expected_step = expected_job['evidence-source']['steps'][1]
    script = actual_step.pop('run').rstrip('\n')
    old_script = expected_step.pop('run')
    assert actual_step.pop('env') == {
        'BASE_SHA': "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.sha) || '' }}",
        'EVENT_NAME': '${{ github.event_name }}',
        'PR_HEAD_SHA': '${{ github.event.pull_request.head.sha }}',
        'GH_TOKEN': '${{ github.token }}',
    }
    assert actual_job == expected_job, 'Source job/step names, upload contract or permissions changed'
    assert actual_job['evidence-source']['permissions'] == {'contents': 'read'}
    assert actual_job['evidence-source']['continue-on-error'] == 'true'
    upload = actual_job['evidence-source']['steps'][2]['with']
    assert upload['name'] == 'ci-evidence-source-${{ github.run_attempt }}'
    assert upload['path'] == '${{ runner.temp }}/ci-evidence-source/'
    assert upload['if-no-files-found'] == 'error'
    assert 'python3' in old_script and 'python3' not in script
    assert '|| echo' not in script and NOTICE_FALLBACK not in script
    assert 'git cat-file -p HEAD' in script and '[ "$2" = "$PR_HEAD_SHA" ]' in script
    assert 'export BASE_SHA="$source_base"' in script
    assert script.endswith('test -n "$BASE_SHA" && git fetch --no-tags --depth=1 -q origin "$BASE_SHA" && provision_evidence_tool && "$MERGEMASTER" evidence source')
    assert script.split('\nsource_base=', 1)[0] == notice_script.split('\ngit fetch', 1)[0]
    return script


def shadow_migration(actual, expected, notice_script):
    actual_job = yaml.load(actual, Loader=yaml.BaseLoader)
    expected_job = yaml.load(expected, Loader=yaml.BaseLoader)
    key = 'evidence-note-linux-gate'
    assert list(actual_job) == list(expected_job) == [key]
    actual_step, = [step for step in actual_job[key]['steps'] if step.get('name') == 'Shadow-verify the published notes']
    expected_step, = [step for step in expected_job[key]['steps'] if step.get('name') == 'Shadow-verify the published notes']
    script = actual_step.pop('run').rstrip('\n')
    old_script = expected_step.pop('run').rstrip('\n')
    assert actual_step.pop('env') == {
        'BASE_SHA': '${{ github.event.merge_group.base_sha || github.event.pull_request.base.sha || github.sha }}',
        'GH_TOKEN': '${{ github.token }}',
    }
    assert actual_job == expected_job, 'Signing job metadata, permissions or non-shadow steps changed'
    assert actual_step['continue-on-error'] == 'true'
    provisioning, body = script.split('\nshadow=', 1)
    assert provisioning == notice_script.split('\ngit fetch', 1)[0]
    expected_body = old_script.replace('python3 "$shadow"', 'provision_evidence_tool || exit 1\npython3 "$shadow"')
    expected_body = expected_body.replace('--verifier "$RUNNER_TEMP/evidence-base/scripts/evidence-verify"',
                                          '--verifier "$MERGEMASTER"')
    assert 'shadow=' + body == expected_body, 'Shadow driver contract changed beyond the trusted verifier cutover'
    assert '--verifier "$MERGEMASTER"' in body
    return script


def verifier_job_migration(actual, expected, notice_script, gate=False):
    actual_job = yaml.load(actual, Loader=yaml.BaseLoader)
    expected_job = yaml.load(expected, Loader=yaml.BaseLoader)
    key, = actual_job
    assert list(expected_job) == [key]
    actual_step = actual_job[key]['steps'][1]
    expected_step = expected_job[key]['steps'][1]
    script = actual_step.pop('run').rstrip('\n')
    old_script = expected_step.pop('run').rstrip('\n')
    assert actual_step['env'].pop('GH_TOKEN') == '${{ github.token }}'
    if not gate:
        assert actual_step['env'].pop('BASE_SHA') == '${{ github.event.pull_request.base.sha }}'
    assert actual_job == expected_job, 'Verifier job changed beyond provisioning'
    provisioning = notice_script.split('\ngit fetch', 1)[0]
    assert script.startswith(provisioning + '\n')
    body = script[len(provisioning) + 1:]
    if gate:
        expected_body = old_script.replace('&& git show "$BASE_SHA:scripts/ci-evidence-gate"',
                                          '&& provision_evidence_tool && git show "$BASE_SHA:scripts/ci-evidence-gate"')
        expected_body = expected_body.replace('&& python3 "$RUNNER_TEMP/ci-evidence-gate"',
                                              '&& MERGEMASTER_BIN="$MERGEMASTER" python3 "$RUNNER_TEMP/ci-evidence-gate"')
    else:
        assert old_script == 'python3 scripts/ci-signed-tree'
        expected_body = ('git fetch --no-tags --depth=1 -q origin "$BASE_SHA" && provision_evidence_tool '
                         '&& MERGEMASTER_BIN="$MERGEMASTER" python3 scripts/ci-signed-tree')
    assert body == expected_body, 'Verifier invocation/base selection/fallback changed'


def tool_provisioning(script, scratch, command):
    root = Path(scratch) / f'{command}-provisioning'
    root.mkdir()
    binary = root / 'released-tool'
    binary.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$TEST_INVOKED"\n'
                      '[ "$TEST_FAILURE" != subcommand ] || exit 127\n'
                      'echo native-tool\n')
    pin = {
        'version': 1, 'repository': 'compoundingtech/mergemaster', 'revision': 'a' * 40,
        'release': {'version': 'v1.2.3', 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()},
    }
    # Only transport/process boundaries are faked; run the generated shell's real
    # pin parsing, digest verification, control flow and native executable dispatch.
    prologue = r'''
uname() {
  if [ "$TEST_FAILURE" = architecture-probe ]; then return 1; fi
  if [ "$TEST_FAILURE" = arm ]; then echo aarch64
  elif [ "$TEST_FAILURE" = unsupported ]; then echo riscv64
  else echo x86_64; fi
}
git() {
  case "$1" in
    fetch)
      printf '%s\n' "${@: -1}" > "$TEST_FETCHED_BASE"
      [ "$TEST_FAILURE" != fetch ] ;;
    cat-file) printf '%s\n' "$TEST_PARENTS" ;;
    show)
      [ "$TEST_FAILURE" != show ] || return 1
      [ "$2" = "$BASE_SHA:.mergemaster/tool-pin.json" ] || return 1
      cat "$TEST_PIN" ;;
    *) return 1 ;;
  esac
}
gh() {
  printf '%s\n' "$@" >> "$TEST_GH_LOG"
  case "$1 $2" in
    'release download')
      [ "$TEST_FAILURE" != download ] || return 1
      cp "$TEST_BINARY" "${@: -1}/mergemaster-x86_64-unknown-linux-musl" ;;
    'attestation verify') [ "$TEST_FAILURE" != attestation ] ;;
    *) return 1 ;;
  esac
}
chmod() {
  [ "$TEST_FAILURE" != chmod ] || return 1
  command chmod "$@"
}
'''
    extended_pin = {**pin, 'extra': True, 'release': {**pin['release'], 'extra': True}}
    cases = [('success', pin, ''), ('extra-fields', extended_pin, ''),
             *[(failure, pin, failure) for failure in
               ('fetch', 'show', 'download', 'attestation', 'chmod', 'subcommand')]]
    if command == 'source':
        cases.extend((name, pin, '') for name in ('pr-effective-base', 'pr-event-base', 'missing-base'))
    cases.extend((failure, pin, failure) for failure in ('arm', 'unsupported', 'architecture-probe'))
    for field, value in (
        ('version', 2), ('version', True), ('repository', 'attacker/mergemaster'),
        ('revision', 'a' * 39), ('revision', 'A' * 40), ('revision', 'a' * 40 + '\n'),
        ('release.version', 'latest'), ('release.version', 'v1.2.3\n'),
        ('release.sha256', '0' * 64), ('release.sha256', '0' * 63),
        ('release.sha256', 'A' * 64),
        ('release.sha256', '0' * 64 + '\n'),
    ):
        altered = json.loads(json.dumps(pin))
        target = altered['release'] if field.startswith('release.') else altered
        target[field.split('.')[-1]] = value
        cases.append((f'invalid-{field}-{len(cases)}', altered, ''))
    for name, case_pin, failure in cases:
        case = root / name
        case.mkdir()
        pin_path, invoked, gh_log = (case / filename for filename in ('pin.json', 'invoked', 'gh.log'))
        pin_path.write_text(json.dumps(case_pin))
        pr_case = name.startswith('pr-')
        success = name in ('success', 'extra-fields', 'pr-effective-base', 'pr-event-base')
        base = '' if name == 'missing-base' else 'b' * 40
        fetched_base = case / 'fetched-base'
        done = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c',
                               prologue + script], capture_output=True, text=True, cwd=case,
                              env=dict(os.environ, RUNNER_TEMP=str(case), BASE_SHA=base,
                                       EVENT_NAME='pull_request' if pr_case else 'workflow_dispatch',
                                       PR_HEAD_SHA='c' * 40,
                                       TEST_PARENTS='parent ' + 'd' * 40 + '\nparent ' +
                                       ('c' if name == 'pr-effective-base' else 'e') * 40,
                                       TEST_PIN=str(pin_path), TEST_BINARY=str(binary),
                                       TEST_FAILURE=failure, TEST_INVOKED=str(invoked),
                                       TEST_FETCHED_BASE=str(fetched_base), TEST_GH_LOG=str(gh_log)))
        if name in ('arm', 'unsupported', 'architecture-probe'):
            assert done.returncode == 1, (name, done)
            assert '::error::' in done.stderr, (name, done)
            assert not done.stdout and not invoked.exists() and not gh_log.exists(), (name, done)
            continue
        if command == 'presign-notice':
            assert done.returncode == 0, (name, done.stderr)
            expected_stdout = 'native-tool' if success else NOTICE_FALLBACK
        else:
            assert (done.returncode == 0) == success, (name, done.stdout, done.stderr)
            expected_stdout = 'native-tool' if success else ''
        assert done.stdout.strip() == expected_stdout, (name, done.stdout, done.stderr)
        assert invoked.exists() == (success or name == 'subcommand'), name
        if invoked.exists():
            assert invoked.read_text() == f'evidence {command}\n'
        if name == 'missing-base':
            assert not fetched_base.exists() and not gh_log.exists()
        else:
            assert fetched_base.read_text().strip() == ('d' * 40 if name == 'pr-effective-base' else base)
        if success:
            arguments = gh_log.read_text().splitlines()
            assert arguments[:8] == [
                'release', 'download', 'v1.2.3', '--repo', 'compoundingtech/mergemaster',
                '--pattern', 'mergemaster-x86_64-unknown-linux-musl', '--dir']
            assert Path(arguments[8]).parent == case
            assert arguments[9:] == [
                'attestation', 'verify', str(Path(arguments[8]) / 'mergemaster-x86_64-unknown-linux-musl'),
                '--repo', 'compoundingtech/mergemaster', '--signer-digest', 'a' * 40,
                '--source-digest', 'a' * 40, '--signer-workflow',
                'compoundingtech/mergemaster/.github/workflows/release.yml', '--deny-self-hosted-runners']


(ROOT / 'tmp').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='workflow-adapters-', dir=ROOT / 'tmp') as scratch:
    work = Path(scratch)
    # A real fixture repository bounds ignore discovery; host temporary paths
    # and the parent's ignored tmp directory must not suppress formatting/files.
    subprocess.run(['git', '-c', 'init.templateDir=', 'init', '--quiet', str(work)], check=True)
    subprocess.run(['tsc', '--strict', '--noEmit', '--target', 'ES2023', '--module', 'ESNext',
                    str(ROOT / 'genie/evidence.ts'), str(ROOT / 'genie/generic-evidence.ts')], check=True)
    workflows = work / '.github/workflows'
    workflows.mkdir(parents=True)
    # Genie invokes oxfmt after serialization and silently falls back if absent.
    # Require the real formatter so both renders match the consumer pipeline.
    assert shutil.which('oxfmt'), 'oxfmt is required for faithful consumer YAML formatting'
    # Keep the consumer's existing queue/cache/sandbox wrappers and lane configuration.
    for path in (FIXTURE / '.github/workflows').glob('*.ts'):
        if not path.name.endswith('.genie.ts'):
            shutil.copy2(path, workflows / path.name)
    (work / 'genie').symlink_to(ROOT / 'genie', target_is_directory=True)
    (work / 'repos').mkdir()
    (work / 'repos/effect-utils').symlink_to(EFFECT_UTILS, target_is_directory=True)
    (work / 'scripts').mkdir()
    for path in (FIXTURE / 'scripts').iterdir():
        (work / 'scripts' / path.name).symlink_to(path, target_is_directory=path.is_dir())
    for name in ('fleet', 'evidence-observe', 'signed-tree'):
        shutil.copy2(FIXTURE / f'.github/workflows/{name}.yml.genie.ts',
                     workflows / f'{name}.yml.genie.ts')
        (workflows / f'{name}.yml.genie.ts').chmod(0o644)
    generate(work, workflows, scratch)
    baseline = {name: (workflows / f'{name}.yml').read_bytes()
                for name in ('fleet', 'evidence-observe', 'signed-tree')}
    source = (FIXTURE / '.github/workflows/fleet.yml.genie.ts').read_text()
    signing = "{ actions: adapterActions, checkoutSteps: fullHistoryCheckoutSteps({ 'persist-credentials': false }, { name: 'Check out the tested commit', 'continue-on-error': true }), environment: evidenceEnvironment, stageNames: evidenceStageNames, stepNames: evidenceStepNames, laneNames: evidenceLaneNames, webNoteEnv: fractalWebNoteEnv, needs: "
    aggregate_needs = signing_needs(source, "    'evidence-note-linux-gate':", "    'evidence-note-rust-tests':")
    rust_needs = signing_needs(source, "    'evidence-note-rust-tests':", '    ...buildFractalWebJobs(')
    # Replace whole anchored blocks; assertions still catch missing or duplicate blocks.
    source = replace_block(source, "    'evidence-note-rust-tests':", "    },", '    ...buildFractalWebJobs(', "    'evidence-note-rust-tests': evidenceRustTestSigningJob(" + signing + rust_needs + " }),\n")
    source = replace_block(source, "    'evidence-note-linux-gate':", "    },", "    'evidence-note-rust-tests':", "    'evidence-note-linux-gate': evidenceAggregateSigningJob(" + signing + aggregate_needs + " }),\n")
    source = replace_block(source, "    'evidence-source':", "    },", '    ...evidenceGateJobs,', "    'evidence-source': evidenceSourceJob(adapterActions),\n")
    source = replace_block(source, 'const presignNoticeJob =', '}', 'export const buildFleetWorkflow', "const presignNoticeJob = evidencePresignNoticeJob({ checks: evidenceGateChecks, actions: adapterActions })\n")
    source = replace_block(source, 'const evidenceGateJobs =', '}]))', 'const presignNoticeJob =', "const evidenceGateJobs = makeGateJobs({ checks: evidenceGateChecks, runInputs: evidenceGateRunInputs, actions: adapterActions })\n")
    (workflows / 'fleet.yml.genie.ts').write_text(IMPORT + ACTIONS + source)
    for name, anchor, replacement in (
        ('evidence-observe', '    observe:', '    observe: evidenceObserveJob([evidenceGroup, evidenceRunner], adapterActions),\n'),
        ('signed-tree', "    'signed-tree':", "    'signed-tree': signedTreeJob(adapterActions),\n"),
    ):
        original = (FIXTURE / f'.github/workflows/{name}.yml.genie.ts').read_text()
        (workflows / f'{name}.yml.genie.ts').write_text(
            IMPORT + ACTIONS + replace_block(original, anchor, '    },', '  },', replacement))
    generate(work, workflows, scratch)
    for name in ('fleet', 'evidence-observe', 'signed-tree'):
        actual = (workflows / f'{name}.yml').read_bytes()
        comparable = actual
        if name == 'fleet':
            actual_blocks = job_blocks(actual.decode())
            baseline_blocks = job_blocks(baseline[name].decode())
            notice_key, = [key for key, job in yaml.load(actual, Loader=yaml.BaseLoader)['jobs'].items()
                           if job.get('name') == 'evidence-presign-notice']
            notice_script = notice_migration(actual_blocks[notice_key], baseline_blocks[notice_key])
            tool_provisioning(notice_script, scratch, 'presign-notice')
            source_script = source_migration(actual_blocks['evidence-source'], baseline_blocks['evidence-source'], notice_script)
            tool_provisioning(source_script, scratch, 'source')
            shadow_migration(actual_blocks['evidence-note-linux-gate'], baseline_blocks['evidence-note-linux-gate'], notice_script)
            gate_keys = [key for key in actual_blocks if key.startswith('evidence-gate-')]
            assert gate_keys
            for key in gate_keys:
                verifier_job_migration(actual_blocks[key], baseline_blocks[key], notice_script, gate=True)
            comparable = actual.decode()
            for key in (notice_key, 'evidence-source', 'evidence-note-linux-gate', *gate_keys):
                comparable = comparable.replace(actual_blocks[key], baseline_blocks[key], 1)
            comparable = comparable.encode()
        elif name == 'signed-tree':
            actual_block = job_blocks(actual.decode())['signed-tree']
            baseline_block = job_blocks(baseline[name].decode())['signed-tree']
            verifier_job_migration(actual_block, baseline_block, notice_script)
            comparable = actual.decode().replace(actual_block, baseline_block, 1).encode()
        assert comparable == baseline[name], ''.join(difflib.unified_diff(
            baseline[name].decode().splitlines(keepends=True),
            comparable.decode().splitlines(keepends=True),
            fromfile=f'consumer-generator/{name}', tofile=f'adapter-generator/{name}'))
        print(f'{name}.yml: generator parity YES (notice/source/verifier native cutovers only)')
        expected = (FIXTURE / f'.github/workflows/{name}.yml').read_bytes()
        if name == 'fleet':
            actual_jobs = job_blocks(actual.decode())
            expected_jobs = job_blocks(expected.decode())
            selected = [key for key in expected_jobs if key.startswith('evidence-')]
            assert selected, 'No evidence jobs selected'
            assert actual_jobs.keys() == expected_jobs.keys(), 'Consumer job inventory changed'
            for key in selected:
                if key == notice_key:
                    notice_migration(actual_jobs[key], expected_jobs[key])
                    continue
                if key == 'evidence-source':
                    source_migration(actual_jobs[key], expected_jobs[key], notice_script)
                    continue
                if key == 'evidence-note-linux-gate':
                    shadow_migration(actual_jobs[key], expected_jobs[key], notice_script)
                    continue
                if key.startswith('evidence-gate-'):
                    verifier_job_migration(actual_jobs[key], expected_jobs[key], notice_script, gate=True)
                    continue
                assert actual_jobs[key].encode() == expected_jobs[key].encode(), ''.join(
                    difflib.unified_diff(expected_jobs[key].splitlines(keepends=True),
                                         actual_jobs[key].splitlines(keepends=True),
                                         fromfile=f'pinned/{name}/{key}', tofile=f'rendered/{name}/{key}'))
        elif name == 'signed-tree':
            actual_block = job_blocks(actual.decode())['signed-tree']
            expected_block = job_blocks(expected.decode())['signed-tree']
            verifier_job_migration(actual_block, expected_block, notice_script)
            assert actual.decode().replace(actual_block, expected_block, 1).encode() == expected
        else:
            assert actual == expected, ''.join(difflib.unified_diff(
                expected.decode().splitlines(keepends=True), actual.decode().splitlines(keepends=True),
                fromfile=f'pinned/{name}', tofile=f'rendered/{name}'))
        print(f'{name}.yml: pinned evidence parity YES (notice/source/verifier native cutovers only)')
    print('Workflow adapter strict typecheck and golden test passed')

subprocess.run(['python3', str(ROOT / 'tests/test-generic-evidence.py')], check=True)
