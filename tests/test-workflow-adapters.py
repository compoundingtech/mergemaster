#!/usr/bin/env python3
"""Render extracted adapters; retain byte parity except the trusted native notice cutover."""
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


def notice_provisioning(script, scratch):
    root = Path(scratch) / 'notice-provisioning'
    root.mkdir()
    binary = root / 'released-tool'
    binary.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$TEST_INVOKED"\n'
                      '[ "$TEST_FAILURE" != subcommand ] || exit 127\n'
                      'echo native-notice\n')
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
    fetch) [ "$TEST_FAILURE" != fetch ] ;;
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
    cases = [('success', pin, ''), *[(failure, pin, failure) for failure in
             ('fetch', 'show', 'download', 'attestation', 'chmod', 'subcommand')]]
    cases.extend((failure, pin, failure) for failure in ('arm', 'unsupported', 'architecture-probe'))
    for field, value in (
        ('version', 2), ('version', True), ('repository', 'attacker/mergemaster'),
        ('revision', 'a' * 39), ('revision', 'a' * 40 + '\n'),
        ('release.version', 'latest'), ('release.version', 'v1.2.3\n'),
        ('release.sha256', '0' * 64), ('release.sha256', '0' * 63),
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
        done = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c',
                               prologue + script], capture_output=True, text=True, cwd=case,
                              env=dict(os.environ, RUNNER_TEMP=str(case), BASE_SHA='b' * 40,
                                       TEST_PIN=str(pin_path), TEST_BINARY=str(binary),
                                       TEST_FAILURE=failure, TEST_INVOKED=str(invoked),
                                       TEST_GH_LOG=str(gh_log)))
        if name in ('arm', 'unsupported', 'architecture-probe'):
            assert done.returncode == 1, (name, done)
            assert '::error::' in done.stderr, (name, done)
            assert not done.stdout and not invoked.exists() and not gh_log.exists(), (name, done)
            continue
        assert done.returncode == 0, (name, done.stderr)
        assert done.stdout.strip() == ('native-notice' if name == 'success' else NOTICE_FALLBACK), (
            name, done.stdout, done.stderr)
        assert invoked.exists() == (name in ('success', 'subcommand')), name
        if invoked.exists():
            assert invoked.read_text() == 'evidence presign-notice\n'
        if name == 'success':
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
        (work / 'scripts' / path.name).symlink_to(
            ROOT / 'scripts/ci-evidence-source' if path.name == 'ci-evidence-source' else path,
            target_is_directory=path.is_dir())
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
    source = replace_block(source, "    'evidence-source':", "    },", '    ...evidenceGateJobs,', "    'evidence-source': evidenceSourceJob(readFileSync(new URL('../../scripts/ci-evidence-source', import.meta.url), 'utf8'), adapterActions),\n")
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
            notice_provisioning(notice_script, scratch)
            comparable = actual.decode().replace(
                actual_blocks[notice_key], baseline_blocks[notice_key], 1).encode()
        assert comparable == baseline[name], ''.join(difflib.unified_diff(
            baseline[name].decode().splitlines(keepends=True),
            comparable.decode().splitlines(keepends=True),
            fromfile=f'consumer-generator/{name}', tofile=f'adapter-generator/{name}'))
        print(f'{name}.yml: generator parity YES (notice native cutover only)')
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
                assert actual_jobs[key].encode() == expected_jobs[key].encode(), ''.join(
                    difflib.unified_diff(expected_jobs[key].splitlines(keepends=True),
                                         actual_jobs[key].splitlines(keepends=True),
                                         fromfile=f'pinned/{name}/{key}', tofile=f'rendered/{name}/{key}'))
        else:
            assert actual == expected, ''.join(difflib.unified_diff(
                expected.decode().splitlines(keepends=True), actual.decode().splitlines(keepends=True),
                fromfile=f'pinned/{name}', tofile=f'rendered/{name}'))
        print(f'{name}.yml: pinned evidence parity YES (notice native cutover only)')
    print('Workflow adapter strict typecheck and golden test passed')

subprocess.run(['python3', str(ROOT / 'tests/test-generic-evidence.py')], check=True)
