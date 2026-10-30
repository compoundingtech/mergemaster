#!/usr/bin/env python3
"""Render extracted adapters through pinned Fractal's real generator and compare bytes."""
import difflib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(os.environ['MERGEMASTER_FRACTAL_FIXTURE'])
EFFECT_UTILS = Path(os.environ['MERGEMASTER_EFFECT_UTILS'])
IMPORT = "import { evidenceGateJobs as makeGateJobs, evidencePresignNoticeJob, evidenceSourceJob, evidenceAggregateSigningJob, evidenceRustTestSigningJob, evidenceObserveJob, signedTreeJob } from '../../genie/evidence.ts'\n"
# These are the original fixture's references, not actions used by this repository's CI.
ACTIONS = "const adapterActions = { checkout: 'actions/checkout@v4', uploadArtifact: 'actions/upload-artifact@v4', downloadArtifact: 'actions/download-artifact@v4' }\n"


def replace_lines(source, start, end, expected, replacement):
    lines = source.splitlines(keepends=True)
    assert expected in lines[start - 1], (start, lines[start - 1])
    return ''.join(lines[:start - 1]) + replacement + ''.join(lines[end:])


def job_blocks(text):
    matches = list(re.finditer(r'^  ([a-zA-Z0-9_-]+):\n', text, re.M))
    return {match[1]: text[match.start():matches[i + 1].start() if i + 1 < len(matches) else len(text)]
            for i, match in enumerate(matches)}


with tempfile.TemporaryDirectory(prefix='mergemaster-workflow-adapters-') as scratch:
    work = Path(scratch)
    subprocess.run(['tsc', '--strict', '--noEmit', '--target', 'ES2023', '--module', 'ESNext',
                    str(ROOT / 'genie/evidence.ts')], check=True)
    workflows = work / '.github/workflows'
    workflows.mkdir(parents=True)
    # Genie preserves scalar quote styles from the consumer's existing YAML.
    # Model a consumer cutover, not first-time generation into an empty tree.
    for name in ('fleet', 'evidence-observe', 'signed-tree'):
        shutil.copy2(FIXTURE / f'.github/workflows/{name}.yml', workflows / f'{name}.yml')
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
    source = (FIXTURE / '.github/workflows/fleet.yml.genie.ts').read_text()
    signing = "{ actions: adapterActions, checkoutSteps: fullHistoryCheckoutSteps({ 'persist-credentials': false }, { name: 'Check out the tested commit', 'continue-on-error': true }), environment: evidenceEnvironment, stageNames: evidenceStageNames, stepNames: evidenceStepNames, laneNames: evidenceLaneNames, webNoteEnv: fractalWebNoteEnv, needs: "
    aggregate_needs = source.splitlines()[725].strip().removeprefix('needs: ').removesuffix(',')
    rust_needs = source.splitlines()[847].strip().removeprefix('needs: ').removesuffix(',')
    # Work backwards so the pinned source ranges remain stable. Assertions catch pin drift.
    source = replace_lines(source, 846, 928, "'evidence-note-rust-tests':", "    'evidence-note-rust-tests': evidenceRustTestSigningJob(" + signing + rust_needs + " }),\n")
    source = replace_lines(source, 723, 837, "'evidence-note-linux-gate':", "    'evidence-note-linux-gate': evidenceAggregateSigningJob(" + signing + aggregate_needs + " }),\n")
    source = replace_lines(source, 406, 431, "'evidence-source':", "    'evidence-source': evidenceSourceJob(readFileSync(new URL('../../scripts/ci-evidence-source', import.meta.url), 'utf8'), adapterActions),\n")
    source = replace_lines(source, 356, 378, 'const presignNoticeJob =', "const presignNoticeJob = evidencePresignNoticeJob({ checks: evidenceGateChecks, actions: adapterActions })\n")
    source = replace_lines(source, 282, 351, 'const evidenceGateJobs =', "const evidenceGateJobs = makeGateJobs({ checks: evidenceGateChecks, runInputs: evidenceGateRunInputs, actions: adapterActions })\n")
    (workflows / 'fleet.yml.genie.ts').write_text(IMPORT + ACTIONS + source)
    for name, start, end, anchor, replacement in (
        ('evidence-observe', 33, 56, 'observe:', '    observe: evidenceObserveJob([evidenceGroup, evidenceRunner], adapterActions),\n'),
        ('signed-tree', 18, 39, "'signed-tree':", "    'signed-tree': signedTreeJob(adapterActions),\n"),
    ):
        original = (FIXTURE / f'.github/workflows/{name}.yml.genie.ts').read_text()
        (workflows / f'{name}.yml.genie.ts').write_text(
            IMPORT + ACTIONS + replace_lines(original, start, end, anchor, replacement))
    subprocess.run(['genie'], cwd=work, check=True,
                   env=dict(os.environ, HOME=scratch))
    for name in ('fleet', 'evidence-observe', 'signed-tree'):
        actual = (workflows / f'{name}.yml').read_bytes()
        expected = (FIXTURE / f'.github/workflows/{name}.yml').read_bytes()
        if name == 'fleet':
            actual_jobs = job_blocks(actual.decode())
            expected_jobs = job_blocks(expected.decode())
            selected = [key for key in expected_jobs if key.startswith('evidence-')]
            assert selected, 'No evidence jobs selected'
            assert actual_jobs.keys() == expected_jobs.keys(), 'Consumer job inventory changed'
            for key in selected:
                assert actual_jobs[key].encode() == expected_jobs[key].encode(), ''.join(
                    difflib.unified_diff(expected_jobs[key].splitlines(keepends=True),
                                         actual_jobs[key].splitlines(keepends=True),
                                         fromfile=f'pinned/{name}/{key}', tofile=f'rendered/{name}/{key}'))
        else:
            assert actual == expected, ''.join(difflib.unified_diff(
                expected.decode().splitlines(keepends=True), actual.decode().splitlines(keepends=True),
                fromfile=f'pinned/{name}', tofile=f'rendered/{name}'))
        print(f'{name}.yml: evidence sections byte-identical YES')
    print('Workflow adapter strict typecheck and golden test passed')
