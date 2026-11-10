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
        assert actual == baseline[name], ''.join(difflib.unified_diff(
            baseline[name].decode().splitlines(keepends=True),
            actual.decode().splitlines(keepends=True),
            fromfile=f'consumer-generator/{name}', tofile=f'adapter-generator/{name}'))
        print(f'{name}.yml: generator-to-generator byte-identical YES')
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

subprocess.run(['python3', str(ROOT / 'tests/test-generic-evidence.py')], check=True)
