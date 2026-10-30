#!/usr/bin/env python3
"""Real tools/graph setup -> full Vitest -> signer -> origin -> gate; retain proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=Path, required=True)
parser.add_argument('--work-dir', type=Path, required=True)
args = parser.parse_args()
binary = args.binary.resolve(strict=True)
work = args.work_dir.resolve()
work.mkdir(parents=True, exist_ok=False)
repo, dependencies = work / 'repository', work / 'dependencies'
shutil.copytree(Path(__file__).parent / 'fixtures/graph', repo)
node = Path(shutil.which('node')).resolve(strict=True)
env = {key: value for key, value in os.environ.items() if not key.startswith(('LD_', 'DYLD_'))
       and key not in ('GCONV_PATH', 'NLSPATH', 'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME')}
env.update(GRAPH_DEPENDENCIES=str(dependencies), GIT_CONFIG_NOSYSTEM='1',
           GIT_CONFIG_GLOBAL='/dev/null', GIT_NO_REPLACE_OBJECTS='1', LC_ALL='C')


def run(argv, cwd=repo, **kwargs):
    result = subprocess.run([str(arg) for arg in argv], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    if result.returncode:
        raise AssertionError(f'{argv}: {result.returncode}\n{result.stdout.decode(errors="replace")}')
    return result.stdout


def git(*argv, cwd=repo):
    return run(['git', '-c', 'init.templateDir=', '-c', 'user.name=Fixture',
                '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
                '-c', 'core.hooksPath=/dev/null', *argv], cwd=cwd).decode().strip()


def write(name, value):
    target = repo / '.mergemaster' / name
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(value) + '\n')


# Setup happens once, outside signing. Capture the resolved complete npm closure
# as a clean Git repository, not merely the mutable package version label.
setup = run([node, 'tools/graph', 'setup'])
(work / 'setup-output.txt').write_bytes(setup)
git('init', '-q', cwd=dependencies)
git('add', '--force', '.', cwd=dependencies)
git('commit', '-q', '-m', 'Resolved complete Vitest dependency closure', cwd=dependencies)
closure = git('rev-parse', 'HEAD', cwd=dependencies)
git('init', '-q')
key = work / 'signing-key'
run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key])
(repo / '.mergemaster').mkdir()
(repo / '.mergemaster/evidence-keys').write_text('agent/fixture ' + key.with_suffix('.pub').read_text())
write('tool-pin.json', {'version': 1, 'repository': 'compoundingtech/mergemaster', 'revision': 'a' * 40})
write('environment.json', {'version': 1, 'system': f'{platform.machine()}-linux', 'toolchain': {
    'runtime': {'name': 'node', 'identity': 'sha256:' + hashlib.sha256(node.read_bytes()).hexdigest()},
    'dependencies': {'vitest-closure': {'name': 'vitest-closure', 'identity': 'git:' + closure}}}})
check = 'graph-full-check'
argv = [str(node), 'tools/graph', 'check', '--full']
write('lanes.json', {'version': 1, 'pull_request': {'same_repository': True,
    'authors': {'mode': 'none'}, 'base_relation': 'ancestor'}, 'protected_paths': [], 'lanes': {check: {
    'argv': argv, 'definition_paths': ['tools', 'lib', 'package.json', 'graph.test.js'],
    'trust_levels': ['agent'], 'mode': 'required_evidence', 'events': ['pull_request'],
    'environment': {'manifest': '.mergemaster/environment.json',
                    'paths': ['tools', 'lib', 'package.json', 'graph.test.js']},
    'protected_edits': 'reject', 'remediation_argv': ['mergemaster', 'evidence', 'wrap']}}})
git('add', '.')
git('commit', '-q', '-m', 'Graph-shaped fixture after setup')
base = git('rev-parse', 'HEAD')
git('update-ref', 'refs/heads/gate-base', base)
(repo / 'candidate.txt').write_text('candidate change covered by exact tree\n')
git('add', '.')
git('commit', '-q', '-m', 'Candidate')
head = git('rev-parse', 'HEAD')
git('init', '--bare', '-q', str(work / 'origin.git'))
git('remote', 'add', 'origin', str(work / 'origin.git'))
git('push', '-q', 'origin', 'HEAD:refs/heads/main')
config = work / 'signer.json'
trusted_path = ':'.join(sorted({str(Path(shutil.which(tool)).resolve().parent) for tool in ('git', 'ssh-keygen')}))
config.write_text(json.dumps({'version': 1, 'signer': 'agent/fixture', 'ssh_key': str(key), 'path': trusted_path,
    'toolchain': {'runtime': str(node), 'dependencies': {'vitest-closure': str(dependencies)}}}))
config.chmod(0o600)
signer = json.dumps([str(binary), 'evidence', 'sign', '--config', str(config)])
# Preserve the complete output even on a failed check/signature assertion.
result = subprocess.run([str(binary), 'evidence', 'wrap', '--check', check, '--base', base,
    '--config', str(config), '--signer', signer, '--', *argv], cwd=repo, env=env,
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(work / 'full-vitest-output.txt').write_bytes(result.stdout)
print(result.stdout.decode(errors='replace'), end='')
assert result.returncode == 0, f'full check or signing failed: {result.returncode}'
assert b'4 passed' in result.stdout, 'proof must contain the actual full Vitest result'
value = json.loads(run([binary, 'gate', '--check', check, '--base', base, '--head', head, '--format', 'json']))
assert value['decision'] == 'skip' and value['outcome'] == 'satisfied', value
assert value['record'], value
(work / 'gate-decision.json').write_text(json.dumps(value, indent=2) + '\n')
# Public retained artifacts contain the store worktree, closure, and complete
# output, but never the ephemeral private signing key or signer configuration.
key.unlink()
config.unlink()
print(json.dumps(value, sort_keys=True))
print('Graph-shaped setup -> full Vitest -> signed origin evidence -> gate skip: PASS')
