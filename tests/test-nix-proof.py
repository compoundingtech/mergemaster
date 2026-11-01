#!/usr/bin/env python3
"""Real Nix closure -> Node module input -> scratch output -> signed gate proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--node', type=Path, required=True)
p.add_argument('--nix', type=Path, required=True)
p.add_argument('--work-dir', type=Path, required=True)
a = p.parse_args()
binary, node, nix = (path.resolve(strict=True) for path in (a.binary, a.node, a.nix))
work = a.work_dir.resolve()
work.mkdir(parents=True, exist_ok=False)
repo, deps, scratch = (work / name for name in ('repo', 'node_modules', 'scratch'))
for directory in (repo, deps / 'fixture', scratch):
    directory.mkdir(parents=True)
env = {k: v for k, v in os.environ.items() if not k.startswith(('LD_', 'DYLD_', 'PYTHON'))
       and k not in ('GCONV_PATH', 'NLSPATH', 'GLIBC_TUNABLES')}
env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', LC_ALL='C')


def run(argv, cwd=repo, ok=True, **kwargs):
    result = subprocess.run([str(x) for x in argv], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    if ok:
        assert result.returncode == 0, (argv, result.stdout, result.stderr)
    return result


def git(*argv, cwd=repo):
    return run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', *argv], cwd).stdout.decode().strip()


def write(name, value):
    (repo / '.mergemaster' / name).write_text(json.dumps(value))


(deps / 'fixture/package.json').write_text('{"name":"fixture","main":"index.js"}')
(deps / 'fixture/index.js').write_text('module.exports = 42;\n')
git('init', '-q', cwd=deps)
git('add', '.', cwd=deps)
git('commit', '-qm', 'Resolved node_modules input', cwd=deps)
dep_commit = git('rev-parse', 'HEAD', cwd=deps)
git('init', '-q')
key = work / 'key'
run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key])
(repo / '.mergemaster').mkdir()
(repo / '.mergemaster/evidence-keys').write_text('agent/fixture ' + key.with_suffix('.pub').read_text())
write('tool-pin.json', {'version': 1, 'repository': 'compoundingtech/mergemaster', 'revision': 'a' * 40})
root = node.parents[1]
assert str(root).startswith('/nix/store/')
identity = 'nix:' + str(root)
write('environment.json', {'version': 1, 'system': f'{platform.machine()}-linux', 'toolchain': {
    'runtime': {'name': 'node', 'identity': identity},
    'dependencies': {'modules': {'name': 'modules', 'identity': 'git:' + dep_commit}}}})
(repo / 'check.cjs').write_text('const fs=require("node:fs"); const value=require(process.argv[2]+"/fixture"); '
                               'if(value!==42) process.exit(1); fs.writeFileSync(process.argv[3]+"/output",String(value)); console.log("PASS node_modules -> scratch");\n')
argv = [str(node), 'check.cjs', str(deps), str(scratch)]
write('lanes.json', {'version': 1, 'pull_request': {'same_repository': True,
    'authors': {'mode': 'none'}, 'base_relation': 'ancestor'}, 'protected_paths': [], 'lanes': {'node': {
        'argv': argv, 'definition_paths': ['check.cjs'], 'trust_levels': ['agent'],
        'mode': 'required_evidence', 'events': ['pull_request'],
        'environment': {'manifest': '.mergemaster/environment.json', 'paths': ['check.cjs']},
        'protected_edits': 'reject', 'remediation_argv': ['mergemaster', 'evidence', 'wrap']}}})
git('add', '.')
git('commit', '-qm', 'BASE policy')
base = git('rev-parse', 'HEAD')
git('update-ref', 'refs/heads/gate-base', base)
(repo / 'candidate').write_text('candidate\n')
git('add', '.')
git('commit', '-qm', 'Candidate')
head = git('rev-parse', 'HEAD')
git('init', '--bare', '-q', str(work / 'origin.git'))
git('remote', 'add', 'origin', str(work / 'origin.git'))
git('push', '-q', 'origin', 'HEAD:refs/heads/main')
config = work / 'signer.json'
paths = {str(Path(shutil.which(tool)).resolve().parent) for tool in ('git', 'ssh-keygen')}
paths.add(str(nix.parent))
configuration = {'version': 1, 'signer': 'agent/fixture', 'ssh_key': str(key), 'path': ':'.join(sorted(paths)),
                 'toolchain': {'runtime': str(root), 'dependencies': {'modules': str(deps)}}}
config.write_text(json.dumps(configuration))
config.chmod(0o600)
signer = [str(binary), 'evidence', 'sign', '--config', str(config)]
wrap = [binary, 'evidence', 'wrap', '--check', 'node', '--base', base, '--config', config,
        '--signer', json.dumps(signer), '--', *argv]
result = run(wrap)
assert (scratch / 'output').read_text() == '42'
decision = json.loads(run([binary, 'gate', '--check', 'node', '--base', base, '--head', head, '--format', 'json']).stdout)
assert decision['decision'] == 'skip', decision
# Closure digest is signed, and the signer independently refuses a changed claim.
record = decision['record']
statement = json.loads(git('show', record + ':' + git('rev-parse', head + '^{tree}')))
inputs = statement['predicate']['observed']['inputs']
closure_key = 'nix_closure_sha256:' + identity
assert len(inputs[closure_key]) == 64
inputs[closure_key] = '0' * 64
import base64
request = {'version': 1, 'repo': str(repo), 'base': base, 'head': head, 'check': 'node', 'command': argv,
           'exit_code': 0, 'output': base64.b64encode(result.stdout).decode(), 'inputs': inputs}
refused = run(signer, ok=False, input=json.dumps(request).encode())
assert refused.returncode != 0 and b'closure digest mismatch' in refused.stderr, refused.stderr
# Configured roots cannot silently replace the committed Nix artifact.
configuration['toolchain']['runtime'] = '/nix/store/' + '0' * 32 + '-missing'
config.write_text(json.dumps(configuration))
assert run(wrap, ok=False).returncode != 0
key.unlink()
config.unlink()
print('PASS real Nix closure, node_modules input, scratch output, gate skip, independent signer mismatch refusal')
