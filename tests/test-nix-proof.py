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
p.add_argument('--derivation', action='store_true')
p.add_argument('--require-daemon', action='store_true')
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
system = f'{platform.machine()}-linux'
write('environment.json', {'version': 1, 'systems': {system: {
    'runtime': {'name': 'node', 'identity': identity},
    'dependencies': {'modules': {'name': 'modules', 'identity': 'git:' + dep_commit}}}}})
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
if a.derivation:
    configuration['toolchain']['runtime'] = str(root)
    configuration['toolchain']['dependencies']['nix-tool'] = str(nix.parents[1])
    config.write_text(json.dumps(configuration))
    environment = json.loads((repo / '.mergemaster/environment.json').read_text())
    environment['systems'][system]['dependencies']['nix-tool'] = {'name': 'nix', 'identity': 'nix:' + str(nix.parents[1])}
    write('environment.json', environment)
    shutil.copytree(deps / 'fixture', repo / 'fixture/node_modules/fixture')
    (repo / 'builder.cjs').write_text('const fs=require("node:fs"); const value=require(process.env.src+"/node_modules/fixture"); '
        'console.error("RUN_BUILDER_START"); let acc=0; for(let i=0;i<20000000000;i++) acc=(acc+i)|0; console.error("RUN_BUILDER_FINISH "+acc); '
        'fs.writeFileSync(process.env.TMPDIR+"/scratch",String(value)); fs.writeFileSync(process.env.out,String(value));\n')
    system = f'{platform.machine()}-linux'
    (repo / 'flake.nix').write_text('{ outputs = { self }: { checks.' + system + '.marker = builtins.derivation { '
        'name = "mergemaster-proof-' + hashlib.sha256(str(work).encode()).hexdigest()[:12] + '"; '
        'system = "' + system + '"; builder = builtins.appendContext "' + str(node) + '" { "' + str(root) +
        '" = { path = true; }; }; args = [ ./builder.cjs ]; src = ./fixture; }; }; }\n')
    policy = json.loads((repo / '.mergemaster/lanes.json').read_text())
    lane = policy['lanes']['node']
    lane.update(argv=[str(nix)], definition_paths=['flake.nix', 'builder.cjs', 'fixture'],
                nix_check={'attribute': f'checks.{system}.marker', 'required': 'fresh'})
    lane['environment']['paths'] = ['flake.nix', 'builder.cjs', 'fixture']
    write('lanes.json', policy)
    git('add', '.')
    git('commit', '-qm', 'Derivation BASE policy')
    base = git('rev-parse', 'HEAD')
    git('update-ref', 'refs/heads/gate-base', base)
    (repo / 'candidate').write_text('derivation candidate\n')
    git('add', '.')
    git('commit', '-qm', 'Derivation candidate')
    head = git('rev-parse', 'HEAD')
    nix_flags = [str(nix), '--extra-experimental-features', 'nix-command flakes',
                 '--option', 'builders', '', '--option', 'build-hook', '', '--option', 'max-jobs', '1']
    installable = f'git+file://{repo}?rev={head}#checks.{system}.marker'
    # Synchronize on a live builder, then require actual same-output lock contention.
    racer = subprocess.Popen([*nix_flags, 'build', '--print-build-logs', '--no-link', installable], cwd=repo, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    startup = bytearray()
    for line in iter(racer.stderr.readline, b''):
        startup.extend(line)
        if b'RUN_BUILDER_START' in line:
            break
    assert b'RUN_BUILDER_START' in startup and racer.poll() is None, startup
    # Hostile caller and candidate preferences must not weaken either boundary.
    env['NIX_CONFIG'] = 'accept-flake-config = true\npure-eval = false\nallow-import-from-derivation = true\nmax-jobs = 0\n'
    wrap = [binary, 'evidence', 'wrap', '--check', 'node', '--base', base, '--config', config,
            '--signer', json.dumps(signer)]
    fresh = run(wrap)
    race_out, race_err = racer.communicate()
    assert racer.returncode == 0, (race_out, race_err)
    assert b'RUN_BUILDER_START' in fresh.stdout and b'waiting for lock on' in fresh.stdout, fresh.stdout
    value = json.loads(run([binary, 'gate', '--check', 'node', '--base', base, '--head', head, '--format', 'json']).stdout)
    assert value['decision'] == 'skip', value
    statement = json.loads(git('show', value['record'] + ':' + git('rev-parse', head + '^{tree}')))
    inputs = statement['predicate']['observed']['inputs']
    actual = statement['predicate']['observed']['checks']['node']['command']
    assert inputs['nix_execution'] == 'rebuild' and '--rebuild' in actual
    for option, expected in [('builders', ''), ('build-hook', ''), ('max-jobs', '1'), ('accept-flake-config', 'false')]:
        assert any(actual[i:i+3] == ['--option', option, expected] for i in range(len(actual))), actual
    assert len(inputs['nix_settings_sha256']) == 64
    if a.require_daemon:
        assert inputs['nix_store'] == 'daemon' and inputs['nix_daemon_trusted'] == 'true', inputs
    print('Verified execution boundary:', json.dumps({k: v for k, v in inputs.items() if k in
          ('nix_settings_sha256', 'nix_store', 'nix_daemon_trusted', 'nix_execution')}, sort_keys=True))
    request.update(base=base, head=head, command=actual, inputs=inputs)
    request['command'] = [*actual[:-1], '/nix/store/' + '0' * 32 + '-wrong.drv^*']
    assert run(signer, ok=False, input=json.dumps(request).encode()).returncode != 0
    reused = run([*wrap, '--reuse'])
    value = json.loads(run([binary, 'gate', '--check', 'node', '--base', base, '--head', head, '--format', 'json']).stdout)
    assert value['reason'] == 'fresh_execution_required', value
    # A non-deterministic check must fail the final rebuild, never assert success.
    with (repo / 'builder.cjs').open('a') as file:
        file.write('fs.writeFileSync(process.env.out, require("node:crypto").randomBytes(32));\n')
    git('add', '.')
    git('commit', '-qm', 'Non-deterministic candidate')
    nondeterministic = run(wrap, ok=False)
    assert nondeterministic.returncode != 0, nondeterministic.stdout
    def failure_record():
        value = json.loads(run([binary, 'gate', '--check', 'node', '--base', base,
                               '--head', git('rev-parse', 'HEAD'), '--format', 'json']).stdout)
        assert value['reason'] == 'check_failed' and value['record'], value
        statement = json.loads(git('show', value['record'] + ':' + git('rev-parse', 'HEAD^{tree}')))
        inputs = statement['predicate']['observed']['inputs']
        assert inputs['nix_execution'] == 'failed' and 'nix_outputs_sha256' not in inputs, inputs
    failure_record()
    (repo / 'builder.cjs').write_text('console.error("COLD_FAILURE"); process.exit(7);\n')
    git('add', '.')
    git('commit', '-qm', 'Cold failing candidate')
    assert run(wrap, ok=False).returncode != 0
    failure_record()
    assert run([*wrap, '--reuse'], ok=False).returncode != 0
    failure_record()
    (repo / 'builder.cjs').write_text('require("node:fs").writeFileSync(process.env.out,"42");\n')
    lane['nix_check']['required'] = 'any'
    write('lanes.json', policy)
    git('add', '.')
    git('commit', '-qm', 'Reuse-accepting BASE policy')
    base = git('rev-parse', 'HEAD')
    git('update-ref', 'refs/heads/gate-base', base)
    (repo / 'candidate').write_text('reuse candidate\n')
    git('add', '.')
    git('commit', '-qm', 'Reuse candidate')
    head = git('rev-parse', 'HEAD')
    wrap = [binary, 'evidence', 'wrap', '--check', 'node', '--base', base, '--config', config,
            '--signer', json.dumps(signer)]
    run([*wrap, '--reuse'])
    value = json.loads(run([binary, 'gate', '--check', 'node', '--base', base, '--head', head, '--format', 'json']).stdout)
    assert value['decision'] == 'skip' and value['outcome'] == 'reused' and value['reason'] == 'execution_reused', value
    # Saved/candidate acceptance cannot enable an absolute-path read in pure evaluation.
    flake = (repo / 'flake.nix').read_text()
    flake = flake.replace('{ outputs', '{ nixConfig = { pure-eval = false; allow-import-from-derivation = true; }; outputs')
    flake = flake.replace('name = "', 'name = builtins.readFile /etc/hostname; ignored = "')
    (repo / 'flake.nix').write_text(flake)
    git('add', '.')
    git('commit', '-qm', 'Hostile flake preferences')
    assert run(wrap, ok=False).returncode != 0
    print('PASS derivation cold/racing rebuild, argv mismatch, reused freshness refusal, non-deterministic refusal')
key.unlink()
config.unlink()
print('PASS real Nix closure, node_modules input, scratch output, gate skip, independent signer mismatch refusal')
