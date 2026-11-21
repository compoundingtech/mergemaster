"""Shared by the evidence script tests. Not a script: tests import it from the scripts directory."""
import json
import subprocess
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True


# What the signer refuses to start with (scripts/evidence-sign REFUSED_ENVIRONMENT). Some hosts set LD_PRELOAD for
# every process, so a test that expects the signer to run first removes these from its own environment.
LOADER_VARIABLES = ('LD_PRELOAD', 'LD_AUDIT', 'DYLD_INSERT_LIBRARIES', 'GCONV_PATH', 'NLSPATH',
                    'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME')


def clean_loader_environment():
    for name in LOADER_VARIABLES:
        os.environ.pop(name, None)


def tool_path():
    """Directories of the real git and ssh-keygen on this machine, usable as the signer's own path.

    The signer accepts only directories it can trust: not under HOME or a temporary directory, not
    writable by the user running it unless in /nix/store. A Nix sandbox keeps the tools in /nix/store,
    outside the signer's fixed system directories, so the tests hand it these.
    """
    unsafe = [Path.home(), Path(tempfile.gettempdir()), Path('/tmp'), Path('/var/tmp')]
    found = []
    for tool in ('git', 'ssh-keygen'):
        for directory in os.environ['PATH'].split(':'):
            real = os.path.realpath(directory)
            if 'recorder' in directory or not (Path(directory) / tool).exists():
                continue
            if any(real == str(root) or real.startswith(str(root).rstrip('/') + '/') for root in unsafe):
                continue
            if not real.startswith('/nix/store/') and os.access(real, os.W_OK):
                continue
            found.append(directory)
            break
    return ':'.join(dict.fromkeys(found))



IDENTITY = ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid']
NOW = datetime.now(timezone.utc)
OBSERVED = 'github:org/repo/actions/runs/7/attempts/1/jobs/9'

def run(*command, cwd=None, stdin=None):
    done = subprocess.run(command, cwd=cwd, input=stdin, capture_output=True, check=False)
    if done.returncode != 0:
        raise AssertionError(done.stderr.decode())
    return done.stdout.decode().strip()


def init_repo(path, *options):
    """A throwaway repository that git never maintains in the background.

    After a commit or a fetch git starts `git maintenance run --auto --detach`, which outlives the command: it takes
    objects/maintenance.lock and, past a few hundred loose objects, repacks (git 2.54 does so even with gc.auto=0;
    only maintenance.auto=false stops it). Running on, it writes into objects/ and objects/pack while the temporary
    directory is removed ("Directory not empty: '.../.git/objects'" at cleanup), and it can repack the objects the
    next command is reading (the likely source of a `git commit` failing with "fatal: could not parse HEAD").
    """
    run('git', 'init', '-q', *options, str(path))
    run('git', '-C', str(path), 'config', 'gc.auto', '0')
    run('git', '-C', str(path), 'config', 'maintenance.auto', 'false')


class Fixture:
    def __init__(self, object_format='sha1', layout='tree'):
        # 'tree': refs/notes/evidence/<tree>/<record> (what publishers write); 'tag': refs/tags/evidence/<tree>/<record> (protected, next);
        # 'legacy': refs/notes/evidence/<record>
        self.layout = layout
        self.ref_of = {}
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        init_repo(self.repo, f'--object-format={object_format}')
        self.allowed = []
        self.keys = self.root / 'allowed-signers'
        self.counter = 0

    def git(self, *args, stdin=None):
        return run('git', '-C', str(self.repo), *IDENTITY, *args, stdin=stdin)

    def ref_for(self, record, tree):
        return {'tree': f'refs/notes/evidence/{tree}/{record}', 'tag': f'refs/tags/evidence/{tree}/{record}'}.get(self.layout, f'refs/notes/evidence/{record}')

    def key(self, name, principal=None):
        path = self.root / name
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path))
        if principal:
            self.allowed.append(f'{principal} namespaces="git" {path.with_suffix(".pub").read_text()}')
            self.keys.write_text(''.join(self.allowed))
        return path

    def commit(self, content):
        (self.repo / 'file.txt').write_text(content)
        self.git('add', '-A')
        self.git('commit', '-q', '-m', content)
        return self.git('rev-parse', 'HEAD'), self.git('rev-parse', 'HEAD^{tree}')

    def note(self, commit, tree, key, signer, check='unit', command=('make', 'test'), exit_code=0,
             runner='nix', tier='full', seconds=0, sign=True, naive=False, inputs=None, omit_inputs=False, mutate=None, parent=None,
             predicate_type='https://smalltalk.dev/evidence/gate/v1'):
        statement = {
            '_type': 'https://in-toto.io/Statement/v1',
            'subject': [{'name': commit, 'digest': {'gitTree': tree}}],
            'predicateType': predicate_type,
            'predicate': {
                'schema_version': 1, 'change_id': 'change-1', 'signer': signer, 'tier': tier,
                're_attests': None, 'producer_sha256': 'a' * 64,
                'observed_at': (NOW + timedelta(seconds=seconds)).replace(tzinfo=None if naive else timezone.utc).isoformat(),
                'observed': {'kind': 'tests', 'runner': runner, 'inputs': inputs or {},
                             'checks': {check: {'command': list(command), 'exit_code': exit_code,
                                                'output_sha256': 'b' * 64}}},
            },
        }
        if omit_inputs:
            del statement['predicate']['observed']['inputs']
        body = json.dumps(statement).encode()
        if mutate is not None:
            body = mutate(body)
        blob = self.git('hash-object', '-w', '--stdin', stdin=body)
        notes = self.git('mktree', stdin=f'100644 blob {blob}\t{tree}\n'.encode())
        args = ['-c', 'gpg.format=ssh', '-c', f'user.signingKey={key}', 'commit-tree']
        if sign:
            args.append('-S')
        record = self.git(*args, notes, '-p', parent or commit, '-m', 'st gate observation v1')
        self.ref_of[record] = self.ref_for(record, tree)
        self.git('update-ref', self.ref_of[record], record)
        return record

    def cli(self, *args):
        done = subprocess.run([os.environ.get('MERGEMASTER_BIN', 'mergemaster'),
                               'legacy-evidence-verify', '--repo', str(self.repo), *args],
                              capture_output=True, check=False)
        return done.returncode, done.stdout.decode(), done.stderr.decode()


def policy_text(**overrides):
    doc = {'version': 1, 'checks': {'unit': {
        'trust_levels': ['machine'],
        'kinds': {
            'observed': {'command': ['github-actions', '{repository}', '.github/workflows/fleet.yml', '{check}'],
                         'runner_prefix': 'github:{repository}/'},
            'wrapper': {'command': ['make', 'test'], 'required_inputs': ['flake_lock_sha256', 'toolchain_sha256'],
                        'bind_inputs': {'flake_lock_sha256': 'file.txt'}},
        }}}}
    doc['checks']['unit'].update(overrides)
    return json.dumps(doc)


def two_check_policy(unit_require=None, other_require=None):
    """Two checks, `unit` and `other`, each accepting only the observed kind, with their own `require` mode."""
    doc = json.loads(policy_text())
    unit = doc['checks']['unit']
    del unit['kinds']['wrapper']
    other = json.loads(json.dumps(unit))
    other['kinds']['observed']['command'] = ['github-actions', '{repository}', '.github/workflows/fleet.yml', '{check}']
    doc['checks']['other'] = other
    if unit_require is not None:
        unit['require'] = unit_require
    if other_require is not None:
        other['require'] = other_require
    return json.dumps(doc)


def project(repo, tree, paths):
    done = subprocess.run([os.environ.get('MERGEMASTER_BIN', 'mergemaster'),
                           'legacy-evidence-verify', '--repo', repo, '--tree', tree,
                           '--check', 'fixture', '--project', '--paths', ','.join(paths)],
                          capture_output=True, check=True)
    return json.loads(done.stdout)['source_inputs']


def helper(operation, *args, text):
    done = subprocess.run([os.environ.get('MERGEMASTER_BIN', 'mergemaster'),
                           'legacy-evidence-verify-helper', operation, *args],
                          input=text.encode(), capture_output=True, check=True)
    return json.loads(done.stdout)
