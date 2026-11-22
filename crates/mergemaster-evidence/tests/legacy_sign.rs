//! Real legacy signer boundaries, replayed against the independent pinned Python source.
#[path = "../src/pinned_python.rs"]
mod pinned_python;

use std::process::Command;

fn replay(group: &str) {
    let oracle = std::env::var_os("MERGEMASTER_PYTHON_ORACLE")
        .expect("MERGEMASTER_PYTHON_ORACLE must name the independent pinned source");
    let mut command: Command = pinned_python::command();
    let output = command
        .args(["-B", "-c", DRIVER])
        .arg(group)
        .arg(
            std::env::var_os("CARGO_BIN_EXE_mergemaster")
                .expect("CARGO_BIN_EXE_mergemaster is set at test runtime"),
        )
        .arg(oracle)
        .arg(
            std::path::PathBuf::from(
                std::env::var_os("CARGO_MANIFEST_DIR")
                    .expect("CARGO_MANIFEST_DIR is set at test runtime"),
            )
            .join("../../tests/fixtures/oracle/request-core/validation/stdout.bin"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{group}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn recorded_requests_reach_validators_and_match_refusal_classes() {
    replay("requests");
}

#[test]
fn real_signed_packs_match_except_for_native_producer_and_cross_verify() {
    replay("signing");
}

#[test]
fn literal_inf_check_keeps_its_name_in_real_signed_statement_parity() {
    replay("signing-inf");
}

#[test]
fn python_json_extensions_match_signed_bytes_and_integer_limit_refusals() {
    for group in [
        "signing-nan",
        "signing-infinity",
        "signing-surrogate",
        "json-refusals",
    ] {
        replay(group);
    }
}

#[test]
fn missing_home_configuration_refusals_name_python_paths() {
    replay("home");
}

#[test]
fn every_falsy_config_path_uses_the_default_tool_path() {
    replay("config-falsy");
}

#[test]
fn group_7_loader_tripwire_precedes_configuration_and_allows_library_path() {
    replay("loader");
}

#[test]
fn direct_signer_request_and_nix_contracts_preserve_every_legacy_assertion() {
    replay("contract");
}

const DRIVER: &str = r#"
import base64, hashlib, importlib.machinery, importlib.util, json, os, pathlib, shutil, subprocess, sys, tempfile

group, binary, oracle, matrix = sys.argv[1], pathlib.Path(sys.argv[2]).resolve(), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4])
script = oracle / 'scripts/evidence-sign'
loader = importlib.machinery.SourceFileLoader('legacy_sign_oracle', str(script))
spec = importlib.util.spec_from_loader(loader.name, loader)
signer = importlib.util.module_from_spec(spec)
loader.exec_module(signer)
LOADER = ('LD_PRELOAD', 'LD_AUDIT', 'DYLD_INSERT_LIBRARIES', 'GCONV_PATH', 'NLSPATH', 'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME')
env = {k: v for k, v in os.environ.items() if k not in LOADER}
env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0', LC_ALL='C')
NOW = '2026-01-02T03:04:05Z'

def run(argv, data=None, cwd=None, extra=None):
    child_env = {k: v for k, v in dict(env, **(extra or {})).items() if v is not None}
    return subprocess.run(list(map(str, argv)), input=data, cwd=cwd, env=child_env, capture_output=True, timeout=300)

def good(done):
    assert done.returncode == 0, (done.args, done.returncode, done.stdout, done.stderr)
    return done.stdout

def git(repo, *args, data=None):
    return good(run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-C', repo,
                     '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', *args], data))

def init(repo, bare=False):
    good(run(['git', 'init', '-q', *(['--bare'] if bare else []), repo]))
    git(repo, 'config', 'gc.auto', '0')
    git(repo, 'config', 'maintenance.auto', 'false')

def invoke(native, home, repo, raw, extra=None):
    argv = [binary, 'evidence', 'legacy-sign'] if native else [sys.executable, '-I', '-B', script]
    return run(argv, raw, repo, {'HOME': str(home), 'EVIDENCE_SIGN_NOW': NOW, **(extra or {})})

def refusal(done):
    assert done.returncode == 1 and done.stdout == b'', (done.args, done.returncode, done.stdout, done.stderr)
    # Loader warnings may precede the one refusal prefix; Git diagnostics can
    # continue on subsequent lines, which remain part of the refusal.
    prefix = 'evidence-sign refused: '
    lines = done.stderr.decode('utf-8', errors='replace').splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    assert len(starts) == 1, done.stderr
    return ''.join(lines[starts[0]:]).removeprefix(prefix).rstrip('\n')

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    home, repo = root / 'home', root / 'source'
    home.mkdir()
    init(repo)
    # Discover real, trusted tools without relaxing either implementation's
    # directory/file policy (including immutable Nix store ownership rules).
    tools = []
    for name in ('git', 'ssh-keygen'):
        for directory in env['PATH'].split(os.pathsep):
            if 'recorder' in directory:
                continue
            found = shutil.which(name, path=directory)
            if not found:
                continue
            real = pathlib.Path(found).resolve()
            if signer.unsafe_directory(directory) is None and signer.unsafe_directory(str(real.parent)) is None and signer.unsafe_file(str(real)) is None:
                tools.append(directory)
                break
        else:
            raise AssertionError('fixture requires a real trusted ' + name)
    tool_path = ':'.join(dict.fromkeys(tools))
    config_path = home / '.config/st/evidence-sign.json'
    config_path.parent.mkdir(parents=True)
    key = home / 'key'
    good(run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key]))
    scratch = home / 'scratch.git'
    init(scratch, bare=True)
    config = dict(signer='fleet/legacy-fixture', ssh_key=str(key), scratch_repo=str(scratch), path=tool_path, test_clock=True)
    config_path.write_text(json.dumps(config))

    if group == 'requests':
        cases = json.loads(matrix.read_bytes())
        assert len(cases) > 100
        for case in cases:
            # Preserve every original token, including huge integers, NaN-like
            # floats, duplicate-sensitive spelling and Python scalar coercions.
            raw = case['request_json'].encode()
            reference = invoke(False, home, repo, raw)
            actual = invoke(True, home, repo, raw)
            expected, observed = refusal(reference), refusal(actual)
            if case['valid']:
                # The recorded synthetic object id is deliberately absent.
                # Native hardening adds a completeness preflight; the pinned
                # Python instead reaches its original cat-file binding check.
                assert expected.startswith('git cat-file failed:'), (case['label'], expected)
                commit = json.loads(raw)['commit']
                if len(commit) == 40:
                    assert observed == '1 missing objects before signing; hydrate the source repository in the caller first', (case['label'], observed)
                else:
                    # The 64-character and final-newline forms pass Python's
                    # validator but are not object names in this SHA-1 repo.
                    preflight = run(['git', '-C', repo, 'rev-list', '--objects', '--missing=print', commit])
                    assert preflight.returncode != 0, (case['label'], preflight.stdout)
                    message = 'git rev-list failed: ' + preflight.stderr.decode(errors='replace').strip()[-500:]
                    assert observed == message, (case['label'], message, observed)
            else:
                assert not expected.startswith(('git ', 'tool path ', 'configuration ', 'invalid signer')), (case['label'], expected)
                # Ignore only Git's host/version-specific detail after the class
                # separator; validator refusal text remains byte-for-byte equal.
                assert observed == expected, (case['label'], expected, observed)
            assert actual.returncode == reference.returncode, case['label']

    elif group == 'json-refusals':
        request = json.loads(json.loads(matrix.read_bytes())[0]['request_json'])
        # Parsing must reach validation for -Infinity; no valid request position
        # can contain it (str(-Infinity) == '-inf' is not a legal check name).
        request['check'] = float('-inf')
        raw = json.dumps(request).encode()
        assert refusal(invoke(True, home, repo, raw)) == refusal(invoke(False, home, repo, raw)) == 'check name must be lowercase letters, digits, dot, dash or underscore'
        request['check'] = 'gate'
        request['exit_code'] = 'OVER_LIMIT_INTEGER'
        raw = json.dumps(request).replace('"OVER_LIMIT_INTEGER"', '1' * 4301).encode()
        expected = 'Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits; use sys.set_int_max_str_digits() to increase the limit'
        assert refusal(invoke(False, home, repo, raw)) == expected
        assert refusal(invoke(True, home, repo, raw)) == expected

    elif group == 'home':
        import pwd
        for setting, expected_home in (('', pathlib.Path('/')), (None, pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir))):
            expected_path = expected_home / '.config/st/evidence-sign.json'
            reference = invoke(False, home, repo, b'{}', {'HOME': setting})
            actual = invoke(True, home, repo, b'{}', {'HOME': setting})
            expected, observed = refusal(reference), refusal(actual)
            if not expected_path.exists():
                assert str(expected_path) in expected and str(expected_path) in observed, (setting, expected, observed)
            else:
                assert expected == observed, (setting, expected, observed)

    elif group == 'config-falsy':
        defaults = dict(config)
        defaults.pop('path')
        for native in (False, True):
            config_path.write_text(json.dumps(defaults))
            baseline = invoke(native, home, repo, b'{}')
            assert 'invalid signer configuration' not in refusal(baseline)
            for value in (None, False, 0, 0.0, -0.0, '', [], {}):
                config_path.write_text(json.dumps(dict(defaults, path=value)))
                actual = invoke(native, home, repo, b'{}')
                assert (actual.returncode, actual.stdout, actual.stderr) == (baseline.returncode, baseline.stdout, baseline.stderr), (native, value, baseline.stderr, actual.stderr)

    elif group == 'loader':
        config_path.unlink()
        for native in (False, True):
            clean = invoke(native, home, repo, b'{}')
            assert 'evidence-sign.json' in refusal(clean), clean.stderr
            for name in LOADER:
                # Empty still means set, but cannot prevent Python itself from
                # starting (PYTHONHOME in particular). No code is loaded.
                done = invoke(native, home, repo, b'{}', {name: ''})
                expected = 'refusing to run with ' + name + ' set: the launcher must scrub the environment (this script cannot undo what the loader or interpreter already did)'
                assert refusal(done) == expected, (native, name, done.stderr)
                assert b'evidence-sign.json' not in done.stderr
            both = invoke(native, home, repo, b'{}', {'NLSPATH': '', 'GCONV_PATH': ''})
            assert refusal(both).startswith('refusing to run with GCONV_PATH, NLSPATH set:'), both.stderr
            accepted = invoke(native, home, repo, b'{}', {'LD_LIBRARY_PATH': '/nonexistent-legacy-sign-library-path'})
            assert 'evidence-sign.json' in refusal(accepted), accepted.stderr
            assert b'scrub' not in accepted.stderr

    elif group == 'contract':
        lock = b'{"nodes":{}}\n'
        (repo / 'flake.lock').write_bytes(lock)
        git(repo, 'add', '.')
        git(repo, 'commit', '-qm', 'direct signer contracts')
        commit = git(repo, 'rev-parse', 'HEAD').decode().strip()
        tree = git(repo, 'rev-parse', 'HEAD^{tree}').decode().strip()
        request = dict(commit=commit, check='linux-gate', command=['true'], exit_code=0,
                       output_sha256='0'*64, change_id='local:x',
                       inputs=dict(flake_lock_sha256=hashlib.sha256(lock).hexdigest(),
                                   toolchain_sha256='d'*64, wrapper_sha256='1'*64,
                                   system='x86_64-linux', attempt='1'))
        def check_request(value, accepted=True):
            statements = []
            for native in (False, True):
                done = invoke(native, home, repo, json.dumps(value).encode())
                if not accepted:
                    refusal(done)
                    continue
                packet = json.loads(good(done))
                pack = base64.b64decode(packet['object_pack_base64'], validate=True)
                git(repo, 'index-pack', '--stdin', data=pack)
                statement = json.loads(git(repo, 'show', packet['record'] + ':' + tree))
                producer = hashlib.sha256(binary.read_bytes() if native else script.read_bytes()).hexdigest()
                assert statement['predicate']['producer_sha256'] == producer
                assert statement['predicate']['observed']['inputs'] == value['inputs']
                assert statement['predicate']['observed']['checks'][value['check']] == {
                    'command': value['command'], 'exit_code': value['exit_code'],
                    'output_sha256': value['output_sha256']}
                statements.append(statement)
            return statements
        assert all(s['predicate']['observed']['runner'] == 'wrapper' for s in check_request(request))
        check_request(dict(request, inputs=dict(request['inputs'], run_id='123', event_name='merge_group')))
        for label, bad in {
            'extra key': dict(request, tier='full'),
            'wrong flake.lock hash': dict(request, inputs=dict(request['inputs'], flake_lock_sha256='2'*64)),
            'unknown commit': dict(request, commit='f'*40),
            'bad output digest': dict(request, output_sha256='zz'),
            'empty command': dict(request, command=[]),
            'badly named extra input': dict(request, inputs=dict(request['inputs'], **{'Bad-Name':'x'})),
            'missing required input': dict(request, inputs={k:v for k,v in request['inputs'].items() if k != 'toolchain_sha256'}),
            'empty extra input': dict(request, inputs=dict(request['inputs'], run_id='')),
            'check name with a slash': dict(request, check='a/b'),
        }.items():
            check_request(bad, False)
        drv = '/nix/store/wndx1738rbbrs30ap8l6ma5nkxgcjb89-genie-freshness-0.1.0.drv'
        out = '/nix/store/hh43mxh295bdyfb96mx8qp37ii3dkzx0-genie-freshness-0.1.0'
        nix_inputs = dict(drv_path=drv, out_path=out,
                          nar_hash='sha256-d6xi4mKdjkX2JFicDIv5niSzpyI0m/Hnm8GGAIU04kY=',
                          nar_size='112', references='-', cache_hit='false',
                          nix_signatures='test-nix-evidence-1:' + 'A'*86 + '==',
                          nix_key_id='test-nix-evidence-1', nix_unsigned='false')
        nix = dict(request, check='genie-freshness', runner='nix',
                   command=['nix', 'build', '.#checks.x86_64-linux.genie-freshness'],
                   inputs=dict(request['inputs'], **nix_inputs))
        assert all(s['predicate']['observed']['runner'] == 'nix' for s in check_request(nix))
        check_request(dict(nix, inputs=dict(nix['inputs'], nix_signatures='none', nix_key_id='none', nix_unsigned='true')))
        references = '/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a,/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b'
        check_request(dict(nix, inputs=dict(nix['inputs'], references=references)))
        check_request(dict(nix, exit_code=1, inputs=dict(request['inputs'], drv_path=drv)))
        for changes in (
            dict(drv_path=out),
            dict(out_path='/nix/store/hh43mxh295bdyfb96mx8qp37ii3dkzx0-other-0.1.0'),
            dict(out_path='/tmp/evil-genie-freshness-0.1.0'),
            dict(nar_hash='sha256:0ip26j2h11n1kgkz36rl4akv694yz65hr72q4kv4b3lxcbi65b3p'),
            dict(nar_size='12 bytes'), dict(references=','.join(reversed(references.split(',')))),
            dict(references='/etc/passwd'), dict(cache_hit='yes'), dict(nix_signatures='AAAA'),
            dict(nix_unsigned='true'), dict(nix_key_id='someone-else'),
        ):
            check_request(dict(nix, inputs=dict(nix['inputs'], **changes)), False)
        for bad in (
            dict(request, runner='sekrets'), dict(nix, command=['sh', '-c', 'true']),
            dict(nix, check='other'),
            dict(nix, command=['nix', 'build', '.#checks.x/../genie-freshness']),
            dict(nix, exit_code=1),
            dict(nix, inputs={k:v for k,v in nix['inputs'].items() if k != 'out_path'}),
        ):
            check_request(bad, False)
        with tempfile.TemporaryDirectory(dir='/tmp') as writable:
            for name in ('git', 'ssh-keygen'):
                (pathlib.Path(writable) / name).symlink_to(shutil.which(name, path=tool_path))
            config_path.write_text(json.dumps(dict(config, path=writable)))
            for native in (False, True):
                done = invoke(native, home, repo, json.dumps(request).encode(),
                              {'RUNNER_TEMP': None, 'GITHUB_WORKSPACE': None, 'TMPDIR': None})
                assert 'where code under test can write' in refusal(done), done.stderr
        config_path.write_text(json.dumps(config))
        # Exercise the signer directly: a wrapper's own Git setup must not mask
        # hostile caller PATH/configuration before the request reaches signing.
        marker = root / 'hostile-program-ran'
        shims = root / 'shims'
        shims.mkdir()
        for name in ('git', 'ssh-keygen', 'git-upload-pack', 'sh-evil'):
            program = shims / name
            program.write_text('#!/bin/sh\ntouch ' + str(marker) + '\nexit 1\n')
            program.chmod(0o755)
        hooks = root / 'hooks'
        hooks.mkdir()
        hook = hooks / 'reference-transaction'
        hook.write_text('#!/bin/sh\ntouch ' + str(marker) + '\n')
        hook.chmod(0o755)
        settings = {'core.fsmonitor': str(shims / 'sh-evil'), 'core.hooksPath': str(hooks),
                    'core.pager': str(shims / 'sh-evil'), 'uploadpack.packObjectsHook': str(shims / 'sh-evil'),
                    'core.sshCommand': str(shims / 'sh-evil'), 'gpg.ssh.program': str(shims / 'ssh-keygen')}
        for name, value in settings.items():
            git(repo, 'config', name, value)
        config_path.write_text(json.dumps({k:v for k,v in config.items() if k != 'test_clock'}))
        for native in (False, True):
            done = invoke(native, home, repo, json.dumps(request).encode(), dict(
                PATH=str(shims) + ':' + env['PATH'], EVIDENCE_SIGN_NOW='1999-01-01T00:00:00Z',
                GIT_DIR=str(root / 'elsewhere'), GIT_CONFIG_COUNT='1',
                GIT_CONFIG_KEY_0='gpg.ssh.program', GIT_CONFIG_VALUE_0=str(shims / 'ssh-keygen')))
            packet = json.loads(good(done))
            statement = json.loads(git(scratch, 'show', packet['record'] + ':' + tree))
            assert statement['predicate']['observed_at'] != '1999-01-01T00:00:00Z'
            assert not marker.exists(), 'caller PATH, environment or checkout program ran'

    elif group in ('signing', 'signing-inf', 'signing-nan', 'signing-infinity', 'signing-surrogate'):
        lock = b'{"nodes":{},"root":"root","version":7}\n'
        (repo / 'flake.lock').write_bytes(lock)
        (repo / 'file.txt').write_text('committed source\n')
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'source')
        commit = git(repo, 'rev-parse', 'HEAD').decode().strip()
        tree = git(repo, 'rev-parse', 'HEAD^{tree}').decode().strip()
        # The signer must use the commit, not mutable checkout bytes.
        (repo / 'flake.lock').write_text('uncommitted hostile lock')
        (repo / 'file.txt').write_text('uncommitted source')
        check = 'inf' if group == 'signing-inf' else 'gate'
        request = dict(commit=commit, check=check, command=['printf', 'héllo', ''], exit_code=0,
                       output_sha256='b'*64, change_id='local:real-signature',
                       inputs=dict(flake_lock_sha256=hashlib.sha256(lock).hexdigest(), toolchain_sha256='d'*64,
                                   wrapper_sha256='e'*64, system='x86_64-linux', attempt='1', run_id='fixture'))
        if group == 'signing-nan':
            request['check'], check = float('nan'), 'NaN'
        elif group == 'signing-infinity':
            request['check'], check = float('inf'), 'Infinity'
        elif group == 'signing-surrogate':
            request['command'] = ['printf', '\ud800', '\udfff']
            request['change_id'] = 'surrogate:\ud800'
            request['inputs']['system'] = 'system:\udfff'
        allowed = root / 'allowed-signers'
        allowed.write_text('fleet/legacy-fixture namespaces="git" ' + key.with_suffix('.pub').read_text())
        untrusted = root / 'untrusted-signers'
        untrusted.write_text('')
        bodies = []
        for native in (False, True):
            # These inherited variables must not reach Git/OpenSSH. In particular,
            # LD_LIBRARY_PATH is accepted at entry and stripped for child tools.
            hostile = dict(LD_LIBRARY_PATH='/nonexistent-legacy-sign-library-path', GIT_DIR='/nonexistent-legacy-sign-repo',
                           GIT_SSH_COMMAND='/nonexistent-legacy-sign-ssh', GIT_CONFIG_COUNT='1',
                           GIT_CONFIG_KEY_0='gpg.ssh.program', GIT_CONFIG_VALUE_0='/nonexistent-legacy-sign-keygen')
            done = invoke(native, home, repo, json.dumps(request).encode(), hostile)
            packet = json.loads(good(done))
            assert done.stderr == b'', done.stderr
            assert set(packet) == {'record', 'tier', 'tree', 'commit', 'object_pack_base64'}, packet
            assert packet['tier'] == 'full' and packet['commit'] == commit and packet['tree'] == tree
            target = root / ('native-import' if native else 'python-import')
            init(target, bare=True)
            pack = base64.b64decode(packet['object_pack_base64'], validate=True)
            assert pack.startswith(b'PACK')
            git(target, 'index-pack', '--stdin', data=pack)
            record = packet['record']
            assert git(target, 'cat-file', '-t', record).strip() == b'commit'
            signed = git(target, 'cat-file', 'commit', record)
            assert b'\ngpgsig -----BEGIN SSH SIGNATURE-----\n' in signed
            assert signed.endswith(b'\nst gate observation v1\n'), signed
            assert git(target, 'rev-parse', record + '^').decode().strip() == commit
            assert git(target, 'rev-parse', commit + '^{tree}').decode().strip() == tree
            assert git(target, 'show', commit + ':flake.lock') == lock
            entries = git(target, 'ls-tree', record).decode().splitlines()
            assert len(entries) == 1 and entries[0].startswith('100644 blob ') and entries[0].endswith('\t' + tree), entries
            body = git(target, 'show', record + ':' + tree)
            statement = json.loads(body)
            assert statement['subject'] == [{'name': commit, 'digest': {'gitTree': tree}}]
            predicate = statement['predicate']
            assert predicate['observed_at'] == NOW and predicate['signer'] == config['signer']
            assert predicate['observed']['inputs'] == request['inputs']
            assert set(predicate['observed']['checks']) == {check}
            producer = hashlib.sha256(binary.read_bytes() if native else script.read_bytes()).hexdigest()
            assert predicate['producer_sha256'] == producer
            # This is the sole approved byte-parity exception. Compare the
            # original signed bytes, never a reserialized JSON approximation.
            assert body.count(producer.encode()) == 1
            bodies.append(body.replace(producer.encode(), b'0'*64))
            reachable = set(git(target, 'rev-list', '--objects', '--no-object-names', record).decode().splitlines())
            packed = {line.split()[0] for line in git(target, 'cat-file', '--batch-all-objects', '--batch-check=%(objectname)').decode().splitlines()}
            assert packed == reachable, (packed, reachable)
            git(target, 'update-ref', 'refs/notes/evidence/' + tree + '/' + record, record)
            # Both verifiers accept each pack, except the native typed verifier's
            # documented fail-closed refusal of lone-surrogate statement text.
            for verifier in ([sys.executable, '-I', '-B', oracle / 'scripts/evidence-verify', '--repo', target,
                              '--tree', tree, '--check', check, '--keys', allowed],
                             [binary, 'evidence', 'verify', '--repo', target, '--record', record, '--trusted-signers', allowed]):
                verified = run(verifier)
                if group == 'signing-surrogate' and verifier[0] == binary:
                    assert verified.returncode == 1 and verified.stdout == b'', (verified.returncode, verified.stdout, verified.stderr)
                    assert verified.stderr.startswith(b'decode evidence statement:'), verified.stderr
                    continue
                result = json.loads(good(verified))
                assert result['record'] == record, result
                if verifier[0] == binary:
                    assert result['subject_binding'] == 'verified', result
            rejected = run([binary, 'evidence', 'verify', '--repo', target, '--record', record, '--trusted-signers', untrusted])
            assert rejected.returncode != 0, rejected.stdout
        assert bodies[0] == bodies[1], (bodies[0], bodies[1])
    else:
        raise AssertionError(group)
"#;
