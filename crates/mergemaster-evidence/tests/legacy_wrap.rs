//! Real Git/OpenSSH replay against the independent, immutable v1 Python wrapper.
//! Only producer/wrapper executable digests differ in signed statement bytes.
#[path = "../src/pinned_python.rs"]
mod pinned_python;

fn replay(group: &str) {
    let oracle = std::env::var_os("MERGEMASTER_PYTHON_ORACLE")
        .expect("MERGEMASTER_PYTHON_ORACLE must name the independent pinned source");
    let output = pinned_python::command()
        .args(["-B", "-c", DRIVER])
        .arg(group)
        .arg(env!("CARGO_BIN_EXE_mergemaster"))
        .arg(oracle)
        .arg(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("launch legacy wrapper parity driver");
    assert!(
        output.status.success(),
        "{group}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

macro_rules! parity {
    ($($name:ident => $group:literal),+ $(,)?) => {$(
        #[test]
        fn $name() {
            replay($group);
        }
    )+};
}

parity! {
    measured_output_is_streamed_once_and_signed_bytes_cross_verify => "measure",
    command_stdout_is_a_reopenable_pipe => "pipe",
    absent_verifier_skips_local_verification_but_blocks_publication => "absent-verifier",
    failures_and_interrupted_children_keep_v1_statuses => "failure",
    extra_inputs_validate_before_signing => "inputs",
    input_files_are_read_after_execution_sorted_and_bounded => "input-file",
    source_input_records_publish_both_exact_indexes => "indexes",
    caller_environment_reaches_command_and_signer_scrubs_loader_variables => "environment",
    aggregate_canonical_output_out_packs_and_dirty_index_rules => "aggregate",
    push_token_is_environment_only_and_failure_still_publishes => "push",
    transient_push_refusals_retry_only_pending_refs_with_bound => "retry",
    isolated_transport_ignores_overrides_and_publishes_only_new_refs => "transport",
    publication_ignores_pushurl_and_rejects_untrusted_fetch_url => "pushurl",
    publication_transfers_subject_history_from_safe_checkout_alternates => "publication-history",
    shallow_publication_preserves_boundary_and_refuses_empty_destination => "publication-shallow",
    checkout_ref_cannot_override_signed_publication_record => "publication-ref-target",
    dirty_or_mutating_commands_never_sign => "dirty",
    aggregate_nix_runner_reaches_real_signer_validation => "nix",
    signer_clock_and_tool_execution_ignore_hostile_checkout_configuration => "security",
    signer_trusted_tool_paths_are_checked_end_to_end => "paths",
    signer_rejects_invalid_aggregate_requests => "validation",
    lane_definitions_compare_pinned_import_with_native_helper => "lanes",
    percrate_verification_is_scoped_and_untrusted_push_is_blocked => "percrate",
    hydrated_partial_history_signs_and_missing_history_never_transports => "partial",
    committed_golden_pack_still_cross_verifies => "golden",
    arbitrary_width_aggregate_exits_preserve_failure_and_cpython_status => "wide-status",
    nonstring_signer_bindings_use_the_python_mismatch_refusal => "answer-types",
    publication_credentials_never_reach_lane_or_signer => "credential-hardening",
    raw_and_basic_auth_tokens_are_redacted_at_all_diagnostic_sinks => "redaction",
    verifier_keys_are_private_exclusive_and_removed_on_every_path => "key-tempfile",
}

const DRIVER: &str = r#"
import base64, hashlib, importlib.machinery, importlib.util, json, os, pathlib, re, shlex, shutil, signal, subprocess, sys, tempfile

group, binary, oracle, manifest = sys.argv[1], pathlib.Path(sys.argv[2]).resolve(), pathlib.Path(sys.argv[3]).resolve(), pathlib.Path(sys.argv[4])
assert str(oracle).startswith('/nix/store/'), oracle
wrap_script, sign_script, verify_script = [oracle / 'scripts' / name for name in ('evidence-wrap', 'evidence-sign', 'evidence-verify')]
def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module
sign_module = load('pinned_sign_for_wrap_test', sign_script)
verify_module = load('pinned_verify_for_wrap_test', verify_script)
NOW = '2026-10-14T12:00:00Z'
env = {k: v for k, v in os.environ.items() if not k.startswith(('GIT_', 'LD_', 'DYLD_', 'PYTHON')) and k not in ('GLIBC_TUNABLES', 'GCONV_PATH', 'NLSPATH', 'EVIDENCE_SIGNER', 'EVIDENCE_PUSH_TOKEN')}
env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null', LC_ALL='C',
           GIT_AUTHOR_NAME='Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
           GIT_COMMITTER_NAME='Fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid',
           GIT_AUTHOR_DATE=NOW, GIT_COMMITTER_DATE=NOW)
os.environ.clear()
os.environ.update(env)
def run(argv, cwd=None, data=None, extra=None):
    return subprocess.run(list(map(str, argv)), cwd=cwd, input=data, capture_output=True,
                          env=dict(env, **(extra or {})), timeout=600)
def good(done):
    assert done.returncode == 0, (done.args, done.returncode, done.stdout, done.stderr)
    return done.stdout
def git(repo, *args, data=None, extra=None):
    return good(run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-C', repo, *args], data=data, extra=extra))
def text(repo, *args):
    return git(repo, *args).decode().strip()
def init(repo, bare=False):
    good(run(['git', 'init', '-q', *(['--bare'] if bare else []), repo]))
    git(repo, 'config', 'gc.auto', '0')
    git(repo, 'config', 'maintenance.auto', 'false')
def refs(repo):
    return git(repo, 'for-each-ref', '--format=%(refname) %(objectname)', 'refs/notes/evidence', 'refs/notes/evidence-input', 'refs/tags/evidence')
def sha(data):
    return hashlib.sha256(data).hexdigest()
def executable(path, body):
    path.write_text(body)
    path.chmod(0o755)
    return path

# Runtime fixtures live under the checkout's ignored task scratch directory, not /tmp.
scratch_root = manifest / '../../tmp/legacy-wrap-parity'
scratch_root.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(dir=scratch_root) as directory:
    root = pathlib.Path(directory).resolve()
    home, repo = root / 'home', root / 'repo'
    home.mkdir()
    init(repo)
    tools = []
    for name in ('git', 'ssh-keygen'):
        for directory in env['PATH'].split(os.pathsep):
            if 'recorder' in directory:
                continue
            found = shutil.which(name, path=directory)
            if found:
                real = pathlib.Path(found).resolve()
                if sign_module.unsafe_directory(directory) is None and sign_module.unsafe_directory(str(real.parent)) is None and sign_module.unsafe_file(str(real)) is None:
                    tools.append(directory)
                    break
        else:
            raise AssertionError('fixture requires a trusted real ' + name)
    tool_path = ':'.join(dict.fromkeys(tools))
    real_git = shutil.which('git', path=tool_path)
    key = root / 'key'
    good(run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key]))
    allowed = root / 'allowed'
    allowed.write_text('fleet/dev namespaces="git" ' + key.with_suffix('.pub').read_text())
    config = home / '.config/st/evidence-sign.json'
    config.parent.mkdir(parents=True)
    signer_config = dict(signer='fleet/dev', ssh_key=str(key), scratch_repo=str(root / 'scratch.git'), path=tool_path, test_clock=True)
    config.write_text(json.dumps(signer_config))
    (repo / 'flake.lock').write_text('{"nodes":{}}\n')
    (repo / 'a').write_text('one\n')
    (repo / '.st').mkdir()
    (repo / '.st/evidence-keys').write_text(allowed.read_text())
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'base')
    git(repo, 'update-ref', 'refs/remotes/origin/main', 'HEAD')
    commit, tree = text(repo, 'rev-parse', 'HEAD'), text(repo, 'rev-parse', 'HEAD^{tree}')
    toolchain = sha(b'drv')
    native_sign = [str(binary), 'evidence', 'legacy-sign']
    python_sign = [sys.executable, '-I', '-B', str(sign_script)]
    def invoke(native, command=None, flags=(), extra=None, check='linux-gate', signer=None, cwd=None, streaming=None):
        argv = [binary, 'evidence', 'legacy-wrap'] if native else [sys.executable, '-I', '-B', wrap_script]
        argv += ['--check', check, '--toolchain-sha256', toolchain, '--signer', json.dumps(signer if signer is not None else native_sign if native else python_sign),
                 '--verifier', str(binary if native else verify_script), '--change-id', 'github:example/repo#5', *flags]
        if command is not None:
            argv += ['--', *command]
        child_env = dict(env, HOME=str(home), TMPDIR=str(root), EVIDENCE_SIGN_NOW=NOW)
        child_env.update(extra or {})
        if streaming is None:
            return run(argv, cwd=cwd or repo, extra=child_env)
        import selectors
        process = subprocess.Popen(list(map(str, argv)), cwd=cwd or repo, env=child_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                assert ready.select(timeout=30), 'wrapper buffered output until command completion'
            first = process.stdout.readline()
            assert first == b'ready\n', first
            with streaming.open('w') as ack:
                ack.write('continue\n')
            stdout, stderr = process.communicate(timeout=300)
            return subprocess.CompletedProcess(argv, process.returncode, first + stdout, stderr)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
    def result(done):
        stderr = done.stderr.decode()
        start = stderr.find('{')
        assert start >= 0, (done.returncode, done.stdout, done.stderr)
        value = json.loads(stderr[start:])
        assert isinstance(value, dict), value
        return value
    def body(record, source=repo):
        entries = text(source, 'ls-tree', record).splitlines()
        assert len(entries) == 1 and entries[0].endswith('\t' + tree), entries
        return git(source, 'show', record + ':' + tree)
    def inspect(native, done, expected_code=0, out=None, successful_verification=True):
        assert done.returncode == expected_code, (done.args, expected_code, done.returncode, done.stdout, done.stderr)
        value = result(done)
        record = value['record']
        if out is None:
            assert set(value) == {'record', 'ref', 'tag', 'tree', 'check', 'exit_code', 'verified', 'pushed'} | ({'verification'} if 'verification' in value else set()), value
            assert value['ref'] == f'refs/notes/evidence/{tree}/{record}'
            assert value['tag'] == f'refs/tags/evidence/{tree}/{record}'
            assert text(repo, 'rev-parse', value['ref']) == record
            assert text(repo, 'rev-parse', value['tag']) == record
            if expected_code == 0 and successful_verification:
                assert value['verified'] is True, value
            raw = body(record)
        else:
            assert set(value) == {'record', 'check', 'tree', 'commit', 'tier', 'exit_code'}, value
            assert value['commit'] == commit and value['tier'] == 'full'
            assert sorted(p.name for p in out.iterdir()) == [record + '.json', record + '.pack']
            assert json.loads((out / (record + '.json')).read_bytes()) == value
            imported = root / ('native-out-import' if native else 'python-out-import')
            init(imported, bare=True)
            git(imported, 'index-pack', '--stdin', data=(out / (record + '.pack')).read_bytes())
            assert refs(repo).find(record.encode()) == -1, 'out imported a ref'
            raw = body(record, imported)
        statement = json.loads(raw)
        predicate = statement['predicate']
        assert statement['subject'] == [{'name': commit, 'digest': {'gitTree': tree}}]
        assert statement['predicateType'] == 'https://compounding.tech/fractal/evidence/gate/v1'
        assert predicate['observed_at'] == NOW and predicate['change_id'] == 'github:example/repo#5'
        assert predicate['tier'] == 'full' and predicate['signer'] == 'fleet/dev'
        inputs = predicate['observed']['inputs']
        producer = sha(binary.read_bytes() if native else sign_script.read_bytes())
        wrapper = sha(binary.read_bytes() if native else wrap_script.read_bytes())
        assert predicate['producer_sha256'] == producer
        assert inputs['wrapper_sha256'] == wrapper
        assert inputs['flake_lock_sha256'] == sha(b'{"nodes":{}}\n')
        assert inputs['toolchain_sha256'] == toolchain
        assert raw.count(producer.encode()) >= 1 and raw.count(wrapper.encode()) >= 1
        normalized = raw.replace(producer.encode(), b'0' * 64).replace(wrapper.encode(), b'0' * 64)
        source = repo if out is None else imported
        git(source, '-c', 'gpg.format=ssh', '-c', 'gpg.ssh.program=' + str(shutil.which('ssh-keygen', path=tool_path)), '-c', 'gpg.ssh.allowedSignersFile=' + str(allowed), 'verify-commit', record)
        # Isolate discovery: equal-clock records (especially another crate's
        # failure) must not decide this artifact's independent cross-check.
        isolated = root / ('cross-' + record)
        init(isolated, bare=True)
        pack = git(source, 'pack-objects', '--stdout', '--revs', data=(record + '\n').encode())
        git(isolated, 'index-pack', '--stdin', data=pack)
        git(isolated, 'update-ref', f'refs/notes/evidence/{tree}/{record}', record)
        source = isolated
        for verifier in ([sys.executable, '-I', '-B', verify_script, '--repo', source, '--tree', tree, '--check', value['check'], '--keys', allowed],
                         [binary, 'evidence', 'verify', '--repo', source, '--record', record, '--trusted-signers', allowed]):
            checked = run(verifier)
            # The generic native verifier authenticates the record, including a
            # failure; the legacy verifier additionally judges check success.
            if expected_code == 0 or verifier[0] == binary:
                good(checked)
                assert json.loads(checked.stdout)['record'] == record, checked.stdout
            else:
                assert checked.returncode != 0, checked.stdout
        return value, statement, normalized
    def pair(command=None, flags=(), code=0, extra=None, check='linux-gate', verify=True):
        values = []
        for native in (False, True):
            done = invoke(native, command, flags, extra, check)
            value, statement, raw = inspect(native, done, code, successful_verification=verify)
            values.append((done, value, statement, raw))
        assert values[0][0].stdout == values[1][0].stdout
        assert values[0][3] == values[1][3], (values[0][3], values[1][3])
        # Record/ref/tag addresses necessarily derive from the two approved digest
        # differences. Check their exact shapes above, not a broader JSON scrub.
        for done, value, _, _ in values:
            assert value['tree'] == tree and value['check'] == check
            assert value['exit_code'] == code
        left, right = values
        if verify:
            assert left[0].stderr.replace(left[1]['record'].encode(), b'RECORD') == right[0].stderr.replace(right[1]['record'].encode(), b'RECORD'), (left[0].stderr, right[0].stderr)
        return values
    def refused(command=None, flags=(), contains=b'', extra=None, signer=None, check='linux-gate', code=1):
        before = refs(repo)
        for native in (False, True):
            done = invoke(native, command, flags, extra, check, signer)
            assert done.returncode == code and contains in done.stderr, (native, done.returncode, done.stdout, done.stderr, contains)
            assert refs(repo) == before, 'refusal published evidence'
        return done
    def observed(values):
        return values[0][2]['predicate']['observed']
    def aggregate(facts, flags=(), code=0, check='linux-gate'):
        path = root / 'facts.json'
        path.write_text(json.dumps(facts))
        return pair(flags=['--aggregate', str(path), *flags], code=code, check=check)

    if group == 'wide-status':
        # Mergemaster measured CPython 3.14.10 sys.exit: signed-i64 overflow
        # becomes -1 (POSIX 255), otherwise the low eight bits are returned.
        cases = [(9223372036854775808, 255), (18446744073709551616, 255),
                 (4294967296, 0), (256, 0), (-1, 255), (9223372036854775807, 255),
                 (-256, 0), (-9223372036854775809, 255)]
        stage = root / 'wide-facts.json'
        for index, (integer, status) in enumerate(cases):
            stage.write_text(json.dumps(dict(command=['aggregate'], exit_code=integer, output='wide')))
            for native in (False, True):
                out = root / f'wide-out-{index}-{native}'
                done = invoke(native, flags=['--aggregate', str(stage), '--out', str(out)])
                assert done.returncode == status, (integer, native, status, done.returncode, done.stderr)
                packet = result(done)
                assert packet['exit_code'] == integer
                assert (out / (packet['record'] + '.pack')).read_bytes().startswith(b'PACK')
                assert json.loads((out / (packet['record'] + '.json')).read_bytes()) == packet
        stage.write_text(json.dumps(dict(command=['aggregate'], exit_code=4294967296, output='failure')))
        sink = root / 'wide-sink.git'
        init(sink, bare=True)
        git(repo, 'remote', 'add', 'wide-sink', str(sink))
        marker = root / 'wrongly-verified'
        verifier = executable(root / 'must-not-verify', '#!/bin/sh\ntouch ' + shlex.quote(str(marker)) + '\nexit 1\n')
        for native in (False, True):
            done = invoke(native, flags=['--aggregate', str(stage), '--push', str(sink), '--verifier', str(verifier)])
            assert done.returncode == 0, (native, done.stderr)
            packet = result(done)
            assert packet['exit_code'] == 4294967296 and packet['verified'] is False and packet['pushed'] is True, packet
            assert text(sink, 'rev-parse', packet['ref']) == packet['record']
            assert not marker.exists()
    elif group == 'answer-types':
        for field in ('commit', 'tree', 'tier'):
            for value in (None, 7):
                code = ('import json,sys; r=json.load(sys.stdin); '
                        "a=dict(record='a'*40,commit=r['commit'],tree=" + repr(tree) + ",tier='full'); "
                        'a[' + repr(field) + ']=' + repr(value) + '; print(json.dumps(a))')
                refused(['true'], signer=[sys.executable, '-I', '-c', code],
                        contains=b'the signer answered for a different commit, tree or tier')
    elif group == 'credential-hardening':
        lane_dump, signer_dump = root / 'lane-env.json', root / 'signer-env.json'
        def dump_code(path):
            return 'import os,json,pathlib; pathlib.Path(' + repr(str(path)) + ').write_text(json.dumps(dict(os.environ)))'
        signer = [sys.executable, '-I', '-c', 'import sys; sys.stdin.buffer.read(); ' + dump_code(signer_dump) + '; sys.exit(7)']
        done = invoke(True, [sys.executable, '-I', '-c', dump_code(lane_dump)], signer=signer,
                      extra=dict(EVIDENCE_PUSH_TOKEN='secret-token-xyz', EVIDENCE_SIGNER='private-signer-command', WRAP_CUSTOM_ENV='preserved',
                                 GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.extraheader', GIT_CONFIG_VALUE_0='caller-secret',
                                 GIT_CONFIG_GLOBAL=str(root / 'private-config'), GIT_CONFIG_PARAMETERS="'http.extraheader=caller-secret'"))
        assert done.returncode == 1 and b'the signer refused' in done.stderr, done.stderr
        for path in (lane_dump, signer_dump):
            seen = json.loads(path.read_bytes())
            assert 'EVIDENCE_PUSH_TOKEN' not in seen and 'EVIDENCE_SIGNER' not in seen, path
            assert not any(key.startswith('GIT_CONFIG_') for key in seen), seen
            assert seen['WRAP_CUSTOM_ENV'] == 'preserved'
    elif group == 'redaction':
        token = 'secret-token-xyz'
        header = base64.b64encode(('x-access-token:' + token).encode()).decode()
        message = token + ' Authorization: Basic ' + header
        extra = dict(EVIDENCE_PUSH_TOKEN=token)
        def redacted(done, status):
            assert done.returncode == status, (done.returncode, done.stdout, done.stderr)
            assert token.encode() not in done.stderr and header.encode() not in done.stderr, done.stderr
            assert b'***' in done.stderr, done.stderr
        signer = [sys.executable, '-I', '-c', 'import sys; sys.stdin.buffer.read(); print(' + repr(message) + ',file=sys.stderr); sys.exit(7)']
        redacted(invoke(True, ['true'], signer=signer, extra=extra), 1)
        verifier = executable(root / 'echo-header-verifier', '#!/bin/sh\nprintf "%s\\n" ' + shlex.quote(message) + '\nexit 1\n')
        checked = invoke(True, ['true'], flags=['--verifier', str(verifier)], extra=extra)
        redacted(checked, 0)
        assert result(checked)['verified'] is False
        shim = root / 'redacting-git'
        shim.mkdir()
        extra['PATH'] = str(shim) + ':' + env['PATH']
        executable(shim / 'git', '#!/bin/sh\ncase " $* " in *" status "*) printf "%s\\n" ' + shlex.quote(message) + ' >&2; exit 1;; esac\nexec ' + shlex.quote(real_git) + ' "$@"\n')
        redacted(invoke(True, ['true'], extra=extra), 1)
        executable(shim / 'git', '#!/bin/sh\ncase " $* " in *" push "*) printf "%s %s\\n" "$EVIDENCE_PUSH_TOKEN" "$GIT_CONFIG_VALUE_0" >&2; exit 1;; esac\nexec ' + shlex.quote(real_git) + ' "$@"\n')
        redacted(invoke(True, ['sh', '-c', 'exit 3'], flags=['--push', 'https://github.com/example/repo.git'], extra=extra), 1)
    elif group == 'key-tempfile':
        log = root / 'key-file.json'
        verifier = root / 'inspect-key-file'
        for status in (0, 1):
            code = ('import json,pathlib,stat,sys; p=pathlib.Path(sys.argv[sys.argv.index("--keys")+1]); '
                    'pathlib.Path(' + repr(str(log)) + ').write_text(json.dumps(dict(path=str(p),mode=stat.S_IMODE(p.stat().st_mode),content=p.read_text()))); '
                    'sys.exit(' + str(status) + ')')
            executable(verifier, '#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' -I -c ' + shlex.quote(code) + ' "$@"\n')
            done = invoke(True, ['true'], flags=['--verifier', str(verifier)])
            good(done)
            seen = json.loads(log.read_bytes())
            assert seen['mode'] == 0o600 and seen['content'] == allowed.read_text(), seen
            assert not pathlib.Path(seen['path']).exists()
            assert not list(root.glob('evidence-keys-*'))
        verifier.chmod(0o644)
        done = invoke(True, ['true'], flags=['--verifier', str(verifier)])
        assert done.returncode == 1, done.stderr
        assert not list(root.glob('evidence-keys-*'))
    elif group == 'measure':
        marker = root / 'executions'
        command = ['sh', '-c', 'printf x >> ' + shlex.quote(str(marker)) + '; printf "built\\n"; printf "tested\\n" >&2']
        values = pair(command)
        check = observed(values)['checks']['linux-gate']
        assert check == dict(command=command, exit_code=0, output_sha256=sha(b'built\ntested\n')), check
        assert values[0][0].stdout == b'built\ntested\n' and marker.read_bytes() == b'xx'
        assert observed(values)['runner'] == 'wrapper'
        assert observed(values)['inputs']['attempt'] == '1'
        pair(['printf', '\u00e9\U0001f680'])
        pair(['sh', '-c', 'head -c 131073 /dev/zero'])
        pair(['true'], ['--keys-from', commit])
        fifo = root / 'ack'
        os.mkfifo(fifo)
        command = ['sh', '-c', 'printf "ready\\n"; read ack < ' + shlex.quote(str(fifo)) + '; printf "finished\\n"']
        streaming_bodies = []
        for native in (False, True):
            done = invoke(native, command, streaming=fifo)
            _, statement, raw = inspect(native, done)
            assert done.stdout == b'ready\nfinished\n'
            assert statement['predicate']['observed']['checks']['linux-gate']['output_sha256'] == sha(done.stdout)
            streaming_bodies.append(raw)
        assert streaming_bodies[0] == streaming_bodies[1]
    elif group == 'pipe':
        values = pair(['sh', '-c', 'echo hi > /dev/stdout; echo err > /dev/stderr'])
        assert values[0][0].stdout == b'hi\nerr\n'
        assert observed(values)['checks']['linux-gate']['output_sha256'] == sha(b'hi\nerr\n')
    elif group == 'absent-verifier':
        flags = ['--verifier', str(root / 'missing-verifier'), '--keys-from', 'no-such-base']
        values = []
        for native in (False, True):
            done = invoke(native, ['true'], flags)
            value, _, raw = inspect(native, done, successful_verification=False)
            assert value['verified'] is False and value['pushed'] is False
            assert 'verification' not in value
            values.append((done, value, raw))
        assert values[0][2] == values[1][2]
        assert values[0][0].stderr.replace(values[0][1]['record'].encode(), b'RECORD') == values[1][0].stderr.replace(values[1][1]['record'].encode(), b'RECORD')
        for native in (False, True):
            done = invoke(native, ['true'], [*flags, '--push', 'no-such-remote'])
            assert done.returncode == 1 and b'not pushing: the note did not verify locally' in done.stderr, done.stderr
    elif group == 'failure':
        values = pair(['sh', '-c', 'echo broken; exit 3'], code=3)
        assert observed(values)['checks']['linux-gate']['output_sha256'] == sha(b'broken\n')
        for signum in (signal.SIGTERM, signal.SIGINT):
            # Popen.wait() returns -signal; v1 records it and shell exit wraps it.
            interrupted = []
            for native in (False, True):
                done = invoke(native, ['sh', '-c', f'kill -{int(signum)} $$'])
                value, statement, raw = inspect(native, done, expected_code=256-int(signum))
                assert value['exit_code'] == -int(signum)
                assert statement['predicate']['observed']['checks']['linux-gate']['exit_code'] == -int(signum)
                interrupted.append(raw)
            assert interrupted[0] == interrupted[1]
        refused(['true'], signer=['no-such-legacy-wrap-signer'], contains=b'is not on PATH')
        refusing = executable(root / 'refusing-signer', '#!/bin/sh\nexit 7\n')
        refused(['true'], signer=[str(refusing)], contains=b'the signer refused')
    elif group == 'inputs':
        values = pair(['true'], ['--input', 'clippy_base_sha=' + 'b' * 40, '--attempt', '2'])
        assert observed(values)['inputs']['clippy_base_sha'] == 'b' * 40
        assert observed(values)['inputs']['attempt'] == '2'
        for bad in ('attempt=9', 'lane_definition_sha256=x', 'workspace_clean=true', 'Clippy=1', 'clippy_base_sha', 'clippy_base_sha=', '=x', '1x=2'):
            refused(['true'], ['--input', bad], b'--input')
        refused(['true'], ['--input', 'x=1', '--input', 'x=2'], b'--input')
    elif group == 'input-file':
        path = root / 'skips'
        command = ['sh', '-c', 'printf "b-crate two\\na-crate one\\n\\nb-crate two\\n" > ' + shlex.quote(str(path))]
        values = pair(command, ['--input-file', 'env_skips=' + str(path)])
        assert observed(values)['inputs']['env_skips'] == 'a-crate one,b-crate two'
        for contents in (None, ''):
            if path.exists(): path.unlink()
            if contents is not None: path.write_text(contents)
            values = pair(['true'], ['--input-file', 'env_skips=' + str(path)])
            assert observed(values)['inputs']['env_skips'] == 'none'
        entries = ['crate-%04d test' % i for i in range(100)]
        path.write_text('\n'.join(reversed(entries)) + '\n' + entries[0])
        values = pair(['true'], ['--input-file', 'env_skips=' + str(path)])
        joined = ','.join(entries)
        assert observed(values)['inputs']['env_skips'] == f'100 entries, sha256 {sha(joined.encode())}'
        for bad in ('attempt=' + str(path), 'env_skips=', 'Env=' + str(path), '=' + str(path)):
            refused(['true'], ['--input-file', bad], b'--input-file')
        refused(['true'], ['--input', 'env_skips=none', '--input-file', 'env_skips=' + str(path)], b'--input-file')
        refused(['true'], ['--input-file', 'env_skips=' + str(path)] * 2, b'--input-file')
        facts = root / 'facts.json'
        facts.write_text('{}')
        refused(flags=['--aggregate', str(facts), '--input-file', 'env_skips=' + str(path)], contains=b'--input-file')
    elif group == 'indexes':
        values = pair(['true'], ['--input', 'source_inputs=' + tree, '--input', 'crate=demo'])
        for _, value, _, _ in values:
            record = value['record']
            expected = [f'refs/notes/evidence-input/linux-gate/{tree}/{record}', f'refs/tags/evidence/input/linux-gate/{tree}/{record}']
            for ref in expected:
                assert text(repo, 'rev-parse', ref) == record
        assert git(repo, 'for-each-ref', 'refs/notes/evidence-input/linux-gate/' + 'f' * 40) == b''
        refused(['true'], ['--input', 'source_inputs=not-a-tree'], b'source_inputs')
    elif group == 'environment':
        hostile = dict(LD_PRELOAD='/nonexistent/libpreload.so', LD_AUDIT='/nonexistent/libaudit.so', LD_LIBRARY_PATH='/nonexistent/library',
                       GLIBC_TUNABLES='glibc.malloc.check=3', PYTHONPATH='/nonexistent/python', PYTHONSTARTUP='/nonexistent/startup.py',
                       DYLD_INSERT_LIBRARIES='/x.dylib', GCONV_PATH='/nonexistent/gconv', NLSPATH='/nonexistent/nls')
        seen = root / 'command-env'
        pair(['sh', '-c', 'env > ' + shlex.quote(str(seen))], extra=hostile)
        assert 'LD_PRELOAD=/nonexistent/libpreload.so' in seen.read_text().splitlines()
        shim = root / 'stub-bin'
        shim.mkdir()
        dump, argv0 = root / 'signer-env', root / 'signer-argv0'
        # The signer's fixed PATH has no utilities inside the Nix sandbox.
        env_tool = shutil.which('env', path=env['PATH'])
        assert env_tool is not None
        executable(shim / 'stub-signer', '#!/bin/sh\n' + shlex.quote(env_tool) + ' > ' + shlex.quote(str(dump)) + '\nprintf "%s" "$0" > ' + shlex.quote(str(argv0)) + '\nexit 7\n')
        refused(['true'], extra=dict(hostile, PATH=str(shim) + ':' + env['PATH']), signer=['stub-signer'], contains=b'the signer refused')
        reached = dict(line.split('=', 1) for line in dump.read_text().splitlines() if '=' in line)
        assert not [name for name in reached if name.startswith(('LD_', 'DYLD_', 'PYTHON')) or name in ('GLIBC_TUNABLES', 'GCONV_PATH', 'NLSPATH')]
        assert reached['PATH'] == '/run/current-system/sw/bin:/usr/bin:/bin' and reached['HOME'] == str(home)
        assert argv0.read_text() == str(shim / 'stub-signer')
        for native in (False, True):
            done = run(native_sign if native else python_sign, data=b'{}', extra=dict(HOME=str(home), LD_PRELOAD='/nonexistent/library.so'))
            assert done.returncode == 1 and b'refusing to run with LD_PRELOAD set' in done.stderr
    elif group == 'aggregate':
        facts = dict(command=['linux-gate', 'aggregate', 'a', 'b'], exit_code=0, output=dict(verdict='success', needs=dict(b='success', a='success')), inputs=dict(run_id='42', event_name='merge_group'))
        values = aggregate(facts)
        check = observed(values)['checks']['linux-gate']
        assert check == dict(command=facts['command'], exit_code=0, output_sha256=sha(json.dumps(facts['output'], sort_keys=True, separators=(',', ':')).encode()))
        assert observed(values)['inputs']['run_id'] == '42'
        for extra in ([], [['run_id', '42']], ['xy'], '', [{'a': 0, 'b': 1}], [[True, 'x'], [1, 'y']]):
            aggregate(dict(facts, inputs=extra))
        invalid_inputs = root / 'invalid-inputs.json'
        invalid_inputs.write_text(json.dumps(dict(facts, inputs=[['run_id']])))
        refused(flags=['--aggregate', str(invalid_inputs)], contains=b'dictionary update sequence element #0 has length 1; 2 is required')
        stage = root / 'stage.json'
        stage.write_text(json.dumps(dict(command=['bash', 'scripts/ci-linux', 'tests'], exit_code=0, output_sha256=sha(b'the log'), inputs=dict(stage='tests'))))
        (repo / 'untracked-build-output').write_text('x')
        artifacts = []
        for native in (False, True):
            out = root / ('native-out' if native else 'python-out')
            done = invoke(native, flags=['--aggregate', str(stage), '--out', str(out)], check='linux-tests')
            _, statement, raw = inspect(native, done, out=out)
            inputs = statement['predicate']['observed']['inputs']
            assert inputs['workspace_clean'] == 'true' and inputs['untracked_files'] == 'true' and inputs['stage'] == 'tests'
            artifacts.append(raw)
        assert artifacts[0] == artifacts[1]
        (repo / 'a').write_text('tracked change\n')
        refused(flags=['--aggregate', str(stage), '--out', str(root / 'refused-out')], contains=b'tracked files differ')
        assert not (root / 'refused-out').exists()
        git(repo, 'checkout', '--', 'a')
        for flag, undo in (('--assume-unchanged', '--no-assume-unchanged'), ('--skip-worktree', '--no-skip-worktree')):
            (repo / 'a').write_text('hidden change\n')
            git(repo, 'update-index', flag, 'a')
            refused(flags=['--aggregate', str(stage), '--out', str(root / 'hidden-out')], contains=b'hide changes')
            assert not (root / 'hidden-out').exists()
            git(repo, 'update-index', undo, 'a')
            git(repo, 'checkout', '--', 'a')
        (repo / 'untracked-build-output').unlink()
        for bad in (dict(command=['x'], exit_code=0, output=1, output_sha256='a'*64), dict(command=['x'], exit_code=0, output=1, tier='full'), dict(command=['x'], exit_code=0)):
            stage.write_text(json.dumps(bad))
            refused(flags=['--aggregate', str(stage)], contains=b'--aggregate')
    elif group == 'publication-history':
        parent = commit
        (repo / 'a').write_text('two\n')
        git(repo, 'commit', '-qam', 'subject with history')
        commit, tree = text(repo, 'rev-parse', 'HEAD'), text(repo, 'rev-parse', 'HEAD^{tree}')
        for hostile in (False, True):
            sink = root / ('history-hostile.git' if hostile else 'history-empty.git')
            init(sink, bare=True)
            assert run(['git', '-C', sink, 'cat-file', '-e', commit]).returncode != 0
            if hostile:
                donor = root / 'alternate.git'
                init(donor, bare=True)
                objects = repo / '.git/objects'
                for entry in list(objects.iterdir()):
                    if entry.name != 'info':
                        target = donor / 'objects' / entry.name
                        if target.exists():
                            shutil.rmtree(target)
                        shutil.move(str(entry), target)
                (objects / 'info/alternates').write_text(str(donor / 'objects') + '\n')
                unrelated = root / 'mismatched-graph.git'
                init(unrelated, bare=True)
                empty_tree = git(unrelated, 'mktree', data=b'').decode().strip()
                unrelated_commit = git(unrelated, 'commit-tree', empty_tree, data=b'unrelated graph\n').decode().strip()
                git(unrelated, 'update-ref', 'refs/heads/unrelated', unrelated_commit)
                git(unrelated, 'commit-graph', 'write', '--reachable')
                shutil.copyfile(unrelated / 'objects/info/commit-graph', donor / 'objects/info/commit-graph')
                (donor / 'objects/info/alternates').write_text(str(unrelated / 'objects') + '\n')
                marker = root / 'alternate-config-or-hook-executed'
                hooks = donor / 'hooks'
                executable(hooks / 'pre-push', '#!/bin/sh\ntouch ' + shlex.quote(str(marker)) + '\n')
                included = root / 'alternate-hostile.config'
                included.write_text('[url "ext::touch ' + str(marker) + '"]\n insteadOf = ' + str(sink) + '\n')
                for repository in (repo, donor):
                    for name, value in [('core.hooksPath', str(hooks)), ('core.sshCommand', 'touch ' + str(marker)),
                                        ('include.path', str(included)), ('credential.helper', '!touch ' + str(marker)),
                                        ('url.ext::touch ' + str(marker) + '.insteadOf', str(sink)),
                                        ('http.extraheader', 'checkout-secret')]:
                        git(repository, 'config', name, value)
            done = invoke(True, ['sh', '-c', 'exit 3'], ['--push', str(sink), '--attempt', '2' if hostile else '1'])
            assert done.returncode == 3 and result(done)['pushed'], done.stderr
            value = result(done)
            assert text(sink, 'rev-parse', value['ref'] + '^') == commit
            assert text(sink, 'rev-parse', commit + '^') == parent
            assert text(sink, 'cat-file', '-t', parent) == 'commit'
            assert text(sink, 'rev-parse', value['tag']) == value['record']
            metadata_off = ['-c', 'core.commitGraph=false', '-c', 'core.multiPackIndex=false',
                            '-c', 'pack.useBitmaps=false', '-c', 'pack.useBitmapBoundaryTraversal=false']
            expected_objects = set(text(repo, *metadata_off, 'rev-list', '--objects', '--no-object-names', value['record']).splitlines())
            received_objects = set(text(sink, *metadata_off, 'cat-file', '--batch-all-objects', '--batch-check=%(objectname)').splitlines())
            assert received_objects == expected_objects, (received_objects - expected_objects, expected_objects - received_objects)
            if hostile:
                assert not marker.exists()
    elif group == 'publication-ref-target':
        sink = root / 'ref-target.git'
        init(sink, bare=True)
        unrelated_tree = git(repo, 'mktree', data=b'').decode().strip()
        unrelated = git(repo, 'commit-tree', unrelated_tree, data=b'unrelated checkout object\n').decode().strip()
        proxy = ('import json,subprocess,sys; '
                 'r=subprocess.run(' + repr(native_sign) + ',input=sys.stdin.buffer.read(),capture_output=True); '
                 'r.check_returncode(); answer=json.loads(r.stdout); '
                 'ref="refs/tags/evidence/"+answer["tree"]+"/"+answer["record"]; '
                 'subprocess.run(' + repr([real_git, '-c', 'core.hooksPath=/dev/null', '-C', str(repo), 'update-ref']) +
                 '+[ref,' + repr(unrelated) + '],check=True); sys.stdout.buffer.write(r.stdout)')
        done = invoke(True, ['sh', '-c', 'exit 3'], ['--push', str(sink)],
                      signer=[sys.executable, '-I', '-c', proxy])
        assert done.returncode == 1 and b'checkout publication ref' in done.stderr, done.stderr
        assert b'not signed record' in done.stderr, done.stderr
        assert unrelated.encode() in done.stderr
        assert refs(sink) == b''
        assert run(['git', '-C', sink, 'cat-file', '-e', unrelated]).returncode != 0
    elif group == 'publication-shallow':
        (repo / 'a').write_text('two\n')
        git(repo, 'commit', '-qam', 'subject boundary')
        commit, tree = text(repo, 'rev-parse', 'HEAD'), text(repo, 'rev-parse', 'HEAD^{tree}')
        checkout = root / 'depth-one'
        good(run(['git', 'clone', '--depth=1', repo.as_uri(), checkout]))
        git(checkout, 'update-ref', 'refs/remotes/origin/main', 'HEAD')
        assert text(checkout, 'rev-parse', '--is-shallow-repository') == 'true'
        for seeded in (True, False):
            sink = root / ('boundary-present.git' if seeded else 'boundary-absent.git')
            init(sink, bare=True)
            if seeded:
                # The destination knows the record's parent: the subject boundary.
                git(repo, 'push', str(sink), commit + ':refs/heads/main')
            done = invoke(True, ['sh', '-c', 'exit 3'], ['--push', str(sink)], cwd=checkout)
            if seeded:
                assert done.returncode == 3 and result(done)['pushed'], done.stderr
                assert text(sink, 'rev-parse', result(done)['ref'] + '^') == commit
            else:
                assert done.returncode == 1, done.stderr
                assert b'publication requires complete checkout history' in done.stderr, done.stderr
                assert b'shallow update not allowed' in done.stderr, done.stderr
                assert refs(sink) == b''
    elif group in ('push', 'retry', 'transport', 'pushurl'):
        sink = root / 'sink.git'
        init(sink, bare=True)
        git(repo, 'remote', 'add', 'sink', str(sink))
        shim = root / 'git-shim'
        shim.mkdir()
        log = root / 'git-log'
        if group == 'push':
            executable(shim / 'git', '#!' + sys.executable + '\nimport os,sys\na=sys.argv[1:]\nwith open(' + repr(str(log)) + ',"a") as f:\n f.write("ARGV "+" ".join(a)+"\\n")\n f.write("ENV "+os.environ.get("GIT_CONFIG_VALUE_0","")+"\\n")\n if "push" in a:\n  f.write("KEY "+os.environ.get("GIT_CONFIG_KEY_0","")+"\\n")\n  f.write("TOKEN "+os.environ.get("EVIDENCE_PUSH_TOKEN","")+"\\n")\nif "push" in a: a[a.index("push")+2]=' + repr(str(sink)) + '\nos.execv(' + repr(real_git) + ',["git",*a])\n')
            values = pair(['sh', '-c', 'exit 3'], ['--push', 'https://github.com/example/repo.git'], code=3, extra=dict(EVIDENCE_PUSH_TOKEN='secret-token-xyz', PATH=str(shim) + ':' + env['PATH']))
            header = base64.b64encode(b'x-access-token:secret-token-xyz').decode()
            lines = log.read_text().splitlines()
            assert any(header in line for line in lines if line.startswith('ENV '))
            assert not any('secret-token-xyz' in line or header in line for line in lines if line.startswith('ARGV '))
            for done, value, _, _ in values:
                assert value['pushed'] is True and b'secret-token-xyz' not in done.stderr and header.encode() not in done.stderr
                for ref in (value['ref'], value['tag']):
                    assert text(sink, 'rev-parse', ref) == value['record']
            expected = {value[name] + ' ' + value['record'] for _, value, _, _ in values for name in ('ref', 'tag')}
            assert set(text(sink, 'for-each-ref', '--format=%(refname) %(objectname)').splitlines()) == expected
            log.unlink()
            marker = root / 'authenticated-hostile-transport-executed'
            included = root / 'authenticated-include'
            included.write_text('[url "ext::touch ' + str(marker) + '"]\n insteadOf = https://github.com/\n')
            for name, value in [('url.ext::touch ' + str(marker) + '.insteadOf', 'https://github.com/'),
                                ('url.ext::touch ' + str(marker) + '.pushInsteadOf', 'https://github.com/'),
                                ('remote.sink.pushurl', 'ext::touch ' + str(marker)), ('include.path', str(included)),
                                ('includeIf.gitdir:' + str(repo) + '/.path', str(included)),
                                ('credential.helper', '!touch ' + str(marker)), ('core.sshCommand', 'touch ' + str(marker)),
                                ('http.extraheader', 'checkout-secret')]:
                git(repo, 'config', name, value)
            git(repo, 'config', 'remote.sink.url', 'git@github.com:example/repo.git')
            done = invoke(True, ['sh', '-c', 'exit 3'], ['--push', 'sink', '--attempt', '2'],
                          dict(EVIDENCE_PUSH_TOKEN='secret-token-xyz', PATH=str(shim)+':'+env['PATH'],
                               GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.extraheader', GIT_CONFIG_VALUE_0='caller-secret'))
            assert done.returncode == 3 and result(done)['pushed'], done.stderr
            lines = log.read_text().splitlines()
            assert [line for line in lines if line.startswith('KEY ')] == ['KEY http.https://github.com/example/repo.git.extraheader'], lines
            assert [line for line in lines if line.startswith('TOKEN ')] == ['TOKEN '], lines
            assert any(header in line for line in lines if line.startswith('ENV '))
            assert not any('secret-token-xyz' in line or header in line for line in lines if line.startswith('ARGV '))
            assert not marker.exists()
            executable(shim / 'git', '#!/bin/sh\ncase " $* " in *" push "*) printf "%s %s" "$EVIDENCE_PUSH_TOKEN" "$GIT_CONFIG_VALUE_0" >&2; exit 1;; esac\nexec ' + shlex.quote(real_git) + ' "$@"\n')
            for native in (False, True):
                done = invoke(native, ['sh', '-c', 'exit 3'], ['--push', 'https://github.com/example/repo.git'], dict(EVIDENCE_PUSH_TOKEN='secret-token-xyz', PATH=str(shim)+':'+env['PATH']))
                assert done.returncode == 1 and b'push failed' in done.stderr
                assert b'secret-token-xyz' not in done.stderr and b'***' in done.stderr
        elif group == 'pushurl':
            git(repo, 'remote', 'set-url', 'sink', 'https://unreachable.invalid/fetch.git')
            git(repo, 'remote', 'set-url', '--push', 'sink', sink.as_uri())
            oracle_done = invoke(False, ['sh', '-c', 'exit 3'], ['--push', 'sink'])
            assert oracle_done.returncode == 3 and result(oracle_done)['pushed'], oracle_done.stderr
            native_done = invoke(True, ['sh', '-c', 'exit 3'], ['--push', 'sink'])
            assert native_done.returncode == 1 and b'publication URL' in native_done.stderr, native_done.stderr
            git(repo, 'remote', 'set-url', 'sink', str(sink))
            git(repo, 'remote', 'set-url', '--push', 'sink', 'ext::must-not-run')
            marker = root / 'checkout-local-receive-hook-executed'
            executable(sink / 'hooks/pre-receive', '#!/bin/sh\ntouch ' + shlex.quote(str(marker)) + '\n')
            native_done = invoke(True, ['sh', '-c', 'exit 3'], ['--push', 'sink'])
            assert native_done.returncode == 1 and b'checkout-configured local publication destination is refused' in native_done.stderr, native_done.stderr
            assert not marker.exists()
            (sink / 'hooks/pre-receive').unlink()
            native_done = invoke(True, ['sh', '-c', 'exit 3'], ['--push', str(sink)])
            assert native_done.returncode == 3 and result(native_done)['pushed'], native_done.stderr
            expected = {value[name] for value in (result(oracle_done), result(native_done)) for name in ('ref', 'tag')}
            assert set(text(sink, 'for-each-ref', '--format=%(refname)').splitlines()) == expected
        elif group == 'transport':
            url = 'https://evidence.invalid/owner/repo.git'
            git(repo, 'remote', 'set-url', 'sink', url)
            (home / '.gitconfig').write_text('[url "git@invalid.example:"]\n\tinsteadOf = https://evidence.invalid/\n')
            transport = dict(GIT_CONFIG_COUNT='2', GIT_CONFIG_KEY_0='url.' + sink.as_uri() + '.insteadOf', GIT_CONFIG_VALUE_0=url,
                             GIT_CONFIG_KEY_1='protocol.file.allow', GIT_CONFIG_VALUE_1='always')
            # The oracle retains caller transport settings; native deliberately refuses
            # this non-GitHub URL and later ignores all checkout transport overrides.
            previous = pair(['true'])[0][1]['record']
            git(repo, 'update-ref', '--stdin', data=''.join(f'update refs/tags/evidence/{"a"*40}/cached-{i} {previous}\n' for i in range(2000)).encode())
            expected = set()
            for token in ('', 'secret-token-xyz'):
                done = invoke(False, ['true'], ['--push', 'sink', '--keys', str(allowed), '--input', 'source_inputs=' + tree, '--attempt', '2' if token else '1'], extra=dict(transport, EVIDENCE_PUSH_TOKEN=token))
                values = [(done, *inspect(False, done))]
                for _, value, _, _ in values:
                    assert value['verified'] and value['pushed']
                    expected.update([value['tag'], value['ref'], f'refs/tags/evidence/input/linux-gate/{tree}/{value["record"]}', f'refs/notes/evidence-input/linux-gate/{tree}/{value["record"]}'])
                assert set(text(sink, 'for-each-ref', '--format=%(refname)').splitlines()) == expected
            refused_native = invoke(True, ['sh', '-c', 'exit 3'], ['--push', 'sink'], extra=transport)
            assert refused_native.returncode == 1 and b'publication URL' in refused_native.stderr, refused_native.stderr
            git(repo, 'remote', 'set-url', 'sink', str(sink))
            marker = root / 'hostile-transport-executed'
            included = root / 'hostile-include'
            included.write_text('[url "ext::touch ' + str(marker) + '"]\n insteadOf = ' + str(sink) + '\n')
            for name, value in [('url.ext::touch ' + str(marker) + '.insteadOf', str(sink)),
                                ('url.ext::touch ' + str(marker) + '.pushInsteadOf', str(sink)),
                                ('remote.sink.pushurl', 'ext::touch ' + str(marker)),
                                ('include.path', str(included)), ('includeIf.gitdir:' + str(repo) + '/.path', str(included)),
                                ('credential.helper', '!touch ' + str(marker)), ('core.sshCommand', 'touch ' + str(marker)),
                                ('http.extraheader', 'checkout-secret'), ('http.https://github.com/example/repo.git.extraheader', 'checkout-secret')]:
                git(repo, 'config', name, value)
            native_done = invoke(True, ['sh', '-c', 'exit 3'], ['--push', str(sink), '--attempt', '3', '--input', 'source_inputs=' + tree], extra=transport)
            assert native_done.returncode == 3 and result(native_done)['pushed'], native_done.stderr
            value = result(native_done)
            expected.update([value['tag'], value['ref'], f'refs/tags/evidence/input/linux-gate/{tree}/{value["record"]}', f'refs/notes/evidence-input/linux-gate/{tree}/{value["record"]}'])
            assert set(text(sink, 'for-each-ref', '--format=%(refname)').splitlines()) == expected
            assert not marker.exists()
        else:
            executable(shim / 'git', '#!' + sys.executable + '\nimport os,sys\na=sys.argv[1:]\nif "push" in a:\n p=' + repr(str(log)) + '\n with open(p,"a") as f: f.write(" ".join(a)+"\\n")\n n=len(open(p).read().splitlines())\n if n<=int(os.environ.get("FAILS","0")):\n  specs=a[a.index("push")+3:]\n  print("To sink")\n  for spec in specs: print("!\\t"+spec+"\\t[remote rejected] (failed)")\n  print("Done")\n  sys.exit(1)\nos.execv(' + repr(real_git) + ',["git",*a])\n')
            for native in (False, True):
                for failures in (2, 3):
                    if log.exists(): log.unlink()
                    done = invoke(native, ['sh', '-c', 'exit 3'], ['--push', str(sink)], dict(PATH=str(shim)+':'+env['PATH'], FAILS=str(failures)))
                    assert len(log.read_text().splitlines()) == 3
                    if failures == 2:
                        assert done.returncode == 3 and result(done)['pushed']
                        assert b'answered 2 ref(s) with a bare (failed); pushing them again (2 of 3)' in done.stderr
                        value = result(done)
                        assert text(sink, 'rev-parse', value['ref']) == value['record']
                        assert text(sink, 'rev-parse', value['tag']) == value['record']
                    else:
                        assert done.returncode == 1 and b'push failed (try 3 of 3):' in done.stderr
                        assert done.stderr.count(b'[remote rejected] (failed)') == 2
                        pattern = r'push failed \(try 3 of 3\): refs/tags/evidence/{0}/(\w+) \[remote rejected\] \(failed\); refs/notes/evidence/{0}/\1 \[remote rejected\] \(failed\)'
                        assert re.search(pattern.format(tree), done.stderr.decode()), done.stderr
                executable(sink / 'hooks/pre-receive', '#!/bin/sh\nexit 1\n')
                log.unlink()
                # A fresh attempt avoids an already-published deterministic ref.
                before_decline = refs(sink)
                done = invoke(native, ['sh', '-c', 'exit 3'], ['--push', str(sink), '--attempt', '9'], dict(PATH=str(shim)+':'+env['PATH'], FAILS='0'))
                assert done.returncode == 1 and len(log.read_text().splitlines()) == 1
                assert b'pre-receive hook declined' in done.stderr and b'pushing them again' not in done.stderr
                pattern = r'push failed \(try 1 of 3\): refs/tags/evidence/{0}/(\w+) \[remote rejected\] \(pre-receive hook declined\); refs/notes/evidence/{0}/\1 \[remote rejected\] \(pre-receive hook declined\)'
                assert re.search(pattern.format(tree), done.stderr.decode()), done.stderr
                assert refs(sink) == before_decline
                (sink / 'hooks/pre-receive').unlink()
            # A partial porcelain refusal retries just the named ref, not the
            # complete publication set, even when source-input indexes exist.
            executable(shim / 'git', '#!' + sys.executable + '\nimport os,sys\na=sys.argv[1:]\nif "push" in a:\n p=' + repr(str(log)) + '\n with open(p,"a") as f: f.write(" ".join(a)+"\\n")\n if len(open(p).read().splitlines())==1:\n  spec=a[-1]\n  print("!\\t"+spec+"\\t[remote rejected] (failed)")\n  sys.exit(1)\nos.execv(' + repr(real_git) + ',["git",*a])\n')
            for native in (False, True):
                log.unlink()
                done = invoke(native, ['sh', '-c', 'exit 3'], ['--push', str(sink), '--input', 'source_inputs='+tree], dict(PATH=str(shim)+':'+env['PATH']))
                assert done.returncode == 3 and result(done)['pushed'], done.stderr
                calls = [shlex.split(line) for line in log.read_text().splitlines()]
                assert len(calls) == 2
                original = calls[0][calls[0].index('push')+3:]
                retried = calls[1][calls[1].index('push')+3:]
                assert len(original) == 4 and retried == original[-1:]
    elif group == 'dirty':
        (repo / 'a').write_text('dirty\n')
        refused(['true'], contains=b'checkout is not clean')
        git(repo, 'checkout', '--', 'a')
        for native in (False, True):
            before = refs(repo)
            done = invoke(native, ['sh', '-c', 'echo x > new-file'])
            assert done.returncode == 1 and b'changed while the command ran' in done.stderr
            assert refs(repo) == before
            (repo / 'new-file').unlink()
            done = invoke(native, ['sh', '-c', 'echo changed > a'])
            assert done.returncode == 1 and b'changed while the command ran' in done.stderr
            assert refs(repo) == before
            git(repo, 'checkout', '--', 'a')
    elif group == 'nix':
        drv = '/nix/store/wndx1738rbbrs30ap8l6ma5nkxgcjb89-genie-freshness-0.1.0.drv'
        out = '/nix/store/hh43mxh295bdyfb96mx8qp37ii3dkzx0-genie-freshness-0.1.0'
        inputs = dict(drv_path=drv, out_path=out, nar_hash='sha256-d6xi4mKdjkX2JFicDIv5niSzpyI0m/Hnm8GGAIU04kY=', nar_size='112', references='-', cache_hit='false', nix_signatures='test-nix-evidence-1:' + 'A'*86 + '==', nix_key_id='test-nix-evidence-1', nix_unsigned='false')
        facts = dict(command=['nix', 'build', '.#checks.x86_64-linux.genie-freshness'], exit_code=0, output='built', inputs=inputs, runner='nix')
        # Aggregate facts carry the same Nix runner contract as direct signing.
        path = root / 'nix.json'
        def nix_pair(value, accepted):
            path.write_text(json.dumps(value))
            if not accepted:
                refused(flags=['--aggregate', str(path)], contains=b'the signer refused', check='genie-freshness')
                return
            bodies = []
            for native in (False, True):
                done = invoke(native, flags=['--aggregate', str(path)], check='genie-freshness')
                assert done.returncode == value['exit_code'], done.stderr
                packet = result(done)
                raw = body(packet['record'])
                statement = json.loads(raw)
                assert statement['predicate']['observed']['runner'] == 'nix'
                assert all(statement['predicate']['observed']['inputs'][k] == v for k, v in value['inputs'].items())
                git(repo, '-c', 'gpg.format=ssh', '-c', 'gpg.ssh.allowedSignersFile='+str(allowed), 'verify-commit', packet['record'])
                verified = run([binary, 'evidence', 'verify', '--repo', repo, '--record', packet['record'], '--trusted-signers', allowed])
                assert json.loads(good(verified))['record'] == packet['record']
                bodies.append(raw.replace(sha(binary.read_bytes() if native else sign_script.read_bytes()).encode(), b'0'*64).replace(sha(binary.read_bytes() if native else wrap_script.read_bytes()).encode(), b'0'*64))
            assert bodies[0] == bodies[1]
        nix_pair(facts, True)
        nix_pair(dict(facts, inputs=dict(inputs, nix_signatures='none', nix_key_id='none', nix_unsigned='true')), True)
        nix_pair(dict(facts, exit_code=1, inputs=dict(drv_path=drv)), True)
        for change in (dict(drv_path=out), dict(out_path='/tmp/evil-genie-freshness-0.1.0'), dict(nar_hash='bad'), dict(nar_size='12 bytes'), dict(references='/etc/passwd'), dict(cache_hit='yes'), dict(nix_signatures='AAAA'), dict(nix_unsigned='true'), dict(nix_key_id='someone-else')):
            nix_pair(dict(facts, inputs=dict(inputs, **change)), False)
        for bad in (dict(facts, runner='sekrets'), dict(facts, command=['true']), dict(facts, exit_code=1)):
            nix_pair(bad, False)
    elif group == 'security':
        marker = root / 'hostile-tool-ran'
        evil = executable(root / 'evil', '#!/bin/sh\ntouch ' + shlex.quote(str(marker)) + '\nexit 1\n')
        hooks = root / 'hostile-hooks'
        hooks.mkdir()
        executable(hooks / 'reference-transaction', '#!/bin/sh\ntouch ' + shlex.quote(str(marker)) + '\n')
        for name, value in (('core.fsmonitor', str(evil)), ('core.hooksPath', str(hooks)), ('core.pager', str(evil)), ('uploadpack.packObjectsHook', str(evil)), ('core.sshCommand', str(evil)), ('gpg.ssh.program', str(evil))):
            git(repo, 'config', name, value)
        values = pair(['true'], extra=dict(GIT_DIR=str(root / 'elsewhere'), GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='gpg.ssh.program', GIT_CONFIG_VALUE_0=str(evil)), verify=False)
        # Signer/measurement ignore GIT_DIR, but both legacy verifiers inherit it.
        for _, value, _, _ in values:
            assert value['verified'] is False and not value['pushed'], value
            assert 'not a git repository' in value['verification'], value
        assert not marker.exists()
        config.write_text(json.dumps({k:v for k,v in signer_config.items() if k != 'test_clock'}))
        for native in (False, True):
            done = invoke(native, ['true'], extra=dict(EVIDENCE_SIGN_NOW='1999-01-01T00:00:00Z'))
            good(done)
            statement = json.loads(body(result(done)['record']))
            assert statement['predicate']['observed_at'] != '1999-01-01T00:00:00Z'
        assert not marker.exists()
    elif group == 'paths':
        writable = root / 'writable-tools'
        writable.mkdir()
        for name in ('git', 'ssh-keygen'):
            (writable / name).symlink_to(shutil.which(name, path=tool_path))
        values = ['bin', tool_path.split(':')[0] + '/../' + pathlib.Path(tool_path.split(':')[0]).name,
                  tool_path.split(':')[0].replace('/', '//', 1),
                  tool_path + '::', str(writable), str(home), str(writable) + ':' + tool_path, '/nix/store-evil/bin', '/does/not/exist']
        for value in values:
            config.write_text(json.dumps(dict(signer_config, path=value)))
            refused(['true'], contains=b'the signer refused')
        link = root / 'tool-link'
        link.symlink_to(writable, target_is_directory=True)
        config.write_text(json.dumps(dict(signer_config, path=str(link))))
        refused(['true'], contains=b'the signer refused')
        # Missing runner-specific roots do not make writable tools trusted.
        # TMPDIR remains the controlled fixture directory for verifier files.
        saved_roots = {name: env.pop(name, None) for name in ('RUNNER_TEMP', 'GITHUB_WORKSPACE')}
        try:
            config.write_text(json.dumps(dict(signer_config, path=str(writable))))
            refused(['true'], contains=b'the signer refused')
        finally:
            for name, value in saved_roots.items():
                if value is not None: env[name] = value
        config.write_text(json.dumps(signer_config))
        pair(['true'])
        assert sign_module.unsafe_directory('/does/not/exist') == 'is not a directory'
        assert sign_module.checked_path('/does/not/exist:' + tool_path, strict=False) == tool_path
        shm = pathlib.Path('/dev/shm')
        if shm.is_dir() and os.access(shm, os.W_OK):
            with tempfile.TemporaryDirectory(prefix='evidence-tools-', dir=shm) as directory:
                for name in ('git', 'ssh-keygen'):
                    (pathlib.Path(directory) / name).symlink_to(shutil.which(name, path=tool_path))
                config.write_text(json.dumps(dict(signer_config, path=directory)))
                for native in (False, True):
                    done = invoke(native, ['true'])
                    assert done.returncode == 1, done.stderr
                    assert b'not owned by root' in done.stderr or b'writable by group' in done.stderr, done.stderr
            config.write_text(json.dumps(signer_config))
    elif group == 'validation':
        facts = dict(command=['true'], exit_code=0, output=1)
        path = root / 'invalid.json'
        # These get past wrapper collection and exercise the signer contract.
        for bad in (dict(facts, command=[]), dict(facts, output_sha256='zz', output=None), dict(facts, inputs={'Bad-Name':'x'}), dict(facts, inputs={'run_id':''}), dict(facts, inputs={'flake_lock_sha256':'2'*64})):
            if 'output_sha256' in bad: bad.pop('output')
            path.write_text(json.dumps(bad))
            refused(flags=['--aggregate', str(path)], contains=b'the signer refused')
        path.write_text(json.dumps(facts))
        refused(flags=['--aggregate', str(path)], contains=b'the signer refused', check='a/b')
        aggregate(dict(facts, inputs=dict(run_id='123', event_name='merge_group')))
    elif group == 'lanes':
        (repo / 'scripts').mkdir()
        lane_path = repo / 'scripts/lane.sh'
        lane_path.write_text('lane\n')
        lane_argv = ['sh', '-c', 'echo lane']
        rules = dict(version=1, lanes={'linux-gate':dict(argv=lane_argv, definition_paths=['scripts/lane.sh'])})
        (repo / '.st/required-lanes.json').write_text(json.dumps(rules))
        git(repo, 'add', '.')
        git(repo, 'commit', '-qm', 'lane base')
        base = text(repo, 'rev-parse', 'HEAD')
        def refresh():
            global commit, tree
            commit, tree = text(repo, 'rev-parse', 'HEAD'), text(repo, 'rev-parse', 'HEAD^{tree}')
        def expected_lane(base, command):
            selected = '.fractal/required-lanes.json' if git(repo, 'ls-tree', base, '--', '.fractal/required-lanes.json') else '.st/required-lanes.json'
            raw_rules = git(repo, 'show', base + ':' + selected).decode()
            parsed = verify_module.lane_rules(raw_rules, 'linux-gate')
            base_tree = text(repo, 'rev-parse', base + '^{tree}')
            # The oracle imports its pinned verifier; the native producer uses
            # Rust helpers. Compare those independent definitions explicitly.
            definition = verify_module.lane_definition(str(repo), base_tree, tree, parsed)
            helper = run([binary, 'legacy-evidence-verify-helper', 'lane-definition', '--repo', repo, '--base-tree', base_tree, '--tree', tree, '--check', 'linux-gate'], data=raw_rules.encode())
            assert json.loads(good(helper)) == definition
            values = pair(command, ['--lanes-from', base])
            if definition['changed']:
                assert all(b'edits lane linux-gate (scripts/lane.sh)' in done.stderr for done, _, _, _ in values)
            assert observed(values)['inputs']['lane_definition_sha256'] == definition['tree_sha256']
            return definition
        (repo / 'a').write_text('unrelated\n')
        git(repo, 'commit', '-qam', 'unrelated')
        refresh()
        expected_lane(base, lane_argv)
        for command, flags, check in (
            (['true'], ['--lanes-from', base], 'linux-gate'),
            (lane_argv, ['--lanes-from', base], 'other-check'),
            (lane_argv, ['--lanes-from', commit + '~2'], 'linux-gate'),
        ):
            scratch = pathlib.Path(signer_config['scratch_repo'])
            before = git(scratch, 'for-each-ref', 'refs')
            refused(command, flags, check=check)
            assert git(scratch, 'for-each-ref', 'refs') == before, 'lane refusal signed a record'
        lane_path.write_text('edited lane\n')
        git(repo, 'commit', '-qam', 'edit lane')
        refresh()
        definition = expected_lane(base, lane_argv)
        assert definition['changed'] == ['scripts/lane.sh'] and definition['tree_sha256'] != definition['sha256']
        assert 'lane_definition_sha256' not in observed(pair(lane_argv))['inputs']
        (repo / '.fractal').mkdir()
        new_argv = ['sh', '-c', 'echo new lane']
        rules['lanes']['linux-gate']['argv'] = new_argv
        (repo / '.fractal/required-lanes.json').write_text(json.dumps(rules))
        for layout in ('both', 'new-only'):
            if layout == 'new-only': (repo / '.st/required-lanes.json').unlink()
            git(repo, 'add', '-A')
            git(repo, 'commit', '-qm', layout)
            refresh()
            expected_lane(commit, new_argv)
            refused(lane_argv, ['--lanes-from', commit], b'not the argv')
        (repo / '.st/required-lanes.json').write_text(json.dumps(dict(version=1, lanes={'linux-gate':dict(argv=lane_argv, definition_paths=['scripts/lane.sh'])})))
        (repo / '.fractal/required-lanes.json').write_text('{malformed')
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'malformed preferred layout')
        refresh()
        refused(lane_argv, ['--lanes-from', commit])
    elif group == 'percrate':
        flags = ['--keys', str(allowed), '--input', 'source_inputs=' + tree]
        failed = pair(['sh', '-c', 'exit 1'], [*flags, '--input', 'crate=alpha'], code=1, check='rust-tests')
        assert all(value['verified'] is False for _, value, _, _ in failed)
        pair(['true'], [*flags, '--input', 'crate=beta'], check='rust-tests')
        wrong = root / 'wrong-keys'
        wrong.write_text('')
        # Exact failure reports are verifier-specific, but both must retain the
        # same result schema and must refuse a push of this crate's own record.
        values = pair(['true'], ['--keys', str(wrong), '--input', 'source_inputs=' + tree, '--input', 'crate=gamma'], check='rust-tests', verify=False)
        for _, value, _, _ in values:
            assert value['verified'] is False and isinstance(value['verification'], str)
        for native in (False, True):
            done = invoke(native, ['true'], ['--keys', str(wrong), '--input', 'source_inputs=' + tree, '--input', 'crate=delta', '--push', 'no-such-remote'], check='rust-tests')
            assert done.returncode == 1 and b'did not verify locally' in done.stderr
    elif group == 'partial':
        (repo / 'historical').write_text('history-only\n')
        git(repo, 'add', '.')
        git(repo, 'commit', '-qm', 'history')
        git(repo, 'rm', 'historical')
        git(repo, 'commit', '-qm', 'remove history')
        origin = root / 'origin.git'
        git(root, 'clone', '-q', '--bare', str(repo), str(origin))
        git(origin, 'config', 'uploadpack.allowFilter', 'true')
        for native in (False, True):
            for hydrate in (False, True):
                checkout = root / ('partial-' + str(native) + '-' + str(hydrate))
                git(root, 'clone', '-q', '--filter=blob:none', origin.as_uri(), str(checkout))
                git(checkout, 'update-ref', 'refs/remotes/origin/main', 'HEAD')
                assert '?' in text(checkout, 'rev-list', '--objects', '--missing=print', 'HEAD')
                assert text(checkout, 'config', '--get', 'remote.origin.promisor') == 'true'
                if hydrate:
                    objects = text(checkout, 'rev-list', '--objects', '--missing=print', 'HEAD').splitlines()
                    missing = [line[1:] for line in objects if line.startswith('?')]
                    git(checkout, 'cat-file', '--batch', data=('\n'.join(missing)+'\n').encode())
                    assert '?' not in text(checkout, 'rev-list', '--objects', '--missing=print', 'HEAD')
                    done = invoke(native, ['true'], cwd=checkout)
                    good(done)
                    git(checkout, '-c', 'gpg.format=ssh', '-c', 'gpg.ssh.allowedSignersFile='+str(allowed), 'verify-commit', result(done)['record'])
                else:
                    marker = root / ('transport-ran-' + str(native))
                    git(checkout, 'remote', 'set-url', 'origin', 'ssh://invalid.example/repository')
                    git(checkout, 'config', 'core.sshCommand', 'touch ' + shlex.quote(str(marker)))
                    done = invoke(native, ['true'], cwd=checkout)
                    assert done.returncode == 1 and not marker.exists(), (done.returncode, done.stderr)
                    if native:
                        assert b'missing objects before signing; hydrate the source repository in the caller first' in done.stderr, done.stderr
                    assert refs(checkout) == b''
    elif group == 'golden':
        fixture = manifest / '../../tests/fixtures/fractal/scripts/testdata/evidence/wrapper-note'
        expected = json.loads((fixture / 'expected.json').read_bytes())
        imported = root / 'golden.git'
        init(imported, bare=True)
        git(imported, 'index-pack', '--strict', '--stdin', data=base64.b64decode((fixture / 'record.pack.base64').read_bytes(), validate=False))
        record, tree = expected['record'], expected['tree']
        git(imported, 'update-ref', f'refs/notes/evidence/{tree}/{record}', record)
        for verifier in ([sys.executable, '-I', '-B', verify_script, '--repo', imported, '--tree', tree, '--check', expected['check'], '--keys', fixture / 'allowed-signers'],
                         [binary, 'evidence', 'verify', '--repo', imported, '--record', record, '--trusted-signers', fixture / 'allowed-signers']):
            assert json.loads(good(run(verifier)))['record'] == record
        git(imported, '-c', 'gpg.format=ssh', '-c', 'gpg.ssh.allowedSignersFile=' + str(fixture / 'allowed-signers'), 'verify-commit', record)
        statement = json.loads(body(record, imported))
        assert statement['predicate']['signer'] == expected['signer']
    else:
        raise AssertionError(group)
"#;
