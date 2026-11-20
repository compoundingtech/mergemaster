import copy, importlib.machinery, importlib.util, json, sys
loader = importlib.machinery.SourceFileLoader('oracle', sys.argv[1] + '/scripts/evidence-sign')
spec = importlib.util.spec_from_loader(loader.name, loader)
signer = importlib.util.module_from_spec(spec)
loader.exec_module(signer)
base = dict(commit='a'*40, check='gate', command=['true', ''], exit_code=0,
            output_sha256='b'*64, change_id='local:one',
            inputs=dict(flake_lock_sha256='c'*64, toolchain_sha256='d'*64,
                        wrapper_sha256='e'*64, system='x86_64-linux', attempt='1'))
cases = []
def add(label, request, raw=None):
    try:
        signer.validate(request)
        valid = True
    except signer.Refused:
        valid = False
    cases.append(dict(label=label, request_json=raw or json.dumps(request), valid=valid,
                      numeric_check=str(request['check']) if isinstance(request, dict) and type(request.get('check')) in (int, float) else None))
def change(label, path, value, source=base):
    request = copy.deepcopy(source)
    parent = request if len(path) == 1 else request[path[0]]
    parent[path[-1]] = value
    add(label, request)
add('wrapper', base)
for key in ['$serde_json::private::Number', '$serde_json::private::RawValue', r'\u0024serde_json::private::RawValue', '$serde_json::private::Future']:
    raw = json.dumps(base).replace('"exit_code": 0', '"exit_code": {"'+key+'": "0"}'); add('private-object-'+key, json.loads(raw), raw)
for spelling in ['10000000000000000.0', '-0', '-0.0', '1e16', '1.5', '1.0', '1e-5', '0.0001', '1e-4', '1e-6', '1e1000', '1'+('0'*40), '1'+('0'*64)]:
    raw = json.dumps(base).replace('"gate"', spelling, 1)
    add('numeric-check-'+spelling, json.loads(raw), raw)
for field, values in {
    'commit': ['a'*64, 'a'*40+'\n', 'A'*40, 'a'*39, None],
    'check': ['0', 12, 'a'*64, 'a\n', 'A', 'a/b', 'a'*65],
    'command': [[], [''], ['ok', 1], ['ok', '\u0000']],
    'exit_code': [True, 1.0, '1', -1, 2**100],
    'output_sha256': ['a'*64+'\n', 'A'*64, 'a'*63],
    'change_id': ['', ' \u001c', 'é'*199, 'é'*200, None],
    'runner': ['wrapper', 'nix', 'unknown', None],
}.items():
    for value in values: change(f'{field}-{len(cases)}', [field], value)
add('non-object', [])
request = copy.deepcopy(base); request['tier'] = 'full'; add('extra-top', request)
for field in base:
    request = copy.deepcopy(base); del request[field]; add('missing-'+field, request)
for field in base['inputs']:
    request = copy.deepcopy(base); del request['inputs'][field]; add('missing-input-'+field, request)
for value in [None, [], {}, 'inputs']:
    change('inputs-type', ['inputs'], value)
for key, values in {
    'attempt': ['0', '01', '10000', '1\n', '9999'],
    'system': ['', 'é'*500, 'é'*501, 1],
    'toolchain_sha256': ['A'*64, 'a'*64+'\n'],
    'wrapper_sha256': ['x', 'a'*64+'\n'],
    'flake_lock_sha256': ['x', 'a'*64+'\n'],
    'run_id': ['123', '', 1], 'Bad': ['x'], 'valid\n': ['x'],
}.items():
    for value in values: change(f'input-{key}-{len(cases)}', ['inputs', key], value)
request = copy.deepcopy(base); request['inputs'].update({f'x{i}':'v' for i in range(36)}); add('too-many-inputs', request)
nix = copy.deepcopy(base)
nix.update(runner='nix', command=['nix', 'build', '.#checks.x86_64-linux.gate'])
nix['inputs'].update(drv_path='/nix/store/'+'a'*32+'-output.drv', out_path='/nix/store/'+'b'*32+'-output',
    nar_hash='sha256-'+'A'*43+'=', nar_size='123', references='-', cache_hit='false',
    nix_signatures='cache:'+'A'*86+'==', nix_unsigned='false', nix_key_id='cache')
add('nix-signed', nix)
# Isolated Python ignores PYTHONHASHSEED; fixture order must not depend on a set.
for field in sorted(set(nix['inputs']) - set(base['inputs'])):
    request = copy.deepcopy(nix); del request['inputs'][field]; add('missing-nix-'+field, request)
for key, values in {
    'drv_path': ['/tmp/output.drv', '/nix/store/'+'a'*32+'-output', '/nix/store/'+'A'*32+'-output.drv'],
    'out_path': ['/tmp/output', '/nix/store/'+'b'*32+'-other'],
    'nar_hash': ['sha256-'+'A'*42+'=', 'sha256-'+'A'*43+'=\n', 'sha256-'+'!'*43+'='],
    'nar_size': ['', '1\n', '1'*16, '0', '01'],
    'references': ['', '/tmp/path', '/nix/store/'+'a'*32+'-x\n'],
    'cache_hit': ['true', 'yes'],
    'nix_signatures': ['', 'cache:AAA===', ':AAA', 'cache:AAA\n', 'a:AA,b:BB'],
    'nix_unsigned': ['true'], 'nix_key_id': ['other'],
}.items():
    for value in values: change(f'nix-{key}-{len(cases)}', ['inputs', key], value, nix)
for command in [['sh','-c','true'], ['nix','build','.#checks.x86_64-linux.other'],
                ['nix','build','.#checks.x/../gate'], ['nix','build','.#checks.x86_64-linux.gate','extra']]:
    change('nix-command', ['command'], command, nix)
refs = ['/nix/store/'+'a'*32+'-a', '/nix/store/'+'b'*32+'-b']
for value in [','.join(refs), ','.join(reversed(refs)), ','.join([refs[0]]*2)]:
    change('nix-references', ['inputs','references'], value, nix)
unsigned = copy.deepcopy(nix); unsigned['inputs'].update(nix_signatures='none', nix_unsigned='true', nix_key_id='none'); add('nix-unsigned', unsigned)
multiple = copy.deepcopy(nix); multiple['inputs'].update(nix_signatures='a:AA,b:BB', nix_key_id='a'); add('nix-multiple-keys', multiple)
failed = copy.deepcopy(nix); failed['exit_code'] = 1; add('failed-output', failed)
for field in ['out_path', 'nar_hash', 'nar_size', 'references', 'nix_signatures']:
    del failed['inputs'][field]
add('failed-no-output', failed)
for field in ['out_path', 'nar_hash', 'nar_size', 'references', 'nix_signatures']:
    change('failed-'+field, ['inputs',field], 'x', failed)
json.dump(cases, sys.stdout)
