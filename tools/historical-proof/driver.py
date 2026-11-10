#!/usr/bin/env python3
"""Offline, resumable two-implementation frozen-corpus pilot. Not a D GO receipt."""
import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time

from clock_adapter import instant, load

HERE = Path(__file__).resolve().parent
PINS = {'fractal': 'e2721e52463428b4ff655addee129cecd2839763',
        'mergemaster': '9b11253604566a764791f68558e449b36f7f38f9'}
CURRENT = ['typescript-client', 'fractal-web', 'linux-gate', 'genie-freshness',
           'ci-script-tests', 'rust-tests', 'linux-clippy', 'linux-fleet-compat']
PREFIXES = ('refs/tags/', 'refs/notes/', 'refs/evidence-log/')
EVIDENCE_PREFIXES = ('refs/tags/evidence/', 'refs/notes/evidence/', 'refs/notes/evidence-input/')
DIAGNOSTIC_DETAIL_PATHS = (('detail',), ('lanes', '*', 'detail'))


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_bytes(encoded(value) + b'\n')
    temporary.replace(path)


def git(repo, *args, data=None, check=True):
    result = subprocess.run(['git', '-C', str(repo), *args], input=data,
                            capture_output=True, env={**os.environ, 'GIT_NO_LAZY_FETCH': '1',
                                                     'GIT_TERMINAL_PROMPT': '0'})
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace'))
    return result.stdout if check else result


def manifest(path, expected, repo):
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError('manifest sha256 mismatch')
    rows = raw.decode('ascii').splitlines(keepends=True)
    if rows != sorted(rows) or any(not re.fullmatch(r'[0-9a-f]{40,64} refs/[^\s]+\n', r) for r in rows):
        raise ValueError('manifest must be sorted unpeeled <oid> <ref> LF rows')
    refs = {r.rstrip().split(' ', 1)[1]: r.split(' ', 1)[0] for r in rows}
    if len(refs) != len(rows):
        raise ValueError('duplicate manifest ref')
    actual = git(repo, 'for-each-ref', '--format=%(objectname) %(refname)', *PREFIXES).decode().splitlines()
    if sorted(actual) != [r.rstrip('\n') for r in rows]:
        raise ValueError('scratch archive refs differ from manifest (including extras)')
    return refs


def batch(repo, expressions):
    """Batch-read objects, preserving missing entries and original query identity."""
    expressions = list(expressions)
    raw = git(repo, 'cat-file', '--batch', data=(''.join(e + '\n' for e in expressions)).encode())
    offset = 0
    for expression in expressions:
        end = raw.index(b'\n', offset)
        header = raw[offset:end].decode().split()
        offset = end + 1
        if header[-1] == 'missing':
            yield expression, None, None
        else:
            size = int(header[2])
            yield expression, header[1], raw[offset:offset + size]
            offset += size + 1


def config(repo, base, name):
    for prefix in ('.fractal/', '.st/'):
        result = git(repo, 'cat-file', '-e', f'{base}:{prefix}{name}', check=False)
        if result.returncode == 0:
            return json.loads(git(repo, 'cat-file', 'blob', f'{base}:{prefix}{name}'))
    return None


def normalize(code, value):
    satisfied, records, reasons = set(), set(), set()

    def walk(node, name=None):
        if isinstance(node, dict):
            if isinstance(node.get('reason'), str):
                reasons.add(node['reason'])
            if node.get('satisfied') is True and (node.get('check') or name):
                satisfied.add(node.get('check') or name)
            for key, item in node.items():
                if key in ('record', 'decided_by') and isinstance(item, str):
                    records.add(item)
                if key == 'crates' and isinstance(item, dict):
                    records.update(v for v in item.values() if isinstance(v, str))
                if key == 'missing' and isinstance(item, dict):
                    reasons.update(v for v in item.values() if isinstance(v, str))
                walk(item, key if name == 'lanes' or key == 'lanes' else None)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    def semantic(node, path=()):
        if isinstance(node, dict):
            result = {}
            for key, item in node.items():
                child_path = path + (key,)
                diagnostic = any(len(child_path) == len(allowed) and
                                 all((expected == '*' and isinstance(actual, str)) or actual == expected
                                     for actual, expected in zip(child_path, allowed))
                                 for allowed in DIAGNOSTIC_DETAIL_PATHS)
                if not (diagnostic and isinstance(item, str)):
                    result[key] = semantic(item, child_path)
            return result
        if isinstance(node, list):
            return [semantic(item, path + (index,)) for index, item in enumerate(node)]
        return node

    walk(value)
    return {'exit_status': code, 'verdict': value.get('decision', value.get('satisfied')),
            'satisfied_checks': sorted(satisfied), 'selected_records': sorted(records),
            'reject_reason_class': sorted(reasons), 'semantic': semantic(value)}


def has_infrastructure_error(value):
    """Inspect verifier diagnostic locations, never signed statement/input contents."""
    if not isinstance(value, dict):
        return False
    if value.get('reason') == 'error' or value.get('decision') == 'error':
        return True
    lanes = value.get('lanes', {})
    if isinstance(lanes, dict) and any(has_infrastructure_error(lane) for lane in lanes.values()):
        return True
    missing = value.get('missing', {})
    return isinstance(missing, dict) and any(
        reason == 'error' or has_infrastructure_error(reason) for reason in missing.values())


def is_unresolved(code, value, json_valid=True):
    return code not in (0, 1) or not json_valid or has_infrastructure_error(value)


def record_probe(args):
    module = load(Path(args.scripts) / 'evidence-verify', args.clock)
    try:
        statement = module.load(args.repo, args.record)
        with tempfile.NamedTemporaryFile() as revocations:
            status, principal = module.signature(args.repo, args.record, args.keys, revocations.name)
        print(json.dumps({'satisfied': statement is not None and status == 'G',
                          'record': args.record, 'statement': statement, 'signature': status,
                          'principal': principal, 'reason': 'malformed' if statement is None else
                          ('unsigned_degraded' if status == 'N' else 'untrusted_signer' if status != 'G' else None)}))
        return 0
    except Exception as error:
        print(json.dumps({'satisfied': False, 'reason': 'error', 'detail': str(error)}))
        return 2


def build_cases(args, refs):
    repo = args.repo
    records = {}
    for ref, oid in refs.items():
        if not ref.startswith(EVIDENCE_PREFIXES):
            continue
        records.setdefault(oid, {'oid': oid, 'aliases': [], 'issues': [], 'cases': []})['aliases'].append(ref)
    # All unique objects are batch-read, including malformed/non-commit aliases.
    for oid, kind, body in batch(repo, sorted(records)):
        row = records[oid]
        row['object_type'] = kind
        row['object_sha256'] = sha(body) if body is not None else None
        if kind != 'commit':
            row['issues'].append('absent_or_non_commit')
            continue
        listing = git(repo, 'ls-tree', '-r', '-z', oid).split(b'\0')
        entries = [e for e in listing if e]
        if len(entries) != 1:
            row['issues'].append('malformed_record_tree')
            continue
        meta, _, name = entries[0].partition(b'\t')
        fields = meta.split()
        if len(fields) != 3 or fields[:2] != [b'100644', b'blob'] or not re.fullmatch(rb'[0-9a-f]{40,64}', name):
            row['issues'].append('malformed_statement_path')
            continue
        row['statement_blob'] = fields[2].decode()
        row['note_tree'] = name.decode()
        for ref in row['aliases']:
            if ref.rsplit('/', 1)[-1] != oid:
                row['issues'].append('ref_suffix_mismatch')
    blobs = sorted({r['statement_blob'] for r in records.values() if 'statement_blob' in r})
    statements = {}
    for oid, kind, body in batch(repo, blobs):
        try:
            statements[oid] = json.loads(body) if kind == 'blob' else None
        except (ValueError, TypeError):
            statements[oid] = None
    subjects = {}
    observations = {}
    for row in records.values():
        try:
            statement = statements[row['statement_blob']]
            subject = statement['subject'][0]
            commit, tree = subject['name'], subject['digest']['gitTree']
            if not re.fullmatch(r'[0-9a-f]{40,64}', commit) or not re.fullmatch(r'[0-9a-f]{40,64}', tree):
                raise ValueError('invalid subject')
            if tree != row['note_tree']:
                raise ValueError('statement/note tree mismatch')
            if git(repo, 'rev-parse', f'{commit}^{{tree}}').decode().strip() != tree:
                raise ValueError('subject tree mismatch')
            row.update(subject=commit, tree=tree)
            subjects.setdefault(commit, set()).update(statement['predicate']['observed']['checks'])
            observations.setdefault(commit, []).append(statement)
            for ref in row['aliases']:
                parts = ref.split('/')
                if '/evidence/input/' in ref or ref.startswith('refs/notes/evidence-input/'):
                    if parts[-3] not in statement['predicate']['observed']['checks'] or parts[-2] != statement['predicate']['observed'].get('inputs', {}).get('source_inputs'):
                        row['issues'].append('input_index_mismatch')
                elif len(parts) >= 5 and parts[-2] != tree:
                    row['issues'].append('tree_index_mismatch')
        except (KeyError, TypeError, IndexError, ValueError, RuntimeError):
            row['issues'].append('malformed_or_unresolvable_subject')
    policy = config(repo, args.base, 'evidence-skip-policy.json')
    lanes = config(repo, args.base, 'required-lanes.json')
    if policy is None:
        raise ValueError('accepted BASE has no policy')
    checks = set(policy['checks']) | set(CURRENT)
    if lanes:
        checks.update(entry.get('check', name) for name, entry in lanes['lanes'].items())
    candidates = []
    visibility = sha(encoded(refs))
    wrapper_source = git(repo, 'cat-file', 'blob', f'{args.base}:scripts/ci-evidence-gate', check=False)
    wrapper = {}
    if wrapper_source.returncode == 0:
        for node in ast.parse(wrapper_source.stdout).body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ('PROTECTED', 'OWN_LEVELS'):
                        wrapper[target.id] = ast.literal_eval(node.value)
    for subject, historical in sorted(subjects.items()):
        edited = set(git(repo, 'diff', '--name-only', args.base, subject).decode().splitlines())
        protected = bool(edited.intersection(wrapper.get('PROTECTED', ())))
        for check in sorted(checks | historical):
            argv = ['--repo', str(repo), '--revision', subject, '--keys-from', args.base,
                    '--policy-from', args.base, '--repository', args.repository, '--log-keys-from', args.base]
            if check not in policy['checks']:
                candidates.append({'lane': check, 'subject': subject, 'kind': 'not-defined', 'argv': [],
                                   'reason': 'not_defined_at_accepted_base'})
                continue
            flags = ['--check', check]
            if lanes:
                flags += ['--lanes-from', args.base]
            if check == 'rust-tests':
                flags += ['--members']
            relevant = [s for s in observations[subject] if check in s['predicate']['observed']['checks']]
            outcomes = sorted({('pass' if s['predicate']['observed']['checks'][check].get('exit_code') == 0 else 'reject')
                               for s in relevant})
            entry = policy['checks'][check]
            ordered_inputs = {key for rule in entry['kinds'].values() for key in rule.get('input_order', {})}
            variants = {encoded({})}
            for statement in relevant:
                inputs = statement['predicate']['observed'].get('inputs', {})
                variants.add(encoded({key: inputs[key] for key in sorted(ordered_inputs) if key in inputs}))
            for variant in sorted(variants):
                run_inputs = json.loads(variant)
                values = [f'--run-input={key}={value}' for key, value in sorted(run_inputs.items())]
                prefer = ['--prefer-levels', ','.join(wrapper['OWN_LEVELS'])] if protected and check != 'rust-tests' and wrapper.get('OWN_LEVELS') else []
                candidates.append({'lane': check, 'subject': subject, 'kind': 'decision', 'argv': argv + flags + values + prefer,
                                   'run_inputs': run_inputs, 'observed_outcomes': outcomes,
                                   'protected_edit': protected, 'special_mode': bool(prefer or values or check == 'rust-tests'),
                                   'input_context': 'frozen-record-derived sizing vector, not historical authorization'})
        candidates.append({'lane': '__aggregate__', 'subject': subject, 'kind': 'decision',
                           'argv': argv + ['--require-all'] + (['--lanes-from', args.base] if lanes else [])})
    for row in sorted(records.values(), key=lambda r: r['oid']):
        candidates.append({'lane': '__records__', 'kind': 'record', 'record': row['oid'], 'argv': []})
    for case in candidates:
        case.update(base=args.base, clock=args.clock, visibility_digest=visibility,
                    mode='frozen-corpus', historical_context='context_unresolved')
        case.setdefault('run_inputs', {})
        case['id'] = sha(encoded(case))
    selected = []
    for lane in sorted({c['lane'] for c in candidates}):
        group = sorted((c for c in candidates if c['lane'] == lane), key=lambda c: c['id'])
        if args.selection == 'pilot':
            limit = 1000 if lane == '__records__' else 100
            chosen = []
            # Labels are stratification hints, NEVER claims that an observation is trusted.
            for predicate in (lambda c: 'pass' in c.get('observed_outcomes', []),
                              lambda c: 'reject' in c.get('observed_outcomes', []),
                              lambda c: c.get('special_mode', False)):
                match = next((c for c in group if predicate(c) and c not in chosen), None)
                if match:
                    chosen.append(match)
            chosen.extend(c for c in group if c not in chosen)
            selected += chosen[:limit]
        else:
            selected += group
    by_subject, by_record = {}, {}
    for case in selected:
        if 'subject' in case:
            by_subject.setdefault(case['subject'], []).append(case['id'])
        if 'record' in case:
            by_record.setdefault(case['record'], []).append(case['id'])
    for row in records.values():
        row['cases'] = sorted(set(by_subject.get(row.get('subject'), []) + by_record.get(row['oid'], [])))
        row['accounting'] = 'candidate_cases' if row['cases'] else 'classified_issue' if row['issues'] else 'outside_pilot_selection'
    selection = {lane: {'available': sum(c['lane'] == lane for c in candidates),
                        'selected': sum(c['lane'] == lane for c in selected),
                        'requested': 1000 if lane == '__records__' else 100}
                 for lane in sorted({c['lane'] for c in candidates})}
    return sorted(selected, key=lambda c: c['id']), records, selection


def run(args):
    instant(args.clock)
    os.umask(0o077)
    args.repo = Path(args.repo).resolve()
    args.base = git(args.repo, 'rev-parse', '--verify', f'{args.base}^{{commit}}').decode().strip()
    root = Path(args.scratch_root).resolve()
    # Refuse mismatches before creating output or executing any oracle.
    refs = manifest(Path(args.manifest), args.manifest_sha256, args.repo)
    if args.workers != 2 or args.time_budget_seconds > 1200 or args.time_budget_seconds <= 0:
        raise ValueError('approved pilot requires 2 workers and shards of at most 1200 seconds')
    allowlist = json.loads((HERE / 'allowlist.json').read_text())
    if allowlist['ignored_message_paths'] != [list(path) for path in DIAGNOSTIC_DETAIL_PATHS]:
        raise ValueError('allowlist changed: independent review required')
    root.mkdir(parents=True, exist_ok=True)
    implementations = {}
    hashes = {}
    helper = git(args.repo, 'cat-file', 'blob', f'{args.base}:scripts/rust-test-keys')
    helper_oid = git(args.repo, 'rev-parse', f'{args.base}:scripts/rust-test-keys').decode().strip()
    for name, source in [('fractal', args.fractal_scripts), ('mergemaster', args.mergemaster_scripts)]:
        source = Path(source).resolve()
        target = root / 'implementations' / name
        if target.resolve() == source or target.resolve() in source.parents or source in target.resolve().parents:
            raise ValueError('source export and staged implementation must not overlap')
        target.mkdir(parents=True, exist_ok=True)
        hashes[name] = {}
        for path in sorted(source.iterdir()):
            if path.is_file():
                hashes[name][path.name] = sha(path.read_bytes())
                destination = target / path.name
                if not destination.exists() or destination.read_bytes() != path.read_bytes():
                    shutil.copyfile(path, destination)
        # Explicit accepted-BASE helper, identical for both; never change source exports.
        (target / 'rust-test-keys').write_bytes(helper)
        implementations[name] = target
    keys = root / 'accepted-keys'
    key_path = None
    for prefix in ('.fractal/', '.st/'):
        if git(args.repo, 'cat-file', '-e', f'{args.base}:{prefix}evidence-keys', check=False).returncode == 0:
            key_path = prefix + 'evidence-keys'
            break
    keys.write_bytes(git(args.repo, 'cat-file', 'blob', f'{args.base}:{key_path}') if key_path else b'')
    receipt = {'manifest': args.manifest_sha256, 'clock': args.clock, 'base': args.base,
               'repository': args.repository,
               'expected_source_pins': PINS, 'implementations': hashes, 'helper': {'base': args.base, 'blob': helper_oid,
               'sha256': sha(helper)}, 'adapter': sha((HERE / 'clock_adapter.py').read_bytes()),
               'driver': sha(Path(__file__).read_bytes()), 'allowlist': sha(encoded(allowlist)),
               'selection': args.selection, 'workers': args.workers, 'python': sys.version,
               'git': git(args.repo, '--version').decode().strip(),
               'accepted_keys_sha256': sha(keys.read_bytes()),
               'environment': {'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_NO_LAZY_FETCH': '1', 'SSH_AUTH_SOCK': ''}}
    receipt_id = sha(encoded(receipt))
    receipt_path = root / 'receipt.json'
    if receipt_path.exists() and json.loads(receipt_path.read_text()) != receipt:
        raise ValueError('resume receipt differs; use a fresh scratch root')
    save(receipt_path, receipt)
    (root / 'archive.manifest').write_bytes(Path(args.manifest).read_bytes())
    index_path = root / 'index-receipt.json'
    if index_path.exists():
        index = json.loads(index_path.read_text())
        if index['receipt'] != receipt_id or any(sha((root / name).read_bytes()) != digest
                                                for name, digest in index['products'].items()):
            raise ValueError('case index receipt/hash mismatch')
        cases = [json.loads(line) for line in (root / 'cases.jsonl').read_text().splitlines()]
        records = {row['oid']: row for row in
                   (json.loads(line) for line in (root / 'records.jsonl').read_text().splitlines())}
        selection = index['selection']
    else:
        cases, records, selection = build_cases(args, refs)
        (root / 'cases.jsonl').write_bytes(b''.join(encoded(c) + b'\n' for c in cases))
        (root / 'records.jsonl').write_bytes(b''.join(encoded(r) + b'\n' for r in records.values()))
        save(index_path, {'receipt': receipt_id, 'selection': selection,
                          'products': {name: sha((root / name).read_bytes())
                                       for name in ('cases.jsonl', 'records.jsonl')}})
    ref_accounting = [{'ref': ref, 'oid': oid, 'classification': 'record_alias' if ref.startswith(EVIDENCE_PREFIXES)
                       else 'log_view' if ref.startswith('refs/evidence-log/') else 'non_evidence_ref'}
                      for ref, oid in sorted(refs.items())]
    (root / 'refs.jsonl').write_bytes(b''.join(encoded(r) + b'\n' for r in ref_accounting))
    disk_before = shutil.disk_usage(root)._asdict()
    started = time.monotonic()

    def execute(case):
        destination = root / 'cases' / (case['id'] + '.json')
        if destination.exists():
            cached = json.loads(destination.read_text())
            if cached['receipt'] != receipt_id:
                raise ValueError('case receipt mismatch')
            return cached
        if time.monotonic() - started >= args.time_budget_seconds:
            return None
        rows = []
        if case['kind'] != 'not-defined':
            for name, scripts in implementations.items():
                if case['kind'] == 'record':
                    command = [sys.executable, str(Path(__file__).resolve()), 'record-probe', '--scripts', str(scripts),
                               '--clock', args.clock, '--repo', str(args.repo), '--record', case['record'], '--keys', str(keys)]
                else:
                    command = [sys.executable, str(HERE / 'clock_adapter.py'), '--at', args.clock,
                               '--script', str(scripts / 'evidence-verify'), '--', *case['argv']]
                before = time.monotonic()
                try:
                    result = subprocess.run(command, capture_output=True, timeout=min(120, max(1, args.time_budget_seconds - (before - started))),
                                            env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1',
                                                 'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0', 'SSH_AUTH_SOCK': ''})
                    stdout, stderr, code = result.stdout, result.stderr, result.returncode
                except subprocess.TimeoutExpired as error:
                    stdout, stderr, code = error.stdout or b'', error.stderr or b'', 124
                raw = root / 'raw' / case['id']
                raw.mkdir(parents=True, exist_ok=True)
                (raw / (name + '.stdout')).write_bytes(stdout)
                (raw / (name + '.stderr')).write_bytes(stderr)
                try:
                    value = json.loads(stdout)
                    if not isinstance(value, dict):
                        raise ValueError('expected object')
                    valid = True
                except (ValueError, UnicodeError):
                    value, valid = {'reason': 'invalid_json'}, False
                normalized = normalize(code, value)
                unresolved = is_unresolved(code, value, valid)
                rows.append({'case_id': case['id'], 'lane': case['lane'], 'implementation': name,
                             'argv': command, 'normalized': normalized, 'json_valid': valid, 'unresolved': unresolved,
                             'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr), 'duration_s': time.monotonic() - before})
        difference = None
        if rows and rows[0]['normalized'] != rows[1]['normalized']:
            fields = rows[0]['normalized']
            first = next(k for k in fields if fields[k] != rows[1]['normalized'][k])
            difference = {'case_id': case['id'], 'lane': case['lane'], 'first_divergent_field': first,
                          'both': [r['normalized'] for r in rows], 'category': 'unexplained',
                          'context_digest': sha(encoded(case)), 'disposition': 'requires_independent_review'}
        raw_diff = bool(rows and any(rows[0][field] != rows[1][field]
                                    for field in ('stdout_sha256', 'stderr_sha256')))
        product = {'receipt': receipt_id, 'case': case, 'decisions': rows, 'diff': difference, 'raw_diff': raw_diff}
        save(destination, product)
        return product

    with ThreadPoolExecutor(max_workers=2) as pool:
        products = list(pool.map(execute, cases))
    products = [p for p in products if p is not None]
    decisions = [r for p in products for r in p['decisions']]
    diffs = [p['diff'] for p in products if p['diff']]
    (root / 'decisions.jsonl').write_bytes(b''.join(encoded(r) + b'\n' for r in decisions))
    (root / 'diffs.jsonl').write_bytes(b''.join(encoded(r) + b'\n' for r in diffs))
    summary = {}
    for lane in sorted({c['lane'] for c in cases}):
        planned = [c for c in cases if c['lane'] == lane]
        complete = [p for p in products if p['case']['lane'] == lane]
        summary[lane] = {'mode': 'frozen-corpus', 'planned': len(planned), 'completed': len(complete),
                         'not_defined': sum(p['case']['kind'] == 'not-defined' for p in complete),
                         'unresolved': sum(any(r['unresolved'] for r in p['decisions']) for p in complete),
                         'raw_diff_count': sum(p['raw_diff'] for p in complete),
                         'explained_count': sum(p['raw_diff'] and p['diff'] is None for p in complete),
                         'unexplained_diff_count': sum(p['diff'] is not None for p in complete),
                         'implementations': {name: {
                             'satisfied': sum(r['normalized']['verdict'] in (True, 'ok') for r in decisions if r['lane'] == lane and r['implementation'] == name),
                             'rejected': sum(r['normalized']['verdict'] in (False, 'reject', 'would-reject') for r in decisions if r['lane'] == lane and r['implementation'] == name),
                             'expired': sum('too_old' in r['normalized']['reject_reason_class'] for r in decisions if r['lane'] == lane and r['implementation'] == name),
                             'error': sum(r['unresolved'] for r in decisions if r['lane'] == lane and r['implementation'] == name),
                             'selected_records': sorted({oid for r in decisions if r['lane'] == lane and r['implementation'] == name for oid in r['normalized']['selected_records']})}
                             for name in PINS}}
    save(root / 'lane-summary.json', summary)
    coverage = {'claim': 'pilot sizing only; not exhaustive D GO', 'selection': args.selection,
                'archive_refs': len(refs), 'log_refs': sum(r.startswith('refs/evidence-log/') for r in refs),
                'unique_record_objects': len(records), 'record_issues': sum(bool(r['issues']) for r in records.values()),
                'selection_counts': selection,
                'record_accounting': {kind: sum(r['accounting'] == kind for r in records.values())
                                      for kind in ('candidate_cases', 'classified_issue', 'outside_pilot_selection')},
                'planned_cases': len(cases), 'completed_cases': len(products), 'pending_cases': len(cases) - len(products),
                'completed_record_checks': sum(p['case']['kind'] == 'record' for p in products),
                'record_results': {name: {kind: sum(r['lane'] == '__records__' and r['implementation'] == name and
                    (kind in r['normalized']['reject_reason_class'] if kind != 'trusted_signed' else r['normalized']['verdict'] is True)
                    for r in decisions) for kind in ('trusted_signed', 'unsigned_degraded', 'untrusted_signer', 'malformed', 'error')}
                    for name in PINS},
                'current_lanes': {lane: summary.get(lane, {'planned': 0}) for lane in CURRENT},
                'unresolved_cases': sum(any(r['unresolved'] for r in p['decisions']) for p in products),
                'unexplained_diffs': len(diffs), 'historical_as_of_cases': 0,
                'log_consumer_replay': 'NOT RUN: separate log/log-watch fixture receipt required',
                'native_replay': 'out of scope; E must not change native call paths'}
    save(root / 'resources.json', {'wall_seconds': time.monotonic() - started,
         'child_peak_rss_kib': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
         'scratch_retained_bytes': sum(p.stat().st_size for p in root.rglob('*') if p.is_file()),
         'disk_before': disk_before, 'disk_after': shutil.disk_usage(root)._asdict(),
         'repository_objects': git(args.repo, 'count-objects', '-v').decode()})
    save(root / 'coverage.json', coverage)
    # Ref drift during replay is a proof failure, even if both implementations agreed.
    manifest(Path(args.manifest), args.manifest_sha256, args.repo)
    save(root / 'products.json', {str(p.relative_to(root)): sha(p.read_bytes())
                                 for p in sorted(root.rglob('*')) if p.is_file() and p.name != 'products.json'})
    print(json.dumps(coverage, sort_keys=True))
    return 1 if diffs or coverage['unresolved_cases'] or coverage['record_issues'] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    replay = commands.add_parser('replay-shard')
    for flag in ('scratch-root', 'repo', 'manifest', 'manifest-sha256', 'fractal-scripts', 'mergemaster-scripts', 'clock'):
        replay.add_argument('--' + flag, required=True)
    replay.add_argument('--base', default=PINS['fractal'])
    replay.add_argument('--repository', default='compoundingtech/fractal')
    replay.add_argument('--selection', choices=('pilot', 'all'), default='pilot')
    replay.add_argument('--workers', type=int, default=2)
    replay.add_argument('--time-budget-seconds', type=int, default=1200)
    probe = commands.add_parser('record-probe')
    for flag in ('scripts', 'repo', 'record', 'keys', 'clock'):
        probe.add_argument('--' + flag, required=True)
    args = parser.parse_args()
    try:
        return record_probe(args) if args.command == 'record-probe' else run(args)
    except (ValueError, RuntimeError) as error:
        parser.exit(2, f'{error}\n')


if __name__ == '__main__':
    sys.exit(main())
