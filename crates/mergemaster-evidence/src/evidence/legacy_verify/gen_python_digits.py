#!/usr/bin/env python3
"""Regenerate python_digits.generated.rs using pinned Python; --check checks freshness.

Run: nix develop -c python3 crates/mergemaster-evidence/src/evidence/legacy_verify/gen_python_digits.py
Authority: flake.nix nixpkgs 4ba99f3209788ed04f01af38f77ddb803ad6ec63.
Generated Rust stays read-only; Git checkout modes are repaired by --check.
"""
import argparse
import hashlib
import pathlib
import sys
import unicodedata

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
if sys.version_info[:3] != (3, 14, 7) or unicodedata.unidata_version != '16.0.0':
    parser.error('requires pinned Python 3.14.7 / Unicode 16.0.0')
script = pathlib.Path(__file__).resolve()
flags = bytes(unicodedata.decimal(chr(p), 10 if chr(p).isdigit() else 11) for p in range(0x110000))
zeros = [p for p, value in enumerate(flags) if value == 0]
ranges = []
for p, value in enumerate(flags):
    if value != 10:
        continue
    if ranges and ranges[-1][1] == p - 1:
        ranges[-1][1] = p
    else:
        ranges.append([p, p])
header = f'''// Generated; do not edit. Python 3.14.7 / Unicode 16.0.0; generated 2026-11-14.
// Generator: gen_python_digits.py; regenerate with its documented command.
// Generator SHA256: {hashlib.sha256(script.read_bytes()).hexdigest()}
// Semantic classification SHA256: {hashlib.sha256(flags).hexdigest()}
'''
def table(name, typ, items):
    rows = ['    ' + ', '.join(items[i:i+8]) + ',' for i in range(0, len(items), 8)]
    return f'#[rustfmt::skip]\nconst {name}: &[{typ}] = &[\n' + '\n'.join(rows) + '\n];\n'
text = header + table('DECIMAL_ZEROS', 'u32', [str(p) for p in zeros])
text += table('DIGIT_ONLY', '(u32, u32)', [f'({a}, {b})' for a, b in ranges])
path = script.with_name('python_digits.generated.rs')
expected = text.encode()
if args.check:
    if path.read_bytes() != expected:
        parser.error('stale generated digit tables')
elif not path.exists() or path.read_bytes() != expected:
    if path.exists():
        path.chmod(path.stat().st_mode | 0o200)
    path.write_bytes(expected)
path.chmod(path.stat().st_mode & ~0o222)
print(f'Python 3.14.7 Unicode 16.0.0: {len(zeros)} decimal zeros, {len(ranges)} digit-only ranges')
