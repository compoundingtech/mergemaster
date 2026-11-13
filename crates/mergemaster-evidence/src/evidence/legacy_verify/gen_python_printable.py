#!/usr/bin/env python3
"""Generate the Python 3.14.7 / Unicode 16.0.0 printable-range contract.

Authority: flake.nix's nixpkgs 4ba99f3209788ed04f01af38f77ddb803ad6ec63.
Regenerate: nix develop -c python3 crates/mergemaster-evidence/src/evidence/legacy_verify/gen_python_printable.py
Freshness: append --check to that command.
The generated JSON header records this generator's SHA-256 and semantic inputs.
Generation/check locks assets read-only (Git does not preserve that mode).
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys
import unicodedata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    check = parser.parse_args().check
    if sys.version_info[:3] != (3, 14, 7) or unicodedata.unidata_version != '16.0.0':
        parser.error('requires pinned Python 3.14.7 / Unicode 16.0.0')
    flags = bytes(chr(point).isprintable() for point in range(0x110000))
    fingerprint = hashlib.sha256(flags).hexdigest()
    assert fingerprint == '88d55a36f9cfaa0fb3f843f787cc267686953939f2e295f7b3156d63d184adb4'
    ranges = bytearray()
    start = None
    for point, printable in enumerate(flags + b'\x00'):
        if printable and start is None:
            start = point
        elif not printable and start is not None:
            ranges.extend(struct.pack('<II', start, point - 1))
            start = None
    assert len(ranges) == 5888
    script = pathlib.Path(__file__).resolve()
    directory = script.parent
    header = dict(generated=True, generated_on='2026-11-13',
                  generator='crates/mergemaster-evidence/src/evidence/legacy_verify/gen_python_printable.py',
                  generator_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
                  python_version='3.14.7', unicodedata_version='16.0.0',
                  printable_sha256=fingerprint, range_bytes=len(ranges),
                  asset_sha256=hashlib.sha256(ranges).hexdigest())
    assets = {directory / 'python_printable.generated.bin': bytes(ranges),
              directory / 'python_printable.generated.json': (json.dumps(header, indent=2, sort_keys=True) + '\n').encode()}
    for path, expected in assets.items():
        if check:
            if path.read_bytes() != expected:
                parser.error(f'stale generated asset: {path.name}')
        elif not path.exists() or path.read_bytes() != expected:
            if path.exists():
                path.chmod(path.stat().st_mode | 0o200)
            path.write_bytes(expected)
        if path.stat().st_mode & 0o222:
            path.chmod(path.stat().st_mode & ~0o222)
        assert not path.stat().st_mode & 0o222
    print(f'Python 3.14.7 Unicode 16.0.0: {len(ranges)} range bytes; generated assets match')


if __name__ == '__main__':
    main()
