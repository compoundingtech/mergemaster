#!/usr/bin/env python3
"""Load an unchanged evidence script; replace only its global datetime class."""
import argparse
from datetime import datetime, timezone
import importlib.machinery
import importlib.util
from pathlib import Path
import sys


def instant(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None or result.utcoffset().total_seconds() != 0:
        raise ValueError('clock must be an explicit UTC instant')
    return result.astimezone(timezone.utc)


def load(script, at):
    script = Path(script).resolve()
    fixed = instant(at) if isinstance(at, str) else at
    if fixed.tzinfo is None or fixed.utcoffset().total_seconds() != 0:
        raise ValueError('clock must be UTC')
    loader = importlib.machinery.SourceFileLoader('proof_' + script.name.replace('-', '_'), str(script))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    original = module.datetime

    class FrozenDateTime(original):
        @classmethod
        def now(cls, tz=None):
            return fixed.replace(tzinfo=None) if tz is None else fixed.astimezone(tz)

    module.datetime = FrozenDateTime
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--at', required=True, type=instant)
    parser.add_argument('--script', required=True)
    parser.add_argument('argv', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.argv[1:] if args.argv[:1] == ['--'] else args.argv
    return load(args.script, args.at).main(argv)


if __name__ == '__main__':
    sys.exit(main())
