"""Byte/mode oracle guard with the single PROVENANCE resync exception."""
import hashlib
import json
import os
from pathlib import Path
import re

EXEMPT = {"PROVENANCE", "test-scripts", "parity-drift", "parity-drift-test"}


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def table(text):
    revisions, original, rows = [], [], {}
    for line in text.splitlines():
        if line.startswith("# Commit: "):
            original.append(line.removeprefix("# Commit: "))
        elif line.startswith("# resync-rev "):
            revisions.append(line.removeprefix("# resync-rev "))
        elif line.startswith("# resync-blob "):
            path, oid = line.removeprefix("# resync-blob ").split()
            if not re.fullmatch(r"scripts/[A-Za-z0-9._-]+", path) or path in rows:
                raise ValueError("invalid/duplicate resync path")
            if not re.fullmatch(r"[0-9a-f]{40}", oid) or path[8:] in EXEMPT:
                raise ValueError("invalid resync blob")
            rows[path] = oid
    if len(revisions) != 1 or len(original) != 1 or not rows:
        raise ValueError("resync requires one target, one original revision and paths")
    if not all(re.fullmatch(r"[0-9a-f]{40}", r) for r in revisions + original):
        raise ValueError("invalid resync revision")
    return revisions[0], original[0], rows


def snapshot(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path}: not a regular script")
    return path.read_bytes(), path.stat().st_mode & 0o111


def check(src, oracle, fixture, fixture_rev):
    target, original, rows = table((src / "scripts/PROVENANCE").read_text())
    if fixture_rev not in (original, target):
        raise ValueError("fixture revision differs from PROVENANCE")
    active = fixture_rev == target
    for path, oid in rows.items():
        local, old = snapshot(src / path), snapshot(oracle / path)
        if blob(old[0]) == oid:
            raise ValueError(f"{path}: expired resync exception; remove it (#115)")
        if active:
            upstream = snapshot(fixture / path)
            if blob(upstream[0]) != oid or local != upstream or local[0] == old[0]:
                raise ValueError(f"{path}: resync bytes/mode/blob mismatch")
        elif local != old:
            raise ValueError(f"{path}: pending resync must still equal oracle")
    for path in sorted((src / "scripts").rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(src).as_posix()
        if relative[8:] in EXEMPT or relative in rows:
            continue
        if snapshot(path) != snapshot(oracle / relative):
            raise ValueError(f"{relative}: differs from pinned oracle")


if __name__ == "__main__":
    src = Path(os.environ["src"])
    lock = json.loads((src / "flake.lock").read_text())
    node = lock["nodes"][lock["nodes"]["root"]["inputs"]["fractal-fixture"]]
    check(src, Path(os.environ["MERGEMASTER_PYTHON_ORACLE"]),
          Path(os.environ["MERGEMASTER_FRACTAL_FIXTURE"]), node["locked"]["rev"])
