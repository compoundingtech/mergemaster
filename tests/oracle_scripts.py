"""Byte/mode oracle guard with the bounded PROVENANCE resync exception."""
import hashlib
import json
import os
from pathlib import Path
import re

EXEMPT = {"PROVENANCE", "test-scripts"}
ORIGINAL = "e2721e52463428b4ff655addee129cecd2839763"
TARGET = "787e8ed592dff34d2bdc2a2b0b584482da567e7f"
LOCAL_PATCHES = {"scripts/ci-signed-tree", "scripts/ci-signed-tree-test"}


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def table(text):
    revisions, original, rows = [], [], {}
    for line in text.splitlines():
        if line.startswith("# resync-original "):
            original.append(line.removeprefix("# resync-original "))
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
    if ORIGINAL == TARGET or original[0] != ORIGINAL or revisions[0] != TARGET:
        raise ValueError("resync revision differs from approved constants")
    return rows


def local_patches(text, resync):
    rows = {}
    for line in text.splitlines():
        if not line.startswith("# local-patch "):
            continue
        path, source, destination = line.removeprefix("# local-patch ").split()
        if path not in LOCAL_PATCHES or path in rows or path in resync:
            raise ValueError("invalid/duplicate/overlapping local patch path")
        if not all(re.fullmatch(r"[0-9a-f]{40}", oid) for oid in (source, destination)) or source == destination:
            raise ValueError("invalid local patch blobs")
        rows[path] = source, destination
    return rows


def snapshot(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path}: not a regular script")
    return path.read_bytes(), path.stat().st_mode & 0o111


def check(src, oracle, fixture=None, fixture_rev=ORIGINAL):
    text = (src / "scripts/PROVENANCE").read_text()
    rows = table(text)
    patches = local_patches(text, rows)
    if fixture_rev not in (ORIGINAL, TARGET):
        raise ValueError("fixture revision differs from approved constants")
    for path, oid in rows.items():
        local, old = snapshot(src / path), snapshot(oracle / path)
        if blob(old[0]) == oid:
            raise ValueError(f"{path}: expired resync exception; remove it (#115)")
        if fixture_rev == TARGET:
            upstream = snapshot(fixture / path)
            if blob(upstream[0]) != oid or local != upstream or local[0] == old[0]:
                raise ValueError(f"{path}: resync bytes/mode/blob mismatch")
        elif local != old:
            raise ValueError(f"{path}: pending resync must still equal oracle")
    for path, (source, destination) in patches.items():
        local, old = snapshot(src / path), snapshot(oracle / path)
        if local[0] == old[0]:
            raise ValueError(f"{path}: expired local patch; remove it")
        if blob(old[0]) != source or blob(local[0]) != destination or local[1] != old[1]:
            raise ValueError(f"{path}: local patch bytes/mode/blob mismatch")
    for path in sorted((src / "scripts").rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(src).as_posix()
        if relative[8:] in EXEMPT or relative in rows or relative in patches:
            continue
        if snapshot(path) != snapshot(oracle / relative):
            raise ValueError(f"{relative}: differs from pinned oracle")
    for path in sorted((oracle / "scripts").rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(oracle).as_posix()
        if relative[8:] not in EXEMPT and not (src / relative).is_file():
            raise ValueError(f"{relative}: missing oracle script")


if __name__ == "__main__":
    src = Path(os.environ["src"])
    lock = json.loads((src / "flake.lock").read_text())
    node = lock["nodes"][lock["nodes"]["root"]["inputs"]["fractal-fixture"]]
    check(src, Path(os.environ["MERGEMASTER_PYTHON_ORACLE"]),
          Path(os.environ["MERGEMASTER_FRACTAL_FIXTURE"]), node["locked"]["rev"])
