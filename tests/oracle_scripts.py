"""Require copied scripts to match the immutable Python oracle, in both directions."""
import os
from pathlib import Path

EXEMPT = {"PROVENANCE", "test-scripts"}


def snapshot(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path}: not a regular script")
    return path.read_bytes(), path.stat().st_mode & 0o111


def check(src, oracle):
    for path in sorted((src / "scripts").rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(src).as_posix()
        if relative[8:] in EXEMPT:
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
    check(Path(os.environ["src"]), Path(os.environ["MERGEMASTER_PYTHON_ORACLE"]))
