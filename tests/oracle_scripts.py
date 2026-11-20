"""Migration-aware byte/mode oracle guard; removals require exact manifest rows."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

# Repository-owned entrypoints have no copied Fractal implementation to compare.
# merge-pr is covered by test-merge-pr.py, not by the legacy byte/mode oracle.
EXEMPT = {"PROVENANCE", "test-scripts", "merge-pr"}
ORIGINAL = "e2721e52463428b4ff655addee129cecd2839763"
TARGET = "787e8ed592dff34d2bdc2a2b0b584482da567e7f"
LOCAL_PATCHES = {"scripts/ci-signed-tree", "scripts/ci-signed-tree-test",
                 "scripts/ci-evidence-gate", "scripts/ci-evidence-gate-test"}
MANIFEST = "tests/python-removals.json"
WAVES = {
    "wave-1-leaves", "wave-2-verifier-crate-keys", "wave-3-sign-wrap",
    "wave-4-ci-adapters", "wave-5-log-gc", "wave-6-lane-tools",
    "wave-7-local-runner", "wave-8-hooks-signers", "wave-9-python-free",
}


def migration(src):
    """Validate individual tombstones, not a wave-wide deletion exemption."""
    document = json.loads((src / MANIFEST).read_text())
    if not isinstance(document, dict) or set(document) != {"version", "paths"} or type(document["version"]) is not int or document["version"] != 1:
        raise ValueError("invalid removal manifest version/fields")
    rows = document["paths"]
    if not isinstance(rows, list):
        raise ValueError("removal paths must be a list")
    paths, removed = set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) not in (
                {"path", "wave", "state"}, {"path", "wave", "state", "sha256", "executable"}):
            raise ValueError("invalid removal row fields")
        name = row["path"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", name) or any(
                part in ("", ".", "..") for part in name.split("/")) or name in paths:
            raise ValueError("invalid/duplicate removal path")
        paths.add(name)
        if not isinstance(row["wave"], str) or row["wave"] not in WAVES or row["state"] not in ("retained", "removed"):
            raise ValueError(f"{name}: invalid removal wave/state")
        if name in {"tests/oracle_scripts.py", "tests/test-oracle-scripts.py",
                    "scripts/evidence_test_support.py"} and row["wave"] != "wave-9-python-free":
            raise ValueError(f"{name}: shared guard/support must remain until wave 9")
        if name.startswith("tests/fixtures/") and "sha256" not in row:
            raise ValueError(f"{name}: fixture requires pinned bytes/mode")
        path = src / name
        if row["state"] == "removed":
            if path.exists() or path.is_symlink():
                raise ValueError(f"{name}: declared removal still exists")
            removed.add(name)
        else:
            if not path.exists() and not path.is_symlink():
                raise ValueError(f"{name}: undeclared removal")
            data, executable = snapshot(path)
            if "sha256" in row:
                if not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
                    raise ValueError(f"{name}: invalid retained digest")
                if type(row["executable"]) is not int or row["executable"] & ~0o111:
                    raise ValueError(f"{name}: invalid executable bits")
                if hashlib.sha256(data).hexdigest() != row["sha256"] or executable != row["executable"]:
                    raise ValueError(f"{name}: retained bytes/mode mismatch")
    inventory = set()
    for directory in ("scripts", "tests", "crates"):
        for path in (src / directory).rglob("*"):
            relative = path.relative_to(src).as_posix()
            if path.is_dir() or "__pycache__" in path.parts:
                continue
            if directory == "scripts" or path.suffix == ".py" or relative.startswith("tests/fixtures/"):
                inventory.add(relative)
    missing = inventory - paths - {MANIFEST}
    if missing:
        raise ValueError(f"uninventoried paths: {', '.join(sorted(missing))}")
    return paths, removed


def migration_history(src, base):
    """Keep historical paths/tombstones against a trusted event base, never this tree."""
    if not isinstance(base, str) or not re.fullmatch(r"[0-9a-f]{40}", base):
        raise ValueError("migration base must be a full commit SHA")

    def git(*args):
        result = subprocess.run(["git", "-C", str(src), *args], capture_output=True)
        if result.returncode:
            raise ValueError(f"migration base/history unavailable: {base}")
        return result.stdout

    # Resolve a commit, not an arbitrary tree/blob, and require its full tree locally.
    resolved = git("rev-parse", "--verify", base + "^{commit}").decode().strip()
    if resolved != base:
        raise ValueError("migration base must identify the exact commit")
    names = git("ls-tree", "-rz", "--name-only", base).decode().split("\0")
    inventory = {
        name for name in names if name and name != MANIFEST
        and "__pycache__" not in name.split("/")
        and (name.startswith("scripts/") or name.startswith("tests/fixtures/")
             or name.startswith(("tests/", "crates/")) and name.endswith(".py"))
    }
    previous = {}
    if MANIFEST in names:
        document = json.loads(git("show", base + ":" + MANIFEST))
        if (not isinstance(document, dict) or set(document) != {"version", "paths"}
                or type(document["version"]) is not int or document["version"] != 1
                or not isinstance(document["paths"], list)):
            raise ValueError("invalid historical removal manifest")
        for row in document["paths"]:
            if (not isinstance(row, dict) or not isinstance(row.get("path"), str)
                    or row["path"] in previous or row.get("wave") not in WAVES
                    or row.get("state") not in ("retained", "removed")):
                raise ValueError("invalid historical removal row")
            previous[row["path"]] = row
        if inventory - previous.keys():
            raise ValueError("historical inventory is missing removal rows")
    # The first migration PR has no earlier manifest: its trusted Git tree is
    # the baseline. Subsequent PRs also retain every historical tombstone.
    migration(src)
    current = {row["path"]: row for row in json.loads((src / MANIFEST).read_text())["paths"]}
    missing = (inventory | previous.keys()) - current.keys()
    if missing:
        raise ValueError(f"historical removal rows disappeared: {', '.join(sorted(missing))}")
    for name, old in previous.items():
        row = current[name]
        if row["wave"] != old["wave"]:
            raise ValueError(f"{name}: historical removal wave changed")
        if old["state"] == "removed" and row != old:
            raise ValueError(f"{name}: removed tombstone changed or resurrected")


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
    inventory, removed = migration(src)
    if fixture_rev not in (ORIGINAL, TARGET):
        raise ValueError("fixture revision differs from approved constants")
    for path, oid in rows.items():
        if path in removed:
            snapshot(oracle / path)
            continue
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
        if path in removed:
            snapshot(oracle / path)
            continue
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
        if relative[8:] not in EXEMPT and relative not in inventory:
            raise ValueError(f"{relative}: missing oracle script inventory")
        if relative[8:] not in EXEMPT and relative not in removed and not (src / relative).is_file():
            raise ValueError(f"{relative}: missing oracle script")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--migration-base":
        migration_history(Path.cwd(), sys.argv[2])
    elif len(sys.argv) != 1:
        raise SystemExit("usage: oracle_scripts.py [--migration-base FULL_COMMIT_SHA]")
    else:
        src = Path(os.environ["src"])
        lock = json.loads((src / "flake.lock").read_text())
        node = lock["nodes"][lock["nodes"]["root"]["inputs"]["fractal-fixture"]]
        check(src, Path(os.environ["MERGEMASTER_PYTHON_ORACLE"]),
              Path(os.environ["MERGEMASTER_FRACTAL_FIXTURE"]), node["locked"]["rev"])
