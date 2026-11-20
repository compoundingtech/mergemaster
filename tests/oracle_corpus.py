"""Replay frozen CLI bytes against independent Python and Rust; --record prints observations."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests/fixtures/oracle/v1"


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def replay(record=False):
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    interpreter = Path(os.environ["MERGEMASTER_ORACLE_PYTHON"])
    assert interpreter.is_absolute(), "oracle interpreter must be absolute"
    version = subprocess.check_output([interpreter, "-I", "-c",
        "import sys; assert sys.implementation.name == 'cpython'; print('.'.join(map(str,sys.version_info[:3])))"])
    assert version == b"3.14.7\n", version
    sources = {}
    for name, pin in manifest["oracles"].items():
        source = Path(os.environ[pin["environment"]]) / pin["path"]
        assert git_blob(source.read_bytes()) == pin["git_blob"], f"{name}: oracle source drift"
        sources[name] = source
    for name, digest in manifest["assets"].items():
        assert hashlib.sha256((CORPUS / name).read_bytes()).hexdigest() == digest, name
    tools = {name: str(Path(shutil.which(name)).resolve().parent) for name in ("git", "ssh-keygen")}
    observations = []
    with tempfile.TemporaryDirectory(prefix="mergemaster-corpus-") as temporary:
        root = Path(temporary)
        for directory in ("home", "tmp", "oracle"):
            (root / directory).mkdir()
        variables = {"scratch": str(root), "git_bin": tools["git"], "openssh_bin": tools["ssh-keygen"]}
        environment = {}
        for key, value in manifest["environment"].items():
            for name, replacement in variables.items():
                value = value.replace("${" + name + "}", replacement)
            environment[key] = value
        for name, source in sources.items():
            shutil.copyfile(source, root / "oracle" / Path(manifest["oracles"][name]["path"]).name)
        for name in ("allowed-signers", "untrusted-signers"):
            shutil.copyfile(CORPUS / name, root / name)

        def git(*args, data=None):
            done = subprocess.run(["git", *args], input=data, cwd=root, env=environment, capture_output=True)
            assert done.returncode == 0, done.stderr
            return done.stdout.strip()

        git("init", "-q", "--object-format=sha1", "signed")
        git("-C", "signed", "index-pack", "--stdin", data=base64.b64decode((CORPUS / "record.pack.base64").read_bytes()))
        signed = manifest["signed_record"]
        git("-C", "signed", "update-ref", f"refs/notes/evidence/{signed['tree']}/{signed['record']}", signed["record"])
        git("init", "-q", "--object-format=sha1", "workspace")
        for name, data in manifest["workspace_files"].items():
            path = root / "workspace" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data.encode())
        git("-C", "workspace", "add", ".")
        tree = git("-C", "workspace", "write-tree").decode()
        raw = f"tree {tree}\nauthor Corpus <corpus@example.invalid> 1700000000 +0000\ncommitter Corpus <corpus@example.invalid> 1700000000 +0000\n\ncorpus\n".encode()
        commit = git("-C", "workspace", "hash-object", "-t", "commit", "-w", "--stdin", data=raw).decode()
        git("-C", "workspace", "update-ref", "HEAD", commit)
        for case in manifest["cases"]:
            done = subprocess.run([interpreter, "-I", "-B", "oracle/" + Path(manifest["oracles"][case["oracle"]]["path"]).name, *case["argv"]],
                                  cwd=root / case["cwd"], env=environment, capture_output=True)
            row = {"id": case["id"], "stdout_base64": base64.b64encode(done.stdout).decode(),
                   "stderr_base64": base64.b64encode(done.stderr).decode(), "exit_code": done.returncode}
            observations.append(row)
            if not record and "rust_argv" in case:
                native = subprocess.run([os.environ["MERGEMASTER_BIN"], *case["rust_argv"]],
                                        cwd=root / case["cwd"], env=environment, capture_output=True)
                assert (native.stdout, native.stderr, native.returncode) == (done.stdout, done.stderr, done.returncode), case["id"]
    if record:
        print(json.dumps({"version": 1, "cases": observations}, indent=2))
    else:
        expected = json.loads((CORPUS / "recordings.json").read_text())
        assert expected == {"version": 1, "cases": observations}, "frozen oracle observations changed"
        print(f"Replayed {len(observations)} frozen oracle cases")


if __name__ == "__main__":
    assert sys.argv[1:] in ([], ["--record"]), "usage: oracle_corpus.py [--record]"
    replay(record=sys.argv[1:] == ["--record"])
