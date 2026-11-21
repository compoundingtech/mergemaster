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


def replay_matrices(interpreter):
    """Replay each explicitly inventoried generator without regenerating expectations."""
    directory = CORPUS.parent
    registry = json.loads((directory / "matrices.json").read_text())
    lock = json.loads((ROOT / "flake.lock").read_text())
    assert registry["version"] == 1
    policy = registry["stdout_policy"]
    assert policy["raw_max_bytes"] == 262144
    for relative in registry["manifests"]:
        fixture = directory / relative
        manifest = json.loads(fixture.read_text())
        assert manifest["version"] == 1
        assert manifest["runtime"] == {"implementation": "CPython", "version": "3.14.7"}
        pin = manifest["oracle"]
        source = Path(os.environ[pin["environment"]])
        assert git_blob((source / pin["path"]).read_bytes()) == pin["git_blob"], relative
        input_name = {"MERGEMASTER_PYTHON_ORACLE": "python-oracle",
                      "MERGEMASTER_PYTHON_PARITY_ORACLE": "python-oracle-parity"}[pin["environment"]]
        locked = lock["nodes"][lock["nodes"]["root"]["inputs"][input_name]]["locked"]
        assert (pin["rev"], pin["nar_hash"]) == (locked["rev"], locked["narHash"]), relative
        with tempfile.TemporaryDirectory(prefix="mergemaster-matrix-") as temporary:
            variables = {"${python_bin}": str(interpreter.parent), "${scratch}": temporary}
            environment = {}
            for key, value in manifest["environment"].items():
                for token, replacement in variables.items():
                    value = value.replace(token, replacement)
                environment[key] = value
            argv = [str(fixture.parent / "driver.py") if value == "driver.py"
                    else str(source) if value == "${oracle}" else value
                    for value in manifest["argv"]]
            done = subprocess.run([interpreter, *argv], input=(fixture.parent / manifest["stdin"]).read_bytes(),
                                  cwd=Path(temporary) / manifest["cwd"], env=environment, capture_output=True)
        assert done.returncode == manifest["exit_code"], (relative, done.stderr)
        expected = (fixture.parent / manifest["stdout"]).read_bytes()
        form = manifest.get("stdout_form", "stream-identities" if "stream_identity" in manifest else "raw")
        assert form in ("raw", "digest-recipes", "stream-identities"), relative
        if form == "raw":
            assert len(expected) <= policy["raw_max_bytes"], (relative, "raw stdout exceeds corpus limit")
        elif form == "digest-recipes":
            document = json.loads(expected)
            assert document["version"] == 1, relative
            assert manifest["raw_stdout_bytes"] > policy["raw_max_bytes"], relative
            assert document["raw_stdout"] == {
                "bytes": manifest["raw_stdout_bytes"], "sha256": manifest["raw_stdout_sha256"]
            }, relative
        else:
            assert "stream_identity" in manifest, relative
        assert done.stdout == expected, relative
        assert done.stderr == (fixture.parent / manifest["stderr"]).read_bytes(), relative
    print(f"Replayed {len(registry['manifests'])} frozen source matrices")


def replay_slo(interpreter):
    """Replay native SLO CLI bytes and its read-only API calls against frozen Python."""
    fixture = json.loads((CORPUS.parent / "slo.json").read_text())
    pin = fixture["oracle"]
    source = Path(os.environ[pin["environment"]]) / pin["path"]
    assert git_blob(source.read_bytes()) == pin["git_blob"], "slo: oracle source drift"
    assert subprocess.check_output([interpreter, "-I", "-c",
        "import sys; print('.'.join(map(str,sys.version_info[:3])))"]) == b"3.14.7\n"
    with tempfile.TemporaryDirectory(prefix="mergemaster-slo-") as temporary:
        root = Path(temporary)
        gh = root / "gh"
        gh.write_text(f"#!{interpreter}\n" + fixture["gh_shim"])
        gh.chmod(0o700)
        environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                           SLO_API=str(root / "api.json"), SLO_CALLS=str(root / "calls"))
        for case in fixture["cases"]:
            (root / "api.json").write_text(json.dumps(case["api"]))
            for command in ([str(interpreter), "-I", "-B", str(source)],
                            [os.environ["MERGEMASTER_BIN"], "evidence", "slo"]):
                (root / "calls").write_text("")
                done = subprocess.run([*command, *case["argv"]], cwd=ROOT,
                                      env=environment, capture_output=True)
                assert done.returncode == case["exit_code"], (case["id"], command, done.stderr)
                assert done.stdout == case["stdout"].encode(), (case["id"], command, "stdout")
                if "stderr_contains" in case:
                    assert case["stderr_contains"].encode() in done.stderr, (case["id"], command, "stderr")
                else:
                    assert done.stderr == case["stderr"].encode(), (case["id"], command, "stderr")
                calls = [int(line) for line in (root / "calls").read_text().splitlines()]
                assert calls == case["logs"], (case["id"], command, calls)
    print(f"Replayed {len(fixture['cases'])} frozen SLO cases against Python and Rust")


def replay_keygen(interpreter):
    """Public fixed-key recordings retain raw streams, expanding only the home path."""
    manifest = json.loads((CORPUS.parent / "keygen.json").read_text())
    source = Path(os.environ[manifest["oracle"]["environment"]]) / manifest["oracle"]["path"]
    assert git_blob(source.read_bytes()) == manifest["oracle"]["git_blob"]
    with tempfile.TemporaryDirectory(prefix="mergemaster-keygen-corpus-") as temporary:
        home = Path(temporary)
        directory = home / ".config/st"
        directory.mkdir(parents=True, mode=0o700)
        key = directory / "evidence-sign-key"
        key.write_bytes(base64.b64decode(manifest["public_test_private_key_base64"]))
        key.chmod(0o600)
        for case in manifest["cases"]:
            if case["id"] == "agent-0":
                (directory / "evidence-sign.json").unlink()
            expand = lambda value: value.replace("${home}", temporary)
            done = subprocess.run([interpreter, "-I", str(source), *map(expand, case["argv"])],
                                  cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True)
            assert (done.stdout, done.stderr, done.returncode) == (
                expand(case["stdout"]).encode(), expand(case["stderr"]).encode(), case["exit_code"]), case["id"]
            assert directory.stat().st_mode & 0o777 == 0o700
            assert key.stat().st_mode & 0o777 == 0o600
            assert (directory / "evidence-sign.json").stat().st_mode & 0o777 == 0o600
    print(f"Replayed {len(manifest['cases'])} frozen keygen cases")


def operational_calls(path):
    """Keep endpoint identities and counts; concurrent downloads need no ordering."""
    calls = []
    for line in path.read_text().splitlines():
        executable, *args = json.loads(line)
        if executable == "gh":
            calls.append(["gh", next(arg for arg in args if arg.startswith("repos/"))])
        elif args[0] in ("show", "ls-tree"):
            calls.append(["git", args[0], args[-1]])
        else:
            calls.append(["git", args[0]])
    return sorted(calls)


def replay_flip_skip(interpreter, binary=None, commands=("flip-ready", "skip-report")):
    """Replay fixed-clock operational recordings, including repeated-cache invocations."""
    binary = binary or os.environ["MERGEMASTER_BIN"]
    for command in commands:
        fixture = json.loads((CORPUS.parent / f"{command}.json").read_text())
        pin = fixture["oracle"]
        source = Path(os.environ[pin["environment"]]) / pin["path"]
        assert git_blob(source.read_bytes()) == pin["git_blob"], (command, "source drift")
        # skip-report imports this exact sibling implementation.
        if command == "skip-report":
            sibling = json.loads((CORPUS.parent / "flip-ready.json").read_text())["oracle"]
            assert git_blob(source.with_name("evidence-flip-ready").read_bytes()) == sibling["git_blob"]
        for case in fixture["cases"]:
            for implementation in ("python", "native"):
                with tempfile.TemporaryDirectory(prefix="mergemaster-flip-skip-") as temporary:
                    root = Path(temporary)
                    for executable in ("gh", "git"):
                        shim = root / executable
                        shim.write_text(f"#!{interpreter}\n" + fixture["shim"])
                        shim.chmod(0o700)
                    (root / "api.json").write_text(json.dumps(case["api"]))
                    for name, content in case.get("files", {}).items():
                        (root / name).write_text(content)
                    environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                                       FLIP_SKIP_API=str(root / "api.json"), FLIP_SKIP_CALLS=str(root / "calls"))
                    arguments = ["--repo", "org/repo", "--cache", str(root / "cache"),
                                 *[arg.replace("${root}", str(root)) for arg in case["argv"]]]
                    if implementation == "python":
                        invocation = [str(interpreter), "-I", "-B", "-c", fixture["launcher"],
                                      str(source), fixture["now"], str(root), *arguments]
                    else:
                        invocation = [str(binary), "evidence", command, "--now", fixture["now"], *arguments]
                    for index, expected in enumerate(case["observations"]):
                        (root / "calls").write_text("")
                        done = subprocess.run(invocation, cwd=root, env=environment, capture_output=True)
                        label = (command, case["id"], implementation, index)
                        assert done.returncode == expected["exit_code"], (label, done.stderr)
                        assert done.stdout == expected["stdout"].replace("${root}", str(root)).encode(), (label, "stdout", done.stdout)
                        assert done.stderr == expected["stderr"].replace("${root}", str(root)).encode(), (label, "stderr", done.stderr)
                        calls = operational_calls(root / "calls")
                        assert calls == expected["calls"], (label, "calls", calls)
                        if index:
                            assert not any(call[0] == "gh" and call[1].endswith("/logs") for call in calls), label
        print(f"Replayed {len(fixture['cases'])} frozen {command} cases against Python and Rust")


def replay_presign_notice(interpreter):
    """Compare both entrypoints to independent frozen stdout and summary bytes."""
    manifest = json.loads((CORPUS.parent / "presign-notice.json").read_text())
    assert manifest["version"] == 1
    assert manifest["runtime"] == {"implementation": "CPython", "version": "3.14.7"}
    pin = manifest["oracle"]
    source = Path(os.environ[pin["environment"]])
    assert git_blob((source / pin["path"]).read_bytes()) == pin["git_blob"]
    lock = json.loads((ROOT / "flake.lock").read_text())
    locked = lock["nodes"][lock["nodes"]["root"]["inputs"]["python-oracle"]]["locked"]
    assert (pin["rev"], pin["nar_hash"]) == (locked["rev"], locked["narHash"])
    required = manifest["required_lanes"]
    data = (source / required["path"]).read_bytes()
    assert git_blob(data) == required["git_blob"]
    lanes = json.loads(data)["lanes"]
    assert list(lanes) == required["names"]
    assert all(lane.get("definition_paths") for lane in lanes.values())
    native = Path(os.environ.get("MERGEMASTER_BIN", ROOT / "target/debug/mergemaster")).resolve()
    for case in manifest["cases"]:
        with tempfile.TemporaryDirectory(prefix="mergemaster-notice-corpus-") as temporary:
            root = Path(temporary)
            for name, script in case["executables"].items():
                target = root / name
                target.write_text(script)
                target.chmod(0o755)
            summary = root / "summary"
            environment = dict(case["environment"], PATH=temporary, LC_ALL="C",
                               GITHUB_STEP_SUMMARY=str(summary))
            for implementation, command in (
                ("python", [interpreter, "-I", "-B", source / pin["path"]]),
                ("rust", [native, "evidence", "presign-notice"]),
            ):
                summary.write_bytes(case["summary_initial"].encode())
                done = subprocess.run(command, cwd=root, env=environment, capture_output=True)
                observed = {"stdout": done.stdout.decode(), "stderr": done.stderr.decode(),
                            "exit_code": done.returncode, "summary": summary.read_bytes().decode()}
                assert observed == case["expected"], (case["id"], implementation, observed)
    print(f"Replayed {len(manifest['cases'])} frozen presign-notice cases against Python and Rust")


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
        replay_slo(interpreter)
        replay_keygen(interpreter)
        replay_matrices(interpreter)
        replay_flip_skip(interpreter)
        replay_presign_notice(interpreter)


if __name__ == "__main__":
    assert sys.argv[1:] in ([], ["--record"]), "usage: oracle_corpus.py [--record]"
    replay(record=sys.argv[1:] == ["--record"])
