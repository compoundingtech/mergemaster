"""Build evidence test targets and record differential witnesses; --record-cli freezes parser bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "tests/fixtures/oracle/divergences.json"


def test_environment(artifact, binaries, directory):
    """Restore Cargo's runtime variables when launching libtest directly."""
    environment = dict(os.environ, MERGEMASTER_WITNESS_DIRECTORY=directory,
                       CARGO_MANIFEST_DIR=str(Path(artifact["manifest_path"]).resolve().parent))
    environment.pop("CARGO_BIN_EXE_mergemaster", None)
    if "test" in artifact["target"]["kind"]:
        environment["CARGO_BIN_EXE_mergemaster"] = binaries["mergemaster"]
    return environment


def cli_cases():
    """Parser-only probes stop at help or a guaranteed error, before operations."""
    options = {
        "log-watch": ("--remote", "--rem", "--r", "--now", "--max-age"),
        "keygen": ("--name", "--na", "--h", None, None),
        "slo": ("--repository", "--rep", "--h", "--hours", "--max-logs"),
        "runner-report": ("--since", "--sin", "--s", "--hours", "--slo-s"),
        "verify": ("--repo", "--repos", "--re", None, "--max-age"),
        "flip-ready": ("--repo", "--rep", "--", None, None),
        "skip-report": ("--repo", "--rep", "--r", "--hours", None),
    }
    for command, (exact, unique, ambiguous, floating, integer) in options.items():
        probes = [
            ("exact", [exact, "value"]),
            ("unique-prefix", [unique, "value"]),
            ("equals", [exact + "=value"]),
            ("dash-value", [exact, "-value"]),
            ("dash-value-equals", [exact + "=-value"]),
            ("repeat", [exact, "first", exact, "last"]),
        ]
        # flip-ready has no ambiguous long prefix: -- is the option terminator.
        if command != "flip-ready":
            probes.append(("ambiguous-prefix", [ambiguous, "value"]))
        else:
            probes.extend([("unique-flag-prefix", ["--pro"]),
                           ("repeat-flag", ["--dry-run", "--dry-run"])])
        if command == "verify":
            probes.extend([("exact-beats-prefix", ["--repo", "value"]),
                           ("repeat-append", ["--run-input", "a=1", "--run-input=b=2"])])
        if command == "skip-report":
            probes.append(("repeat-append", ["--actor", "first", "--actor=last"]))
        for option, kind in ((floating, "float"), (integer, "int")):
            if option is None:
                continue
            values = [("whitespace", " \t12\n"), ("plus", "+12"), ("underscore", "1_2"),
                      ("negative", "-12"), ("negative-exponent", "-1e3"),
                      ("negative-underscore", "-1_0"), ("negative-dot", "-1."),
                      ("negative-invalid", "-1x"), ("nan", "nan"), ("inf", "inf"),
                      ("negative-infinity", "-infinity"), ("bad-underscore", "1__2")]
            for label, value in values:
                probes.append((f"{kind}-{label}", [option, value]))
                probes.append((f"{kind}-{label}-equals", [option + "=" + value]))
        for label, arguments in probes:
            yield {"id": f"cli-{command}-{label}", "command": command,
                   "argv": [*arguments, "--help"]}
    verify_probes = [
        ("target-conflict", ["--tree", "tree", "--revision", "revision"]),
        ("signer-source-conflict", ["--keys", "keys", "--keys-from", "base"]),
        ("int-error-before-target-conflict",
         ["--max-age", "invalid", "--tree", "tree", "--revision", "revision"]),
        ("int-above-i64", ["--max-age", "9223372036854775808"]),
        ("int-digit-limit", ["--max-age", "1" * 4301]),
    ]
    for label, arguments in verify_probes:
        yield {"id": f"cli-verify-{label}", "command": "verify",
               "argv": [*arguments, "--help"]}
    # Without help or a target, argparse rejects the required group before extras.
    yield {"id": "cli-verify-required-target-before-extras", "command": "verify",
           "argv": ["--unknown"]}


def cli_source(command, registry):
    if command == "verify":
        return registry["source_pins"]["verifier"]
    return json.loads((REGISTRY.parent / f"{command}.json").read_text())["oracle"]


def cli_observation(argv):
    done = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True)
    return {"exit_code": done.returncode, "stdout_hex": done.stdout.hex(),
            "stderr_hex": done.stderr.hex()}


def record_cli(interpreter, registry):
    """Print frozen Python observations; never build or execute the Rust target."""
    rows = []
    for case in cli_cases():
        pin = cli_source(case["command"], registry)
        source = Path(os.environ[pin["environment"]]) / pin["path"]
        data = source.read_bytes()
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == pin["git_blob"]
        rows.append(dict(case, python=cli_observation(
            [str(interpreter), "-I", "-B", str(source), *case["argv"]])))
    return rows


def replay_cli(interpreter, binary, registry, failures):
    rows = []
    frozen = registry["cli_cases"]
    assert [{key: row[key] for key in ("id", "command", "argv")} for row in frozen] == list(cli_cases())
    for expected, actual in zip(frozen, record_cli(interpreter, registry)):
        command = ["legacy-evidence-verify"] if actual["command"] == "verify" else ["evidence", actual["command"]]
        rust = cli_observation([binary, *command, *actual["argv"]])
        row = dict(actual, rust=rust, execution_status="observed",
                   observed_difference=actual["python"] != rust)
        rows.append(row)
        if actual["python"] != expected["python"]:
            failures.append({"id": row["id"], "error": "frozen CLI oracle drift"})
        if row["observed_difference"]:
            failures.append({"id": row["id"], "error": "CLI parser contract diverged",
                             "python": actual["python"], "rust": rust})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--record-cli", action="store_true",
                        help="print pinned Python CLI recordings without compiling or running tests")
    args = parser.parse_args()
    if not args.record_cli and args.output is None:
        parser.error("--output is required unless --record-cli is given")
    registry = json.loads(REGISTRY.read_text())
    interpreter = Path(os.environ["MERGEMASTER_ORACLE_PYTHON"])
    assert interpreter.is_absolute()
    runtime = subprocess.check_output([interpreter, "-I", "-c",
        "import json,sys; print(json.dumps(dict(implementation=sys.implementation.name,version=list(sys.version_info[:3]))))"])
    assert json.loads(runtime) == {"implementation": "cpython", "version": [3, 14, 7]}
    if args.record_cli:
        print(json.dumps(record_cli(interpreter, registry), indent=2))
        return 0
    lock = json.loads((ROOT / "flake.lock").read_text())
    inputs = lock["nodes"]["root"]["inputs"]
    names = {"verifier": "python-oracle", "parity_verifier": "python-oracle-parity", "keys": "fractal-fixture"}
    for name, pin in registry["source_pins"].items():
        source = Path(os.environ[pin["environment"]]) / pin["path"]
        data = source.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        assert blob == pin["git_blob"], name
        locked = lock["nodes"][inputs[names[name]]]["locked"]
        assert (locked["rev"], locked["narHash"]) == (pin["rev"], pin["nar_hash"]), name
    tests = sorted({(case.get("capture_target", "mergemaster_evidence"), case["capture_test"])
                    for case in registry["cases"]})
    assert tests, "no witness tests registered"
    targets = {target for target, _ in tests}
    compile_argv = ["cargo", "test", "--package", "mergemaster-evidence", "--lib"]
    for target in sorted(targets - {"mergemaster_evidence"}):
        compile_argv.extend(["--test", target])
    compile_argv.extend(["--locked", "--no-run", "--message-format=json"])
    compiled = subprocess.run(compile_argv, cwd=ROOT, capture_output=True)
    sys.stderr.buffer.write(compiled.stderr)
    if compiled.returncode:
        sys.stdout.buffer.write(compiled.stdout)
        return compiled.returncode
    artifacts = [message for line in compiled.stdout.splitlines()
                 if (message := json.loads(line)).get("reason") == "compiler-artifact"
                 and message.get("executable")]
    test_artifacts = {message["target"]["name"]: message for message in artifacts
                      if message["profile"]["test"] and message["target"]["name"] in targets}
    binaries = {message["target"]["name"]: message["executable"] for message in artifacts
                if "bin" in message["target"]["kind"] and not message["profile"]["test"]}
    assert set(test_artifacts) == targets, test_artifacts
    test_runs = []
    failures = []
    cli_rows = replay_cli(interpreter, binaries["mergemaster"], registry, failures)
    with tempfile.TemporaryDirectory(prefix="mergemaster-witness-") as directory:
        for target, test in tests:
            artifact = test_artifacts[target]
            environment = test_environment(artifact, binaries, directory)
            argv = [artifact["executable"], "--exact", test, "--nocapture", "--test-threads=1"]
            done = subprocess.run(argv, cwd=ROOT, env=environment, capture_output=True)
            test_runs.append({"argv": argv, "cwd": str(ROOT), "stdin": None,
                              "stdout_hex": done.stdout.hex(), "stderr_hex": done.stderr.hex(),
                              "exit_code": done.returncode})
            sys.stdout.buffer.write(done.stdout)
            sys.stderr.buffer.write(done.stderr)
            if done.returncode or b"1 passed" not in done.stdout:
                failures.append({"test": test, "exit_code": done.returncode,
                                 "stdout_hex": done.stdout.hex(), "stderr_hex": done.stderr.hex()})
        observed = {}
        for path in sorted(Path(directory).glob("*.json")):
            row = json.loads(path.read_text())
            assert row["id"] == path.stem and row["execution_status"] == "observed"
            observed[row["id"]] = row
    cases = []
    for expected in registry["cases"]:
        row = dict(expected)
        actual = observed.pop(row["id"], None)
        if actual is not None:
            row.update(actual)
            if actual["test"] != expected["capture_test"]:
                failures.append({"id": row["id"], "error": "capture came from a different test",
                                 "actual_test": actual["test"], "expected_test": expected["capture_test"]})
            comparison = row.get("local_python") if row.get("comparison") == "python-local-patch" else row["rust"]
            row["observed_difference"] = row["python"] != comparison
            expected_difference = expected.get("expected_difference", True)
            if row["observed_difference"] != expected_difference:
                failures.append({"id": row["id"], "error":
                                 "named divergence did not differ" if expected_difference
                                 else "resolved contract diverged"})
        else:
            failures.append({"id": row["id"], "error": "no observed witness"})
        cases.append(row)
    assert not observed, ("unregistered witness IDs", sorted(observed))
    result = {"version": 1, "runtime": registry["runtime"], "source_pins": registry["source_pins"],
              "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
              "compile_argv": compile_argv, "test_runs": test_runs, "cases": cases,
              "cli_cases": cli_rows, "failures": failures}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    summary = ["## Divergence witness observations", "",
               "Real executions only. Review-requested statuses are not promoted by CI.", "",
               f"Observed {sum(row['execution_status'] == 'observed' for row in cases)}/{len(cases)} divergence cases and {len(cli_rows)} CLI parser cases; failures: {len(failures)}.", ""]
    for row in cases:
        presented = dict(row)
        for field in ("input", "python", "rust", "local_python"):
            if field not in presented:
                continue
            encoded = json.dumps(presented[field], ensure_ascii=True, sort_keys=True).encode()
            if len(encoded) > 4096:
                presented[field] = {"json_bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest(),
                                    "complete_value": f"oracle-divergence-witnesses artifact: cases[id={row['id']}].{field}"}
        text = json.dumps(presented, ensure_ascii=True).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        summary.extend([f"<details><summary>{row['id']}: {row['execution_status']} / {row['review_status']}</summary>",
                        "", "<pre>" + text + "</pre>", "", "</details>", ""])
        print("MERGEMASTER_WITNESS_RESULT " + json.dumps(presented, ensure_ascii=True))
    for row in cli_rows:
        print("MERGEMASTER_CLI_WITNESS_RESULT " + json.dumps(
            {key: row[key] for key in ("id", "execution_status", "observed_difference")}))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
            output.write("\n".join(summary))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
