import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from oracle_scripts import EXEMPT, MANIFEST, ORIGINAL, TARGET, blob, check, migration, migration_history
from oracle_witnesses import test_environment


class WitnessEnvironment(unittest.TestCase):
    def test_integration_restores_cargo_paths_without_parent_variables(self):
        manifest = Path(__file__).resolve().parent.parent / "crates/mergemaster-evidence/Cargo.toml"
        binary = str(manifest.parent / "custom-build-output/mergemaster")
        artifact = {"manifest_path": str(manifest), "target": {"kind": ["test"]}}
        with patch.dict(os.environ, {}, clear=True):
            environment = test_environment(artifact, {"mergemaster": binary}, "/witnesses")
        self.assertEqual(environment["CARGO_MANIFEST_DIR"], str(manifest.parent))
        self.assertEqual(environment["CARGO_BIN_EXE_mergemaster"], binary)
        self.assertEqual(environment["MERGEMASTER_WITNESS_DIRECTORY"], "/witnesses")

    def test_library_uses_its_manifest_and_omits_inherited_binary(self):
        manifest = Path(__file__).resolve().parent.parent / "crates/mergemaster-reconciler/Cargo.toml"
        artifact = {"manifest_path": str(manifest), "target": {"kind": ["lib"]}}
        with patch.dict(os.environ, {"CARGO_MANIFEST_DIR": "/wrong-crate",
                                     "CARGO_BIN_EXE_mergemaster": "/wrong-binary"}, clear=True):
            environment = test_environment(artifact, {}, "/witnesses")
        self.assertEqual(environment["CARGO_MANIFEST_DIR"], str(manifest.parent))
        self.assertNotIn("CARGO_BIN_EXE_mergemaster", environment)

    def test_integration_requires_a_reported_binary_not_a_guessed_path(self):
        artifact = {"manifest_path": __file__, "target": {"kind": ["test"]}}
        with patch.dict(os.environ, {"MERGEMASTER_BIN": "/unrelated-build"}, clear=True):
            with self.assertRaises(KeyError):
                test_environment(artifact, {}, "/witnesses")


class ResyncGuard(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.src, self.oracle, self.fixture = [Path(self.temp.name) / p for p in ("src", "oracle", "fixture")]
        for root in (self.src, self.oracle, self.fixture):
            (root / "scripts").mkdir(parents=True)
        self.old, self.target = ORIGINAL, TARGET
        self.oid = blob(b"new")
        self.write(self.src, "one", b"new")
        self.write(self.oracle, "one", b"old")
        self.write(self.fixture, "one", b"new")
        self.manifest()

    def write(self, root, name, data, mode=0o755):
        path = root / "scripts" / name
        path.write_bytes(data)
        path.chmod(mode)

    def manifest(self):
        (self.src / "scripts/PROVENANCE").write_text(
            f"# resync-original {self.old}\n# resync-rev {self.target}\n# resync-blob scripts/one {self.oid}\n")

    def run_check(self, rev=None, removed=()):
        names = {path.relative_to(root).as_posix()
                 for root in (self.src, self.oracle)
                 for path in (root / "scripts").iterdir()}
        (self.src / "tests").mkdir(exist_ok=True)
        (self.src / MANIFEST).write_text(json.dumps({"version": 1, "paths": [
            {"path": name, "wave": "wave-1-leaves",
             "state": "removed" if name in removed else "retained"}
            for name in sorted(names)
        ]}))
        check(self.src, self.oracle, self.fixture, rev or self.target)

    def test_match(self):
        self.run_check()

    def test_pending_is_oracle_only(self):
        with self.assertRaises(ValueError):
            self.run_check(self.old)
        self.write(self.src, "one", b"old")
        self.run_check(self.old)
        with self.assertRaises(ValueError):
            self.run_check("c" * 40)

    def test_local_mismatch_and_oracle_copy(self):
        for data in (b"edited", b"old"):
            self.write(self.src, "one", data)
            with self.assertRaises(ValueError):
                self.run_check()

    def test_fixture_and_table_must_agree(self):
        self.write(self.fixture, "one", b"edited")
        with self.assertRaises(ValueError):
            self.run_check()
        self.write(self.fixture, "one", b"new")
        self.oid = blob(b"edited")
        self.manifest()
        with self.assertRaises(ValueError):
            self.run_check()

    def test_modes_and_missing_paths(self):
        self.write(self.src, "one", b"new", 0o644)
        with self.assertRaises(ValueError):
            self.run_check()
        (self.src / "scripts/one").unlink()
        with self.assertRaises(ValueError):
            self.run_check()

    def test_unlisted_stays_oracle(self):
        self.write(self.src, "two", b"old")
        self.write(self.oracle, "two", b"old")
        self.run_check()
        self.write(self.src, "two", b"new")
        with self.assertRaises(ValueError):
            self.run_check()

    def test_expiry_is_byte_identical_even_if_modes_differ(self):
        self.write(self.oracle, "one", b"new", 0o644)
        with self.assertRaisesRegex(ValueError, "expired"):
            self.run_check()

    def test_manifest_cannot_retarget_approved_revisions(self):
        for original, target in [("c" * 40, "c" * 40), (ORIGINAL, "c" * 40),
                                 (TARGET, TARGET), (ORIGINAL, ORIGINAL)]:
            self.old, self.target = original, target
            self.manifest()
            with self.assertRaisesRegex(ValueError, "approved constants"):
                self.run_check(target)

    def test_duplicate_or_malformed_rows(self):
        path = self.src / "scripts/PROVENANCE"
        original = path.read_text()
        for row in [f"# resync-blob scripts/one {self.oid}",
                    "# resync-blob scripts/../escape " + self.oid,
                    "# resync-blob scripts/two invalid",
                    "# resync-blob scripts/two"]:
            path.write_text(original + row + "\n")
            with self.assertRaises(ValueError):
                self.run_check()

    def test_listed_symlink_is_not_a_script(self):
        path = self.src / "scripts/one"
        path.unlink()
        path.symlink_to(self.fixture / "scripts/one")
        with self.assertRaisesRegex(ValueError, "not a regular script"):
            self.run_check()

    def patch_manifest(self, name="ci-signed-tree", source=b"old", destination=b"patched"):
        path = self.src / "scripts/PROVENANCE"
        path.write_text(path.read_text() + f"# local-patch scripts/{name} {blob(source)} {blob(destination)}\n")

    def test_local_patch_pins_both_blobs_and_mode(self):
        for name in ("ci-signed-tree", "ci-signed-tree-test", "ci-evidence-gate", "ci-evidence-gate-test",
                     "evidence-prepush", "evidence-prepush-test", "evidence-log-watch.service"):
            self.write(self.src, name, b"patched")
            self.write(self.oracle, name, b"old")
            self.patch_manifest(name)
        self.run_check()
        for root, data, mode in [(self.src, b"edited", 0o755), (self.oracle, b"edited", 0o755),
                                 (self.src, b"patched", 0o644)]:
            self.write(root, "ci-signed-tree", data, mode)
            with self.assertRaisesRegex(ValueError, "local patch bytes/mode/blob mismatch"):
                self.run_check()
            self.write(root, "ci-signed-tree", b"patched" if root == self.src else b"old")
        self.write(self.oracle, "ci-signed-tree", b"patched")
        with self.assertRaisesRegex(ValueError, "expired local patch"):
            self.run_check()

    def test_keygen_adoption_does_not_authorize_unlisted_copied_script(self):
        self.write(self.src, "evidence-prepush", b"patched")
        self.write(self.oracle, "evidence-prepush", b"old")
        self.patch_manifest("evidence-prepush")
        self.run_check()
        self.write(self.src, "two", b"unapproved")
        self.write(self.oracle, "two", b"original")
        with self.assertRaisesRegex(ValueError, "differs from pinned oracle"):
            self.run_check()

    def test_local_patch_rejects_unapproved_duplicate_overlap_and_bad_blobs(self):
        for row in ["# local-patch scripts/one " + blob(b"old") + " " + blob(b"new"),
                    "# local-patch scripts/ci-signed-tree invalid " + blob(b"new"),
                    "# local-patch scripts/ci-signed-tree " + blob(b"old") + " " + blob(b"old")]:
            self.manifest()
            path = self.src / "scripts/PROVENANCE"
            path.write_text(path.read_text() + row + "\n")
            with self.assertRaises(ValueError):
                self.run_check()
        self.manifest()
        self.patch_manifest()
        self.patch_manifest()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_check()
        self.manifest()
        self.patch_manifest()
        path = self.src / "scripts/PROVENANCE"
        path.write_text(path.read_text() + f"# resync-blob scripts/ci-signed-tree {blob(b'new')}\n")
        with self.assertRaisesRegex(ValueError, "overlapping"):
            self.run_check()


    def test_repository_owned_exemptions(self):
        for name in EXEMPT - {"PROVENANCE"}:
            self.write(self.src, name, b"local")
            self.write(self.oracle, name, b"oracle")
        self.run_check()

    def test_native_merge_gate_has_no_legacy_oracle_counterpart(self):
        self.write(self.src, "merge-pr", b"#!/usr/bin/env python3\n# repository-owned merge gate\n")
        self.assertFalse((self.oracle / "scripts/merge-pr").exists())
        self.run_check()

    def test_oracle_script_deletion_is_refused(self):
        self.write(self.oracle, "two", b"old")
        with self.assertRaisesRegex(ValueError, "undeclared removal"):
            self.run_check()

    def test_unlisted_addition_is_refused(self):
        for name in ("not-in-oracle", "parity-drift", "parity-drift-test"):
            self.write(self.src, name, b"new")
            with self.assertRaisesRegex(ValueError, "not a regular script"):
                self.run_check()
            (self.src / "scripts" / name).unlink()

    def test_declared_resync_removal(self):
        (self.src / "scripts/one").unlink()
        self.run_check(removed={"scripts/one"})

    def test_declared_ordinary_removal_does_not_allow_retained_drift(self):
        self.write(self.oracle, "two", b"old")
        self.run_check(removed={"scripts/two"})
        self.write(self.src, "one", b"edited")
        with self.assertRaisesRegex(ValueError, "resync bytes/mode/blob mismatch"):
            self.run_check(removed={"scripts/two"})

    def test_declared_local_patch_removal(self):
        self.write(self.oracle, "ci-signed-tree", b"old")
        self.patch_manifest()
        self.run_check(removed={"scripts/ci-signed-tree"})

    def test_tombstone_cannot_hide_present_script(self):
        with self.assertRaisesRegex(ValueError, "declared removal still exists"):
            self.run_check(removed={"scripts/one"})


class RemovalManifest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.src = Path(self.temp.name)
        self.name = "tests/fixtures/fractal/scripts/shared.py"
        self.path = self.src / self.name
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(b"shared fixture\n")
        self.path.chmod(0o755)
        self.row = {"path": self.name, "wave": "wave-7-local-runner", "state": "retained",
                    "sha256": hashlib.sha256(self.path.read_bytes()).hexdigest(), "executable": 0o111}

    def run_check(self, rows=None):
        (self.src / MANIFEST).write_text(json.dumps(
            {"version": 1, "paths": [self.row] if rows is None else rows}))
        return migration(self.src)

    def test_shared_fixture_bytes_and_modes_are_pinned(self):
        self.run_check()
        self.path.write_bytes(b"changed\n")
        with self.assertRaisesRegex(ValueError, "retained bytes/mode mismatch"):
            self.run_check()
        self.path.write_bytes(b"shared fixture\n")
        self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "retained bytes/mode mismatch"):
            self.run_check()

    def test_removal_requires_individual_tombstone(self):
        self.path.unlink()
        with self.assertRaisesRegex(ValueError, "undeclared removal"):
            self.run_check()
        self.row["state"] = "removed"
        self.assertEqual(self.run_check()[1], {self.name})

    def test_no_blanket_exemptions_or_unknown_waves(self):
        for field, value in (("path", "scripts/*"), ("path", "../escape"),
                             ("wave", "wave-0-oracle-contract"), ("state", "exempt")):
            with self.subTest(field=field, value=value):
                row = dict(self.row, **{field: value})
                with self.assertRaises(ValueError):
                    self.run_check([row])

    def test_duplicate_rows_and_uninventoried_fixtures_fail(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_check([self.row, self.row])
        with self.assertRaisesRegex(ValueError, "uninventoried"):
            self.run_check([])

    def test_fixture_digest_is_required(self):
        row = {key: value for key, value in self.row.items() if key not in ("sha256", "executable")}
        with self.assertRaisesRegex(ValueError, "requires pinned"):
            self.run_check([row])

    def test_new_python_path_requires_inventory(self):
        path = self.src / "tests/new.py"
        path.write_bytes(b"pass\n")
        with self.assertRaisesRegex(ValueError, "uninventoried"):
            self.run_check()

    def test_guard_and_shared_support_stay_until_wave9(self):
        for name in ("tests/oracle_scripts.py", "tests/test-oracle-scripts.py",
                     "scripts/evidence_test_support.py"):
            with self.assertRaisesRegex(ValueError, "until wave 9"):
                self.run_check([{"path": name, "wave": "wave-1-leaves", "state": "removed"}])


class MigrationHistory(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.src = Path(self.temp.name) / "repo"
        self.src.mkdir()
        # Exercise real Git history without inheriting host identity, signing,
        # repository selectors or config (including GIT_CONFIG_COUNT overrides).
        home = Path(self.temp.name) / "home"
        home.mkdir()
        self.git_env = {key: value for key, value in os.environ.items()
                        if not key.startswith("GIT_")}
        self.git_env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
                            GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        self.enterContext(patch.dict(os.environ, self.git_env, clear=True))
        self.git("init", "--quiet")
        self.git("config", "user.name", "Migration History Test")
        self.git("config", "user.email", "migration@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.name = "tests/fixtures/fractal/scripts/shared.py"
        self.path = self.src / self.name
        self.path.parent.mkdir(parents=True)
        self.data = b"shared fixture\n"
        self.path.write_bytes(self.data)
        self.path.chmod(0o755)
        self.row = {"path": self.name, "wave": "wave-7-local-runner", "state": "retained",
                    "sha256": hashlib.sha256(self.data).hexdigest(), "executable": 0o111}
        self.write_manifest([self.row])
        self.base = self.commit_tree()

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.src), *args], env=self.git_env,
            check=True, capture_output=True, text=True).stdout.strip()

    def commit_tree(self):
        self.git("add", "--all")
        tree = self.git("write-tree")
        return self.git("commit-tree", tree, "-m", "Trusted migration base")

    def write_manifest(self, rows):
        (self.src / MANIFEST).write_text(json.dumps({"version": 1, "paths": rows}))

    def assert_history_rejected(self, base):
        # The current tree is valid: only comparison with trusted history can reject it.
        migration(self.src)
        with self.assertRaises(ValueError):
            migration_history(self.src, base)

    def test_deleting_fixture_and_manifest_row_fails(self):
        self.path.unlink()
        self.write_manifest([])
        self.assert_history_rejected(self.base)

    def test_retained_to_removed_with_file_gone_passes(self):
        self.path.unlink()
        self.write_manifest([dict(self.row, state="removed")])
        self.assertEqual(migration(self.src)[1], {self.name})
        migration_history(self.src, self.base)

    def test_removed_to_retained_fails(self):
        self.path.unlink()
        self.write_manifest([dict(self.row, state="removed")])
        base = self.commit_tree()
        self.path.write_bytes(self.data)
        self.path.chmod(0o755)
        self.write_manifest([self.row])
        self.assert_history_rejected(base)

    def test_removed_row_deletion_fails(self):
        self.path.unlink()
        self.write_manifest([dict(self.row, state="removed")])
        base = self.commit_tree()
        self.write_manifest([])
        self.assert_history_rejected(base)

    def test_wave_reassignment_fails(self):
        self.write_manifest([dict(self.row, wave="wave-8-hooks-signers")])
        self.assert_history_rejected(self.base)

    def test_unavailable_base_fails(self):
        self.assert_history_rejected("0" * 40)

    def test_missing_or_non_full_commit_base_fails(self):
        for base in ("", self.base[:12], "HEAD", "g" * 40):
            with self.subTest(base=base):
                self.assert_history_rejected(base)

    def test_unavailable_git_history_fails(self):
        (self.src / ".git").rename(Path(self.temp.name) / "unavailable-history")
        self.assert_history_rejected(self.base)

    def test_bootstrap_base_rejects_disappearing_inventory_and_row(self):
        (self.src / MANIFEST).unlink()
        base = self.commit_tree()
        self.path.unlink()
        self.write_manifest([])
        self.assert_history_rejected(base)

if __name__ == "__main__":
    unittest.main()
