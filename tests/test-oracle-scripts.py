import tempfile
from pathlib import Path
import unittest

from oracle_scripts import ORIGINAL, TARGET, blob, check


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
            f"# Commit: {self.old}\n# resync-rev {self.target}\n# resync-blob scripts/one {self.oid}\n")

    def run_check(self, rev=None):
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

    def test_unlisted_addition_is_refused(self):
        self.write(self.src, "not-in-oracle-or-table", b"new")
        with self.assertRaisesRegex(ValueError, "not a regular script"):
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


if __name__ == "__main__":
    unittest.main()
