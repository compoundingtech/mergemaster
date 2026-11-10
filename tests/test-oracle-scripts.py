import tempfile
from pathlib import Path
import unittest

from oracle_scripts import EXEMPT, check


class OracleGuard(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.src, self.oracle = [Path(self.temp.name) / p for p in ("src", "oracle")]
        for root in (self.src, self.oracle):
            (root / "scripts").mkdir(parents=True)
            self.write(root, "one", b"old")

    def write(self, root, name, data, mode=0o755):
        path = root / "scripts" / name
        path.write_bytes(data)
        path.chmod(mode)

    def run_check(self):
        check(self.src, self.oracle)

    def test_match(self):
        self.run_check()

    def test_repository_owned_exemptions(self):
        for name in EXEMPT:
            self.write(self.src, name, b"local")
            self.write(self.oracle, name, b"oracle")
        self.run_check()

    def test_local_mismatch(self):
        for data in (b"edited", b"new"):
            self.write(self.src, "one", data)
            with self.assertRaises(ValueError):
                self.run_check()

    def test_executable_modes(self):
        self.write(self.src, "one", b"old", 0o644)
        with self.assertRaises(ValueError):
            self.run_check()

    def test_oracle_script_deletion_is_refused(self):
        (self.src / "scripts/one").unlink()
        with self.assertRaisesRegex(ValueError, "missing oracle script"):
            self.run_check()

    def test_unlisted_stays_oracle(self):
        self.write(self.src, "two", b"old")
        self.write(self.oracle, "two", b"old")
        self.run_check()
        self.write(self.src, "two", b"new")
        with self.assertRaises(ValueError):
            self.run_check()

    def test_unlisted_addition_is_refused(self):
        for name in ("not-in-oracle", "parity-drift", "parity-drift-test"):
            with self.subTest(name=name):
                self.write(self.src, name, b"new")
                with self.assertRaisesRegex(ValueError, "not a regular script"):
                    self.run_check()
                (self.src / "scripts" / name).unlink()

    def test_symlink_is_not_a_script(self):
        path = self.src / "scripts/one"
        path.unlink()
        path.symlink_to(self.oracle / "scripts/one")
        with self.assertRaisesRegex(ValueError, "not a regular script"):
            self.run_check()


if __name__ == "__main__":
    unittest.main()
