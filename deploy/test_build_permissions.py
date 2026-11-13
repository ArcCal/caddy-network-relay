"""Build output permission checks with local failure fixtures only."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "build-linux-servers-on-linux.sh"


class BuildPermissionTests(unittest.TestCase):
    def test_sourcing_preserves_caller_umask(self):
        for mask in (0o000, 0o077):
            with self.subTest(umask=oct(mask)):
                result = subprocess.run(
                    ["bash", "-c", 'source "$1"; umask', "source-check", str(SCRIPT)],
                    capture_output=True, text=True, umask=mask, check=True)
                self.assertEqual(int(result.stdout.strip(), 8), mask)

    def test_failed_build_preserves_private_existing_output(self):
        # Override the first prerequisite step after actual artifact setup;
        # this never invokes a compiler, package manager or remote source.
        wrapper = '''source() {
    if [[ $1 == /etc/os-release ]]; then
        ID=debian; VERSION_ID=13
        lr_memory_jobs() { jobs=2; }
        lr_ensure_system() { printf 'fixture prerequisite failure\\n'; return 37; }
    else builtin source "$@"; fi
}
export -f source
"$BASH" "$@"
'''
        for mask, expected in ((0o000, 0o755), (0o077, 0o700)):
            for existing in (False, True):
                with self.subTest(umask=oct(mask), existing=existing), tempfile.TemporaryDirectory(
                        prefix="caddy-build-permissions-") as temporary, tempfile.TemporaryDirectory(
                        prefix="20261108-010203.", dir="/tmp") as private:
                    root = Path(temporary)
                    # The production mktemp handoff accepts alphanumeric
                    # suffixes; Python's suffix can contain underscores.
                    stage = Path(private).with_name("20261108-010203." + uuid.uuid4().hex)
                    Path(private).rename(stage)
                    self.addCleanup(shutil.rmtree, stage, ignore_errors=True)
                    checkout = stage / "caddy-source"
                    checkout.mkdir()
                    commit = "1" * 40
                    (stage / ".owner").write_text(commit + "\n")
                    (stage / ".build-parent").write_text(str(root) + "\n")
                    output = root / "artifacts"
                    if existing:
                        output.mkdir(mode=0o700)
                        output.chmod(0o700)
                    command = ["bash", "-c", wrapper, "backend", str(SCRIPT), "--build-updated",
                               str(checkout), str(stage), str(output), commit, "2", "0", "--deps-policy-v2"]
                    result = subprocess.run(command, cwd=root, capture_output=True, text=True, umask=mask)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    log = output / "logs/system-prerequisites.log"
                    self.assertTrue(log.exists(), result.stdout + result.stderr)
                    self.assertEqual(log.read_text(), "fixture prerequisite failure\n")
                    self.assertEqual(output.stat().st_mode & 0o777, 0o700 if existing else expected)
                    self.assertEqual(log.parent.stat().st_mode & 0o777, expected)
                    self.assertEqual(log.stat().st_mode & 0o777, 0o600 if mask else 0o644)
                    self.assertFalse(os.path.lexists(output / ".work"))
                    self.assertFalse(stage.exists())
                    self.assertFalse(list(root.glob("relay-servers.*")))


if __name__ == "__main__":
    unittest.main()
