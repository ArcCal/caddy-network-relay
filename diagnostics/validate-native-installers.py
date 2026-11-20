"""Exercise installer identity and rollback with a real disposable Linux host."""

import importlib
import os
import platform
import sys
import unittest
from pathlib import Path


def main():
    path = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(path))
    tests = importlib.import_module("test_native_cloudflare_installer")
    group = Path("/proc/self/cgroup").read_text()
    if os.geteuid() != 0 or ".service" not in group:
        raise RuntimeError("A systemd service and disposable root account are required")
    print(platform.system(), platform.machine(), group.strip(), flush=True)
    suite = unittest.defaultTestLoader.loadTestsFromModule(tests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() and result.testsRun > 0 and not result.skipped else 1


if __name__ == "__main__":
    sys.exit(main())
