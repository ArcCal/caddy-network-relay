"""Validate the published source bundle and exclude local Python bytecode."""
import base64
import hashlib
import importlib.util
import io
from pathlib import Path
import re
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('package_installer', ROOT / 'deploy/package-debian13-installer.py')
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


def payload(path):
    match = re.search(r"<<'CADDY_NETWORK_RELAY_SOURCE_BUNDLE'[^\n]*\n(.*?)\nCADDY_NETWORK_RELAY_SOURCE_BUNDLE", path.read_text(), re.S)
    return tarfile.open(fileobj=io.BytesIO(base64.b64decode(match[1])), mode='r:gz')


class InstallerPackageTests(unittest.TestCase):
    def test_published_payload_and_checksum_match_current_sources(self):
        path = ROOT / 'caddy-network-relay-install-debian13.sh'
        checksum, filename = path.with_suffix('.sh.sha256').read_text().split()
        self.assertEqual(filename, path.name)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), checksum)
        with payload(path) as archive:
            for entry in archive:
                with self.subTest(file=entry.name):
                    self.assertTrue(entry.isfile())
                    self.assertEqual(archive.extractfile(entry).read(), (ROOT / entry.name).read_bytes())

    def test_package_excludes_bytecode_and_preserves_dependency_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('go.mod', 'go.sum', 'third_party/dependency/LICENSE',
                         'third_party/__pycache__/cache.pyc', 'third_party/cache.pyo'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture')
            out = root / 'installer.sh'
            with mock.patch.object(PACKAGE, 'ROOT', root), mock.patch.object(PACKAGE, 'DEPLOY_FILES', ()):
                PACKAGE.package(out)
            with payload(out) as archive:
                self.assertEqual(set(archive.getnames()), {'go.mod', 'go.sum', 'third_party/dependency/LICENSE'})


if __name__ == '__main__':
    unittest.main()
