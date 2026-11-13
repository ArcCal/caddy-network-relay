"""Validate the published source bundle and exclude local Python bytecode."""
import base64
import errno
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
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
    def test_atomic_write_failures_preserve_output_and_close_descriptors(self):
        for stage in ('fdopen', 'fsync', 'replace'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                output = parent / 'installer.sh'
                output.write_bytes(b'original output')
                output.chmod(0o640)
                opened = []
                real_open = os.open

                def tracking_open(*args, **kwargs):
                    descriptor = real_open(*args, **kwargs)
                    opened.append(descriptor)
                    return descriptor

                error = MemoryError('wrapper allocation failed') if stage == 'fdopen' else OSError(errno.EIO, stage)
                with mock.patch.object(PACKAGE.os, 'open', side_effect=tracking_open), \
                        mock.patch.object(PACKAGE.os, stage, side_effect=error):
                    with self.assertRaises(type(error)):
                        PACKAGE.atomic_write(output, b'replacement', 0o755, force_mode=True)
                self.assertEqual(output.read_bytes(), b'original output')
                self.assertEqual(output.stat().st_mode & 0o777, 0o640)
                self.assertEqual(set(parent.iterdir()), {output})
                self.assertTrue(opened, 'failure must occur after acquiring a descriptor')
                live = []
                for descriptor in set(opened):
                    try:
                        os.fstat(descriptor)
                    except OSError as failure:
                        self.assertEqual(failure.errno, errno.EBADF)
                    else:
                        live.append(descriptor)
                try:
                    self.assertEqual(live, [], 'failed writes must not retain descriptors')
                finally:
                    for descriptor in live:
                        os.close(descriptor)

    def test_atomic_write_preserves_modes_and_respects_checksum_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'installer.sh'
            checksum = output.with_name(output.name + '.sha256')
            previous = os.umask(0o077)
            try:
                PACKAGE.atomic_write(output, b'script', 0o755, force_mode=True)
                PACKAGE.atomic_write(checksum, b'first hash', 0o644)
                self.assertEqual(output.stat().st_mode & 0o777, 0o755)
                self.assertEqual(checksum.stat().st_mode & 0o777, 0o600)
                checksum.chmod(0o640)
                PACKAGE.atomic_write(checksum, b'updated hash', 0o640, force_mode=True)
                self.assertEqual(checksum.stat().st_mode & 0o777, 0o640)
                self.assertEqual(checksum.read_bytes(), b'updated hash')
            finally:
                os.umask(previous)

    def test_packaging_creates_nested_output_directories_with_safe_permissions(self):
        for mask, expected in ((0o000, 0o755), (0o077, 0o700)):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'source'
                source.mkdir(mode=0o700)
                for relative in (*PACKAGE.DEPLOY_FILES, 'go.mod', 'go.sum'):
                    path = source / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('fixture\n')
                script = source / 'deploy/package-debian13-installer.py'
                shutil.copyfile(ROOT / 'deploy/package-debian13-installer.py', script)
                existing = Path(directory) / 'output'
                existing.mkdir(mode=0o700)
                first = existing / 'new'
                second = first / 'nested'
                output = second / 'installer.sh'
                previous = os.umask(mask)
                try:
                    subprocess.run([sys.executable, '-B', str(script), '--out', str(output)],
                                   capture_output=True, text=True, check=True, timeout=15)
                finally:
                    os.umask(previous)
                for folder in (first, second):
                    self.assertEqual(folder.stat().st_mode & 0o777, expected)
                self.assertEqual(existing.stat().st_mode & 0o777, 0o700)
                self.assertEqual(source.stat().st_mode & 0o777, 0o700)

    def test_packaging_preserves_private_source_and_existing_output_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            output = Path(directory) / 'output'
            source.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            metadata = source / '.git'
            metadata.mkdir(mode=0o700)
            for relative in (*PACKAGE.DEPLOY_FILES, 'go.mod', 'go.sum'):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture\n')
            script = source / 'deploy/package-debian13-installer.py'
            shutil.copyfile(ROOT / 'deploy/package-debian13-installer.py', script)
            subprocess.run([sys.executable, str(script), '--out', str(output / 'installer.sh')],
                           capture_output=True, text=True, check=True, timeout=15)
            for path in (source, metadata, output):
                with self.subTest(path=path.name):
                    self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_packaging_refuses_linked_outputs_before_changing_either_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            for relative in (*PACKAGE.DEPLOY_FILES, 'go.mod', 'go.sum'):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture\n')
            script = source / 'deploy/package-debian13-installer.py'
            shutil.copyfile(ROOT / 'deploy/package-debian13-installer.py', script)
            output = Path(directory) / 'installer.sh'
            checksum = output.with_name(output.name + '.sha256')
            victim = Path(directory) / 'unrelated'
            for linked in (output, checksum):
                output.unlink(missing_ok=True)
                checksum.unlink(missing_ok=True)
                victim.write_bytes(b'unchanged')
                other = checksum if linked == output else output
                other.write_bytes(b'existing output')
                linked.symlink_to(victim)
                result = subprocess.run([sys.executable, str(script), '--out', str(output)],
                                        capture_output=True, text=True, timeout=15)
                with self.subTest(linked=linked.name):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(victim.read_bytes(), b'unchanged')
                    self.assertEqual(other.read_bytes(), b'existing output')

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

    def test_package_retains_composed_stdlib_policy_and_compile_guards(self):
        required = {'stdlib_policy_guard.go', 'stdlib_policy_guard_tag.go',
                    'deploy/go-tls/prepare.py', 'deploy/go-tls/source-manifest.json',
                    'deploy/go-tls/LICENSE', 'deploy/go-tls/UPSTREAM.md',
                    'deploy/go-tls/relay_key_usage.go.txt', 'deploy/go-tls/relay_host_field.go.txt',
                    'deploy/go-tls/versions/go1.26.11/conn.go.txt', 'deploy/go-tls/versions/go1.27.4/conn.go.txt',
                    'deploy/go-tls/versions/go1.26.11/server.go.txt', 'deploy/go-tls/versions/go1.27.4/server.go.txt'}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'installer.sh'
            PACKAGE.package(output)
            with payload(output) as archive:
                self.assertTrue(required.issubset(archive.getnames()))
                for name in required:
                    self.assertEqual(archive.extractfile(name).read(), (ROOT / name).read_bytes())

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
