"""Verify private source preparation and fail-closed policy boundaries."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'deploy/go-tls'
SPEC = importlib.util.spec_from_file_location('relay_prepare_go', ASSETS / 'prepare.py')
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


def official_roots():
    values = os.environ.get('RELAY_TEST_OFFICIAL_GO_ROOTS', '').split(os.pathsep)
    if os.environ.get('RELAY_OFFICIAL_GOROOT'):
        values.append(os.environ['RELAY_OFFICIAL_GOROOT'])
    try:
        values.append(subprocess.check_output(['go', 'env', 'GOROOT'], text=True, stderr=subprocess.DEVNULL).strip())
    except (OSError, subprocess.CalledProcessError):
        pass
    manifest = json.loads((ASSETS / 'source-manifest.json').read_text())
    result = {}
    for value in values:
        if not value:
            continue
        root = Path(value)
        try:
            version = (root / 'VERSION').read_text().splitlines()[0]
            record = manifest['versions'][version]
            if PREPARE.digest(root / 'src/crypto/tls/conn.go') == record['original_conn_sha256']:
                result[version] = root
        except (OSError, KeyError, IndexError):
            continue
    return result


class PreparedGoPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.roots = official_roots()
        if not cls.roots:
            raise unittest.SkipTest('No reviewed official Go source root; supply RELAY_TEST_OFFICIAL_GO_ROOTS.')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='relay-go-policy-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.version, self.official = next(iter(self.roots.items()))
        self.source = self.fixture(self.official, 'official')
        self.output = self.base / 'prepared'

    def fixture(self, official, name):
        root = self.base / name
        (root / 'src/crypto/tls').mkdir(parents=True)
        shutil.copyfile(official / 'src/crypto/tls/conn.go', root / 'src/crypto/tls/conn.go')
        (root / 'src/net/http').mkdir(parents=True)
        shutil.copyfile(official / 'src/net/http/server.go', root / 'src/net/http/server.go')
        shutil.copyfile(official / 'VERSION', root / 'VERSION')
        (root / 'bin').mkdir()
        (root / 'bin/go').write_text('fixture tool; no compiler is executed in these unit tests\n')
        return root

    def test_each_available_official_input_prepares_exact_output_without_source_changes(self):
        manifest = json.loads((ASSETS / 'source-manifest.json').read_text())
        for index, (version, official) in enumerate(self.roots.items()):
            with self.subTest(version=version):
                source = self.fixture(official, 'input-' + str(index))
                output = self.base / ('output-' + str(index))
                before = PREPARE.digest(source / 'src/crypto/tls/conn.go')
                self.assertEqual(PREPARE.prepare(source, output), output)
                self.assertEqual(PREPARE.digest(source / 'src/crypto/tls/conn.go'), before)
                self.assertEqual(PREPARE.digest(output / 'src/crypto/tls/conn.go'),
                                 manifest['versions'][version]['patched_conn_sha256'])
                for relative, asset in manifest['versions'][version]['patched_files'].items():
                    self.assertEqual(PREPARE.digest(output / relative), manifest['files'][asset])
                self.assertEqual(PREPARE.prepare(source, output), output)
                self.assertTrue((output / 'bin').is_symlink())
                self.assertFalse((output / 'src').is_symlink())

    def read_only_fixture(self, official, name):
        source = self.fixture(official, name)
        (source / 'src/iter').mkdir()
        (source / 'src/iter/iter_test.go').write_text('package iter\n')
        executable = source / 'src/make.bash'
        executable.write_text('#!/bin/sh\nexit 0\n')
        executable.chmod(0o555)
        paths = [source, *source.rglob('*')]
        for path in paths:
            path.chmod(0o555 if path.is_dir() or path == executable else 0o444)
        def restore_directories():
            for path in paths:
                if path.is_dir():
                    path.chmod(0o700)
        self.addCleanup(restore_directories)
        return source, {str(p.relative_to(source)): stat.S_IMODE(p.stat().st_mode) for p in paths}

    def test_read_only_toolchain_cache_prepares_without_changing_installed_modes(self):
        for index, (version, official) in enumerate(self.roots.items()):
            with self.subTest(version=version):
                source, modes = self.read_only_fixture(official, 'readonly-' + str(index))
                before = PREPARE.source_inventory(source)
                output = self.base / ('writable-' + str(index))
                self.assertEqual(PREPARE.prepare(source, output), output)
                self.assertEqual(PREPARE.prepare(source, output), output)
                self.assertEqual(PREPARE.source_inventory(source), before)
                self.assertEqual({name: stat.S_IMODE((source / name).stat().st_mode) for name in modes}, modes)
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                self.assertTrue((output / 'src/make.bash').stat().st_mode & stat.S_IXUSR)
                for directory in [output / 'src', *(p for p in (output / 'src').rglob('*') if p.is_dir())]:
                    self.assertTrue(directory.stat().st_mode & stat.S_IWUSR)
                shutil.rmtree(output)
                self.assertFalse(output.exists())

    def test_read_only_copy_failure_preserves_error_and_removes_private_work(self):
        source, modes = self.read_only_fixture(self.official, 'readonly-failure')
        original_copy = shutil.copyfile
        def fail_policy_copy(src, dst, *args, **kwargs):
            if Path(src).is_relative_to(ASSETS):
                raise OSError('controlled policy copy failure')
            return original_copy(src, dst, *args, **kwargs)
        with mock.patch.object(PREPARE.shutil, 'copyfile', side_effect=fail_policy_copy):
            with self.assertRaisesRegex(OSError, 'controlled policy copy failure'):
                PREPARE.prepare(source, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.base.glob('.relay-go-tls-*')), [])
        self.assertEqual({name: stat.S_IMODE((source / name).stat().st_mode) for name in modes}, modes)

    def test_unknown_source_version_is_refused_without_output(self):
        (self.source / 'VERSION').write_text('go1.28.0\n')
        with self.assertRaisesRegex(ValueError, 'No reviewed TLS source policy'):
            PREPARE.prepare(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_modified_official_source_is_refused_without_output(self):
        with (self.source / 'src/crypto/tls/conn.go').open('a') as stream:
            stream.write('\n// controlled changed source\n')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            PREPARE.prepare(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_modified_original_http_source_is_refused_without_output(self):
        with (self.source / 'src/net/http/server.go').open('a') as stream:
            stream.write('\n// controlled changed HTTP source\n')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            PREPARE.prepare(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_modified_policy_asset_is_refused_without_output(self):
        assets = self.base / 'assets'
        shutil.copytree(ASSETS, assets)
        with (assets / 'relay_key_usage.go.txt').open('a') as stream:
            stream.write('\n// controlled changed policy\n')
        previous = PREPARE.ASSETS
        try:
            PREPARE.ASSETS = assets
            with self.assertRaisesRegex(ValueError, 'asset checksum mismatch'):
                PREPARE.prepare(self.source, self.output)
        finally:
            PREPARE.ASSETS = previous
        self.assertFalse(self.output.exists())

    def test_modified_prepared_source_is_refused_on_reuse(self):
        PREPARE.prepare(self.source, self.output)
        manifest = json.loads((ASSETS / 'source-manifest.json').read_text())
        for relative in manifest['versions'][self.version]['patched_files']:
            with self.subTest(relative=relative):
                target = self.output / relative
                original = target.read_bytes()
                target.write_bytes(original + b'\n// controlled changed output\n')
                try:
                    with self.assertRaisesRegex(ValueError, 'modified TLS/HTTP source'):
                        PREPARE.prepare(self.source, self.output)
                finally:
                    target.write_bytes(original)

    def test_partial_prepared_policy_is_refused_on_reuse(self):
        PREPARE.prepare(self.source, self.output)
        (self.output / 'src/net/http/relay_host_field.go').unlink()
        with self.assertRaises(OSError):
            PREPARE.prepare(self.source, self.output)

    def test_unpatched_prepared_source_drift_is_refused_on_reuse(self):
        source = self.source / 'src/crypto/tls/unchanged.go'
        source.write_text('package tls\n// original fixture\n')
        PREPARE.prepare(self.source, self.output)
        target = self.output / source.relative_to(self.source)
        target.write_text('package tls\n// changed cached source\n')
        with self.assertRaisesRegex(ValueError, 'source tree'):
            PREPARE.prepare(self.source, self.output)

    def test_added_prepared_source_is_refused_on_reuse(self):
        PREPARE.prepare(self.source, self.output)
        (self.output / 'src/crypto/tls/extra.go').write_text('package tls\n')
        with self.assertRaisesRegex(ValueError, 'source tree'):
            PREPARE.prepare(self.source, self.output)

    def test_prepared_source_symlink_is_refused_on_reuse(self):
        source = self.source / 'src/crypto/tls/unchanged.go'
        source.write_text('package tls\n')
        PREPARE.prepare(self.source, self.output)
        target = self.output / source.relative_to(self.source)
        target.unlink()
        target.symlink_to(source)
        with self.assertRaisesRegex(ValueError, 'source tree'):
            PREPARE.prepare(self.source, self.output)

    def test_installed_root_and_symlink_aliases_are_never_outputs(self):
        link = self.base / 'linked-source'
        link.symlink_to(self.source, target_is_directory=True)
        for output in (self.source, self.source / 'inside', link, link / 'inside'):
            with self.subTest(output=output):
                with self.assertRaisesRegex(ValueError, 'separate|symbolic link'):
                    PREPARE.prepare(self.source, output)
        self.assertFalse((self.source / 'inside').exists())
