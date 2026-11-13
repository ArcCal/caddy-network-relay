#!/usr/bin/env python3
"""Check the installed admin default and its real Caddy run/reload behavior.

Set CADDY_REAL_BINARY to test a built binary without compiling. The distinct-UID
permission check also needs root in an isolated test container.
"""
from contextlib import contextmanager, nullcontext
import os
from pathlib import Path
import socket
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


class InstalledAdminTests(unittest.TestCase):
    def test_unit_defaults_to_a_private_runtime_socket_for_run_and_reload(self):
        unit = (ROOT / 'deploy/caddy.service').read_text().splitlines()
        self.assertIn('RuntimeDirectory=caddy', unit)
        self.assertIn('RuntimeDirectoryMode=0700', unit)
        self.assertIn('Environment=CADDY_ADMIN=unix//run/caddy/admin.sock', unit)
        self.assertTrue(any(line.startswith('ExecStart=') and ' run ' in line for line in unit))
        self.assertTrue(any(line.startswith('ExecReload=') and ' reload ' in line for line in unit))


@unittest.skipUnless(os.environ.get('CADDY_REAL_BINARY'), 'set CADDY_REAL_BINARY for real-binary checks')
class RealAdminTests(unittest.TestCase):
    @contextmanager
    def fixture(self, *, explicit=False, parent=None, runtime_name=None, uid=None, binary=None):
        binary = str(Path(binary or os.environ['CADDY_REAL_BINARY']).resolve(strict=True))
        context = (tempfile.TemporaryDirectory(prefix='caddy-admin-security-') if parent is None
                   else nullcontext(str(parent / runtime_name)))
        with context as directory:
            base = Path(directory)
            base.mkdir(mode=0o700, exist_ok=True)
            base.chmod(0o700)
            if uid is not None:
                os.chown(base, uid, uid)
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            endpoint = base / ('explicit.sock' if explicit else 'admin.sock')
            environment = os.environ | {
                'CADDY_ADMIN': 'unix/' + str(base / 'admin.sock'),
                'XDG_CONFIG_HOME': str(base / 'config'),
                'XDG_DATA_HOME': str(base / 'data'),
            }
            config = base / 'Caddyfile'
            prefix = '{\n    admin unix/' + str(endpoint) + '\n}\n' if explicit else ''

            def write(body):
                config.write_text(prefix + f'http://127.0.0.1:{port} {{\n    respond "{body}" 200\n}}\n')

            write('first')
            with (base / 'server.log').open('w+') as output:
                identity = {} if uid is None else {'user': uid, 'group': uid, 'extra_groups': []}
                process = subprocess.Popen([binary, 'run', '--config', str(config), '--adapter', 'caddyfile'],
                                           env=environment, stdout=output, stderr=output, **identity)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        if process.poll() is not None:
                            output.seek(0)
                            self.fail('Caddy startup failed: ' + output.read())
                        try:
                            with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=0.5) as response:
                                if response.read() == b'first' and endpoint.exists():
                                    break
                        except OSError:
                            pass
                        if time.monotonic() > deadline:
                            self.fail('Caddy fixture did not become ready')
                        time.sleep(0.05)
                    yield binary, base, port, endpoint, config, environment, write
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()

    def reload_and_check(self, fixture):
        binary, base, port, endpoint, config, environment, write = fixture
        self.assertTrue(stat.S_ISSOCK(endpoint.stat().st_mode))
        write('second')
        result = subprocess.run([binary, 'reload', '--config', str(config), '--adapter', 'caddyfile', '--force'],
                                env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=2) as response:
            self.assertEqual(response.read(), b'second')

    def test_environment_default_is_used_by_run_and_reload_without_a_tcp_admin_listener(self):
        # Reserve the old TCP endpoint without listening. Startup would fail if
        # Caddy ignored the private default and tried to bind localhost:2019.
        with socket.socket() as old_endpoint:
            old_endpoint.bind(('127.0.0.1', 2019))
            with self.fixture() as fixture:
                self.reload_and_check(fixture)
                with self.assertRaises(OSError):
                    socket.create_connection(('127.0.0.1', 2019), timeout=0.2)

    def test_explicit_existing_admin_address_still_controls_run_and_reload(self):
        with self.fixture(explicit=True) as fixture:
            self.assertFalse((fixture[1] / 'admin.sock').exists())
            self.reload_and_check(fixture)

    @unittest.skipUnless(os.geteuid() == 0, 'a distinct unprivileged UID requires isolated root execution')
    def test_another_unprivileged_uid_cannot_connect_to_the_private_admin_socket(self):
        with self.fixture() as fixture:
            endpoint = fixture[3]
            code = ('import os,socket,sys; assert os.geteuid()==65534; '
                    's=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])')
            result = subprocess.run([sys.executable, '-c', code, str(endpoint)],
                                    user=65534, group=65534, extra_groups=[],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('PermissionError', result.stderr)
            self.assertIn('Permission denied', result.stderr)

    @unittest.skipUnless(os.geteuid() == 0, 'dual service ownership requires isolated root execution')
    def test_generic_and_native_services_keep_separate_owned_admin_namespaces(self):
        generic = (ROOT / 'deploy/caddy.service').read_text()
        native = subprocess.check_output(['bash', '-c', 'source "$1"; cr_unit_text', 'admin-test',
                                         str(ROOT / 'install-caddy-network-relay-native-build-cloudflare-dns.sh')],
                                        text=True)

        def field(text, key):
            return next(line.split('=', 1)[1] for line in text.splitlines() if line.startswith(key + '='))

        generic_name = field(generic, 'RuntimeDirectory')
        native_name = field(native, 'RuntimeDirectory')
        self.assertNotEqual(field(generic, 'User'), field(native, 'User'))
        self.assertNotEqual(generic_name, native_name)
        with tempfile.TemporaryDirectory(prefix='caddy-dual-admin-') as directory:
            base = Path(directory)
            base.chmod(0o755)
            binary = base / 'caddy-executable'
            shutil.copyfile(os.environ['CADDY_REAL_BINARY'], binary)
            binary.chmod(0o755)
            with self.fixture(parent=base, runtime_name=generic_name, uid=65533, binary=binary) as first:
                with self.fixture(parent=base, runtime_name=native_name, uid=65534, binary=binary) as second:
                    for own, other, uid in [(first, second, 65533), (second, first, 65534)]:
                        self.assertEqual(own[1].stat().st_uid, uid)
                        self.assertEqual(stat.S_IMODE(own[1].stat().st_mode), 0o700)
                        code = 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])'
                        allowed = subprocess.run([sys.executable, '-c', code, str(own[3])],
                                                 user=uid, group=uid, extra_groups=[],
                                                 capture_output=True, text=True, timeout=10)
                        self.assertEqual(allowed.returncode, 0, allowed.stderr)
                        denied = subprocess.run([sys.executable, '-c', code, str(other[3])],
                                                user=uid, group=uid, extra_groups=[],
                                                capture_output=True, text=True, timeout=10)
                        self.assertNotEqual(denied.returncode, 0)
                        self.assertIn('PermissionError', denied.stderr)
                        own[6]('second')
                        reloaded = subprocess.run([str(binary), 'reload', '--config', str(own[4]),
                                                   '--adapter', 'caddyfile', '--force'],
                                                  env=own[5], user=uid, group=uid, extra_groups=[],
                                                  capture_output=True, text=True, timeout=15)
                        self.assertEqual(reloaded.returncode, 0, reloaded.stderr)
                        with urllib.request.urlopen(f'http://127.0.0.1:{own[2]}/', timeout=2) as response:
                            self.assertEqual(response.read(), b'second')
                    with urllib.request.urlopen(f'http://127.0.0.1:{first[2]}/', timeout=2) as response:
                        self.assertEqual(response.read(), b'second')
                # Stopping the native instance must leave the generic listener usable.
                self.assertTrue(first[3].exists())
                with urllib.request.urlopen(f'http://127.0.0.1:{first[2]}/', timeout=2) as response:
                    self.assertEqual(response.read(), b'second')


if __name__ == '__main__':
    unittest.main()
