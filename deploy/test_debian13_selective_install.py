#!/usr/bin/env python3
"""Test the selective Debian installer in a scratch directory.

Native Caddy profile generation and configuration adaptation run for real.
System installation, runtime validation, and network readiness use stubs.
Run: python3 deploy/test_debian13_selective_install.py
Optionally reuse a built binary with RELAY_TEST_CADDY=/path/to/caddy.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import tempfile
import unittest

SRC = Path(__file__).resolve().parent.parent
BINARY = None
BUILD_DIRECTORY = None
spec = importlib.util.spec_from_file_location('upstream_installer_tests', SRC / 'deploy/test_install.py')
upstream = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upstream)
upstream.SRC = SRC
upstream.INSTALL = SRC / 'deploy/install-debian13-selective.sh'
upstream.FAKE_CADDY = r'''#!/bin/sh
echo "caddy $*" >> "$LOG"
case "$1 $2" in
  "validate --config") [ -n "$FAKE_INVALID" ] && exit 1; exit 0 ;;
  "network-relay check")
    cat > "$STATE/check-stdin"
    if [ -n "$FAKE_H3_FAILS" ]; then echo 'FAIL HTTP/3 connect timed out'; else echo 'ok   HTTP/3 TCP example.com:80 HTTP/1.1 200 OK'; fi
    if [ -n "$FAKE_H2_FAILS" ]; then
      echo 'FAIL HTTP/2 UDP 1.1.1.1:53 timeout'
    else
      echo 'ok   HTTP/2 TCP example.com:80 HTTP/1.1 200 OK'
      echo 'ok   HTTP/2 UDP 1.1.1.1:53 valid DNS answer'
    fi
    if [ -n "$FAKE_AUTH_FAILS" ]; then echo 'FAIL no password: refused tunnel opened'; else echo 'ok   no password: refused 405 Method Not Allowed'; fi
    [ -n "$FAKE_H3_FAILS$FAKE_H2_FAILS$FAKE_AUTH_FAILS" ] && exit 1
    exit 0 ;;
  "network-relay profile")
    [ -n "$FAKE_PROFILE_FAILS" ] && { echo 'profile generation failed' >&2; exit 1; } ;;
esac
exec "$REAL_CADDY" "$@"
'''


def setUpModule():
    global BINARY, BUILD_DIRECTORY
    provided = os.environ.get('RELAY_TEST_CADDY')
    if provided:
        BINARY = Path(provided).resolve(strict=True)
        if not BINARY.is_file():
            raise ValueError('RELAY_TEST_CADDY must name a built Caddy binary.')
    else:
        BUILD_DIRECTORY = tempfile.TemporaryDirectory(prefix='selective-installer-build-')
        BINARY = Path(BUILD_DIRECTORY.name) / 'caddy'
        subprocess.run([os.environ.get('GO', 'go'), 'build', '-buildvcs=false', '-tags', 'http2legacy',
                        '-o', str(BINARY), './cmd/caddy'], cwd=SRC, check=True)
    upstream.REAL_CADDY = BINARY


def tearDownModule():
    if BUILD_DIRECTORY is not None:
        BUILD_DIRECTORY.cleanup()


class SelectiveInstallTest(unittest.TestCase):
    # Reuse only upstream harness helpers, not tests for the different installer.
    install = upstream.InstallTest.install
    path = upstream.InstallTest.path
    calls = upstream.InstallTest.calls
    files = upstream.InstallTest.files

    def setUp(self):
        upstream.InstallTest.setUp(self)
        (self.dir / 'os-release-default').write_text('ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian 13"\n')
        # Record bootstrap package calls, which must precede curl use.
        Path(self.env['PATH'].split(':')[0], 'apt-get').write_text('#!/bin/sh\necho "apt-get $*" >> "$LOG"\nexit 0\n')
        curl = Path(self.env['PATH'].split(':')[0], 'curl')
        curl.write_text('#!/bin/sh\necho "curl $*" >> "$LOG"\ncase "$*" in *ipify*|*ifconfig.me*) echo "$FAKE_IP" ;; *) exit 2 ;; esac\n')

    def fresh(self, *args, **env):
        return self.install('--domain', 'Relay.Example.COM', '--user', 'iphone', '--email', 'me@example.org', '--no-gfwlist', '--no-service-rules', *args, **env)

    def read_profile(self):
        path = self.path('/etc/caddy/relay/relay.example.com-iphone.mobileconfig')
        return path, plistlib.loads(path.read_bytes())['PayloadContent'][0]

    def assert_no_deployment(self):
        for path in ['/etc/caddy/Caddyfile', '/usr/local/bin/caddy', '/etc/systemd/system/caddy.service', '/etc/caddy/relay/relay.example.com-iphone.mobileconfig']:
            self.assertFalse(self.path(path).exists(), path)
        self.assertNotIn('systemctl restart caddy', self.calls())

    def test_selective_fresh_debian13(self):
        result = self.fresh()
        path, payload = self.read_profile()
        relay = payload['Relays'][0]
        self.assertEqual(relay['HTTP2RelayURL'], 'https://relay.example.com/.well-known/masque/udp/{target_host}/{target_port}/')
        self.assertNotIn('HTTP3RelayURL', relay)
        self.assertTrue(payload['MatchDomains'])
        self.assertEqual(payload['ExcludedDomains'], ['relay.example.com'])
        self.assertIs(payload['UIToggleEnabled'], True)
        self.assertEqual(sorted(p.name for p in path.parent.iterdir()), [path.name])
        actual_domains = json.loads(self.path('/var/cache/caddy-network-relay/selected-domains.json').read_text())
        self.assertEqual(payload['MatchDomains'], actual_domains)
        self.assertIn('google.com', actual_domains)
        self.assertNotIn('relay.example.com', actual_domains)
        user, secret = base64.b64decode(relay['AdditionalHTTPHeaderFields']['Authorization'].split()[1]).decode().split(':', 1)
        self.assertEqual(user, 'iphone')
        self.assertEqual(len(secret), 24)
        self.assertNotIn(secret, result.stdout + result.stderr + self.calls())
        self.assertNotIn('--password ' + secret, self.calls())
        self.assertEqual((self.state / 'check-stdin').read_text(), secret + '\n')
        self.assertIn('-buildvcs=false', self.calls())
        self.assertIn('-tags http2legacy', self.calls())
        self.assertLess(self.calls().index('install -y'), self.calls().index('curl '))
        self.assertLess(self.calls().index('validate --config'), self.calls().index('systemctl restart caddy'))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path('/etc/caddy').stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.path('/etc/caddy/Caddyfile').stat().st_mode), 0o640)
        config = self.path('/etc/caddy/Caddyfile')
        a = subprocess.run([str(BINARY), 'adapt', '--config', str(config), '--adapter', 'caddyfile'], capture_output=True, text=True)
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertIn('"handler":"network_relay"', a.stdout)
        self.assertIn('authenticated HTTP/2 TCP and UDP checks passed', result.stdout)

    def test_native_build_ignores_ambient_cross_target_and_workspace(self):
        self.fresh(CDPATH='.', GOOS='darwin', GOARCH='arm64', GOWORK='/missing-workspace', CHECK_NATIVE_BUILD_ENV='1')

    def test_http3_failure_is_diagnostic(self):
        result = self.fresh(FAKE_H3_FAILS='1')
        self.assertIn('HTTP/2 TCP', result.stdout)
        self.assertIn('HTTP/2 UDP', result.stdout)
        self.assertTrue(self.path('/usr/local/bin/caddy').exists())

    def test_http2_failure_is_not_success(self):
        result = self.fresh(ok=False, FAKE_H2_FAILS='1')
        self.assertIn('readiness checks did not pass', result.stdout)
        self.assertNotIn('Done: Caddy', result.stdout)
        self.assertTrue(self.path('/usr/local/bin/caddy').exists())
        self.assertTrue((self.state / 'active-caddy').exists())
        self.read_profile()

    def test_auth_failure_is_not_success(self):
        result = self.fresh(ok=False, FAKE_AUTH_FAILS='1')
        self.assertIn('readiness checks did not pass', result.stdout)
        self.assertNotIn('Done: Caddy', result.stdout)

    def test_existing_files_and_symlinks_refused(self):
        for target in ['/etc/caddy/Caddyfile', '/usr/local/bin/caddy', '/etc/systemd/system/caddy.service']:
            with self.subTest(target=target):
                path = self.path(target)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('original')
                result = self.fresh(ok=False)
                self.assertIn('installation already exists', result.stderr)
                self.assertEqual(path.read_text(), 'original')
                path.unlink()
        self.path('/etc/caddy/Caddyfile').symlink_to('/missing/example')
        result = self.fresh(ok=False)
        self.assertIn('installation already exists', result.stderr)

    def test_wrong_os_and_conflicts_refused(self):
        release = self.dir / 'debian12'
        release.write_text('ID=debian\nVERSION_ID="12"\n')
        self.fresh(ok=False, RELAY_TEST_OS_RELEASE=str(release))
        self.fresh(ok=False, FAKE_APT_CADDY='1')
        (self.state / 'active-network-relay').touch()
        self.fresh(ok=False)
        (self.state / 'active-network-relay').unlink()
        self.fresh(ok=False, FAKE_SS='tcp LISTEN 0 4096 *:443 *:* users:(("other",pid=1,fd=3))')
        self.assert_no_deployment()

    def test_empty_base_leaves_no_config(self):
        empty = self.dir / 'empty.txt'
        empty.write_text('# no domains\n')
        result = self.fresh('--domains', str(empty), ok=False)
        self.assertIn('base domain list is empty', result.stderr)
        self.assert_no_deployment()

    def test_missing_service_source_leaves_no_config(self):
        rules = self.dir / 'rules'
        rules.mkdir()
        result = self.install('--domain', 'relay.example.com', '--no-gfwlist', '--rules-dir', str(rules), ok=False)
        self.assertIn('No partial profile', result.stderr)
        self.assert_no_deployment()

    def test_profile_and_config_failure_cleanup(self):
        self.fresh(ok=False, FAKE_PROFILE_FAILS='all')
        self.assert_no_deployment()
        self.fresh(ok=False, FAKE_INVALID='1')
        self.assert_no_deployment()
        self.assertEqual(list(self.path('/etc/caddy').glob('.Caddyfile.*')), [])

    def test_start_failure_rolls_back_and_retry_works(self):
        self.fresh(ok=False, FAKE_START_FAILS='exit')
        self.assert_no_deployment_files_only()
        self.assertFalse((self.state / 'active-caddy').exists())
        self.assertFalse((self.state / 'enabled-caddy').exists())
        self.fresh()

    def test_early_unit_install_failure_rolls_back_without_unit(self):
        bindir = Path(self.env['PATH'].split(':')[0])
        stub = bindir / 'install'
        # Fail before creating the service unit; the default systemctl stub
        # rejects stop/disable for absent units to reproduce real systemd.
        stub.write_text('#!/bin/sh\ncase "$*" in\n *caddy.service*) exit 1 ;;\nesac\nexec /usr/bin/install "$@"\n')
        stub.chmod(0o755)
        systemctl = bindir / 'systemctl'
        original = systemctl.read_text()
        systemctl.write_text(original.replace('#!/bin/sh\n', '#!/bin/sh\ncase "$1 $2" in\n "stop caddy"|"disable caddy") [ -e "$RELAY_TEST_ROOT/etc/systemd/system/caddy.service" ] || exit 5 ;;\nesac\n', 1))
        result = self.fresh(ok=False)
        self.assertIn('new service, configuration, binary and profile were removed', result.stderr)
        self.assertNotIn('rollback was incomplete', result.stderr)
        self.assert_no_deployment_files_only()
        self.assertFalse((self.state / 'active-caddy').exists())
        self.assertNotIn('systemctl stop caddy', self.calls())
        stub.unlink()
        systemctl.write_text(original)
        self.fresh()

    def assert_no_deployment_files_only(self):
        for path in ['/etc/caddy/Caddyfile', '/usr/local/bin/caddy', '/etc/systemd/system/caddy.service', '/etc/caddy/relay/relay.example.com-iphone.mobileconfig']:
            self.assertFalse(self.path(path).exists(), path)

    def test_invalid_uploaded_binary_not_executed(self):
        supplied = self.dir / 'uploaded'
        supplied.write_text('#!/bin/sh\necho BINARY_EXECUTED > ' + str(self.dir / 'executed') + '\n')
        supplied.chmod(0o755)
        result = self.fresh('--binary', str(supplied), ok=False)
        self.assertIn('Expected a Linux x86_64 ELF', result.stderr)
        self.assertFalse((self.dir / 'executed').exists())
        self.assert_no_deployment()

    def test_all18_local_rules(self):
        rules = self.dir / 'rules'
        rules.mkdir()
        names = ('Cloudflare', 'Gemini', 'OpenAI', 'Anthropic', 'Google', 'GitHub', 'Twitter', 'Jsdelivr', 'Pandora', 'Spotify', 'Reddit', 'Discord', 'iCloudPrivateRelay', 'Claude', 'AppleNews', 'AppleProxy', 'TikTok', 'TigerFintech')
        for name in names:
            (rules / (name + '.yaml')).write_text('payload:\n - DOMAIN-SUFFIX,' + name.lower() + '.example\n')
        self.install('--domain', 'relay.example.com', '--no-gfwlist', '--rules-dir', str(rules))
        _, payload = self.read_profile()
        for name in names:
            self.assertIn(name.lower() + '.example', payload['MatchDomains'])

    def test_profile_size_bound(self):
        domains = self.dir / 'huge-base.txt'
        # Distinct registered roots prevent normalization collapsing the input.
        domains.write_text(''.join('d%05dexamplelongroot.com\n' % n for n in range(17000)))
        result = self.fresh('--domains', str(domains), ok=False)
        self.assertIn('524288', result.stderr)
        self.assert_no_deployment()


if __name__ == '__main__':
    unittest.main(verbosity=2)
