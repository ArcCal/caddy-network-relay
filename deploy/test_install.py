#!/usr/bin/env python3
"""Tests deploy/install.sh in a scratch directory.

System commands (apt-get, systemctl, ss, curl, ...) are replaced by stubs
that record their calls; the Caddy binary is the real one built from this
source, except that `validate` and `network-relay check` (which need a
running system) are simulated. Run: python3 deploy/test_install.py
"""

import base64
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tempfile
import unittest

SRC = Path(__file__).resolve().parent.parent
INSTALL = SRC / 'deploy/install.sh'
REAL_CADDY = None
SOURCE_FIXTURE = None

STUBS = {
    'git': 'for arg in "$@"; do shift; [ "$arg" != protocol.file.allow=never ] || arg=protocol.file.allow=always; set -- "$@" "$arg"; done; exec "$REAL_GIT" -c "url.file://$SOURCE_FIXTURE.insteadOf=https://github.com/ArcCal/caddy-network-relay.git" "$@"',
    'stat': 'case "$*" in "-f -c %T "*) echo ext2/ext3 ;; *) exec "$REAL_STAT" "$@" ;; esac',
    'df': 'printf "Filesystem 1024-blocks Used Available Capacity Mounted\\nfixture 30000000 0 30000000 0%%%% /\\n"',
    'apt-get': 'exit 0',
    'dpkg': '[ -n "$FAKE_APT_CADDY" ] && exit 0; exit 1',
    'systemctl': r'''
echo "systemctl $*" >> "$LOG"
case "$1 $2" in
  "is-active --quiet")
    unit=$3
    [ -e "$STATE/active-$unit" ] && exit 0; exit 3 ;;
  "is-enabled --quiet") [ -e "$STATE/enabled-$3" ] && exit 0; exit 1 ;;
  "enable caddy"|"enable network-relay") touch "$STATE/enabled-$2" ;;
  "disable caddy"|"disable network-relay") rm -f "$STATE/enabled-$2" ;;
  "stop caddy") rm -f "$STATE/active-caddy" ;;
  "restart caddy")
    # FAKE_START_FAILS: the service is not running afterwards; "exit" makes
    # restart itself fail too, as it does for a Type=notify unit.
    if [ -n "$FAKE_START_FAILS" ] && { [ -z "$FAKE_START_FAILS_ONCE" ] || [ ! -e "$STATE/start-failed-once" ]; }; then
      touch "$STATE/start-failed-once"
      rm -f "$STATE/active-caddy"
      [ "$FAKE_START_FAILS" = exit ] && exit 1
      exit 0
    fi
    touch "$STATE/active-caddy" ;;
  "restart network-relay") touch "$STATE/active-network-relay" ;;
  "disable --now")
    rm -f "$STATE/active-$3" "$STATE/enabled-$3" ;;
esac
exit 0''',
    'journalctl': 'exit 0',
    'ss': 'printf "%s\\n" "$FAKE_SS"',
    'curl': r'''
case "$*" in
  *ipify*|*ifconfig.me*) echo "$FAKE_IP" ;;
  *) exec /usr/bin/curl "$@" ;;
esac''',
    'getent': r'''
case "$1" in
  ahostsv4) [ -n "$FAKE_DNS" ] && echo "$FAKE_DNS   STREAM $2"; exit 0 ;;
  passwd) [ -e "$STATE/user-caddy" ] && exit 0; exit 2 ;;
esac''',
    'adduser': 'touch "$STATE/user-caddy"; echo "adduser $*" >> "$LOG"',
    'runuser': 'shift 3; exec "$@"',  # runuser -u caddy -- cmd...
    'chown': 'exit 0',
    'sysctl': r'''
if [ "$1" = -n ]; then
  case "$2" in
    net.core.rmem_max) echo "${FAKE_SYSCTL_RMEM:-212992}" ;;
    net.core.wmem_max) echo "${FAKE_SYSCTL_WMEM:-212992}" ;;
  esac
fi
exit 0''',
    'tailscale': 'echo 100.64.0.7',
}

FAKE_CADDY = r'''#!/bin/sh
# The real binary, except for the parts that need a running system.
case "$1 $2" in
  "build-info ")
    "$REAL_CADDY" build-info | awk -F '\t' -v missing="${FAKE_MISSING_REPLACEMENT:-}" -v version="${FAKE_BUILD_GO_VERSION:-}" -v missing_tag="${FAKE_MISSING_TLS_POLICY:-}" -v tags="${FAKE_BUILD_TAGS:-http2legacy,relay_tls9846_v1}" '
      BEGIN { OFS="\t" }
      drop { drop=0; if ($1 == "=>") next }
      ($1 == "dep" || $1 == "mod") && $2 == missing { drop=1 }
      $1 == "go" && version != "" { $2=version }
      $1 == "build" && $2 ~ /^-tags=/ { seen_tag=1; if (missing_tag != "") next; $2="-tags=" tags }
      { print }
      END { if (!seen_tag && missing_tag == "") print "build", "-tags=" tags }
    '
    exit ;;
  "validate --config") echo "validate" >> "$LOG"; [ -n "$FAKE_INVALID" ] && exit 1; exit 0 ;;
  "network-relay check") cat > "$STATE/check-stdin"; echo "check $*" >> "$LOG"; [ -n "$FAKE_CHECK_FAILS" ] && { echo "FAIL HTTP/3"; exit 1; }; echo "all checks passed"; exit 0 ;;
  "network-relay profile")
    if [ "$FAKE_PROFILE_FAILS" = all ] || { [ "$FAKE_PROFILE_FAILS" = global ] && case "$*" in *global*) true ;; *) false ;; esac; }; then
      echo "profile generation failed" >&2
      exit 1
    fi ;;
esac
# A module list longer than a pipe buffer, with network_relay first (or,
# with "missing", not at all).
if [ "$1" = list-modules ] && [ -n "$FAKE_LONG_MODULES" ]; then
  exec awk -v first="$FAKE_LONG_MODULES" 'BEGIN {
    if (first != "missing") print "http.handlers.network_relay"
    for (i = 0; i < 200000; i++) print "other.module." i
  }'
fi
exec "$REAL_CADDY" "$@"
'''

FAKE_GO = r'''#!/bin/sh
# go build ... -o OUT ./cmd/caddy; the source must be a fresh checkout.
case "$PWD" in /tmp/????????-??????.*/source) ;; *) exit 94 ;; esac
[ -z "${GOCACHEPROG:-}" ] || exit 95
if [ -n "$CHECK_NATIVE_BUILD_ENV" ]; then
  [ "$GOOS" = linux ] && [ "$GOARCH" = amd64 ] && [ "$GOWORK" = off ] || exit 93
fi
echo "go $*" >> "$LOG"
if [ "$1 $2" = "env GOROOT" ]; then printf '%s\n' "$FAKE_INSTALLED_GOROOT"; exit 0; fi
while [ $# -gt 0 ]; do
  if [ "$1" = -o ]; then cp "$FAKE_CADDY_SCRIPT" "$2"; chmod 755 "$2"; fi
  shift
done
'''


def source_fixture():
    global SOURCE_FIXTURE
    if SOURCE_FIXTURE is None or not Path(SOURCE_FIXTURE.name).exists():
        SOURCE_FIXTURE = tempfile.TemporaryDirectory(prefix='caddy-source-fixture-')
        unittest.addModuleCleanup(SOURCE_FIXTURE.cleanup)
        source = Path(SOURCE_FIXTURE.name) / 'source'
        shutil.copytree(SRC, source, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
        (source / 'deploy/go-tls/prepare.py').write_text("import os, pathlib, sys\nroot, output = map(pathlib.Path, sys.argv[1:])\nassert str(root) == os.environ['FAKE_INSTALLED_GOROOT']\noutput.mkdir(parents=True, exist_ok=True)\nprint(output)\n")
        subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', 'init', '--template=', '-q', '-b', 'main', str(source)], check=True)
        subprocess.run(['git', '-C', str(source), 'add', '.'], check=True)
        environment = os.environ | {'GIT_AUTHOR_NAME': 'Anonymous', 'GIT_AUTHOR_EMAIL': 'anonymous@example.invalid',
                                     'GIT_COMMITTER_NAME': 'Anonymous', 'GIT_COMMITTER_EMAIL': 'anonymous@example.invalid'}
        subprocess.run(['git', '-C', str(source), '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
                        'commit', '-qm', 'Source fixture'], env=environment, check=True)
    return str(Path(SOURCE_FIXTURE.name) / 'source')


def setUpModule():
    global REAL_CADDY
    supplied = os.environ.get('CADDY_REAL_BINARY')
    if supplied:
        REAL_CADDY = Path(supplied).resolve(strict=True)
    else:
        temporary = tempfile.TemporaryDirectory(prefix='caddy-installer-test-build-')
        unittest.addModuleCleanup(temporary.cleanup)
        out = Path(temporary.name) / 'caddy'
        subprocess.run(['go', 'build', '-tags', 'http2legacy,relay_tls9846_v1', '-o', str(out), './cmd/caddy'], cwd=SRC, check=True)
        REAL_CADDY = out


class InstallTest(unittest.TestCase):
    def test_native_build_ignores_ambient_cross_target_and_workspace(self):
        self.install('--domain', 'relay.example.com', '--no-gfwlist',
                     CDPATH='.', GOOS='darwin', GOARCH='arm64', GOWORK='/missing-workspace',
                     GOCACHEPROG='/missing-cache-program', CHECK_NATIVE_BUILD_ENV='1')

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.root = self.dir / 'root'
        self.root.mkdir()
        self.state = self.dir / 'state'
        self.state.mkdir()
        self.log = self.dir / 'calls.log'
        self.log.touch()
        bin_dir = self.dir / 'bin'
        bin_dir.mkdir()
        for name, body in STUBS.items():
            p = bin_dir / name
            p.write_text('#!/bin/sh\n' + body + '\n')
            p.chmod(0o755)
        (self.dir / 'os-release-default').write_text('ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04"\n')
        self.fake_caddy = self.dir / 'fake-caddy'
        self.fake_caddy.write_text(FAKE_CADDY)
        self.fake_caddy.chmod(0o755)
        fake_go = self.dir / 'fake-go'
        fake_go.write_text(FAKE_GO)
        fake_go.chmod(0o755)
        self.env = {
            'PATH': f'{bin_dir}:{os.environ["PATH"]}',
            'SOURCE_FIXTURE': source_fixture(),
            'REAL_GIT': shutil.which('git'), 'REAL_STAT': shutil.which('stat'),
            'HOME': str(self.dir),
            'RELAY_TEST_ROOT': str(self.root),
            'RELAY_TEST_GO': str(fake_go),
            'FAKE_CADDY_SCRIPT': str(self.fake_caddy),
            'FAKE_INSTALLED_GOROOT': str(self.dir / 'installed-go'),
            'REAL_CADDY': str(REAL_CADDY),
            'LOG': str(self.log),
            'STATE': str(self.state),
            'FAKE_IP': '203.0.113.9',
            'FAKE_DNS': '203.0.113.9',
            'FAKE_SS': '',
            'RELAY_TEST_OS_RELEASE': str(self.dir / 'os-release-default'),
            'RELAY_TEST_SLEEP': '0',
            'RELAY_TEST_TRIES': '2',
        }

    def install(self, *args, ok=True, **env):
        e = dict(self.env, **env)
        r = subprocess.run(['bash', str(INSTALL.relative_to(SRC)), *args], cwd=SRC, env=e, capture_output=True, text=True, timeout=120)
        if ok is not None and (r.returncode == 0) != ok:
            self.fail(f'exit {r.returncode}\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}')
        return r

    def path(self, p):
        return self.root / p.lstrip('/')

    def calls(self):
        return self.log.read_text()

    def files(self):
        # The private runtime lock is coordination state, not a deployment file.
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*')
                      if p.is_file() and 'run/caddy-network-relay-install/' not in str(p.relative_to(self.root)))

    def fresh(self, *args, **env):
        return self.install('--domain', 'Relay.Example.COM', '--user', 'iphone', '--no-gfwlist', *args, **env)

    def test_fresh_install(self):
        r = self.fresh('--email', 'me@example.org')
        caddyfile = self.path('/etc/caddy/Caddyfile').read_text()
        self.assertIn('# domain: relay.example.com', caddyfile)
        self.assertIn('relay.example.com, :443 {', caddyfile)
        self.assertIn('email me@example.org', caddyfile)
        # A generated password gets the fast hash.
        self.assertRegex(caddyfile, r'user iphone \$pbkdf2-sha256\$i=1000,l=32\$\S+\$\S+')
        # The generated Caddyfile is valid for the real adapter.
        a = subprocess.run([str(REAL_CADDY), 'adapt', '--config', str(self.path('/etc/caddy/Caddyfile'))],
                           capture_output=True, text=True)
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertIn('"handler":"network_relay"', a.stdout)

        # The password is in the profiles and nowhere else on the server.
        profile = plistlib.loads(self.path('/etc/caddy/relay/relay.example.com-iphone.mobileconfig').read_bytes())
        basic = profile['PayloadContent'][0]['Relays'][0]['AdditionalHTTPHeaderFields']['Authorization']
        user, password = base64.b64decode(basic.split()[1]).decode().split(':', 1)
        self.assertEqual((user, len(password)), ('iphone', 24))
        self.assertEqual(sorted(p.name for p in self.path('/etc/caddy/relay').iterdir()),
                         ['relay.example.com-iphone-global.mobileconfig', 'relay.example.com-iphone.mobileconfig'])
        for f in self.files():
            if not f.endswith('.mobileconfig'):
                self.assertNotIn(password.encode(), self.path(f).read_bytes(), f)
        self.assertEqual(stat.S_IMODE(self.path('/etc/caddy/relay').stat().st_mode), 0o700)
        self.assertNotIn(password, r.stdout + r.stderr, 'the password is never printed')
        self.assertEqual((self.state / 'check-stdin').read_text(), password + '\n', 'the self-check gets it on stdin')

        for name, toggle in [('relay.example.com-iphone.mobileconfig', None),
                             ('relay.example.com-iphone-global.mobileconfig', False)]:
            p = self.path('/etc/caddy/relay/' + name)
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            payload = plistlib.loads(p.read_bytes())['PayloadContent'][0]
            relay = payload['Relays'][0]
            self.assertEqual(relay['HTTP3RelayURL'],
                             'https://relay.example.com/.well-known/masque/udp/{target_host}/{target_port}/')
            self.assertIn(password.encode(), base64.b64decode(
                relay['AdditionalHTTPHeaderFields']['Authorization'].split()[1]))
            self.assertEqual(payload.get('UIToggleEnabled'), toggle)
            self.assertEqual(payload['ExcludedDomains'], ['relay.example.com'])
            self.assertIn('google.com', payload['MatchDomains'])
        global_domains = plistlib.loads(self.path(
            '/etc/caddy/relay/relay.example.com-iphone-global.mobileconfig').read_bytes())['PayloadContent'][0]['MatchDomains']
        self.assertIn('spotify.com', global_domains)

        self.assertTrue(self.path('/usr/local/bin/caddy').exists())
        unit = self.path('/etc/systemd/system/caddy.service').read_text()
        self.assertIn('ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile', unit)
        self.assertNotIn('--environ', unit)
        self.assertNotIn('CAP_NET_ADMIN', unit)
        self.assertIn('relay_id relay.example.com', self.path('/etc/caddy/Caddyfile').read_text())
        self.assertIn('GODEBUG=http2xconnect=1', unit)
        self.assertIn('RuntimeDirectory=caddy', unit.splitlines())
        self.assertIn('RuntimeDirectoryMode=0700', unit)
        self.assertIn('Environment=CADDY_ADMIN=unix//run/caddy/admin.sock', unit.splitlines())
        self.assertIn('net.core.rmem_max = 7500000', self.path('/etc/sysctl.d/60-caddy-network-relay.conf').read_text())
        self.assertTrue(self.path('/var/www/relay/index.html').exists())
        calls = self.calls()
        self.assertIn('relay_tls9846_v1', self.calls())
        self.assertIn('-tags http2legacy', calls)
        self.assertIn('systemctl enable caddy', calls)
        self.assertIn('systemctl restart caddy', calls)
        self.assertIn('adduser --system --group --home /var/lib/caddy', calls)
        self.assertIn('check network-relay check --server relay.example.com --address 127.0.0.1 --user iphone', calls)
        self.assertIn('scp root@100.64.0.7:', r.stdout)

    def test_upgrade_keeps_everything(self):
        self.fresh()
        caddyfile = self.path('/etc/caddy/Caddyfile').read_text()
        profile = self.path('/etc/caddy/relay/relay.example.com-iphone-global.mobileconfig').read_bytes()
        self.log.write_text('')
        self.path('/usr/local/bin/caddy').write_text('old binary')
        # An upgrade needs no DNS: here the domain no longer resolves.
        r = self.install(FAKE_DNS='', FAKE_SS='tcp LISTEN 0 4096 *:443 *:* users:(("caddy",pid=1,fd=3))')
        self.assertEqual(self.path('/etc/caddy/Caddyfile').read_text(), caddyfile)
        self.assertEqual(self.path('/etc/caddy/relay/relay.example.com-iphone-global.mobileconfig').read_bytes(), profile)
        # Without the password, the self-check is left to the operator.
        self.assertNotIn('network-relay check', self.calls())
        self.assertIn('does not keep the password', r.stdout)
        self.assertIn('network-relay check --server relay.example.com --address 127.0.0.1 --user iphone', r.stdout)
        self.assertNotEqual(self.path('/usr/local/bin/caddy').read_text(), 'old binary')
        self.assertNotIn('adduser', self.calls())
        # Same domain and user may be given again; different ones are refused.
        self.install('--domain', 'relay.example.com', '--user', 'iphone')
        r = self.install('--domain', 'other.example.com', ok=False)
        self.assertIn('cannot be changed to other.example.com', r.stderr)
        r = self.install('--user', 'ipad', ok=False)
        self.assertIn('User iphone already exists', r.stderr)

    def test_upgrade_persists_runtime_udp_buffer_limits(self):
        self.fresh()
        self.install(FAKE_SYSCTL_RMEM='7500000', FAKE_SYSCTL_WMEM='12000000')
        persistent = self.path('/etc/sysctl.d/60-caddy-network-relay.conf').read_text()
        self.assertIn('net.core.rmem_max = 7500000', persistent)
        self.assertIn('net.core.wmem_max = 12000000', persistent)

    def test_failed_primary_profile_leaves_a_clean_retry(self):
        r = self.fresh(ok=False, FAKE_PROFILE_FAILS='all')
        self.assertIn('profile generation failed', r.stderr)
        self.assertFalse(self.path('/etc/caddy/Caddyfile').exists())
        self.assertFalse(self.path('/usr/local/bin/caddy').exists())
        self.assertFalse((self.state / 'active-caddy').exists())
        self.assertNotIn('systemctl restart caddy', self.calls())
        self.assertEqual(list(self.path('/etc/caddy/relay').glob('*.mobileconfig')), [])
        # Retry must generate a new account and credentials, not detect an
        # upgrade with an irrecoverable password and no device profile.
        self.fresh()
        self.assertTrue(self.path('/etc/caddy/relay/relay.example.com-iphone.mobileconfig').exists())

    def test_failed_global_profile_keeps_primary_credentials(self):
        stale = self.path('/etc/caddy/relay/relay.example.com-iphone-global.mobileconfig')
        stale.parent.mkdir(parents=True)
        stale.write_text('stale credentials')
        r = self.fresh(FAKE_PROFILE_FAILS='global')
        self.assertIn('primary profile contains the credentials', r.stdout)
        self.assertTrue((self.state / 'active-caddy').exists())
        self.assertFalse(stale.exists(), 'do not offer a leftover profile for different credentials')
        primary_path = self.path('/etc/caddy/relay/relay.example.com-iphone.mobileconfig')
        self.assertIn('scp root@100.64.0.7:' + str(primary_path), r.stdout)
        self.assertNotIn('scp root@100.64.0.7:' + str(stale), r.stdout)
        self.assertIn('Re-running the installer cannot regenerate', r.stdout)
        primary = plistlib.loads(primary_path.read_bytes())
        basic = primary['PayloadContent'][0]['Relays'][0]['AdditionalHTTPHeaderFields']['Authorization']
        self.assertEqual(base64.b64decode(basic.split()[1]).decode().split(':', 1)[1] + '\n',
                         (self.state / 'check-stdin').read_text())

    def test_refusals_change_nothing(self):
        cases = [
            ({}, ['--domain', 'relay.example.com'], {'FAKE_DNS': '198.51.100.1'}, 'does not point to this machine'),
            ({}, ['--domain', 'relay.example.com'], {'FAKE_DNS': ''}, 'has no DNS record yet'),
            ({}, ['--domain', 'relay.example.com'],
             {'FAKE_SS': 'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=9,fd=6))'}, 'in use by other programs'),
            ({}, ['--domain', 'relay.example.com'], {'FAKE_APT_CADDY': '1'}, 'apt caddy package'),
            ({}, [], {}, 'A first install needs a domain'),
            ({}, ['--domain', 'not a domain'], {}, 'is not a domain name'),
            ({}, ['--domain', 'relay.example.com', '--user', '.bad'], {}, 'User name .bad'),
            ({}, ['--domain', 'relay.example.com', '--email', 'nope'], {}, 'is not an email address'),
            ({'active-network-relay': ''}, ['--domain', 'relay.example.com'], {}, '--replace-network-relay'),
        ]
        for state, args, env, message in cases:
            with self.subTest(message):
                for f in self.state.iterdir():
                    f.unlink()
                for name in state:
                    (self.state / name).touch()
                r = self.install(*args, ok=False, **env)
                self.assertIn(message, r.stderr)
                self.assertEqual(self.files(), [], 'nothing was written')

    def test_supported_systems(self):
        for pretty, accepted in [
            ('ID=debian\nVERSION_ID="12"\n', True), ('ID=debian\nVERSION_ID="13"\n', True),
            ('ID=debian\nVERSION_ID="14"\n', True), ('ID=debian\n', True),  # testing/unstable
            ('ID=ubuntu\nVERSION_ID="22.04"\n', True), ('ID=ubuntu\nVERSION_ID="24.04"\n', True),
            ('ID=ubuntu\nVERSION_ID="26.04"\n', True), ('ID=ubuntu\nVERSION_ID="27.04"\n', True),
            ('ID=debian\nVERSION_ID="11"\n', False), ('ID=ubuntu\nVERSION_ID="20.04"\n', False),
            ('ID=fedora\nVERSION_ID="42"\n', False), ('ID=alpine\nVERSION_ID="3.21"\n', False),
        ]:
            with self.subTest(pretty.replace('\n', ' ')):
                osr = self.dir / 'os-release'
                osr.write_text(pretty + 'PRETTY_NAME="test system"\n')
                # A system that is refused stops before the DNS check; one that
                # is accepted goes on and fails at the missing domain.
                r = self.install(ok=False, RELAY_TEST_OS_RELEASE=str(osr))
                if accepted:
                    self.assertIn('A first install needs a domain', r.stderr)
                else:
                    self.assertIn('Only Debian 12 or newer', r.stderr)

    def test_foreign_caddyfile_is_left_alone(self):
        p = self.path('/etc/caddy/Caddyfile')
        p.parent.mkdir(parents=True)
        p.write_text('example.com {\n\trespond hi\n}\n')
        r = self.install('--domain', 'relay.example.com', ok=False)
        self.assertIn('was not generated by this script', r.stderr)
        self.assertEqual(p.read_text(), 'example.com {\n\trespond hi\n}\n')

    def test_replaces_the_rust_relay(self):
        (self.state / 'active-network-relay').touch()
        self.fresh('--replace-network-relay',
                   FAKE_SS='tcp LISTEN 0 4096 *:443 *:* users:(("network-relay",pid=7,fd=9))')
        self.assertIn('systemctl disable --now network-relay', self.calls())

    def test_failed_start_rolls_back(self):
        for how in ['inactive', 'exit']:
            with self.subTest(how):
                for f in self.state.iterdir():
                    f.unlink()
                shutil.rmtree(self.root)
                self.root.mkdir()
                self.log.write_text('')
                r = self.fresh(ok=False, FAKE_START_FAILS=how)
                self.assertIn('Install failed and was rolled back', r.stderr)
                self.assertFalse(self.path('/etc/caddy/Caddyfile').exists())
                self.assertFalse(self.path('/usr/local/bin/caddy').exists())
                self.assertEqual(list(self.path('/etc/caddy/relay').glob('*.mobileconfig')), [],
                                 'remove profiles for the rolled-back account before retry')
                self.assertIn('systemctl stop caddy', self.calls())
                self.assertIn('systemctl disable caddy', self.calls())
                # A later run is a fresh install again.
                self.fresh()
                self.assertTrue(self.path('/etc/caddy/Caddyfile').exists())

    def test_failed_upgrade_restores_the_old_binary(self):
        self.fresh()
        for how in ['inactive', 'exit']:
            with self.subTest(how):
                self.path('/usr/local/bin/caddy').write_text('#!/bin/sh\necho old\n')
                (self.state / 'start-failed-once').unlink(missing_ok=True)
                r = self.install(ok=False, FAKE_START_FAILS=how, FAKE_START_FAILS_ONCE='1')
                self.assertIn('The old version keeps running', r.stderr)
                self.assertEqual(self.path('/usr/local/bin/caddy').read_text(), '#!/bin/sh\necho old\n')
                self.assertTrue(self.path('/etc/caddy/Caddyfile').exists())
                self.assertTrue((self.state / 'active-caddy').exists())

    def test_failed_rollback_reports_incomplete_recovery(self):
        self.fresh()
        r = self.install(ok=False, FAKE_START_FAILS='exit')
        self.assertIn('rollback is incomplete', r.stderr)
        self.assertNotIn('The old version keeps running', r.stderr)

    def test_failed_upgrade_restores_inactive_and_disabled_state(self):
        self.fresh()
        for enabled in [False, True]:
            with self.subTest(enabled=enabled):
                (self.state / 'active-caddy').unlink(missing_ok=True)
                (self.state / 'enabled-caddy').unlink(missing_ok=True)
                if enabled:
                    (self.state / 'enabled-caddy').touch()
                r = self.install(ok=False, FAKE_START_FAILS='exit')
                self.assertNotIn('The old version keeps running', r.stderr)
                self.assertIn('remains stopped', r.stderr)
                self.assertFalse((self.state / 'active-caddy').exists())
                self.assertEqual((self.state / 'enabled-caddy').exists(), enabled)

    def test_another_installer_is_refused(self):
        import fcntl
        lock = self.path('/run/caddy-network-relay-install/lock')
        lock.parent.mkdir(parents=True)
        with lock.open('w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            r = self.fresh(ok=False)
        self.assertIn('Another caddy-network-relay installer is running', r.stderr)
        self.assertEqual(self.files(), [])

    def test_upgrade_uses_and_flags_a_password_file_from_earlier_versions(self):
        self.fresh()
        legacy = self.path('/etc/caddy/relay/iphone.password')
        legacy.write_text('old-password-from-file\n')
        self.log.write_text('')
        r = self.install(FAKE_SS='tcp LISTEN 0 4096 *:443 *:* users:(("caddy",pid=1,fd=3))')
        self.assertIn('check network-relay check --server relay.example.com', self.calls())
        self.assertEqual((self.state / 'check-stdin').read_text(), 'old-password-from-file\n')
        self.assertIn('rm ' + str(legacy), r.stdout)
        self.assertTrue(legacy.exists(), 'the operator decides when to delete it')

    def test_failed_migration_restores_the_rust_service(self):
        (self.state / 'active-network-relay').touch()
        self.fresh('--replace-network-relay', ok=False, FAKE_START_FAILS='exit')
        self.assertTrue((self.state / 'active-network-relay').exists())

    def test_invalid_config_stops_before_installing(self):
        r = self.fresh(ok=False, FAKE_INVALID='1')
        self.assertIn('configuration check failed', r.stderr)
        self.assertFalse(self.path('/usr/local/bin/caddy').exists())
        self.assertNotIn('systemctl restart', self.calls())
        # Nothing that would make the next run look like an upgrade.
        self.assertFalse(self.path('/etc/caddy/Caddyfile').exists())
        self.assertFalse(self.path('/etc/caddy/relay/iphone.password').exists())
        self.fresh()

    def test_module_check_reads_the_whole_list(self):
        # grep -q stopping at the first line used to kill the writer with
        # SIGPIPE, which pipefail turned into "no network_relay module".
        self.fresh(FAKE_LONG_MODULES='1')
        self.assertTrue((self.state / 'active-caddy').exists())

    def test_build_without_the_module_is_refused(self):
        r = self.fresh(ok=False, FAKE_LONG_MODULES='missing')
        self.assertIn('has no network_relay module', r.stderr)
        self.assertFalse(self.path('/usr/local/bin/caddy').exists())

    def test_missing_jose_fork_is_refused_before_account_or_service_activation(self):
        for major in ('v3', 'v4'):
            with self.subTest(major=major):
                result = self.fresh(ok=False, FAKE_MISSING_REPLACEMENT=f'github.com/go-jose/go-jose/{major}')
                self.assertIn(f'go-jose/go-jose/{major}', result.stderr)
                self.assertFalse(self.path('/usr/local/bin/caddy').exists())
                self.assertFalse(self.path('/etc/caddy/Caddyfile').exists())
                self.assertFalse((self.state / 'user-caddy').exists())
                self.assertNotIn('systemctl restart caddy', self.calls())

    def test_missing_jose_fork_keeps_the_existing_upgrade_running(self):
        self.fresh()
        old_binary = self.path('/usr/local/bin/caddy').read_bytes()
        old_config = self.path('/etc/caddy/Caddyfile').read_bytes()
        for major in ('v3', 'v4'):
            with self.subTest(major=major):
                self.log.write_text('')
                result = self.install(ok=False, FAKE_MISSING_REPLACEMENT=f'github.com/go-jose/go-jose/{major}')
                self.assertIn(f'go-jose/go-jose/{major}', result.stderr)
                self.assertEqual(self.path('/usr/local/bin/caddy').read_bytes(), old_binary)
                self.assertEqual(self.path('/etc/caddy/Caddyfile').read_bytes(), old_config)
                self.assertTrue((self.state / 'active-caddy').exists())
                self.assertTrue((self.state / 'enabled-caddy').exists())
                self.assertNotIn('systemctl restart caddy', self.calls())
                self.assertNotIn('systemctl stop caddy', self.calls())

    def test_insecure_or_unknown_go_build_is_refused_before_activation(self):
        for version in ('go1.26.10', 'go1.27.2', 'go1.28rc1', 'devel go1.28-snapshot',
                        'go1.026.11', 'go1.26.011'):
            with self.subTest(version=version):
                result = self.fresh(ok=False, FAKE_BUILD_GO_VERSION=version)
                self.assertIn('Go', result.stderr)
                self.assertFalse((self.state / 'user-caddy').exists())
                self.assertFalse(self.path('/usr/local/bin/caddy').exists())
                self.assertNotIn('systemctl restart caddy', self.calls())

    def test_missing_or_lookalike_tls_policy_is_refused_before_activation(self):
        for overrides in ({'FAKE_MISSING_TLS_POLICY': '1'},
                          {'FAKE_BUILD_TAGS': 'http2legacy,relay_tls9846_v10'},
                          {'FAKE_BUILD_TAGS': 'http2legacy,prefix_relay_tls9846_v1'}):
            with self.subTest(overrides=overrides):
                result = self.fresh(ok=False, **overrides)
                self.assertIn('TLS policy build tag', result.stderr)
                self.assertFalse((self.state / 'user-caddy').exists())
                self.assertFalse(self.path('/usr/local/bin/caddy').exists())
                self.assertNotIn('systemctl restart caddy', self.calls())

    def test_newer_stable_go_build_is_accepted(self):
        self.fresh(FAKE_BUILD_GO_VERSION='go1.28.0')
        self.assertTrue((self.state / 'active-caddy').exists())

    def test_large_canonical_go_patch_is_accepted_without_overflow(self):
        self.fresh(FAKE_BUILD_GO_VERSION='go1.26.' + '9' * 40)
        self.assertTrue((self.state / 'active-caddy').exists())

    def test_failed_self_check_keeps_the_service(self):
        r = self.fresh(ok=False, FAKE_CHECK_FAILS='1')
        self.assertIn('self-check did not fully pass', r.stdout)
        self.assertTrue((self.state / 'active-caddy').exists())
        self.assertTrue(self.path('/etc/caddy/relay/relay.example.com-iphone-global.mobileconfig').exists())


if __name__ == '__main__':
    unittest.main()
