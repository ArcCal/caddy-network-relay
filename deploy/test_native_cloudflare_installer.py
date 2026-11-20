"""Regression tests for install-caddy-network-relay-native-build-cloudflare-dns.sh.

Only installer shell functions are sourced. Terminal reads are redirected to a
pipe in a private copy; nothing is built, installed or stopped.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'install-caddy-network-relay-native-build-cloudflare-dns.sh'
TOKEN = 'A' * 20 + 'b' * 10 + '0123456789'
SAVED = 'cfut_' + 'S' * 40


def domain_status(value):
    return subprocess.run(['bash', '-c', 'source "$1"; cr_domain "$2"', 'test', str(SCRIPT), value]).returncode


class GoVersionTests(unittest.TestCase):
    def test_exact_minimum_and_preferred_toolchain_select_a_release(self):
        cases = (("go 1.26.11\n", "go1.26.11"),
                 ("go 1.26.0\ntoolchain go1.27.4\n", "go1.27.4"),
                 ("go 1.26\n", None),
                 ("go 1.26.11\ntoolchain go1.27rc1\n", None))
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / 'go.mod'
            for text, expected in cases:
                with self.subTest(text=text):
                    module.write_text('module fixture.example/relay\n' + text)
                    result = subprocess.run(['bash', '-c', 'source "$1"; cr_go_version "$2"',
                                             'test', str(SCRIPT), str(module)], capture_output=True, text=True)
                    if expected is None:
                        self.assertNotEqual(result.returncode, 0)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.strip(), expected)


PATCHED_REPLACEMENTS = (
    ('github.com/quic-go/quic-go', './third_party/quic-go'),
    ('golang.org/x/net', './third_party/x-net'),
    ('github.com/go-jose/go-jose/v3', './third_party/go-jose-v3'),
    ('github.com/go-jose/go-jose/v4', './third_party/go-jose-v4'),
)


def build_info(missing=None, missing_tag=False):
    lines = ['fixture: go1.26.11']
    for module, replacement in (*PATCHED_REPLACEMENTS,
                                ('github.com/caddy-dns/cloudflare', '../cloudflare-src')):
        lines.append(f'\tdep\t{module}\tv0.0.0')
        if module != missing:
            lines.append(f'\t=>\t{replacement}\t(devel)\t')
    lines.extend(('\tbuild\tGOARCH=amd64', '\tbuild\tCGO_ENABLED=0'))
    if not missing_tag:
        lines.append('\tbuild\t-tags=http2legacy,relay_tls9846_v1')
    return '\n'.join(lines) + '\n'


class NativeBuildReplacementTests(unittest.TestCase):
    """Run cr_build with local Go/download fixtures; never compile or deploy."""

    def run_build(self, missing_binary=None, missing_overlay=None, missing_tag=False):
        with tempfile.TemporaryDirectory(prefix='native-build-forks-') as temporary:
            base = Path(temporary)
            source = base / 'source'
            (source / 'cmd/caddy').mkdir(parents=True)
            (source / 'go.mod').write_text('module fixture.example/relay\n\ngo 1.26.11\n')
            (source / 'go.sum').write_text('')
            (source / 'deploy/go-tls').mkdir(parents=True)
            (source / 'deploy/go-tls/prepare.py').write_text("import pathlib, sys\nroot, out=map(pathlib.Path, sys.argv[1:])\nassert (root / 'bin/go').is_file()\nout.mkdir()\n")
            (base / 'work').mkdir()
            (base / 'checkout').mkdir()
            info = base / 'build-info'
            info.write_text(build_info(missing_binary, missing_tag))
            replacements = (*PATCHED_REPLACEMENTS,
                            ('github.com/caddy-dns/cloudflare', '../cloudflare-src'))
            overlay = base / 'overlay.json'
            overlay.write_text(json.dumps({'Replace': [
                {'Old': {'Path': module}, 'New': {'Path': replacement}}
                for module, replacement in replacements if module != missing_overlay
            ]}))
            releases = base / 'releases.json'
            releases.write_text(json.dumps([{'version': 'go1.26.11', 'files': [{
                'os': 'linux', 'arch': 'amd64', 'kind': 'archive',
                'filename': 'go1.26.11.linux-amd64.tar.gz', 'sha256': '0' * 64,
            }]}]))
            binary = base / 'fake-caddy'
            binary.write_text('''#!/bin/sh
case "$1" in
  list-modules) printf '%s\\n' network_relay http.handlers.network_relay dns.providers.cloudflare ;;
  version) echo fixture ;;
  *) exit 94 ;;
esac
''')
            fake_go = base / 'fake-go'
            fake_go.write_text('''#!/bin/bash
set -e
case "$1" in
  version)
    if [[ ${2:-} == -m ]]; then cat "$CR_TEST_BUILDINFO"; else echo 'go version go1.26.11 linux/amd64'; fi ;;
  mod)
    for argument in "$@"; do
      if [[ $argument == -json ]]; then cat "$CR_TEST_OVERLAY"; fi
    done ;;
  get) ;;
  build)
    touch "$CR_TEST_BUILT"
    while (( $# )); do
      if [[ $1 == -o ]]; then cp "$CR_TEST_BINARY" "$2"; chmod 755 "$2"; break; fi
      shift
    done ;;
  *) exit 93 ;;
esac
''')
            fake_go.chmod(0o755)
            environment = os.environ | {
                'CR_TEST_ROOT': str(base), 'CR_TEST_BUILDINFO': str(info),
                'CR_TEST_OVERLAY': str(overlay), 'CR_TEST_RELEASES': str(releases),
                'CR_TEST_BINARY': str(binary), 'CR_TEST_FAKE_GO': str(fake_go),
                'CR_TEST_BUILT': str(base / 'built'),
            }
            command = '''source "$1"
work=$CR_TEST_ROOT/work
REPO=$CR_TEST_ROOT/source
CADDY_SOURCE_WORK=$CR_TEST_ROOT/checkout
arch=amd64
cr_clone_plugin() {
    mkdir -p "$CADDY_SOURCE_WORK/cloudflare-src"
    printf 'module fixture.example/plugin\\n' > "$CADDY_SOURCE_WORK/cloudflare-src/go.mod"
    : > "$work/plugin-clone.log"
}
cr_download() {
    if [[ $1 == *go.dev* ]]; then cp "$CR_TEST_RELEASES" "$2"; else : > "$2"; fi
}
cr_verify() { :; }
tar() { mkdir -p "$work/go/bin"; cp "$CR_TEST_FAKE_GO" "$work/go/bin/go"; }
git() { printf '%s\\n' "$PLUGIN_COMMIT"; }
cr_build 1
'''
            result = subprocess.run(['bash', '-euo', 'pipefail', '-c', command,
                                     'native-build', str(SCRIPT)], env=environment,
                                    capture_output=True, text=True, timeout=30)
            return result, (base / 'built').exists()

    def test_all_reviewed_sources_are_accepted(self):
        result, built = self.run_build()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(built)

    def test_binary_without_tls_policy_is_refused_after_build(self):
        result, built = self.run_build(missing_tag=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(built)
        self.assertIn('TLS policy build tag', result.stderr)

    def test_binary_without_either_jose_replacement_is_refused(self):
        for major in ('v3', 'v4'):
            with self.subTest(major=major):
                result, built = self.run_build(missing_binary=f'github.com/go-jose/go-jose/{major}')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(built, 'the actual binary metadata must be checked')
                self.assertIn(f'Missing patched JOSE {major}', result.stderr)

    def test_overlay_without_either_jose_replacement_is_refused_before_build(self):
        for major in ('v3', 'v4'):
            with self.subTest(major=major):
                result, built = self.run_build(missing_overlay=f'github.com/go-jose/go-jose/{major}')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(built)
                self.assertIn('Missing reviewed source replacement in Cloudflare build overlay: '
                              f'github.com/go-jose/go-jose/{major}=./third_party/go-jose-{major}.',
                              result.stderr)


class WorkflowReplacementTests(unittest.TestCase):
    def test_every_release_and_ci_artifact_guard_rejects_missing_reviewed_sources(self):
        for filename, expected_blocks in (('release.yml', 2), ('test.yml', 1)):
            text = (ROOT / '.github/workflows' / filename).read_text()
            blocks = re.findall(r'(?m)^([ ]*)for replacement in [\s\S]*?^\1done', text)
            # Capture complete shell loops separately from their indentation.
            loops = [match.group(0) for match in re.finditer(
                r'(?m)^([ ]*)for replacement in [\s\S]*?^\1done', text)]
            self.assertEqual(len(blocks), expected_blocks, filename)
            for index, loop in enumerate(loops):
                for missing in (None, *(module for module, _ in PATCHED_REPLACEMENTS)):
                    with self.subTest(workflow=filename, guard=index, missing=missing), \
                            tempfile.TemporaryDirectory(prefix='workflow-forks-') as temporary:
                        info = Path(temporary) / 'build-info'
                        info.write_text(build_info(missing))
                        result = subprocess.run(
                            ['bash', '-euo', 'pipefail', '-c', 'info=$(cat "$1")\n' + loop,
                             'workflow-build', str(info)], capture_output=True, text=True)
                        self.assertEqual(result.returncode == 0, missing is None,
                                         result.stdout + result.stderr)


class WorkflowTLSBuildTests(unittest.TestCase):
    def test_artifact_guards_require_exact_retained_policy_token(self):
        for filename, expected in (('release.yml', 2), ('test.yml', 1)):
            text = (ROOT / '.github/workflows' / filename).read_text()
            blocks = re.findall(r'info=\$\(go version -m caddy\)\n(.*?)^[ ]*for replacement in', text, re.S | re.M)
            self.assertEqual(len(blocks), expected)
            for index, block in enumerate(blocks):
                for metadata, valid in ((build_info(), True),
                                        (build_info(missing_tag=True), False),
                                        (build_info().replace('relay_tls9846_v1', 'relay_tls9846_v10'), False)):
                    with self.subTest(workflow=filename, guard=index, valid=valid), tempfile.TemporaryDirectory() as directory:
                        info = Path(directory) / 'info'
                        info.write_text(metadata)
                        result = subprocess.run(['bash', '-euo', 'pipefail', '-c',
                                                 'info=$(cat "$1")\n' + block, 'workflow-tls', str(info)],
                                                capture_output=True, text=True)
                        self.assertEqual(result.returncode == 0, valid, result.stderr)

    def test_every_server_job_prepares_private_source_before_go_checks(self):
        for filename in ('release.yml', 'test.yml'):
            text = (ROOT / '.github/workflows' / filename).read_text()
            self.assertEqual(text.count('uses: actions/setup-go@'), 3)
            self.assertEqual(text.count('- name: Prepare reviewed TLS source'), 3)
            self.assertEqual(text.count('echo "GOTOOLCHAIN=local"'), 3)
            self.assertEqual(text.count('echo "GOFLAGS=-tags=relay_tls9846_v1"'), 3)
            self.assertNotIn('-tags http2legacy ', text)


class AdminUnitTests(unittest.TestCase):
    def test_template_defaults_are_replaced_once_for_the_native_service(self):
        result = subprocess.run(['bash', '-c', 'source "$1"; cr_unit_text',
                                 'test', str(SCRIPT)], capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        for prefix, expected in (
            ('RuntimeDirectory=', 'RuntimeDirectory=caddy-network-relay'),
            ('RuntimeDirectoryMode=', 'RuntimeDirectoryMode=0700'),
            ('Environment=CADDY_ADMIN=',
             'Environment=CADDY_ADMIN=unix//run/caddy-network-relay/admin.sock'),
        ):
            self.assertEqual([line for line in lines if line.startswith(prefix)], [expected])
        self.assertIn('Environment=GODEBUG=http2xconnect=1', lines)
        self.assertIn('NoNewPrivileges=yes', lines)
        reload = next(line for line in lines if line.startswith('ExecReload='))
        self.assertIn('--address unix//run/caddy-network-relay/admin.sock ', reload)


class DomainTests(unittest.TestCase):
    def test_hostnames_including_punycode_tlds_are_accepted(self):
        for value in ('relay.example.com', 'a-b.example.org', 'relay.example.xn--p1ai', 'relay.xn--80ao21a'):
            self.assertEqual(domain_status(value), 0, value)

    def test_addresses_urls_wildcards_and_caddyfile_metacharacters_are_rejected(self):
        for value in ('10.0.0.1', 'relay.example.123', 'relay.example.xn--', '*.example.com', 'https://relay.example.com',
                      'example', 'relay..example.com', 'relay.example.c', 'relay.example.com:443',
                      'relay.example.com{', 'relay example.com'):
            self.assertNotEqual(domain_status(value), 0, value)


class TokenInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.script = self.base / 'installer.sh'
        self.script.write_text(SCRIPT.read_text().replace('</dev/tty', ''))
        self.token = self.base / 'cloudflare.token'

    def tearDown(self):
        self.tmp.cleanup()

    def inputs(self, data, saved=None, check_stub=True):
        if saved is not None:
            self.token.write_text(saved)
            self.token.chmod(0o600)
        stub = 'cr_check_parent_dirs() { printf "checked:parents\\n" >&2; }; ' if check_stub else ''
        command = (stub + 'TOKEN_FILE="$1"; cf_token=; cr_inputs; '
                   'if [[ $cf_token == "$2" ]]; then echo token-selected; fi')
        return subprocess.run(['bash', '-c', 'source "$1"; shift; ' + command, 'test', str(self.script),
                               str(self.token), SAVED], input=data, capture_output=True, text=True, timeout=30)

    @unittest.skipUnless(os.geteuid() == 0, 'requires a root-owned saved token')
    def test_enter_reuses_the_checked_saved_token(self):
        result = self.inputs('relay.example.com\n\n', SAVED)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('token-selected', result.stdout)
        self.assertIn('checked:parents', result.stderr)
        self.assertNotIn(SAVED, result.stdout + result.stderr)

    def test_typed_token_takes_precedence(self):
        result = self.inputs(f'relay.example.com\n{TOKEN}\n', SAVED)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('token-selected', result.stdout)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_enter_without_saved_token_fails(self):
        result = self.inputs('relay.example.com\n\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('No safe saved token', result.stderr)

    def test_malformed_or_multiline_saved_token_is_not_used(self):
        # TOKEN followed only by extra newlines exercises the single-line rule
        # itself: $( ) would strip them and the syntax check would accept it.
        for saved in ('bad token', SAVED + '\nsecond line\n', SAVED + '\n\n', ''):
            result = self.inputs('relay.example.com\n\n', saved)
            self.assertNotEqual(result.returncode, 0, repr(saved))
            self.assertNotIn('token-selected', result.stdout)
            self.assertIn('No safe saved token', result.stderr, repr(saved))
            self.assertNotIn('second line', result.stdout + result.stderr)

    @unittest.skipUnless(os.geteuid() == 0, 'the real dedicated-path check requires root-owned parents')
    def test_loose_mode_saved_token_is_reused_and_reported(self):
        with tempfile.TemporaryDirectory(dir='/root') as private:
            self.token = Path(private) / 'cloudflare.token'
            self.token.write_text(SAVED)
            self.token.chmod(0o640)
            result = self.inputs('relay.example.com\n\n', check_stub=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('token-selected', result.stdout)
            self.assertIn('reinstalled root-only', result.stderr)
            self.assertNotIn(SAVED, result.stderr)

    @unittest.skipUnless(os.geteuid() == 0, 'creating a foreign-owned file requires root')
    def test_foreign_owned_or_linked_saved_token_is_never_read(self):
        with tempfile.TemporaryDirectory(dir='/root') as private:
            elsewhere = Path(private) / 'elsewhere'
            elsewhere.write_text(SAVED)
            elsewhere.chmod(0o600)
            self.token = Path(private) / 'cloudflare.token'
            self.token.symlink_to(elsewhere)
            linked = self.inputs('relay.example.com\n\n', check_stub=False)
            self.token.unlink()
            self.token.write_text(SAVED)
            os.chown(self.token, 65534, 65534)
            foreign = self.inputs('relay.example.com\n\n', check_stub=False)
            for result in (linked, foreign):
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('token-selected', result.stdout)
                self.assertNotIn(SAVED, result.stdout + result.stderr)


@unittest.skipUnless(os.geteuid() == 0, 'dedicated-path checks require root-owned parents')
class SameNameRepairTests(unittest.TestCase):
    """Real files under a private root-owned directory; nothing outside it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/root')
        self.base = Path(self.tmp.name)
        self.outside = self.base / 'unrelated'
        self.outside.mkdir()
        (self.outside / 'data').write_text('keep')

    def tearDown(self):
        self.tmp.cleanup()

    def shell(self, command, *args):
        return subprocess.run(['bash', '-c', 'source "$1"; shift; ' + command, 'test', str(SCRIPT), *args],
                              capture_output=True, text=True, timeout=30)

    def test_symlinked_or_misplaced_files_are_replaced_without_writing_through(self):
        source = self.base / 'new'
        source.write_text('new')
        linked = self.base / 'linked'
        linked.symlink_to(self.outside / 'data')
        directory = self.base / 'was-directory'
        directory.mkdir()
        (directory / 'inside').write_text('old')
        for destination in (linked, directory):
            result = self.shell('cr_atomic_install "$1" "$2" 644', str(source), str(destination))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(destination.read_text(), 'new')
        self.assertEqual((self.outside / 'data').read_text(), 'keep')
        aside = list(self.base.glob('was-directory.replaced-*'))
        self.assertEqual(len(aside), 1)
        self.assertEqual((aside[0] / 'inside').read_text(), 'old')

    def test_unsafe_or_linked_dedicated_directories_are_refused_not_adopted(self):
        # Content of a directory another account could write may be planted
        # (file_server follows links); the preflight check refuses it.
        loose = self.base / 'loose'
        loose.mkdir()
        os.chmod(loose, 0o777)
        link = self.base / 'link'
        link.symlink_to(self.outside)
        os.chmod(self.outside, 0o777)
        for path, kind in ((loose, 'rootdir'), (link, 'rootdir'), (link, 'statedir')):
            result = self.shell('cr_check_leaf "$1" "$2"', str(path), kind)
            self.assertNotEqual(result.returncode, 0, (path, kind))
        self.assertEqual(loose.stat().st_mode & 0o777, 0o777)
        self.assertEqual(self.outside.stat().st_mode & 0o777, 0o777)


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get('CR_TEST_ACCOUNTS') == '1',
                     'creates and deletes a temporary local account; set CR_TEST_ACCOUNTS=1 in a disposable host')
class AccountRepairTests(unittest.TestCase):
    def test_account_in_use_is_repaired_and_its_home_change_deferred(self):
        # Older installers gave the account home DATA. Some shadow-utils
        # versions refuse a home change while the running old relay uses the
        # account, and the change waits until it stops; others make it at
        # once. Either way the run must not abort and the account is repaired.
        name = f'crbusy{os.getpid() % 100000}'
        subprocess.run(['useradd', '--system', '--user-group', '--shell', '/bin/bash', '--home-dir',
                        f'/var/lib/{name}', '--groups', 'adm', name], check=True)
        process = subprocess.Popen(['sleep', '60'], user=name)
        command = 'source "$1"; SERVICE="$2"; DATA=/var/lib/"$2"; cr_account && echo "ok pending=$account_home_pending"'
        try:
            result = subprocess.run(['bash', '-c', command, 'test', str(SCRIPT), name], capture_output=True,
                                    text=True, timeout=60)
            self.assertRegex(result.stdout, r'ok pending=[01]\n', result.stderr)
            deferred = 'ok pending=1' in result.stdout
            entry = subprocess.run(['getent', 'passwd', name], capture_output=True, text=True).stdout.strip()
            home = f'/var/lib/{name}' if deferred else '/nonexistent'
            self.assertTrue(entry.endswith(f':{home}:/usr/sbin/nologin'), entry)
            self.assertEqual(subprocess.run(['id', '-Gn', name], capture_output=True, text=True).stdout.split(), [name])
            process.kill()
            process.wait()
            result = subprocess.run(['bash', '-c', command, 'test', str(SCRIPT), name], capture_output=True,
                                    text=True, timeout=60)
            self.assertIn('ok pending=0', result.stdout, result.stderr)
            entry = subprocess.run(['getent', 'passwd', name], capture_output=True, text=True).stdout.strip()
            self.assertTrue(entry.endswith(':/nonexistent:/usr/sbin/nologin'), entry)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            subprocess.run(['userdel', '-f', name], check=False)
            subprocess.run(['groupdel', name], check=False, stderr=subprocess.DEVNULL)

    def test_login_shell_home_and_supplementary_groups_are_repaired(self):
        name = f'crtest{os.getpid() % 100000}'
        subprocess.run(['useradd', '--system', '--user-group', '--shell', '/bin/bash', '--home-dir', '/root',
                        '--groups', 'adm', name], check=True)
        try:
            result = subprocess.run(['bash', '-c', 'source "$1"; SERVICE="$2"; DATA=/var/lib/"$2"; cr_account && echo ok',
                                     'test', str(SCRIPT), name], capture_output=True, text=True, timeout=60)
            self.assertIn('ok', result.stdout, result.stderr)
            entry = subprocess.run(['getent', 'passwd', name], capture_output=True, text=True).stdout.strip()
            self.assertTrue(entry.endswith(':/nonexistent:/usr/sbin/nologin'), entry)
            groups = subprocess.run(['id', '-Gn', name], capture_output=True, text=True).stdout.split()
            self.assertEqual(groups, [name])
        finally:
            subprocess.run(['userdel', '-f', name], check=False)
            subprocess.run(['groupdel', name], check=False, stderr=subprocess.DEVNULL)


@unittest.skipUnless(os.geteuid() == 0, 'creating a mount namespace requires root')
class StandaloneIdentityTests(unittest.TestCase):
    """Real processes and /proc; a compiled sleeper stands in for the server."""

    def test_same_namespace_instance_is_identified_but_a_container_copy_is_not(self):
        probe = subprocess.run(['unshare', '-m', '--propagation', 'private', 'true'],
                               env={**os.environ, 'LC_ALL': 'C'}, capture_output=True, text=True)
        if probe.returncode and 'Operation not permitted' in probe.stderr:
            self.skipTest('the host forbids creating a private mount namespace')
        self.assertEqual(probe.returncode, 0, probe.stderr)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'sleeper.c').write_text('#include <unistd.h>\nint main(void) { for (;;) pause(); }\n')
            binary = base / 'caddy-network-relay'
            subprocess.run(['cc', '-o', str(binary), str(base / 'sleeper.c')], check=True)
            config = str(base / 'Caddyfile')
            args = [str(binary), 'run', '--config', config, '--adapter', 'caddyfile']
            ours = subprocess.Popen(args)
            other = subprocess.Popen(['unshare', '-m', '--propagation', 'private', *args])
            try:
                time.sleep(0.3)

                def identified(pid):
                    return subprocess.run(['bash', '-c', 'source "$1"; BIN="$2"; CONFIG="$3"; cr_is_relay_pid "$4"',
                                           'test', str(SCRIPT), str(binary), config, str(pid)]).returncode == 0
                self.assertTrue(identified(ours.pid))
                self.assertIsNone(other.poll(), 'the foreign relay must still be running')
                self.assertNotEqual(os.readlink(f'/proc/{other.pid}/ns/mnt'), os.readlink('/proc/self/ns/mnt'))
                self.assertFalse(identified(other.pid), 'a process in another mount namespace is not ours')
            finally:
                for process in (ours, other):
                    process.kill()
                    process.wait()


class ConcurrentCloneTests(unittest.TestCase):
    """A fake git on PATH; exec bypasses shell functions, as it should."""

    def run_with_git(self, body, command):
        with tempfile.TemporaryDirectory() as tools, tempfile.TemporaryDirectory() as parent:
            git = Path(tools) / 'git'
            git.write_text('#!/bin/sh\n' + body + '\n')
            git.chmod(0o755)
            work = Path(parent) / 'work'
            work.mkdir()
            env = dict(os.environ, PATH=f'{tools}:{os.environ["PATH"]}')
            result = subprocess.run(['bash', '-c', 'source "$1"; shift; work="$1"; ' + command, 'test', str(SCRIPT),
                                     str(work)], capture_output=True, text=True, timeout=30, env=env)
            return result, work

    def test_clone_failure_status_reaches_the_waiting_build(self):
        result, _ = self.run_with_git('echo clone-error >&2; exit 128',
                                      'cr_clone_plugin & clone_job=$!; wait "$clone_job"; echo "status=$?"; '
                                      'cat "$work/plugin-clone.log"')
        self.assertIn('status=128', result.stdout)
        self.assertIn('clone-error', result.stdout)

    def test_cleanup_stops_a_stalled_clone_and_removes_scratch(self):
        result, work = self.run_with_git('sleep 300',
                                         'cr_clone_plugin & clone_job=$!; sleep 0.3; transaction_started=0; '
                                         '(exit 1); cr_cleanup')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(work.exists(), 'cleanup must remove the scratch directory after stopping the clone')

    def test_clone_starts_before_go_download_and_is_verified_before_use(self):
        text = SCRIPT.read_text()
        build = text[text.index('cr_build() {'):text.index('\n}\n', text.index('cr_build() {'))]
        self.assertLess(build.index('cr_clone_plugin &'), build.index('cr_download'))
        self.assertLess(build.index('wait "$clone_job"'), build.index('rev-parse --verify HEAD'))
        self.assertLess(build.index('rev-parse --verify HEAD'), build.index('mod edit'))


class BuildMemoryTests(unittest.TestCase):
    """The build was measured under memory caps; see cr_check_build_memory."""

    def check(self, available, swap, cgroups='', groups=None, mount_root='/'):
        """`groups` maps a cgroup directory, relative to a fake mount, to its
        files; `cgroups` is /proc/self/cgroup. No cgroups by default, so the
        machine running the tests does not matter."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            meminfo = base / 'meminfo'
            meminfo.write_text(f'MemTotal: 4000000 kB\nMemAvailable: {available} kB\nSwapFree: {swap} kB\n')
            (base / 'self-cgroup').write_text(cgroups)
            mounts = []
            for kind, options in (('cgroup2', 'rw'), ('cgroup', 'rw,memory')):
                mount = base / kind
                mount.mkdir()
                mounts.append(f'30 25 0:26 {mount_root} {mount} rw,nosuid - {kind} {kind} {options}\n')
            (base / 'mountinfo').write_text(''.join(mounts))
            for relative, files in (groups or {}).items():
                folder = base / relative
                folder.mkdir(parents=True, exist_ok=True)
                if 'memory.swap.max' in files:
                    files = {'memory.swap.current': 0, **files}
                for name, value in files.items():
                    (folder / name).write_text(f'{value}\n')
            return subprocess.run(['bash', '-c', 'source "$1"; cr_check_build_memory "$2" "$3" "$4" && echo accepted',
                                   'test', str(SCRIPT), str(meminfo), str(base / 'self-cgroup'), str(base / 'mountinfo')],
                                  capture_output=True, text=True, timeout=30)

    def test_unlimited_ram_does_not_allow_swap_forbidden_by_cgroup(self):
        groups = {'cgroup2/child': {'memory.max': 'max', 'memory.swap.max': 0}}
        self.assertNotEqual(self.check(320 * 1024, 2 << 20, '0::/child\n', groups).returncode, 0)

    def test_namespaced_mount_root_keeps_memory_quota(self):
        groups = {'cgroup2/child': {'memory.max': 320 << 20, 'memory.current': 0, 'memory.stat': 'inactive_file 0'}}
        self.assertNotEqual(self.check(4000000, 0, '0::/child\n', groups, mount_root='/..').returncode, 0)

    def test_too_little_memory_is_refused_with_advice(self):
        result = self.check(655360 - 1, 0)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('640 MiB of available memory plus free swap', result.stderr)

    def test_exact_threshold_is_accepted(self):
        self.assertIn('accepted', self.check(655360, 0).stdout)

    def test_free_swap_counts_toward_the_requirement(self):
        self.assertIn('accepted', self.check(655360 // 2, 655360 // 2).stdout)

    # A container or systemd unit with a memory limit caps the build below
    # what the host's /proc/meminfo reports.
    def test_a_cgroup_v2_limit_below_the_requirement_is_refused(self):
        groups = {'cgroup2/system.slice': {'memory.max': 'max'},
                  'cgroup2/system.slice/install.scope': {'memory.max': 320 << 20, 'memory.current': 8 << 20,
                                                         'memory.stat': 'inactive_file 0', 'memory.swap.max': 0}}
        result = self.check(4000000, 0, '0::/system.slice/install.scope\n', groups)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('memory limit on this container or service', result.stderr)

    def test_a_limit_on_an_ancestor_cgroup_counts(self):
        groups = {'cgroup2/lxc': {'memory.max': 512 << 20, 'memory.current': 0, 'memory.stat': 'inactive_file 0'},
                  'cgroup2/lxc/c1': {'memory.max': 'max'}}
        self.assertNotEqual(self.check(4000000, 0, '0::/lxc/c1\n', groups).returncode, 0)

    def test_reclaimable_cache_and_allowed_swap_count_within_a_limit(self):
        # 512 MiB limit, 300 MiB used of which 200 MiB is inactive file cache,
        # plus 256 MiB of the cgroup's swap allowance: about 668 MiB.
        group = {'memory.max': 512 << 20, 'memory.current': 300 << 20, 'memory.stat': f'inactive_file {200 << 20}',
                 'memory.swap.max': 256 << 20, 'memory.swap.current': 0}
        self.assertIn('accepted', self.check(4000000, 2 << 20, '0::/svc\n', {'cgroup2/svc': group}).stdout)
        # Host swap that the cgroup may not use does not count.
        group['memory.swap.max'] = 0
        self.assertNotEqual(self.check(4000000, 2 << 20, '0::/svc\n', {'cgroup2/svc': group}).returncode, 0)

    def test_a_cgroup_v1_limit_counts_and_unlimited_is_ignored(self):
        limited = {'memory.limit_in_bytes': 320 << 20, 'memory.usage_in_bytes': 0, 'memory.stat': 'total_inactive_file 0'}
        result = self.check(4000000, 0, '4:memory:/docker/c1\n', {'cgroup/docker/c1': limited})
        self.assertNotEqual(result.returncode, 0)
        unlimited = dict(limited, **{'memory.limit_in_bytes': 9223372036854771712})
        self.assertIn('accepted', self.check(4000000, 0, '4:memory:/docker/c1\n', {'cgroup/docker/c1': unlimited}).stdout)

    def test_a_roomy_cgroup_leaves_the_host_figure_in_charge(self):
        group = {'memory.max': 8 << 30, 'memory.current': 0, 'memory.stat': 'inactive_file 0'}
        self.assertIn('accepted', self.check(640 * 1024, 0, '0::/svc\n', {'cgroup2/svc': group}).stdout)
        self.assertNotEqual(self.check(640 * 1024 - 1, 0, '0::/svc\n', {'cgroup2/svc': group}).returncode, 0)

    def test_check_precedes_packages_and_the_build(self):
        text = SCRIPT.read_text()
        body = text[text.index('cr_main() {'):]
        positions = [body.index(marker) for marker in ('cr_check_build_memory', 'cr_apt "${apt[@]:1}" update', 'cr_build "$jobs"')]
        self.assertEqual(positions, sorted(positions))


if __name__ == '__main__':
    unittest.main()
