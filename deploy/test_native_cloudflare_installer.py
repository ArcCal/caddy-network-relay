"""Regression tests for install-caddy-network-relay-native-build-cloudflare-dns.sh.

Only installer shell functions are sourced. Terminal reads are redirected to a
pipe in a private copy; nothing is built, installed or stopped.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'install-caddy-network-relay-native-build-cloudflare-dns.sh'
TOKEN = 'A' * 20 + 'b' * 10 + '0123456789'
SAVED = 'cfut_' + 'S' * 40


def domain_status(value):
    return subprocess.run(['bash', '-c', 'source "$1"; cr_domain "$2"', 'test', str(SCRIPT), value]).returncode


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
        for saved in ('bad token', SAVED + '\nsecond line\n', 'x' * 10):
            result = self.inputs('relay.example.com\n\n', saved)
            self.assertNotEqual(result.returncode, 0, saved)
            self.assertNotIn('token-selected', result.stdout)
            if saved != 'x' * 10:
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

    def test_directory_repair_is_not_recursive_and_links_are_refused(self):
        loose = self.base / 'loose'
        (loose / 'child').mkdir(parents=True)
        os.chmod(loose, 0o777)
        os.chmod(loose / 'child', 0o777)
        self.assertEqual(self.shell('cr_repair_dir "$1" root root 750', str(loose)).returncode, 0)
        self.assertEqual(loose.stat().st_mode & 0o777, 0o750)
        self.assertEqual((loose / 'child').stat().st_mode & 0o777, 0o777)
        link = self.base / 'link'
        link.symlink_to(self.outside)
        os.chmod(self.outside, 0o777)
        result = self.shell('cr_repair_dir "$1" root root 750', str(link))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.outside.stat().st_mode & 0o777, 0o777)


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get('CR_TEST_ACCOUNTS') == '1',
                     'creates and deletes a temporary local account; set CR_TEST_ACCOUNTS=1 in a disposable host')
class AccountRepairTests(unittest.TestCase):
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


class ConcurrentCloneTests(unittest.TestCase):
    def test_clone_failure_status_reaches_the_waiting_build(self):
        with tempfile.TemporaryDirectory() as work:
            command = ('work="$1"; git() { echo clone-error >&2; return 128; }; '
                       'cr_clone_plugin & clone_job=$!; wait "$clone_job"; echo "status=$?"; cat "$work/plugin-clone.log"')
            result = subprocess.run(['bash', '-c', 'source "$1"; shift; ' + command, 'test', str(SCRIPT), work],
                                    capture_output=True, text=True, timeout=30)
            self.assertIn('status=128', result.stdout)
            self.assertIn('clone-error', result.stdout)

    def test_clone_starts_before_go_download_and_is_verified_before_use(self):
        text = SCRIPT.read_text()
        build = text[text.index('cr_build() {'):text.index('\n}\n', text.index('cr_build() {'))]
        self.assertLess(build.index('cr_clone_plugin &'), build.index('cr_download'))
        self.assertLess(build.index('wait "$clone_job"'), build.index('rev-parse --verify HEAD'))
        self.assertLess(build.index('rev-parse --verify HEAD'), build.index('mod edit'))


if __name__ == '__main__':
    unittest.main()
