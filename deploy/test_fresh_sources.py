"""Exercise fresh source selection and cleanup with real disposable Git history."""
import base64
import fcntl
import os
import pty
from pathlib import Path
import shutil
import subprocess
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'deploy/fresh-source.sh'
BUILDER = ROOT / 'build-linux-servers-on-linux.sh'


class FreshSourcesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.remote = self.base / 'upstream'
        self.remote.mkdir()
        self.git = shutil.which('git')
        self.call_git('init', '-q', '-b', 'main')
        (self.remote / 'version').write_text('first\n')
        self.commit()
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.log = self.base / 'git.log'
        self.stages = self.base / 'stages.log'
        self.env = os.environ | {
            'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
            'FAKE_REMOTE': self.remote.as_uri(), 'REAL_GIT': self.git,
            'GIT_LOG': str(self.log), 'STAGES': str(self.stages),
            'REAL_MKTEMP': shutil.which('mktemp'), 'HOME': str(self.base),
            'CADDY_NETWORK_RELAY_TOKEN': '',
        }
        (self.bin / 'git').write_text('''#!/bin/bash
printf '%s\\n' "$*" >> "$GIT_LOG"
if [[ ${FAIL_CLONE:-} == 1 && " $* " == *" clone "* ]]; then exit 128; fi
if [[ ${REQUIRE_TOKEN:-} == 1 && " $* " == *" clone "* && ${GIT_CONFIG_COUNT:-} != 2 ]]; then exit 128; fi
# This fixture deliberately substitutes a local transport for GitHub.
for arg in "$@"; do
    shift
    if [[ $arg == protocol.file.allow=never && ${DENY_LOCAL_MIRROR:-} != 1 ]]; then arg=protocol.file.allow=always; fi
    set -- "$@" "$arg"
done
exec "$REAL_GIT" -c "url.$FAKE_REMOTE.insteadOf=https://github.com/ArcCal/caddy-network-relay.git" "$@"
''')
        (self.bin / 'mktemp').write_text('''#!/bin/bash
result=$("$REAL_MKTEMP" "$@") || exit
printf '%s\\n' "$result" >> "$STAGES"
printf '%s\\n' "$result"
''')
        for path in self.bin.iterdir():
            path.chmod(0o755)

    def tearDown(self):
        # Failed cleanup assertions must not leave the regression fixture itself.
        if self.stages.exists():
            for name in self.stages.read_text().splitlines():
                path = Path(name)
                if path.is_dir():
                    for parent, _, _ in os.walk(path):
                        Path(parent).chmod(0o700)
                    shutil.rmtree(path)
        self.tmp.cleanup()

    def call_git(self, *args):
        return subprocess.check_output([self.git, '-C', str(self.remote), *args], text=True).strip()

    def commit(self):
        self.call_git('add', '.')
        self.call_git('-c', 'user.name=Anonymous', '-c', 'user.email=anonymous@example.invalid',
                      '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Fixture source update')

    def shell(self, code, **env):
        return subprocess.run(['bash', '-c', 'set -e; source "$1"; shift; ' + code,
                               'test', str(HELPER)], env=self.env | env,
                              capture_output=True, text=True, timeout=30)

    def assert_clean(self):
        self.assertTrue(self.stages.exists())
        for stage in self.stages.read_text().splitlines():
            self.assertFalse(Path(stage).exists(), stage)

    def test_python_bootstrap_is_required_only_with_a_controlling_terminal(self):
        calls = self.base / 'apt.log'
        code = ('source "$1"; '
                'command() { if [[ "$1 ${2:-}" == "-v python3" ]]; then return 1; fi; builtin command "$@"; }; '
                'apt-get() { printf "%s\\n" "$*" >> "$APT_LOG"; [[ " $* " != *" install "* ]]; }; '
                'caddy_new_sources() { return 71; }; caddy_latest_entry unused')
        args = ['bash', '-c', code, 'test', str(HELPER)]
        env = self.env | {'APT_LOG': str(calls)}
        plain = subprocess.run(args, env=env, capture_output=True, text=True,
                               start_new_session=True, timeout=10)
        self.assertEqual(plain.returncode, 71, plain.stderr)
        self.assertFalse(calls.exists())
        master, slave = pty.openpty()
        def terminal_session():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        try:
            process = subprocess.Popen(args, env=env, stdin=slave, stdout=slave,
                                       stderr=slave, preexec_fn=terminal_session)
            self.assertNotEqual(process.wait(timeout=10), 71)
        finally:
            os.close(slave)
            os.close(master)
        if os.geteuid() == 0:
            self.assertIn('install -y --no-install-recommends git ca-certificates procps python3', calls.read_text())

    def test_each_run_uses_latest_complete_main_and_ignores_old_checkout(self):
        old = self.base / 'saved-checkout'
        old.mkdir()
        (old / 'version').write_text('stale local edit')
        first = self.shell('trap caddy_source_cleanup EXIT; caddy_new_sources; '
                           'git -C "$REPLY" rev-parse HEAD; git -C "$REPLY" rev-parse --is-shallow-repository',
                           CADDY_NETWORK_RELAY_SRC=str(old))
        self.assertEqual(first.returncode, 0, first.stderr)
        (self.remote / 'version').write_text('second\n')
        self.commit()
        second = self.shell('trap caddy_source_cleanup EXIT; caddy_new_sources; '
                            'git -C "$REPLY" rev-parse HEAD; git -C "$REPLY" rev-list --count HEAD; '
                            'git -C "$REPLY" rev-parse --is-shallow-repository',
                            CADDY_NETWORK_RELAY_SRC=str(old))
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn(self.call_git('rev-parse', 'HEAD'), second.stdout)
        self.assertTrue(second.stdout.endswith('2\nfalse\n'), second.stdout)
        self.assertNotEqual(first.stdout, second.stdout)
        self.assertEqual((old / 'version').read_text(), 'stale local edit')
        self.assertNotIn('--depth', self.log.read_text())
        self.assertNotIn('--single-branch', self.log.read_text())
        for stage in self.stages.read_text().splitlines():
            self.assertRegex(stage, r'^/tmp/\d{8}-\d{6}\.[A-Za-z0-9]+$')
        self.assert_clean()

    def test_failure_cleans_source_and_readonly_compiler_cache(self):
        result = self.shell('trap caddy_source_cleanup EXIT; caddy_new_sources; '
                            'caddy_build_parent() { REPLY=$1; }; caddy_new_build_work "$HOME"; '
                            'mkdir -p "$CADDY_BUILD_WORK/gomod/module"; '
                            'echo cache > "$CADDY_BUILD_WORK/gomod/module/file"; '
                            'chmod 555 "$CADDY_BUILD_WORK/gomod/module"; exit 17')
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assert_clean()

    def test_download_failure_does_not_fall_back_to_saved_source(self):
        result = self.shell('trap caddy_source_cleanup EXIT; caddy_new_sources; echo should-not-build', FAIL_CLONE='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('should-not-build', result.stdout)
        self.assertIn('No saved source is used', result.stderr)
        self.assert_clean()

    def test_token_fallback_handles_git_fatal_status_without_disclosure(self):
        token = 'fixture-private-token'
        result = self.shell('trap caddy_source_cleanup EXIT; set -x; caddy_new_sources',
                            REQUIRE_TOKEN='1', CADDY_NETWORK_RELAY_TOKEN=token, GIT_CONFIG_COUNT='0')
        self.assertEqual(result.returncode, 0, result.stderr)
        encoded = base64.b64encode(('x-access-token:' + token).encode()).decode()
        for secret in (token, encoded):
            self.assertNotIn(secret, result.stdout + result.stderr + self.log.read_text())
        self.assert_clean()

    def test_dns_token_is_handed_only_to_the_fresh_native_installer(self):
        entry = 'install-caddy-network-relay-native-build-cloudflare-dns.sh'
        (self.remote / entry).write_text('#!/bin/bash\n'
                                         '[[ ${CF_API_TOKEN:-} == fixture-zone-token ]] || exit 96\n'
                                         'printf "TOKEN-HANDOFF-OK\\n"\n')
        self.commit()
        git = self.bin / 'git'
        git.write_text(git.read_text().replace('printf \'%s\\n\' "$*" >> "$GIT_LOG"',
                                               '[[ -z ${CF_API_TOKEN:-} && -z ${cf_token:-} ]] || exit 97\n'
                                               'printf \'%s\\n\' "$*" >> "$GIT_LOG"'))
        result = self.shell('cf_token=fixture-zone-token; export -n cf_token; unset CF_API_TOKEN; caddy_latest_entry ' + entry,
                            cf_token='previous-exported-value')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('TOKEN-HANDOFF-OK', result.stdout)
        self.assertNotIn('fixture-zone-token', result.stdout + result.stderr + self.log.read_text())
        self.assert_clean()

    def test_saved_local_mirror_cannot_masquerade_as_current_github_source(self):
        result = self.shell('trap caddy_source_cleanup EXIT; caddy_new_sources', DENY_LOCAL_MIRROR='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("transport 'file' not allowed", result.stderr)
        self.assert_clean()

    def test_fresh_script_syntax_failure_removes_the_download(self):
        (self.remote / 'broken.sh').write_text('#!/bin/bash\nif true; then\n')
        self.commit()
        result = self.shell('caddy_latest_entry broken.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('syntax error', result.stderr)
        self.assert_clean()

    def test_term_stops_compiler_writers_before_cleanup(self):
        child_pid = self.base / 'compiler.pid'
        loop = 'trap "" TERM; echo $$ > "$2"; while :; do echo writing >> "$1/cache"; sleep .02; done'
        code = ('set -e; source "$1"; trap caddy_source_cleanup EXIT; trap "exit 143" TERM; '
                'caddy_new_sources; caddy_build_parent() { REPLY=$1; }; caddy_new_build_work "$HOME"; '
                'caddy_run_build bash -c "$2" compiler "$CADDY_BUILD_WORK" "$3"')
        process = subprocess.Popen(['bash', '-c', code, 'test', str(HELPER), loop, str(child_pid)],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not child_pid.exists():
                self.assertIsNone(process.poll())
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.02)
            process.terminate()
            process.communicate(timeout=10)
            self.assertEqual(process.returncode, 143)
            time.sleep(.1)
            state = subprocess.run(['ps', '-o', 'stat=', '-p', child_pid.read_text().strip()],
                                   capture_output=True, text=True).stdout.strip()
            self.assertTrue(not state or state.startswith('Z'), state)
            self.assert_clean()
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
            if child_pid.exists():
                try:
                    os.kill(int(child_pid.read_text()), 9)
                except ProcessLookupError:
                    pass

    def test_term_cleans_source_and_compiler_work(self):
        process = subprocess.Popen(['bash', '-c', 'set -e; source "$1"; trap caddy_source_cleanup EXIT; '
                                    'trap "exit 143" TERM; caddy_new_sources || exit; '
                                    'caddy_build_parent() { REPLY=$1; }; caddy_new_build_work "$HOME"; echo READY; read -r ignored',
                                    'test', str(HELPER)], env=self.env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            while process.stdout.readline().strip() != 'READY':
                self.assertIsNone(process.poll())
            process.terminate()
            process.communicate(timeout=20)
            self.assertEqual(process.returncode, 143)
            self.assertEqual(len(self.stages.read_text().splitlines()), 2)
            self.assert_clean()
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_builder_cleanup_does_not_touch_unowned_artifact_folder(self):
        existing = self.base / 'existing-output'
        existing.mkdir()
        marker = existing / '.work'
        marker.write_text('existing user file')
        result = subprocess.run(['bash', '-c', 'source "$1"; output=$2; stage=$(mktemp -d); '
                                 'work=; output_owned=0; trap lr_cleanup EXIT; exit 23',
                                 'test', str(BUILDER), str(existing)], env=self.env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(marker.read_text(), 'existing user file')
        self.assert_clean()

    def test_builder_uses_the_fresh_main_driver_without_touching_repo_override(self):
        old = self.base / 'old-checkout'
        old.mkdir()
        (old / 'keep').write_text('local source stays untouched')
        driver = self.remote / 'build-linux-servers-on-linux.sh'
        driver.write_text('''#!/bin/bash
set -e
trap 'rm -rf -- "$3"' EXIT
printf 'LATEST-DRIVER\\n'
git -C "$2" rev-parse HEAD
git -C "$2" rev-parse --is-shallow-repository
''')
        self.commit()
        result = subprocess.run(['bash', '-c', 'source "$1"; '
                                 'lr_host() { platform=debian-13-amd64; host_arch=amd64; }; '
                                 'lr_memory_jobs() { :; }; lr_work_parent() { REPLY=$HOME; }; '
                                 'lr_main --repo "$2" --no-install-deps',
                                 'test', str(BUILDER), str(old)], env=self.env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('LATEST-DRIVER', result.stdout)
        self.assertIn(self.call_git('rev-parse', 'HEAD'), result.stdout)
        self.assertTrue(result.stdout.endswith('false\n'), result.stdout)
        self.assertEqual((old / 'keep').read_text(), 'local source stays untouched')
        self.assert_clean()

    def test_compiler_workspace_rejects_ram_filesystems(self):
        result = self.shell('stat() { case "${!#}" in "$HOME") echo ext2/ext3 ;; *) echo tmpfs ;; esac; }; '
                            'df() { printf "Filesystem 1024-blocks Used Available Capacity Mounted\\nfixture 9000000 0 9000000 0%% /\\n"; }; '
                            'caddy_build_parent /tmp; [[ $REPLY == "$HOME" ]]')
        self.assertEqual(result.returncode, 0, result.stderr)


class MemoryBudgetTests(unittest.TestCase):
    def check(self, available, swap, limit=None, allowed_swap=0, mount_root='/'):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / 'meminfo').write_text(f'MemAvailable: {available} kB\nSwapFree: {swap} kB\n')
            (base / 'groups').write_text('0::/child\n' if limit is not None else '')
            mount = base / 'cgroup'; child = mount / 'child'; child.mkdir(parents=True)
            (base / 'mounts').write_text(f'30 25 0:26 {mount_root} {mount} rw - cgroup2 cgroup2 rw\n')
            if limit is not None:
                for key, value in {'memory.max': limit << 20 if isinstance(limit, int) else limit, 'memory.current': 0,
                                   'memory.stat': 'inactive_file 0', 'memory.swap.max': allowed_swap << 20, 'memory.swap.current': 0}.items():
                    (child / key).write_text(str(value))
            return subprocess.run(['bash', '-c', 'source "$1"; jobs=8; lr_memory_jobs "$2" "$3" "$4"; echo jobs=$jobs',
                                   'test', str(BUILDER), str(base / 'meminfo'), str(base / 'groups'), str(base / 'mounts')],
                                  capture_output=True, text=True, timeout=30)

    def test_unlimited_ram_still_respects_zero_swap_allowance(self):
        self.assertNotEqual(self.check(512 * 1024, 4 << 20, limit='max').returncode, 0)

    def test_namespaced_mount_root_does_not_hide_the_limit(self):
        self.assertNotEqual(self.check(8 << 20, 0, limit=512, mount_root='/..').returncode, 0)

    def test_low_ram_fails_with_disk_swap_guidance(self):
        result = self.check(512 * 1024, 0)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not /tmp tmpfs', result.stderr)

    def test_usable_swap_allows_a_serial_build(self):
        self.assertIn('jobs=1', self.check(512 * 1024, 512 * 1024).stdout)

    def test_cgroup_without_swap_cannot_use_host_swap(self):
        self.assertNotEqual(self.check(8 << 20, 4 << 20, limit=512).returncode, 0)
        self.assertIn('jobs=1', self.check(8 << 20, 4 << 20, limit=512, allowed_swap=512).stdout)

    def test_standalone_runner_matches_the_shared_implementation(self):
        body = BUILDER.read_text().split('# BEGIN SHARED BUILD CHILD RUNNER\n', 1)[1]
        body = body.split('# END SHARED BUILD CHILD RUNNER', 1)[0]
        shared = (ROOT / 'deploy/run-build-child.sh').read_text().splitlines()[2:]
        self.assertEqual(body, '\n'.join(shared) + '\n')

    def test_standalone_memory_accounting_copies_match(self):
        copies = []
        for name, prefix, end in [
            ('build-linux-servers-on-linux.sh', 'lr_', '\nlr_memory_jobs() {'),
            ('deploy/fresh-source.sh', 'caddy_', '\ncaddy_memory_jobs() {'),
            ('install-caddy-network-relay-native-build-cloudflare-dns.sh', 'cr_', '\n# Sequence matters:'),
        ]:
            text = (ROOT / name).read_text()
            start = text.index(prefix + 'cgroup_headroom() {')
            copies.append(text[start:text.index(end, start)].replace(prefix + 'cgroup_headroom', 'headroom').strip())
        self.assertTrue(all(body == copies[0] for body in copies))


if __name__ == '__main__':
    unittest.main()
