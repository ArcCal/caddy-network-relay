#!/usr/bin/env python3
"""Focused tests for the unchanged Rust domain pipeline and Caddy profile adapter."""

import base64
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('selective_profile_under_test', HERE / 'selective-profile.py')
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)
HOST = 'relay.example.com'
PASSWORD = 'a-long-fixture-password'


class DomainSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.base = self.root / 'base.txt'
        self.base.write_text('www.google.com\nrelay.example.com\nx.foo.github.io\napi.example.co.uk\nsite.adult\n')
        self.gfw = self.root / 'gfw.txt'
        self.gfw.write_bytes(base64.b64encode(b'[AutoProxy]\n||sub.example.net^\n@@||direct.example.net^\n/regex/\n'))
        self.rules = self.root / 'rules'
        self.rules.mkdir()
        for name in ADAPTER.RULES.SERVICE_RULE_NAMES:
            (self.rules / (name + '.yaml')).write_text(
                'payload:\n  - DOMAIN,api.service.example.com\n  - DOMAIN-SUFFIX,listed.example.org\n'
                '  - IP-CIDR,192.0.2.0/24\n')

    def tearDown(self):
        self.temp.cleanup()

    def test_copied_source_and_data_are_exact_upstream_bytes(self):
        expected = {
            'global-profile.py': '18ec3021e176033b17a4226c63bab2c0a8f46029b5138e62950ec5a12144b64a',
            'domains/google-ai-social.txt': 'b85cc1cedd63e8160a621c79e710f7a49d48c06871b0837e7d93816d986d73fc',
            'domains/public-suffix-icann.dat': 'c296bb2831fb2828dc9eaea2db9c937b3171744c56624446be31b5f739bb2db0',
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), digest)

    def test_matches_exact_rust_installer_pipeline(self):
        with redirect_stdout(io.StringIO()):
            expected = ADAPTER.RULES.load_domain_file(self.base)
            expected += ADAPTER.RULES.extract_gfwlist(ADAPTER.RULES.decode_gfwlist(self.gfw.read_bytes()))[0]
            expected += ADAPTER.RULES.load_service_rules(self.rules)
            expected = ADAPTER.RULES.normalized_domains(expected, HOST)
            actual = ADAPTER.build_domains(HOST, base=self.base, gfwlist_file=self.gfw, rules_dir=self.rules)
        self.assertEqual(actual, expected)
        self.assertEqual(actual, ['example.co.uk', 'example.com', 'example.net', 'example.org', 'github.io', 'google.com'])
        self.assertNotIn('adult', actual)
        self.assertNotIn(HOST, actual)

    def test_default_downloads_all_selected_sources(self):
        fetched = []

        def fetch(url, timeout=None):
            fetched.append(url.full_url if hasattr(url, 'full_url') else url)
            if fetched[-1] == ADAPTER.RULES.GFWLIST_URL:
                return io.BytesIO(self.gfw.read_bytes())
            return io.BytesIO(b'payload:\n  - DOMAIN-SUFFIX,selected.example.org\n')

        with patch.object(ADAPTER.RULES.urllib.request, 'urlopen', side_effect=fetch), redirect_stdout(io.StringIO()):
            ADAPTER.build_domains(HOST)
        self.assertEqual(set(fetched), {ADAPTER.RULES.GFWLIST_URL, *ADAPTER.RULES.SERVICE_RULE_URLS.values()})
        self.assertEqual(len(fetched), 19)
        self.assertNotIn(ADAPTER.RULES.PROXY_LIST_URL, fetched)

    def test_missing_service_does_not_issue_partial_domains(self):
        (self.rules / 'Claude.yaml').unlink()
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, 'No partial profile'):
            ADAPTER.build_domains(HOST, base=self.base, no_gfwlist=True, rules_dir=self.rules)

    def test_empty_base_and_gfwlist_fail(self):
        self.base.write_text('# Empty\n')
        with self.assertRaisesRegex(ValueError, 'base domain list is empty'):
            ADAPTER.build_domains(HOST, base=self.base, no_gfwlist=True, no_service_rules=True)
        self.base.write_text('www.google.com\n')
        self.gfw.write_text('[AutoProxy]\n! Empty\n')
        with self.assertRaisesRegex(ValueError, 'no convertible domains'):
            ADAPTER.build_domains(HOST, base=self.base, gfwlist_file=self.gfw, no_service_rules=True)

    def test_default_base_is_only_the_rust_installer_base(self):
        with redirect_stdout(io.StringIO()):
            actual = ADAPTER.build_domains(HOST, no_gfwlist=True, no_service_rules=True)
        expected = ADAPTER.RULES.normalized_domains(
            ADAPTER.RULES.load_domain_file(HERE / 'domains/google-ai-social.txt'), HOST)
        self.assertEqual(actual, expected)


class ProfileGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.domains = self.root / 'domains.json'
        self.domains.write_text(json.dumps(['example.net', 'google.com']))
        self.out = self.root / 'device.mobileconfig'
        self.binary = self.root / 'caddy-stub'
        self.binary.write_text('#!/bin/sh\nexit 0\n')
        self.binary.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def seed(self):
        return {
            'PayloadType': 'Configuration',
            'PayloadContent': [{
                'PayloadType': 'com.apple.relay.managed',
                'MatchDomains': ['example.invalid'],
                'ExcludedDomains': [HOST],
                'UIToggleEnabled': True,
                'Relays': [{
                    'HTTP2RelayURL': f'https://{HOST}{ADAPTER.UDP_TEMPLATE}',
                    'AdditionalHTTPHeaderFields': {
                        'Authorization': 'Basic ' + base64.b64encode(f'iphone:{PASSWORD}'.encode()).decode(),
                    },
                }],
            }],
        }

    def fake_run(self, command, **kwargs):
        self.assertEqual(command[:3], [str(self.binary), 'network-relay', 'profile'])
        self.assertIn('--password-stdin', command)
        self.assertIn('--no-http3', command)
        self.assertNotIn('--password', command)
        self.assertNotIn(PASSWORD, command)
        self.assertEqual(kwargs['input'], PASSWORD + '\n')
        Path(command[-1]).write_bytes(plistlib.dumps(self.seed()))
        return subprocess.CompletedProcess(command, 0)

    def generate(self, run=None):
        with patch.object(ADAPTER.subprocess, 'run', side_effect=run or self.fake_run), redirect_stdout(io.StringIO()):
            return ADAPTER.generate_profile(HOST, 'iphone', self.binary, self.domains, self.out, PASSWORD)

    def test_password_stdin_transport_scope_and_private_atomic_output(self):
        self.out.write_bytes(b'old profile')
        self.out.chmod(0o644)
        self.generate()
        profile = plistlib.loads(self.out.read_bytes())
        payload = profile['PayloadContent'][0]
        self.assertEqual(payload['MatchDomains'], ['example.net', 'google.com'])
        self.assertEqual(payload['ExcludedDomains'], [HOST])
        self.assertNotIn('HTTP3RelayURL', payload['Relays'][0])
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)
        self.assertFalse(any(p.name.startswith('.relay-profile') for p in self.root.iterdir()))

    def test_rejects_wrong_transport_credentials_scope_and_hops(self):
        for mutation in ('http3', 'url', 'auth', 'exclude', 'hops', 'payloads', 'dns'):
            with self.subTest(mutation=mutation):
                seed = self.seed()
                payload = seed['PayloadContent'][0]
                relay = payload['Relays'][0]
                if mutation == 'http3':
                    relay['HTTP3RelayURL'] = relay['HTTP2RelayURL']
                elif mutation == 'url':
                    relay['HTTP2RelayURL'] = 'https://other.example.com/'
                elif mutation == 'auth':
                    relay['AdditionalHTTPHeaderFields']['Authorization'] = 'Basic wrong'
                elif mutation == 'exclude':
                    payload['ExcludedDomains'] = []
                elif mutation == 'hops':
                    payload['Relays'].append(dict(relay))
                elif mutation == 'payloads':
                    seed['PayloadContent'].append(dict(payload))
                elif mutation == 'dns':
                    payload['AllowDNSFailover'] = True
                self.out.write_bytes(b'preserve prior profile')

                def emit(command, **kwargs):
                    Path(command[-1]).write_bytes(plistlib.dumps(seed))
                    return subprocess.CompletedProcess(command, 0)

                with self.assertRaises(ValueError):
                    self.generate(emit)
                self.assertEqual(self.out.read_bytes(), b'preserve prior profile')

    def test_rejects_oversize_without_replacing_output(self):
        seed = self.seed()
        seed['PayloadDisplayName'] = 'x' * ADAPTER.RULES.MAX_DEVICE_PROFILE_BYTES

        def emit(command, **kwargs):
            Path(command[-1]).write_bytes(plistlib.dumps(seed))
            return subprocess.CompletedProcess(command, 0)

        self.out.write_bytes(b'old')
        with self.assertRaisesRegex(ValueError, '524288'):
            self.generate(emit)
        self.assertEqual(self.out.read_bytes(), b'old')

    def test_invalid_seed_structure_preserves_prior_output(self):
        for raw in (b'not a plist', plistlib.dumps({'PayloadContent': []}), plistlib.dumps({'PayloadContent': ['invalid']})):
            with self.subTest(raw=raw[:30]):
                self.out.write_bytes(b'old profile')

                def emit(command, **kwargs):
                    Path(command[-1]).write_bytes(raw)
                    return subprocess.CompletedProcess(command, 0)

                with self.assertRaises((ValueError, plistlib.InvalidFileException)):
                    self.generate(emit)
                self.assertEqual(self.out.read_bytes(), b'old profile')

    def test_rejects_nonregular_and_self_overwrite(self):
        self.out.symlink_to(self.domains)
        with self.assertRaises(ValueError):
            self.generate()
        self.out.unlink()
        self.out.mkdir()
        with self.assertRaises(ValueError):
            self.generate()
        self.out.rmdir()
        for output in (self.binary, self.domains):
            with self.assertRaises(ValueError):
                ADAPTER.generate_profile(HOST, 'iphone', self.binary, self.domains, output, PASSWORD)

    def test_bad_domains_are_rejected_before_running_binary(self):
        for domains in ([], ['a.foo.github.io'], ['google.com', 'google.com'], [HOST], [123], ['not a domain']):
            with self.subTest(domains=domains):
                self.domains.write_text(json.dumps(domains))
                with patch.object(ADAPTER.subprocess, 'run') as run, self.assertRaises(ValueError):
                    ADAPTER.generate_profile(HOST, 'iphone', self.binary, self.domains, self.out, PASSWORD)
                run.assert_not_called()

    def test_failed_child_stderr_is_not_exposed(self):
        with (patch.object(sys, 'stdin', io.StringIO(PASSWORD + '\n')),
                patch.object(ADAPTER.subprocess, 'run', side_effect=subprocess.CalledProcessError(
                    1, 'caddy', stderr=PASSWORD)), redirect_stderr(io.StringIO()) as errors):
            status = ADAPTER.main(['profile', '--host', HOST, '--user', 'iphone', '--binary', str(self.binary),
                                   '--domains', str(self.domains), '--out', str(self.out)])
        self.assertEqual(status, 1)
        self.assertNotIn(PASSWORD, errors.getvalue())
        self.assertFalse(self.out.exists())

    @unittest.skipUnless(os.environ.get('CADDY_REAL_BINARY'), 'set CADDY_REAL_BINARY to test the real profile CLI')
    def test_real_caddy_profile_command(self):
        with redirect_stdout(io.StringIO()):
            ADAPTER.generate_profile(HOST, 'iphone', os.environ['CADDY_REAL_BINARY'],
                                     self.domains, self.out, PASSWORD)
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)
        ADAPTER.validate_profile(self.out.read_bytes(), HOST, 'iphone', PASSWORD, ['example.net', 'google.com'])


if __name__ == '__main__':
    unittest.main()
