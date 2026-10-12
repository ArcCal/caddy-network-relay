#!/usr/bin/env python3
"""Adapt the unchanged Rust installer domain pipeline to Caddy profile generation."""

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('rust_relay_profile_rules', HERE / 'global-profile.py')
RULES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RULES)
UDP_TEMPLATE = '/.well-known/masque/udp/{target_host}/{target_port}/'
PROFILE_NAME = 'Selected domains - everything else direct'
MAX_INPUT_BYTES = 16 << 20


def relay_host(value):
    """Use the copied parser's domain syntax; relay endpoints require a DNS name."""
    host = value.lower().removesuffix('.')
    if RULES.clean_host(host) != host:
        raise ValueError('The relay host must be a valid DNS name, not an IP address.')
    return host


def output_path(path):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Refusing to replace a non-regular or symbolic-link output file.')
    if not path.parent.is_dir():
        raise ValueError('The output directory must already exist.')
    return path


def write_private(path, data):
    """Validate first, then atomically replace an owner-readable output file."""
    path = output_path(path)
    with tempfile.NamedTemporaryFile(prefix='.relay-profile-', dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            output_path(path)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def build_domains(host, *, base=None, no_gfwlist=False, gfwlist_file=None,
                  rules_dir=None, no_service_rules=False):
    """Same base, source selection, parsing, and normalization as Rust install.py."""
    host = relay_host(host)
    if no_gfwlist and gfwlist_file is not None:
        raise ValueError('Choose --no-gfwlist or --gfwlist-file, not both.')
    if no_service_rules and rules_dir is not None:
        raise ValueError('Choose --no-service-rules or --rules-dir, not both.')
    domains = RULES.load_domain_file(base or HERE / 'domains/google-ai-social.txt')
    if not domains:
        raise ValueError('The base domain list is empty; no partial profile will be generated.')
    if not no_gfwlist:
        if gfwlist_file is not None:
            with Path(gfwlist_file).open('rb') as stream:
                raw = RULES.read_bounded(stream)
        else:
            with RULES.urllib.request.urlopen(RULES.GFWLIST_URL, timeout=60) as stream:
                raw = RULES.read_bounded(stream)
        extracted, statistics = RULES.extract_gfwlist(RULES.decode_gfwlist(raw))
        if not extracted:
            raise ValueError('gfwlist contains no convertible domains; no partial profile will be generated.')
        domains += extracted
        print(f'gfwlist: {len(extracted)} extracted domains.', flush=True)
        for kind, count in statistics.items():
            print(f'  {kind}: {count}', flush=True)
    if not no_service_rules:
        domains += RULES.load_service_rules(rules_dir)
    domains = RULES.normalized_domains(domains, host)
    if not domains:
        raise ValueError('No matched domains remain; refusing an all-traffic profile.')
    return domains


def read_domains(path, host):
    with Path(path).open('rb') as stream:
        raw = RULES.read_bounded(stream)
    domains = json.loads(raw)
    if not isinstance(domains, list) or not domains or any(not isinstance(d, str) for d in domains):
        raise ValueError('The domains JSON must contain a non-empty array of domain strings.')
    if any(RULES.clean_host(d) != d and
           not (RULES.LABEL.fullmatch(d) and not d.isdigit()) for d in domains):
        raise ValueError('The domains JSON contains an invalid domain.')
    if RULES.normalized_domains(domains, host) != domains:
        raise ValueError('The domains JSON must be the sorted, normalized selected-domain output.')
    return domains


def validate_profile(data, host, user, password, domains):
    if len(data) >= RULES.MAX_DEVICE_PROFILE_BYTES:
        raise ValueError('The single mobileconfig must be smaller than 524288 bytes.')
    profile = plistlib.loads(data)
    if not isinstance(profile, dict) or profile.get('PayloadType') != 'Configuration':
        raise ValueError('Expected an unsigned Configuration mobileconfig.')
    payloads = profile.get('PayloadContent')
    if not isinstance(payloads, list) or len(payloads) != 1 or not isinstance(payloads[0], dict):
        raise ValueError('The mobileconfig must contain exactly one relay payload.')
    payload = payloads[0]
    if payload.get('PayloadType') != 'com.apple.relay.managed':
        raise ValueError('Expected a com.apple.relay.managed payload.')
    relays = payload.get('Relays')
    if not isinstance(relays, list) or len(relays) != 1 or not isinstance(relays[0], dict):
        raise ValueError('The mobileconfig must contain exactly one relay hop.')
    relay = relays[0]
    if 'HTTP3RelayURL' in relay or relay.get('HTTP2RelayURL') != f'https://{host}{UDP_TEMPLATE}':
        raise ValueError('The relay must use the expected HTTP/2 URL and omit HTTP3RelayURL.')
    if payload.get('MatchDomains') != domains or not domains:
        raise ValueError('The selected routing domains must be retained and non-empty.')
    if payload.get('ExcludedDomains') != [host]:
        raise ValueError('The relay hostname and its subdomains must be excluded.')
    if payload.get('MatchFQDNs') or payload.get('ExcludedFQDNs'):
        raise ValueError('Unexpected additional routing selectors in the seed profile.')
    if payload.get('UIToggleEnabled') is not True or payload.get('AllowDNSFailover') not in (None, False):
        raise ValueError('Unexpected relay toggle or DNS failover policy.')
    expected = 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()
    headers = relay.get('AdditionalHTTPHeaderFields')
    if not isinstance(headers, dict) or headers.get('Authorization') != expected:
        raise ValueError('The profile credentials must match the new server account.')
    if any(key in relay for key in ('RawPublicKeys', 'PayloadCertificateUUID')):
        raise ValueError('Unexpected certificate pinning or client identity in the public-CA profile.')
    return profile


def generate_profile(host, user, binary, domains_path, out, password):
    host = relay_host(host)
    if not user or ':' in user or any(ord(c) < 32 or ord(c) == 127 for c in user):
        raise ValueError('The relay user name must be non-empty and contain no colon or control characters.')
    if not password or any(ord(c) < 32 or ord(c) == 127 for c in password):
        raise ValueError('The password must be non-empty and contain no control characters.')
    domains = read_domains(domains_path, host)
    out = output_path(out)
    binary = Path(binary).resolve(strict=True)
    if not binary.is_file() or out.resolve() == binary or out.resolve() == Path(domains_path).resolve():
        raise ValueError('The profile output must not replace the binary or domains JSON.')
    with tempfile.TemporaryDirectory(prefix='.relay-profile-seed-', dir=out.parent) as directory:
        seed = Path(directory) / 'seed.mobileconfig'
        command = [str(binary), 'network-relay', 'profile', '--host', host, '--user', user,
                   '--password-stdin', '--no-http3', '--match-domain', 'example.invalid',
                   '--exclude-domain', host, '--ui-toggle-enabled', 'true', '--name', PROFILE_NAME,
                   '-o', str(seed)]
        subprocess.run(command, input=password + '\n', text=True, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
        with seed.open('rb') as stream:
            raw = RULES.read_bounded(stream)
        # The copied helper supplies the full compact list without ARG_MAX exposure.
        try:
            data = RULES.profile_with_domains(raw, domains)
        except (KeyError, IndexError, TypeError) as error:
            raise ValueError('The seed profile has an invalid relay payload structure.') from error
        validate_profile(data, host, user, password, domains)
        write_private(out, data)
    print(f'Wrote {out}: {len(domains)} matched roots; HTTP/2 only; mode 600.')
    return out


def password_stdin():
    value = sys.stdin.readline(MAX_INPUT_BYTES + 1)
    if len(value) > MAX_INPUT_BYTES or sys.stdin.read(1):
        raise ValueError('Provide exactly one password line on standard input.')
    return value.removesuffix('\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    domains = commands.add_parser('domains', help='Download and clean the Rust installer routing selection.')
    domains.add_argument('--host', required=True)
    domains.add_argument('--out', required=True, type=Path)
    domains.add_argument('--domains', type=Path, help='replace the Google/AI base list only')
    gfw = domains.add_mutually_exclusive_group()
    gfw.add_argument('--no-gfwlist', action='store_true')
    gfw.add_argument('--gfwlist-file', type=Path)
    RULES.add_service_rule_arguments(domains)
    profile = commands.add_parser('profile', help='Create an HTTP/2-only profile; password from stdin only.')
    for name in ('host', 'user'):
        profile.add_argument('--' + name, required=True)
    for name in ('binary', 'domains', 'out'):
        profile.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'domains':
            output_path(args.out)
            roots = build_domains(args.host, base=args.domains, no_gfwlist=args.no_gfwlist,
                                  gfwlist_file=args.gfwlist_file, rules_dir=args.rules_dir,
                                  no_service_rules=args.no_service_rules)
            write_private(args.out, (json.dumps(roots, separators=(',', ':')) + '\n').encode())
            print(f'Wrote {args.out}: {len(roots)} selected roots; relay hostname excluded.')
        else:
            generate_profile(args.host, args.user, args.binary, args.domains, args.out, password_stdin())
        return 0
    except (ValueError, OSError, plistlib.InvalidFileException, subprocess.SubprocessError) as error:
        # Do not replay a child process's stderr, which might contain credentials.
        message = 'Caddy seed profile generation failed.' if isinstance(error, subprocess.SubprocessError) else str(error)
        print(f'Profile preparation failed: {message}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
