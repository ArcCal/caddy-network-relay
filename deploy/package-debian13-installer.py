#!/usr/bin/env python3
"""Package private Caddy source and deployment tools into one uploadable script."""
import argparse
import base64
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import textwrap

ROOT = Path(__file__).resolve().parent.parent
DEPLOY_FILES = (
    'deploy/install-debian13-selective.sh', 'deploy/selective-profile.py',
    'deploy/global-profile.py', 'deploy/caddy.service',
    'deploy/domains/google-ai-social.txt', 'deploy/domains/public-suffix-icann.dat',
    'deploy/domains/LICENSE.domain-list-community',
    'deploy/domains/UPSTREAM.md',
    'docs/debian13-selective-install.md', 'deploy/selective-source.json',
)


def package(output):
    files = set(DEPLOY_FILES) | {'go.mod', 'go.sum'}
    files.update(p.name for p in ROOT.glob('*.go') if not p.name.endswith('_test.go'))
    files.update(str(p.relative_to(ROOT)) for p in (ROOT / 'cmd').rglob('*.go')
                 if not p.name.endswith('_test.go'))
    # Preserve local replacements, licenses and embedded resources. This is
    # the actual repository's Caddy build, not a vanilla xcaddy module build.
    files.update(str(p.relative_to(ROOT)) for p in (ROOT / 'third_party').rglob('*')
                 if p.is_file() and '.git' not in p.parts)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for relative in sorted(files):
            data = (ROOT / relative).read_bytes()
            entry = tarfile.TarInfo(relative)
            entry.size = len(data)
            entry.mode = 0o644
            archive.addfile(entry, io.BytesIO(data))
    compressed = bytearray(gzip.compress(stream.getvalue(), mtime=0))
    compressed[9] = 255
    bundle_hash = hashlib.sha256(compressed).hexdigest()
    payload = '\n'.join(textwrap.wrap(base64.b64encode(compressed).decode(), 76))
    script = '''#!/usr/bin/env bash
# Fresh Debian 13 x64 Caddy Network Relay installer, with bundled private sources.
# Default: source build, public ACME TLS, selected domains, HTTP/2-only mobileconfig.
# Run with sudo bash; --help shows installation options; --extract DIR only unpacks.
set +x
set -Eeuo pipefail
if [[ ${1:-} != --help && ${1:-} != -h && ${1:-} != --extract && $EUID != 0 ]]; then
    echo 'Run this installer with sudo bash.' >&2
    exit 1
fi
bundle_dir=$(mktemp -d "${TMPDIR:-/tmp}/caddy-network-relay-installer.XXXXXXXX")
trap 'rm -rf -- "$bundle_dir"' EXIT
base64 --decode >"$bundle_dir/source.tar.gz" <<'CADDY_NETWORK_RELAY_SOURCE_BUNDLE'
''' + payload + '''
CADDY_NETWORK_RELAY_SOURCE_BUNDLE
'''
    script += f"printf '%s  %s\\n' '{bundle_hash}' \"$bundle_dir/source.tar.gz\" | sha256sum --check --status\n"
    script += '''mkdir "$bundle_dir/source"
tar -xzf "$bundle_dir/source.tar.gz" -C "$bundle_dir/source"
if [[ ${1:-} == --extract ]]; then
    [[ $# == 2 && -n $2 && ! -e $2 && ! -L $2 ]] || {
        echo '--extract requires a new, nonexistent destination directory.' >&2
        exit 1
    }
    mkdir -m 700 -- "$2"
    cp -R "$bundle_dir/source/." "$2/"
    echo "Bundled sources extracted to $2; no service was installed."
    exit 0
fi
bash "$bundle_dir/source/deploy/install-debian13-selective.sh" "$@"
'''
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(script)
    output.chmod(0o755)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + '.sha256').write_text(f'{digest}  {output.name}\n')
    print(f'Wrote {output}: {output.stat().st_size} bytes; {len(files)} bundled files.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'caddy-network-relay-install-debian13.sh')
    package(parser.parse_args().out)
