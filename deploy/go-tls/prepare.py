#!/usr/bin/env python3
"""Prepare hash-pinned TLS source in a private GOROOT; never edit installed Go."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

ASSETS = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_inventory(root):
    source = root / 'src'
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Go source tree must be a real directory.')
    inventory = {}
    for path in source.rglob('*'):
        if path.is_symlink():
            raise ValueError('Go source tree contains a symbolic link.')
        if path.is_file():
            inventory[str(path.relative_to(root))] = digest(path)
        elif not path.is_dir():
            raise ValueError('Go source tree contains a non-regular entry.')
    return inventory


def prepare(original, output):
    root = original.resolve(strict=True)
    if output.is_symlink():
        raise ValueError('The prepared GOROOT must not be a symbolic link.')
    output = output.resolve()
    if output == root or root in output.parents:
        raise ValueError('The prepared GOROOT must be separate from the installed toolchain.')
    manifest = json.loads((ASSETS / 'source-manifest.json').read_text())
    version = (root / 'VERSION').read_text().splitlines()[0]
    record = manifest['versions'].get(version)
    if record is None:
        raise ValueError('No reviewed TLS source policy for Go release: ' + version)
    for relative, expected_hash in record['original_files'].items():
        if digest(root / relative) != expected_hash:
            raise ValueError('Installed Go source does not match the reviewed official release: ' + relative)
    assets = dict(manifest['files'])
    assets[record['patched_conn_file']] = record['patched_conn_sha256']
    for relative, expected in assets.items():
        path = ASSETS / relative
        if path.is_symlink() or digest(path) != expected:
            raise ValueError('TLS policy asset checksum mismatch: ' + relative)
    expected = {
        'policy': manifest['policy'], 'build_tag': manifest['retained_build_tag'],
        'go_version': version, 'original_root': str(root),
        'original_conn_sha256': record['original_conn_sha256'],
        'patched_conn_sha256': record['patched_conn_sha256'],
        'helper_sha256': manifest['files']['relay_key_usage.go.txt'],
        'stdlib_policies': manifest['stdlib_policies'],
        'original_files': record['original_files'],
        'patched_files': {relative: manifest['files'][asset]
                          for relative, asset in record['patched_files'].items()},
    }
    expected_source = source_inventory(root) | expected['patched_files']
    if output.exists():
        if not output.is_dir() or json.loads((output / 'relay-tls-policy.json').read_text()) != expected:
            raise ValueError('Existing prepared GOROOT has a different policy or source.')
        for relative, expected_hash in expected['patched_files'].items():
            if digest(output / relative) != expected_hash:
                raise ValueError('Existing prepared GOROOT has modified TLS/HTTP source: ' + relative)
        if source_inventory(output) != expected_source:
            raise ValueError('Existing prepared GOROOT source tree differs from its inputs.')
        return output
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='.relay-go-tls-', dir=output.parent))
    try:
        for entry in root.iterdir():
            if entry.name == 'src':
                shutil.copytree(entry, temporary / 'src')
            else:
                (temporary / entry.name).symlink_to(entry)
        for relative, asset in record['patched_files'].items():
            shutil.copyfile(ASSETS / asset, temporary / relative)
        if source_inventory(temporary) != expected_source:
            raise ValueError('Prepared Go source tree differs from its inputs.')
        (temporary / 'relay-tls-policy.json').write_text(json.dumps(expected, indent=2) + '\n')
        temporary.rename(output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        print(prepare(args.original, args.output))
    except (OSError, ValueError, KeyError, IndexError) as error:
        parser.exit(1, 'Cannot prepare reviewed Go TLS policy: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
