"""Reproduce readonly toolchain failure and verify private preparation on macOS."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

root = Path.cwd()
evidence = Path(os.environ['RUNNER_TEMP']) / 'go-permissions-evidence'
evidence.mkdir(exist_ok=True)
work = Path(os.environ['RUNNER_TEMP']) / 'go-permissions-work'
work.mkdir(exist_ok=True)
assets = root / 'deploy/go-tls'
spec = importlib.util.spec_from_file_location('prepare_candidate', assets / 'prepare.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def snapshot(source):
    return {'files': module.source_inventory(source),
            'modes': {str(p.relative_to(source)): stat.S_IMODE(p.stat().st_mode)
                      for p in [source, *source.rglob('*')] if not p.is_symlink()}}

if sys.argv[1] == 'before':
    source = Path(subprocess.check_output(['go', 'env', 'GOROOT'], text=True).strip())
    assert not (source / 'src').stat().st_mode & stat.S_IWUSR
    assert not (source / 'src/crypto/tls/conn.go').stat().st_mode & stat.S_IWUSR
    state = {'original_root': str(source), 'source': snapshot(source),
             'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
             'system': subprocess.check_output(['sw_vers'], text=True),
             'helper_sha256': hashlib.sha256((assets / 'prepare.py').read_bytes()).hexdigest()}
    (evidence / 'before.json').write_text(json.dumps(state, indent=2) + '\n')
    previous = assets / 'prepare_baseline_diagnostic.py'
    previous.write_bytes(subprocess.check_output(['git', 'show', '82441f55f70c9cdc3b24b2b91962c7786961986f:deploy/go-tls/prepare.py']))
    baseline = work / 'baseline'
    baseline.mkdir()
    try:
        result = subprocess.run([sys.executable, str(previous), str(source), str(baseline / 'prepared')],
                                capture_output=True, text=True)
        (evidence / 'baseline.log').write_text(result.stdout + result.stderr)
        assert result.returncode != 0 and 'Permission denied' in result.stderr, result
    finally:
        previous.unlink()
        for directory, _, _ in os.walk(baseline, followlinks=False):
            p = Path(directory)
            p.chmod(p.stat().st_mode | stat.S_IRWXU)
        shutil.rmtree(baseline)
    subprocess.run([sys.executable, str(assets / 'prepare.py'), str(source), str(work / 'go-tls')], check=True)
    subprocess.run([sys.executable, str(assets / 'prepare.py'), str(source), str(work / 'go-tls')], check=True)
    assert snapshot(source) == state['source']
    with open(os.environ['GITHUB_ENV'], 'a') as env:
        env.write('RELAY_TEST_OFFICIAL_GO_ROOTS=' + str(source) + '\n')
    print('Original readonly helper fails; candidate prepares and reuses exact source without changing installed content or modes.')
else:
    state = json.loads((evidence / 'before.json').read_text())
    assert snapshot(Path(state['original_root'])) == state['source']
    assert hashlib.sha256((assets / 'prepare.py').read_bytes()).hexdigest() == state['helper_sha256']
    built = []
    for arch, machine in [('amd64', 62), ('arm64', 183)]:
        binary = work / ('caddy-network-relay-' + arch)
        data = binary.read_bytes()
        assert data[:6] == b'\x7fELF\x02\x01' and int.from_bytes(data[18:20], 'little') == machine
        info = subprocess.check_output(['go', 'version', '-m', str(binary)], text=True)
        assert 'relay_tls9846_v1' in info and 'http2legacy' in info
        for dependency in ['github.com/caddy-dns/cloudflare', 'github.com/quic-go/quic-go', 'golang.org/x/net']:
            assert dependency in info, dependency
        (evidence / (arch + '-buildinfo.txt')).write_text(info)
        built.append({'arch': arch, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
    (evidence / 'result.json').write_text(json.dumps({'status': 'passed', 'binaries': built,
                                                    'installed_content_and_modes_unchanged': True}, indent=2) + '\n')
    print('Both actual Linux build helpers produced valid policy-tagged ELF binaries; installed Go is unchanged.')
