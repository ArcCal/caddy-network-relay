"""Check that the release advisory review follows each pinned module version."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class TransportAdvisoryTests(unittest.TestCase):
    def run_gate(self, reviewed, empty_query=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / 'check-advisories.sh'
            shutil.copyfile(Path(__file__).resolve().parents[1] / 'third_party' / script.name, script)
            snapshots = [
                {'module': name, 'version': 'v1.0.0', 'reviewed_advisories': {'GO-FIXTURE': 'reviewed'} if value else {}}
                for name, value in zip(('example.invalid/a', 'example.invalid/b'), reviewed)
            ]
            (root / 'provenance.json').write_text(json.dumps({'snapshots': snapshots}))
            tool = root / 'go'
            tool.write_text("""#!/bin/bash
set -eu
[[ "$1" == run && "$3" == -mode=query && "$4" == -json && $# == 5 ]]
[[ "$5" == 'example.invalid/a@v1.0.0' || "$5" == 'example.invalid/b@v1.0.0' ]]
if [[ "$EMPTY_QUERY" == 0 ]]; then
    printf '%s\\n' '{"config":{}}' '{"osv":{"id":"GO-FIXTURE"}}'
fi
""")
            tool.chmod(0o700)
            env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'], 'EMPTY_QUERY': str(int(empty_query))}
            return subprocess.run(['bash', script], env=env, text=True, capture_output=True, timeout=10)

    def test_shared_advisory_must_be_reviewed_for_each_snapshot(self):
        self.assertEqual(self.run_gate([True, True]).returncode, 0)
        for reviewed, module in (([True, False], 'b'), ([False, True], 'a')):
            with self.subTest(module=module):
                result = self.run_gate(reviewed)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'example.invalid/{module}@v1.0.0 has unreviewed advisories GO-FIXTURE', result.stderr)

    def test_empty_scanner_output_fails(self):
        result = self.run_gate([True, True], empty_query=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing govulncheck output', result.stderr)
