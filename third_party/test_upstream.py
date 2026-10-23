#!/usr/bin/env python3
"""Verify snapshot provenance and run original transport tests with our patches."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from fixture_patches import apply_records

# x/net v0.60.0 test files, unchanged, that replace their v0.59.0 versions:
# frame_test.go covers GO-2026-6603; the others follow the GO-2026-6611 flow
# accounting API.
HTTP2_SECURITY_TEST_FILES = {
    "flow_test.go": "3210e9d2f9fb2cb2286eebe350304e4374b22e7258af62ccccefd02a740a202a",
    "frame_test.go": "f4d911738bcdc395e9e6cb0a252940776ee0f9c17d8f6e054bb8e4ad00ed2186",
    "writesched_test.go": "55a122db9707e8df1c4b26ae7757ae33fd7b91ccd9a9eaf0a51be0af98188273",
    "writesched_priority_rfc7540_test.go": "2c3c03d779530e47f64bb696346bbd51f60142b203b009268a030e0e2b0e8b54",
}


def main():
    root = Path(__file__).resolve().parent
    provenance = json.loads((root / "provenance.json").read_text())
    with tempfile.TemporaryDirectory(prefix="relay-transports-") as scratch:
        for snapshot in provenance["snapshots"]:
            module, version = snapshot["module"], snapshot["version"]
            local = root / ("quic-go" if module.endswith("quic-go") else "x-net")
            selected = json.loads(subprocess.check_output(
                ["go", "list", "-m", "-json", module], cwd=root.parent, text=True))
            if (selected.get("Version") != version or
                    Path(selected.get("Replace", {}).get("Dir", "")).resolve() != local.resolve()):
                raise RuntimeError(f"main module does not use the recorded snapshot: {module}")
            files = {f["path"]: f for f in snapshot["files"]}
            actual = {str(p.relative_to(local)) for p in local.rglob("*") if p.is_file()}
            if actual != set(files):
                raise RuntimeError(f"snapshot file list changed: {module}")
            fixture_hashes = {}
            if local.name == "x-net":
                records = json.loads((root / "fixture-patches.json").read_text())
                for entry in records["files"]:
                    name = entry["path"]
                    if files[name]["modified"] or files[name]["local_sha256"] != entry["before_sha256"]:
                        raise RuntimeError(f"Fixture provenance mismatch: {name}")
                    fixture_hashes[name] = entry["after_sha256"]
            for name, entry in files.items():
                digest = hashlib.sha256((local / name).read_bytes()).hexdigest()
                if digest != fixture_hashes.get(name, entry["local_sha256"]):
                    raise RuntimeError(f"snapshot hash mismatch: {module}/{name}")

            downloaded = json.loads(subprocess.check_output(
                ["go", "mod", "download", "-json", f"{module}@{version}"], text=True))
            checksum = f"{module} {version} {downloaded['Sum']}"
            if checksum not in snapshot["go_sum"]:
                raise RuntimeError(f"upstream module checksum mismatch: {module}")
            original = Path(downloaded["Dir"])
            for name, entry in files.items():
                digest = hashlib.sha256((original / name).read_bytes()).hexdigest()
                if digest != entry["upstream_sha256"]:
                    raise RuntimeError(f"upstream source hash mismatch: {module}/{name}")

            if local.name == "x-net":
                baseline = {name: (original / name).read_bytes() for name in fixture_hashes}
                replayed = apply_records(baseline, root / "fixture-patches.json")
                for name, data in replayed.items():
                    if data != (local / name).read_bytes():
                        raise RuntimeError(f"Fixture replay mismatch: {name}")

            target = Path(scratch) / local.name
            shutil.copytree(original, target)
            target.chmod(target.stat().st_mode | 0o700)
            for p in target.rglob("*"):
                p.chmod(p.stat().st_mode | (0o700 if p.is_dir() else 0o200))
            shutil.copytree(local, target, dirs_exist_ok=True)
            packages = ["./http2"]
            if local.name == "x-net":
                shutil.copyfile(root / "http2_regression_test.go.txt",
                                target / "http2/relay_patch_test.go")
                shutil.copyfile(root / "http2_buffer_regression_test.go.txt",
                                target / "http2/relay_buffer_patch_test.go")
                # Security fixes backported from x/net v0.60.0 come with its
                # regression tests: whole test files, unchanged, which replace
                # their v0.59.0 versions, and selected tests.
                for name, digest in HTTP2_SECURITY_TEST_FILES.items():
                    fixture = root / f"http2_security_{name}.txt"
                    if hashlib.sha256(fixture.read_bytes()).hexdigest() != digest:
                        raise RuntimeError(f"x/net v0.60.0 test fixture changed: {name}")
                    shutil.copyfile(fixture, target / "http2" / name)
                shutil.copyfile(root / "http2_security_test.go.txt",
                                target / "http2/relay_security_test.go")
                shutil.copyfile(root / "http2_security_internal_test.go.txt",
                                target / "http2/relay_security_internal_test.go")
            if local.name == "quic-go":
                shutil.copyfile(root / "quic_receive_budget_test.go.txt",
                                target / "relay_receive_budget_test.go")
                shutil.copyfile(root / "quic_push_frames_test.go.txt",
                                target / "http3/relay_push_frames_test.go")
                config_test = target / "config_test.go"
                config_source = config_test.read_text()
                config_before = '\t\tcase "EnableStreamResetPartialDelivery":'
                config_after = ('\t\tcase "ReceiveBufferBudget":\n'
                                '\t\t\tf.Set(reflect.ValueOf(&relayQUICReceiveBudget{}))\n'
                                + config_before)
                if config_source.count(config_before) != 1:
                    raise RuntimeError("upstream Config reflection fixture changed")
                config_test.write_text(config_source.replace(config_before, config_after))
                # Our intentional API change preserves extended CONNECT's
                # scheme in URL.Scheme. Keep every other upstream assertion.
                test = target / "http3/headers_test.go"
                test.chmod(test.stat().st_mode | 0o200)
                before = ('require.Equal(t, "/foo?val=1337", req.URL.String())\n'
                          '\trequire.Empty(t, req.URL.Scheme)')
                after = ('require.Equal(t, "ftp:///foo?val=1337", req.URL.String())\n'
                         '\trequire.Equal(t, "ftp", req.URL.Scheme)')
                source = test.read_text()
                if source.count(before) != 1:
                    raise RuntimeError("upstream extended CONNECT test contract changed")
                test.write_text(source.replace(before, after))
                print("Updated two extended CONNECT assertions to require preserved scheme.", flush=True)
                packages = [".", "./http3"]
            print(f"Testing patched {module}@{version}", flush=True)
            subprocess.run(["go", "test", "-p", str(os.cpu_count() and min(4, os.cpu_count())),
                            "-race", "-count=1", "-timeout=10m",
                            *(["-tags=http2legacy"] if local.name == "x-net" else []),
                            # Replaced by relay_push_frames_test.go: it requires
                            # push frames to be skipped, which RFC 9114 forbids.
                            *(["-skip", "^TestParserUnsupportedFrameTypes$"]
                              if local.name == "quic-go" else []),
                            *packages],
                           cwd=target, check=True)


if __name__ == "__main__":
    main()
