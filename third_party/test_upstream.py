#!/usr/bin/env python3
"""Verify snapshot provenance and run original transport tests with our patches."""

import hashlib
import json
import os
from pathlib import Path
import re
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
            local = root / snapshot.get("directory", "quic-go" if module.endswith("quic-go") else "x-net")
            selected = json.loads(subprocess.check_output(
                ["go", "list", "-m", "-json", module], cwd=root.parent, text=True))
            if (selected.get("Version") != snapshot.get("selected_version", version) or
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
            if local.name in ("go-jose-v3", "go-jose-v4"):
                for fixture in snapshot["test_fixtures"]:
                    source = root / fixture["source"]
                    if hashlib.sha256(source.read_bytes()).hexdigest() != fixture["sha256"]:
                        raise RuntimeError(f"JOSE security fixture changed: {source.name}")
                    destination = target / fixture["target"]
                    original_hash = fixture.get("upstream_sha256")
                    if original_hash and hashlib.sha256(destination.read_bytes()).hexdigest() != original_hash:
                        raise RuntimeError(f"upstream JOSE fixture changed: {destination.name}")
                    shutil.copyfile(source, destination)
                crypto = subprocess.check_output(
                    ["go", "list", "-m", "-f", "{{.Path}}@{{.Version}}", "golang.org/x/crypto"],
                    cwd=root.parent, text=True).strip()
                subprocess.run(["go", "mod", "edit", "-go=1.26.0", f"-require={crypto}"],
                               cwd=target, check=True)
                sums = set((target / "go.sum").read_text().splitlines())
                sums.update((root.parent / "go.sum").read_text().splitlines())
                (target / "go.sum").write_text("\n".join(sorted(sums)) + "\n")
                packages = ["./..."]
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
                # Exercise Host fallback with an absent :authority. An empty
                # but present :authority cannot be replaced by Host (RFC 9113
                # section 8.3.1). Keep the fixture's request assertions intact.
                server_test = target / "http2/server_test.go"
                source = server_test.read_text()
                before = 'BlockFragment: st.encodeHeader(":authority", "", "host", host),'
                after = ('BlockFragment: st.encodeHeaderRaw(":method", "GET", '
                         '":scheme", "https", ":path", "/", "host", host),')
                if source.count(before) != 1:
                    raise RuntimeError("upstream Host fallback fixture changed")
                source = source.replace(before, after)
                # The field-size test must name an HTTP authority so that its
                # only error is its oversized field section, still yielding 431.
                start = source.index("func testServerDoS_MaxHeaderListSize(")
                end = source.index("\nfunc ", start + 1)
                block = source[start:end]
                before = 'st.encodeHeaderField(":scheme", "https")\n'
                if block.count(before) != 1:
                    raise RuntimeError("upstream field-size fixture changed")
                block = block.replace(before, before + '\tst.encodeHeaderField(":authority", "example.com")\n')
                source = source[:start] + block + source[end:]
                server_test.write_text(source)
            if local.name == "quic-go":
                # HTTP/3 and HTTP/2 share the reviewed authority grammar.
                # Keep the temporary test module's transport dependencies at
                # the same reviewed versions as the application module.
                dependency_names = [f"golang.org/x/{name}"
                                    for name in ("crypto", "net", "sys", "term", "text")]
                dependencies = subprocess.check_output(
                    ["go", "list", "-m", "-f", "{{.Path}}@{{.Version}}", *dependency_names],
                    cwd=root.parent, text=True).splitlines()
                if sorted(item.split("@")[0] for item in dependencies) != sorted(dependency_names):
                    raise RuntimeError("application transport dependency graph changed")
                subprocess.run(["go", "mod", "edit", "-replace",
                                f"golang.org/x/net={root / 'x-net'}",
                                *(f"-require={item}" for item in dependencies)],
                               cwd=target, check=True)
                sums = set((target / "go.sum").read_text().splitlines())
                sums.update((root.parent / "go.sum").read_text().splitlines())
                (target / "go.sum").write_text("\n".join(sorted(sums)) + "\n")
                shutil.copyfile(root / "quic_receive_budget_test.go.txt",
                                target / "relay_receive_budget_test.go")
                shutil.copyfile(root / "quic_push_frames_test.go.txt",
                                target / "http3/relay_push_frames_test.go")
                shutil.copyfile(root / "quic_request_scheme_test.go.txt",
                                target / "http3/relay_request_scheme_test.go")
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
                # These valid-message fixtures omitted the mandatory scheme.
                # Supply that precondition without changing their assertions.
                for name, expected in (("TestRequestHeadersContentLength", 2),
                                       ("TestCookieHeader", 1),
                                       ("TestHeadersConcatenation", 1)):
                    start = source.index(f"func {name}(")
                    end = source.index("\nfunc ", start + 1)
                    block = source[start:end]
                    block, count = re.subn(
                        r"(?m)^([\t ]*)headers := \[\]qpack.HeaderField\{\n",
                        lambda m: m.group(0) + m.group(1) + '\t{Name: ":scheme", Value: "https"},\n',
                        block)
                    if count != expected:
                        raise RuntimeError(f"upstream valid-request fixture changed: {name}")
                    source = source[:start] + block + source[end:]
                benchmark_before = "var benchmarkRequestHeaders = []qpack.HeaderField{\n"
                if source.count(benchmark_before) != 1:
                    raise RuntimeError("upstream request benchmark fixture changed")
                source = source.replace(benchmark_before, benchmark_before + '\t{Name: ":scheme", Value: "https"},\n')
                if source.count(before) != 1:
                    raise RuntimeError("upstream extended CONNECT test contract changed")
                test.write_text(source.replace(before, after))
                print("Updated two extended CONNECT assertions to require preserved scheme.", flush=True)
                packages = [".", "./http3"]
            print(f"Testing patched {module}@{version}", flush=True)
            subprocess.run(["go", "test",
                            # The temporary QUIC test module now uses our x/net
                            # replacement, whose dependency graph differs from
                            # upstream. Permit sums to update only in that copy.
                            *(["-mod=mod"] if local.name in ("quic-go", "go-jose-v3", "go-jose-v4") else []),
                            "-p", str(os.cpu_count() and min(4, os.cpu_count())),
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
