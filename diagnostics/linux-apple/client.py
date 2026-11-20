"""Score a native Apple client against independently counted Linux TCP and UDP origins."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

opener = build_opener(ProxyHandler({}))
def fetch(path):
    with opener.open("http://127.0.0.1:18080/" + path, timeout=10) as response:
        return response.read()

def run(kind, mode, operation, size, count, concurrency, trial):
    label = f"{kind}-{mode}-{operation}-{size}-{concurrency}-trial{trial}"
    result = output / (label + ".json")
    if result.exists():
        raise ValueError("duplicate case " + label)
    block = bytes(range(256)) * 256
    digest = hashlib.sha256()
    for _ in range(size // len(block)):
        digest.update(block)
    digest.update(block[:size % len(block)])
    settings = {
        "profile": str(private / (kind + ".mobileconfig")), "mode": mode,
        "url": f"https://relay.test:18443/{size}", "expectedBytes": size,
        "expectedSHA256": digest.hexdigest(), "count": count, "concurrency": concurrency,
        "timeoutSeconds": 180, "testRootDER": str(private / "ca.der"), "trustRelay": True,
    }
    request = private/"settings.json"
    request.write_text(json.dumps(settings))
    before = json.loads(fetch("counts"))
    try:
        rc = subprocess.run([probe, str(request), str(result)], capture_output=True, timeout=245).returncode
    except subprocess.TimeoutExpired:
        rc = 124
    after = json.loads(fetch("counts"))
    report = json.loads(result.read_text()) if result.exists() else {}
    samples = report.get("samples", [])
    observed = after.get(operation,0) - before.get(operation,0)
    key = kind + ("_udp" if operation == "udp" else "_tcp")
    route = after.get(key,0) - before.get(key,0)
    verified = sum(x.get("ok") is True for x in samples)
    ok = (rc == 0 and report.get("completed") is True and verified == count
          and observed == count and (mode == "direct" or route > 0))
    row = {"case":label,"rc":rc,"ok":bool(ok),"origin_count":observed,"relay_log_count":route,
           "checked_payloads":verified,"client_os":report.get("os"),"native_wall_seconds":report.get("wall_seconds")}
    print(json.dumps(row),flush=True)
    rows.append(row)
    (output/"summary.json").write_text(json.dumps(rows,indent=2))


probe = sys.argv[1]
output = Path(sys.argv[2]).resolve()
output.mkdir(parents=True)
(output/"linux.json").write_bytes(fetch("environment"))
rows=[]
with tempfile.TemporaryDirectory() as directory:
    private=Path(directory)
    (private/"ca.der").write_bytes(fetch("ca.der"))
    for server in ("rust","caddy"):
        profile=fetch(server+".mobileconfig")
        (private/(server+".mobileconfig")).write_bytes(profile)
    size = 64 * 1024 * 1024
    run("rust","direct","download",size,4,4,1)
    # Alternate the order across trials to expose transient H3 progress stalls.
    for trial, servers in enumerate((("caddy","rust"),("rust","caddy")),start=1):
        for server in servers:
            if trial == 1:
                run(server,"h2","download",size,4,4,trial)
                run(server,"h3","download",size,1,1,trial)
            run(server,"h3","download",size,4,4,trial)
failed=sum(not r["ok"] for r in rows)
print(f"{len(rows)} cases, {failed} failures")
sys.exit(bool(failed))
