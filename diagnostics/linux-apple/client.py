"""Score a native Apple client against independently counted Linux TCP and UDP origins."""
import base64
import hashlib
import json
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

opener = build_opener(ProxyHandler({}))
def fetch(path):
    with opener.open("http://127.0.0.1:18080/" + path, timeout=10) as response:
        return response.read()

def run(kind, mode, operation, size, count, concurrency, negative=""):
    label = f"{kind}-{mode}-{operation}-{size}-{concurrency}" + (f"-{negative}" if negative else "")
    result = output / (label + ".json")
    if result.exists():
        raise ValueError("duplicate case " + label)
    data = (bytes(range(256)) * (size // 256 + 1))[:size]
    digest = hashlib.sha256(data).hexdigest()
    settings = {"profile": str(private / (kind + ("-wrong" if negative == "password" else "") + ".mobileconfig")),
                "mode": mode, "url": "https://relay.test:" + ("18553/" if operation == "udp" else "18443/") + str(size),
                "expectedBytes": size, "expectedSHA256": digest, "count": count, "concurrency": concurrency,
                "timeoutSeconds": 8 if operation == "udp" or negative else 75, "testRootDER": str(private/"ca.der"),
                "trustRelay": negative != "certificate"}
    if operation == "udp":
        settings["operation"] = "udp"
    if operation == "upload":
        upload = private/"upload.bin"
        upload.write_bytes(data)
        settings.update(uploadFile=str(upload), uploadBytes=size, uploadSHA256=digest, expectedBytes=4096,
                        expectedSHA256=hashlib.sha256(bytes(range(256))*16).hexdigest())
    request = private/"settings.json"
    request.write_text(json.dumps(settings))
    before = json.loads(fetch("counts"))
    child = subprocess.run([probe, str(request), str(result)], capture_output=True, timeout=190)
    after = json.loads(fetch("counts"))
    report = json.loads(result.read_text()) if result.exists() else {}
    samples = report.get("samples", [])
    observed = after.get(operation,0) - before.get(operation,0)
    key = kind + ("_udp" if operation == "udp" else "_tcp")
    route = after.get(key,0) - before.get(key,0)
    verified = sum(x.get("ok") is True for x in samples)
    ok = (child.returncode != 0 and observed == 0 and not report.get("completed",False) and bool(report)) if negative else (
        child.returncode == 0 and report.get("completed") is True and verified == count and observed == count
        and (mode == "direct" or route > 0))
    row = {"case":label,"rc":child.returncode,"ok":bool(ok),"origin_count":observed,"relay_log_count":route,
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
        cfg=plistlib.loads(profile)
        hop=next(x for x in cfg["PayloadContent"] if x.get("PayloadType")=="com.apple.relay.managed")["Relays"][0]
        headers=hop.setdefault("AdditionalHTTPHeaderFields",{})
        for key in list(headers):
            if key.lower() in ("authorization","proxy-authorization"):
                del headers[key]
        headers["Authorization"]="Basic "+base64.b64encode(b"alice:wrong-disposable-password").decode()
        (private/(server+"-wrong.mobileconfig")).write_bytes(plistlib.dumps(cfg))
        for mode in ("direct","h2","h3","auto"):
            run(server,mode,"download",4096,2,1)
            run(server,mode,"download",1048576,4,4)
            run(server,mode,"upload",1048576,2,1)
            for size in (62,63,64,1200,1350,1400):
                run(server,mode,"udp",size,8,1)
            if mode in ("h2","h3"):
                for negative in ("password","certificate"):
                    run(server,mode,"download",4096,1,1,negative)
                    run(server,mode,"udp",64,1,1,negative)
failed=sum(not r["ok"] for r in rows)
print(f"{len(rows)} cases, {failed} failures")
sys.exit(bool(failed))
