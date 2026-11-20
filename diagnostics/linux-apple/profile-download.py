"""Drive four concurrent checked transfers through existing-profile H2-only copies."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import runpy
import subprocess
import sys
import tempfile

fetch = runpy.run_path(str(Path(__file__).with_name("client.py")))["fetch"]
probe, out = Path(sys.argv[1]), Path(sys.argv[2]); out.mkdir(exist_ok=True)
(out/"linux.json").write_bytes(fetch("environment"))
size = 64 * 1024 * 1024
digest = hashlib.sha256()
for _ in range(1024):
    digest.update(bytes(range(256))*256)
expected = digest.hexdigest()
rows = []
with tempfile.TemporaryDirectory() as name:
    root = Path(name)
    ca = root/"ca.der"; ca.write_bytes(fetch("ca.der"))
    targets = ["rust", "candidate"]
    if os.environ["RELAY_BULK_REVERSE"] == "true":
        targets.reverse()
    for kind in targets:
        original = fetch(kind+"-h3.mobileconfig")
        source = root/(kind+"-seed.mobileconfig"); source.write_bytes(original)
        selected = root/(kind+"-copy.mobileconfig")
        subprocess.run([sys.executable, "profile-tool/tools/select-apple-relay-transport.py", "h2", source, selected], check=True)
        compare = plistlib.loads(original)
        hop = compare["PayloadContent"][0]["Relays"][0]
        hop["HTTP2RelayURL"] = hop.pop("HTTP3RelayURL")
        assert compare == plistlib.loads(selected.read_bytes()) and source.read_bytes() == original
    cases = [("rust","direct"), *((t,"auto") for t in targets), *((t,"auto") for t in reversed(targets)), ("rust","direct")]
    for index, (kind, mode) in enumerate(cases):
        file = root/(kind+"-copy.mobileconfig")
        settings = dict(profile=str(file), mode=mode, url="https://relay.test:18443/"+str(size), expectedBytes=size,
                    expectedSHA256=expected, count=4, concurrency=4, timeoutSeconds=180, testRootDER=str(ca), trustRelay=True)
        request=root/"settings.json"; request.write_text(json.dumps(settings)); output=out/(str(index)+"-"+kind+"-"+mode+".json")
        before=json.loads(fetch("counts"))
        p=subprocess.run([probe,request,output],timeout=240,capture_output=True)
        after=json.loads(fetch("counts"))
        body=json.loads(output.read_bytes()) if output.exists() else {}
        samples=body.get("samples",[])
        verified=sum(s.get("ok") is True and s.get("bytes")==size and s.get("sha256")==expected and s.get("status")==200 for s in samples)
        received=after.get("download",0)-before.get("download",0)
        route=after.get(kind+"_tcp",0)-before.get(kind+"_tcp",0)
        elapsed=body.get("wall_seconds")
        good=(p.returncode==0 and body.get("completed") is True and verified==received==4
              and (route>=4 if mode=="auto" else route==0) and elapsed is not None and elapsed<=180)
        row=dict(target=kind,mode=mode,trial=index,os=body.get("os"),origin=received,relay_events=route,verified=verified,
                 elapsed=elapsed,rc=p.returncode,accepted=good)
        rows.append(row); print(json.dumps(row),flush=True); (out/"summary.json").write_text(json.dumps(rows,indent=2))
assert len(rows)==6 and all(r["accepted"] for r in rows)
