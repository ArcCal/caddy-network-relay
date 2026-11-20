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
import time

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
                    expectedSHA256=expected, count=4, concurrency=4, timeoutSeconds=360, testRootDER=str(ca), trustRelay=True)
        request=root/"settings.json"; request.write_text(json.dumps(settings)); output=out/(str(index)+"-"+kind+"-"+mode+".json")
        before=json.loads(fetch("counts"))
        task_dir=root/f"tasks-{index}"; task_dir.mkdir()
        start=time.monotonic(); initial=json.loads(fetch("progress")); observations=[]
        with subprocess.Popen([probe,request,output], env=dict(os.environ,RELAY_TASK_PROGRESS=str(task_dir),
                                     SIMCTL_CHILD_RELAY_TASK_PROGRESS=str(task_dir))) as p:
            while p.poll() is None:
                if time.monotonic()-start>410:
                    p.kill(); break
                try:
                    metrics=json.loads(fetch("progress")); observations.append({"seconds":time.monotonic()-start,
                    "writes":{k:v for k,v in metrics["writes"].items() if k not in initial["writes"]},
                    "cpu":metrics["cpu"][kind]-initial["cpu"][kind],"tcp":metrics["tcp_queues"]})
                except OSError:
                    observations.append({"seconds":time.monotonic()-start,"read_timeout":True})
                try: p.wait(timeout=2)
                except subprocess.TimeoutExpired: pass
            p.wait()
        apple=sorted([json.loads(f.read_bytes()) for f in task_dir.glob("*.json")],key=lambda v:v["elapsed"])
        (out/f"{index}-progress.json").write_text(json.dumps({"apple":apple,"linux":observations},separators=(",",":")))
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
                 elapsed=elapsed,rc=p.returncode,accepted=good,task_observations=len(apple),
                 completed_by_360=bool(p.returncode==0 and verified==received==4 and elapsed is not None and elapsed<=360))
        rows.append(row); print(json.dumps(row),flush=True); (out/"summary.json").write_text(json.dumps(rows,indent=2))
assert len(rows)==6 and all(r["accepted"] and r["task_observations"] for r in rows)
