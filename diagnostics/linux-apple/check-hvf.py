"""Record whether a QEMU machine on this host can actually start with Apple HVF."""
import json
import os
from pathlib import Path
import platform
import subprocess

temp=Path(os.environ["RUNNER_TEMP"]); out=temp/"evidence";out.mkdir(exist_ok=True)
arch=platform.machine()
binary,machine,image={"arm64":("qemu-system-aarch64","virt","arm64"),
                      "x86_64":("qemu-system-x86_64","q35","amd64")}[arch]
arg=[binary,"-machine",machine,"-accel","hvf","-cpu","host","-smp","2","-m","512","-nodefaults",
     "-display","none","-serial","none","-monitor","none","-S","-qmp","stdio"]
queries="".join(json.dumps({"execute":cmd})+"\n" for cmd in ("qmp_capabilities","query-status","quit"))
p=subprocess.run(arg,input=queries,capture_output=True,text=True,timeout=30)
responses=[]
for line in p.stdout.splitlines():
    try: responses.append(json.loads(line))
    except ValueError: pass
hvf=p.returncode==0 and any(isinstance(r.get("return"),dict) and r["return"].get("status") in ("prelaunch","paused") for r in responses)
desc={"host_arch":arch,"linux_arch":image,"qemu":binary,"launch_code":p.returncode,"hvf":hvf,
      "accelerator":"hvf" if hvf else "tcg","detail":p.stderr[:600]}
(out/"acceleration.json").write_text(json.dumps(desc,indent=2))
print(json.dumps(desc),flush=True)
with open(os.environ["GITHUB_ENV"],"a") as env:
    env.write("RELAY_READER_ACCEL="+desc["accelerator"]+"\n")
