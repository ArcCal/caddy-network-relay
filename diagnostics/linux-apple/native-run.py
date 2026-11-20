"""Run the Apple API matrix with separate relay and application names on a disposable Mac."""

import os
from pathlib import Path
import runpy
import subprocess

private = Path(os.environ["RUNNER_TEMP"])
origin_name = runpy.run_path("native-probe/diagnostics/run-native-probe.py")["origin_name"]
with origin_name():
    hosts = Path("/etc/hosts")
    before = hosts.read_bytes()
    if b"ingress.relay.test" in before:
        raise RuntimeError("The diagnostic ingress name already exists")
    after = before + b"\n127.0.0.1 ingress.relay.test # disposable Linux relay fixture\n"
    def configure(content):
        subprocess.run(["sudo", "tee", str(hosts)], input=content, stdout=subprocess.DEVNULL, check=True)
        subprocess.run(["sudo", "dscacheutil", "-flushcache"], check=True)
    try:
        configure(after)
        subprocess.run(["python3", "diagnostics/linux-apple/client.py", private / "probe", private / "evidence"],
                       check=True)
    finally:
        if hosts.read_bytes() != after:
            raise RuntimeError("Hosts file changed concurrently")
        configure(before)
