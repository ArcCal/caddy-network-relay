"""Keep the client, release servers, origin and transfer identical across Linux execution modes."""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import platform
import runpy
import signal
import subprocess
import sys
import time
from urllib.request import ProxyHandler, build_opener

here = Path(__file__).resolve().parent
private = Path(os.environ["RUNNER_TEMP"])
evidence = private / "evidence"
evidence.mkdir(exist_ok=True)
client = Path(os.environ["RS_CONTROL_BIN"])
run = runpy.run_path(str(here / "bulk-control.py"))["run"]
http = build_opener(ProxyHandler({}))
def fetch(name):
    with http.open("http://127.0.0.1:18080/" + name, timeout=10) as response:
        return response.read()

def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(handle.read()).hexdigest()

def stop(pid):
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    for _ in range(250):
        stat = Path(f"/proc/{pid}/stat")
        if not stat.is_file() or stat.read_text().rsplit(")", 1)[1].split()[0] == "Z":
            return
        time.sleep(.1)
    raise RuntimeError("Guest did not stop")

def test(which, order):
    cpu_ids = sorted(os.sched_getaffinity(0))[:2]
    assert len(cpu_ids) == 2
    guest = private / "guest.pid"
    if guest.exists():
        raise RuntimeError("Another guest is present")
    host_proc = None
    try:
        if which == "native":
            # Give the server and the origin the same processor count as the guest.
            host_proc = subprocess.Popen(["taskset", "-c", ",".join(map(str, cpu_ids)), sys.executable, here / "guest.py"],
                env=dict(os.environ, FIXTURE_BIND="127.0.0.1", RUST_RELAY=str(private/"linux"/"srv"/"network-relay"),
                         CADDY_RELAY=str(private/"pair"/"caddy-candidate")), start_new_session=True)
        else:
            subprocess.run(["bash", str(here/"boot.sh"), os.environ["RELAY_ARCH"], private/"image"],
                env=dict(os.environ, RELAY_EXECUTION=which), check=True)
        for _ in range(120):
            try:
                env = json.loads(fetch("environment")); break
            except OSError:
                if host_proc is not None and host_proc.poll() is not None:
                    raise RuntimeError("Native Linux fixture exited")
                time.sleep(.5)
        else:
            raise RuntimeError("Linux fixture did not become ready")
        assert env["machine"] == platform.machine() and env["caddy"] == digest(private/"pair"/"caddy-candidate")
        assert env["rust"] == digest(private/"linux"/"srv"/"network-relay")
        desc = dict(mode=which, server_environment=env, host_kernel=platform.release(), client_sha256=digest(client), server_cpus=2)
        (evidence / (which+"-environment.json")).write_text(json.dumps(desc, indent=2))
        rows = []
        for i, transport in enumerate(order):
            row = run(client, fetch, "caddy", transport, 64 << 20)
            row["valid"] = bool(row["ok"] and row["relay_log_count"] >= (0 if transport == "direct" else 4)
                                and (transport != "direct" or row["relay_log_count"] == 0))
            rows.append(row)
            print(which, i, transport, row["valid"], round(row["elapsed"], 3), row["origin_count"], flush=True)
            (evidence / (which+"-transfers.json")).write_text(json.dumps(rows, indent=2))
        return all(row["valid"] for row in rows)
    finally:
        if host_proc is not None:
            try:
                os.killpg(host_proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            host_proc.wait(timeout=15)
        if guest.exists():
            stop(int(guest.read_text())); guest.unlink()

modes = []
try:
    with open("/dev/kvm", "r+b", buffering=0) as handle:
        version = fcntl.ioctl(handle.fileno(), 0xAE00, 0)  # KVM_GET_API_VERSION
        vm = fcntl.ioctl(handle.fileno(), 0xAE01, 0)  # KVM_CREATE_VM
        os.close(vm)
    if version != 12:
        raise RuntimeError("Unexpected KVM API version")
    modes = ["native", "kvm", "tcg"]
    reason = None
except OSError as exc:
    reason = {"operation": "open or create KVM VM", "errno": exc.errno}
availability = {"modes": modes, "dev_kvm": os.path.exists("/dev/kvm"), "arch": platform.machine(), "unavailable": reason}
(evidence / "modes.json").write_text(json.dumps(availability,indent=2))
print(availability, flush=True)
order = ["direct", "h2", "h3", "h3", "h2"]
accepted = [test(mode, order) for mode in modes]
if not all(accepted):
    raise SystemExit("At least one Linux transfer lacked four verified bodies and complete route controls")
