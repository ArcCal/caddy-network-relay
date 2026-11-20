"""Measure all individual echoes, including later packets after the first loss, on one flow."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.request import ProxyHandler, build_opener

opener = build_opener(ProxyHandler({}))


def fetch(path):
    for attempt in range(3):
        try:
            with opener.open("http://127.0.0.1:18080/" + path, timeout=15) as response:
                return response.read()
        except OSError:
            if attempt == 2 or path != "counts":
                raise
            time.sleep(.3)



def check(probe, out, secret_dir, server, size, phase, trial):
    delay = 0 if phase == "immediate" else 500
    small = phase == "small"
    case = f"{server}-{size}-{phase}-{trial}"
    output = out / (case + ".json")
    data = bytes(i % 256 for i in range(size))
    settings = {"profile": str(secret_dir / (server + ".mobileconfig")), "mode": "h3", "operation": "udp",
                "url": f"https://relay.test:18553/{size}", "expectedBytes": size,
                "expectedSHA256": hashlib.sha256(data).hexdigest(), "count": 4, "concurrency": 1,
                "timeoutSeconds": 8, "udpWarmupCount": int(small), "udpStartDelayMilliseconds": delay,
                "testRootDER": str(secret_dir / "ca.der"), "trustRelay": True}
    request = secret_dir / "settings.json"
    request.write_text(json.dumps(settings))
    before = json.loads(fetch("counts"))
    child = subprocess.run([probe, request, output], capture_output=True, timeout=35)
    report = json.loads(output.read_text()) if output.exists() else {}
    after = json.loads(fetch("counts"))
    if server in ("caddy", "candidate"):
        limit = time.monotonic() + 2
        while time.monotonic() < limit and after.get(server + "_closed_udp", 0) == before.get(server + "_closed_udp", 0):
            time.sleep(.05)
            after = json.loads(fetch("counts"))
    diff = lambda key: after.get(key, 0) - before.get(key, 0)
    expected = 4 + int(small)
    checked = sorted(int(s["sample"]) for s in report.get("samples", []) if s.get("ok") is True)
    return {"case": case, "rc": child.returncode, "origin": diff("udp"), "expected_origin": expected,
            "received_ids": checked, "relay_events": diff(server + "_udp"), "size": size,
            "confirmed": bool(report) and diff("udp") == expected and diff(server + "_udp") > 0,
            "caddy_closed_sessions": diff(server + "_closed_udp"), "caddy_bytes_up": diff(server + "_closed_up"),
            "caddy_bytes_down": diff(server + "_closed_down"), "caddy_budget_drops": diff(server + "_budget_drops")}


def main():
    probe, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(exist_ok=True)
    (out / "linux.json").write_bytes(fetch("environment"))
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        private = Path(tmp)
        (private / "ca.der").write_bytes(fetch("ca.der"))
        for kind in ("candidate", "caddy"):
            (private / (kind + ".mobileconfig")).write_bytes(fetch(kind + ".mobileconfig"))
        phase = os.environ["RELAY_TRAIN_PHASE"]
        assert phase in ("immediate", "delay", "small")
        for trial, servers in enumerate((("caddy", "candidate"), ("candidate", "caddy")), 1):
            for size in (64, 1200, 1400):
                for server in servers:
                    try:
                        row = check(probe, out, private, server, size, phase, trial)
                    except Exception as error:
                        temp = Path(os.environ["RUNNER_TEMP"])
                        pid = (temp / "guest.pid").read_text().strip()
                        vm = subprocess.run(["ps", "-p", pid, "-o", "stat=,rss=,time="], capture_output=True, text=True)
                        console = (temp / "guest-console.log").read_bytes().lower()
                        details = {"server":server, "size":size, "phase":phase, "trial":trial,
                                   "error":type(error).__name__, "message":str(error), "emulator":vm.stdout.strip(),
                                   "kernel_events": {key:console.count(key.encode()) for key in
                                       ("out of memory", "oom-kill", "killed process", "kernel panic", "no space left")}}
                        (out / "fixture-failure.json").write_text(json.dumps(details, indent=2))
                        raise
                    rows.append(row)
                    print(json.dumps(row), flush=True)
                    (out / "trains.json").write_text(json.dumps(rows, indent=2))
    # Missing replies are measured outcomes. Missing controls or origin arrivals
    # invalidate the experiment, as does a failed 64-byte reference train.
    return not (len(rows) == 12 and all(r["confirmed"] for r in rows)
                and all(r["rc"] == 0 for r in rows if r["size"] == 64))


if __name__ == "__main__":
    sys.exit(main())
