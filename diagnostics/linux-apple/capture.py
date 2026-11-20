"""Join the installed macOS packet helper to this product's real Relay SOCKS transport."""

import contextlib
import importlib.util
import json
import os
import subprocess
import threading
from pathlib import Path


def run(socks_port):
    product = Path(os.environ["TUN_PROJECT"]).resolve()
    app = product / "dist/Network Relay Tun.app"
    helper = app / "Contents/Helpers/network-relay-tun-host"
    spec = importlib.util.spec_from_file_location("native_capture", product / "tests/native_capture.py")
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    initial_dns = native.dns_state()
    initial_route = native.route_interface(native.ENDPOINT)
    with subprocess.Popen([helper, "control"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as control:
        timer = threading.Timer(90, control.kill)
        timer.start()

        def request(operation, **fields):
            control.stdin.write(json.dumps({"operation": operation, **fields}) + "\n")
            control.stdin.flush()
            response = json.loads(control.stdout.readline())
            if not response["ok"]:
                raise RuntimeError(operation + " failed: " + str(response.get("error")))
            return response["status"]

        try:
            assert request("recover")["state"] == "idle"
            prepared = request("prepare", plan={"endpoints": [native.ENDPOINT], "resolvers": [native.DNS],
                                                "mtu": 1500, "socks_port": socks_port})
            lease, interface = prepared["lease"], prepared["interface"]
            assert request("activate", lease=lease)["state"] == "active"
            assert request("refresh", lease=lease)["state"] == "active"
            assert all(native.route_interface(host) == interface for host in native.TARGETS)
            assert native.route_interface(native.ENDPOINT) == initial_route and native.DNS in native.dns_state()
            native.check_packets()
            assert request("stop", lease=lease)["state"] == "idle"
            assert native.dns_state() == initial_dns and native.route_interface(native.ENDPOINT) == initial_route
            return {"interface": interface, "dns_restored": True, "bypass_restored": True}
        finally:
            try:
                if control.poll() is None:
                    with contextlib.suppress(BrokenPipeError):
                        request("recover")
                    control.stdin.close()
                    control.wait(timeout=10)
            finally:
                timer.cancel()
