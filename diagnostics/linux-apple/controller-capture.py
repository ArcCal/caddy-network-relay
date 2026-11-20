"""Exercise the installed helper exclusively through the product controller."""
import importlib.util
import os
from pathlib import Path
import time

project = Path(os.environ["TUN_PROJECT"]).resolve()
spec = importlib.util.spec_from_file_location("native_capture", project / "tests/native_capture.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
native.DNS = "1.1.1.1"


def original():
    return native.dns_state(), native.route_interface(native.ENDPOINT)


def exercise(prior, read_status):
    interface = native.route_interface("198.51.100.42")
    if not interface.startswith("utun"):
        raise RuntimeError("Controller did not activate a packet tunnel")
    for seq in range(3):
        if seq:
            time.sleep(6)
        if read_status() != "connected":
            raise RuntimeError("Controller left connected state during ordinary traffic")
        if any(native.route_interface(ip) != interface for ip in native.TARGETS | {native.DNS, "8.8.8.8"}):
            raise RuntimeError("The captured IP and DNS routes do not belong to the same tunnel")
        if native.route_interface(native.ENDPOINT) != prior[1] or native.DNS not in native.dns_state():
            raise RuntimeError("Endpoint bypass or resolver ownership changed")
        native.check_packets()
    return {"interface": interface, "verified_packet_rounds": 3}


def restored(prior):
    return {"dns_restored": native.dns_state() == prior[0],
            "bypass_restored": native.route_interface(native.ENDPOINT) == prior[1]}
