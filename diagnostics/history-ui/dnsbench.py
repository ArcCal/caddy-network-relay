"""Compare DNS delays with fresh TLS connections and a verified HTTPS response."""
import html
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import urllib.request

chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
for mode in (["pinned", "normal", "doh"] if os.getenv("TEST_CHROME_DOH") == "yes" else ["pinned", "normal"]):
    nonce = secrets.token_hex(6)
    with tempfile.TemporaryDirectory() as profile:
        cmd = [chrome, "--headless", "--dump-dom", "--no-first-run", "--no-proxy-server",
               "--disable-background-networking", "--user-data-dir=" + profile]
        if mode == "pinned":
            cmd.append("--host-resolver-rules=" + ", ".join(
                "MAP " + kind + "-" + nonce + ".dns-fixture.test 198.51.100.42" for kind in ("fast", "slow")))
        if mode == "doh":
            (Path(profile) / "Local State").write_text(json.dumps({"dns_over_https": {
                "mode": "secure", "templates": "https://198.51.100.42:14201/dns-query{?dns}"}}))
        cmd.append("https://relay.test:18443/dns-page?trial=" + nonce)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=35, check=True)
    match = re.search(r'<pre id="results">([^<]+)</pre>', result.stdout)
    assert match, "Missing HTTPS result from browser"
    rows = json.loads(html.unescape(match[1]))
    print("DNS trial", nonce, mode, json.dumps(rows), flush=True)
    assert [(r["kind"], r["visit"]) for r in rows] == [("fast", 1), ("fast", 2), ("slow", 1), ("slow", 2)]
    for cold, warm in (rows[:2], rows[2:]):
        assert cold["port"] != warm["port"], "Two requests reused the same TCP connection"
        assert warm["queries"] == 0
        if mode == "pinned":
            assert cold["queries"] == 0
        else:
            assert cold["queries"] > 0
    if mode != "pinned":
        assert rows[2]["ms"] >= 1200
    if mode == "doh":
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://127.0.0.1:18080/counts", timeout=10) as response:
            counts = json.load(response)
        for kind in ("fast", "slow"):
            name = kind + "-" + nonce + ".dns-fixture.test"
            assert counts.get(name, 0) == counts.get("doh_" + name, 0) > 0, "Fresh Chrome hostname did not use the fixture DoH server"
        print("Verified Chrome Secure DNS at the HTTPS resolver for both fresh names", flush=True)
