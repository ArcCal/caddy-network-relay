"""Check Chrome with a new profile and the same trusted origin on each path."""
import os
from pathlib import Path
import subprocess
import tempfile

chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
results = []
for mode, proxy in [("transparent", "--no-proxy-server"), ("socks", "--proxy-server=socks5://127.0.0.1:1080")]:
    with tempfile.TemporaryDirectory() as profile:
        cmd = [chrome, "--headless", "--dump-dom", "--disable-background-networking", "--no-first-run",
               "--no-default-browser-check", "--user-data-dir=" + profile, proxy,
               "https://relay.test:18443/browser/" + mode]
        try:
            req = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=25)
            ok = req.returncode == 0 and "<title>Verified Relay " + mode + "</title>" in req.stdout
            if not ok:
                import re
                errors = sorted(set(re.findall(r'(?:net::)?ERR_[A-Z_]+', req.stdout + req.stderr)))
                results.append((mode, False, str(errors)[:400]))
            else:
                results.append((mode, True, "Verified HTTPS content"))
        except subprocess.TimeoutExpired:
            results.append((mode, False, "Timeout"))
Path("/tmp/relay-history-app/browser-results").write_text("\n".join(str(r) for r in results) + "\n")
if not all(ok for _, ok, _ in results):
    raise SystemExit(str(results))
print("Chrome verified both paths")
