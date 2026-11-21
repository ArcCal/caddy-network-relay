"""Load Google's public robots page and clone the reported public build dependency."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

stage = Path("/tmp/relay-history-app")
baseline = sys.argv[1:] == ["--baseline"]
env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy") and not k.startswith("GIT_")}
env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0")
modes = ["control"] if baseline else ["transparent", "socks"]
results = []
for mode in modes:
    socks = mode == "socks"
    with tempfile.TemporaryDirectory() as temp:
        chrome = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "--headless",
                  "--dump-dom", "--disable-background-networking", "--no-first-run",
                  "--user-data-dir=" + temp, "--proxy-server=socks5://127.0.0.1:1080" if socks else "--no-proxy-server",
                  "https://www.google.com/robots.txt"]
        try:
            r = subprocess.run(chrome, capture_output=True, text=True, timeout=22, env=env)
            ok = r.returncode == 0 and "User-agent:" in r.stdout and "Disallow: /search" in r.stdout
            results.append((mode, "Google Chrome HTTPS", ok, sorted(set(re.findall(r'net::ERR_[A-Z_]+', r.stdout)))))
        except subprocess.TimeoutExpired:
            results.append((mode, "Google Chrome HTTPS", False, "timeout"))
    with tempfile.TemporaryDirectory() as temp:
        git = ["/usr/bin/git", "-c", "http.proxy=" + ("socks5h://127.0.0.1:1080" if socks else "")]
        try:
            subprocess.run(git + ["clone", "-q", "https://github.com/caddy-dns/cloudflare.git", temp],
                           check=True, cwd="/tmp", env=env, timeout=30)
            subprocess.run(git + ["-C", temp, "fsck", "--full"], check=True, env=env, timeout=15)
            head = subprocess.check_output(git + ["-C", temp, "rev-parse", "HEAD"], env=env, text=True).strip()
            results.append((mode, "GitHub clone and fsck", True, head))
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as err:
            results.append((mode, "GitHub clone and fsck", False, str(err)))
for item in results:
    print(item, flush=True)
if not all(item[2] for item in results):
    raise SystemExit(1)
