"""Compare the same HTTPS clone using transparent capture and explicit SOCKS."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

name = "git-fixture.test"
url = "https://" + name + ":18443/repo.git"
expected = hashlib.shake_256(b"ordinary HTTPS clone fixture").digest(256 * 1024)
env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy") and not k.startswith("GIT_")}
env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0")
variants = {
    "socks-remote-dns": ["http.proxy=socks5h://127.0.0.1:1080"],
    "transparent-pinned": ["http.proxy=", "http.curloptResolve=" + name + ":18443:198.51.100.42"],
    "transparent-system-dns": ["http.proxy="],
}
failures = []
with tempfile.TemporaryDirectory() as tmp:
    for mode, settings in variants.items():
        argv = ["/usr/bin/git", "-c", "http.sslCAInfo=/tmp/relay-history-app/ca.pem"]
        for setting in settings:
            argv.extend(["-c", setting])
        dst = Path(tmp, mode)
        try:
            result = subprocess.run(argv + ["clone", "-q", url, str(dst)], cwd=tmp, env=env,
                                    capture_output=True, text=True, timeout=18)
            if result.returncode or (dst / "payload").read_bytes() != expected:
                raise RuntimeError(result.stderr)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            failures.append(mode + ": " + str(error))
        else:
            print(mode + " clone verified")
with open("/tmp/relay-history-app/clone-results", "a") as report:
    report.write("\n".join(failures) + "\n" if failures else "All three clone paths verified.\n")
if failures:
    raise SystemExit("\n".join(failures))
