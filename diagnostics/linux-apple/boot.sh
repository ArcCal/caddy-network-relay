#!/usr/bin/env bash
set -euo pipefail
arch=$1
image=$2
case "$arch" in
    arm64) cmd=qemu-system-aarch64; machine=virt; cpu=cortex-a72; console=ttyAMA0 ;;
    amd64) cmd=qemu-system-x86_64; machine=q35; cpu=max; console=ttyS0 ;;
    *) exit 2 ;;
esac
(cd "$image" && shasum -a 256 --check SHA256SUMS)
# The signed kernel and release binaries stay in the verified original image.
# Append only the loopback test fixture. The archived Linux binaries stay intact.
overlay=$(mktemp -d "$RUNNER_TEMP/origin-overlay.XXXXXX")
mkdir "$overlay/srv"
cp diagnostics/linux-apple/guest.py "$overlay/srv/guest.py"
(cd "$RUNNER_TEMP/probe-arm" && shasum -a 256 --check SHA256SUMS)
install -m 755 "$RUNNER_TEMP/probe-arm/caddy-baseline" "$overlay/srv/caddy"
install -m 755 "$RUNNER_TEMP/probe-arm/caddy-candidate" "$overlay/srv/caddy-candidate"
(cd "$overlay" && printf '%s\n' srv/guest.py srv/caddy srv/caddy-candidate | cpio -o -H newc | gzip -1) > "$overlay/fixture.gz"
cat "$image/guest.gz" "$overlay/fixture.gz" > "$overlay/guest-with-bulk.gz"
command -v "$cmd" >/dev/null || HOMEBREW_NO_AUTO_UPDATE=1 brew install qemu
# libslirp restricted mode drops every guest UDP reply, including forwarded
# loopback ports. The guest permits only a host route to the forwarding gateway.
net=user,id=nic,ipv6=off
for mapping in tcp:18080 tcp:18443 udp:18553 tcp:14200 udp:14200 tcp:14201 udp:14201 tcp:14202 udp:14202; do
    protocol=${mapping%:*}
    port=${mapping#*:}
    net+=",hostfwd=$protocol:127.0.0.1:$port-10.0.2.15:$port"
done
log="$RUNNER_TEMP/guest-console.log"
touch "$log"
# The minimal guest may start without an RTC driver. Establish the runner's
# real UTC before the fixture issues its one-day certificate.
epoch=$(date +%s)
initargs="rdinit=/bin/sh console=$console panic=-1 -- -c \"/bin/date -u -s @$epoch && exec /relay-init\""
"$cmd" -machine "$machine" -accel tcg,thread=multi -cpu "$cpu" -smp 2 -m 2048 \
  -kernel "$image/kernel" -initrd "$overlay/guest-with-bulk.gz" -append "$initargs" \
  -netdev "$net" -device virtio-net-pci,netdev=nic -object rng-random,filename=/dev/urandom,id=rng \
  -device virtio-rng-pci,rng=rng -display none -monitor none -serial "file:$log" -no-reboot \
  >"$RUNNER_TEMP/qemu.log" 2>&1 &
pid=$!
echo "$pid" > "$RUNNER_TEMP/guest.pid"
for ((attempt=0; attempt<240; attempt++)); do
    if curl -fsS --max-time 2 --noproxy '*' http://127.0.0.1:18080/ca.der > "$RUNNER_TEMP/guest-ca.der" 2>/dev/null; then
        curl -fsS --noproxy '*' --max-time 15 http://127.0.0.1:18080/environment > "$RUNNER_TEMP/linux.json"
        python3 - "$RUNNER_TEMP/linux.json" "$arch" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); print(x); assert x['system']=='Linux' and x['machine']=={'arm64':'aarch64','amd64':'x86_64'}[sys.argv[2]]
PY
        openssl x509 -inform DER -in "$RUNNER_TEMP/guest-ca.der" -out "$RUNNER_TEMP/guest-ca.pem"
        curl --noproxy '*' --fail --silent --show-error --max-time 15 --cacert "$RUNNER_TEMP/guest-ca.pem" \
             --resolve relay.test:18443:127.0.0.1 https://relay.test:18443/4096 -o "$RUNNER_TEMP/verified-origin"
        test "$(wc -c < "$RUNNER_TEMP/verified-origin")" -eq 4096
        python3 - "$RUNNER_TEMP" <<'UDP'
import ssl
import json, os, socket, sys
from pathlib import Path
from urllib.request import build_opener, ProxyHandler
opener = build_opener(ProxyHandler({}))
def observed():
    with opener.open("http://127.0.0.1:18080/counts", timeout=12) as response:
        return json.load(response).get("udp", 0)
trust = ssl.create_default_context(cafile=str(Path(sys.argv[1]) / "guest-ca.pem"))
for port in (14200, 14201, 14202):
    for identity in ("ingress.relay.test", "127.0.0.1"):
        with socket.create_connection(("127.0.0.1", port), timeout=12) as connection:
            with trust.wrap_socket(connection, server_hostname=identity) as secure:
                if not secure.getpeercert():
                    raise RuntimeError("Linux relay did not present a verified certificate")
before = observed()
sizes = [63, 1200, 1350]
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
    channel.connect(("127.0.0.1", 18553))
    channel.settimeout(10)
    for size in sizes:
        body = os.urandom(size)
        channel.send(body)
        if channel.recv(65535) != body:
            raise RuntimeError("Direct Linux UDP payload mismatch")
after = observed()
if after - before != len(sizes):
    raise RuntimeError("Direct Linux UDP count mismatch")
evidence = Path(sys.argv[1]) / "evidence"
evidence.mkdir(exist_ok=True)
(evidence / "transport-preflight.json").write_text(json.dumps(
    {"direct_tls_bytes": 4096, "direct_udp_sizes": sizes, "udp_origin_datagrams": after-before}))
print("Verified TLS and direct, byte-complete UDP over the Linux port forwards", sizes)
UDP
        exit 0
    fi
    kill -0 "$pid" || break
    sleep 1
done
tail -50 "$log"
tail -12 "$RUNNER_TEMP/qemu.log"
exit 1
