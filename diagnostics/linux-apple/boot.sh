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
command -v "$cmd" >/dev/null || HOMEBREW_NO_AUTO_UPDATE=1 brew install qemu
net=user,id=nic,restrict=on
for mapping in tcp:18080 tcp:18443 udp:18553 tcp:14200 udp:14200 tcp:14201 udp:14201; do
    protocol=${mapping%:*}
    port=${mapping#*:}
    net+=",hostfwd=$protocol:127.0.0.1:$port-10.0.2.15:$port"
done
log="$RUNNER_TEMP/guest-console.log"
touch "$log"
"$cmd" -machine "$machine" -accel tcg,thread=multi -cpu "$cpu" -smp 2 -m 2048 \
  -kernel "$image/kernel" -initrd "$image/guest.gz" -append "rdinit=/relay-init console=$console panic=-1" \
  -netdev "$net" -device virtio-net-pci,netdev=nic -object rng-random,filename=/dev/urandom,id=rng \
  -device virtio-rng-pci,rng=rng -display none -monitor none -serial "file:$log" -no-reboot \
  >"$RUNNER_TEMP/qemu.log" 2>&1 &
pid=$!
echo "$pid" > "$RUNNER_TEMP/guest.pid"
for ((attempt=0; attempt<240; attempt++)); do
    if curl -fsS --max-time 2 http://127.0.0.1:18080/environment > "$RUNNER_TEMP/linux.json" 2>/dev/null; then
        python3 - "$RUNNER_TEMP/linux.json" "$arch" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); print(x); assert x['system']=='Linux' and x['machine']=={'arm64':'aarch64','amd64':'x86_64'}[sys.argv[2]]
PY
        exit 0
    fi
    kill -0 "$pid" || break
    sleep 1
done
tail -50 "$log"
tail -12 "$RUNNER_TEMP/qemu.log"
exit 1
