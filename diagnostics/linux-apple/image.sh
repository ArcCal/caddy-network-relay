#!/usr/bin/env bash
# Build this disposable initramfs on the release architecture using signed Ubuntu packages.
set -euo pipefail
out=$1
arch=$(dpkg --print-architecture)
case "$arch" in
    amd64) mirror=https://archive.ubuntu.com/ubuntu ;;
    arm64) mirror=https://ports.ubuntu.com/ubuntu-ports ;;
    *) exit 2 ;;
esac
test "$(id -u)" = 0
mkdir -p "$out"
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
apt-get -qq update
DEBIAN_FRONTEND=noninteractive apt-get -y -qq install debootstrap linux-image-generic kmod cpio zstd
rel=$(ls /lib/modules | sort -V | awk '/-generic$/ { value=$0 } END{print value}')
test -s "/boot/vmlinuz-$rel"
debootstrap --variant=minbase --include=iproute2,kmod,python3,openssl,ca-certificates jammy "$root" "$mirror"
rm -f "$root"/var/cache/apt/archives/*.deb
mkdir -p "$root/boot" "$root/srv" "$root/lib/modules/$rel"
for module in virtio_net virtio_pci virtio_mmio; do
    modprobe --set-version "$rel" --show-depends "$module" | awk '$1=="insmod"{ print $2 }'
done | sort -u > "$out/drivers"
while IFS= read -r mod; do
    install -D -m 644 "$mod" "$root/lib/modules/$rel/${mod#*/modules/$rel/}"
done < "$out/drivers"
for name in modules.order modules.builtin modules.builtin.modinfo; do
    test ! -f "/lib/modules/$rel/$name" || cp "/lib/modules/$rel/$name" "$root/lib/modules/$rel/"
done
depmod -b "$root" "$rel"
install -m 755 "$2" "$root/srv/network-relay"
install -m 755 "$3" "$root/srv/caddy"
install -m 644 diagnostics/linux-apple/guest.py "$root/srv/guest.py"
cat > "$root/relay-init" <<'INIT'
#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t devtmpfs devtmpfs /dev || true
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /tmp
chmod 1777 /tmp
hostname relay-fixture
printf '127.0.0.1 localhost relay.test\n::1 localhost\n' >/etc/hosts
for mod in virtio_pci virtio_mmio virtio_net; do modprobe "$mod" || true; done
ip link set lo up
iface=
for dev in /sys/class/net/*; do test "$dev" = /sys/class/net/lo || iface=${dev##*/}; done
test -n "$iface"
ip link set "$iface" up
ip addr add 10.0.2.15/24 dev "$iface"
export FIXTURE_BIND=0.0.0.0 HOME=/root
exec /usr/bin/python3 /srv/guest.py
INIT
chmod 755 "$root/relay-init"
if gzip -t "/boot/vmlinuz-$rel" 2>/dev/null; then
    gzip -dc "/boot/vmlinuz-$rel" > "$out/kernel"
else
    cp "/boot/vmlinuz-$rel" "$out/kernel"
fi
(cd "$root" && find . -print0 | cpio --null --quiet -o -H newc | gzip -1 > "$out/guest.gz")
ls -lh "$out/kernel" "$out/guest.gz"
(cd "$out" && sha256sum kernel guest.gz > SHA256SUMS)
