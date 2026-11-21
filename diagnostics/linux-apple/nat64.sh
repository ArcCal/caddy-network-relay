#!/usr/bin/env bash
set -euo pipefail
d=$(mktemp -d)
chmod 700 "$d"
g=relay-lab-gateway
c=relay-lab-client
cleanup() {
    for ns in "$c" "$g"; do
        ip netns pids "$ns" | xargs -r kill || true
        ip netns del "$ns" || true
    done
    rm -f /etc/netns/"$c"/resolv.conf
    rmdir /etc/netns/"$c" || true
    rm -rf "$d"
}
ip netns add "$g"
trap cleanup EXIT
ip netns add "$c"
ip link add v6c type veth peer name v6g
ip link set v6c netns "$c"
ip link set v6g netns "$g"
for ns in "$c" "$g"; do ip -n "$ns" link set lo up; done
ip -n "$c" link set v6c up
ip -n "$g" link set v6g up
ip -n "$c" -6 addr add fd21:1::2/64 dev v6c nodad
ip -n "$g" -6 addr add fd21:1::1/64 dev v6g nodad
ip -n "$c" -6 route add default via fd21:1::1
ip -n "$g" addr add 192.0.2.1/32 dev lo
gw() { ip netns exec "$g" "$@"; }
cl() { ip netns exec "$c" "$@"; }
gw sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv4.ip_forward=1
cat > "$d/tayga.conf" <<EOF
tun-device tun64
ipv4-addr 192.0.2.254
prefix fd64:64:64::/96
map 192.0.2.2 fd21:1::2
EOF
gw tayga --config "$d/tayga.conf" --mktun
ip -n "$g" link set tun64 up
ip -n "$g" addr add 192.0.2.253/32 dev tun64
ip -n "$g" -6 addr add fd64:64:65::1/128 dev tun64 nodad
ip -n "$g" route add 192.0.2.2/32 dev tun64
ip -n "$g" -6 route add fd64:64:64::/96 dev tun64
gw tayga --config "$d/tayga.conf" --nodetach > "$d/tayga.log" 2>&1 &
gw dnsmasq --keep-in-foreground --no-resolv --no-hosts --bind-interfaces --listen-address=127.0.0.1 --port=1053 --local=/relay.test/ --address=/relay.test/192.0.2.1 > "$d/auth.log" 2>&1 &
cat > "$d/unbound.conf" <<EOF
server:
    chroot: ""
    username: ""
    logfile: ""
    pidfile: ""
    interface: fd21:1::1
    access-control: fd21:1::/64 allow
    do-not-query-localhost: no
    module-config: "dns64 iterator"
    dns64-prefix: fd64:64:64::/96
    local-zone: "test." nodefault
forward-zone:
    name: "relay.test."
    forward-addr: 127.0.0.1@1053
EOF
gw unbound -d -c "$d/unbound.conf" > "$d/dns64.log" 2>&1 &
mkdir -p /etc/netns/"$c"
echo 'nameserver fd21:1::1' > /etc/netns/"$c"/resolv.conf
test -z "$(ip -n "$c" -4 route)"
test -z "$(ip -n "$c" -o -4 addr show scope global)"
for i in {1..25}; do
    if [[ "$(cl dig +time=1 +tries=1 +short AAAA relay.test)" == "fd64:64:64::c000:201" ]]; then break; fi
    sleep 0.2
done
test "$(cl dig +short AAAA relay.test)" = "fd64:64:64::c000:201" || { cat "$d/dns64.log"; exit 1; }
test -z "$(gw dig +short -p 1053 @127.0.0.1 AAAA relay.test)"
test "$(gw dig +short -p 1053 @127.0.0.1 A relay.test)" = 192.0.2.1
echo "IPv6-only client, authoritative A only, DNS64 synthesized fd64:64:64::c000:201"
gw env RUST_RELAY="$1" CADDY_RELAY="$2" FIXTURE_BIND=192.0.2.1 python3 diagnostics/linux-apple/nat64.py serve "$d" &
for i in {1..75}; do test ! -f "$d/ready" || break; sleep 0.2; done
test -f "$d/ready"
cl python3 diagnostics/linux-apple/nat64.py client "$d" "$3"
ip -n "$g" -s link show tun64
