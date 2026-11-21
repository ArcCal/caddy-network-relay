#!/usr/bin/env bash
set -euo pipefail
umask 077
phase=$1
stage=/tmp/relay-history-app
root=$PWD
app="$stage/Network Relay Tun.app"
support="$HOME/Library/Application Support/NetworkRelayTun"
cert="$RUNNER_TEMP/guest-ca.der"
pem="$RUNNER_TEMP/guest-ca.pem"
run_ui() {
    cd "$root/diagnostics/history-ui"
    xcodebuild -quiet -project RelayBoundaryUI.xcodeproj -scheme Boundary -destination 'platform=macOS,arch=arm64' -derivedDataPath "$RUNNER_TEMP/ui-derived" -parallel-testing-enabled NO -test-timeouts-enabled YES -default-test-execution-time-allowance 350 -resultBundlePath "$RUNNER_TEMP/ui-$1.xcresult" test
}
case "$phase" in
prepare)
mkdir "$stage"
app="$stage/Network Relay Tun.app"
support="$HOME/Library/Application Support/NetworkRelayTun"
test ! -e "$support"
test ! -e '/Library/Application Support/NetworkRelayTun'
ditto "clients/network-relay-tun/dist/Network Relay Tun.app" "$app"
codesign --verify --deep --strict "$app"
cp diagnostics/history-ui/{ordinary,clone,browser,public,dnsbench}.py "$stage/"
if [[ ! -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]]; then
    HOMEBREW_NO_AUTO_UPDATE=1 brew install --cask google-chrome
fi
codesign -v -R='identifier "com.google.Chrome" and anchor apple generic and certificate leaf[subject.OU] = EQHXZ8M8AV' "/Applications/Google Chrome.app"
mkdir -m 700 "$support"
python3 - "$support/settings.json" <<'PY'
import base64,json,plistlib,sys,urllib.request
with urllib.request.urlopen('http://127.0.0.1:18080/caddy.mobileconfig',timeout=10) as response:
    doc=plistlib.loads(response.read())
headers=next(i for i in doc['PayloadContent'] if i.get('PayloadType')=='com.apple.relay.managed')['Relays'][0]['AdditionalHTTPHeaderFields']
secret=base64.b64decode(next(v for k,v in headers.items() if 'authorization' in k.lower()).split()[1]).decode().split(':',1)[1]
open(sys.argv[1],'w').write(json.dumps({'servers':[dict(name='Isolated Linux relay',domain='relay.test:14201',serverIP='198.51.100.254',username='alice',password=secret,transport='h2',probeTarget='127.0.0.1:18443')]}))
PY
cd diagnostics/history-ui
command -v xcodegen >/dev/null || HOMEBREW_NO_AUTO_UPDATE=1 brew install xcodegen
xcodegen generate
cd "$root"

;;
missing)
cp "$pem" "$stage/ca.pem"
# Chromium ignores macOS trust entries constrained to one hostname.
# Trust only this guest's newly generated CA on the disposable runner.
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$cert"
touch "$stage/trusted"
/usr/bin/python3 "$stage/browser.py" --preflight
defaults write com.arccal.network-relay-tun GlobalTUN -bool false
[[ ${MODE_VARIANT:-} != baseline ]] || touch "$stage/baseline"
run_ui missing
;;
network)
python3 -u diagnostics/history-ui/public-bridge.py > "$stage/public-bridge.log" 2>&1 &
echo $! > "$stage/public-bridge.pid"
for ((i=0; i<100; i++)); do grep -q "Both fixed" "$stage/public-bridge.log" && break; sleep .1; done
grep -q "Both fixed" "$stage/public-bridge.log"
gw=$(/sbin/route -n get default | awk '/gateway:/ {print $2}')
while read -r site ip; do
    sudo /sbin/route -n add -host "$ip" "$gw"
    /sbin/route -n get "$ip" | grep 'interface:'
done < "$stage/bridge-targets"
for spec in www.google.com:18481 github.com:18482; do
    site=${spec%:*}
    curl --noproxy '*' --max-time 12 -sS -o /dev/null --connect-to "$site:443:127.0.0.1:${spec#*:}" "https://$site/"
done
# Verify external HTTPS before trusting an outcome through either proxy path.
/usr/bin/python3 "$stage/public.py" --baseline
# The product rejects loopback as a global relay endpoint. Exercise the
# shipped binary with a non-loopback address on a pre-owned static host route.
sudo /sbin/route -n add -host 198.51.100.254 127.0.0.1
sudo /sbin/ifconfig lo0 alias 198.51.100.254 netmask 255.255.255.255
/sbin/route -n get 198.51.100.254
sudo /sbin/route -n change -host 198.51.100.254 127.0.0.1 -static
/sbin/route -n get 198.51.100.254 | grep STATIC
python3 -u - <<'FORWARD' &
import socket,threading,select
with socket.socket() as listener:
    listener.bind(('198.51.100.254',14201)); listener.listen()
    def tunnel(conn):
        with conn,socket.create_connection(('127.0.0.1',14201)) as dst:
            inputs=[conn,dst]
            while inputs:
                for source in select.select(inputs,[],[],30)[0]:
                    other=dst if source is conn else conn
                    data=source.recv(65536)
                    if data:other.sendall(data)
                    else:
                        inputs.remove(source);other.shutdown(socket.SHUT_WR)
    while True:threading.Thread(target=tunnel,args=(listener.accept()[0],),daemon=True).start()
FORWARD
echo $! > "$stage/forward.pid"
sleep 1
curl --noproxy '*' --cacert "$pem" --resolve relay.test:14201:198.51.100.254 --max-time 7 -sS -o /dev/null https://relay.test:14201/

;;
install)
sudo bash "$app/Contents/Resources/install-helper.sh" "$(id -u)"
touch "$stage/helper"
touch "$stage/installed"
/usr/sbin/scutil --dns | shasum > "$stage/dns.before"
/sbin/route -n get 198.51.100.42 | awk '/interface:/{print $2}' > "$stage/route.before"

;;
installed)
(
    for cycle in 0 1; do
        for ((n=0; n<550; n++)); do
            if /sbin/route -n get 198.51.100.42 2>/dev/null | grep -q "interface: utun"; then break; fi
            sleep .2
        done
        /sbin/route -n get 198.51.100.42 | grep "interface: utun"
        for ip in 198.51.100.42 1.1.1.1 8.8.8.8; do /sbin/route -n get "$ip" | awk '/interface:/{print $0}'; done
        /usr/sbin/scutil --dns | awk '/nameserver|order|flags/ {print}' | head -65
        while read -r site ip; do
            echo "Public bridge uplink for $site"
            /sbin/route -n get "$ip" | grep 'interface:'
        done < "$stage/bridge-targets"
        for spec in www.google.com:18481 github.com:18482; do
            site=${spec%:*}
            curl --noproxy '*' --max-time 12 -sS -o /dev/null --connect-to "$site:443:127.0.0.1:${spec#*:}" "https://$site/" || echo "Uplink TLS control failed for $site"
        done
        for check in dnsbench ordinary clone browser public; do
            [[ "$cycle" == 0 || "$check" == dnsbench || "$check" == ordinary || "$check" == clone ]] || continue
            echo "Cycle $cycle: $check"
            /usr/bin/python3 -u "$stage/$check.py" || touch "$stage/check-failed"
        done
        curl --max-time 5 --noproxy '*' -fsS http://127.0.0.1:18080/counts || true
        touch "$stage/done-$cycle"
        if [[ $cycle == 0 ]]; then
            for ((n=0; n<200; n++)); do
                /sbin/route -n get 198.51.100.42 2>/dev/null | grep -q "interface: utun" || break
                sleep .1
            done
        fi
    done
) &
probe_pid=$!
rc=0
run_ui installed || rc=$?
if [[ "$rc" != 0 ]]; then kill "$probe_pid" 2>/dev/null || true; fi
wait "$probe_pid" || true
cat "$stage/public-bridge.log"
[[ ! -f "$stage/browser-results" ]] || cat "$stage/browser-results"
[[ ! -f "$stage/clone-results" ]] || cat "$stage/clone-results"
[[ "$rc" == 0 ]] || exit "$rc"
[[ ! -e "$stage/check-failed" ]] || exit 1
curl --noproxy '*' -fsS http://127.0.0.1:18080/counts > "$RUNNER_TEMP/plain-counts.json"
python3 - "$RUNNER_TEMP/plain-counts.json" <<'CHECK'
import json,sys
d=json.load(open(sys.argv[1]))
assert all(d.get("browser_" + mode, 0) >= 1 for mode in ("transparent", "socks")), d
assert all(d.get("public_" + port, 0) >= 2 for port in ("18481", "18482")), d
assert d.get("git_dns6_a", 0) >= 2, d
assert d.get("git_dns_a", 0) > 0, d
assert d.get("git_object", 0) >= 18, d
print("Git DNS answers and object reads:", d["git_dns_a"], d["git_object"])
for kind in ("tcp4","tcp6","udp4","udp6"):
 n=d["capture_"+kind]; print(kind,n); assert n>=2
CHECK
test "$(cat "$stage/dns.before")" = "$(/usr/sbin/scutil --dns | shasum)"
test "$(cat "$stage/route.before")" = "$(/sbin/route -n get 198.51.100.42 | awk '/interface:/{print $2}')"

;;
cleanup)
fp=$(openssl x509 -in "$pem" -fingerprint -sha256 -noout | cut -d= -f2 | tr -d :)
    if [[ -e "$stage/helper" ]]; then
        /usr/bin/pkill -x NetworkRelayTun 2>/dev/null || true
        printf '%s\n' '{"operation":"recover"}' | "$app/Contents/Helpers/network-relay-tun-host" control || true
        sudo bash "$app/Contents/Resources/uninstall-helper.sh"; fi
    if [[ -e "$stage/trusted" ]]; then
        # This disposable runner used a fixture-specific system trust entry.
        # Run its noninteractive cleanup with a deadline.
        python3 - "$cert" <<'CLEAN'
import subprocess,sys
try:
 subprocess.run(["sudo","security","remove-trusted-cert","-d",sys.argv[1]],timeout=10)
except subprocess.TimeoutExpired:
 print("Timed out removing fixture trust settings on disposable runner.")
CLEAN
        sudo security delete-certificate -Z "$fp" /Library/Keychains/System.keychain </dev/null || true
    fi
    if [[ -f "$stage/bridge-targets" ]]; then
        gw=$(/sbin/route -n get default | awk '/gateway:/ {print $2}')
        while read -r site ip; do sudo /sbin/route -n delete -host "$ip" "$gw" || true; done < "$stage/bridge-targets"
    fi
    if [[ -f "$stage/public-bridge.pid" ]]; then kill "$(cat "$stage/public-bridge.pid")" || true; fi
    if [[ -f "$stage/forward.pid" ]]; then kill "$(cat "$stage/forward.pid")" || true; fi
    sudo /sbin/ifconfig lo0 -alias 198.51.100.254 2>/dev/null || true
    sudo /sbin/route -n delete -host 198.51.100.254 127.0.0.1 2>/dev/null || true
    rm -f "$support/settings.json"
    rmdir "$support" || true
;;
esac
