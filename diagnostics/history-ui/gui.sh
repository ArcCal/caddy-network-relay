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
    xcodebuild -quiet -project RelayBoundaryUI.xcodeproj -scheme Boundary -destination 'platform=macOS,arch=arm64' -derivedDataPath "$RUNNER_TEMP/ui-derived" -parallel-testing-enabled NO -test-timeouts-enabled YES -default-test-execution-time-allowance 120 -resultBundlePath "$RUNNER_TEMP/ui-$1.xcresult" test
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
cp diagnostics/history-ui/ordinary.py "$stage/ordinary.py"
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
sudo security add-trusted-cert -d -r trustRoot -p ssl -s relay.test -k /Library/Keychains/System.keychain "$cert"
touch "$stage/trusted"
defaults write com.arccal.network-relay-tun GlobalTUN -bool false
[[ ${MODE_VARIANT:-} != baseline ]] || touch "$stage/baseline"
run_ui missing
;;
network)
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
run_ui installed
curl --noproxy '*' -fsS http://127.0.0.1:18080/counts > "$RUNNER_TEMP/plain-counts.json"
python3 - "$RUNNER_TEMP/plain-counts.json" <<'CHECK'
import json,sys
d=json.load(open(sys.argv[1]))
for kind in ("tcp4","tcp6","udp4","udp6"):
 n=d["capture_"+kind]; print(kind,n); assert n>=2
CHECK
test "$(cat "$stage/dns.before")" = "$(/usr/sbin/scutil --dns | shasum)"
test "$(cat "$stage/route.before")" = "$(/sbin/route -n get 198.51.100.42 | awk '/interface:/{print $2}')"

;;
cleanup)
fp=$(openssl x509 -in "$pem" -fingerprint -sha256 -noout | cut -d= -f2 | tr -d :)
    if [[ -e "$stage/helper" ]]; then sudo bash "$app/Contents/Resources/uninstall-helper.sh"; fi
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
    if [[ -f "$stage/forward.pid" ]]; then kill "$(cat "$stage/forward.pid")" || true; fi
    sudo /sbin/ifconfig lo0 -alias 198.51.100.254 2>/dev/null || true
    sudo /sbin/route -n delete -host 198.51.100.254 127.0.0.1 2>/dev/null || true
    rm -f "$support/settings.json"
    rmdir "$support" || true
;;
esac
