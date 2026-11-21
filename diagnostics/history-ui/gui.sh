#!/usr/bin/env bash
set -euo pipefail
umask 077
stage=/tmp/relay-history-app
mkdir "$stage"
app="$stage/Network Relay Tun.app"
support="$HOME/Library/Application Support/NetworkRelayTun"
test ! -e "$support"
test ! -e '/Library/Application Support/NetworkRelayTun'
ditto "clients/network-relay-tun/dist/Network Relay Tun.app" "$app"
codesign --verify --deep --strict "$app"
cert="$RUNNER_TEMP/guest-ca.der"
pem="$RUNNER_TEMP/guest-ca.pem"
fp=$(openssl x509 -in "$pem" -fingerprint -sha256 -noout | cut -d= -f2 | tr -d :)
installed=0
trusted=0
cleanup() {
    if [[ $installed == 1 ]]; then sudo bash "$app/Contents/Resources/uninstall-helper.sh"; fi
    if [[ $trusted == 1 ]]; then
        sudo security remove-trusted-cert -d "$cert" || true
        sudo security delete-certificate -Z "$fp" /Library/Keychains/System.keychain || true
    fi
    if [[ -n ${forward_pid:-} ]]; then kill "$forward_pid" || true; fi
    sudo /sbin/ifconfig lo0 -alias 198.51.100.254 2>/dev/null || true
    sudo /sbin/route -n delete -host 198.51.100.254 127.0.0.1 2>/dev/null || true
    rm -f "$support/settings.json"
    rmdir "$support" || true
}
trap cleanup EXIT
mkdir -m 700 "$support"
python3 - "$support/settings.json" <<'PY'
import base64,json,plistlib,sys,urllib.request
doc=plistlib.load(urllib.request.urlopen('http://127.0.0.1:18080/caddy.mobileconfig'))
headers=next(i for i in doc['PayloadContent'] if i.get('PayloadType')=='com.apple.relay.managed')['Relays'][0]['AdditionalHTTPHeaderFields']
secret=base64.b64decode(next(v for k,v in headers.items() if 'authorization' in k.lower()).split()[1]).decode().split(':',1)[1]
open(sys.argv[1],'w').write(json.dumps({'servers':[dict(name='Isolated Linux relay',domain='relay.test:14201',serverIP='198.51.100.254',username='alice',password=secret,transport='h2',probeTarget='127.0.0.1:18443')]}))
PY
cd diagnostics/history-ui
command -v xcodegen >/dev/null || HOMEBREW_NO_AUTO_UPDATE=1 brew install xcodegen
xcodegen generate
run_ui(){
    xcodebuild -project RelayBoundaryUI.xcodeproj -scheme Boundary -destination 'platform=macOS' -derivedDataPath "$RUNNER_TEMP/ui-derived" -parallel-testing-enabled NO -resultBundlePath "$RUNNER_TEMP/ui-$1.xcresult" test
}
run_ui missing
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
forward_pid=$!
sleep 1
curl --noproxy '*' --cacert "$pem" --resolve relay.test:14201:198.51.100.254 --max-time 7 -sS -o /dev/null https://relay.test:14201/
sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain "$cert"
trusted=1
sudo bash "$app/Contents/Resources/install-helper.sh" "$(id -u)"
installed=1
touch "$stage/installed"
before=$(/usr/sbin/scutil --dns | shasum); route_before=$(/sbin/route -n get 198.51.100.42 | awk '/interface:/{print $2}')
run_ui installed
test "$before" = "$(/usr/sbin/scutil --dns | shasum)"
test "$route_before" = "$(/sbin/route -n get 198.51.100.42 | awk '/interface:/{print $2}')"
