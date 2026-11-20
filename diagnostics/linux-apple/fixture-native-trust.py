"""Build-only test provision for one SecTrust object on a disposable Mac."""
from pathlib import Path
import sys

source, output = map(Path, sys.argv[1:])
text = source.read_text()
point = "            let value = sec_trust_copy_ref(trust).takeRetainedValue()"
if text.count(point) != 1:
    raise ValueError("Native TLS evaluation changed; review the fixture")
setup = """
            guard let path = ProcessInfo.processInfo.environment["RELAY_FIXTURE_CA_DER"],
                  let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let anchor = SecCertificateCreateWithData(nil, data as CFData),
                  SecTrustSetAnchorCertificates(value, [anchor] as CFArray) == errSecSuccess,
                  SecTrustSetAnchorCertificatesOnly(value, true) == errSecSuccess else {
                complete(false)
                return
            }
"""
text = text.replace(point, point + setup)
point = "        var endpointHost: NWEndpoint.Host {"
assert text.count(point) == 1
# Only the two QEMU ingress sockets are bound on loopback. The application
# controller, helper bypass, ordinary targets and TLS identity are unmodified.
text = text.replace(point, point + """
            if host == "198.51.100.254" && (port == 14200 || port == 14201) {
                return .ipv4(IPv4Address("127.0.0.1")!)
            }
""")
output.write_text(text)
