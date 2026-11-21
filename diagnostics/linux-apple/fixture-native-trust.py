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
output.write_text(text.replace(point, point + setup))
text = output.read_text()
a='data, _, complete, error in'
assert text.count(a) == 1
text=text.replace(a,'data, context, complete, error in')
a='            entry.reading = false'
assert text.count(a)==1
text=text.replace(a,a+r'''
            if entry.trust != nil && (complete || error != nil) {
                print("EOF-SAMPLE", id, Date().timeIntervalSince1970, "context", context?.identifier ?? "nil", "final", context?.isFinal ?? false, "complete", complete, "error", String(describing: error), "state", entry.native.state, "bytes", data?.count ?? 0)
            }''')
output.write_text(text)
a='let parameters = NWParameters(tls: tls, tcp: tcp)'
assert text.count(a)==1
text=text.replace(a,a+'\n        parameters.defaultProtocolStack.applicationProtocols.append(NWProtocolFramer.Options(definition: StrictTCP.definition))')
output.write_text(text+'\n'+Path('diagnostics/linux-apple/strict-tcp.swift').read_text())
