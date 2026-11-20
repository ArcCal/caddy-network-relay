"""Keep Apple's native relay setup and the project's strict certificate checks."""
from pathlib import Path
import sys

source, target = map(Path, sys.argv[1:])
text = source.read_text()
start = text.index('        let evidence = Evidence(', text.index('    static func udp('))
end = text.index('    }\n    static func main()', start)
part = r'''        let evidence = Evidence(root: root, origin: settings.url)
        let fields = settings.url.path.split(separator: "/")
        guard fields.count == 4, let size = Int(fields[0]), let expected = UInt8(fields[1]), let tail = UInt8(fields[2]),
              (62...64).contains(size), (62...64).contains(Int(expected)) else { throw ProbeError(message: "Bad fixture arguments") }
        var payload = Data((0..<size).map { UInt8(($0 * 13 + 7) & 255) })
        payload.replaceSubrange(0..<5, with: Data([0x52, 0x4c, 0x59, 0x55, expected]))
        payload[payload.count - 1] = tail
        let done = DispatchSemaphore(value: 0)
        let sent = DispatchSemaphore(value: 0)
        if connected {
            connection.receiveMessage { data, _, _, error in
                if let data {
                    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                    evidence.put("reply", ["ok": data.count == Int(expected) && digest == settings.expectedSHA256,
                                           "bytes": data.count, "sha256": digest])
                }
                if let error { evidence.put("error", ["error": String(describing: error)]) }
                done.signal()
            }
            if String(fields[3]) == "split" {
                let context = NWConnection.ContentContext(identifier: "single-udp-message")
                let prefix = Data(payload.prefix(31))
                let suffix = Data(payload.dropFirst(31))
                connection.batch {
                    connection.send(content: prefix, contentContext: context, isComplete: false,
                                    completion: .contentProcessed { error in
                        if let error { evidence.put("prefix_error", ["error": String(describing: error)]) }
                    })
                    connection.send(content: suffix, contentContext: context, isComplete: true,
                                    completion: .contentProcessed { error in
                        evidence.put("send", ["sent": error == nil])
                        sent.signal()
                    })
                }
            } else {
                connection.send(content: payload, completion: .contentProcessed { error in
                    evidence.put("send", ["sent": error == nil]); sent.signal()
                })
            }
            _ = sent.wait(timeout: .now() + 3)
            _ = done.wait(timeout: .now() + 3)
        }
        let rows = evidence.result()
        let complete = rows.contains { $0["ok"] as? Bool == true }
        try writeReport(["completed": complete, "ready": connected, "samples": rows,
                         "state": state.result(), "os": ProcessInfo.processInfo.operatingSystemVersionString])
        try require(complete, "No byte-complete response")
'''
target.write_text(text[:start] + part + text[end:])
