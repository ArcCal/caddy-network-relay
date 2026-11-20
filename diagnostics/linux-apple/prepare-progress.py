"""Add numeric-only transfer sampling to an exact revision of the test probe."""
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text()
anchor = "        defer { session.invalidateAndCancel() }"
if source.count(anchor) != 1:
    sys.exit("Unexpected native probe: the URLSession marker must be unique")
sampling = '''        let samples = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "relay.bulk-progress"))
        let sampleStart = ProcessInfo.processInfo.systemUptime
        let folder = ProcessInfo.processInfo.environment["RELAY_TASK_PROGRESS"]!
        samples.schedule(deadline: .now(), repeating: .seconds(2))
        samples.setEventHandler {
            session.getAllTasks { tasks in
                let stamp = ProcessInfo.processInfo.systemUptime - sampleStart
                let counts: [[String: Any]] = tasks.map {
                    ["id": $0.taskIdentifier, "received": $0.countOfBytesReceived,
                     "expected": $0.countOfBytesExpectedToReceive, "state": $0.state.rawValue]
                }
                let row: [String: Any] = ["elapsed": stamp, "tasks": counts]
                let file = URL(fileURLWithPath: folder).appendingPathComponent(String(Int(stamp * 1000)) + ".json")
                if let data = try? JSONSerialization.data(withJSONObject: row) {
                    try? data.write(to: file, options: .atomic)
                }
            }
        }
        samples.resume()
        defer { samples.cancel() }
'''
path.write_text(source.replace(anchor, sampling + anchor))

anchor = '            var request = URLRequest(url: settings.url)'
assert path.read_text().count(anchor) == 1
path.write_text(path.read_text().replace(anchor, anchor + '\n            request.setValue(id, forHTTPHeaderField: "X-Relay-Test-Sample")'))
