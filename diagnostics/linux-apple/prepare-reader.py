"""Compare Apple's file download task with a bounded incremental URLSession data delegate."""
from pathlib import Path
import sys

path = Path(sys.argv[1]); src=path.read_text()
def edit(old, new):
    global src
    assert src.count(old)==1,old
    src=src.replace(old,new)
edit('final class Evidence: NSObject, URLSessionTaskDelegate, @unchecked Sendable {','''final class Evidence: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private final class Body {
        let limit: Int
        var bytes = 0
        var hasher = SHA256()
        let finish: (Int, String, HTTPURLResponse?, Error?) -> Void
        init(_ limit: Int, _ finish: @escaping (Int, String, HTTPURLResponse?, Error?) -> Void) {
            self.limit = limit
            self.finish = finish
        }
    }
    private var bodies: [Int: Body] = [:]
    func watch(_ id: Int, limit: Int,
               finish: @escaping (Int, String, HTTPURLResponse?, Error?) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        bodies[id] = Body(limit, finish)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        guard let body = bodies[dataTask.taskIdentifier] else { lock.unlock(); return }
        guard data.count <= body.limit - body.bytes else {
            lock.unlock()
            dataTask.cancel()
            return
        }
        body.hasher.update(data: data)
        body.bytes += data.count
        lock.unlock()
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        let body = bodies.removeValue(forKey: task.taskIdentifier)
        lock.unlock()
        guard let body else { return }
        let hash = body.hasher.finalize().map { String(format: "%02x", $0) }.joined()
        body.finish(body.bytes, hash, task.response as? HTTPURLResponse, error)
    }
''')
edit('            } else {\n                task = session.downloadTask(with: request)', '''            } else if ProcessInfo.processInfo.environment["RELAY_READER"] == "stream" {
                task = session.dataTask(with: request)
                evidence.watch(task.taskIdentifier, limit: settings.expectedBytes) { count, digest, response, error in
                    defer { permits.signal(); group.leave() }
                    var fields: [String: Any] = ["bytes": count, "sha256": digest, "status": response?.statusCode ?? 0,
                        "elapsed_seconds": ProcessInfo.processInfo.systemUptime - began,
                        "ok": error == nil && response?.statusCode == 200 && count == settings.expectedBytes &&
                            digest == settings.expectedSHA256.lowercased()]
                    if let error = error as NSError? {
                        fields["error_domain"] = error.domain; fields["error_code"] = error.code
                    }
                    evidence.put(id, fields)
                }
            } else {
                task = session.downloadTask(with: request)''')
path.write_text(src)
