import XCTest
final class Connect: XCTestCase {
    private let folder = URL(fileURLWithPath: "/tmp/relay-history-app", isDirectory: true)
    private func output(_ exe: String, _ args: [String]) throws -> String {
        let proc = Process(), pipe = Pipe()
        proc.executableURL = URL(fileURLWithPath: exe)
        proc.arguments = args
        proc.standardOutput = pipe
        if exe == "/usr/bin/python3" { proc.standardError = pipe }
        try proc.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        XCTAssertEqual(proc.terminationStatus, 0, exe + " " + String(decoding: data, as: UTF8.self).prefix(800))
        return String(decoding: data, as: UTF8.self)
    }
    private func socks() throws {
        let n = try output("/usr/bin/curl", ["--silent", "--show-error", "--fail", "--noproxy", "",
            "--proxy", "socks5h://127.0.0.1:1080", "--max-time", "10",
            "--cacert", folder.appendingPathComponent("ca.pem").path,
            "--connect-to", "relay.test:18443:127.0.0.1:18443", "-o", "/dev/null", "-w", "%{size_download}",
            "https://relay.test:18443/4096"])
        XCTAssertEqual(n, "4096")
    }
    private func route() throws -> String {
        try XCTUnwrap(output("/sbin/route", ["-n","get","198.51.100.42"]).split(separator:"\n")
            .first(where: { $0.contains("interface:") })).trimmingCharacters(in: .whitespaces)
    }
    @MainActor private func page(_ name: String, in app: XCUIApplication) {
        let segment = app.radioButtons[name].firstMatch
        let button = segment.exists ? segment : app.buttons[name].firstMatch
        XCTAssertTrue(button.waitForExistence(timeout: 5))
        button.click()
    }
    @MainActor private func recordClosures(_ cycle: Int, in app: XCUIApplication) throws {
        struct Trial: Decodable { let mode: String; let port: Int }
        page("Log", in: app)
        let copy = app.buttons["Copy All"].firstMatch
        XCTAssertTrue(copy.waitForExistence(timeout: 5))
        copy.click()
        let lines = try output("/usr/bin/pbpaste", []).components(separatedBy: .newlines)
        let data = try Data(contentsOf: folder.appendingPathComponent("close-\(cycle).json"))
        let trials = try JSONDecoder().decode([Trial].self, from: data)
        XCTAssertEqual(trials.count, 3)
        var evidence = [String]()
        for trial in trials {
            let peer = "peer=127.0.0.1:\(trial.port) "
            let ready = try XCTUnwrap(lines.last { $0.contains("SOCKS CONNECT ready") && $0.contains(peer) && $0.contains("port=853 ") })
            let resource = try XCTUnwrap(ready.range(of: #"local_resource=[0-9]+"#, options: .regularExpression))
            let id = ready[resource].dropFirst("local_resource=".count)
            let tag = try XCTUnwrap(ready.range(of: #"\[run=[A-F0-9]{8}\]$"#, options: .regularExpression))
            let terminal = lines.filter { $0.contains(ready[tag]) && (($0.contains("Resource \(id) failed:") && $0.contains(" native:")) || ($0.contains("SOCKS session ended:") && $0.contains(peer))) }
            evidence.append("Local DoT \(trial.mode) socket \(id) matching terminal records: \(terminal.count)")
            evidence.append(contentsOf: terminal)
        }
        let attachment = XCTAttachment(string: evidence.joined(separator: "\n"))
        attachment.name = "DoT-closures-\(cycle)"
        attachment.lifetime = .keepAlways
        add(attachment)
        page("Settings", in: app)
    }
    @MainActor func testSwitchWhileConnected() throws {
        continueAfterFailure = false
        let app = XCUIApplication(url: folder.appendingPathComponent("Network Relay Tun.app"))
        app.launch()

        let connect = app.windows.buttons["Connect"].firstMatch
        XCTAssertTrue(connect.waitForExistence(timeout: 20))
        let toggle = app.windows.descendants(matching: .any).matching(identifier: "Global TUN").firstMatch
        XCTAssertTrue(toggle.exists, app.debugDescription.split(separator:"\n").filter { $0.contains("Global") }.joined(separator:"\n"))
        XCTAssertEqual(toggle.value.map { String(describing: $0) }, "0")
        let before = try route(), dns = try output("/usr/sbin/scutil", ["--dns"])
        connect.click()
        let connected = app.windows.staticTexts["Relay Connected"].firstMatch
        XCTAssertTrue(connected.waitForExistence(timeout: 50))
        try socks()
        if FileManager.default.fileExists(atPath: folder.appendingPathComponent("baseline").path) {
            XCTAssertFalse(toggle.isEnabled)
            print("BASELINE connected SOCKS works, mode toggle disabled")
        } else if !FileManager.default.fileExists(atPath: folder.appendingPathComponent("installed").path) {
            XCTAssertTrue(toggle.isEnabled)
            toggle.click()
            let error = app.windows.staticTexts.matching(NSPredicate(format:"label CONTAINS[c] %@ OR value CONTAINS[c] %@", "Install / Update Helper", "Install / Update Helper")).firstMatch
            XCTAssertTrue(error.waitForExistence(timeout: 10), app.debugDescription.split(separator:"\n").filter { $0.contains("capture:") || $0.contains("Global TUN") }.joined(separator:"\n"))
            XCTAssertEqual(toggle.value.map { String(describing: $0) }, "0")
            XCTAssertTrue(connected.exists)
            try socks()
            print("PASS missing helper preserves connected SOCKS")
        } else {
            for cycle in 0..<2 {
                XCTAssertTrue(toggle.isEnabled)
                toggle.click()
                XCTAssertTrue(app.windows.staticTexts["System capture: Capturing IPv4 and IPv6"].firstMatch.waitForExistence(timeout: 50))
                XCTAssertTrue(connected.exists)
                XCTAssertEqual(toggle.value.map { String(describing: $0) }, "1")
                XCTAssertNotEqual(try route(), before)
                XCTAssertTrue(try route().contains("utun"))
                try socks()
                let done = folder.appendingPathComponent("done-\(cycle)")
                let deadline = Date().addingTimeInterval(170)
                while !FileManager.default.fileExists(atPath: done.path), Date() < deadline {
                    Thread.sleep(forTimeInterval: 0.1)
                }
                XCTAssertTrue(FileManager.default.fileExists(atPath: done.path))
                try recordClosures(cycle, in: app)
                toggle.click()
                XCTAssertTrue(app.windows.staticTexts["System capture: Off"].firstMatch.waitForExistence(timeout: 30))
                XCTAssertTrue(connected.waitForExistence(timeout: 50))
                XCTAssertEqual(toggle.value.map { String(describing: $0) }, "0")
                XCTAssertEqual(try route(), before)
                XCTAssertEqual(try output("/usr/sbin/scutil", ["--dns"]), dns)
                try socks()
            }
            print("PASS two live mode round trips restored routes, DNS and SOCKS")
        }
        app.windows.buttons["Disconnect"].firstMatch.click()
        XCTAssertTrue(app.windows.staticTexts["Not Connected"].firstMatch.waitForExistence(timeout: 30))
        let segment = app.radioButtons["Log"].firstMatch
        let button = segment.exists ? segment : app.buttons["Log"].firstMatch
        XCTAssertTrue(button.waitForExistence(timeout: 5))
        button.click()
        let copy = app.buttons["Copy All"].firstMatch
        XCTAssertTrue(copy.waitForExistence(timeout: 5))
        copy.click()
        let log = try output("/usr/bin/pbpaste", [])
        let format = #"(?m)^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z TRACE native: .+ \[run=[A-Fa-f0-9]{8}\]$"#
        XCTAssertNotNil(log.range(of: format, options: .regularExpression))
        XCTAssertNotNil(log.range(of: #" INFO app: System capture: Off \[run=[A-F0-9]{8}\]"#, options: .regularExpression))
        let active = log.range(of: #" INFO app: System capture: Capturing IPv4 and IPv6 \[run=[A-F0-9]{8}\]"#, options: .regularExpression)
        XCTAssertEqual(active != nil, FileManager.default.fileExists(atPath: folder.appendingPathComponent("installed").path))
        let accepted = try NSRegularExpression(pattern: #"SOCKS CONNECT ready [^\n]*local_resource=(\d+) \[run=([A-F0-9]{8})\]"#)
        let rendered = log as NSString
        let linked = accepted.matches(in: log, range: NSRange(location: 0, length: rendered.length)).contains { match in
            let resource = rendered.substring(with: match.range(at: 1)), run = rendered.substring(with: match.range(at: 2))
            return log.contains("resource=\(resource) bytes=0 [run=\(run)]")
        }
        XCTAssertTrue(linked, "The retained log must link an admitted local TCP socket to its native I/O in the same run")
        print("Verified exported native timestamp, correlated SOCKS socket and actual capture mode")
        app.terminate()
    }
}
