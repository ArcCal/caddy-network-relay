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
                let deadline = Date().addingTimeInterval(120)
                while !FileManager.default.fileExists(atPath: done.path), Date() < deadline {
                    Thread.sleep(forTimeInterval: 0.1)
                }
                XCTAssertTrue(FileManager.default.fileExists(atPath: done.path))
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
        let format = #"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z TRACE native: .+ \[run=[A-Fa-f0-9]{8}\]$"#
        let rendered = app.windows.staticTexts.matching(NSPredicate(format: "label MATCHES %@ OR value MATCHES %@", format, format)).firstMatch
        XCTAssertTrue(rendered.waitForExistence(timeout: 15), "Native trace timestamp was not displayed in the Log tab")
        app.terminate()
    }
}
