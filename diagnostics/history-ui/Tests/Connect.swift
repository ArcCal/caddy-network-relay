import XCTest
final class Connect: XCTestCase {
    @MainActor func testConnectButton() throws {
        let folder = URL(fileURLWithPath: "/tmp/relay-history-app", isDirectory: true)
        let app = XCUIApplication(url: folder.appendingPathComponent("Network Relay Tun.app"))
        app.launch()
        defer { app.terminate() }
        let connect = app.windows.buttons["Connect"].firstMatch
        XCTAssertTrue(connect.waitForExistence(timeout: 20))
        XCTAssertTrue(connect.isEnabled)
        connect.click()
        let installed = FileManager.default.fileExists(atPath: folder.appendingPathComponent("installed").path)
        let expected = installed ? "Relay Connected" : "Connection Failed"
        XCTAssertTrue(app.staticTexts[expected].firstMatch.waitForExistence(timeout: 50))
        for _ in 0..<4 {
            Thread.sleep(forTimeInterval: 2)
            XCTAssertNotEqual(app.state, .notRunning)
            XCTAssertTrue(app.staticTexts[expected].firstMatch.exists)
        }
        if installed {
            let off = app.windows.buttons["Disconnect"].firstMatch
            XCTAssertTrue(off.exists)
            off.click()
            XCTAssertTrue(app.staticTexts["Not Connected"].firstMatch.waitForExistence(timeout: 30))
        }
    }
}
