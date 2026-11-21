// Test whether native TLS preserves authenticated EOF when bare TCP FIN is an error.
private final class StrictTCP: NWProtocolFramerImplementation {
    static let label = "Strict TCP EOF probe"
    static let definition = NWProtocolFramer.Definition(implementation: StrictTCP.self)
    required init(framer: NWProtocolFramer.Instance) {}
    func start(framer: NWProtocolFramer.Instance) -> NWProtocolFramer.StartResult {
        framer.passThroughOutput()
        return .ready
    }
    func handleInput(framer: NWProtocolFramer.Instance) -> Int {
        while true {
            var count = 0
            var final = false
            _ = framer.parseInput(minimumIncompleteLength: 1, maximumLength: 65536) { buffer, end in
                count = buffer?.count ?? 0
                final = end
                return 0
            }
            if count > 0 {
                let message = NWProtocolFramer.Message(definition: Self.definition)
                guard framer.deliverInputNoCopy(length: count, message: message, isComplete: true) else { return 0 }
            }
            if final {
                framer.markFailed(error: .posix(.ECONNRESET))
                return 0
            }
            if count == 0 { return 1 }
        }
    }
    func handleOutput(framer: NWProtocolFramer.Instance, message: NWProtocolFramer.Message, messageLength: Int, isComplete: Bool) {
        do { try framer.writeOutputNoCopy(length: messageLength) }
        catch { framer.markFailed(error: .posix(.EIO)) }
    }
    func wakeup(framer: NWProtocolFramer.Instance) {}
    func stop(framer: NWProtocolFramer.Instance) -> Bool { true }
    func cleanup(framer: NWProtocolFramer.Instance) {}
}
