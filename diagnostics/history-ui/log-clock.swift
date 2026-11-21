import Foundation

let legacy = ISO8601DateFormatter()
let reused = ISO8601DateFormatter()
let foundationStyle = Date.ISO8601FormatStyle()
var lastSecond: Double?
var lastText = ""
func cachedSecond(_ date: Date) -> String {
    let key = date.timeIntervalSince1970.rounded(.down)
    if lastSecond != key {
        lastText = reused.string(from: date)
        lastSecond = key
    }
    return lastText
}
let cases: [(String, (Date) -> String)] = [
    ("original", { ISO8601DateFormatter().string(from: $0) }),
    ("one-formatter-per-client", { reused.string(from: $0) }),
    ("ISO8601FormatStyle", { foundationStyle.format($0) }),
    ("last-second", cachedSecond)
]
let start = 1_795_251_600.0
let samples = [-1.1, -0.0001, 0, 0.001, 951_782_400, start, start + 0.999, start + 0.9999, start + 1, start - 30]
let dates = (0..<10000).map { Date(timeIntervalSince1970: start + Double($0) / 460.0) }
var times = [String: [Double]]()
for (name, render) in cases {
    let mismatches = samples.filter {
        let date = Date(timeIntervalSince1970: $0)
        return render(date) != legacy.string(from: date)
    }
    print("format-validation", name, "mismatches", mismatches)
    if name == "one-formatter-per-client" { precondition(mismatches.isEmpty) }
}
for round in 0..<5 {
    for index in 0..<cases.count {
        let (name, render) = cases[(index + round) % cases.count]
        var last = "", sum = 0
        let before = DispatchTime.now().uptimeNanoseconds
        for date in dates {
            last = render(date)
            sum += last.utf8.count
        }
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - before) / 1_000_000
        precondition(sum == dates.count * 20 && last == legacy.string(from: dates.last!))
        times[name,default: []].append(elapsed)
        print("sample-ms", name, round, elapsed)
    }
}
for (name, _) in cases { print("median-ms-for-10000", name, times[name]!.sorted()[2]) }
