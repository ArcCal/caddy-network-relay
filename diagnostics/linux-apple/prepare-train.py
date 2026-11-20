"""Keep the genuine Network.framework configuration and trust checks in the native fixture."""
from pathlib import Path
import sys

source, out = map(Path, sys.argv[1:])
text = source.read_text()
options = "    let udpWarmupCount: Int?"
assert text.count(options) == 1
text = text.replace(options, options + "\n    let udpStartDelayMilliseconds: Int?")
begin = text.index("        let evidence = Evidence(", text.index("    static func udp("))
end = text.index("    }\n    static func main()", begin)
part = Path(__file__).with_name("udp-train.swiftpart").read_text()
out.write_text(text[:begin] + part + text[end:])
