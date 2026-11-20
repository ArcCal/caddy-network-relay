"""Apply a bounded large-only scratch cache to the shipping reader in a disposable checkout."""
from pathlib import Path

def source(original):
    marker="func readCapsules(r io.Reader, deliver func([]byte)) error {"
    start=original.index("// readCapsules")
    decl='''// At most four idle large Capsule buffers are kept for reuse across streams.
var largeCapsuleBuffers = make(chan *[maxUDPPayload]byte, 4)

'''
    source=original[:start]+decl+original[start:]
    old="\t\t\tbuf = make([]byte, maxUDPPayload)"
    assert source.count(old)==1 and source.count(marker)==1
    return source.replace(old,'''			var large *[maxUDPPayload]byte
			select {
			case large = <-largeCapsuleBuffers:
			default:
				large = new([maxUDPPayload]byte)
			}
			buf = large[:]
			defer func() {
				clear(large[:])
				select {
				case largeCapsuleBuffers <- large:
				default:
				}
			}()''').replace("deliver(buf[:size])","deliver(buf[:size:size])")

if __name__=="__main__":
    path=Path("udp.go")
    path.write_text(source(path.read_text()))
