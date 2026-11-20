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
    once="\tvar buf []byte\n"
    assert source.count(once)==1
    source=source.replace(once, once+'''	var large *[maxUDPPayload]byte
	defer func() {
		if large != nil {
			clear(large[:])
			select {
			case largeCapsuleBuffers <- large:
			default:
			}
		}
	}()
''')
    return source.replace(old,'''			select {
			case large = <-largeCapsuleBuffers:
			default:
				large = new([maxUDPPayload]byte)
			}
			buf = large[:]''').replace("deliver(buf[:size])","deliver(buf[:size:size])")

if __name__=="__main__":
    path=Path("udp.go")
    path.write_text(source(path.read_text()))
