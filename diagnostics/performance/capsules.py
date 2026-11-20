"""Generate four readers with the same production parser and different scratch allocation."""
from pathlib import Path
import subprocess
p=Path("udp.go");s=p.read_text()
def body(text): return text[text.index("func readCapsules("):text.index("func discard(")]
old=body(subprocess.check_output(["git","show","HEAD:udp.go"],text=True))
current=body(s)
start=current.index("\t\tif buf == nil && size > 0 {");end=current.index("\t\tif _, err := io.ReadFull",start)
prior=current[:start]+'''		if size > 0 && buf == nil { buf=make([]byte,maxUDPPayload) }
'''+current[end:]
growth=current[:start]+'''		if uint64(cap(buf)) < size { buf=make([]byte,int(size)) }
		buf=buf[:size]
'''+current[end:]
pool=prior.replace("var buf []byte","""var buf []byte
    var slot *[maxUDPPayload]byte
    defer func(){ if slot != nil { clear(slot[:]); select { case studyPool<-slot: default: } } }()""").replace("buf=make([]byte,maxUDPPayload)","select { case slot=<-studyPool: default: slot=new([maxUDPPayload]byte) }; buf=slot[:]")
header="""package networkrelay
import ("bufio";"io";"github.com/quic-go/quic-go/quicvarint")
var studyPool=make(chan *[maxUDPPayload]byte,4)
"""
out=header
for name,source in (("original",prior),("exact",growth),("pool",pool)):
 out+=source.replace("func readCapsules(","func study_"+name+"(")
Path("study_readers_test.go").write_text(out)
