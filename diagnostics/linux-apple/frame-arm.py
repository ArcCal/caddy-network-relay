"""Bound only HTTP/3 DATA frames in the experimental binary."""
import sys
from pathlib import Path

root = Path(sys.argv[1]); variant = sys.argv[2]
assert variant in ('stock', 'frame')

def substitute(p, before, after):
    f = root / p; source = f.read_text(); assert source.count(before) == 1, p; f.write_text(source.replace(before, after))

if variant == 'frame':
    substitute('client.go','func (c *h3Client) Write(p []byte) (int, error) { return c.str.Write(p) }', '''func (c *h3Client) Write(p []byte) (int, error) {
    const maxPayload = 16383
    total := 0
    for len(p) > maxPayload {
        n, err := c.str.Write(p[:maxPayload]); total += n
        if err != nil { return total, err }
        if n != maxPayload { return total, io.ErrShortWrite }
        p = p[n:]
    }
    n, err := c.str.Write(p)
    return total+n, err
}''')
