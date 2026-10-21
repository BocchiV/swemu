"""Find client packet writers for (main, sub): `mov dl, main` and `mov r8b, sub`
close to each other. Prints the site VA and the containing function.
usage: findpkt.py <main> <sub> [<sub> ...]"""
import sys
from xref import Img

img = Img("targets/gb2334/SoulWorker64.dll")
name, rva, vsz, raw, rsz = img.text
d = bytes(img.pe.d[raw:raw + min(vsz, rsz)])
base = img.pe.base
main = int(sys.argv[1], 0)
for sub in (int(x, 0) for x in sys.argv[2:]):
    hits = set()
    a, b = bytes([0xB2, main]), bytes([0x41, 0xB0, sub])
    i = d.find(b)
    while i >= 0:
        j = d.find(a, max(0, i - 40), i + 40)
        if j >= 0:
            site = base + rva + min(i, j)
            hits.add((site, img.func_of(site)))
        i = d.find(b, i + 1)
    print(f"{main}/0x{sub:02X}:", ", ".join(f"{s:#x} in {(f or 0):#x}" for s, f in sorted(hits)) or "-")
