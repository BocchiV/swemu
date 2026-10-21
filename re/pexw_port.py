#!/usr/bin/env python
"""Python port of evo-i/pexw (pexw.c @ sha256 d692ab83..., MIT) for checking it against
our client DLL without building/running third-party code.

pexw: .rdata holds markers "dataNN"; one function (prologue `sub rsp,0x38`) references
only those markers via `lea rdx,[rip+X]`; another function of the same shape references
the XOR-0x05 encrypted archive passwords. Marker k (sorted by RVA) is paired with the
k-th *last* string reference of the first function that has >= 15 non-marker refs.

   .venv/Scripts/python.exe pexw_port.py <dll> [--show]
"""
import re
import struct
import sys

SUB_RSP_38 = b"\x48\x83\xEC\x38"
SCAN_DEPTH, MIN_MARKERS = 2000, 15


def sections(d):
    e = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, e + 6)[0]
    opt = e + 24
    base = struct.unpack_from("<Q", d, opt + 24)[0]
    so = opt + struct.unpack_from("<H", d, e + 20)[0]
    out = {}
    for i in range(n):
        o = so + 40 * i
        name = d[o:o + 8].rstrip(b"\0").decode()
        vsz, va, rsz, raw = struct.unpack_from("<IIII", d, o + 8)
        out[name] = (va, vsz, raw, rsz)
    return base, out


def main():
    d = open(sys.argv[1], "rb").read()
    base, secs = sections(d)
    tva, tvs, traw, trs = secs[".text"]
    rva, rvs, rraw, rrs = secs[".rdata"]
    rdata = d[rraw:rraw + rrs]
    text = d[traw:traw + trs]

    markers = {}
    for m in re.finditer(rb"data[0-9]{2}[0-9]*", rdata):
        if m.start() % 4 == 0:  # pexw scans aligned u32 words
            markers[rva + m.start()] = m.group().decode()
    order = sorted(markers)

    def lea_targets(i):
        out = []
        for j in range(i, min(i + SCAN_DEPTH, len(text) - 7)):
            if text[j:j + 3] == b"\x48\x8D\x15":
                disp = struct.unpack_from("<i", text, j + 3)[0]
                t = tva + j + 7 + disp
                if rva <= t < rva + rvs:
                    out.append(t)
            if text[j] == 0xC3:
                break
        return out

    marker_fn = strings_fn = None
    strings = []
    for m in re.finditer(re.escape(SUB_RSP_38), text):
        i = m.start()
        refs = lea_targets(i)
        mk = [t for t in refs if t in markers]
        other = [t for t in refs if t not in markers]
        if marker_fn is None and len(mk) >= MIN_MARKERS and not other:
            marker_fn = tva + i
        if strings_fn is None and len(other) >= MIN_MARKERS:
            strings_fn = tva + i
            for t in other[:128]:
                o = rraw + (t - rva)
                s = d[o:d.index(b"\0", o)][:511]
                if s:
                    strings.append(s)
    print(f"markers={len(markers)} marker_fn={base + marker_fn:#x}" if marker_fn else f"markers={len(markers)} marker_fn=None")
    print(f"strings_fn={base + strings_fn:#x} strings={len(strings)}" if strings_fn else "strings_fn=None")
    pairs = {}
    for k in range(min(len(order), len(strings))):
        pw = bytes(b ^ 0x05 for b in strings[len(strings) - 1 - k])
        pairs[markers[order[k]]] = pw.decode("latin1")
    if "--show" in sys.argv:
        for name in sorted(pairs, key=lambda x: int(x[4:])):
            print(f"{name}: {pairs[name]}")
    return pairs


if __name__ == "__main__":
    main()
