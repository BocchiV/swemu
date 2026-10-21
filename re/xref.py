#!/usr/bin/env python
"""Fast static cross-reference scan without Ghidra (numpy over raw section bytes).

   python xref.py <dll> call <hexva> [...]   direct CALL/JMP rel32 sites -> containing function start (via .pdata)
   python xref.py <dll> ref  <hexva> [...]   RIP-relative disp32 references (lea/mov/cmp ... [rip+X])
   python xref.py <dll> str  <text>          VA of an ASCII / UTF-16LE string, plus its RIP-relative refs
   python xref.py <dll> func <hexva>         function (from .pdata) containing the VA

RIP-relative matches assume the disp32 is the last 4 bytes of the instruction or is
followed by an imm8/imm32; candidates are reported with the assumed instruction end.
"""
import struct, sys
import numpy as np
sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "tools"))
from pe import PE  # noqa: E402


class Img:
    def __init__(self, path):
        self.pe = PE(path)
        self.d = np.frombuffer(self.pe.d, dtype=np.uint8)
        self.text = next(s for s in self.pe.secs if s[0] == ".text")
        d = self.pe.d
        e = struct.unpack_from("<I", d, 0x3C)[0]
        opt = e + 24
        pdata_rva, pdata_sz = struct.unpack_from("<II", d, opt + 112 + 3 * 8)
        off = self.pe.va2off(self.pe.base + pdata_rva)
        arr = np.frombuffer(d[off:off + pdata_sz], dtype=np.uint32).reshape(-1, 3)
        self.fstart, self.fend = arr[:, 0].astype(np.int64), arr[:, 1].astype(np.int64)

    def func_of(self, va):
        rva = va - self.pe.base
        i = np.searchsorted(self.fstart, rva, side="right") - 1
        if i >= 0 and self.fstart[i] <= rva < self.fend[i]:
            return self.pe.base + int(self.fstart[i])
        return None

    def _text(self):
        name, va, vsz, raw, rsz = self.text
        n = min(vsz, rsz)
        return self.d[raw:raw + n], self.pe.base + va

    def calls(self, target):
        buf, base = self._text()
        rel = buf[1:len(buf) - 3].view(np.uint8)
        # int32 at every offset i+1
        b = buf.astype(np.int64)
        i32 = (b[1:-3] | (b[2:-2] << 8) | (b[3:-1] << 16) | (b[4:] << 24))
        i32 = np.where(i32 >= 2**31, i32 - 2**32, i32)
        idx = np.arange(len(i32), dtype=np.int64)
        tgt = base + idx + 5 + i32
        op = buf[:-4]
        hits = np.nonzero((tgt == target) & ((op == 0xE8) | (op == 0xE9)))[0]
        return [(int(base + h), "call" if buf[h] == 0xE8 else "jmp") for h in hits]

    def refs(self, target):
        out = []
        for name, va, vsz, raw, rsz in self.pe.secs:
            if name != ".text":
                continue
            buf = self.d[raw:raw + min(vsz, rsz)].astype(np.int64)
            base = self.pe.base + va
            i32 = buf[:-3] | (buf[1:-2] << 8) | (buf[2:-1] << 16) | (buf[3:] << 24)
            i32 = np.where(i32 >= 2**31, i32 - 2**32, i32)
            idx = np.arange(len(i32), dtype=np.int64)
            for extra in (0, 1, 4):
                hits = np.nonzero(base + idx + 4 + extra + i32 == target)[0]
                out += [(int(base + h), extra) for h in hits]
        return sorted(set(out))

    def find_str(self, s):
        res = []
        for enc in ("ascii", "utf-16-le"):
            needle = s.encode(enc)
            i = self.pe.d.find(needle)
            while i != -1:
                va = self.pe.off2va(i)
                if va:
                    res.append((va, enc))
                i = self.pe.d.find(needle, i + 1)
        return res


def main():
    img = Img(sys.argv[1])
    cmd = sys.argv[2]
    if cmd == "call":
        for a in sys.argv[3:]:
            t = int(a, 16)
            hits = img.calls(t)
            print(f"== callers of {t:#x}: {len(hits)}")
            for va, kind in hits:
                f = img.func_of(va)
                print(f"  {kind} at {va:#x}  in {f:#x}" if f else f"  {kind} at {va:#x}")
    elif cmd == "ref":
        for a in sys.argv[3:]:
            t = int(a, 16)
            hits = img.refs(t)
            print(f"== rip refs to {t:#x}: {len(hits)}")
            for va, extra in hits:
                f = img.func_of(va)
                print(f"  disp@{va:#x} (+{extra}) in {f:#x}" if f else f"  disp@{va:#x} (+{extra})")
    elif cmd == "str":
        for va, enc in img.find_str(sys.argv[3]):
            hits = img.refs(va)
            fs = sorted({img.func_of(h) for h, _ in hits} - {None})
            print(f"{enc} {va:#x}: refs in " + ", ".join(f"{f:#x}" for f in fs))
    elif cmd == "func":
        f = img.func_of(int(sys.argv[3], 16))
        print(hex(f) if f else None)


if __name__ == "__main__":
    main()
