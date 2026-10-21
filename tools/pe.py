#!/usr/bin/env python
"""Tiny PE helper for quick static checks without Ghidra round-trips.
   python pe.py <file> qword <hexva>        -> file/VA locations where a qword VA is stored
   python pe.py <file> read <hexva> <len>   -> hex bytes at VA
   python pe.py <file> vtbl <hexva> <n>     -> n qwords starting at VA"""
import struct, sys

class PE:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        e = struct.unpack_from("<I", self.d, 0x3C)[0]
        nsec = struct.unpack_from("<H", self.d, e + 6)[0]
        optsz = struct.unpack_from("<H", self.d, e + 20)[0]
        opt = e + 24
        self.base = struct.unpack_from("<Q", self.d, opt + 24)[0]
        self.secs = []
        so = opt + optsz
        for i in range(nsec):
            o = so + i * 40
            name = self.d[o:o + 8].rstrip(b"\0").decode()
            vsz, va, rsz, raw = struct.unpack_from("<IIII", self.d, o + 8)
            self.secs.append((name, va, vsz, raw, rsz))
    def va2off(self, va):
        rva = va - self.base
        for n, v, vs, r, rs in self.secs:
            if v <= rva < v + max(vs, rs):
                return r + (rva - v)
        return None
    def off2va(self, off):
        for n, v, vs, r, rs in self.secs:
            if r <= off < r + rs:
                return self.base + v + (off - r)
        return None
    def read(self, va, n):
        o = self.va2off(va)
        return self.d[o:o + n]

if __name__ == "__main__":
    p = PE(sys.argv[1]); cmd = sys.argv[2]
    if cmd == "qword":
        needle = struct.pack("<Q", int(sys.argv[3], 16))
        i = p.d.find(needle)
        while i != -1:
            print(f"off={i:#x} va={p.off2va(i):#x}")
            i = p.d.find(needle, i + 1)
    elif cmd == "read":
        print(p.read(int(sys.argv[3], 16), int(sys.argv[4])).hex())
    elif cmd == "vtbl":
        va = int(sys.argv[3], 16)
        b = p.read(va, 8 * int(sys.argv[4]))
        for i in range(0, len(b), 8):
            print(f"[{i//8:2d}] +{i:#04x} {struct.unpack_from('<Q', b, i)[0]:#x}")
    elif cmd == "info":
        print(hex(p.base)); [print(s[0], hex(s[1]), hex(s[2])) for s in p.secs]
