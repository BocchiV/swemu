"""Minidump reader: exception, faulting module, and SoulWorker64.dll return
addresses on the faulting thread's stack (mapped to the 0x180000000 image base).

usage: dumpstack.py <file.dmp> [stack_bytes]
"""
import struct
import sys

IMAGE = 0x180000000


def main():
    path = sys.argv[1]
    depth = int(sys.argv[2]) if len(sys.argv) > 2 else 0x4000
    b = open(path, "rb").read()
    _, _, ns, rva = struct.unpack_from("<4sIII", b, 0)
    streams = {}
    for i in range(ns):
        t, sz, r = struct.unpack_from("<III", b, rva + i * 12)
        streams[t] = (sz, r)

    mods = []
    _, r = streams[4]
    for i in range(struct.unpack_from("<I", b, r)[0]):
        o = r + 4 + i * 108
        base, size = struct.unpack_from("<QI", b, o)
        nr = struct.unpack_from("<I", b, o + 20)[0]
        ln = struct.unpack_from("<I", b, nr)[0]
        name = b[nr + 4:nr + 4 + ln].decode("utf-16-le").replace("/", "\\").split("\\")[-1]
        mods.append((base, size, name))

    def mod(a):
        for base, size, name in mods:
            if base <= a < base + size:
                return name, a - base
        return None, None

    def readmem(a, n):
        if 5 in streams:
            _, r = streams[5]
            for i in range(struct.unpack_from("<I", b, r)[0]):
                st, dsz, drva = struct.unpack_from("<QII", b, r + 4 + i * 16)
                if st <= a < st + dsz:
                    n = min(n, st + dsz - a)
                    return b[drva + a - st:drva + a - st + n]
        if 9 in streams:
            _, r = streams[9]
            c, off = struct.unpack_from("<QQ", b, r)
            for i in range(c):
                st, dsz = struct.unpack_from("<QQ", b, r + 16 + i * 16)
                if st <= a < st + dsz:
                    n = min(n, st + dsz - a)
                    return b[off + a - st:off + a - st + n]
                off += dsz
        return None

    sw = [m for m in mods if m[2].lower() == "soulworker64.dll"]
    print("SoulWorker64.dll base", hex(sw[0][0]) if sw else None)
    _, r = streams[6]
    code, _, _, addr = struct.unpack_from("<IIQQ", b, r + 8)
    print("exception", hex(code), "at", hex(addr), mod(addr))
    csz, crva = struct.unpack_from("<II", b, r + 8 + 152)
    ctx = b[crva:crva + csz]
    rsp = struct.unpack_from("<Q", ctx, 0x98)[0]
    rip = struct.unpack_from("<Q", ctx, 0xF8)[0]
    print("context rip", hex(rip), mod(rip), "rsp", hex(rsp))
    stk = readmem(rsp, depth)
    if not stk:
        print("stack memory not in dump")
        return
    print(f"stack {len(stk)} bytes; module return addresses:")
    for i in range(0, len(stk) - 7, 8):
        v = struct.unpack_from("<Q", stk, i)[0]
        m, o = mod(v)
        if m and m.lower() == "soulworker64.dll":
            print(f"  rsp+{i:#06x}  {IMAGE + o:#x}")
        elif m and i < 0x400:
            print(f"  rsp+{i:#06x}  {m}+{o:#x}")


if __name__ == "__main__":
    main()
