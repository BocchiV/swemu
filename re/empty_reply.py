"""For PlayScene reply handlers: list the packet-reader calls in order (until
the first non-reader call), and the smallest all-zero payload those readers
accept (err 0, pos == len). Inline counted loops show up as repeated reader
calls; with zero counts they would not run, so check the listing by hand.

  python empty_reply.py <handler_va> [...]
"""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from emu_wire import Emu, DLL

PRIM = {0x180010900: "u8", 0x18000e580: "u16", 0x18000e5b0: "u32", 0x18000e5e0: "u64", 0x18000e610: "f32"}
STR = {0x18000e4b0: "wstr", 0x18000e290: "raw", 0x18000e370: "str8"}
SKIP = {0x1812bb690, 0x18001da90}  # __chkstk, item ctor

d = open(DLL, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
for i in range(nsec):
    nm, vs, v, rs, ro = struct.unpack_from("<8sIIII", d, pe + 24 + opt + i * 40)
    if nm.startswith(b".text"):
        tv, tr = v, ro
md = Cs(CS_ARCH_X86, CS_MODE_64)


def reader_calls(fs, n=0x600):
    o = fs - 0x180000000 - tv + tr
    out = []
    for x in md.disasm(d[o:o + n], fs):
        if x.mnemonic == "ret":
            break
        if x.mnemonic != "call":
            continue
        try:
            t = int(x.op_str, 16)
        except ValueError:
            if out:
                break
            continue
        if t in SKIP:
            continue
        if t in PRIM or t in STR or 0x180000000 <= t < 0x180070000:
            out.append(t)
        elif out:
            break
    return out


def run(emu, steps, payload):
    emu.reset_heap()
    data = emu.alloc(payload if payload else b"\0")
    pkt = bytearray(0x40)
    struct.pack_into("<QIH", pkt, 0x0B, data, 0, 0)
    struct.pack_into("<H", pkt, 0x1B, len(payload))
    p = emu.alloc(pkt)
    out = emu.alloc(0x8000)
    for t in steps:
        if t in PRIM:
            emu.call(t, p + 0x0B)
        elif t == 0x18000e4b0:
            emu.call(t, p + 0x0B, out, 0xFF, out + 0x7FF0)
        elif t == 0x18000e290:
            emu.call(t, p + 0x0B, out, 0x100)
        elif t == 0x18000e370:
            emu.call(t, p + 0x0B, out, 0x100)
        else:
            emu.call(t, p, out)
    return struct.unpack("<IH", emu.read(p + 0x13, 6))


def main():
    emu = Emu(DLL)
    for a in sys.argv[1:]:
        h = int(a, 16)
        steps = reader_calls(h)
        names = [PRIM.get(t) or STR.get(t) or hex(t) for t in steps]
        size = None
        for n in range(0, 400):
            try:
                err, pos = run(emu, steps, bytes(n))
            except Exception:
                continue
            if err == 0 and pos == n:
                size = n
                break
        print(f"{h:#x}: readers {names} -> empty {size}")


if __name__ == "__main__":
    main()
