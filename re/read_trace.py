#!/usr/bin/env python
"""Trace which bytes a client reader consumes, in order (Unicorn memory-read hook).

Feeds the reader a payload and records every read inside the payload buffer as
(offset, size). Contiguous same-call reads are merged by the cursor helpers, so
the output is the wire layout: one line per primitive read.

  python read_trace.py <main> <sub> <hex payload>      # a READERS entry
  python read_trace.py fn <hexaddr> <hex payload>      # any reader fn(pkt, out)

Use a payload of zeros to get the fixed prefix (counted lists run 0 times),
then put 1 into a count to see one list entry.
"""
import struct
import sys

from unicorn import UC_HOOK_MEM_READ

from emu_wire import Emu, DLL
import reader_check as rc


def trace(emu, steps, payload, out_size=0x4000):
    emu.reset_heap()
    data = emu.alloc(payload if payload else b"\0")
    pkt = bytearray(0x40)
    struct.pack_into("<QIH", pkt, 0x0B, data, 0, 0)
    struct.pack_into("<H", pkt, 0x1B, len(payload))
    p = emu.alloc(pkt)
    out = emu.alloc(out_size)
    reads = []

    def hook(u, access, addr, size, value, _):
        if data <= addr < data + max(len(payload), 1):
            reads.append((addr - data, size))

    h = emu.u.hook_add(UC_HOOK_MEM_READ, hook)
    try:
        for kind, fn in steps:
            if kind == "cur":
                emu.call(fn, p + 0x0B)
            elif kind == "wstr":
                emu.call(fn, p + 0x0B, out, 0xFF, out + out_size - 8)
            elif kind == "cur256":
                emu.call(fn, p + 0x0B, out, 0x100)
            else:
                emu.call(fn, p, out)
    finally:
        emu.u.hook_del(h)
    err, pos = struct.unpack("<IH", emu.read(p + 0x13, 6))
    # memcpy-style reads show up as many 1..8 byte reads; merge runs per start
    merged = []
    for off, size in reads:
        if merged and merged[-1][0] + merged[-1][1] == off and merged[-1][2]:
            merged[-1] = (merged[-1][0], merged[-1][1] + size, True)
        else:
            merged.append((off, size, size == 1 and False))
    return [(o, s) for o, s, _ in merged], err, pos


def main():
    emu = Emu(DLL)
    if sys.argv[1] == "fn":
        steps = [("pkt", int(sys.argv[2], 16))]
    else:
        addr = rc.READERS[(int(sys.argv[1], 0), int(sys.argv[2], 0))][0]
        payload = bytes.fromhex(sys.argv[3])
        steps = addr(payload) if callable(addr) else addr if isinstance(addr, list) else [("pkt", addr)]
    payload = bytes.fromhex(sys.argv[3])
    reads, err, pos = trace(emu, steps, payload)
    for o, s in reads:
        v = int.from_bytes(payload[o:o + s], "little") if s <= 8 else payload[o:o + s].hex()
        print(f"  +{o:3d} {s}B  {v}")
    print(f"err={err} consumed {pos}/{len(payload)}")


if __name__ == "__main__":
    main()
