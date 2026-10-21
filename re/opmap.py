#!/usr/bin/env python
"""Build the client's opcode map statically (no Ghidra needed).

C->S: every call to pktinit FUN_18005b5f0(pkt, main, sub, rand_pad) — main/sub are
      the last `mov dl/edx` and `mov r8b/r8d` before the call; the containing
      function's "send_eSUB_CMD_*" debug string names it.
S->C: functions whose debug string is "receive_eSUB_CMD_*".

   python opmap.py > out/opmap.txt
"""
import re, sys
import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_OP_REG, X86_REG_RIP, X86_REG_DL, X86_REG_EDX, X86_REG_R8B, X86_REG_R8D, X86_REG_R9B, X86_REG_R9D
from xref import Img

DLL = "targets/gb2334/SoulWorker64.dll"
PKTINIT = 0x18005B5F0


def func_range(img, f):
    i = int(np.searchsorted(img.fstart, f - img.pe.base, side="right") - 1)
    return f, img.pe.base + int(img.fend[i])


def strings_in(img, md, f):
    a, b = func_range(img, f)
    out = []
    for ins in md.disasm(img.pe.read(a, b - a), a):
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = ins.address + ins.size + op.mem.disp
                off = img.pe.va2off(tgt)
                if off is None:
                    continue
                s = img.pe.d[off:off + 120].split(b"\0", 1)[0]
                if s.startswith((b"send_eSUB", b"receive_eSUB", b"send_e", b"receive_e")):
                    out.append(s.decode("ascii", "replace"))
    return out


def main():
    img = Img(DLL)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    rows = []
    for site, kind in img.calls(PKTINIT):
        if kind != "call":
            continue
        f = img.func_of(site)
        start = max(f, site - 0x60)
        regs = {}
        for ins in md.disasm(img.pe.read(start, site - start + 5), start):
            if ins.address >= site:
                break
            if ins.mnemonic == "mov" and len(ins.operands) == 2 and ins.operands[0].type == X86_OP_REG:
                r = ins.operands[0].reg
                if ins.operands[1].type == X86_OP_IMM:
                    if r in (X86_REG_DL, X86_REG_EDX):
                        regs["main"] = ins.operands[1].imm & 0xFF
                    elif r in (X86_REG_R8B, X86_REG_R8D):
                        regs["sub"] = ins.operands[1].imm & 0xFF
            if ins.mnemonic == "xor" and len(ins.operands) == 2 and ins.operands[0].type == X86_OP_REG:
                if ins.operands[0].reg == X86_REG_R8D:
                    regs["sub"] = 0
                if ins.operands[0].reg == X86_REG_EDX:
                    regs["main"] = 0
        names = [s for s in strings_in(img, md, f) if s.startswith("send")]
        rows.append((regs.get("main"), regs.get("sub"), f, names[0] if names else ""))
    print("# C->S (pktinit callers)")
    for m, s, f, n in sorted(rows, key=lambda r: (r[0] if r[0] is not None else 999, r[1] if r[1] is not None else 999)):
        ms = f"{m}/0x{s:02X}" if m is not None and s is not None else f"{m}/{s}"
        print(f"{ms:9} {f:#x} {n}")

    print("\n# S->C (functions referencing receive_eSUB_* strings)")
    seen = set()
    for enc in ("ascii",):
        d = img.pe.d
        for m in re.finditer(rb"receive_eSUB_CMD_[A-Za-z0-9_]+", d):
            va = img.pe.off2va(m.start())
            if va is None or va in seen:
                continue
            seen.add(va)
            fs = sorted({img.func_of(h) for h, _ in img.refs(va)} - {None})
            print(f"{m.group().decode():60} " + ", ".join(f"{x:#x}" for x in fs))


if __name__ == "__main__":
    main()
