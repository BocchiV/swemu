#!/usr/bin/env python
"""Quick look at a function without Ghidra: calls and referenced strings.

   python fnview.py <dll> <hexva> [--asm]

Uses .pdata for the function range and capstone for decoding. Prints every
direct call target and every RIP-relative operand that points at a printable
ASCII or UTF-16LE string.
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
from xref import Img


def string_at(img, va):
    off = img.pe.va2off(va)
    if off is None:
        return None
    d = img.pe.d
    raw = d[off:off + 200]
    a = raw.split(b"\0", 1)[0]
    if len(a) >= 3 and all(32 <= c < 127 for c in a):
        return repr(a.decode())
    w = []
    for i in range(0, len(raw) - 1, 2):
        c = raw[i] | raw[i + 1] << 8
        if c == 0:
            break
        w.append(c)
    if len(w) >= 3 and all(32 <= c < 0xD800 for c in w) and all(raw[2 * i + 1] == 0 for i in range(len(w))):
        return "L" + repr("".join(map(chr, w)))
    return None


def main():
    img = Img(sys.argv[1])
    va = int(sys.argv[2], 16)
    f = img.func_of(va)
    rva = f - img.pe.base
    import numpy as np
    i = int(np.searchsorted(img.fstart, rva, side="right") - 1)
    end = img.pe.base + int(img.fend[i])
    code = img.pe.read(f, end - f)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    print(f"function {f:#x}..{end:#x} ({end - f} bytes)")
    for ins in md.disasm(code, f):
        note = ""
        if ins.mnemonic in ("call", "jmp") and ins.operands and ins.operands[0].type == 2:
            note = f"-> {ins.operands[0].imm:#x}"
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = ins.address + ins.size + op.mem.disp
                s = string_at(img, tgt)
                note += f" [{tgt:#x}]" + (f" {s}" if s else "")
        if "--asm" in sys.argv:
            print(f"{ins.address:x}: {ins.mnemonic} {ins.op_str}  {note}")
        elif note and ("'" in note or ins.mnemonic == "call"):
            print(f"{ins.address:x}: {ins.mnemonic:5} {note}")


if __name__ == "__main__":
    main()
