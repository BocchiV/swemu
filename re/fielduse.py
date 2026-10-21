#!/usr/bin/env python
"""Find uses of fields of a global struct reached as `lea reg, [rip+BASE]` followed by
`[reg + disp]`. Prints function start, instruction, and field offset.
   python fielduse.py <dll> <base_va> <disp> [<disp> ...]"""
import os
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RIP

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from pe import PE  # noqa: E402
from xref import Img  # noqa: E402

dll, base = sys.argv[1], int(sys.argv[2], 16)
disps = {int(a, 16) for a in sys.argv[3:]}
p = PE(dll)
img = Img(dll)
data = open(dll, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
start, end = p.va2off(0x180001000), p.va2off(0x1812F0000)
seen = set()
for off in range(start, end - 7):
    # lea r64, [rip+disp32]: 48/4C 8D modrm(00 reg 101)
    if data[off] not in (0x48, 0x4C) or data[off + 1] != 0x8D or (data[off + 2] & 0xC7) != 0x05:
        continue
    va = p.off2va(off)
    disp = int.from_bytes(data[off + 3:off + 7], "little", signed=True)
    if va + 7 + disp != base:
        continue
    lea = next(md.disasm(data[off:off + 7], va))
    reg = lea.operands[0].reg
    for ins in md.disasm(data[off + 7:off + 7 + 48], va + 7):
        hit = False
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == reg and op.mem.disp in disps:
                key = (ins.address, op.mem.disp)
                if key not in seen:
                    seen.add(key)
                    fn = img.func_of(ins.address)
                    print(f"+{op.mem.disp:#x} fn={fn:#x} {ins.address:#x} {ins.mnemonic} {ins.op_str}" if fn else
                          f"+{op.mem.disp:#x} fn=? {ins.address:#x} {ins.mnemonic} {ins.op_str}")
                hit = True
        # stop when reg is overwritten
        if ins.operands and ins.operands[0].type == X86_OP_REG and ins.operands[0].reg == reg and not hit:
            break
        if ins.mnemonic in ("ret", "jmp", "call"):
            break
