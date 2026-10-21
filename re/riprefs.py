#!/usr/bin/env python
"""List instructions that address given absolute VAs via RIP-relative operands.
   python riprefs.py <dll> <va> [<va> ...]"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "tools"))
from pe import PE  # noqa: E402

dll = sys.argv[1]
targets = {int(a, 16) for a in sys.argv[2:]}
p = PE(dll)
data = open(dll, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
lo, hi = min(targets) - 0x40, max(targets) + 0x40
start, end = p.va2off(0x180001000), p.va2off(0x1812F0000)
for off in range(start, end - 6):
    disp = int.from_bytes(data[off:off + 4], "little", signed=True)
    # disp32 sits 2..7 bytes into the instruction; the next-instruction VA is unknown,
    # so prefilter on any plausible target in range, then decode to confirm.
    va_disp = p.off2va(off)
    if not (lo - 16 <= va_disp + 4 + disp <= hi + 16):
        continue
    for back in range(2, 8):
        s = off - back
        ins = next(md.disasm(data[s:s + 15], p.off2va(s)), None)
        if ins is None:
            continue
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                if t in targets and ins.disp_offset == back:
                    print(f"{hex(t)} <- {hex(ins.address)} {ins.mnemonic} {ins.op_str}")
