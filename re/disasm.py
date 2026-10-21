import sys, struct
sys.path.insert(0, "../tools")
from pe import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
p = PE("targets/gb2334/SoulWorker64.dll")
va = int(sys.argv[1], 16); n = int(sys.argv[2])
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(p.read(va, n), va):
    print(f"{i.address:x}: {i.mnemonic} {i.op_str}")
    if i.mnemonic == "int3": break
