"""Trace several client readers with zero payloads (layout survey)."""
import sys
from emu_wire import Emu, DLL
from read_trace import trace

emu = Emu(DLL)
for spec in sys.argv[1:]:
    fn, n = spec.split(":")
    reads, err, pos = trace(emu, [("pkt", int(fn, 16))], bytes(int(n)))
    print(f"== {fn} len {n}: err={err} pos={pos}  " + " ".join(f"{o}:{s}" for o, s in reads))
