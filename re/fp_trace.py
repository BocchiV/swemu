"""Check that the client's CHARACTER_INFO row reader (FUN_180012e20) puts the
server's FP into the row at +0x2c4 / +0x2c6 and the Zenny at player +0x340.
Feeds a real CHARACTER_INFO_RES payload captured from the e2e test server.
usage: fp_trace.py <hex payload file>"""
import struct, sys
from emu_wire import Emu, DLL

pl = bytes.fromhex(open(sys.argv[1]).read().strip())
emu = Emu(DLL)
emu.reset_heap()
data = emu.alloc(pl)
pkt = bytearray(0x40)
struct.pack_into("<QIH", pkt, 0x0B, data, 0, 0)
struct.pack_into("<H", pkt, 0x1B, len(pl))
p = emu.alloc(pkt)
out = emu.alloc(0x1000)
emu.call(0x180013560, p, out)
err, pos = struct.unpack("<IH", emu.read(p + 0x13, 6))
fp = struct.unpack("<hh", emu.read(out + 0x2c4, 4))
zenny = struct.unpack("<Q", emu.read(out + 0x340, 8))[0]
print(f"reader err={err} pos={pos}/{len(pl)} FP row+0x2c4={fp} zenny +0x340={zenny}")
