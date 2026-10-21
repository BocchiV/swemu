#!/usr/bin/env python
"""Prove which command line makes the 2.3.34.7 client send LOGIN_FOR_VFUN by itself.

Runs the client's own per-argument parser FUN_1804b2ce0(app, arg, &kind) under Unicorn
against a zeroed copy of the app-config object (Ghidra global DAT_181a24cf0) and
prints the two fields that decide the login path:

  +0x738  launch mode   0 none (ctor 0x1804a7259) | 1 MultiExecuteClient/SkipTWNAuthen
                        | 2 --ip (Steam) | 3 VFunQA:: | 4 fromVLauncher::
  +0x66e  VFunQA flag   set only by "VFunQA::" (0x1804b37a1)

The main loop FUN_180f19640 calls FUN_180f1b790 (auto LOGIN_FOR_VFUN 2/0x23 with a
token, MAC and 0x989746) only when mode == 4; the LoginScene shows the ID/password
dialog (LOGIN_REQ 2/1 via FUN_180beee20) only when VFunQA is set, and mode 3 would
send the typed ID/password to valofe.com (FUN_180becd00) instead of our server.

   .venv/Scripts/python.exe launch_check.py
"""
import struct
from emu_wire import Emu, DLL

F_ARG = 0x1804B2CE0
APP_SIZE = 0x800


def parse_args(emu, args):
    emu.reset_heap()
    app = emu.alloc(APP_SIZE)
    for a in args:
        kind = emu.alloc(4)
        ret = emu.call(F_ARG, app, emu.alloc(a.encode() + b"\0"), kind) & 0xFFFFFFFF
        assert ret == 0, f"parser rejected {a!r}: {ret}"
    mode = struct.unpack("<I", emu.read(app + 0x738, 4))[0]
    qa = emu.read(app + 0x66E, 1)[0]
    return mode, qa


def main():
    emu = Emu(DLL)
    cases = {
        ("swemu",): (0, 0),                                   # old launcher: no login at all
        ("VFunQA::",): (3, 1),                                # ID dialog -> valofe.com, not us
        ("fromVLauncher::",): (4, 0),                         # auto 2/0x23, but token only from VLauncher
        ("VFunQA::", "MultiExecuteClient"): (1, 1),           # ID dialog -> LOGIN_REQ 2/1 to General.ini IP
        ("MultiExecuteClient", "VFunQA::"): (3, 1),           # order matters
    }
    ok = True
    for args, want in cases.items():
        got = parse_args(emu, args)
        flag = "ok" if got == want else "MISMATCH"
        ok &= got == want
        print(f"[{flag}] {' '.join(args):40s} -> mode={got[0]} VFunQA={got[1]}")
    assert ok
    print("launch args for swemu: VFunQA:: MultiExecuteClient")


if __name__ == "__main__":
    main()
