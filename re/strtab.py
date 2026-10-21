#!/usr/bin/env python
"""Read SoulWorker string tables (tb_*_String_<LANG>.res) from data11.v in memory.

Layout (tb_UI_String_ENG.res, checked on 2.3.34.7):
  u32 count, then count x { u32 id, u8 flag, u16 len_units, UTF-16LE[len_units] }

   .venv/Scripts/python.exe strtab.py <table> <id_hex> [<id_hex> ...]
   e.g. strtab.py tb_UI_String_ENG d7a1 d7a2
"""
import os
import contextlib
import io
import struct
import sys
import zipfile

import pexw_port

DATAS = os.path.join(os.environ.get("SW_CLIENT", "."), "datas", "")
DLL = "targets/gb2334/SoulWorker64.dll"


def open_archive(n):
    argv = sys.argv
    sys.argv = ["x", DLL]
    with contextlib.redirect_stdout(io.StringIO()):
        pw = pexw_port.main()
    sys.argv = argv
    raw = open(f"{DATAS}/data{n:02d}.v", "rb").read()
    z = zipfile.ZipFile(io.BytesIO(raw.translate(bytes(b ^ 0x55 for b in range(256)))))
    return z, pw.get(f"data{n:02d}", "").encode("latin1")


def parse(b):
    count = struct.unpack_from("<I", b, 0)[0]
    o, out = 4, {}
    for _ in range(count):
        sid, _flag, n = struct.unpack_from("<IBH", b, o)
        o += 7
        out[sid] = b[o:o + 2 * n].decode("utf-16-le", "replace")
        o += 2 * n
    return out, o


def load(table):
    z, key = open_archive(11)
    b = z.read(f"../bin/Table/{table}.res", pwd=key)
    return parse(b), len(b)


if __name__ == "__main__":
    (tab, used), size = load(sys.argv[1])
    print(f"{sys.argv[1]}: {len(tab)} strings, parsed {used}/{size} bytes")
    for a in sys.argv[2:]:
        k = int(a, 16)
        print(f"0x{k:x} ({k}): {tab.get(k)!r}")
