#!/usr/bin/env python
"""List the contents of SoulWorker `datas/*.v` archives without extracting anything.

A .v file is a zip whose every byte is XORed with 0x55 (data24.v starts with
05 1E 56 51 = "PK\\x03\\x04" ^ 0x55). The central directory is not encrypted, so
names/sizes/flags are readable without the archive password. Only the tail of each
file is read (EOCD + central directory), so this is fast even for GB-sized archives.

   .venv/Scripts/python.exe vlist.py <datas_dir> <out.json>
"""
import json
import os
import struct
import sys

KEY = 0x55
TAB = bytes(b ^ KEY for b in range(256))


def read_x(f, off, n):
    f.seek(off)
    return f.read(n).translate(TAB)


def central_dir(f, size):
    tail_len = min(size, 0x10000 + 22)
    tail = read_x(f, size - tail_len, tail_len)
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        raise ValueError("no end-of-central-directory record")
    _, _, _, _, count, cd_size, cd_off, _ = struct.unpack_from("<IHHHHIIH", tail, i)
    if cd_off == 0xFFFFFFFF or count == 0xFFFF:  # zip64
        j = tail.rfind(b"PK\x06\x07")
        loc_off = struct.unpack_from("<Q", tail, j + 8)[0]
        rec = read_x(f, loc_off, 56)
        count, cd_size, cd_off = struct.unpack_from("<QQQ", rec, 32)
    return count, read_x(f, cd_off, cd_size)


def entries(cd, count):
    o = 0
    for _ in range(count):
        sig, _, _, flag, method, _, _, _, csize, usize, nlen, xlen, clen = struct.unpack_from("<IHHHHHHIIIHHH", cd, o)
        assert sig == 0x02014B50, "bad central directory entry"
        name = cd[o + 46:o + 46 + nlen].decode("cp949", "replace")
        yield {"name": name, "csize": csize, "usize": usize, "method": method, "encrypted": bool(flag & 1)}
        o += 46 + nlen + xlen + clen


def main():
    src, out = sys.argv[1], sys.argv[2]
    result = {}
    for fn in sorted(os.listdir(src)):
        if not fn.lower().endswith(".v"):
            continue
        path = os.path.join(src, fn)
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = read_x(f, 0, 4)
            if head != b"PK\x03\x04":
                result[fn] = {"error": f"not a xor-0x55 zip (head {head.hex()})", "size": size}
                continue
            try:
                count, cd = central_dir(f, size)
                result[fn] = {"size": size, "files": list(entries(cd, count))}
            except Exception as e:  # keep going; report per archive
                result[fn] = {"error": str(e), "size": size}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False)
    ok = sum(1 for v in result.values() if "files" in v)
    print(f"archives={len(result)} listed={ok} errors={len(result) - ok} -> {out}")


if __name__ == "__main__":
    main()
