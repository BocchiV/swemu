"""Generic reader for the reference server's res/*.res tables, driven by the
TB_*.h struct (fields in struct order; char[N] = u16-length
UTF-16LE string, arrays expand). Usage:

  rows = tbgen.load("TB_SKILL", "tb_Skill.res")   # list of dicts
"""
import os
import re
import struct

HDR = os.environ.get("SW_TB_HEADERS", "TB_headers")
RES = os.path.join(os.environ.get("SW_SERVER_DATA", "server-data"), "res", "")
T = {"unsigned int": "I", "std::uint32_t": "I", "int": "i", "std::int32_t": "i", "std::uint8_t": "B",
     "unsigned char": "B", "std::int8_t": "b", "char": "b", "bool": "B", "std::uint16_t": "H", "unsigned short": "H",
     "std::int16_t": "h", "short": "h", "float": "f", "std::uint64_t": "Q", "std::int64_t": "q", "__int64": "q"}


def fields(struct_name):
    src = open(os.path.join(HDR, struct_name + ".h"), encoding="utf-8", errors="replace").read()
    m = re.search(r"struct %s\s*\{(.*?)\n\};" % struct_name, src, re.S)
    body = re.sub(r"//[^\n]*", "", m.group(1))
    out = []
    for decl in body.split(";"):
        decl = " ".join(decl.split())
        dm = re.match(r"(.+?)\s+(\w+)(?:\[(\d+)\])?(?:\s*=.*)?$", decl)
        if not dm or "(" in decl:
            continue
        typ, name, n = dm.group(1), dm.group(2), dm.group(3)
        typ = typ.replace("const ", "")
        if typ == "char" and n:
            out.append((name, "s"))
        elif typ in T:
            for i in range(int(n or 1)):
                out.append((f"{name}_{i}" if n else name, T[typ]))
        else:
            raise ValueError(f"{struct_name}: unknown type {typ!r} ({name})")
    return out


def load(struct_name, res_name, strict=True):
    b = open(os.path.join(RES, res_name), "rb").read()
    n = struct.unpack_from("<I", b, 0)[0]
    fl = fields(struct_name)
    o, rows = 4, []
    for _ in range(n):
        r = {}
        for name, k in fl:
            if k == "s":
                ln = struct.unpack_from("<H", b, o)[0]
                r[name] = b[o + 2:o + 2 + ln * 2].decode("utf-16-le", "replace")
                o += 2 + ln * 2
            else:
                r[name] = struct.unpack_from("<" + k, b, o)[0]
                o += struct.calcsize(k)
        rows.append(r)
    left = len(b) - o
    if strict and not 0 <= left < 64:
        raise ValueError(f"{res_name}: {left} bytes left after {n} rows -> layout drift")
    return rows


if __name__ == "__main__":
    import sys
    rows = load(sys.argv[1], sys.argv[2])
    print(len(rows), "rows")
    for r in rows[:2]:
        print(r)
