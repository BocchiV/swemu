"""GB 2.3.34.7 tb_Maze_Info: u16 id, 46 B of fixed fields, wstr ServerMap, ...
(the tail holds more strings, so rows are found by the next {u16 id, 46 B,
wstr map name} match). Must find exactly the header's row count."""
import os
import re, struct

MAP = re.compile(r"^[A-Z][A-Z0-9]{1,3}_[A-Z0-9_]+$")


def gb_maze_maps(path=os.path.join(os.environ.get("TEMP", "."), "tb_Maze_Info_gb.res")):
    b = open(path, "rb").read()
    n = struct.unpack_from("<I", b, 0)[0]

    def name_at(o):
        if o + 50 > len(b):
            return None
        ln = struct.unpack_from("<H", b, o + 48)[0]
        if not 3 <= ln <= 64:
            return None
        try:
            s = b[o + 50:o + 50 + ln * 2].decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        return s if MAP.match(s) else None

    out, o, rows = {}, 4, 0
    while rows < n and len(b) - o >= 64:
        mid = struct.unpack_from("<H", b, o)[0]
        s = name_at(o)
        assert s, f"row {rows} at {o}: no map name"
        out.setdefault(mid, (s, b[o:o + 48]))
        rows += 1
        p = o + 50 + 2 * len(s)
        while p < len(b) - 50 and not (struct.unpack_from("<H", b, p)[0] > 0 and name_at(p)):
            p += 1
        o = p
    assert len(b) - o < 64 or rows == n, (len(b) - o)
    return out


if __name__ == "__main__":
    m = gb_maze_maps()
    print(len(m), "rows")
    for k in (20001, 21011, 21106, 21511, 22001):
        print(k, m.get(k, ("-",))[0])
