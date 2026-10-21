"""Maze entry data from the GB client files: tb_Maze_Info (fixed prefix: u16 id,
u8 type, u16 group, u8 min level, u8 members, u16 FP; then the server map
name) + each maze's .vbatch start box (maze*100+1) and VMazeEscapeBox, and
the district exits (VPortalExitBox / VStartEventBox) a maze escape lands on.
Imported by gen_gamedata."""
import os
import contextlib, io, re, struct, sys, zipfile

import gb_maze
import maze_spawn

DATAS = os.path.join(os.environ.get("SW_CLIENT", "."), "datas", "")
_zips = {}


def _pw():
    argv, sys.argv = sys.argv, ["x", "targets/gb2334/SoulWorker64.dll"]
    import pexw_port
    with contextlib.redirect_stdout(io.StringIO()):
        pw = pexw_port.main()
    sys.argv = argv
    return pw


def _zip(name):
    if name not in _zips:
        raw = open(DATAS + name + ".v", "rb").read()
        _zips[name] = zipfile.ZipFile(io.BytesIO(raw.translate(bytes(b ^ 0x55 for b in range(256)))))
    return _zips[name]


def read(arch, path, pw):
    z = _zip(arch)
    try:
        return z.read(path)
    except RuntimeError:
        return z.read(path, pwd=pw[arch].encode("latin1"))


def boxes(text, kind):
    out = []
    for blk in re.findall(r"<%s\b.*?</%s>" % (kind, kind), text, re.S):
        def v(k, blk=blk):
            m = re.search(r'<%s type="\d+" value="([^"]*)"' % k, blk)
            return m.group(1) if m else None
        tl = [float(x) for x in v("m_vPosTopLeft").split(",")]
        br = [float(x) for x in v("m_vPosBottomRight").split(",")]
        centre = [(tl[0] + br[0]) / 2, (tl[1] + br[1]) / 2, tl[2]]
        out.append({"id": int(v("m_ID")), "pos": centre, "rot": float(v("m_fRotation") or 0), "v": v,
                    "rect": [min(tl[0], br[0]), min(tl[1], br[1]), max(tl[0], br[0]), max(tl[1], br[1])]})
    return out


KEY_MAPS = {}


def maze_entries(district_maps):
    pw = _pw()
    tb = read("data11", "../bin/Table/tb_Maze_Info.res", pw)
    open(os.path.join(os.environ.get("TEMP", "."), "tb_Maze_Info_gb.res"), "wb").write(tb)
    rows = gb_maze.gb_maze_maps(os.path.join(os.environ.get("TEMP", "."), "tb_Maze_Info_gb.res"))
    names = set(_zip("data09").namelist())
    mazes, spawn_rows, check_rows = [], [], []
    # Sector flow per map (spawn key): VSectorBox (area, boss, exit portal),
    # VPortalBox (area, jump target) and the in-maze VPortalExitBox /
    # VSectorStartBox landing points.
    sector_rows, portal_rows, jump_rows = [], [], []
    # Difficulty / episode variants share one map file: the start box is the
    # map's own (base maze id*100+1), so take the exact box when present,
    # else the map's first VStartEventBox. Spawns are stored once per map
    # under the first maze id that uses it (MAZES field 9 = spawn key).
    map_key = {}
    for mid, (mapname, pre) in sorted(rows.items()):
        # GB adds one byte after the group (: lv right after it). Checked:
        # 21211 Awakening = Lv.2 FP 2 in the client UI, 21511 = Lv.9.
        mtype, group, _, lv, members, fp = struct.unpack_from("<BHBBBH", pre, 2)
        path = f"World/Table/{mapname}.vbatch"
        if path not in names:
            continue
        text = read("data09", path, pw).decode("utf-8", "replace")
        starts = boxes(text, "VStartEventBox")
        start = next((b for b in starts if b["id"] == mid * 100 + 1), None) or (starts[0] if starts else None)
        if not start:
            continue
        esc = boxes(text, "VMazeEscapeBox")
        # No escape box: the server sends the player back to the town start.
        field, exit_box = (int(esc[0]["v"]("m_iField") or 0), int(esc[0]["v"]("m_iEventObject") or 0)) if esc else (0, 0)
        first = mapname not in map_key
        key = map_key.setdefault(mapname, mid)
        KEY_MAPS[key] = mapname
        mazes.append((mid, lv, fp, start["id"], start["pos"], start["rot"], field, exit_box, key))
        if not first:
            continue
        # Monster spawn boxes (OpenWorker LuaCreatureManager.Create): every
        # VMonsterSpawnBox with Monster slots; check boxes name the spawn
        # boxes a 17/0x31 EVENT_SPAWN_BOX_REQ triggers.
        sp = maze_spawn.spawns(text)
        for bid, b in sorted(sp.items()):
            mons = [m for t, m, _ in b["monsters"] if t == "Monster"]
            if mons:
                spawn_rows.append((mid, bid, b["cond"] == "Immediate", mons[:4], b["pos"], b["rot"], b["sector"], b["waypoint"], b["step"]))
        for b in boxes(text, "VSectorBox"):
            steps = [int(b["v"](f"m_iConditionKillRatio_{i}Step") or 0) for i in range(1, 6)]
            sector_rows.append((mid, b["id"], b["rect"], b["v"]("m_eType") == "Boss", int(b["v"]("m_iSectorExitID") or 0), steps))
        for b in boxes(text, "VPortalBox"):
            field = b["v"]("m_eJumpType") == "Field"
            portal_rows.append((mid, b["id"], b["rect"], field, int(b["v"]("m_iJumpMap") or 0), int(b["v"]("m_iJump") or 0)))
        for kind in ("VPortalExitBox", "VSectorStartBox", "VStartEventBox"):
            for b in boxes(text, kind):
                jump_rows.append((mid, b["id"], b["pos"], b["rot"]))
        for cid, ids in sorted(maze_spawn.checks(text).items()):
            ids = [i for i in ids if i in sp and any(t == "Monster" for t, *_ in sp[i]["monsters"])]
            if ids:
                check_rows.append((mid, cid, ids))
    exits = []
    for district, name in sorted(district_maps.items()):
        text = read("data09", f"World/Table/{name}.vbatch", pw).decode("utf-8", "replace")
        for kind in ("VStartEventBox", "VPortalExitBox"):
            for b in boxes(text, kind):
                exits.append((district, b["id"], b["pos"], b["rot"]))
    return mazes, exits, spawn_rows, check_rows, (sector_rows, portal_rows, jump_rows)


if __name__ == "__main__":
    m, e, sp, ck, _ = maze_entries({10003: "F031_ROCCOTOWN"})
    print(len(sp), "monster spawn boxes,", len(ck), "check boxes")
    print([r for r in sp if r[0] == 21211][:3], [r for r in ck if r[0] == 21211])
    print(len(m), "mazes with start + escape;", len(e), "district exits")
    for r in m:
        if r[0] in (21011, 21211, 21511, 22001, 20001):
            print(r)
    print(e)
