#!/usr/bin/env python
"""Generate server/src/gamedata.rs: starter weapon and costume sets per class.

Reads the client's own tables from datas/data11.v in memory (zip XOR 0x55,
ZipCrypto passwords from pexw_port; nothing is extracted or printed):

  tb_Character_Info.res  row per class (id = class * 1000): u32 Item_ID_Weapon_01
                         followed by u32 Default_Cloth_ID_01..04 (tb_Create_Cloth ids)
  tb_Create_Cloth.res    u32 count, rows {u16 id, u32 x6 item ids, wstr icon}
                         item order (reconstructed server): head, body, hands,
                         stocking, foot, pants
  tb_Item.res            only ids present here are kept (sanity check)

Usage: python gen_gamedata.py [--check]   (--check: compare with the file on disk)
"""
import os
import contextlib
import io
import struct
import sys
import zipfile

DATAS = os.path.join(os.environ.get("SW_CLIENT", "."), "datas", "data11.v")
DLL = "targets/gb2334/SoulWorker64.dll"
OUT = "../server/src/gamedata.rs"


def load_tables():
    argv, sys.argv = sys.argv, ["x", DLL]
    import pexw_port
    with contextlib.redirect_stdout(io.StringIO()):
        pw = pexw_port.main()
    sys.argv = argv
    raw = open(DATAS, "rb").read()
    z = zipfile.ZipFile(io.BytesIO(raw.translate(bytes(b ^ 0x55 for b in range(256)))))
    key = pw["data11"].encode("latin1")
    read = lambda n: z.read("../bin/Table/" + n, pwd=key)
    return (read("tb_Character_Info.res"), read("tb_Create_Cloth.res"), read("tb_Item.res"),
            read("tb_CashShop.res"), read("tb_CashBilling_Info.res"), read("tb_Item_Package.res"),
            read("tb_Item_Classify.res"), read("tb_NPC.res"), read("tb_Quest_Episode.res"),
            read("tb_Shop.res"), read("tb_Skill.res"))


def quest_bits(b):
    """tb_Quest_Episode: episode id -> Complete_Bit. Rows are variable length;
    each starts u32 id, u32 Complete_Bit, u32 id (C++ TB_QUEST_EPISODE)."""
    rows, n = {}, struct.unpack_from("<I", b, 0)[0]
    for o in range(4, len(b) - 12):
        i, bit, i2 = struct.unpack_from("<III", b, o)
        if i == i2 and 100000 <= i < 10_000_000 and bit < 2048 and i not in rows:
            rows[i] = bit
    assert len(rows) == n, (len(rows), n)
    return rows


def npc_show_quests(b, npc_id):
    """tb_NPC row of npc_id: (default visible, [(episode, state)] toggles).
    Row: u32 id, u16, u8, wstr code name, u32 id, u32 script, 3 x u32, u8,
    u32, u8, u8 visible, 4 x u32 episode, 4 x u8 state, ... The client spawn
    check FUN_180466390 starts from `visible` and flips it for each listed
    episode that is completed (any state) or in progress with state 0/1."""
    key = struct.pack("<I", npc_id)
    o = b.find(key)
    while o >= 0:
        n = struct.unpack_from("<H", b, o + 7)[0]
        if n < 40:
            p = o + 9 + 2 * n
            if struct.unpack_from("<I", b, p)[0] == npc_id:
                p += 20 + 1 + 4 + 1
                vis = b[p]
                eps = struct.unpack_from("<4I", b, p + 1)
                sts = b[p + 17:p + 21]
                return vis, [(e, s) for e, s in zip(eps, sts) if e]
        o = b.find(key, o + 1)
    return None


VBATCH_ARCHIVE = os.path.join(os.environ.get("SW_CLIENT", "."), "datas", "data09.v")
# district id -> World/Table/<name>.vbatch (data09.v). Only districts the
# server can put players in are listed.
DISTRICT_MAPS = {10003: "F031_ROCCOTOWN"}


def load_vbatch(name):
    argv, sys.argv = sys.argv, ["x", DLL]
    import pexw_port
    with contextlib.redirect_stdout(io.StringIO()):
        pw = pexw_port.main()
    sys.argv = argv
    raw = open(VBATCH_ARCHIVE, "rb").read()
    z = zipfile.ZipFile(io.BytesIO(raw.translate(bytes(b ^ 0x55 for b in range(256)))))
    path = f"World/Table/{name}.vbatch"
    try:
        return z.read(path).decode("utf-8", "replace")
    except RuntimeError:  # encrypted entry
        return z.read(path, pwd=pw["data09"].encode("latin1")).decode("utf-8", "replace")


def parse_vbatch_npcs(text):
    """NPCs placed on a district map: VMonsterSpawnBox slots with m_eTypeN=NPC
    (OpenWorker NpcManager: only m_eCreationCondition Immediate). Position =
    box centre in x/y, box floor in z; rotation in degrees."""
    import re

    def val(blk, key):
        m = re.search(r'<%s type="\d+" value="([^"]*)"' % key, blk)
        return m.group(1) if m else None

    out = []
    for blk in re.findall(r"<VMonsterSpawnBox\b.*?</VMonsterSpawnBox>", text, re.S):
        if val(blk, "m_eCreationCondition") != "Immediate":
            continue
        tl = [float(v) for v in val(blk, "m_vPosTopLeft").split(",")]
        br = [float(v) for v in val(blk, "m_vPosBottomRight").split(",")]
        pos = ((tl[0] + br[0]) / 2, (tl[1] + br[1]) / 2, tl[2])
        rot = float(val(blk, "m_fRotation") or 0)
        waypoint = int(val(blk, "m_iWaypoint") or 0)
        sector = int(val(blk, "m_iSectorID") or 0)
        for i in range(1, 11):
            nid = int(val(blk, f"m_iMonsterID{i}") or 0)
            if val(blk, f"m_eType{i}") == "NPC" and nid:
                out.append((nid, pos, rot, waypoint, sector))
    return out


def parse_classify(b):
    """tb_Item_Classify (2.3.34.7): u32 id, 4 x {u8 group, u16 name}, 11 bytes
    {gain, inven, slot, repair, use_state, use_type, consume, ...}, u16 fee,
    4 x wstr (move/drop/equip/unequip sounds), u16. -> {id: (inven, slot)}."""
    n = struct.unpack_from("<I", b, 0)[0]
    o, out = 4, {}
    for _ in range(n):
        rid = struct.unpack_from("<I", b, o)[0]
        o += 4 + 12
        inven, slot = b[o + 1], b[o + 2]
        o += 11 + 2
        for _ in range(4):
            ln = struct.unpack_from("<H", b, o)[0]
            o += 2 + ln * 2
        o += 2
        out[rid] = (inven, slot)
    assert len(b) - o < 64, f"tb_Item_Classify layout drift: {len(b) - o} bytes left"
    return out


def item_storage(items, classify, wanted=None):
    """item id -> (inven, slot). tb_Item rows are variable length (238/240/264 B
    seen: embedded strings), so rows are walked by finding the next
    {u32 id, u32 classify id} pair; the walk must end within one row of EOF and
    yield exactly the header's row count."""
    n = struct.unpack_from("<I", items, 0)[0]
    out, o = {}, 4
    for k in range(n):
        iid, cls = struct.unpack_from("<II", items, o)
        if cls in classify and iid not in out:
            # u32 id, u32 classify, u8 rank, u8, u16 level, u32 sell, u32 buy,
            # u32 recycle sell, u32 recycle buy, u16 stack max. Offsets checked
            # on the 2.3.34.7 file (one byte more than C++ TB_ITEM before the
            # prices: weapon 111011301 sells 54, buys 1080 = 20 x sell).
            sell, buy = struct.unpack_from("<II", items, o + 12)
            stack = struct.unpack_from("<H", items, o + 28)[0]
            out[iid] = classify[cls] + (sell, buy, max(stack, 1))
        if k == n - 1:
            break
        p = o + 200
        while p < len(items) - 8:
            nid, ncls = struct.unpack_from("<II", items, p)
            if ncls in classify and 0 < nid < 2**31:
                break
            p += 1
        o = p
    assert len(items) - o < 400, f"tb_Item walk ended {len(items) - o} bytes before EOF"
    if wanted is not None:
        missing = sorted(i for i in wanted if i not in out)
        # Package entries 11.. are currencies (gold, points), not tb_Item rows.
        if missing:
            print(f"note: {len(missing)} referenced ids are not tb_Item rows: {missing[:8]}", file=sys.stderr)
    return out


def parse_shop(b):
    """tb_Shop (2.3.34.7, checked against the file: the whole table parses to
    within the trailer): u32 index, u32 group, 7 bytes, u32 item, 6 bytes,
    2 x wstr dates, u8 price type, u16 item count, 5 x u32 price, u8, u8, u32.
    (Differs from the C++ TB_SHOP field order.) -> [(index, group, item,
    price type, count, base price)]."""
    n = struct.unpack_from("<I", b, 0)[0]
    o, out = 4, []
    for _ in range(n):
        idx, grp = struct.unpack_from("<II", b, o)
        item = struct.unpack_from("<I", b, o + 15)[0]
        p = o + 25
        for _ in range(2):
            ln = struct.unpack_from("<H", b, p)[0]
            p += 2 + ln * 2
        ptype, count = struct.unpack_from("<BH", b, p)
        base = struct.unpack_from("<I", b, p + 3)[0]
        out.append((idx, grp, item, ptype, count, base))
        o = p + 29
    assert len(b) - o < 64, f"tb_Shop layout drift: {len(b) - o} bytes left"
    return out


def parse_packages(b):
    """tb_Item_Package: fixed 156-byte rows (u32 count header, 34-byte table trailer)."""
    n = struct.unpack_from("<I", b, 0)[0]
    assert 0 <= len(b) - 4 - 156 * n < 64, "tb_Item_Package layout drift"
    out = []
    for i in range(n):
        o = 4 + i * 156
        items = struct.unpack_from("<15I", b, o + 21)
        counts = struct.unpack_from("<15I", b, o + 96)
        its = [(it, c) for it, c in zip(items, counts) if it]
        if its:
            out.append((struct.unpack_from("<I", b, o)[0], its))
    return out


def _walk(b, spec):
    """Rows of a .res table: u32 count, then fields per spec ('s' = u16-counted UTF-16LE)."""
    n = struct.unpack_from("<I", b, 0)[0]
    o, rows = 4, []
    for _ in range(n):
        row = []
        for f in spec:
            if f == "s":
                ln = struct.unpack_from("<H", b, o)[0]
                o += 2
                row.append(b[o:o + ln * 2].decode("utf-16-le", "replace"))
                o += ln * 2
            else:
                row.append(struct.unpack_from("<" + f, b, o)[0])
                o += struct.calcsize("<" + f)
        rows.append(row)
    return rows, o


# tb_CashShop row (2.3.34.7; 608818 of 608852 bytes consumed, rest is the table trailer):
# 0 id, 1 tab, 2 sub-tab, 3 sell_active, 4 item, 5 u8, 6 u8, 7 u8, 8 order, 9 u8,
# 10 start date, 11 end date, 12 u32, 13 billing id, 14..16 u8, 17 u32, 18 url, 19 u32, 20 u8, 21 u8
CASH_SHOP_SPEC = ["I", "H", "H", "B", "I", "B", "B", "B", "I", "B", "s", "s",
                  "I", "I", "B", "B", "B", "I", "s", "I", "B", "B"]


def parse_cash_shop(shop, billing, today):
    """Products on sale: (id, item, order, billing, [(item, count, base, price)])."""
    rows, used = _walk(shop, CASH_SHOP_SPEC)
    assert len(shop) - used < 64, f"tb_CashShop layout drift: {len(shop) - used} bytes left"
    nb = struct.unpack_from("<I", billing, 0)[0]
    bill = {}
    for i in range(nb):  # u16 id + 20 u32: item[5], count[5], base price[5], price[5]
        o = 4 + i * 82
        v = struct.unpack_from("<20I", billing, o + 2)
        bill[struct.unpack_from("<H", billing, o)[0]] = [
            (v[k], v[5 + k], v[10 + k], v[15 + k]) for k in range(5) if v[k]]
    out = []
    for r in rows:
        end = r[11][:10]
        if r[3] != 1 or r[13] not in bill or (end not in ("", "0") and end < today):
            continue
        out.append((r[0], r[4], r[8], r[13], bill[r[13]]))
    return out


def parse_cloth(b):
    n = struct.unpack_from("<I", b, 0)[0]
    o, rows = 4, {}
    for _ in range(n):
        rid = struct.unpack_from("<H", b, o)[0]
        items = struct.unpack_from("<6I", b, o + 2)
        o += 2 + 24
        ln = struct.unpack_from("<H", b, o)[0]
        o += 2 + ln * 2
        rows[rid] = items
    return rows


def parse_class_starts(b, cloth_ids):
    """Each class row holds weapon id + 4 cloth ids right after each other."""
    out = {}
    for cls in range(1, 31):
        rid = cls * 1000
        start = b.find(struct.pack("<H", rid) + b"\x00\x00", 4)
        # rows begin with u16 id; locate the (weapon, cloth x4) run inside this row
        for o in range(4, len(b) - 20):
            w, c1, c2, c3, c4 = struct.unpack_from("<5I", b, o)
            if c1 in cloth_ids and c1 // 100 == cls and 100_000_000 <= w < 300_000_000:
                out[cls] = (w, [c for c in (c1, c2, c3, c4) if c in cloth_ids])
                break
        del start
    return out


def skill_ids(b):
    """tb_Skill: every skill id (rows start u32 id, u16, u32 id again)."""
    ids = set()
    for o in range(4, len(b) - 10):
        a = struct.unpack_from("<I", b, o)[0]
        if 10000 <= a < 2_000_000_000 and a == struct.unpack_from("<I", b, o + 6)[0]:
            ids.add(a)
    return ids


def class_skills(info, starts, skills):
    """tb_Character_Info Default_Skill_01..20 (20 x u32, 106 bytes after the
    weapon + cloth run of the class row), kept if present in tb_Skill."""
    out = {}
    for cls, (w, cl) in starts.items():
        o = info.find(struct.pack("<I", w))
        while o >= 0 and struct.unpack_from("<I", info, o + 4)[0] != (cl[0] if cl else 0):
            o = info.find(struct.pack("<I", w), o + 1)
        if o < 0:
            continue
        seen = []
        for v in struct.unpack_from("<20I", info, o + 106):
            if v in skills and v not in seen:
                seen.append(v)
        out[cls] = seen
    return out


def item_ids(b):
    return b  # membership checked by searching the packed u32


def main():
    (info, cloth, items, shop, billing, package, classify_raw, npc_tab, episodes, npc_shop_raw,
     skill_tab) = load_tables()
    cloth_rows = parse_cloth(cloth)
    starts = parse_class_starts(info, set(cloth_rows))
    # Fixed date so --check is reproducible; regenerate to refresh the shop.
    products = parse_cash_shop(shop, billing, "2026-10-18")
    packages = parse_packages(package)
    has_item = lambda i: i != 0 and items.find(struct.pack("<I", i)) >= 0
    lines = [
        "//! Generated by re/gen_gamedata.py from the 2.3.34.7 client tables",
        "//! (data11.v: tb_Character_Info, tb_Create_Cloth, tb_Item, tb_CashShop,",
        "//! tb_CashBilling_Info). Do not edit.",
        "",
        "/// (class, starter soul weapon item id, creator costume choices)",
        "pub const CLASS_START: &[(u8, u32, &[u16])] = &[",
    ]
    for cls, (w, cl) in sorted(starts.items()):
        if not has_item(w):
            w = 0
        lines.append(f"    ({cls}, {w}, &[{', '.join(map(str, cl))}]),")
    lines += [
        "];",
        "",
        "/// tb_Create_Cloth: id -> item ids (head, body, hands, stocking, foot, pants);",
        "/// 0 = no item in that slot (or not in tb_Item).",
        "pub const CREATE_CLOTH: &[(u16, [u32; 6])] = &[",
    ]
    for rid, its in sorted(cloth_rows.items()):
        its = [i if has_item(i) else 0 for i in its]
        lines.append(f"    ({rid}, [{', '.join(map(str, its))}]),")
    lines += [
        "];",
        "",
        "/// Cash shop products on sale (tb_CashShop sell_active = 1, not expired,",
        "/// with a tb_CashBilling_Info row): (shop id, item, order, billing id,",
        "/// [(item, count, base price, price)]).",
        "pub const CASH_SHOP: &[(u32, u32, u32, u32, &[(u32, u16, u32, u32)])] = &[",
    ]
    for pid, item, order, bid, infos in products:
        inf = ", ".join(f"({i}, {c}, {bp}, {p})" for i, c, bp, p in infos)
        lines.append(f"    ({pid}, {item}, {order}, {bid}, &[{inf}]),")
    lines += [
        "];",
        "",
        "/// tb_Item_Package: box item -> contents [(item, count)] (row 156 B: u32 id,",
        "/// 17 B header, 15 x u32 item at 21, 15 x u32 count at 96). Opened by ITEM_USE.",
        "pub const ITEM_PACKAGE: &[(u32, &[(u32, u32)])] = &[",
    ]
    for pid, its in packages:
        lines.append(f"    ({pid}, &[{', '.join(f'({i}, {c})' for i, c in its)}]),")
    # Storage + equip slot for every item the server can hand out (shop, boxes,
    # starter gear), from tb_Item -> tb_Item_Classify.
    wanted = {i for p in products for i, _, _, _ in p[4]}
    wanted |= {i for _, its in packages for i, _ in its}
    wanted |= {w for w, _ in starts.values()}
    wanted |= {i for its in cloth_rows.values() for i in its if i}
    where = item_storage(items, parse_classify(classify_raw), wanted)
    lines += [
        "];",
        "",
        "/// item id -> (storage group, equip slot type, sell price, buy price,",
        "/// stack max): tb_Item_Classify Item_Inven_Type / Item_Slot_Type and",
        "/// tb_Item Sell_Price / Buy_Price / Item_Stack_Max, for every tb_Item row",
        "/// (also the list of valid ids for /item). Sorted by id (binary search).",
        "pub const ITEM_STORAGE: &[(u32, u8, u8, u32, u32, u16)] = &[",
    ]
    for iid, (inven, slot, sell, buy, stack) in sorted(where.items()):
        lines.append(f"    ({iid}, {inven}, {slot}, {sell}, {buy}, {stack}),")
    # NPC shops: rows paid in Zenny (price type 1). The client shows tb_Shop
    # itself; the server only needs index -> (item, count, price) to charge.
    npc_shop = [r for r in parse_shop(npc_shop_raw) if r[3] == 1 and r[2] in where]
    lines += [
        "];",
        "",
        "/// NPC shop rows paid in Zenny (tb_Shop Price_Type 1, Sell_Active):",
        "/// (shop index, group, item, count, unit price; 0 = tb_Item Buy_Price).",
        "/// Sorted by index.",
        "pub const NPC_SHOP: &[(u32, u32, u32, u16, u32)] = &[",
    ]
    for idx, grp, item, _, count, base in sorted(npc_shop):
        lines.append(f"    ({idx}, {grp}, {item}, {count}, {base}),")
    lines += [
        "];",
        "",
        "/// NPCs on each district map (World/Table/<map>.vbatch VMonsterSpawnBox,",
        "/// type NPC, created Immediate): (district, [(npc id, [x, y, z], rotation",
        "/// degrees, waypoint, sector)]). Sent as WORLD_OTHER_INFOS_NPC 4/0x22.",
        "pub const DISTRICT_NPCS: &[(u16, &[(u32, [f32; 3], f32, u32, u32)])] = &[",
    ]
    for district, name in sorted(DISTRICT_MAPS.items()):
        npcs = parse_vbatch_npcs(load_vbatch(name))
        lines.append(f"    ({district}, &[")
        for nid, (x, y, z), rot, wp, sec in npcs:
            lines.append(f"        ({nid}, [{x:.3f}, {y:.3f}, {z:.3f}], {rot:.3f}, {wp}, {sec}),")
        lines.append("    ]),")
    # Town NPCs hidden until a story episode is completed (tb_NPC visible = 0,
    # episode with state 2 = "completed" only). Until quests are implemented
    # the server reports these episodes as completed so the NPCs spawn.
    bits = quest_bits(episodes)
    unlock = {}
    for district, name in sorted(DISTRICT_MAPS.items()):
        for nid, *_ in parse_vbatch_npcs(load_vbatch(name)):
            row = npc_show_quests(npc_tab, nid)
            if row and row[0] == 0:
                for ep, st in row[1]:
                    if st == 2 and bits.get(ep):
                        unlock[ep] = (bits[ep], nid)
    lines += [
        "];",
        "",
        "/// Story episodes that unlock town NPCs (tb_NPC show condition, state 2):",
        "/// (episode id, tb_Quest_Episode Complete_Bit, npc id). Reported done in",
        "/// QUEST_COMPLETE_LIST until quest progress is implemented.",
        "pub const NPC_UNLOCK_EPISODES: &[(u32, u16, u32)] = &[",
    ]
    for ep, (bit, nid) in sorted(unlock.items()):
        lines.append(f"    ({ep}, {bit}, {nid}),")
    skills = class_skills(info, starts, skill_ids(skill_tab))
    lines += [
        "];",
        "",
        "/// Skills every character of a class knows from the start (tb_Character_Info",
        "/// Default_Skill_01..20, ids checked against tb_Skill). Sent in",
        "/// SKILL_LOAD_INFO 6/0x70; the dash (skill type 10, e.g. 12100011) is one.",
        "pub const CLASS_SKILLS: &[(u8, &[u32])] = &[",
    ]
    for cls, ids in sorted(skills.items()):
        lines.append(f"    ({cls}, &[{', '.join(map(str, ids))}]),")
    # Mazes (dungeons): tb_Maze_Info (client copy) + each maze's .vbatch start
    # box (id*100+1) and escape box, and the district exits a maze escape
    # lands on. Layout/logic: reference server ReqWorldEnter (checks
    # level, FP, quest, soul weapon) via WorldProcess.cpp.
    import maze_data
    mazes, exits, spawn_rows, check_rows, (sector_rows, portal_rows, jump_rows) = maze_data.maze_entries(DISTRICT_MAPS)
    lines += [
        "];",
        "",
        "/// Mazes with a start box and an escape box in the GB client data:",
        "/// (maze id, min level, FP, start jump id, [x, y, z], rotation degrees,",
        "/// escape district (0 = town start), escape exit box, spawn key = the",
        "/// maze id whose MAZE_SPAWNS / MAZE_CHECKS rows hold this map's boxes).",
        "/// Sorted by id.",
        "pub const MAZES: &[(u16, u8, u16, u32, [f32; 3], f32, u16, u32, u16)] = &[",
    ]
    for mid, lv, fp, jump, (x, y, z), rot, field, box, key in mazes:
        lines.append(f"    ({mid}, {lv}, {fp}, {jump}, [{x:.3f}, {y:.3f}, {z:.3f}], {rot:.3f}, {field}, {box}, {key}),")
    lines += [
        "];",
        "",
        "/// District arrival points (VStartEventBox / VPortalExitBox):",
        "/// (district, box id, [x, y, z], rotation degrees).",
        "pub const DISTRICT_EXITS: &[(u16, u32, [f32; 3], f32)] = &[",
    ]
    for district, bid, (x, y, z), rot in exits:
        lines.append(f"    ({district}, {bid}, [{x:.3f}, {y:.3f}, {z:.3f}], {rot:.3f}),")
    lines += [
        "];",
        "",
        "/// Maze monster spawn boxes (VMonsterSpawnBox with Monster slots):",
        "/// (maze, box id, spawns on map load, monster ids (tb_Monster), [x, y, z],",
        "/// rotation degrees, sector, waypoint, spawn step m_iStep). Sorted by maze, box.",
        "pub const MAZE_SPAWNS: &[(u16, u32, bool, &[u32], [f32; 3], f32, u32, u32, u8)] = &[",
    ]
    for mid, bid, imm, mons, (x, y, z), rot, sector, wp, step in spawn_rows:
        ids = ", ".join(str(m) for m in mons)
        lines.append(f"    ({mid}, {bid}, {'true' if imm else 'false'}, &[{ids}], [{x:.1f}, {y:.1f}, {z:.1f}], {rot:.1f}, {sector}, {wp}, {step}),")
    lines += [
        "];",
        "",
        "/// Maze check boxes (VCheckMonsterSpawnBox): (maze, check box id, spawn",
        "/// box ids it releases when the client sends EVENT_SPAWN_BOX_REQ 17/0x31).",
        "pub const MAZE_CHECKS: &[(u16, u32, &[u32])] = &[",
    ]
    for mid, cid, ids in check_rows:
        lines.append(f"    ({mid}, {cid}, &[{', '.join(str(i) for i in ids)}]),")
    lines += [
        "];",
        "",
        "/// Maze sectors (VSectorBox): (spawn key, sector id, [x0, y0, x1, y1],",
        "/// boss sector, exit portal opened when its monsters are dead, kill",
        "/// ratio % that completes spawn step 1..5 (m_iConditionKillRatio_nStep).",
        "pub const MAZE_SECTORS: &[(u16, u32, [f32; 4], bool, u32, [u8; 5])] = &[",
    ]
    for mid, sid, r, boss, exit_id, steps in sector_rows:
        st = ", ".join(str(min(max(x, 0), 255)) for x in steps)
        lines.append(f"    ({mid}, {sid}, [{r[0]:.1f}, {r[1]:.1f}, {r[2]:.1f}, {r[3]:.1f}], {'true' if boss else 'false'}, {exit_id}, [{st}]),")
    lines += [
        "];",
        "",
        "/// Maze portals (VPortalBox): (spawn key, portal id, [x0, y0, x1, y1],",
        "/// leads to a district, jump map, jump box).",
        "pub const MAZE_PORTALS: &[(u16, u32, [f32; 4], bool, u32, u32)] = &[",
    ]
    for mid, pid, r, field, jmap, jump in portal_rows:
        lines.append(f"    ({mid}, {pid}, [{r[0]:.1f}, {r[1]:.1f}, {r[2]:.1f}, {r[3]:.1f}], {'true' if field else 'false'}, {jmap}, {jump}),")
    lines += [
        "];",
        "",
        "/// Landing points inside a maze map (VPortalExitBox, VSectorStartBox,",
        "/// VStartEventBox): (spawn key, box id, [x, y, z], rotation degrees).",
        "pub const MAZE_JUMPS: &[(u16, u32, [f32; 3], f32)] = &[",
    ]
    for mid, bid, (x, y, z), rot in jump_rows:
        lines.append(f"    ({mid}, {bid}, [{x:.1f}, {y:.1f}, {z:.1f}], {rot:.1f}),")
    print(f"maze flow: {len(sector_rows)} sectors, {len(portal_rows)} portals, {len(jump_rows)} landing points")
    # Monster stats for every monster a maze spawns (reference server
    # tb_Monster: level, rank, HP; GB-only monsters fall back to the maze
    # level), EXP per monster level and rank (tb_Monster_EXP), EXP needed
    # per character level (GB client tb_Levelup_Point: u8 level, i32 need,
    # u8 skill point, u8).
    import server_tables
    jp_mons = {m["id"]: m for m in server_tables.table("tb_Monster.res", server_tables.monster)}
    used = sorted({m for r in spawn_rows for m in r[3]})
    lines += [
        "];",
        "",
        "/// Monsters used by maze spawns (tb_Monster): (id, level, rank, HP or",
        "/// 0 = derive, physical attack (0 = derive), first skill, run speed,",
        "/// sight, counts for a sector clear (XMaze::IsSectorClearConditionBox:",
        "/// Monster_Type 0/3/11 and Monster_ClearCondition_Type != 1)). Sorted by id.",
        "pub const MONSTERS: &[(u32, u8, u8, u32, u32, u32, u16, u32, bool)] = &[",
    ]
    import tbgen
    tbm = {r["ID"]: r for r in tbgen.load("TB_MONSTER", "tb_Monster.res")}
    missing = 0
    for mid in used:
        m = jp_mons.get(mid)
        t = tbm.get(mid)
        if m and t:
            sk = m["skills"][0] if m["skills"] else 0
            counts = t["Monster_Type"] in (0, 3, 11) and t["Monster_ClearCondition_Type"] != 1
            speed = t["Monster_Run_Speed"] or t["Monster_Walk_Speed"]
            lines.append(f"    ({mid}, {m['level']}, {m['rank']}, {max(m['hp'], 0)}, {max(m['patk'], 0)}, {sk}, {speed}, {t['Monster_Sight']}, {'true' if counts else 'false'}),")
        else:
            missing += 1
    print(f"monsters: {len(used) - missing} of {len(used)} spawned ids have stats, {missing} use derived stats (GB-only ids)")
    # Drops (tb_Drop / tb_Drop_Group, logic CDropProcess::MakeDropItems):
    # only items that exist in the GB client's tb_Item are kept.
    jp_drops = {r["id"]: r for r in server_tables.table("tb_Drop.res", server_tables.drop)}
    jp_groups = {r["id"]: r for r in server_tables.table("tb_Drop_Group.res", server_tables.drop_group)}
    drop_of = {mid: jp_mons[mid]["drop"] for mid in used if mid in jp_mons and jp_mons[mid]["drop"] in jp_drops}
    drop_rows, group_ids = [], set()
    for did in sorted(set(drop_of.values())):
        d = jp_drops[did]
        gch, gmin, gmax = d["gold"][0], d["gold"][1], d["gold"][2]
        groups = [(g, c) for g, c in d["groups"] if g in jp_groups and any(has_item(i) for i, *_ in jp_groups[g]["items"])]
        group_ids.update(g for g, _ in groups)
        drop_rows.append((did, gch, gmin, gmax, groups, d["sv"], d["ether"][:3], d["bp"]))
    lines += [
        "];",
        "",
        "/// Monster -> drop table id (tb_Monster Monster_Drop_ID).",
        "pub const MONSTER_DROPS: &[(u32, u32)] = &[",
    ]
    for mid, did in sorted(drop_of.items()):
        lines.append(f"    ({mid}, {did}),")
    lines += [
        "];",
        "",
        "/// tb_Drop: (id, gold chance /10000, gold min, gold max, [(group, chance",
        "/// /10000)], soul vapor / ether / BP as (chance /10000, min, max)).",
        "pub const DROPS: &[(u32, u16, u16, u16, &[(u32, u16)], [u16; 3], [u16; 3], [u16; 3])] = &[",
    ]
    for did, gch, gmin, gmax, groups, sv, eth, bp in drop_rows:
        gs = ", ".join(f"({g}, {c})" for g, c in groups)
        lines.append(f"    ({did}, {gch}, {gmin}, {gmax}, &[{gs}], [{sv[0]}, {sv[1]}, {sv[2]}], [{eth[0]}, {eth[1]}, {eth[2]}], [{bp[0]}, {bp[1]}, {bp[2]}]),")
    jp_maze = {r["id"]: r for r in server_tables.table("tb_Maze_Info.res", server_tables.maze_info)}
    rew = [(mid, jp_maze[mid]["exp"], jp_maze[mid]["money"]) for mid, *_ in mazes if mid in jp_maze]
    print(f"maze rewards: {len(rew)} of {len(mazes)} mazes have clear EXP/Zenny, the rest use a level-based fallback")
    lines += [
        "];",
        "",
        "/// Maze clear reward (tb_Maze_Info Maze_Exp, Maze_Money): (maze, EXP, Zenny).",
        "pub const MAZE_REWARDS: &[(u16, u32, u32)] = &[",
    ]
    for mid, e, mo in rew:
        lines.append(f"    ({mid}, {max(e, 0)}, {max(mo, 0)}),")
    lines += [
        "];",
        "",
        "/// tb_Drop_Group: (id, [(item, chance /10000, min, max)]); GB items only.",
        "pub const DROP_GROUPS: &[(u32, &[(u32, u16, u8, u8)])] = &[",
    ]
    for gid in sorted(group_ids):
        its = ", ".join(f"({i}, {c}, {a}, {b})" for i, c, a, b in jp_groups[gid]["items"] if has_item(i))
        lines.append(f"    ({gid}, &[{its}]),")
    mexp = server_tables.table("tb_Monster_EXP.res", server_tables.monster_exp)
    lines += [
        "];",
        "",
        "/// EXP for killing a monster: (level, [slave, normal, elite, named, boss,",
        "/// raid, summon]) (tb_Monster_EXP).",
        "pub const MONSTER_EXP: &[(u8, [u32; 7])] = &[",
    ]
    for r in mexp:
        lines.append(f"    ({r['level']}, [{', '.join(str(max(v, 0)) for v in r['exp'])}]),")
    # Combat tables from the reference server (struct order via tbgen):
    # skill damage ratio / range / cooldown for every skill a GB class or a
    # spawned monster uses, and the class status rows (HP first + growth).
    import tbgen
    jp_skills = {r["Skill_Index"]: r for r in tbgen.load("TB_SKILL", "tb_Skill.res")}
    want = set(skill_ids(skill_tab)) | {m["skills"][0] for mid in used if (m := jp_mons.get(mid)) and m["skills"]}
    sk_rows = sorted((i, jp_skills[i]) for i in want if i in jp_skills)
    print(f"skills: {len(sk_rows)} of {len(want)} class/monster skills found in tb_Skill (others use ratio 100, range 250)")
    lines += [
        "];",
        "",
        "/// Skill combat values (tb_Skill): (skill, damage ratio %, basic damage,",
        "/// range max, cooldown ms, cost stat (Skill_Cost_Attribute: 1 HP, 2 SG,",
        "/// 3 stamina), cost). Sorted by id.",
        "pub const SKILLS: &[(u32, u16, u32, u16, u32, u8, u16)] = &[",
    ]
    for i, r in sk_rows:
        lines.append(f"    ({i}, {int(max(r['Skill_Add_Damage_RAT'], 0))}, {int(max(r['Skill_Basic_Damage'] + r['Skill_Add_Damage_INT'], 0))}, {r['Skill_Range_Max']}, {r['CoolTime']}, {r['Skill_Cost_Attribute']}, {max(int(r['Skill_Cost']), 0)}),")
    status = [r for r in tbgen.load("TB_STATUS", "tb_Status.res") if 1001 <= r["ID"] <= 1020]
    lines += [
        "];",
        "",
        "/// Class status (tb_Status 1000 + class): (class, HP at level 1, HP per",
        "/// level, physical attack factor, physical defence factor).",
        "pub const CLASS_STATUS: &[(u8, u32, f32, f32, f32)] = &[",
    ]
    for r in status:
        lines.append(f"    ({r['ID'] - 1000}, {int(r['Con_HP_First_Value'])}, {r['Con_HP_Grow']:.2f}, {r['Con_PATK_Max']:.3f}, {r['Con_PDEF']:.3f}),")
    lv = maze_data.read("data11", "../bin/Table/tb_Levelup_Point.res", maze_data._pw())
    n = struct.unpack_from("<I", lv, 0)[0]
    assert 0 <= len(lv) - 4 - n * 8 < 64, "tb_Levelup_Point layout drift"
    lines += [
        "];",
        "",
        "/// EXP needed to go from a level to the next (GB tb_Levelup_Point).",
        "pub const LEVEL_EXP: &[(u8, u32)] = &[",
    ]
    for i in range(n):
        lvl, need = struct.unpack_from("<BI", lv, 4 + i * 8)
        lines.append(f"    ({lvl}, {need}),")
    lines.append("];")
    # Skill tree (GB tb_Skill rows: u32 id, u16, u32 group, u32 swap, u8 lv,
    # u8 use position, u8 class, u8 req level, u8 awakening, u8 req skill
    # point, u8 max level, u8 consume, u32 req prev skill; layout checked
    # against the TB_SKILL column order) and the skill points every level
    # gives (tb_Levelup_Point Give_Skill_Point; GB rows carry the same
    # u8 at +6).
    sk = maze_data.read("data11", "../bin/Table/tb_Skill.res", maze_data._pw())
    groups = skill_ids(sk)
    tree = {}
    for o in range(4, len(sk) - 30):
        sid, grp = struct.unpack_from("<I", sk, o)[0], struct.unpack_from("<I", sk, o + 6)[0]
        if grp in groups and 0 <= sid - grp < 40 and sid not in tree:
            lvl, _pos, cls, req_lv, _aw, req_sp, max_lv, _cons, prev = struct.unpack_from("<BBBBBBBBI", sk, o + 14)
            if 1 <= cls <= 20 and 1 <= lvl <= 30:
                tree[sid] = (grp, lvl, cls, req_lv, req_sp, max_lv, prev)
    lines += [
        "",
        "/// Learnable skills (GB tb_Skill): (skill, group, skill level, class,",
        "/// required character level, skill points per level, max level, required",
        "/// previous skill). Sorted by id.",
        "pub const SKILL_TREE: &[(u32, u32, u8, u8, u8, u8, u8, u32)] = &[",
    ]
    for sid, (grp, lvl, cls, req_lv, req_sp, max_lv, prev) in sorted(tree.items()):
        lines.append(f"    ({sid}, {grp}, {lvl}, {cls}, {req_lv}, {req_sp}, {max_lv}, {prev}),")
    lines += [
        "];",
        "",
        "/// Skill points granted on reaching a level (tb_Levelup_Point).",
        "pub const LEVEL_SKILL_POINTS: &[(u8, u8)] = &[",
    ]
    # GB rows carry no skill-point column (the u8 after the EXP is 3 on every
    # row); the table's Give_Skill_Point is used.
    for r in tbgen.load("TB_LEVELUP_POINT", "tb_Levelup_Point.res"):
        lines.append(f"    ({r['Level']}, {r['Give_Skill_Point']}),")
    lines += ["];", ""]
    print(f"skill tree: {len(tree)} rows")
    # Monster AI (Scripts/AI/*.lua via ai_scripts.py, tb_Monster
    # Monster_AI_ID) and all 10 skill slots per monster.
    import ai_scripts
    ais = ai_scripts.load()
    ai_names = sorted({(tbm[m]["Monster_AI_ID"] or "").lower() for m in used if m in tbm} & set(ais))
    ai_index = {n: i for i, n in enumerate(ai_names)}
    lines += [
        "/// Monster AI (Scripts/AI): (check ms, select ms lo/hi, attack ms",
        "/// lo/hi, battle-move keep distance lo/hi, skill groups (slot lists by",
        "/// group), picks (target group 255 = idle action, ANDed conditions",
        "/// (var, op, value)), slot conditions (group, slot, conditions)). Vars:",
        "/// 0 random /10000, 1 HP %, 2 target distance, 3 spawned monsters,",
        "/// 4 time since spawn ms, 5 attacked, 9 unknown (false).",
        "pub const AIS: &[AiDef] = &[",
    ]

    def conds(cs):
        return "&[" + ", ".join(f"({v}, {o}, {int(x)})" for v, o, x in cs) + "]"

    for n in ai_names:
        a = ais[n]
        top = max(a.groups) if a.groups else 0
        groups = "&[" + ", ".join("&[" + ", ".join(str(s) for s in a.groups.get(g, [])) + "]" for g in range(top + 1)) + "]"
        picks = "&[" + ", ".join(f"({t}, {conds(c)})" for t, c in a.picks) + "]"
        slots = "&[" + ", ".join(f"({g}, {s}, {conds(c)})" for g, s, c in a.slot_conds) + "]"
        lines.append(
            f"    AiDef {{ check_ms: {a.check_ms}, select_ms: ({a.select_ms[0]}, {a.select_ms[1]}), attack_ms: ({a.attack_ms[0]}, {a.attack_ms[1]}), "
            f"keep: ({a.battle_move[0]}, {a.battle_move[1]}), groups: {groups}, picks: {picks}, slots: {slots} }}, // {n}")
    lines += [
        "];",
        "",
        "/// Monster -> (AI index into AIS or u16::MAX, 10 skill slots, collision",
        "/// radius (tb_Monster Monster_CollisionRadius)).",
        "pub const MONSTER_AI: &[(u32, u16, [u32; 10], u16)] = &[",
    ]
    with_ai = 0
    for mid in used:
        t = tbm.get(mid)
        if not t:
            continue
        idx = ai_index.get((t["Monster_AI_ID"] or "").lower(), 65535)
        with_ai += idx != 65535
        sk = [t[f"Monster_Skill{k}_ID"] for k in range(1, 11)]
        rad = max(int(t["Monster_CollisionRadius"] or 0), 0)
        lines.append(f"    ({mid}, {idx}, [{', '.join(map(str, sk))}], {rad}),")
    lines += ["];", ""]
    print(f"monster AI: {len(ai_names)} scripts, {with_ai} of {len(used)} monsters scripted")
    # Navmesh per maze map (client World/Navmesh/<map>.hkt, Havok tagfile;
    # metres -> world units x100): walkable polygons the monsters stay on.
    import hkt
    pw = maze_data._pw()
    nav_lines, nav_maps = [], 0
    for key, mapname in sorted(maze_data.KEY_MAPS.items()):
        try:
            verts, faces = hkt.load_navmesh(maze_data.read("data09", f"World/Navmesh/{mapname}.hkt", pw))
        except Exception:
            continue
        if not faces:
            continue
        nav_maps += 1
        vs = ", ".join(f"[{x * 100:.1f}, {y * 100:.1f}]" for x, y, _ in verts)
        fs = ", ".join("&[" + ", ".join(map(str, f)) + "]" for f in faces)
        nav_lines.append(f"    ({key}, &[{vs}], &[{fs}]),")
    lines += [
        "/// Walkable navmesh per maze spawn key: (key, vertices x/y, faces as",
        "/// vertex index polygons).",
        "pub const NAVMESH: &[(u16, &[[f32; 2]], &[&[u16]])] = &[",
    ] + nav_lines + ["];", ""]
    print(f"navmesh: {nav_maps} of {len(maze_data.KEY_MAPS)} maze maps")
    hdr = max(i for i, l in enumerate(lines[:12]) if l.startswith("//!")) + 1
    lines.insert(hdr, "\n/// One monster AI script (see AIS).\n#[derive(Debug)]\npub struct AiDef {\n    pub check_ms: u32,\n    pub select_ms: (u32, u32),\n    pub attack_ms: (u32, u32),\n    pub keep: (u32, u32),\n    pub groups: &'static [&'static [u8]],\n    pub picks: &'static [(u8, &'static [(u8, u8, i32)])],\n    pub slots: &'static [(u8, u8, &'static [(u8, u8, i32)])],\n}\n")
    text = "\n".join(lines)
    if "--check" in sys.argv:
        same = open(OUT, encoding="utf-8").read() == text
        print("gamedata.rs up to date" if same else "gamedata.rs differs")
        sys.exit(0 if same else 1)
    open(OUT, "w", encoding="utf-8", newline="\n").write(text)
    print(f"wrote {OUT}: {len(starts)} classes, {len(cloth_rows)} costume sets, {len(products)} cash shop products")
    for cls, (w, cl) in sorted(starts.items()):
        print(f"  class {cls}: weapon {w} in tb_Item={has_item(w)}, cloth {cl}")


if __name__ == "__main__":
    main()
