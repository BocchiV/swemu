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
import re
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
# district id -> World/Table/<name>.vbatch (data09.v). The district id is the
# file's VStartEventBox m_ID / 100 (F021 Candus City starts at 1002101, ...).
# F001_TESTFIELD and F101_ETHEDLREDA (shares Arcadia's start box) are left out.
DISTRICT_MAPS = {
    10021: "F021_CANDUSCITY",
    10003: "F031_ROCCOTOWN",
    10031: "F041_GRACECITY",
    10041: "F051_RUINFORTRESS",
    10051: "F061_GRASSCOVERCAMP",
    10061: "F071_DIPLUCEHORIZON",
    10071: "F081_TOWEROFLORD",
    10081: "F091_ARCADIAREALM",
}


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


def gb_monster_rows(b, valid_skill):
    """GB client tb_Monster rows: id -> (model, AI script name, 10 skill
    slots, collision radius). Row = u32 id, wstr model, 111 B, wstr AI, 95 B,
    10 x u32 skills; u16 radius at AI end + 152. Checked against the table:
    skills equal on 2217 of 2314 common rows, AI name on 2297, radius on
    589/600 sampled. Rows whose slots are not real skill ids (bosses with an
    extra field) get no skills (caller falls back)."""
    out = {}
    for mid, mdl in gb_monster_models(b).items():
        p = b.find(mdl.encode("utf-16le"))
        q = p - 6
        while q >= 0 and struct.unpack_from("<I", b, q)[0] != mid:
            p = b.find(mdl.encode("utf-16le"), p + 1)
            if p < 0:
                break
            q = p - 6
        if p < 0:
            continue
        a = p + 2 * len(mdl) + 111
        an = struct.unpack_from("<H", b, a)[0]
        if not 0 < an < 80 or a + 2 + 2 * an + 95 + 160 > len(b):
            continue
        ai = b[a + 2:a + 2 + 2 * an].decode("utf-16le", "replace")
        e = a + 2 + 2 * an
        sk = list(struct.unpack_from("<10I", b, e + 95))
        if not all(x == 0 or valid_skill(x) for x in sk):
            sk = None
        rad = struct.unpack_from("<H", b, e + 152)[0]
        out[mid] = (mdl, ai, sk, rad if rad < 2000 else 0)
    return out


def gb_monster_models(b, origins=None):
    """GB client tb_Monster: monster id -> model name. Rows start u32 id,
    wstr model ("MOB_..."), u32 origin: the row's own id, or (523 spawned
    GB-only monsters) another monster's id whose data it is derived from.
    `origins` (dict) receives id -> origin."""
    out = {}
    ai = "Ai_".encode("utf-16le")
    for m in re.finditer(rb"M\x00O\x00B\x00_\x00", b):
        p = m.start()
        if p < 6 or b[p - 6:p] == ai:
            continue
        mid, n = struct.unpack_from("<IH", b, p - 6)
        end = p + 2 * n
        if not (0 < n < 100 and end + 4 <= len(b) and 1_000_000 <= mid < 1_000_000_000):
            continue
        org = struct.unpack_from("<I", b, end)[0]
        if not 1_000_000 <= org < 1_000_000_000:
            continue
        out[mid] = b[p:end].decode("utf-16le", "replace")
        if origins is not None:
            origins[mid] = org
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


def skill_frame_lines(sk, gb_models, mon_skills):
    """SKILL_FRAMES: attack frames (trigger id, ms) per skill from the client
    ActionData (action_data.py). Player skills use their class's PC_<letter>
    .adf (tb_Skill row class byte at +16), monster skills the model's .adf."""
    import action_data
    import maze_data
    pw = maze_data._pw()
    groups = skill_ids(sk)
    rows = {}
    for o in range(4, len(sk) - 30):
        sid, grp = struct.unpack_from("<I", sk, o)[0], struct.unpack_from("<I", sk, o + 6)[0]
        if grp in groups and 0 <= sid - grp < 40 and sid not in rows:
            rows[sid] = o
    order = sorted(rows.values())
    nxt = {order[i]: order[i + 1] for i in range(len(order) - 1)}
    adf_cache = {}
    reach_cache = {}
    cone_cache = {}
    region_cache = {}

    def frames(adf_name):
        if adf_name not in adf_cache:
            try:
                raw = maze_data.read("data04", f"Character/ActionData/{adf_name}.adf", pw)
                adf_cache[adf_name] = action_data.attack_frames(raw)
                reach_cache[adf_name] = action_data.attack_reach(raw)
                cone_cache[adf_name] = action_data.attack_cone(raw)
                region_cache[adf_name] = action_data.attack_regions(raw)
            except Exception:
                adf_cache[adf_name] = {}
                reach_cache[adf_name] = {}
                cone_cache[adf_name] = {}
                region_cache[adf_name] = {}
        return adf_cache[adf_name]

    reach = {}
    cone = {}
    regions = {}

    def action(sid):
        o = rows.get(sid)
        if o is not None:
            return action_data.skill_action(sk, o, nxt.get(o, o + 800))
        # Monster skill rows (u32 id, u16 1, group 0): the action name is the
        # first string within the row head (+173 like player rows).
        p = sk.find(struct.pack("<I", sid))
        while p != -1:
            act = action_data.skill_action(sk, p, p + 240)
            if act:
                return act
            p = sk.find(struct.pack("<I", sid), p + 1)
        return None

    out = {}
    no_action = no_anim = 0
    for sid, o in rows.items():
        cls = sk[o + 16]
        if not 1 <= cls <= 10:
            continue
        act = action(sid)
        if not act:
            no_action += 1
            continue
        adf_name = f"PC_{chr(ord('A') + cls - 1)}"
        fr = frames(adf_name).get(act)
        if fr:
            out[sid] = fr
            if act in reach_cache[adf_name]:
                reach[sid] = reach_cache[adf_name][act]
            if act in cone_cache[adf_name]:
                cone[sid] = cone_cache[adf_name][act]
            if act in region_cache[adf_name]:
                regions[sid] = region_cache[adf_name][act]
        else:
            no_anim += 1
    players = len(out)
    mon_hit = mon_miss = 0
    for mid, sks in sorted(mon_skills.items()):
        model = gb_models.get(mid)
        if not model:
            continue
        for sid in sks:
            if sid in out:
                continue
            act = action(sid)
            fr = frames(model).get(act) if act else None
            if fr:
                out[sid] = fr
                if act in reach_cache[model]:
                    reach[sid] = reach_cache[model][act]
                mon_hit += 1
            else:
                mon_miss += 1
    print(f"skill frames: {players} player skills ({no_action} rows without an action, {no_anim} actions "
          f"without attack events), {mon_hit} monster skills ({mon_miss} monster skill uses without frames)")
    lines = [
        "/// Attack frames per skill (client ActionData .adf AttackJudgmentTrigger):",
        "/// (skill, [(trigger id, ms after the skill starts)]). The server sends one",
        "/// ACTION_SKILL_BT per frame with that trigger id (CUser::ActionProcess).",
        "/// Sorted by skill.",
        "pub const SKILL_FRAMES: &[(u32, &[(u16, u16)])] = &[",
    ]
    for sid in sorted(out):
        fr = out[sid][:16]
        lines.append(f"    ({sid}, &[{', '.join(f'({t}, {min(ms, 65535)})' for t, ms in fr)}]),")
    print(f"skill reach: {len(reach)} of {len(out)} skills with frames have an attack area "
          f"({len(out) - len(reach)} without: no parseable tagATTACK_RANGE)")
    lines += [
        "];",
        "",
        "/// Hit reach per skill (cm from the attacker): farthest point of its attack",
        "/// events' tagATTACK_RANGE (forward offset of vCenterPos + fRadius or box",
        "/// size; CMySkillList::GetAttackArea / CheckSkillTarget). Sorted by skill.",
        "pub const SKILL_REACH: &[(u32, u16)] = &[",
    ]
    for sid in sorted(reach):
        lines.append(f"    ({sid}, {min(int(round(reach[sid])), 65535)}),")
    lines += [
        "];",
        "",
        "/// Player skill hit area: (skill, radius cm, angle deg) of the widest",
        "/// damage event (ActionData tagATTACK_RANGE fRadius / fAngle): a sector",
        "/// from the attacker along its facing; 360 = all around, 0 = box. Sorted.",
        "pub const SKILL_CONE: &[(u32, u16, u16)] = &[",
    ]
    for sid in sorted(cone):
        r, ang = cone[sid]
        lines.append(f"    ({sid}, {min(int(round(r)), 65535)}, {min(int(round(ang)), 360)}),")
    lines += [
        "];",
        "",
        "/// Player hit area per attack event: (skill, [(client event key, back cm,",
        "/// start cm, radius cm, angle deg, deals damage)]). IsAttackDecision:",
        "/// a sector whose apex sits `back` cm behind the attacker (vCenterPos.y;",
        "/// client local forward is -y), from start to radius along the facing,",
        "/// within +-angle/2; angle 0 = box (radius = box size). Sorted by skill.",
        "pub const SKILL_AREAS: &[(u32, &[(u16, i16, u16, u16, u16, bool)])] = &[",
    ]
    for sid in sorted(regions):
        ev = sorted(regions[sid].items())
        body = ", ".join(f"({k}, {max(-32768, min(32767, int(round(b))))}, {min(int(round(st)), 65535)}, "
                         f"{min(int(round(r)), 65535)}, {min(int(round(a)), 360)}, {'true' if d else 'false'})"
                         for k, (b, st, r, a, d) in ev if k < 65536)
        lines.append(f"    ({sid}, &[{body}]),")
    lines += ["];", ""]
    return lines


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
    # episode with state 2 = "completed" only). The server reports these
    # episodes as completed so the NPCs spawn. Rocco Town only (Janice, Eo,
    # Trisha): faking later story episodes for the other towns would make
    # NPCs offer episodes out of story order.
    bits = quest_bits(episodes)
    unlock = {}
    for district, name in sorted(DISTRICT_MAPS.items()):
        if district != 10003:
            continue
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
    import maze_spawn
    print(f"spawn boxes: {len(spawn_rows)} kept, {maze_spawn.SKIPPED[0]} dropped "
          f"(layer {'/'.join(sorted(maze_spawn.INACTIVE_LAYERS))}: no maze turns it on)")
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
        "/// Spawn boxes whose monster appears at a random point of the box",
        "/// (m_eCreationPositionType Random): (maze, box id, half size x, half",
        "/// size y). Sorted by maze, box.",
        "pub const MAZE_SPAWN_AREAS: &[(u16, u32, f32, f32)] = &[",
    ]
    for mid, bid, hx, hy in sorted(set(maze_data.AREA_ROWS)):
        lines.append(f"    ({mid}, {bid}, {hx:.1f}, {hy:.1f}),")
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
    import tbgen
    tbm = {r["ID"]: r for r in tbgen.load("TB_MONSTER", "tb_Monster.res")}
    # Monsters added after the 2020 server (e.g. the Tower of Lord mazes
    # 28xxx, 309011xx) have no row. They borrow AI, skills, speed and rank
    # from a monster with the same model (GB client tb_Monster model name,
    # "MOB_0282_WildStone" -> "MOB_0282_JH_WildStone"), and take the level
    # of the maze they spawn in; HP and attack are derived from that level.
    gb_mon_raw = maze_data.read("data11", "../bin/Table/tb_Monster.res", maze_data._pw())
    gb_origin = {}
    gb_models = gb_monster_models(gb_mon_raw, gb_origin)
    gb_skill_raw = maze_data.read("data11", "../bin/Table/tb_Skill.res", maze_data._pw())
    gb_rows = gb_monster_rows(gb_mon_raw, lambda x: 1_000_000_000 <= x < 2_000_000_000 and gb_skill_raw.find(struct.pack("<I", x)) >= 0)
    have_jp = {m for m in jp_mons if m in tbm}
    by_prefix = {}
    for m in have_jp:
        mdl = gb_models.get(m)
        if mdl:
            by_prefix.setdefault("_".join(mdl.split("_")[:2]), []).append(m)
    maze_lv = {}
    for mid_, lv, _fp, _j, _p, _r, _f, _b, key in mazes:
        maze_lv[key] = min(maze_lv.get(key, 255), lv) if lv else maze_lv.get(key, 0)
    gb_level = {}
    for r in spawn_rows:
        for m in r[3]:
            if maze_lv.get(r[0]):
                gb_level[m] = max(gb_level.get(m, 0), maze_lv[r[0]])
    template = {}
    for m in used:
        if m in have_jp:
            continue
        org = gb_origin.get(m)
        if org in have_jp and org != m:
            # The GB row names the monster it is derived from.
            template[m] = org
            continue
        mdl = gb_models.get(m, "")
        cands = by_prefix.get("_".join(mdl.split("_")[:2]), []) if mdl.startswith("MOB_") else []
        if cands:
            gb_ai = (gb_rows.get(m) or (None, ""))[1].lower()
            same_ai = [c for c in cands if (tbm[c]["Monster_AI_ID"] or "").lower() == gb_ai]
            exact = [c for c in cands if gb_models.get(c, "").replace("_JH", "") == mdl]
            template[m] = max(same_ai or exact or cands, key=lambda c: (jp_mons[c]["level"], -c))
    src = lambda m: template.get(m, m)
    print(f"monsters: {len(template)} GB-only spawned ids borrow a template by model, "
          f"{sum(1 for m in used if m not in have_jp and m not in template)} have none")
    lines += [
        "];",
        "",
        "/// Monsters used by maze spawns (tb_Monster): (id, level, rank, HP or",
        "/// 0 = derive, physical attack (0 = derive), first skill, run speed,",
        "/// sight, counts for a sector clear (XMaze::IsSectorClearConditionBox:",
        "/// Monster_Type 0/3/11 and Monster_ClearCondition_Type != 1)). Sorted by id.",
        "pub const MONSTERS: &[(u32, u8, u8, u32, u32, u32, u16, u32, bool)] = &[",
    ]
    missing = 0
    for mid in used:
        m = jp_mons.get(src(mid))
        t = tbm.get(src(mid))
        if m and t:
            sk = m["skills"][0] if m["skills"] else 0
            counts = t["Monster_Type"] in (0, 3, 11) and t["Monster_ClearCondition_Type"] != 1
            speed = t["Monster_Run_Speed"] or t["Monster_Walk_Speed"]
            if mid in template:
                # Template stats at the maze's level: HP / attack 0 = derive.
                # Attack skill: the monster's own first GB slot.
                level, hp, patk = gb_level.get(mid) or m["level"], 0, 0
                own = (gb_rows.get(mid) or (0, 0, None))[2]
                sk = next((x for x in own or [] if x), sk)
            else:
                level, hp, patk = m["level"], max(m["hp"], 0), max(m["patk"], 0)
            lines.append(f"    ({mid}, {level}, {m['rank']}, {hp}, {patk}, {sk}, {speed}, {t['Monster_Sight']}, {'true' if counts else 'false'}),")
        else:
            missing += 1
            if gb_level.get(mid):
                # No row and no template: the maze's level (the server's
                # defaults were level 1, one-hit kills) and the GB row's skill.
                own = (gb_rows.get(mid) or (0, 0, None))[2]
                sk0 = next((x for x in own or [] if x), 0)
                lines.append(f"    ({mid}, {gb_level[mid]}, 0, 0, 0, {sk0}, 0, 0, true),")
    print(f"monsters: {len(used) - missing} of {len(used)} spawned ids have stats, {missing} use derived stats (GB-only ids)")
    defence = {mid: tbm[src(mid)]["Monster_Defence_Type"] for mid in used
               if tbm.get(src(mid)) and tbm[src(mid)]["Monster_Defence_Type"]}
    print(f"monster defence: {len(defence)} of {len(used)} spawned ids resist hit reactions (type 1/2/3/5)")
    lines += [
        "];",
        "",
        "/// Monster_Defence_Type (tb_Monster, GB-only ids via their template) for",
        "/// monsters that do not flinch on every hit: 1/2 only on strong attacks,",
        "/// 3/5 never (CMover::IsDamageMotionDisplay). Missing = 0. Sorted by id.",
        "pub const MONSTER_DEFENCE: &[(u32, u8)] = &[",
    ]
    for mid in sorted(defence):
        lines.append(f"    ({mid}, {defence[mid]}),")
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
    want = set(skill_ids(skill_tab)) | {m["skills"][0] for mid in used if (m := jp_mons.get(src(mid))) and m["skills"]}
    want |= {x for mid in used if mid not in have_jp and (r := gb_rows.get(mid)) and r[2] for x in r[2] if x}
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
    lines += [
        "];",
        "",
        "/// Class base stats (tb_Status 1000 + class): (class, STR first, STR per",
        "/// level, VIT first, VIT per level) for SP_GET_FINAL_PDEF.",
        "pub const CLASS_STATS: &[(u8, f32, f32, f32, f32)] = &[",
    ]
    for r in status:
        lines.append(f"    ({r['ID'] - 1000}, {r['STR_First_Value']:.3f}, {r['STR_UP_Value']:.3f}, {r['VIT_First_Value']:.3f}, {r['VIT_UP_Value']:.3f}),")
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
    # Quests (GB tb_Quest_Episode / tb_Quest_Condition, layout in
    # quest_data.py), the monster quest groups hunt conditions count (
    # tb_Monster Quest_Group_1..5) and the story mazes MAZE_CLEAR_INFO
    # 17/0x64 reports (GB tb_Maze_Info: u16 Maze_Group at +3, u8
    # Maze_Episode_No at +37; CGocRecode::UpdateClearInfo keeps
    # episodes 1..5 only).
    import quest_data
    import gb_maze
    pw = maze_data._pw()
    q_eps = quest_data.episodes(maze_data.read("data11", "../bin/Table/tb_Quest_Episode.res", pw))
    q_conds = quest_data.conditions(maze_data.read("data11", "../bin/Table/tb_Quest_Condition.res", pw))
    lines += [
        "/// Quest episodes (GB tb_Quest_Episode): (episode, Complete_Bit, condition",
        "/// ids in slot order, reward EXP, Zenny, ether, BP, reward items (item, count)).",
        "/// Sorted by id.",
        "pub const QUEST_EPISODES: &[(u32, u16, &[u32], u32, u32, u32, u32, &[(u32, u32)])] = &[",
    ]
    for eid, e in sorted(q_eps.items()):
        conds = ", ".join(str(c) for c in e["conds"] if c in q_conds)
        rewards = ", ".join(f"({i}, {n})" for i, n in e["items"])
        lines.append(f"    ({eid}, {e['bit']}, &[{conds}], {e['exp']}, {e['zenny']}, {e['ether']}, {e['bp']}, &[{rewards}]),")
    lines += [
        "];",
        "",
        "/// Episodes that complete by themselves once every condition is done",
        "/// (tb_Quest_Episode Finish_Type 1: no finish NPC, the client never sends",
        "/// QUEST_EPISODE_COMPLETE). Sorted.",
        "pub const QUEST_AUTO_FINISH: &[u32] = &[",
    ]
    auto_finish = sorted(e for e, d in q_eps.items() if d["auto_finish"])
    lines += [f"    {e}," for e in auto_finish]
    lines += [
        "];",
        "",
        "/// Episodes accepted automatically when another one is completed",
        "/// (tb_Quest_Episode Auto_Start, event 7): (completed episode, episode).",
        "/// Sorted.",
        "pub const QUEST_AUTO_START: &[(u32, u32)] = &[",
    ]
    auto_start = sorted((d["auto_after"], e) for e, d in q_eps.items() if d["auto_after"] in q_eps)
    lines += [f"    ({p}, {e})," for p, e in auto_start]
    print(f"quests: {len(auto_finish)} auto-finish episodes, {len(auto_start)} auto-start links")
    lines += [
        "];",
        "",
        "/// Quest conditions (GB tb_Quest_Condition): (condition, type, target type,",
        "/// target id, count, mazes it counts in (empty = anywhere)). Types follow",
        "/// OpenWorker QuestConditionType (3 hunt, 10 clear), targets",
        "/// QuestConditionTarget (1 monster, 7 maze, 8 monster group, 9 sector). Sorted.",
        "pub const QUEST_CONDITIONS: &[(u32, u8, u8, u32, u8, &[u16])] = &[",
    ]
    for cid, (ct, tt, target, count, mz) in sorted(q_conds.items()):
        lines.append(f"    ({cid}, {ct}, {tt}, {target}, {count}, &[{', '.join(map(str, mz))}]),")
    hunt_groups = {c[2] for c in q_conds.values() if c[0] == 3 and c[1] == 8}
    mon_groups = {}
    for r in tbgen.load("TB_MONSTER", "tb_Monster.res"):
        gs = [r[f"Quest_Group_{i}"] for i in range(1, 6) if r[f"Quest_Group_{i}"] in hunt_groups]
        if gs:
            mon_groups[r["ID"]] = gs
    lines += [
        "];",
        "",
        "/// Monster -> quest groups a kill counts for (tb_Monster Quest_Group_1..5,",
        "/// only groups GB hunt conditions target). Sorted by monster id.",
        "pub const MONSTER_QUEST_GROUPS: &[(u32, &[u32])] = &[",
    ]
    for mid, gs in sorted(mon_groups.items()):
        lines.append(f"    ({mid}, &[{', '.join(map(str, gs))}]),")
    clear_rows = []
    for mid, (_name, fixed) in sorted(gb_maze.gb_maze_maps().items()):
        group, ep = struct.unpack_from("<H", fixed, 3)[0], fixed[37]
        if 1 <= ep <= 5 and group:
            clear_rows.append((mid, group, ep))
    lines += [
        "];",
        "",
        "/// Story mazes MAZE_CLEAR_INFO reports: (maze, Maze_Group, episode 1..5),",
        "/// from GB tb_Maze_Info. Sorted by maze id.",
        "pub const MAZE_CLEAR_GROUPS: &[(u16, u16, u8)] = &[",
    ]
    for mid, group, ep in clear_rows:
        lines.append(f"    ({mid}, {group}, {ep}),")
    lines += ["];", ""]
    print(f"quests: {len(q_eps)} episodes, {len(q_conds)} conditions, {len(mon_groups)} monsters with quest groups, "
          f"{len(clear_rows)} story mazes")
    # Monster AI (Scripts/AI/*.lua via ai_scripts.py, tb_Monster
    # Monster_AI_ID) and all 10 skill slots per monster.
    import ai_scripts
    ais = ai_scripts.load()
    def ai_of(m):
        # monsters: their script; GB-only: the GB row's own script name
        # (Scripts/AI has many of them), else the template's.
        if m in have_jp:
            return (tbm[m]["Monster_AI_ID"] or "").lower()
        own = (gb_rows.get(m) or (0, ""))[1].lower()
        if own in ais or src(m) not in tbm:
            return own
        return (tbm[src(m)]["Monster_AI_ID"] or "").lower()

    ai_names = sorted({ai_of(m) for m in used} & set(ais))
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
    with_ai = gb_own = 0
    mon_skills = {}
    for mid in used:
        t = tbm.get(src(mid))
        own = gb_rows.get(mid) if mid not in have_jp else None
        if not t and not own:
            continue
        idx = ai_index.get(ai_of(mid), 65535)
        with_ai += idx != 65535
        if own and own[2]:
            # GB-only monster: its own skill slots (slot order is what the AI
            # script's skill groups index) and radius from the GB row.
            sk, rad = own[2], own[3]
            gb_own += 1
        elif not t:
            # GB row without readable skill slots and no template.
            sk, rad = [0] * 10, own[3]
        else:
            sk = [t[f"Monster_Skill{k}_ID"] for k in range(1, 11)]
            rad = max(int(t["Monster_CollisionRadius"] or 0), 0)
        lines.append(f"    ({mid}, {idx}, [{', '.join(map(str, sk))}], {rad}),")
        mon_skills[mid] = [x for x in sk if x]
    print(f"monster AI: {gb_own} GB-only monsters use their own GB skill slots")
    lines += ["];", ""]
    lines += skill_frame_lines(gb_skill_raw, gb_models, mon_skills)
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
