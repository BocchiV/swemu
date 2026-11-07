"""GB 2.3.34.7 quest tables from data11.v, for gen_gamedata.py.

tb_Quest_Episode row: 0x143 fixed bytes, wstr, 0xbb fixed bytes, wstr
(u16 length + UTF-16LE). Fixed part A: u32 id, u16 Complete_Bit (+4).
Fixed part B (after the first string): u8 reward type, u32 EXP (+1),
u32 Zenny (+5), u32 ether (+9), u32 BP (+0xd), u8 item type (+0x1d),
5 x u32 reward item (+0x1e) / 5 x u32 count (+0x32), u8 select type
(+0x46), 5 x u32 select item (+0x47) / 5 x u32 count (+0x5b), 10 x u32
condition id (+0x91).

tb_Quest_Condition row: 0xac fixed bytes, wstr. u32 id, u8 condition type
(+9, OpenWorker QuestConditionType: 3 = hunt), u8 target type (+0x12,
QuestConditionTarget: 1 monster, 7 maze, 8 monster group), u32 target id
(+0x13), u32 field (+0x1b), u32 maze group (+0x1f), 12 x u32 maze id
(+0x23, 0 = unused), u8 count (+0x8b).

Offsets were found by aligning rows with the 2020 tables (same ids, TB_QUEST_*
column order); the rows must end exactly at the MD5 trailer, so parsing fails
loudly if the layout drifts.
"""
import struct

EPISODE_A = 0x143
EPISODE_B = 0xBB
CONDITION_FIXED = 0xAC


def _wstr_len(b, o):
    return 2 + 2 * struct.unpack_from("<H", b, o)[0]


def _check_end(b, o, name):
    """Every .res ends with u16 32 + the table's MD5 as 32 ASCII hex digits."""
    tail = b[o:]
    ok = len(tail) == 34 and struct.unpack_from("<H", tail, 0)[0] == 32 and all(c in b"0123456789abcdef" for c in tail[2:])
    assert ok, f"{name} layout drift: {len(tail)} bytes after the last row"


def episodes(b):
    """id -> dict(bit, conds, exp, zenny, ether, bp, items, select)."""
    n = struct.unpack_from("<I", b, 0)[0]
    o, out = 4, {}
    for _ in range(n):
        a = b[o:o + EPISODE_A]
        o += EPISODE_A
        o += _wstr_len(b, o)
        c = b[o:o + EPISODE_B]
        o += EPISODE_B
        o += _wstr_len(b, o)
        eid, bit = struct.unpack_from("<IH", a, 0)
        assert 100_000 <= eid < 10_000_000 and bit < 2048, (eid, bit)
        exp, zenny, ether, bp = struct.unpack_from("<4I", c, 1)
        pairs = lambda at, cnt: [(i, k) for i, k in zip(struct.unpack_from("<5I", c, at), struct.unpack_from("<5I", c, cnt))
                                 if i and k]
        out[eid] = {
            "bit": bit,
            "conds": [x for x in struct.unpack_from("<10I", c, 0x91) if x],
            "exp": exp, "zenny": zenny, "ether": ether, "bp": bp,
            "items": pairs(0x1E, 0x32),
            "select": pairs(0x47, 0x5B),
            # Part A +0xba Auto_Start, +0xbb Auto_Start_Event (7 = after an
            # episode is completed), +0xbc u32 that episode; +0xc5 Finish_Type
            # (1 = completes by itself once its conditions are done: no finish
            # NPC, e.g. 800010 "2nd Generation SoulWorker"). Offsets checked on
            # the tutorial chain (100009 starts after 100007, ...).
            "auto_after": struct.unpack_from("<I", a, 0xBC)[0] if a[0xBA] == 1 and a[0xBB] == 7 else 0,
            "auto_finish": a[0xC5] == 1,
        }
    _check_end(b, o, "tb_Quest_Episode")
    assert len(out) == n
    return out


def conditions(b):
    """id -> (condition type, target type, target id, count, maze ids)."""
    n = struct.unpack_from("<I", b, 0)[0]
    o, out = 4, {}
    for _ in range(n):
        r = b[o:o + CONDITION_FIXED]
        o += CONDITION_FIXED
        o += _wstr_len(b, o)
        cid = struct.unpack_from("<I", r, 0)[0]
        mazes = [m for m in struct.unpack_from("<12I", r, 0x23) if m]
        assert all(m <= 0xFFFF for m in mazes), (cid, mazes)
        out[cid] = (r[9], r[0x12], struct.unpack_from("<I", r, 0x13)[0], r[0x8B], mazes)
    _check_end(b, o, "tb_Quest_Condition")
    assert len(out) == n
    return out
