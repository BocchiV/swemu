#!/usr/bin/env python
"""Run server replies through the 2.3.34.7 client's own payload READERS (Unicorn)
and check each reader consumes exactly the payload without setting its error flag.

A reader takes `pkt` (packet object from pktinit FUN_18005b5f0) and reads through
the cursor at pkt+0xb: u8* data (+0xb), u32 err (+0x13), u16 pos (+0x17),
u16 len (+0x1b) — offsets from FUN_18000e370 ([rcx+8] err, [rcx+0xc] pos,
[rcx+0x10] len with rcx = pkt+0xb). After the call:
  err (pkt+0x13) == 0      no out-of-bounds read / bad string length
  pos (pkt+0x17) == len    every byte consumed, nothing missing or left over

Used by e2e_client.py; `python reader_check.py` runs self-tests.
"""
import struct
from emu_wire import Emu, DLL

# (main, sub): (reader address, output buffer size, name)
READERS = {
    (2, 0x02): (0x180015130, 0x1000, "LOGIN_RESULT"),
    (2, 0x04): (0x180034cc0, 0x40, "SERVER_LIST"),
    (2, 0x14): (0x1800312c0, 0x80, "ENTER_SERVER_RES"),
    (3, 0x12): (0x180016d40, 0x200, "CHARACTER_LIST_RES"),
    (3, 0x57): (0x180014010, 0x40, "CHARACTER_CHECK_NAME"),
    # 3/0x0D and 3/0x03 are read inline by their handlers (FUN_180da04d0,
    # FUN_180d9f7b0): one u32 each; FUN_18004d4f0 is the same u32 read.
    (3, 0x0D): (0x18004d4f0, 0x10, "REPRESENTATIVE_CHECK"),
    (3, 0x03): (0x18004d4f0, 0x10, "DELETE_CHARACTER_RES"),
    (3, 0x17): (0x180054a50, 0x10, "SECOND_PASSWORD"),
    # SELECT_CHARACTER_RES: FUN_18002cb70 (map info FUN_18002d270 + party info).
    (3, 0x14): (0x18002cb70, 0x300, "SELECT_CHARACTER_RES"),
    # ENTER_GAMESERVER_RES has no single reader: handler FUN_180da0f70 reads
    # u32 (FUN_18000e5b0), u8 (FUN_180010900), position (FUN_180012610), u8, u32.
    (3, 0x22): ([("cur", 0x18000e5b0), ("cur", 0x180010900), ("pkt", 0x180012610),
                 ("cur", 0x180010900), ("cur", 0x18000e5b0)], 0x40, "ENTER_GAMESERVER_RES"),
    # CHARACTER_INFO_RES: handler FUN_180da1170 = reader FUN_180013560 into the
    # player struct, then three u8 (FUN_180010900) read inline.
    (3, 0x32): ([("pkt", 0x180013560), ("cur", 0x180010900), ("cur", 0x180010900),
                 ("cur", 0x180010900)], 0x1000, "CHARACTER_INFO_RES"),
    # SKILL_LOAD_INFO: handler FUN_180dd5170 reads everything with FUN_18001aa90;
    # its last call applies the pending scene (LoadingScene).
    (6, 0x70): (0x18001aa90, 0x4000, "SKILL_LOAD_INFO"),
    (6, 0x71): ([("pkt", 0x18001a780)], 0x40, "SKILL_LEARN"),
    (6, 0x72): ([("pkt", 0x18001aa90), ("cur", 0x180010900)], 0x4000, "SKILL_RESET"),
    (6, 0x75): ([("pkt", 0x18001aa00)], 0x40, "SKILL_UPDATE_DECK"),
    (6, 0x76): ([("cur", 0x18000e580)], 0x40, "SKILL_ADD_DECK_SLOT"),
    (6, 0x77): ([("pkt", 0x18004d370)], 0x40, "SKILL_DIVERGENCE_LEARN"),
    (6, 0x79): ([("pkt", 0x18001b3f0)], 0x40, "SKILL_DECK_BONUS"),
    (6, 0x07): ([("cur", 0x18000e580)], 0x40, "SKILL_PASSIVE"),
    # QUEST_COMPLETE_LIST: FUN_18000e290(cursor, buf, 0x100) = 256 raw bytes.
    (0x15, 0x01): ([("cur256", 0x18000e290)], 0x200, "QUEST_COMPLETE_LIST"),
    # QUEST_LIST: FUN_180038d70 + FUN_180038f00 (empty = 4 bytes).
    (0x15, 0x02): ([("pkt", 0x180038d70), ("pkt", 0x180038f00)], 0x2000, "QUEST_LIST"),
    # SYSTEM_PING reply: PlayScene handler FUN_180decc20, one u64 (FUN_18000e5e0).
    (1, 0x06): ([("cur", 0x18000e5e0)], 0x10, "SYSTEM_PING"),
    # GESTURE_SLOT_LOAD: PlayScene handler FUN_180e2bd50 runs four readers in order.
    (0x23, 0x02): ([("pkt", 0x1800207e0), ("pkt", 0x180024940), ("pkt", 0x18001c100),
                    ("pkt", 0x180038a90)], 0x800, "GESTURE_SLOT_LOAD"),
    # SHOP_CASH_LOAD: handler FUN_180e0b0c0 reads u8 inline, then FUN_18000eb70.
    (9, 0x20): ([("cur", 0x180010900), ("pkt", 0x18000eb70)], 0x800, "SHOP_CASH_LOAD"),
    (9, 0x28): (0x18000f290, 0x800, "SHOP_BANNER_LOAD"),
    # SHOP_CASH_BUY reply: handler FUN_180e0ba90 = FUN_180021a20 then FUN_1800224a0.
    (9, 0x21): ([("pkt", 0x180021a20), ("pkt", 0x1800224a0)], 0x800, "SHOP_CASH_BUY"),
    # ITEM_UPDATE_CASH: handler FUN_180ddfb00 reads three u32 (FUN_18000e5b0).
    (8, 0x33): ([("cur", 0x18000e5b0), ("cur", 0x18000e5b0), ("cur", 0x18000e5b0)], 0x40, "ITEM_UPDATE_CASH"),
    # GESTURE_SHOW: handler FUN_180e2bb90 = u32 actor, then FUN_18001b1b0 (7 x u32).
    (0x23, 0x01): ([("cur", 0x18000e5b0), ("pkt", 0x18001b1b0)], 0x800, "GESTURE_SHOW"),
    # Inventory: ITEM_OPEN_SLOT_INFO (handler FUN_180dfa290) and ITEM_INVEN_INFO (FUN_180df3ac0).
    (8, 0x0E): (0x18001e600, 0x800, "ITEM_OPEN_SLOT_INFO"),
    (8, 0x01): (0x18001e840, 0x4000, "ITEM_INVEN_INFO"),
    (8, 0x15): (0x18001e840, 0x4000, "ITEM_UPDATE"),
    # SHOP_BUY reply (handler FUN_180e09070): item list FUN_18001e840, u64
    # spent (FUN_18000e5e0), u8 currency (FUN_180010900), u32 (FUN_18000e5b0).
    (9, 0x01): ([("pkt", 0x18001e840), ("cur", 0x18000e5e0), ("cur", 0x180010900),
                 ("cur", 0x18000e5b0)], 0x4000, "SHOP_BUY"),
    # SHOP_SELL reply (handler FUN_180e09ba0): item list only.
    (9, 0x02): (0x18001e840, 0x4000, "SHOP_SELL"),
    # SHOP_REPURCHASER_LIST reply (handler FUN_180e0a220): FUN_18001faa0 u8 n x entry.
    (9, 0x03): (0x18001faa0, 0x4000, "SHOP_REPURCHASER_LIST"),
    # ITEM_UPDATE_INVEN_MONEY (handler FUN_180dde8c0): FUN_180015c10 u64, u32, u8.
    (8, 0x20): (0x180015c10, 0x20, "ITEM_UPDATE_INVEN_MONEY"),
    # SHOP_REPURCHASER reply (handler FUN_180e0a480): item list FUN_18001e840.
    (9, 0x04): (0x18001e840, 0x4000, "SHOP_REPURCHASER"),
    # ITEM_COMBINE reply (handler FUN_180df6930): FUN_18001f050.
    (8, 0x03): (0x18001f050, 0x800, "ITEM_COMBINE"),
    # ITEM_DIVIDE reply (handler FUN_180df6f70): FUN_18001ed80.
    (8, 0x04): (0x18001ed80, 0x800, "ITEM_DIVIDE"),
    # ITEM_BREAK reply (handler FUN_180df75f0): inline u8 storage, u16 slot, u64 serial.
    (8, 0x05): ([("cur", 0x180010900), ("cur", 0x18000e580), ("cur", 0x18000e5e0)], 0x40, "ITEM_BREAK"),
    # ITEM_LINE_UP reply (handler FUN_180dfd7c0): FUN_1800204b0.
    (8, 0x25): (0x1800204b0, 0x4000, "ITEM_LINE_UP"),
    # Repair at an NPC: FUN_180e11ae0 = FUN_18001e790 + u64; equip/all =
    # FUN_180e12520 / FUN_180e12b10 = item list + u64.
    (0x18, 0x09): ([("pkt", 0x18001e790), ("cur", 0x18000e5e0)], 0x400, "ITEM_REPAIR_NPC"),
    (0x18, 0x10): ([("pkt", 0x18001e840), ("cur", 0x18000e5e0)], 0x4000, "ITEM_REPAIR_EQUIP"),
    (0x18, 0x11): ([("pkt", 0x18001e840), ("cur", 0x18000e5e0)], 0x4000, "ITEM_REPAIR_ALL"),
    # WORLD_ENTER_RES 4/0x02 (handler FUN_180dcd530): FUN_18002cb70 + 2 x u8.
    (4, 0x02): ([("pkt", 0x18002cb70), ("cur", 0x180010900), ("cur", 0x180010900)], 0x300, "WORLD_ENTER_RES"),
    # WORLD_OTHER_INFOS_MONSTER 4/0x23 (handler FUN_180dedaf0).
    (4, 0x23): (lambda p: [("cur", 0x18000e580)] + [("pkt", 0x180056d80)] * int.from_bytes(p[0:2], "little"),
                0x400, "WORLD_OTHER_INFOS_MONSTER"),
    # ACTIVE_SKILL_RES 6/0x09 (handler FUN_180dcf530).
    (6, 0x09): ([("cur", 0x18000e580), ("cur", 0x18000e5b0), ("cur", 0x180010900), ("pkt", 0x180011da0)],
                0x100, "ACTIVE_SKILL_RES"),
    # ACTION_SKILL_BT 6/0x13 (handler FUN_180dd0770).
    (6, 0x13): ([("pkt", 0x180019c50), ("pkt", 0x180019910)], 0x2000, "ACTION_SKILL_BT"),
    # DROP_INFOS 20/0x01 (handler FUN_180e10b90) / DROP_PICK_UP 20/0x02.
    (0x14, 0x01): ([("pkt", 0x18001f680)], 0x2000, "DROP_INFOS"),
    (0x14, 0x02): ([("pkt", 0x180027220)], 0x40, "DROP_PICK_UP"),
    # MONSTER_DIE 0x17/0x11 (handler FUN_180deb180): u32, u16, u8.
    (0x17, 0x11): ([("cur", 0x18000e5b0), ("cur", 0x18000e580), ("cur", 0x180010900)], 0x40, "MONSTER_DIE"),
    # CHARACTER_EXP 3/0x37 (handler FUN_180ddbd60).
    (3, 0x37): ([("pkt", 0x1800252c0)], 0x40, "CHARACTER_EXP"),
    # CHARACTER_LEVEL 3/0x36 (handler FUN_180ddb400): u32, u32, u8.
    (3, 0x36): ([("pkt", 0x18002d680)], 0x40, "CHARACTER_LEVEL"),
    # CHARACTER_GOBACK_LOBBY 3/0x60 (handler FUN_180e2afc0).
    (3, 0x60): ([("pkt", 0x180034b40)], 0x300, "CHARACTER_GOBACK_LOBBY"),
    # CHARACTER_QUICK_CHANGE_LIST 3/0x5B (handler FUN_180e48e10).
    (3, 0x5B): ([("pkt", 0x18002fea0)], 0x200, "CHARACTER_QUICK_CHANGE_LIST"),
    # Category 1 (maze play): monster AI, player HP / death / revive, warps,
    # sector flow, maze reward, BP / ether.
    (5, 0x02): ([("pkt", 0x180010b60)], 0x100, "MOVE_BT"),
    (5, 0x04): ([("pkt", 0x180010e90)], 0x100, "MOVE_STOP_BT"),
    (6, 0x10): ([("pkt", 0x1800197b0)], 0x100, "ACTIVE_SKILL_BT"),
    (6, 0x48): ([("cur", 0x18000e5b0)] + [("cur", 0x18000e610)] * 4, 0x40, "SKILL_SYNC_POSITION"),
    (0x17, 0x22): ([("cur", 0x18000e5b0), ("cur", 0x18000e5b0)], 0x40, "MONSTER_TARGET_CHANGE_BT"),
    (3, 0x34): ([("pkt", 0x1800138d0)], 0x400, "CHARACTER_UPDATE_STAT_LIST"),
    (0x17, 0x12): ([("pkt", 0x1800138d0)], 0x400, "MONSTER_UPDATE_STAT"),
    (3, 0x41): ([("cur", 0x18000e5b0)] * 3, 0x40, "CHARACTER_DIE"),
    (3, 0x44): ([("pkt", 0x180015000)], 0x100, "CHARACTER_REVIVE_BT"),
    (4, 0x08): ([("cur", 0x18000e5b0), ("pkt", 0x18002c830)], 0x100, "WARP_RES"),
    (8, 0x31): ([("pkt", 0x180015880)], 0x100, "ITEM_UPDATE_BP"),
    (8, 0x32): ([("cur", 0x18000e5e0)], 0x40, "ITEM_UPDATE_ETHER"),
    (0x11, 0x52): ([("cur", 0x18000e5b0), ("cur", 0x180010900)], 0x40, "SECTOR_CLEAR"),
    (0x11, 0x53): (lambda p: [("cur", 0x18000e5b0)] * (2 + int.from_bytes(p[0:4], "little")), 0x400, "SECTOR_INFOS"),
    (0x11, 0x54): (lambda p: [("cur", 0x180010900)] + [("cur", 0x18000e5b0)] * (1 + int.from_bytes(p[1:5], "little")),
                   0x400, "GATE_INFOS"),
    (0x11, 0x68): (lambda p: [("cur", 0x18000e5b0)] * (1 + int.from_bytes(p[0:4], "little")), 0x400, "DIE_MONSTERS"),
    (0x11, 0x70): ([("cur", 0x180010900)], 0x40, "USE_REVIVE_COUNT"),
    (0x11, 0x55): (lambda p: [("cur", 0x18000e5b0)] * (2 + int.from_bytes(p[0:4], "little") + int.from_bytes(p[4:8], "little")),
                   0x400, "POTAL_INFOS"),
    (0x11, 0x75): ([("pkt", 0x18001fd00)], 0x400, "MAZE_REWARD_INFO"),
    # MAZE_LUA_FUNCTION_RES 17/0x7F (handler FUN_180e05550): u32 box.
    (0x11, 0x7F): ([("cur", 0x18000e5b0)], 0x40, "MAZE_LUA_FUNCTION_RES"),
    # Panel lists answered empty (proto::empty_list_reply).
    (3, 0x23): (0x180013bc0, 0x400, "CHARACTER_LOAD_TITLE"),
    (3, 0x7B): (0x1800269f0, 0x400, "CHARACTER_CASH_MILEAGE"),
    (0x20, 0x10): ([("cur", 0x18000e580), ("cur", 0x18000e580)], 0x40, "POST_INFO"),
    (0x20, 0x02): (0x18003d100, 0x4000, "POST_RECV_LIST"),
    (0x20, 0x14): (0x18003db20, 0x4000, "POST_ACCOUNT_LIST"),
    (0x19, 0x41): (0x18003c490, 0x400, "FRIEND_RECRUIT_LIST"),
    (0x19, 0x44): (0x180049c30, 0x400, "FRIEND_RECRUIT_INFO"),
    (0x19, 0x51): (0x18003cbd0, 0x400, "FRIEND_RECOMMAND_LIST"),
    (0x12, 0x36): (0x180035cd0, 0x400, "PARTY_RECRUIT_LIST"),
    (0x12, 0x37): (0x180035cd0, 0x400, "PARTY_RECRUIT_MY_APPLY_LIST"),
    (0x2B, 0x03): (0x1800494d0, 0x400, "EXCHANGE_INTEREST_LIST"),
    (0x2B, 0x08): (0x18004d520, 0x400, "EXCHANGE_MY_LIST"),
    (0x2B, 0x10): (0x18004da80, 0x400, "EXCHANGE_MY_INFO"),
    (0x18, 0x58): (0x1800269f0, 0x400, "ITEM_OVERCLOCK_BONUS_RATE_LIST"),
    (0x19, 0x01): (0x18003bce0, 0x400, "FRIEND_LOAD"),
    (0x19, 0x02): (0x18003bea0, 0x400, "FRIEND_LOAD_BLOCKLIST"),
    (0x2C, 0x01): (0x180050f90, 0x400, "RANKING_TIME_ATTACK_LIST"),
    (0x2C, 0x02): (0x1800512b0, 0x400, "RANKING_PVP_LIST"),
    (0x08, 0x10): (0x18001e840, 0x400, "ITEM_BANK_INFO"),
    (0x2A, 0x50): (0x180056600, 0x400, "EVENT_50"),
    # SPECIAL_OPTION_LIST (handler FUN_180e2ead0): u32 actor, u8 n x {u16, f32}.
    (3, 0x47): (lambda p: [("cur", 0x18000e5b0), ("cur", 0x180010900)]
                + [("cur", 0x18000e580), ("cur", 0x18000e610)] * (p[4] if len(p) > 4 else 0),
                0x40, "SPECIAL_OPTION_LIST"),
    # ITEM_MOVE reply: handler FUN_180df52d0, reader FUN_18001ef50.
    (8, 0x02): (0x18001ef50, 0x4000, "ITEM_MOVE"),
    # WORLD_OTHER_INFOS_NPC: handler FUN_180deea80 = i16 n, n x FUN_180056ab0.
    (4, 0x22): (lambda p: [("cur", 0x18000e580)] + [("pkt", 0x180056ab0)] * int.from_bytes(p[0:2], "little"),
                0x400, "WORLD_OTHER_INFOS_NPC"),
    # CHAT_NORMAL 7/0x01: handler FUN_180df0c30 reads inline u32 actor, u16,
    # u32, wstr message (FUN_18000e4b0, max 0xFF units), u8 n item links
    # (<= 3), then n x FUN_180016130 (the step list follows the payload's n).
    (7, 0x01): (lambda p: [("cur", 0x18000e5b0), ("cur", 0x18000e580), ("cur", 0x18000e5b0),
                           ("wstr", 0x18000e4b0), ("cur", 0x180010900)]
                + [("pkt", 0x180016130)] * min(3, p[12 + int.from_bytes(p[10:12], "little")] if len(p) > 12 else 0),
                0x2000, "CHAT_NORMAL"),
    # UPDATE_ORIGIN_STAT: handler FUN_180ddac80 = u32 actor, u8 n, then inline
    # n x {f32 value (FUN_18000e610), u16 stat index (FUN_18000e580)}.
    (3, 0x51): (lambda p: [("cur", 0x18000e5b0), ("cur", 0x180010900)]
                + [("cur", 0x18000e610), ("cur", 0x18000e580)] * (p[4] if len(p) > 4 else 0),
                0x40, "UPDATE_ORIGIN_STAT"),
    # ITEM_USE reply: handler FUN_180dfbdb0 = u32, FUN_180020fb0, u64 (FUN_18000e5e0).
    (8, 0x11): ([("cur", 0x18000e5b0), ("pkt", 0x180020fb0), ("cur", 0x18000e5e0)], 0x4000, "ITEM_USE"),
}


def run_reader(emu, main, sub, payload):
    addr, out_size, name = READERS[(main, sub)]
    if callable(addr):  # step list depends on the payload (inline counted loops)
        addr = addr(payload)
    emu.reset_heap()
    data = emu.alloc(payload if payload else b"\0")
    pkt = bytearray(0x40)
    struct.pack_into("<QIH", pkt, 0x0B, data, 0, 0)
    struct.pack_into("<H", pkt, 0x1B, len(payload))
    p = emu.alloc(pkt)
    out = emu.alloc(out_size)
    if isinstance(addr, list):
        # Inline handler: replay its reads in order. "cur" helpers take the
        # cursor (pkt+0xb), "pkt" readers take (pkt, out).
        for kind, fn in addr:
            if kind == "cur":
                emu.call(fn, p + 0x0B)
            elif kind == "wstr":  # FUN_18000e4b0(cursor, buf, max units, &len)
                emu.call(fn, p + 0x0B, out, 0xFF, out + out_size - 8)
            elif kind == "cur256":  # FUN_18000e290(cursor, buf, 0x100)
                emu.call(fn, p + 0x0B, out, 0x100)
            else:
                emu.call(fn, p, out)
    else:
        emu.call(addr, p, out)
    err, pos = struct.unpack("<IH", emu.read(p + 0x13, 6))
    ln = struct.unpack("<H", emu.read(p + 0x1B, 2))[0]
    return name, err, pos, ln


def check_payloads(pairs, emu=None):
    """pairs: [(main, sub, payload)] -> names of replies the client would misread."""
    emu = emu or Emu(DLL)
    bad = []
    for main, sub, payload in pairs:
        if (main, sub) not in READERS:
            continue
        name, err, pos, ln = run_reader(emu, main, sub, payload)
        ok = err == 0 and pos == ln
        print(f"[{'ok' if ok else 'FAIL'}] client reader {name} ({main}/0x{sub:02X}): consumed {pos}/{ln} bytes, err={err}")
        if not ok:
            bad.append(name)
    return bad


if __name__ == "__main__":
    # Self-test: the checker must catch a short and an over-long payload.
    emu = Emu(DLL)
    good_esr = struct.pack("<BIIH", 0, 1001, 0, 0)
    assert run_reader(emu, 2, 0x14, good_esr)[1:] == (0, len(good_esr), len(good_esr))
    _, err, pos, ln = run_reader(emu, 2, 0x14, good_esr[:-1])
    assert err != 0 or pos != ln, "short payload must be detected"
    _, err, pos, ln = run_reader(emu, 2, 0x14, good_esr + b"\0")
    assert pos != ln, "extra bytes must be detected"
    print("reader_check self-test OK")
