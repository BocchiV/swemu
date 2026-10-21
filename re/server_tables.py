"""Read server-only tables from the reference server .

Layouts follow TB_*.h structs , with the
.res string fields as u16 length + UTF-16LE. A layout is accepted only when
the whole file parses with < 64 bytes left (the checksum trailer).

  python server_tables.py            # parse + print a summary of each table
"""
import os
import struct
import sys

RES = os.path.join(os.environ.get("SW_SERVER_DATA", "server-data"), "res", "")


class Cur:
    def __init__(self, b, o=0):
        self.b, self.o = b, o

    def f(self, fmt):
        v = struct.unpack_from("<" + fmt, self.b, self.o)
        self.o += struct.calcsize("<" + fmt)
        return v if len(v) > 1 else v[0]

    def wstr(self):
        n = self.f("H")
        s = self.b[self.o:self.o + n * 2].decode("utf-16-le", "replace")
        self.o += n * 2
        return s


def table(name, row):
    b = open(RES + name, "rb").read()
    c = Cur(b)
    n = c.f("I")
    rows = [row(c) for _ in range(n)]
    left = len(b) - c.o
    assert 0 <= left < 64, f"{name}: layout drift, {left} bytes left after {n} rows"
    return rows


def drop_group(c):
    gid = c.f("I")
    chance = c.f("10H")
    items = c.f("10I")
    mn = c.f("10B")
    mx = c.f("10B")
    return {"id": gid, "items": [(items[i], chance[i], mn[i], mx[i]) for i in range(10) if items[i]]}


def drop(c):
    d = {"id": c.f("I"), "rate_clear": c.f("B")}
    d["gold"] = c.f("HHHHB")          # chance, min, max, jp rate, jp multi
    d["sv"] = c.f("HHH")
    d["ether"] = c.f("HHHHHH")
    d["bp"] = c.f("HHH")
    gch = c.f("21H")
    gid = c.f("21I")
    d["groups"] = [(gid[i], gch[i]) for i in range(21) if gid[i]]
    cch = c.f("10H")
    cid = c.f("10I")
    d["class_groups"] = [(cid[i], cch[i]) for i in range(10) if cid[i]]
    d["quest"] = c.f("IIHHBBIIHHHH")
    return d


def maze_info(c):
    m = {}
    m["id"], m["type"], m["group"], m["min_lv"], m["members"], m["fp"] = c.f("HBHBBH")
    c.f("HBBBBBB")                     # enter count group/type/count/pc room/plus day/plus value/helper
    m["need_quest"], m["need_item"] = c.f("II")
    c.f("BBBB")                        # need item value, revival type/count, difficulty
    m["difficulty"] = struct.unpack_from("<B", c.b, c.o - 1)[0]
    c.f("BBBBBB")                      # layer mask, episode, clear cal, clear con 1..3
    c.f("IIII")                        # clear values 1..3, check clear maze
    c.f("HHH")                         # open maze, open group, clear time
    m["exp"], m["money"] = c.f("II")
    c.f("H")                           # bind rate
    m["map"] = c.wstr()
    m["script"] = c.wstr()
    c.f("If")                          # scene attack monster, share point ratio
    m["ui"] = c.wstr()
    m["portal"] = c.f("H")
    m["start"] = c.f("ii")
    m["size"] = c.f("II")
    m["escape_district"], m["escape_box"] = c.f("hI")
    c.f("5I")                          # ing quests
    c.f("BBIB")                        # akashic, potion limit, warp orb, re-enter
    return m


def monster(c):
    """TB_MONSTER (size 0x1F77): char[511] = wstr here."""
    m = {"id": c.f("I"), "code": c.wstr()}
    c.wstr()                                  # Monster_Name_D
    c.f("IIBB")                               # parts 2/3, summon hit, faction
    c.f("5I3I")                               # quest + mission groups
    m["level"] = c.f("B")
    m["exp"] = c.f("f")
    c.f("I")                                  # kill score
    m["rank"], m["type"], m["flag"] = c.f("BBB")
    c.f("BB")                                 # clear condition, object max damage
    c.wstr(); c.wstr()                        # object anis
    el = c.f("BB4IfIBBBBB4HBIHB")             # element .. battle mode
    m["sight"], m["run"] = el[7], el[14]      # Monster_Sight, Monster_Run_Speed
    m["ai"] = c.wstr()
    c.f("BB")                                 # ai type, death type
    c.wstr()                                  # special damage
    # The .res follows the STRUCT order (not the SQL select order): the
    # _01.._03 switching fields are grouped per kind.
    c.f("Bh")                                 # default action, stand
    c.f("3Bh")                                # default action 01..03, stand 01
    for _ in range(3): c.wstr()               # switching AI 01..03
    c.f("3B")                                 # AI type 01..03
    for _ in range(3): c.wstr()               # special damage 01..03
    c.f("3B3I3B")                             # condition, value, step 01..03
    for _ in range(3): c.wstr()               # switching action 01..03
    c.f("2h")                                 # stand 02, 03
    m["skills"] = [x for x in c.f("10I") if x]
    m["drop"], m["hit_drop"] = c.f("II")
    c.f("fHHHIB")                             # scale .. SA type
    stats = c.f("46i")
    m["hp"], m["sg"], m["patk"] = stats[0], stats[1], stats[2]
    m["pdef"] = stats[6]
    m["stats"] = stats
    c.f("B")                                  # IS_Item_Rate
    return m


def monster_exp(c):
    """TB_MONSTER_EXP: u8 id, u8 level, 7 x i32 (slave, normal, elite, named,
    boss, raid, summon)."""
    i, lv = c.f("BB")
    return {"id": i, "level": lv, "exp": c.f("7i")}


TABLES = {"tb_Drop_Group.res": drop_group, "tb_Drop.res": drop, "tb_Maze_Info.res": maze_info,
          "tb_Monster.res": monster, "tb_Monster_EXP.res": monster_exp}


if __name__ == "__main__":
    for name, fn in TABLES.items():
        try:
            rows = table(name, fn)
            print(f"[ok] {name}: {len(rows)} rows; first {str(rows[0])[:200]}")
        except AssertionError as e:
            print(f"[FAIL] {e}")
        except struct.error as e:
            print(f"[FAIL] {name}: {e}")
