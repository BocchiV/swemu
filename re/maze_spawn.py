"""Maze spawn data from a maze .vbatch: VCheckMonsterSpawnBox (id -> spawn box
ids it triggers) and VMonsterSpawnBox (id, monster slots, condition, pos)."""
import re, sys


def blocks(text, kind):
    out = []
    for blk in re.findall(r"<%s\b(?:(?!<%s\b).)*?</%s>" % (kind, kind, kind), text, re.S):
        kv = dict(re.findall(r'<(m_\w+) type="\d+" value="([^"]*)"', blk))
        out.append(kv)
    return out


def centre(kv):
    tl = [float(x) for x in kv["m_vPosTopLeft"].split(",")]
    br = [float(x) for x in kv["m_vPosBottomRight"].split(",")]
    return [(tl[0] + br[0]) / 2, (tl[1] + br[1]) / 2, tl[2]], tl, br


def checks(text):
    """VCheckMonsterSpawnBox id -> [spawn box ids]"""
    out = {}
    for kv in blocks(text, "VCheckMonsterSpawnBox"):
        ids = [int(v) for k, v in sorted(kv.items()) if k.startswith("m_iCheckBox_") and int(v or 0)]
        out[int(kv["m_ID"])] = ids
    return out


def spawns(text):
    """VMonsterSpawnBox id -> dict(monsters=[(type, id, chance)], cond, pos, rot,
    tl, br, sector, waypoint, max, random)"""
    out = {}
    for kv in blocks(text, "VMonsterSpawnBox"):
        mons = []
        for i in range(1, 11):
            mid = int(kv.get(f"m_iMonsterID{i}") or 0)
            if mid:
                mons.append((kv.get(f"m_eType{i}"), mid, int(kv.get(f"m_iChance{i}") or 0)))
        pos, tl, br = centre(kv)
        out[int(kv["m_ID"])] = dict(
            monsters=mons, cond=kv.get("m_eCreationCondition"), pos=pos, tl=tl, br=br,
            rot=float(kv.get("m_fRotation") or 0), sector=int(kv.get("m_iSectorID") or 0),
            waypoint=int(kv.get("m_iWaypoint") or 0), max=int(kv.get("m_iMaxEntityCount") or 1),
            step=max(int(kv.get("m_iStep") or 1), 1),
            random=kv.get("m_eCreationPositionType") == "Random")
    return out


if __name__ == "__main__":
    text = open(sys.argv[1], encoding="utf-8").read()
    c, s = checks(text), spawns(text)
    print(len(c), "check boxes;", len(s), "spawn boxes")
    for k, v in c.items():
        print("CHECK", k, "->", v)
        for b in v:
            if b in s:
                x = s[b]
                print("   ", b, x["cond"], x["monsters"], "max", x["max"], "sector", x["sector"], [round(p) for p in x["pos"]])
    imm = {k: v for k, v in s.items() if v["cond"] == "Immediate" and any(t == "Monster" for t, *_ in v["monsters"])}
    print("immediate monster boxes:", len(imm))
