"""Monster AI from the reference server's Scripts/AI/*.lua (Initial_Normal):
skill groups, state timings, the ATTACK -> ATTACK_SKILLn pick conditions and
per-slot skill conditions. Returns compact rows for gamedata.rs.

    import ai_scripts
    ai = ai_scripts.load()       # {script name (lower): Ai}
"""
import os
import glob, os, re

AI_DIR = os.path.join(os.environ.get("SW_SERVER_DATA", "server-data"), "Scripts", "AI")

# condition variables the server understands (others are skipped -> false)
VARS = {
    "FSMVAR_RANDOM": 0,
    "FSMVAR_HEALTH": 1,
    "FSMVAR_TARGETDISTANCE": 2,
    "FSMVAR_TARGETDISTANCE_CAPSULE": 2,
    "FSMVAR_SPAWN_MONSTER_COUNT": 3,
    "FSMVAR_SPAWN_TIME": 4,
    "FSMVAR_ISATTACK": 5,
}
OPS = {"<": 0, ">": 1, "<=": 2, ">=": 3, "==": 4, "=": 4, "!=": 5}


def _num(s):
    s = s.strip().strip('"')
    try:
        return float(s)
    except ValueError:
        return None


def _args(call):
    return [a.strip() for a in call.split(",")]


class Ai:
    def __init__(self):
        self.check_ms = 300
        self.find_range = 0.0
        self.groups = {}           # group -> [slot, ...]
        self.select_ms = (300, 500)
        self.attack_ms = (500, 800)
        self.wait_ms = (800, 1200)
        self.battle_move = (0, 0)  # BATTLE_MOVE target distance min/max
        self.return_dist = 0
        self.picks = []            # (target group or 255, [(var, op, value)])
        self.slot_conds = []       # (group, slot, [(var, op, value)])


def parse(text):
    ai = Ai()
    body = "\n".join(l.split("--")[0] for l in text.splitlines())
    m = re.search(r"function\s+Initial_Normal\s*\(.*?\)(.*?)\nend", body, re.S)
    if m:
        body = m.group(1)
    for name, raw in re.findall(r"ai:(\w+)\s*\((.*?)\)\s*$", body, re.M):
        a = _args(raw)
        if name == "SetAiCheckTime" and _num(a[0]) is not None:
            ai.check_ms = int(_num(a[0]) * 1000)
        elif name == "SetFindEnemyInfo" and len(a) >= 3 and _num(a[2]) is not None:
            ai.find_range = _num(a[2])
        elif name == "SetSkillGroupInfo" and len(a) >= 2:
            g = int(_num(a[0]) or 0)
            slots = [int(_num(x)) for x in a[2:] if _num(x)]
            if slots:
                ai.groups[g] = slots
        elif name == "SetReturnDistance" and _num(a[0]) is not None:
            ai.return_dist = int(_num(a[0]))
        elif name == "RegisterStateVars" and len(a) >= 4:
            state, var = a[0].split(".")[-1], a[1].split(".")[-1]
            lo, hi = _num(a[2]), _num(a[3])
            if lo is None or hi is None:
                continue
            if var == "STATEVAR_LIFE_TIME":
                if state == "FSMSTATES_SELECT_ACTION":
                    ai.select_ms = (int(lo), int(hi))
                elif state == "FSMSTATES_ATTACK":
                    ai.attack_ms = (int(lo), int(hi))
                elif state == "FSMSTATES_WAIT":
                    ai.wait_ms = (int(lo), int(hi))
            elif var == "STATEVAR_TARGET_DIST" and state == "FSMSTATES_BATTLE_MOVE":
                ai.battle_move = (int(lo), int(hi))
        elif name == "RegisterConditions" and len(a) >= 5:
            src, dst, var = a[0].split(".")[-1], a[1].split(".")[-1], a[2].split(".")[-1]
            if src != "FSMSTATES_ATTACK":
                continue
            mm = re.match(r"FSMSTATES_ATTACK_SKILL(\d+)$", dst)
            target = int(mm.group(1)) - 1 if mm else 255
            op, val = OPS.get(a[3].strip().strip('"')), _num(a[4])
            cond = (VARS.get(var, 9), op if op is not None else 0, int(val or 0))
            # Consecutive conditions with the same target are ANDed (the 
            # FSM keeps a condition list per transition).
            if ai.picks and ai.picks[-1][0] == target and not ai.picks[-1][2]:
                ai.picks[-1][1].append(cond)
            else:
                ai.picks.append([target, [cond], False])
            if var == "FSMVAR_RANDOM":
                ai.picks[-1][2] = True  # a RANDOM roll closes the group
        elif name == "RegisterSkillConditions" and len(a) >= 4:
            slot, var = int(_num(a[0]) or 0), a[1].split(".")[-1]
            op, val = OPS.get(a[2].strip().strip('"')), _num(a[3])
            group = int(_num(a[5]) or 0) if len(a) >= 6 and _num(a[5]) is not None else 0
            ai.slot_conds.append((group, slot, [(VARS.get(var, 9), op if op is not None else 0, int(val or 0))]))
    ai.picks = [(t, c) for t, c, _ in ai.picks]
    if 0 not in ai.groups:
        ai.groups[0] = [1]
    return ai


def load():
    out = {}
    for f in glob.glob(os.path.join(AI_DIR, "*.lua")):
        text = open(f, "rb").read().decode("cp949", "replace")
        out[os.path.splitext(os.path.basename(f))[0].lower()] = parse(text)
    return out


if __name__ == "__main__":
    ai = load()
    print(len(ai))
    for k in ("ai_mob_0223_smallcell", "ai_mob_0226_howler", "ai_mob_0255_teeth"):
        a = ai.get(k)
        print(k, a and (a.check_ms, a.find_range, a.groups, a.select_ms, a.attack_ms, a.picks, a.slot_conds))
