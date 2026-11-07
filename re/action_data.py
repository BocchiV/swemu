"""Skill hit timing from the client's ActionData (data04.v
Character/ActionData/PC_<class letter>.adf, Vision VBIN chunk files).

An animation record is u32 name length + name + 00 00 01 00 ff ff. Its
events are 'TNVE' chunks: u32 chunk length, u16 trigger type, then the
ActionTrigger fields (GameServer ActionTrigger::Serialize): u32 name
length + name, u32 id, f32 time (s), f32 end time. Type 3 is an
AttackJudgmentTrigger: one damage frame. The official server sends one
ACTION_SKILL_BT 6/0x13 per attack frame with the trigger id (
CUser::ActionProcess -> CMover::send_eSUB_CMD_ACTION_SKILL); the client
applies the hit only when the id names an attack event of the animation it
plays (CPlayer::ActionSkill FUN_1803fad80 -> FUN_180358680 GetAttackEvent,
else "ApplySkillDamageFrame>> ActionEvent not found").

GB tb_Skill rows carry the skill's action (animation) name as the first
UTF-16 string of the row ("B_Skill_..." / "B_N_Attack_...").
"""
import bisect
import re
import struct

ANIM = re.compile(rb"([\x01-\x7f]\x00\x00\x00)([A-Za-z0-9_&\-\. ]{2,80}?)\x00\x00\x01\x00\xff\xff")
# Every animation (sequence) record: chunk tag ('TDSO', or 'TNVE' right after
# the previous sequence's empty event list) + u32 0 + u32 name length + name
# + u8 flag, 00, u8 flag, 00, ff ff.
SEQ = re.compile(rb"(?:TDSO|TNVE)\x00\x00\x00\x00(?:\x00\x00\x00\x00)?([\x01-\x7f])\x00\x00\x00")


def anims(adf):
    """[(file offset, animation name)] of every sequence record, file order."""
    out = []
    for m in SEQ.finditer(adf):
        n = m.group(1)[0]
        name = adf[m.end():m.end() + n]
        tail = adf[m.end() + n:m.end() + n + 6]
        if re.fullmatch(rb"[A-Za-z0-9_&\-\. ]+", name) and tail[1] == 0 and tail[3] == 0 and tail[4:6] == b"\xff\xff":
            out.append((m.start(), name.decode()))
    return out


def attack_triggers(adf):
    """[(animation name, client event key, file offset)] of every attack
    event (type 3) in file order. The GB client does not use the stored id:
    it numbers the attack events itself in file order, each animation that
    has any starting at the next multiple of 50 (key = base + 1-based event
    index; one with more than 50 events runs into the next block), and looks the 6/0x13 trigger up by that
    key (measured live: PC_E B_N_Attack_01 -> 201/202, B_N_Attack_03 ->
    351..354; all 673 PC_E keys match)."""
    starts, seqs = _seq_starts(adf)
    out = []
    base, key, fresh = -50, 0, True
    nxt = 0
    p = adf.find(b"TNVE")
    while p != -1:
        while nxt < len(starts) and starts[nxt] < p:
            nxt, fresh = nxt + 1, True
        ln, typ, nlen = struct.unpack_from("<IHI", adf, p + 4)
        if typ == 3 and nlen < 64 and ln < 4096:
            if fresh:
                # next multiple of 50 (an animation with > 50 events spills over)
                base, fresh = max(base + 50, (key // 50 + 1) * 50 if key else 0), False
                key = base
            key += 1
            out.append((seqs[nxt - 1][1] if nxt else None, key, p))
        p = adf.find(b"TNVE", p + 1)
    return out
WSTR = re.compile(rb"((?:[\x20-\x7e]\x00){3,80})")


def real_time(t, windows):
    """Sequence time t (s) -> wall time (s) under AnimSpeed windows
    [(start, end, speed)]: inside a window the animation plays at `speed`
    (AnimSpeedTrigger::Serialize: +0x94 start, +0x98 end, +0xac speed;
    the mover's SetAnimSpeed overwrites, so the latest-started window
    containing a moment wins)."""
    if not windows:
        return t
    cuts = sorted({0.0, t} | {w[0] for w in windows if w[0] < t} | {w[1] for w in windows if w[1] < t})
    real = 0.0
    for a, b in zip(cuts, cuts[1:]):
        mid = (a + b) / 2
        active = [w for w in windows if w[0] <= mid < w[1]]
        speed = max(active, key=lambda w: w[0])[2] if active else 1.0
        real += (b - a) / speed
    return real


def _seq_starts(adf):
    """Sequence records found either way (old ANIM pattern + anims())."""
    seen = {}
    for m in ANIM.finditer(adf):
        if m.group(1)[0] == len(m.group(2)):
            seen[m.start()] = m.group(2).decode()
    for p, n in anims(adf):
        if not any(abs(p - q) < 16 for q in seen):
            seen[p] = n
    out = sorted(seen.items())
    return [a[0] for a in out], out


def attack_frames(adf):
    """animation name -> [(client event key, time ms)] (attack events, time
    order). Keys are the client's own numbering (attack_triggers), which the
    6/0x13 trigger must carry. Times are wall-clock ms: AnimSpeed triggers
    (type 23, f32 speed 16 B after the end time) speed up / slow down the
    sequence, and the event times are sequence times."""
    starts, seqs = _seq_starts(adf)
    keys = {p: k for _, k, p in attack_triggers(adf)}
    raw = {}
    speed = {}
    p = adf.find(b"TNVE")
    while p != -1:
        ln, typ, nlen = struct.unpack_from("<IHI", adf, p + 4)
        if typ in (3, 23) and nlen < 64 and ln < 4096:
            q = p + 14 + nlen
            tid, t = struct.unpack_from("<If", adf, q)
            i = bisect.bisect_right(starts, p) - 1
            if typ == 3 and i >= 0 and 0 <= t < 30 and p in keys and keys[p] < 65536:
                raw.setdefault(seqs[i][1], []).append((keys[p], t))
            elif typ == 23 and i >= 0:
                end = struct.unpack_from("<f", adf, q + 8)[0]
                sp = struct.unpack_from("<f", adf, q + 28)[0]
                if end > t and 0.05 <= sp <= 20:
                    speed.setdefault(seqs[i][1], []).append((t, end, sp))
        p = adf.find(b"TNVE", p + 1)
    out = {}
    for name, v in raw.items():
        w = speed.get(name, [])
        out[name] = sorted(((tid, int(round(real_time(t, w) * 1000))) for tid, t in v), key=lambda e: (e[1], e[0]))
    return out


def attack_area(adf, q):
    """AttackJudgmentTrigger tagATTACK_RANGE after the base fields (symbols:
    fAngle, vCenterPos xyz, fBoxSizeX/Y, fRadius, fHeight). Player files put
    u16 range type, u16 attack type, u16 collision, u32 spawn object first
    (angle at +38 from the event id); older monster files lack those 8 bytes
    (angle at +30). Returns (forward offset, radius, angle) or None."""
    for off in (38, 30):
        if q + off + 32 > len(adf):
            continue
        ang, cx, cy, cz, bx, by, r, h = struct.unpack_from("<8f", adf, q + off)
        vals = (ang, cx, cy, cz, bx, by, r, h)
        if not all(v == v and abs(v) < 1e6 and (v == 0 or abs(v) > 1e-4) for v in vals):
            continue
        # Box areas (range type 1) leave the angle at 0.
        if 0 <= ang <= 360 and 0 <= r < 30000 and h > 0 and bx >= 0 and by >= 0 and max(r, bx, by) > 1:
            return ((cx * cx + cy * cy) ** 0.5, max(r, bx, by), ang)
    return None


def attack_regions(adf):
    """animation name -> {client event key: (back, r_start, r_end, angle,
    damage)} per attack event: CMover::IsAttackDecision / GetAttackArea
    sector — apex at attacker + rotated vCenterPos (client local forward is
    -y, so vCenterPos.y > 0 sits BEHIND the attacker by `back` cm), from
    fStartPos to fRadius along the facing, within +-fAngle/2. angle 0 = box
    (r_end = box size). damage False for buff / Evol events (allies)."""
    starts, anims_ = _seq_starts(adf)
    keys = {p: k for _, k, p in attack_triggers(adf)}
    out = {}
    p = adf.find(b"TNVE")
    while p != -1:
        ln, typ, nlen = struct.unpack_from("<IHI", adf, p + 4)
        if typ == 3 and nlen < 64 and ln < 4096 and p in keys:
            q = p + 14 + nlen
            i = bisect.bisect_right(starts, p) - 1
            if i >= 0 and attack_area(adf, q):
                off = 38 if attack_area(adf, q) and _area_at(adf, q, 38) else 30
                ang, cx, cy, cz, bx, by, r, h, start = struct.unpack_from("<9f", adf, q + off)
                if not (start == start and 0 <= start < 30000):
                    start = 0.0
                name = adf[p + 14:q].decode("latin1").lower()
                dmg = not any(w in name for w in ("buff", "evol", "heal"))
                if ang == 0:
                    r, start = max(r, bx, by), 0.0
                out.setdefault(anims_[i][1], {})[keys[p]] = (cy, min(start, r), r, ang, dmg)
        p = adf.find(b"TNVE", p + 1)
    return out


def _area_at(adf, q, off):
    if q + off + 32 > len(adf):
        return False
    ang, cx, cy, cz, bx, by, r, h = struct.unpack_from("<8f", adf, q + off)
    vals = (ang, cx, cy, cz, bx, by, r, h)
    return all(v == v and abs(v) < 1e6 and (v == 0 or abs(v) > 1e-4) for v in vals) and \
        0 <= ang <= 360 and 0 <= r < 30000 and h > 0 and bx >= 0 and by >= 0 and max(r, bx, by) > 1


def attack_cone(adf):
    """animation name -> (radius cm, angle deg) of its widest-reaching damage
    event, for player hit tests: a sector from the attacker along its facing
    (angle 360 = all around; 0 = box area, radius = box size). Buff / debuff
    / Evol events (allies, status) are skipped when the animation has others."""
    starts, anims_ = _seq_starts(adf)
    per = {}
    p = adf.find(b"TNVE")
    while p != -1:
        ln, typ, nlen = struct.unpack_from("<IHI", adf, p + 4)
        if typ == 3 and nlen < 64 and ln < 4096:
            q = p + 14 + nlen
            i = bisect.bisect_right(starts, p) - 1
            a = attack_area(adf, q)
            if i >= 0 and a:
                name = adf[p + 14:q].decode("latin1").lower()
                buff = any(w in name for w in ("buff", "evol", "debuff", "heal"))
                per.setdefault(anims_[i][1], []).append((buff, max(a[1], a[0]) if a[2] == 0 else a[1], a[2]))
        p = adf.find(b"TNVE", p + 1)
    out = {}
    for name, v in per.items():
        dmg = [e for e in v if not e[0]] or v
        _, r, ang = max(dmg, key=lambda e: e[1])
        out[name] = (r, ang)
    return out


def attack_reach(adf):
    """animation name -> farthest point (cm) any of its attack events reaches
    from the attacker (forward offset + radius / box size)."""
    starts, anims_ = _seq_starts(adf)
    out = {}
    p = adf.find(b"TNVE")
    while p != -1:
        ln, typ, nlen = struct.unpack_from("<IHI", adf, p + 4)
        if typ == 3 and nlen < 64 and ln < 4096:
            q = p + 14 + nlen
            i = bisect.bisect_right(starts, p) - 1
            a = attack_area(adf, q)
            if i >= 0 and a:
                out[anims_[i][1]] = max(out.get(anims_[i][1], 0), a[0] + a[1])
        p = adf.find(b"TNVE", p + 1)
    return out


def skill_action(sk, row_start, row_end):
    """First UTF-16 action name in a tb_Skill row ('X_...')."""
    blob = sk[row_start:row_end]
    for m in WSTR.finditer(blob):
        s = m.group(1).decode("utf-16le")
        n = struct.unpack_from("<H", blob, m.start() - 2)[0] if m.start() >= 2 else -1
        if n == len(s) and re.match(r"^[A-Z]_[A-Za-z]", s):
            return s
    return None
