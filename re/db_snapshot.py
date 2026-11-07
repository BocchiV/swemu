"""Snapshot a swemu SQLite file: row counts + a hash of every table's rows
(ordered by key, selected by column NAME so column reordering does not
matter). Usage: db_snapshot.py <db> [columns-json-out]"""
import hashlib, json, sqlite3, sys

TABLES = {
    "account": ["id", "name", "password_hash", "second_pw_hash", "cash", "created_at"],
    "character": ["id", "account_id", "slot", "name", "class", "class_ref", "outfit", "appearance", "level", "exp",
                  "zenny", "ether", "bp", "soul_vapor", "deck_slots", "deck_bonus", "equip_seeded", "created_at"],
    "item": ["id", "character_id", "storage", "slot", "item_id", "count", "created_at"],
    "buyback": ["id", "character_id", "serial", "item_id", "count", "storage", "price"],
    "skill": ["character_id", "skill_group", "skill_id", "divergence"],
    "skill_deck": ["character_id", "pos", "s1", "s2", "s3", "s4"],
    # v3 (absent in older files)
    "quest": ["character_id", "episode", "is_helper", "is_failed", "steps", "accepted_at"],
    "quest_done": ["character_id", "episode", "done_at"],
    "maze_clear": ["character_id", "maze", "cleared_at"],
}

c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
out = {}
have = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
for t, cols in TABLES.items():
    if t not in have:
        out[t] = None
        continue
    rows = c.execute(f"SELECT {', '.join(cols)} FROM {t} ORDER BY {', '.join(cols[:2])}").fetchall()
    out[t] = (len(rows), hashlib.sha256(repr(rows).encode()).hexdigest()[:16])
out["sqlite_sequence"] = sorted(c.execute("SELECT name, seq FROM sqlite_sequence").fetchall())
out["user_version"] = c.execute("PRAGMA user_version").fetchone()[0]
out["integrity"] = c.execute("PRAGMA integrity_check").fetchone()[0]
out["fk_violations"] = len(c.execute("PRAGMA foreign_key_check").fetchall())
print(json.dumps(out, indent=1))
