"""Snapshot a swemu SQLite file: row counts + a hash of every table's rows
(ordered by key, selected by column NAME so column reordering does not
matter). Usage: db_snapshot.py <db> [columns-json-out]"""
import hashlib, json, sqlite3, sys

TABLES = {
    "account": ["id", "name", "password_hash", "second_pw_hash", "cash", "created_at"],
    "character": ["id", "account_id", "slot", "name", "class", "class_ref", "outfit", "appearance", "level", "exp",
                  "zenny", "ether", "bp", "soul_vapor", "deck_slots", "deck_bonus", "equip_seeded", "created_at"],
    "item": ["id", "character_id", "account_id", "storage", "slot", "item_id", "count", "created_at"],
    "storage_capacity": ["account_id", "storage", "slots"],
    "bank_zenny": ["account_id", "balance"],
    "buyback": ["id", "character_id", "serial", "item_id", "count", "storage", "price"],
    "skill": ["character_id", "skill_group", "skill_id", "divergence"],
    "skill_deck": ["character_id", "pos", "s1", "s2", "s3", "s4"],
}

c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
out = {}
for t, cols in TABLES.items():
    actual = {row[1] for row in c.execute(f'PRAGMA table_info("{t}")')}
    if actual:
        selected = [f'"{col}"' if col in actual else f'NULL AS "{col}"' for col in cols]
        order = ", ".join(f'"{col}"' for col in cols[:2] if col in actual)
        query = f"SELECT {', '.join(selected)} FROM \"{t}\""
        if order:
            query += f" ORDER BY {order}"
        rows = c.execute(query).fetchall()
    else:
        rows = []
    out[t] = (len(rows), hashlib.sha256(repr(rows).encode()).hexdigest()[:16])
if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'").fetchone():
    out["sqlite_sequence"] = sorted(c.execute("SELECT name, seq FROM sqlite_sequence").fetchall())
else:
    out["sqlite_sequence"] = []
out["user_version"] = c.execute("PRAGMA user_version").fetchone()[0]
out["integrity"] = c.execute("PRAGMA integrity_check").fetchone()[0]
out["fk_violations"] = len(c.execute("PRAGMA foreign_key_check").fetchall())
print(json.dumps(out, indent=1))
