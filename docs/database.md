# swemu database (SQLite, schema v3)

One file: `run/data/swemu.db` (WAL mode: `swemu.db-wal`, `swemu.db-shm` belong to it).
No MySQL / MSSQL. The schema lives in `server/src/db.rs` (`SCHEMA_V2` + `migrate_v3`); `PRAGMA
user_version` = 3. Older files are migrated once on start (one transaction, data
copied column by column, foreign keys checked before commit); the AUTOINCREMENT
counters are kept so ids are never reused. Account ids start at 1000.

Connection settings: `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`,
`foreign_keys=ON`.

## Tables

| Table | Key | What it holds |
|---|---|---|
| `account` | `id` | login name, Argon2id password hash, Argon2id second password (PIN) hash, cash (NULL = start amount on first read) |
| `character` | `id`, unique (`account_id`, `slot`), unique `name` | identity (class, class_ref, outfit, appearance), progress (level 1..255, exp), currencies (zenny NULL = start amount, ether, bp, soul_vapor), skill deck meta (deck_slots 0..6, deck_bonus = 4 x u16), `equip_seeded` (starter costume written once) |
| `item` | `id`, unique (`character_id`, `storage`, `slot`) | every item a character owns: storage 0 = equipped, 1.. = bags, 13 = costume bag, 255 = temporary while swapping; count >= 1 |
| `buyback` | `id`, unique `serial` | NPC shop sell history (newest 12 kept per character) |
| `skill` | (`character_id`, `skill_group`) | learned skill per skill group (skill id = level), divergence |
| `skill_deck` | (`character_id`, `pos`) | deck slot with 4 skill ids |
| `quest` | (`character_id`, `episode`) | accepted quest episode: helper flag, failed flag, `steps` = 10 condition step counters (BLOB, length 10) |
| `quest_done` | (`character_id`, `episode`) | completed quest episodes (rewards are given once) |
| `maze_clear` | (`character_id`, `maze`) | cleared mazes with `cleared_at` (unix time), sent in 17/0x64 |

All child tables reference `character(id) ON DELETE CASCADE` (characters reference
`account(id)` the same way): deleting a character removes its items, buyback,
skills, decks, quests and maze clears. CHECK constraints reject negative currencies, item count 0 and
levels outside 1..255.

## Backups

Before every deploy: `cp -p run/data/swemu.db* %LOCALAPPDATA%\Temp\swemu-db-backup-<time>\`.
A consistent copy while the server runs: Python `sqlite3` `src.backup(dst)`.
`re/db_snapshot.py <db>` prints row counts + a hash per table (by column name), used to
prove a migration kept every row.

## Migrations

- v2: full rebuild with ordered columns, CASCADE and CHECKs.
- v3 (`migrate_v3`): adds `quest`, `quest_done`, `maze_clear`; existing tables untouched (verified on a copy of the live file with `re/db_snapshot.py`: every v2 table identical).
