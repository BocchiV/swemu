# swemu database (SQLite, schema v6)

One file: `run/data/swemu.db` (WAL mode: `swemu.db-wal`, `swemu.db-shm` belong to it).
No MySQL / MSSQL. Schema lives in `server/src/db.rs`; `PRAGMA user_version`
is 6. V6 moves bank items, capacities, and Zenny from character ownership to
account ownership. Account ids start 1000.

Connection settings: `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`,
`foreign_keys=ON`.

## Tables

| Table | Key | What it holds |
|---|---|---|
| `account` | `id` | login name, Argon2id password hash, Argon2id second password (PIN) hash, cash (NULL = start amount on first read) |
| `character` | `id`, unique (`account_id`, `slot`), unique `name` | identity (class, class_ref, outfit, appearance), progress (level 1..255, exp), currencies (zenny NULL = start amount, ether, bp, soul_vapor), skill deck meta (deck_slots 0..6, deck_bonus = 4 x u16), `equip_seeded` (starter costume written once) |
| `item` | `id`, unique owner/storage/slot | every item: character-owned storage 0 = equipped, 1.. = bags, 13 = costume bag; account-owned storage 0x16 = Normal bank, 0x17 = Costume bank, 0x18 = Cash bank; 255 = temporary while swapping; count >= 1 |
| `storage_capacity` | (`account_id`, `storage`) | Account-wide bank capacity keyed by groups 0x16 Normal (24 slots initially), 0x17 Costume (48), 0x18 Cash (384) |
| `bank_zenny` | `account_id` | Account-wide bank Zenny balance stored as decimal text |
| `buyback` | `id`, unique `serial` | NPC shop sell history (newest 12 kept per character) |
| `skill` | (`character_id`, `skill_group`) | learned skill per skill group (skill id = level), divergence |
| `skill_deck` | (`character_id`, `pos`) | deck slot with 4 skill ids |

Bank item records and capacity rows use groups 0x16↔2 Normal, 0x17↔4
Costume, 0x18↔13 Cash. Server `8/0x0E` slot-info also reports UI groups
5/6/14, mapping capacities to persisted keys 0x16/0x17/0x18. S→C `8/0x10`
bank-item responses encode canonical groups 0x16/0x17/0x18 as client-visible
aliases 0x10/0x11/0x12. ITEM_MOVE requests use those aliases and normalize
internally; successful replies preserve the wire aliases.

Initial capacities are 24/48/384. Item 6001026 adds 12 Normal-storage slots
per use, capped at 48. Table-backed Add Slots 8/0x0F accepts request modes 0
(Normal) and 1 (Costume), consuming one item 837000002 and adding 12 slots;
Cash is unsupported. Do not infer unconfirmed 0x10/0x11 selector mappings.
Normal and Costume banks cap at 384; zero-valued Costume options above 384
remain parsed but cannot be selected by the handler.
After the UI auxiliary fix, the user reports that the actual client locks
Costume slots 49–72 at capacity 48. This confirms the reported Costume48 case
only; other capacities and account states remain unverified.

Bank Sort C→S `8/0x25` accepts selected UI groups 5/6/14 or bank aliases
0x10/0x11/0x12, mapping to canonical DB groups 22/23/24 (0x16/0x17/0x18).
The response echoes the request selector; rows are packed by `(item_id,
serial)` into slots `0..n-1`. Sorting is scoped to account and storage group.
Bank stack split/combine `8/0x04` and `8/0x03` operate within one same-group
bank, subject to account ownership, capacity and stack constraints.

Character-owned child tables reference `character(id) ON DELETE CASCADE`;
deleting a character removes its inventory, buyback, skills and decks, but not
account-owned bank items, capacity or bank Zenny. Account-owned bank tables and
items reference `account(id) ON DELETE CASCADE`. V6 migrates legacy character
bank rows to their owning account. When multiple characters have an item in the
same bank group and slot, rows are processed by character id and item serial:
the first keeps its slot and later rows move to the lowest free slot.
Capacities merge by maximum and are raised as needed to cover migrated item
slots. Legacy bank-Zenny balances are summed per account; migration fails on
u128 overflow, an unrepresentable old bank slot, or a full slot range that
prevents collision relocation. CHECK constraints reject negative currencies,
item count 0 and levels outside 1..255.

## Backups

Before every deploy: `cp -p run/data/swemu.db* %LOCALAPPDATA%\\Temp\\swemu-db-backup-<time>\\`.
A consistent copy while the server runs: Python `sqlite3` `src.backup(dst)`.
`re/db_snapshot.py <db>` prints row counts + a hash per table (by column name), used to
prove a migration kept every row.
