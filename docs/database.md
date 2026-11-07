# swemu database (SQLite, schema v6)

One file: `run/data/swemu.db` (WAL mode: `swemu.db-wal`, `swemu.db-shm` belong to it).
No MySQL or MSSQL. Schema is defined in `server/src/db.rs`; `PRAGMA user_version` is 6.
V6 moves bank items, capacities, and Zenny from character ownership to account ownership.
Account IDs start at 1000.

Connection settings: `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`,
`foreign_keys=ON`.

## Tables

| Table | Key | What it holds |
|---|---|---|
| `account` | `id` | login name, Argon2id password hash, Argon2id second password (PIN) hash, cash (NULL = start amount on first read) |
| `character` | `id`, unique (`account_id`, `slot`), unique `name` | identity (class, class_ref, outfit, appearance); progress (level 1..255, exp); currencies (zenny NULL = start amount, ether, bp, soul_vapor); skill deck meta (`deck_slots` 0..6; `deck_bonus`: four u16 values); `equip_seeded` (starter costume written once) |
| `item` | `id`, unique owner/storage/slot | Character-owned storage 0 = equipped, 1+ = bags, 13 = Costume bag; account-owned storage 0x16/0x17/0x18 = Normal/Costume/Cash banks; 255 = temporary during swaps; count >= 1 |
| `storage_capacity` | (`account_id`, `storage`) | Account-wide bank capacity keyed by storage group: 0x16 Normal (24 slots initially), 0x17 Costume (48), 0x18 Cash (384) |
| `bank_zenny` | `account_id` | Account-wide bank Zenny balance stored as decimal text |
| `buyback` | `id`, unique `serial` | NPC shop sell history (newest 12 kept per character) |
| `skill` | (`character_id`, `skill_group`) | learned skill per skill group (skill id = level), divergence |
| `skill_deck` | (`character_id`, `pos`) | deck slot with four skill IDs |

Bank item and capacity rows use canonical groups 0x16/0x17/0x18, mapped to
inventory groups 2/4/13 (Normal/Costume/Cash). `8/0x0E` also reports UI groups
5/6/14, mapped to those capacity keys. S→C `8/0x10` bank-item rows use
client-visible aliases 0x10/0x11/0x12. C→S `ITEM_MOVE` requests use these
aliases; the server normalizes them for persistence and preserves them in
successful replies.

Initial capacities are 24/48/384. Item 6001026 adds 12 Normal slots per use,
up to 48. Table-backed Add Slots (`8/0x0F`) accepts raw client selectors
`0x10` (Normal) and `0x11` (Costume), consumes one item `837000002`, and adds
12 slots; replies echo the selector. Cash selector `0x12` is unsupported.
Normal and Costume banks cap at 384. Zero-valued Costume options above 384
remain in the generated table but cannot be selected by the handler.
The user confirmed that Add Slots prompts expand Normal and Costume banks in
the client. At Costume capacity 48, slots 49–72 remain locked. Cash expansion
remains unsupported; exact visible slot counts after expansion are unconfirmed.

Bank Sort C→S `8/0x25` accepts UI groups 5/6/14 or aliases 0x10/0x11/0x12;
these map to canonical DB groups 22/23/24 (0x16/0x17/0x18). Replies echo the
requested selector, and rows sort by `(item_id, serial)` into packed slots
`0..n-1`. Sorting is scoped to the account and storage group.
Bank stack split/combine (`8/0x04` and `8/0x03`) is restricted to one bank
group and enforces account ownership, capacity, and stack constraints.

Character-owned child tables reference `character(id) ON DELETE CASCADE`;
deleting a character removes its inventory, buyback rows, skills, and decks
but preserves account-owned bank items, capacities, and Zenny. Account-owned
bank tables and items reference `account(id) ON DELETE CASCADE`. V6 migrates
legacy character-owned bank rows to the owning account. For duplicate group
and slot rows, migration processes items by character ID and then serial: the
first keeps its slot; later rows move to the lowest free slot.
Capacities merge by maximum and increase as needed to cover migrated item
slots. Legacy bank-Zenny balances are summed per account. Migration fails on
u128 overflow, an unrepresentable bank slot, or a full slot range that
prevents collision relocation. CHECK constraints reject negative currencies,
zero item counts, and levels outside 1..255.

## Backups

Before every deploy: `cp -p run/data/swemu.db* %LOCALAPPDATA%\\Temp\\swemu-db-backup-<time>\\`.
A consistent copy while the server runs: Python `sqlite3` `src.backup(dst)`.
`re/db_snapshot.py <db>` prints row counts + a hash per table (by column name), used to
prove a migration kept every row.
