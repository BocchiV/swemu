//! SQLite persistence (accounts, characters). Replaces the MSSQL + DBAgent stack.

use anyhow::Result;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rusqlite::{params, Connection, OptionalExtension};

pub struct Db {
    conn: Connection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BankZennyDirection {
    Deposit,
    Withdraw,
}

/// Current schema layout (see migrations and docs/database.md).
pub const SCHEMA_VERSION: i64 = 6;

const NORMAL_BANK_SLOTS: u16 = 24;
const COSTUME_BANK_SLOTS: u16 = 48;
const CASH_BANK_SLOTS: u16 = 384;

/// v2 tables, in dependency order. Column order: identity, owner, content,
/// progress, currencies, bookkeeping.
const SCHEMA_V2: &str = "
CREATE TABLE account (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  name            TEXT    NOT NULL UNIQUE,
  password_hash   TEXT,
  second_pw_hash  TEXT,
  cash            INTEGER CHECK (cash IS NULL OR cash >= 0),
  created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE TABLE character (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id      INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  slot            INTEGER NOT NULL CHECK (slot BETWEEN 0 AND 255),
  name            TEXT    NOT NULL UNIQUE,
  class           INTEGER NOT NULL,
  class_ref       INTEGER NOT NULL DEFAULT 0,
  outfit          INTEGER NOT NULL DEFAULT 0,
  appearance      BLOB,
  level           INTEGER NOT NULL DEFAULT 1 CHECK (level BETWEEN 1 AND 255),
  exp             INTEGER NOT NULL DEFAULT 0 CHECK (exp >= 0),
  zenny           INTEGER CHECK (zenny IS NULL OR zenny >= 0),
  ether           INTEGER NOT NULL DEFAULT 0 CHECK (ether >= 0),
  bp              INTEGER NOT NULL DEFAULT 0 CHECK (bp >= 0),
  soul_vapor      INTEGER NOT NULL DEFAULT 0 CHECK (soul_vapor >= 0),
  deck_slots      INTEGER NOT NULL DEFAULT 3 CHECK (deck_slots BETWEEN 0 AND 6),
  deck_bonus      INTEGER NOT NULL DEFAULT 0,
  equip_seeded    INTEGER NOT NULL DEFAULT 0 CHECK (equip_seeded IN (0, 1)),
  created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  UNIQUE (account_id, slot)
);
CREATE TABLE item (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  character_id    INTEGER NOT NULL REFERENCES character(id) ON DELETE CASCADE,
  storage         INTEGER NOT NULL CHECK (storage BETWEEN 0 AND 255),
  slot            INTEGER NOT NULL CHECK (slot >= 0),
  item_id         INTEGER NOT NULL,
  count           INTEGER NOT NULL DEFAULT 1 CHECK (count >= 1),
  created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  UNIQUE (character_id, storage, slot)
);
CREATE TABLE buyback (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  character_id    INTEGER NOT NULL REFERENCES character(id) ON DELETE CASCADE,
  serial          INTEGER NOT NULL UNIQUE,
  item_id         INTEGER NOT NULL,
  count           INTEGER NOT NULL CHECK (count >= 1),
  storage         INTEGER NOT NULL,
  price           INTEGER NOT NULL CHECK (price >= 0)
);
CREATE INDEX buyback_character ON buyback(character_id, id);
CREATE TABLE skill (
  character_id    INTEGER NOT NULL REFERENCES character(id) ON DELETE CASCADE,
  skill_group     INTEGER NOT NULL,
  skill_id        INTEGER NOT NULL,
  divergence      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (character_id, skill_group)
) WITHOUT ROWID;
CREATE TABLE skill_deck (
  character_id    INTEGER NOT NULL REFERENCES character(id) ON DELETE CASCADE,
  pos             INTEGER NOT NULL CHECK (pos >= 0),
  s1              INTEGER NOT NULL DEFAULT 0,
  s2              INTEGER NOT NULL DEFAULT 0,
  s3              INTEGER NOT NULL DEFAULT 0,
  s4              INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (character_id, pos)
) WITHOUT ROWID;
";

/// Copy statements old -> v2 (column lists explicit, values clamped into the
/// new CHECK ranges; orphans dropped).
const COPY_V2: &[(&str, &str)] = &[
    ("account", "INSERT INTO account (id, name, password_hash, second_pw_hash, cash, created_at)
        SELECT id, name, password_hash, second_pw_hash, CASE WHEN cash < 0 THEN 0 ELSE cash END, created_at FROM old_account"),
    ("character", "INSERT INTO character (id, account_id, slot, name, class, class_ref, outfit, appearance, level, exp,
            zenny, ether, bp, soul_vapor, deck_slots, deck_bonus, equip_seeded, created_at)
        SELECT id, account_id, slot, name, class, class_ref, outfit, appearance, MAX(1, MIN(level, 255)), MAX(exp, 0),
            CASE WHEN zenny < 0 THEN 0 ELSE zenny END, MAX(ether, 0), MAX(bp, 0), MAX(soul_vapor, 0),
            MAX(0, MIN(deck_slots, 6)), deck_bonus, CASE WHEN equip_seeded <> 0 THEN 1 ELSE 0 END, created_at
        FROM old_character WHERE account_id IN (SELECT id FROM account)"),
    ("item", "INSERT INTO item (id, character_id, storage, slot, item_id, count, created_at)
        SELECT id, character_id, storage, slot, item_id, count, created_at FROM old_item
        WHERE count >= 1 AND character_id IN (SELECT id FROM character)"),
    ("buyback", "INSERT INTO buyback (id, character_id, serial, item_id, count, storage, price)
        SELECT id, character_id, serial, item_id, count, storage, MAX(price, 0) FROM old_buyback
        WHERE count >= 1 AND character_id IN (SELECT id FROM character)"),
    ("skill", "INSERT INTO skill (character_id, skill_group, skill_id, divergence)
        SELECT character_id, skill_group, skill_id, divergence FROM old_skill
        WHERE character_id IN (SELECT id FROM character)"),
    ("skill_deck", "INSERT INTO skill_deck (character_id, pos, s1, s2, s3, s4)
        SELECT character_id, pos, s1, s2, s3, s4 FROM old_skill_deck
        WHERE character_id IN (SELECT id FROM character)"),
];

/// Rebuild every table into the v2 layout once (user_version < 2). Runs in
/// one transaction; foreign keys are checked before commit.
fn migrate_v2(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= 2 {
        return Ok(());
    }
    // AUTOINCREMENT counters, so ids are never reused after the rebuild.
    let seqs: Vec<(String, i64)> = conn
        .prepare("SELECT name, seq FROM sqlite_sequence")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    conn.execute_batch("PRAGMA foreign_keys=OFF;")?;
    let tx = conn.unchecked_transaction()?;
    for (table, _) in COPY_V2 {
        tx.execute_batch(&format!("ALTER TABLE {table} RENAME TO old_{table};"))?;
    }
    tx.execute_batch(SCHEMA_V2)?;
    for (_, copy) in COPY_V2 {
        tx.execute_batch(copy)?;
    }
    for (table, _) in COPY_V2.iter().rev() {
        tx.execute_batch(&format!("DROP TABLE old_{table};"))?;
    }
    for (name, seq) in &seqs {
        let name = name.trim_start_matches("old_");
        tx.execute(
            "UPDATE sqlite_sequence SET seq = MAX(seq, ?2) WHERE name = ?1",
            params![name, seq],
        )?;
        tx.execute(
            "INSERT INTO sqlite_sequence(name, seq) SELECT ?1, ?2 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = ?1)",
            params![name, seq],
        )?;
    }
    tx.execute("DELETE FROM sqlite_sequence WHERE name LIKE 'old_%'", [])?;
    let broken: i64 = tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
    anyhow::ensure!(broken == 0, "schema v2 migration: {broken} foreign key violations");
    tx.execute_batch("PRAGMA user_version = 2;")?;
    tx.commit()?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    tracing::info!(version = 2, "database schema migrated");
    Ok(())
}

fn migrate_v4(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= 4 {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS storage_capacity (
           character_id INTEGER NOT NULL REFERENCES character(id) ON DELETE CASCADE,
           storage INTEGER NOT NULL CHECK (storage IN (5, 6, 14)),
           slots INTEGER NOT NULL CHECK (slots >= 0),
           PRIMARY KEY(character_id, storage)
         ) WITHOUT ROWID;
         INSERT OR IGNORE INTO storage_capacity(character_id, storage, slots) SELECT id, 5, 24 FROM character;
         INSERT OR IGNORE INTO storage_capacity(character_id, storage, slots) SELECT id, 6, 48 FROM character;
         INSERT OR IGNORE INTO storage_capacity(character_id, storage, slots) SELECT id, 14, 384 FROM character;
         PRAGMA user_version=4;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_v5(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= 5 {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "ALTER TABLE character ADD COLUMN bank_zenny INTEGER NOT NULL DEFAULT 0 CHECK (bank_zenny >= 0);
         UPDATE item SET storage=CASE storage WHEN 5 THEN 22 WHEN 6 THEN 23 WHEN 14 THEN 24 ELSE storage END
           WHERE storage IN (5,6,14);
         ALTER TABLE storage_capacity RENAME TO storage_capacity_v4;
         CREATE TABLE storage_capacity (
           character_id INTEGER NOT NULL REFERENCES character(id) ON DELETE CASCADE,
           storage INTEGER NOT NULL CHECK (storage IN (22,23,24)),
           slots INTEGER NOT NULL CHECK (slots >= 0),
           PRIMARY KEY(character_id, storage)
         ) WITHOUT ROWID;
         INSERT INTO storage_capacity(character_id,storage,slots)
           SELECT character_id, CASE storage WHEN 5 THEN 22 WHEN 6 THEN 23 WHEN 14 THEN 24 END, slots FROM storage_capacity_v4;
         DROP TABLE storage_capacity_v4;
         PRAGMA user_version=5;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_v6(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= 6 {
        return Ok(());
    }
    let item_seq: Option<i64> = conn.query_row(
        "SELECT seq FROM sqlite_sequence WHERE name='item'",
        [],
        |row| row.get(0),
    ).optional()?;
    let tx = conn.unchecked_transaction()?;
    let violations: i64 = tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
    anyhow::ensure!(violations == 0, "schema v6 migration: {violations} legacy foreign key violations");
    let bank_slots_overflow: bool = tx.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM item i JOIN character c ON c.id=i.character_id
             WHERE i.storage IN (22,23,24) AND i.slot >= 65535
         )",
        [],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        !bank_slots_overflow,
        "schema v6 migration: legacy bank slot capacity exceeds u16"
    );
    let bank_item_count_overflow: bool = tx.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM item i JOIN character c ON c.id=i.character_id
             WHERE i.storage IN (22,23,24)
             GROUP BY c.account_id,i.storage HAVING COUNT(*) > 65535
         )",
        [],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        !bank_item_count_overflow,
        "schema v6 migration: legacy bank storage exceeds u16 slot capacity"
    );
    let mut bank_balances = std::collections::HashMap::<u32, u128>::new();
    {
        let mut statement = tx.prepare("SELECT account_id,bank_zenny FROM character ORDER BY id")?;
        for row in statement.query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, i64>(1)?)))? {
            let (account, balance) = row?;
            let total = bank_balances.entry(account).or_default();
            *total = total.checked_add(balance.max(0) as u128)
                .ok_or_else(|| anyhow::anyhow!("legacy bank balance overflow"))?;
            anyhow::ensure!(*total <= u64::MAX as u128, "schema v6 migration: legacy bank Zenny exceeds client u64 range");
        }
    }
    let capacity_overflow: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM storage_capacity WHERE slots < 0 OR slots > 65535)",
        [],
        |row| row.get(0),
    )?;
    anyhow::ensure!(!capacity_overflow, "schema v6 migration: legacy bank capacity exceeds u16");
    let count_overflow: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM item WHERE storage IN (22,23,24) AND (count < 1 OR count > 65535))",
        [],
        |row| row.get(0),
    )?;
    anyhow::ensure!(!count_overflow, "schema v6 migration: legacy bank item count exceeds u16");
    tx.execute_batch(
        "CREATE TABLE item_v6 (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           character_id INTEGER REFERENCES character(id) ON DELETE CASCADE,
           account_id INTEGER REFERENCES account(id) ON DELETE CASCADE,
           storage INTEGER NOT NULL CHECK(storage BETWEEN 0 AND 255),
           slot INTEGER NOT NULL CHECK(slot >= 0),
           item_id INTEGER NOT NULL,
           count INTEGER NOT NULL DEFAULT 1 CHECK(count >= 1),
           created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
           CHECK ((character_id IS NOT NULL AND account_id IS NULL AND storage NOT IN (22,23,24)) OR
                  (character_id IS NULL AND account_id IS NOT NULL AND storage IN (22,23,24)))
         );
         CREATE TABLE storage_capacity_v6 (
           account_id INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
           storage INTEGER NOT NULL CHECK(storage IN (22,23,24)),
           slots INTEGER NOT NULL CHECK(slots >= 0),
           PRIMARY KEY(account_id,storage)
         ) WITHOUT ROWID;
         CREATE TABLE bank_zenny (
           account_id INTEGER PRIMARY KEY REFERENCES account(id) ON DELETE CASCADE,
           balance TEXT NOT NULL CHECK(balance NOT GLOB '*[^0-9]*' AND length(balance)>0)
         );
         INSERT INTO item_v6(id,character_id,storage,slot,item_id,count,created_at)
           SELECT id,character_id,storage,slot,item_id,count,created_at FROM item WHERE storage NOT IN (22,23,24);
         WITH RECURSIVE slot_numbers(n) AS (
           SELECT 0 UNION ALL SELECT n+1 FROM slot_numbers WHERE n < 65535
         ), bank_rows AS (
           SELECT i.id,c.account_id,i.storage,i.slot,i.item_id,i.count,i.created_at,c.id AS character_order,
                  ROW_NUMBER() OVER(PARTITION BY c.account_id,i.storage,i.slot ORDER BY c.id,i.id) AS duplicate_rank
           FROM item i JOIN character c ON c.id=i.character_id WHERE i.storage IN (22,23,24)
         ), duplicates AS (
           SELECT id,account_id,storage,
                  ROW_NUMBER() OVER(PARTITION BY account_id,storage ORDER BY character_order,id) AS relocation_rank
           FROM bank_rows WHERE duplicate_rank > 1
         ), free_slots AS (
           SELECT groups.account_id,groups.storage,slot_numbers.n,
                  ROW_NUMBER() OVER(PARTITION BY groups.account_id,groups.storage ORDER BY slot_numbers.n) AS free_rank
           FROM (SELECT DISTINCT account_id,storage FROM bank_rows) groups CROSS JOIN slot_numbers
           WHERE NOT EXISTS (
             SELECT 1 FROM bank_rows b WHERE b.account_id=groups.account_id
               AND b.storage=groups.storage AND b.slot=slot_numbers.n
           )
         )
         INSERT INTO item_v6(id,account_id,storage,slot,item_id,count,created_at)
           SELECT b.id,b.account_id,b.storage,COALESCE(f.n,b.slot),b.item_id,b.count,b.created_at
           FROM bank_rows b LEFT JOIN duplicates d ON d.id=b.id
           LEFT JOIN free_slots f ON f.account_id=d.account_id AND f.storage=d.storage AND f.free_rank=d.relocation_rank
           WHERE b.duplicate_rank=1 OR f.n IS NOT NULL;
         INSERT INTO storage_capacity_v6(account_id,storage,slots)
           SELECT c.account_id, sc.storage, MAX(sc.slots) FROM storage_capacity sc
           JOIN character c ON c.id=sc.character_id GROUP BY c.account_id,sc.storage;
         INSERT OR IGNORE INTO storage_capacity_v6(account_id,storage,slots)
           SELECT a.id, 22, 24 FROM account a;
         INSERT OR IGNORE INTO storage_capacity_v6(account_id,storage,slots)
           SELECT a.id, 23, 48 FROM account a;
         INSERT OR IGNORE INTO storage_capacity_v6(account_id,storage,slots)
           SELECT a.id, 24, 384 FROM account a;
         UPDATE storage_capacity_v6 SET slots=MAX(slots,(
           SELECT COALESCE(MAX(i.slot)+1,0) FROM item_v6 i
           WHERE i.account_id=storage_capacity_v6.account_id AND i.storage=storage_capacity_v6.storage
         ));
         DROP TABLE item;
         ALTER TABLE item_v6 RENAME TO item;
         CREATE UNIQUE INDEX item_character_slot ON item(character_id,storage,slot) WHERE character_id IS NOT NULL;
         CREATE UNIQUE INDEX item_account_slot ON item(account_id,storage,slot) WHERE account_id IS NOT NULL;
         CREATE INDEX item_character ON item(character_id);
         CREATE INDEX item_account ON item(account_id);
         DROP TABLE storage_capacity;
         ALTER TABLE storage_capacity_v6 RENAME TO storage_capacity;
         ALTER TABLE character DROP COLUMN bank_zenny;
         PRAGMA user_version=6;",
    )?;
    for (account, balance) in bank_balances {
        if balance != 0 {
            tx.execute(
                "INSERT INTO bank_zenny(account_id,balance) VALUES (?1,?2)",
                params![account, balance.to_string()],
            )?;
        }
    }
    let broken: i64 = tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
    anyhow::ensure!(broken == 0, "schema v6 migration: {broken} foreign key violations");
    let old_seq = item_seq.unwrap_or(0);
    tx.execute("UPDATE sqlite_sequence SET seq=MAX(seq,?1) WHERE name='item'", [old_seq])?;
    tx.execute(
        "INSERT INTO sqlite_sequence(name,seq) SELECT 'item',?1 WHERE ?1>0
         AND NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='item')",
        [old_seq],
    )?;
    tx.commit()?;
    Ok(())
}

/// Result of a username/password check.
#[derive(Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    /// Existing account, password matched.
    Ok(u32),
    /// Name was free and `auto_register` is on: account created with this password.
    Registered(u32),
    WrongPassword,
    /// Name unknown and auto-registration is off.
    NoSuchAccount,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        if let Some(dir) = std::path::Path::new(path).parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let conn = Connection::open(path)?;
        // Connection settings: WAL, enforced foreign keys, wait instead of
        // failing when the file is briefly locked.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=5000;
             PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS account (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               name TEXT NOT NULL UNIQUE,
               created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
             );
             CREATE TABLE IF NOT EXISTS character (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               account_id INTEGER NOT NULL REFERENCES account(id),
               slot INTEGER NOT NULL,
               name TEXT NOT NULL UNIQUE,
               class INTEGER NOT NULL,
               level INTEGER NOT NULL DEFAULT 1,
               appearance BLOB,
               created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
             );",
        )?;
        // Older databases predate password hashes; add the column in place.
        let has_hash: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('account') WHERE name='password_hash'")?
            .exists([])?;
        if !has_hash {
            conn.execute_batch("ALTER TABLE account ADD COLUMN password_hash TEXT")?;
        }
        for (col, ddl) in [
            ("class_ref", "ALTER TABLE character ADD COLUMN class_ref INTEGER NOT NULL DEFAULT 0"),
            ("outfit", "ALTER TABLE character ADD COLUMN outfit INTEGER NOT NULL DEFAULT 0"),
        ] {
            let exists: bool = conn
                .prepare("SELECT 1 FROM pragma_table_info('character') WHERE name=?1")?
                .exists(params![col])?;
            if !exists {
                conn.execute_batch(ddl)?;
            }
        }
        let has_pin: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('account') WHERE name='second_pw_hash'")?
            .exists([])?;
        if !has_pin {
            conn.execute_batch("ALTER TABLE account ADD COLUMN second_pw_hash TEXT")?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS item (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               character_id INTEGER NOT NULL REFERENCES character(id),
               storage INTEGER NOT NULL,
               slot INTEGER NOT NULL,
               item_id INTEGER NOT NULL,
               count INTEGER NOT NULL DEFAULT 1,
               created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
               UNIQUE(character_id, storage, slot)
             );",
        )?;
        let has_seed: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('character') WHERE name='equip_seeded'")?
            .exists([])?;
        if !has_seed {
            // 0 = starter costume not yet written to the item table (storage 0).
            conn.execute_batch("ALTER TABLE character ADD COLUMN equip_seeded INTEGER NOT NULL DEFAULT 0")?;
        }
        let has_cash: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('account') WHERE name='cash'")?
            .exists([])?;
        if !has_cash {
            // NULL = never set: the first read gives the account the configured start cash.
            conn.execute_batch("ALTER TABLE account ADD COLUMN cash INTEGER")?;
        }
        let has_zenny: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('character') WHERE name='zenny'")?
            .exists([])?;
        if !has_zenny {
            // NULL = never set: the first read gives the character the start amount.
            conn.execute_batch("ALTER TABLE character ADD COLUMN zenny INTEGER")?;
        }
        let has_exp: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('character') WHERE name='exp'")?
            .exists([])?;
        if !has_exp {
            conn.execute_batch("ALTER TABLE character ADD COLUMN exp INTEGER NOT NULL DEFAULT 0")?;
        }
        // Maze currencies picked up from drops.
        for col in ["ether", "bp", "soul_vapor"] {
            let has: bool = conn
                .prepare(&format!("SELECT 1 FROM pragma_table_info('character') WHERE name='{col}'"))?
                .exists([])?;
            if !has {
                conn.execute_batch(&format!("ALTER TABLE character ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0"))?;
            }
        }
        // NPC shop buyback: what a character sold, newest last (the shop keeps
        // BUYBACK_MAX per character, like CGocInventory::PushRepurchaserItem).
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS buyback (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               character_id INTEGER NOT NULL REFERENCES character(id),
               serial INTEGER NOT NULL UNIQUE,
               item_id INTEGER NOT NULL,
               count INTEGER NOT NULL,
               storage INTEGER NOT NULL,
               price INTEGER NOT NULL
             );",
        )?;
        // Skill tree state (PS_SKILL_LOAD: learned skills with divergence,
        // deck slots of 4 skills, slot count, 4 deck bonus values).
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS skill (
               character_id INTEGER NOT NULL REFERENCES character(id),
               skill_group INTEGER NOT NULL,
               skill_id INTEGER NOT NULL,
               divergence INTEGER NOT NULL DEFAULT 0,
               PRIMARY KEY(character_id, skill_group)
             );
             CREATE TABLE IF NOT EXISTS skill_deck (
               character_id INTEGER NOT NULL REFERENCES character(id),
               pos INTEGER NOT NULL,
               s1 INTEGER NOT NULL, s2 INTEGER NOT NULL, s3 INTEGER NOT NULL, s4 INTEGER NOT NULL,
               PRIMARY KEY(character_id, pos)
             );",
        )?;
        for (col, ddl) in [
            ("deck_slots", "ALTER TABLE character ADD COLUMN deck_slots INTEGER NOT NULL DEFAULT 3"),
            ("deck_bonus", "ALTER TABLE character ADD COLUMN deck_bonus INTEGER NOT NULL DEFAULT 0"),
        ] {
            let exists: bool = conn
                .prepare("SELECT 1 FROM pragma_table_info('character') WHERE name=?1")?
                .exists(params![col])?;
            if !exists {
                conn.execute_batch(ddl)?;
            }
        }
        migrate_v2(&conn)?;
        migrate_v4(&conn)?;
        migrate_v5(&conn)?;
        migrate_v6(&conn)?;
        // Start account ids at 1000 like the reconstructed server's test account.
        conn.execute(
            "INSERT INTO sqlite_sequence(name, seq) SELECT 'account', 999
             WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='account')",
            [],
        )?;
        conn.execute("UPDATE sqlite_sequence SET seq = 999 WHERE name = 'account' AND seq < 999", [])?;
        Ok(Self { conn })
    }

    /// Schema version (PRAGMA user_version).
    pub fn schema_version(&self) -> Result<i64> {
        Ok(self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    /// Account-wide bank capacity, initialized to the protocol's base size.
    pub fn storage_capacity(&self, account: u32, storage: u8) -> Result<u16> {
        let default = match storage {
            22 => NORMAL_BANK_SLOTS,
            23 => COSTUME_BANK_SLOTS,
            24 => CASH_BANK_SLOTS,
            _ => return Ok(0),
        };
        self.conn.execute(
            "INSERT OR IGNORE INTO storage_capacity(account_id,storage,slots) VALUES (?1,?2,?3)",
            params![account, storage, default],
        )?;
        Ok(self.conn.query_row(
            "SELECT slots FROM storage_capacity WHERE account_id=?1 AND storage=?2",
            params![account, storage],
            |r| r.get(0),
        )?)
    }

    pub fn consume_storage_expansion(
        &self, account: u32, character: u32, source_storage: u8, target_storage: u8,
        selected: Option<(u64, u16)>, required_item_id: u32, required_count: u16, target_capacity: u16,
    ) -> Result<Option<(ItemRecord, u16)>> {
        let (base, maximum) = match target_storage {
            22 => (NORMAL_BANK_SLOTS, 384),
            23 => (COSTUME_BANK_SLOTS, 384),
            _ => return Ok(None),
        };
        if required_count == 0 || target_capacity <= base || target_capacity > maximum { return Ok(None); }
        let tx = self.conn.unchecked_transaction()?;
        if !tx.prepare("SELECT 1 FROM character WHERE id=?1 AND account_id=?2")?
            .exists(params![character, account])? { return Ok(None); }
        let row = tx.query_row(
            "SELECT id,slot,count FROM item WHERE character_id=?1 AND storage=?2 AND item_id=?3 AND count>=?4
             AND (?5 IS NULL OR id=?5) AND (?6 IS NULL OR slot=?6) ORDER BY slot LIMIT 1",
            params![character, source_storage, required_item_id, required_count,
                selected.map(|(serial, _)| serial as i64), selected.map(|(_, slot)| slot)],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, u16>(1)?, r.get::<_, u16>(2)?)),
        ).optional()?;
        let Some((serial, slot, count)) = row else { return Ok(None) };
        let current = tx.query_row(
            "SELECT slots FROM storage_capacity WHERE account_id=?1 AND storage=?2",
            params![account, target_storage], |r| r.get::<_, u16>(0),
        ).optional()?.unwrap_or(base);
        if target_capacity <= current { return Ok(None); }
        let left = count - required_count;
        if left == 0 {
            tx.execute("DELETE FROM item WHERE id=?1 AND character_id=?2", params![serial as i64, character])?;
        } else {
            tx.execute("UPDATE item SET count=?1 WHERE id=?2 AND character_id=?3", params![left, serial as i64, character])?;
        }
        tx.execute(
            "INSERT INTO storage_capacity(account_id,storage,slots) VALUES (?1,?2,?3)
             ON CONFLICT(account_id,storage) DO UPDATE SET slots=excluded.slots",
            params![account, target_storage, target_capacity],
        )?;
        tx.commit()?;
        Ok(Some((ItemRecord { serial, storage: source_storage, slot, item_id: required_item_id, count: left }, target_capacity)))
    }

    pub(crate) fn bank_zenny_balance(&self, account: u32) -> Result<u128> {
        let balance: Option<String> = self.conn.query_row(
            "SELECT balance FROM bank_zenny WHERE account_id=?1",
            params![account],
            |r| r.get(0),
        ).optional()?;
        Ok(balance.unwrap_or_else(|| "0".to_owned()).parse()?)
    }

    /// Single-player convenience used by the launcher-token path: any name is auto-registered.
    pub fn login_or_register(&self, name: &str) -> Result<u32> {
        if let Some(id) = self.account_id(name)? {
            return Ok(id);
        }
        self.conn.execute("INSERT INTO account(name) VALUES (?1)", params![name])?;
        Ok(self.conn.last_insert_rowid() as u32)
    }

    fn account_id(&self, name: &str) -> Result<Option<u32>> {
        Ok(self
            .conn
            .query_row("SELECT id FROM account WHERE name=?1", params![name], |r| r.get::<_, u32>(0))
            .optional()?)
    }

    /// Verify (or, on first use, set) the account password. Hashes are Argon2id
    /// PHC strings; the cleartext never touches the database.
    pub fn login_with_password(&self, name: &str, password: &str, auto_register: bool) -> Result<LoginOutcome> {
        let row = self
            .conn
            .query_row("SELECT id, password_hash FROM account WHERE name=?1", params![name], |r| {
                Ok((r.get::<_, u32>(0)?, r.get::<_, Option<String>>(1)?))
            })
            .optional()?;
        match row {
            Some((id, Some(stored))) => {
                let parsed = PasswordHash::new(&stored).map_err(|e| anyhow::anyhow!("stored hash for {name}: {e}"))?;
                Ok(if Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok() {
                    LoginOutcome::Ok(id)
                } else {
                    LoginOutcome::WrongPassword
                })
            }
            // Account created by the launcher path before passwords existed: first
            // password login claims it.
            Some((id, None)) => {
                self.set_password(id, password)?;
                Ok(LoginOutcome::Registered(id))
            }
            None if auto_register => {
                let hash = hash_password(password)?;
                self.conn.execute("INSERT INTO account(name, password_hash) VALUES (?1, ?2)", params![name, hash])?;
                Ok(LoginOutcome::Registered(self.conn.last_insert_rowid() as u32))
            }
            None => Ok(LoginOutcome::NoSuchAccount),
        }
    }

    fn set_password(&self, id: u32, password: &str) -> Result<()> {
        let hash = hash_password(password)?;
        self.conn.execute("UPDATE account SET password_hash=?1 WHERE id=?2", params![hash, id])?;
        Ok(())
    }

    /// Characters of one account, ordered by slot.
    pub fn characters(&self, account: u32) -> Result<Vec<CharacterRecord>> {
        let mut st = self.conn.prepare(
            "SELECT id, slot, name, class, level, appearance, class_ref, outfit
             FROM character WHERE account_id=?1 ORDER BY slot",
        )?;
        let rows = st.query_map(params![account], |r| {
            let app: Option<Vec<u8>> = r.get(5)?;
            Ok(CharacterRecord {
                id: r.get(0)?,
                slot: r.get(1)?,
                name: r.get(2)?,
                class: r.get(3)?,
                level: r.get(4)?,
                appearance: decode_appearance(app.as_deref()),
                class_ref: r.get(6)?,
                outfit: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn character_count(&self, account: u32) -> Result<u32> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM character WHERE account_id=?1", params![account], |r| r.get(0))?)
    }

    /// Create a character in `wanted_slot` (1-based) or, if that slot is used,
    /// the lowest free slot up to `max_slots`. Names are unique server-wide,
    /// compared case-insensitively.
    pub fn create_character(&self, account: u32, c: &NewCharacter<'_>, wanted_slot: u8, max_slots: u8) -> Result<CreateOutcome> {
        let tx = self.conn.unchecked_transaction()?;
        let taken: bool = tx.prepare("SELECT 1 FROM character WHERE lower(name)=lower(?1)")?.exists(params![c.name])?;
        if taken {
            return Ok(CreateOutcome::NameTaken);
        }
        let used: Vec<u8> = tx
            .prepare("SELECT slot FROM character WHERE account_id=?1")?
            .query_map(params![account], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let free = |s: u8| (1..=max_slots).contains(&s) && !used.contains(&s);
        let Some(slot) = Some(wanted_slot).filter(|&s| free(s)).or_else(|| (1..=max_slots).find(|&s| free(s))) else {
            return Ok(CreateOutcome::NoFreeSlot);
        };
        let app: Vec<u8> = c.appearance.iter().flat_map(|v| v.to_le_bytes()).collect();
        tx.execute(
            "INSERT INTO character(account_id, slot, name, class, level, appearance, class_ref, outfit)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)",
            params![account, slot, c.name, c.class, app, c.class_ref, c.outfit],
        )?;
        let id = tx.last_insert_rowid() as u32;
        tx.commit()?;
        Ok(CreateOutcome::Created { id, slot })
    }

    /// Delete one of the account's own characters (and its items). False if it is not theirs.
    pub fn delete_character(&self, account: u32, id: u32) -> Result<bool> {
        let tx = self.conn.unchecked_transaction()?;
        let owned: bool = tx.prepare("SELECT 1 FROM character WHERE id=?1 AND account_id=?2")?.exists(params![id, account])?;
        if !owned {
            return Ok(false);
        }
        // Child rows first (ON DELETE CASCADE would do it too; explicit so a
        // database opened without foreign_keys stays clean).
        for table in ["item", "buyback", "skill", "skill_deck"] {
            tx.execute(&format!("DELETE FROM {table} WHERE character_id=?1"), params![id])?;
        }
        tx.execute("DELETE FROM character WHERE id=?1", params![id])?;
        tx.commit()?;
        Ok(true)
    }

    /// Account cash; an account that never had a balance gets `start`.
    pub fn cash(&self, account: u32, start: u32) -> Result<u32> {
        let v: Option<i64> = self
            .conn
            .query_row("SELECT cash FROM account WHERE id=?1", params![account], |r| r.get(0))
            .optional()?
            .flatten();
        Ok(match v {
            Some(v) => v.clamp(0, u32::MAX as i64) as u32,
            None => {
                self.conn.execute("UPDATE account SET cash=?1 WHERE id=?2", params![start, account])?;
                start
            }
        })
    }

    /// Take `amount` cash; false (and nothing changes) if the balance is too low.
    pub fn spend_cash(&self, account: u32, amount: u32, start: u32) -> Result<bool> {
        self.cash(account, start)?;
        let n = self.conn.execute(
            "UPDATE account SET cash = cash - ?1 WHERE id=?2 AND cash >= ?1",
            params![amount, account],
        )?;
        Ok(n == 1)
    }

    /// Use one of an item (by serial): delete it or lower its count, then put
    /// `gain` (item, count, storage, capacity) into free slots. All or nothing.
    /// Returns (the used item with its remaining count, the added items), or
    /// None if the item is not the character's or the bags are full.
    pub fn use_item(&self, character: u32, serial: u64, gain: &[(u32, u16, u8, u16)]) -> Result<Option<(ItemRecord, Vec<ItemRecord>)>> {
        let tx = self.conn.unchecked_transaction()?;
        let row = tx
            .query_row(
                "SELECT storage, slot, item_id, count FROM item WHERE id=?1 AND character_id=?2",
                params![serial as i64, character],
                |r| Ok((r.get::<_, u8>(0)?, r.get::<_, u16>(1)?, r.get::<_, u32>(2)?, r.get::<_, u16>(3)?)),
            )
            .optional()?;
        let Some((storage, slot, item_id, count)) = row else { return Ok(None) };
        let left = count.saturating_sub(1);
        if left == 0 {
            tx.execute("DELETE FROM item WHERE id=?1", params![serial as i64])?;
        } else {
            tx.execute("UPDATE item SET count=?1 WHERE id=?2", params![left, serial as i64])?;
        }
        let mut added = Vec::with_capacity(gain.len());
        for &(gid, gcount, gstorage, capacity) in gain {
            let used: std::collections::HashSet<u16> = tx
                .prepare("SELECT slot FROM item WHERE character_id=?1 AND storage=?2")?
                .query_map(params![character, gstorage], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let Some(gslot) = (0..capacity).find(|s| !used.contains(s)) else { return Ok(None) };
            tx.execute(
                "INSERT INTO item(character_id, storage, slot, item_id, count) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![character, gstorage, gslot, gid, gcount],
            )?;
            added.push(ItemRecord { serial: tx.last_insert_rowid() as u64, storage: gstorage, slot: gslot, item_id: gid, count: gcount });
        }
        tx.commit()?;
        Ok(Some((ItemRecord { serial, storage, slot, item_id, count: left }, added)))
    }

    /// Write the starter costume (shape slot -> item) as worn items, once per
    /// character. Afterwards the worn look comes only from the item table.
    pub fn seed_equipment(&self, character: u32, worn: &[(u16, u32)]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let n = tx.execute("UPDATE character SET equip_seeded=1 WHERE id=?1 AND equip_seeded=0", params![character])?;
        if n == 1 {
            for &(slot, item) in worn {
                tx.execute(
                    "INSERT OR IGNORE INTO item(character_id, storage, slot, item_id, count) VALUES (?1, 0, ?2, ?3, 1)",
                    params![character, slot, item],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Put the class's starter soul weapon into the weapon slot if it has
    /// nothing there (new characters, and ones made before weapons were items).
    /// Moves never empty that slot, so this runs once per character.
    pub fn ensure_weapon(&self, character: u32, slot: (u8, u16), weapon: u32) -> Result<()> {
        if weapon != 0 {
            self.conn.execute(
                "INSERT OR IGNORE INTO item(character_id, storage, slot, item_id, count) VALUES (?1, ?2, ?3, ?4, 1)",
                params![character, slot.0, slot.1, weapon],
            )?;
        }
        Ok(())
    }

    /// Swap the contents of two slots (either may be empty) if `allowed`
    /// accepts each item at its new place. Returns the two slots' items after
    /// the attempt (src, dest); unchanged when refused.
    pub fn move_item(
        &self,
        account: u32,
        character: u32,
        src: (u8, u16),
        dest: (u8, u16),
        allowed: impl Fn(u32, u8, u16) -> bool,
        keep_filled: &[(u8, u16)],
    ) -> Result<(Option<ItemRecord>, Option<ItemRecord>, bool)> {
        let tx = self.conn.unchecked_transaction()?;
        if !tx.prepare("SELECT 1 FROM character WHERE id=?1 AND account_id=?2")?
            .exists(params![character, account])?
        {
            return Ok((None, None, false));
        }
        let at = |(storage, slot): (u8, u16)| -> Result<Option<ItemRecord>> {
            let bank = (22..=24).contains(&storage);
            Ok(tx.query_row(
                "SELECT id,item_id,count FROM item WHERE storage=?1 AND slot=?2 AND
                 ((?3=1 AND account_id=?4 AND character_id IS NULL) OR
                  (?3=0 AND character_id=?5 AND account_id IS NULL))",
                params![storage, slot, bank, account, character],
                |row| Ok(ItemRecord {
                    serial: row.get::<_, i64>(0)? as u64,
                    storage,
                    slot,
                    item_id: row.get(1)?,
                    count: row.get(2)?,
                }),
            ).optional()?)
        };
        let (a, b) = (at(src)?, at(dest)?);
        let empties_kept =
            (keep_filled.contains(&src) && b.is_none()) || (keep_filled.contains(&dest) && a.is_none());
        let ok = src != dest && !empties_kept && a.is_some()
            && a.map_or(true, |item| allowed(item.item_id, dest.0, dest.1))
            && b.map_or(true, |item| allowed(item.item_id, src.0, src.1));
        if !ok {
            return Ok((a, b, false));
        }
        let owner = |storage: u8| -> (Option<u32>, Option<u32>) {
            if (22..=24).contains(&storage) { (None, Some(account)) } else { (Some(character), None) }
        };
        let park = |serial: u64, storage: u8, slot: i64| -> Result<()> {
            let (character_id, account_id) = owner(storage);
            tx.execute(
                "UPDATE item SET character_id=?1,account_id=?2,storage=?3,slot=?4 WHERE id=?5",
                params![character_id, account_id, storage, slot, serial as i64],
            )?;
            Ok(())
        };
        let a = a.unwrap();
        park(a.serial, src.0, i64::MAX)?;
        if let Some(item) = b {
            park(item.serial, src.0, src.1 as i64)?;
        }
        park(a.serial, dest.0, dest.1 as i64)?;
        tx.commit()?;
        let moved_b = b.map(|item| ItemRecord { storage: src.0, slot: src.1, ..item });
        Ok((moved_b, Some(ItemRecord { storage: dest.0, slot: dest.1, ..a }), true))
    }

    pub fn bank_items(&self, account: u32) -> Result<Vec<ItemRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id,storage,slot,item_id,count FROM item
             WHERE account_id=?1 AND character_id IS NULL ORDER BY storage,slot",
        )?;
        let rows = statement.query_map(params![account], |row| Ok(ItemRecord {
            serial: row.get::<_, i64>(0)? as u64,
            storage: row.get(1)?,
            slot: row.get(2)?,
            item_id: row.get(3)?,
            count: row.get(4)?,
        }))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn bank_item_at(&self, account: u32, storage: u8, slot: u16) -> Result<Option<ItemRecord>> {
        Ok(self.conn.query_row(
            "SELECT id,item_id,count FROM item WHERE account_id=?1 AND character_id IS NULL AND storage=?2 AND slot=?3",
            params![account, storage, slot],
            |row| Ok(ItemRecord {
                serial: row.get::<_, i64>(0)? as u64,
                storage,
                slot,
                item_id: row.get(1)?,
                count: row.get(2)?,
            }),
        ).optional()?)
    }

    pub fn divide_bank_item(
        &self, account: u32, storage: u8, src_slot: u16, dest_slot: u16, count: u16,
        allowed: impl Fn(u32, u8, u16) -> bool,
    ) -> Result<Option<(ItemRecord, ItemRecord)>> {
        if !(22..=24).contains(&storage) { return Ok(None); }
        let capacity = self.storage_capacity(account, storage)?;
        if src_slot >= capacity || dest_slot >= capacity || src_slot == dest_slot { return Ok(None); }
        let Some(src) = self.bank_item_at(account, storage, src_slot)? else { return Ok(None) };
        if count == 0 || count >= src.count || self.bank_item_at(account, storage, dest_slot)?.is_some()
            || !allowed(src.item_id, storage, dest_slot) { return Ok(None); }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("UPDATE item SET count=?1 WHERE id=?2 AND account_id=?3 AND character_id IS NULL",
            params![src.count - count, src.serial as i64, account])?;
        tx.execute("INSERT INTO item(character_id,account_id,storage,slot,item_id,count) VALUES(NULL,?1,?2,?3,?4,?5)",
            params![account, storage, dest_slot, src.item_id, count])?;
        let added = ItemRecord { serial: tx.last_insert_rowid() as u64, storage, slot: dest_slot, item_id: src.item_id, count };
        tx.commit()?;
        Ok(Some((ItemRecord { count: src.count - count, ..src }, added)))
    }

    pub fn combine_bank_items(
        &self, account: u32, storage: u8, src_slot: u16, dest_slot: u16, count: u16, stack: u16,
    ) -> Result<Option<(ItemRecord, ItemRecord)>> {
        if !(22..=24).contains(&storage) || src_slot == dest_slot { return Ok(None); }
        let capacity = self.storage_capacity(account, storage)?;
        if src_slot >= capacity || dest_slot >= capacity { return Ok(None); }
        let (Some(src), Some(dest)) = (
            self.bank_item_at(account, storage, src_slot)?, self.bank_item_at(account, storage, dest_slot)?,
        ) else { return Ok(None) };
        let moved = (if count == 0 { src.count } else { count.min(src.count) })
            .min(stack.saturating_sub(dest.count));
        if src.item_id != dest.item_id || moved == 0 { return Ok(None); }
        let tx = self.conn.unchecked_transaction()?;
        if moved == src.count {
            tx.execute("DELETE FROM item WHERE id=?1 AND account_id=?2 AND character_id IS NULL", params![src.serial as i64, account])?;
        } else {
            tx.execute("UPDATE item SET count=?1 WHERE id=?2 AND account_id=?3 AND character_id IS NULL",
                params![src.count - moved, src.serial as i64, account])?;
        }
        tx.execute("UPDATE item SET count=?1 WHERE id=?2 AND account_id=?3 AND character_id IS NULL",
            params![dest.count + moved, dest.serial as i64, account])?;
        tx.commit()?;
        Ok(Some((ItemRecord { count: src.count - moved, ..src }, ItemRecord { count: dest.count + moved, ..dest })))
    }

    pub fn line_up_bank(&self, account: u32, storage: u8) -> Result<Vec<ItemRecord>> {
        if !(22..=24).contains(&storage) { anyhow::bail!("invalid bank storage {storage}"); }
        let tx = self.conn.unchecked_transaction()?;
        let mut items = {
            let mut statement = tx.prepare(
                "SELECT id,storage,slot,item_id,count FROM item
                 WHERE account_id=?1 AND character_id IS NULL AND storage=?2 ORDER BY item_id,id",
            )?;
            let rows = statement.query_map(params![account, storage], |row| Ok(ItemRecord {
                serial: row.get::<_, i64>(0)? as u64, storage: row.get(1)?, slot: row.get(2)?,
                item_id: row.get(3)?, count: row.get(4)?,
            }))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let max_slot: Option<i64> = tx.query_row(
            "SELECT MAX(slot) FROM item WHERE account_id=?1 AND character_id IS NULL AND storage=?2",
            params![account, storage], |row| row.get(0),
        )?;
        let mut temporary = max_slot.unwrap_or(-1).checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("bank slot range exhausted"))?;
        for (index, item) in items.iter().enumerate() {
            tx.execute("UPDATE item SET slot=?1 WHERE id=?2 AND account_id=?3 AND character_id IS NULL AND storage=?4",
                params![temporary, item.serial as i64, account, storage])?;
            if index + 1 < items.len() {
                temporary = temporary.checked_add(1).ok_or_else(|| anyhow::anyhow!("bank slot range exhausted"))?;
            }
        }
        for (slot, item) in items.iter_mut().enumerate() {
            item.slot = slot as u16;
            tx.execute("UPDATE item SET slot=?1 WHERE id=?2 AND account_id=?3 AND character_id IS NULL AND storage=?4",
                params![item.slot, item.serial as i64, account, storage])?;
        }
        tx.commit()?;
        Ok(items)
    }

    /// Items of a character, ordered by storage and slot.
    pub fn items(&self, character: u32) -> Result<Vec<ItemRecord>> {
        let mut st = self.conn.prepare(
            "SELECT id, storage, slot, item_id, count FROM item WHERE character_id=?1 ORDER BY storage, slot",
        )?;
        let rows = st.query_map(params![character], |r| {
            Ok(ItemRecord { serial: r.get::<_, i64>(0)? as u64, storage: r.get(1)?, slot: r.get(2)?, item_id: r.get(3)?, count: r.get(4)? })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Put each (item, count) into the lowest free slot of `storage` (slots
    /// 0..capacity). All or nothing: None if there is not enough room.
    pub fn add_items(&self, character: u32, storage: u8, capacity: u16, items: &[(u32, u16)]) -> Result<Option<Vec<ItemRecord>>> {
        let tx = self.conn.unchecked_transaction()?;
        let used: std::collections::HashSet<u16> = tx
            .prepare("SELECT slot FROM item WHERE character_id=?1 AND storage=?2")?
            .query_map(params![character, storage], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut free = (0..capacity).filter(|s| !used.contains(s));
        let mut added = Vec::with_capacity(items.len());
        for &(item_id, count) in items {
            let Some(slot) = free.next() else { return Ok(None) };
            tx.execute(
                "INSERT INTO item(character_id, storage, slot, item_id, count) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![character, storage, slot, item_id, count],
            )?;
            added.push(ItemRecord { serial: tx.last_insert_rowid() as u64, storage, slot, item_id, count });
        }
        tx.commit()?;
        Ok(Some(added))
    }

    pub fn account_name(&self, account: u32) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT name FROM account WHERE id=?1", params![account], |r| r.get(0)).optional()?)
    }

    /// Character Zenny; a character that never had a balance gets `start`.
    pub fn zenny(&self, character: u32, start: u64) -> Result<u64> {
        let z: Option<i64> = self
            .conn
            .query_row("SELECT zenny FROM character WHERE id=?1", params![character], |r| r.get(0))
            .optional()?
            .flatten();
        match z {
            Some(z) => Ok(z.max(0) as u64),
            None => {
                self.conn.execute("UPDATE character SET zenny=?1 WHERE id=?2", params![start as i64, character])?;
                Ok(start)
            }
        }
    }

    pub fn transfer_bank_zenny(
        &self, account: u32, character: u32, direction: BankZennyDirection, amount: u64, start_wallet: u64,
    ) -> Result<Option<(u64, u128)>> {
        if amount == 0 || start_wallet > i64::MAX as u64 { return Ok(None); }
        let tx = self.conn.unchecked_transaction()?;
        let balances: Option<(Option<i64>, Option<String>)> = tx.query_row(
            "SELECT c.zenny,b.balance FROM character c LEFT JOIN bank_zenny b ON b.account_id=c.account_id
             WHERE c.id=?1 AND c.account_id=?2",
            params![character, account], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let Some((wallet, bank)) = balances else { return Ok(None) };
        let wallet = wallet.unwrap_or(start_wallet as i64).max(0) as u64;
        let bank = bank.as_deref().unwrap_or("0").parse::<u128>()?;
        let (new_wallet, new_bank) = match direction {
            BankZennyDirection::Deposit if wallet >= amount => {
                let Some(next) = bank.checked_add(amount as u128) else { return Ok(None) };
                if next > u64::MAX as u128 { return Ok(None); }
                (wallet - amount, next)
            }
            BankZennyDirection::Withdraw if bank >= amount as u128 => {
                let Some(next) = wallet.checked_add(amount) else { return Ok(None) };
                if next > i64::MAX as u64 { return Ok(None); }
                (next, bank - amount as u128)
            }
            _ => return Ok(None),
        };
        tx.execute("UPDATE character SET zenny=?1 WHERE id=?2", params![new_wallet as i64, character])?;
        tx.execute(
            "INSERT INTO bank_zenny(account_id,balance) VALUES (?1,?2)
             ON CONFLICT(account_id) DO UPDATE SET balance=excluded.balance",
            params![account, new_bank.to_string()],
        )?;
        tx.commit()?;
        Ok(Some((new_wallet, new_bank)))
    }

    /// Set a character's level (GM command); EXP into the level starts at 0.
    pub fn set_level(&self, character: u32, level: u8) -> Result<()> {
        self.conn.execute("UPDATE character SET level=?1, exp=0 WHERE id=?2", params![level, character])?;
        Ok(())
    }

    /// Add a maze currency (drop object 800000002 soul vapor, ..03 BP, ..04
    /// ether) and return the new total.
    pub fn add_currency(&self, character: u32, object: u32, n: u64) -> Result<u64> {
        let col = match object {
            800_000_002 => "soul_vapor",
            800_000_003 => "bp",
            _ => "ether",
        };
        self.conn.execute(&format!("UPDATE character SET {col}={col}+?1 WHERE id=?2"), params![n as i64, character])?;
        let v: i64 = self.conn.query_row(&format!("SELECT {col} FROM character WHERE id=?1"), params![character], |r| r.get(0))?;
        Ok(v.max(0) as u64)
    }

    /// (ether, BP).
    pub fn currencies(&self, character: u32) -> Result<(u64, u64)> {
        let (e, b): (i64, i64) =
            self.conn.query_row("SELECT ether, bp FROM character WHERE id=?1", params![character], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok((e.max(0) as u64, b.max(0) as u64))
    }

    /// (level, EXP into that level).
    pub fn level_exp(&self, character: u32) -> Result<(u8, u64)> {
        let (lv, exp): (i64, i64) = self
            .conn
            .query_row("SELECT level, exp FROM character WHERE id=?1", params![character], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok((lv.clamp(1, 255) as u8, exp.max(0) as u64))
    }

    /// Learned skills: (group, skill id, divergence).
    pub fn skills(&self, character: u32) -> Result<Vec<(u32, u32, u32)>> {
        let mut st = self
            .conn
            .prepare("SELECT skill_group, skill_id, divergence FROM skill WHERE character_id=?1 ORDER BY skill_group")?;
        let rows = st.query_map(params![character], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn set_skill(&self, character: u32, group: u32, skill: u32, divergence: u32) -> Result<()> {
        self.conn.execute(
            "INSERT INTO skill(character_id, skill_group, skill_id, divergence) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(character_id, skill_group) DO UPDATE SET skill_id=?3, divergence=?4",
            params![character, group, skill, divergence],
        )?;
        Ok(())
    }

    pub fn clear_skills(&self, character: u32) -> Result<()> {
        self.conn.execute("DELETE FROM skill WHERE character_id=?1", params![character])?;
        self.conn.execute("DELETE FROM skill_deck WHERE character_id=?1", params![character])?;
        Ok(())
    }

    /// Skill deck rows: (position, 4 skill ids).
    pub fn skill_decks(&self, character: u32) -> Result<Vec<(u16, [u32; 4])>> {
        let mut st = self
            .conn
            .prepare("SELECT pos, s1, s2, s3, s4 FROM skill_deck WHERE character_id=?1 ORDER BY pos")?;
        let rows = st.query_map(params![character], |r| Ok((r.get(0)?, [r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?])))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn set_skill_deck(&self, character: u32, pos: u16, s: [u32; 4]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO skill_deck(character_id, pos, s1, s2, s3, s4) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(character_id, pos) DO UPDATE SET s1=?3, s2=?4, s3=?5, s4=?6",
            params![character, pos, s[0], s[1], s[2], s[3]],
        )?;
        Ok(())
    }

    /// (deck slot count, 4 deck bonus values packed 16 bits each).
    pub fn deck_meta(&self, character: u32) -> Result<(u16, [u16; 4])> {
        let (slots, bonus): (i64, i64) = self.conn.query_row(
            "SELECT deck_slots, deck_bonus FROM character WHERE id=?1",
            params![character],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let b = bonus as u64;
        Ok((slots.clamp(0, 6) as u16, [b as u16, (b >> 16) as u16, (b >> 32) as u16, (b >> 48) as u16]))
    }

    pub fn set_deck_meta(&self, character: u32, slots: u16, bonus: [u16; 4]) -> Result<()> {
        let b = u64::from(bonus[0]) | u64::from(bonus[1]) << 16 | u64::from(bonus[2]) << 32 | u64::from(bonus[3]) << 48;
        self.conn.execute(
            "UPDATE character SET deck_slots=?1, deck_bonus=?2 WHERE id=?3",
            params![slots, b as i64, character],
        )?;
        Ok(())
    }

    pub fn set_level_exp(&self, character: u32, level: u8, exp: u64) -> Result<()> {
        self.conn.execute("UPDATE character SET level=?1, exp=?2 WHERE id=?3", params![level, exp as i64, character])?;
        Ok(())
    }

    /// Set a character's Zenny (GM command).
    pub fn set_zenny(&self, character: u32, zenny: u64) -> Result<()> {
        self.conn.execute("UPDATE character SET zenny=?1 WHERE id=?2", params![zenny.min(i64::MAX as u64) as i64, character])?;
        Ok(())
    }

    /// NPC shop purchase: `count` of `item` into `storage` (topping up stacks of
    /// the same item up to `stack`, then the lowest free slots), paying `cost`
    /// Zenny. All or nothing. Returns the changed items and the new balance.
    pub fn shop_buy(&self, character: u32, buy: &ShopPurchase, start: u64) -> Result<ShopBuyOutcome> {
        let have = self.zenny(character, start)?;
        if have < buy.cost {
            return Ok(ShopBuyOutcome::NotEnoughZenny);
        }
        let tx = self.conn.unchecked_transaction()?;
        let mut left = u32::from(buy.count);
        let stack = u32::from(buy.stack.max(1));
        let mut changed = Vec::new();
        let rows: Vec<(i64, u16, u16)> = tx
            .prepare("SELECT id, slot, count FROM item WHERE character_id=?1 AND storage=?2 AND item_id=?3 ORDER BY slot")?
            .query_map(params![character, buy.storage, buy.item], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, slot, count) in rows {
            let room = stack.saturating_sub(u32::from(count)).min(left);
            if room == 0 {
                continue;
            }
            let n = count + room as u16;
            tx.execute("UPDATE item SET count=?1 WHERE id=?2", params![n, id])?;
            changed.push(ItemRecord { serial: id as u64, storage: buy.storage, slot, item_id: buy.item, count: n });
            left -= room;
            if left == 0 {
                break;
            }
        }
        if left > 0 {
            let used: std::collections::HashSet<u16> = tx
                .prepare("SELECT slot FROM item WHERE character_id=?1 AND storage=?2")?
                .query_map(params![character, buy.storage], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let mut free = (0..buy.capacity).filter(|s| !used.contains(s));
            while left > 0 {
                let Some(slot) = free.next() else { return Ok(ShopBuyOutcome::BagFull) };
                let n = left.min(stack) as u16;
                tx.execute(
                    "INSERT INTO item(character_id, storage, slot, item_id, count) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![character, buy.storage, slot, buy.item, n],
                )?;
                changed.push(ItemRecord { serial: tx.last_insert_rowid() as u64, storage: buy.storage, slot, item_id: buy.item, count: n });
                left -= u32::from(n);
            }
        }
        let balance = have - buy.cost;
        tx.execute("UPDATE character SET zenny=?1 WHERE id=?2", params![balance as i64, character])?;
        tx.commit()?;
        Ok(ShopBuyOutcome::Bought { changed, balance })
    }

    /// Sell whole stacks at (storage, slot) for `price(item) x count` Zenny.
    /// Only `sellable` storages count; unknown slots are skipped. Returns the
    /// emptied slots (count 0) and the new balance.
    pub fn shop_sell(
        &self,
        character: u32,
        slots: &[(u8, u16)],
        sellable: impl Fn(u8) -> bool,
        price: impl Fn(u32) -> u64,
        start: u64,
    ) -> Result<(Vec<ItemRecord>, u64)> {
        let have = self.zenny(character, start)?;
        let tx = self.conn.unchecked_transaction()?;
        let mut sold = Vec::new();
        let mut gain = 0u64;
        for &(st, sl) in slots {
            if !sellable(st) {
                continue;
            }
            let row = tx
                .query_row(
                    "SELECT id, item_id, count FROM item WHERE character_id=?1 AND storage=?2 AND slot=?3",
                    params![character, st, sl],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, u32>(1)?, r.get::<_, u16>(2)?)),
                )
                .optional()?;
            let Some((id, item_id, count)) = row else { continue };
            tx.execute("DELETE FROM item WHERE id=?1", params![id])?;
            let paid = price(item_id).saturating_mul(u64::from(count));
            gain = gain.saturating_add(paid);
            sold.push(ItemRecord { serial: id as u64, storage: st, slot: sl, item_id, count: 0 });
            tx.execute(
                "INSERT INTO buyback(character_id, serial, item_id, count, storage, price) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![character, id, item_id, count, st, paid.min(i64::MAX as u64) as i64],
            )?;
        }
        // Keep the newest BUYBACK_MAX entries.
        tx.execute(
            "DELETE FROM buyback WHERE character_id=?1 AND id NOT IN \
             (SELECT id FROM buyback WHERE character_id=?1 ORDER BY id DESC LIMIT ?2)",
            params![character, BUYBACK_MAX as i64],
        )?;
        let balance = have.saturating_add(gain);
        tx.execute("UPDATE character SET zenny=?1 WHERE id=?2", params![balance.min(i64::MAX as u64) as i64, character])?;
        tx.commit()?;
        Ok((sold, balance))
    }

    /// Buyback list, oldest first. `serial` is the sold item's own serial: the
    /// client sends it back in 9/0x04 and, after the reply, drops the buyback
    /// entry whose serial equals the returned item's, so it must not change.
    /// `storage` is the bag it was sold from.
    pub fn buyback(&self, character: u32) -> Result<Vec<ItemRecord>> {
        let mut st = self
            .conn
            .prepare("SELECT serial, item_id, count, storage FROM buyback WHERE character_id=?1 ORDER BY id")?;
        let rows = st.query_map(params![character], |r| {
            Ok(ItemRecord { serial: r.get::<_, i64>(0)? as u64, item_id: r.get(1)?, count: r.get(2)?, storage: r.get(3)?, slot: 0 })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Buy back a sold stack (by its serial) for what it was sold for, into
    /// the lowest free slot of the bag it came from (`capacity(storage)`
    /// slots). The item gets its old serial back.
    pub fn repurchase(&self, character: u32, serial: u64, capacity: impl Fn(u8) -> u16, start: u64) -> Result<RepurchaseOutcome> {
        let row = self
            .conn
            .query_row(
                "SELECT item_id, count, storage, price FROM buyback WHERE serial=?1 AND character_id=?2",
                params![serial as i64, character],
                |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u16>(1)?, r.get::<_, u8>(2)?, r.get::<_, i64>(3)?)),
            )
            .optional()?;
        let Some((item_id, count, storage, price)) = row else { return Ok(RepurchaseOutcome::NotFound) };
        let price = price.max(0) as u64;
        let have = self.zenny(character, start)?;
        if have < price {
            return Ok(RepurchaseOutcome::NotEnoughZenny);
        }
        let tx = self.conn.unchecked_transaction()?;
        let used: std::collections::HashSet<u16> = tx
            .prepare("SELECT slot FROM item WHERE character_id=?1 AND storage=?2")?
            .query_map(params![character, storage], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let Some(slot) = (0..capacity(storage)).find(|s| !used.contains(s)) else { return Ok(RepurchaseOutcome::BagFull) };
        tx.execute(
            "INSERT INTO item(id, character_id, storage, slot, item_id, count) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![serial as i64, character, storage, slot, item_id, count],
        )?;
        let item = ItemRecord { serial, storage, slot, item_id, count };
        tx.execute("DELETE FROM buyback WHERE serial=?1", params![serial as i64])?;
        let balance = have - price;
        tx.execute("UPDATE character SET zenny=?1 WHERE id=?2", params![balance as i64, character])?;
        tx.commit()?;
        Ok(RepurchaseOutcome::Bought { item, balance, price })
    }

    fn item_at(&self, character: u32, (st, sl): (u8, u16)) -> Result<Option<ItemRecord>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, item_id, count FROM item WHERE character_id=?1 AND storage=?2 AND slot=?3",
                params![character, st, sl],
                |r| Ok(ItemRecord { serial: r.get::<_, i64>(0)? as u64, storage: st, slot: sl, item_id: r.get(1)?, count: r.get(2)? }),
            )
            .optional()?)
    }

    /// Split `count` off the stack at `src` into the empty slot `dest` (same
    /// item; `allowed` checks the new place). Returns (src after, new stack).
    pub fn divide_item(
        &self,
        character: u32,
        src: (u8, u16),
        dest: (u8, u16),
        count: u16,
        allowed: impl Fn(u32, u8, u16) -> bool,
    ) -> Result<Option<(ItemRecord, ItemRecord)>> {
        let Some(a) = self.item_at(character, src)? else { return Ok(None) };
        if count == 0 || count >= a.count || src == dest || self.item_at(character, dest)?.is_some() || !allowed(a.item_id, dest.0, dest.1) {
            return Ok(None);
        }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("UPDATE item SET count=?1 WHERE id=?2", params![a.count - count, a.serial as i64])?;
        tx.execute(
            "INSERT INTO item(character_id, storage, slot, item_id, count) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![character, dest.0, dest.1, a.item_id, count],
        )?;
        let b = ItemRecord { serial: tx.last_insert_rowid() as u64, storage: dest.0, slot: dest.1, item_id: a.item_id, count };
        tx.commit()?;
        Ok(Some((ItemRecord { count: a.count - count, ..a }, b)))
    }

    /// Move `count` from the stack at `src` onto the same item's stack at
    /// `dest`, up to `stack`. Returns (src after, count 0 = gone; dest after).
    pub fn combine_items(&self, character: u32, src: (u8, u16), dest: (u8, u16), count: u16, stack: u16) -> Result<Option<(ItemRecord, ItemRecord)>> {
        let (Some(a), Some(b)) = (self.item_at(character, src)?, self.item_at(character, dest)?) else { return Ok(None) };
        let n = if count == 0 { a.count } else { count.min(a.count) };
        let n = n.min(stack.saturating_sub(b.count));
        if src == dest || a.item_id != b.item_id || n == 0 {
            return Ok(None);
        }
        let tx = self.conn.unchecked_transaction()?;
        if n == a.count {
            tx.execute("DELETE FROM item WHERE id=?1", params![a.serial as i64])?;
        } else {
            tx.execute("UPDATE item SET count=?1 WHERE id=?2", params![a.count - n, a.serial as i64])?;
        }
        tx.execute("UPDATE item SET count=?1 WHERE id=?2", params![b.count + n, b.serial as i64])?;
        tx.commit()?;
        Ok(Some((ItemRecord { count: a.count - n, ..a }, ItemRecord { count: b.count + n, ..b })))
    }

    /// Throw away `count` (0 = all) of the item at `at`, if its serial matches.
    /// Returns the item after (count 0 = slot emptied).
    pub fn discard_item(&self, character: u32, at: (u8, u16), serial: u64, count: u32) -> Result<Option<ItemRecord>> {
        let Some(a) = self.item_at(character, at)? else { return Ok(None) };
        if a.serial != serial {
            return Ok(None);
        }
        let left = if count == 0 { 0 } else { u32::from(a.count).saturating_sub(count) as u16 };
        if left == 0 {
            self.conn.execute("DELETE FROM item WHERE id=?1", params![a.serial as i64])?;
        } else {
            self.conn.execute("UPDATE item SET count=?1 WHERE id=?2", params![left, a.serial as i64])?;
        }
        Ok(Some(ItemRecord { count: left, ..a }))
    }

    /// Sort a bag: items packed from slot 0, ordered by item id then serial.
    /// Returns every item of the bag at its new slot.
    pub fn line_up(&self, character: u32, storage: u8) -> Result<Vec<ItemRecord>> {
        let mut items: Vec<ItemRecord> = self.items(character)?.into_iter().filter(|i| i.storage == storage).collect();
        items.sort_by_key(|i| (i.item_id, i.serial));
        let tx = self.conn.unchecked_transaction()?;
        // Two passes: park everything, then place (UNIQUE(storage, slot)).
        for (k, it) in items.iter().enumerate() {
            tx.execute("UPDATE item SET storage=255, slot=?1 WHERE id=?2", params![k as i64 + 1000, it.serial as i64])?;
        }
        for (k, it) in items.iter_mut().enumerate() {
            it.slot = k as u16;
            tx.execute("UPDATE item SET storage=?1, slot=?2 WHERE id=?3", params![storage, it.slot, it.serial as i64])?;
        }
        tx.commit()?;
        Ok(items)
    }

    /// Set an account's cash balance (GM command).
    pub fn set_cash(&self, account: u32, cash: u32) -> Result<()> {
        self.conn.execute("UPDATE account SET cash=?1 WHERE id=?2", params![cash, account])?;
        Ok(())
    }

    pub fn has_second_password(&self, account: u32) -> Result<bool> {
        Ok(self
            .conn
            .query_row("SELECT second_pw_hash FROM account WHERE id=?1", params![account], |r| r.get::<_, Option<String>>(0))
            .optional()?
            .flatten()
            .is_some())
    }

    /// Store the account's first second password (Argon2id). Refuses to
    /// overwrite an existing one: changing it needs the old PIN.
    pub fn set_second_password(&self, account: u32, pin: &str) -> Result<bool> {
        if self.has_second_password(account)? {
            return Ok(false);
        }
        let hash = hash_password(pin)?;
        let n = self.conn.execute(
            "UPDATE account SET second_pw_hash=?1 WHERE id=?2 AND second_pw_hash IS NULL",
            params![hash, account],
        )?;
        Ok(n == 1)
    }

    pub fn verify_second_password(&self, account: u32, pin: &str) -> Result<bool> {
        let stored: Option<String> = self
            .conn
            .query_row("SELECT second_pw_hash FROM account WHERE id=?1", params![account], |r| r.get(0))
            .optional()?
            .flatten();
        let Some(stored) = stored else { return Ok(false) };
        let parsed = PasswordHash::new(&stored).map_err(|e| anyhow::anyhow!("stored second pw hash: {e}"))?;
        Ok(Argon2::default().verify_password(pin.as_bytes(), &parsed).is_ok())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharacterRecord {
    pub id: u32,
    pub slot: u8,
    pub name: String,
    pub class: u8,
    pub level: u8,
    pub appearance: [u16; 4],
    pub class_ref: u16,
    pub outfit: u32,
}

/// An NPC shop purchase, already priced from the client tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShopPurchase {
    pub item: u32,
    pub count: u16,
    pub stack: u16,
    pub storage: u8,
    pub capacity: u16,
    pub cost: u64,
}

/// Buyback entries kept per character (official server: 12).
pub const BUYBACK_MAX: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepurchaseOutcome {
    Bought { item: ItemRecord, balance: u64, price: u64 },
    NotFound,
    NotEnoughZenny,
    BagFull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShopBuyOutcome {
    Bought { changed: Vec<ItemRecord>, balance: u64 },
    NotEnoughZenny,
    BagFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemRecord {
    /// Row id; doubles as the item's unique serial number.
    pub serial: u64,
    pub storage: u8,
    pub slot: u16,
    pub item_id: u32,
    pub count: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct NewCharacter<'a> {
    pub name: &'a str,
    pub class: u8,
    pub appearance: [u16; 4],
    pub class_ref: u16,
    pub outfit: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CreateOutcome {
    Created { id: u32, slot: u8 },
    NameTaken,
    NoFreeSlot,
}

fn decode_appearance(b: Option<&[u8]>) -> [u16; 4] {
    let mut out = [0u16; 4];
    if let Some(b) = b.filter(|b| b.len() == 8) {
        for (i, v) in out.iter_mut().enumerate() {
            *v = u16::from_le_bytes([b[2 * i], b[2 * i + 1]]);
        }
    }
    out
}

fn hash_password(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bank_divide_combine_is_scoped_and_bounded() {
        let db = Db::open(":memory:").unwrap();
        let account = db.login_or_register("bank-stack").unwrap();
        let other = db.login_or_register("bank-stack-other").unwrap();
        for (owner, storage, slot, item, count) in [
            (account, 22, 0, 500, 12), (account, 22, 1, 501, 5),
            (account, 23, 0, 500, 7), (other, 23, 0, 500, 9),
        ] {
            db.conn.execute(
                "INSERT INTO item(character_id,account_id,storage,slot,item_id,count) VALUES(NULL,?1,?2,?3,?4,?5)",
                params![owner, storage, slot, item, count],
            ).unwrap();
        }
        let other_before = db.bank_items(other).unwrap();
        let nc = NewCharacter { name: "BankStackBag", class: 1, appearance: [0; 4], class_ref: 0, outfit: 0 };
        let CreateOutcome::Created { id: character, .. } = db.create_character(account, &nc, 0, 4).unwrap() else { panic!() };
        let bag_before = db.add_items(character, 2, 4, &[(500, 3)]).unwrap().unwrap();
        let any = |_: u32, _: u8, _: u16| true;
        let (source, divided) = db.divide_bank_item(account, 22, 0, 2, 4, any).unwrap().unwrap();
        assert_eq!((source.storage, source.count, divided.count), (22, 8, 4));
        assert_ne!(source.serial, divided.serial);
        assert!(db.divide_bank_item(account, 22, 0, 24, 1, any).unwrap().is_none());
        assert!(db.divide_bank_item(account, 22, 0, 3, 1, |_, _, _| false).unwrap().is_none());
        assert!(db.divide_bank_item(other, 22, 0, 2, 1, any).unwrap().is_none());
        let (source_partial, dest_partial) = db.combine_bank_items(account, 22, 2, 0, 0, 10).unwrap().unwrap();
        assert_eq!((source_partial.count, dest_partial.count), (2, 10));
        let (source_after, dest_after) = db.combine_bank_items(account, 22, 2, 0, 0, 50).unwrap().unwrap();
        assert_eq!((source_after.count, dest_after.count), (0, 12));
        assert!(db.bank_items(account).unwrap().iter().all(|i| !(i.storage == 22 && i.slot == 2)));
        assert!(db.combine_bank_items(account, 22, 1, 0, 0, 50).unwrap().is_none());
        assert!(db.combine_bank_items(account, 22, 0, 24, 1, 50).unwrap().is_none());
        assert_eq!(db.bank_items(other).unwrap(), other_before);
        assert_eq!(db.items(character).unwrap(), bag_before);
    }

    #[test]
    fn line_up_bank_packs_only_selected_account_storage() {
        let db = Db::open(":memory:").unwrap();
        let account = db.login_or_register("bank-sort").unwrap();
        let other = db.login_or_register("bank-sort-other").unwrap();
        for (owner, storage, slot, item) in [
            (account, 22, 3, 300), (account, 22, 8, 100),
            (account, 23, 5, 50), (other, 22, 2, 25),
        ] {
            db.conn.execute(
                "INSERT INTO item(character_id,account_id,storage,slot,item_id,count) VALUES(NULL,?1,?2,?3,?4,1)",
                params![owner, storage, slot, item],
            ).unwrap();
        }
        let other_before = db.bank_items(other).unwrap();
        let lined = db.line_up_bank(account, 22).unwrap();
        assert_eq!(lined.iter().map(|i| (i.storage, i.slot, i.item_id)).collect::<Vec<_>>(),
            vec![(22, 0, 100), (22, 1, 300)]);
        let bank = db.bank_items(account).unwrap();
        assert_eq!(bank.iter().filter(|i| i.storage == 22).map(|i| (i.slot, i.item_id)).collect::<Vec<_>>(),
            vec![(0, 100), (1, 300)]);
        assert_eq!(bank.iter().filter(|i| i.storage == 23).map(|i| (i.slot, i.item_id)).collect::<Vec<_>>(),
            vec![(5, 50)]);
        assert_eq!(db.bank_items(other).unwrap(), other_before);
    }
    #[test]
    fn autoregister_is_stable() {
        let db = Db::open(":memory:").unwrap();
        let a = db.login_or_register("test").unwrap();
        let b = db.login_or_register("test").unwrap();
        let c = db.login_or_register("other").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn password_flow() {
        let db = Db::open(":memory:").unwrap();
        assert_eq!(db.login_with_password("haru", "pw1", false).unwrap(), LoginOutcome::NoSuchAccount);
        let LoginOutcome::Registered(id) = db.login_with_password("haru", "pw1", true).unwrap() else { panic!() };
        assert_eq!(db.login_with_password("haru", "pw1", false).unwrap(), LoginOutcome::Ok(id));
        assert_eq!(db.login_with_password("haru", "wrong", true).unwrap(), LoginOutcome::WrongPassword);

        let stored: String = db.conn.query_row("SELECT password_hash FROM account WHERE id=?1", [id], |r| r.get(0)).unwrap();
        assert!(stored.starts_with("$argon2id$"), "{stored}");
        assert!(!stored.contains("pw1"));
    }

    #[test]
    fn launcher_account_is_claimed_by_first_password() {
        let db = Db::open(":memory:").unwrap();
        let id = db.login_or_register("erza").unwrap();
        assert_eq!(db.login_with_password("erza", "secret", false).unwrap(), LoginOutcome::Registered(id));
        assert_eq!(db.login_with_password("erza", "secret", false).unwrap(), LoginOutcome::Ok(id));
        assert_eq!(db.login_with_password("erza", "nope", false).unwrap(), LoginOutcome::WrongPassword);
    }

    #[test]
    fn second_password_flow() {
        let db = Db::open(":memory:").unwrap();
        let a = db.login_or_register("a").unwrap();
        assert!(!db.has_second_password(a).unwrap());
        assert!(!db.verify_second_password(a, "135790").unwrap());
        assert!(db.set_second_password(a, "135790").unwrap());
        assert!(db.has_second_password(a).unwrap());
        // cannot be overwritten without the old PIN
        assert!(!db.set_second_password(a, "000000").unwrap());
        assert!(db.verify_second_password(a, "135790").unwrap());
        assert!(!db.verify_second_password(a, "000000").unwrap());
        let stored: String = db.conn.query_row("SELECT second_pw_hash FROM account WHERE id=?1", [a], |r| r.get(0)).unwrap();
        assert!(stored.starts_with("$argon2id$") && !stored.contains("135790"));
    }

    #[test]
    fn characters_lifecycle() {
        let db = Db::open(":memory:").unwrap();
        let a = db.login_or_register("a").unwrap();
        let b = db.login_or_register("b").unwrap();
        let nc = |name| NewCharacter { name, class: 1, appearance: [0x44d, 0x835, 0x13ed, 0xc1d], class_ref: 1001, outfit: 111 };

        let CreateOutcome::Created { id, slot } = db.create_character(a, &nc("Haru"), 1, 12).unwrap() else { panic!() };
        assert_eq!(slot, 1);
        // names are unique server-wide, case-insensitively
        assert_eq!(db.create_character(b, &nc("haru"), 1, 12).unwrap(), CreateOutcome::NameTaken);
        // a used slot falls back to the lowest free one
        assert_eq!(db.create_character(a, &nc("Erwin"), 1, 12).unwrap(), CreateOutcome::Created { id: id + 1, slot: 2 });
        // out-of-range slot also falls back
        assert!(matches!(db.create_character(a, &nc("Lily"), 0, 12).unwrap(), CreateOutcome::Created { slot: 3, .. }));
        assert_eq!(db.create_character(a, &nc("Jin"), 1, 3).unwrap(), CreateOutcome::NoFreeSlot);

        let list = db.characters(a).unwrap();
        assert_eq!(list.iter().map(|c| (c.slot, c.name.as_str())).collect::<Vec<_>>(), [(1, "Haru"), (2, "Erwin"), (3, "Lily")]);
        assert_eq!(list[0].appearance, [0x44d, 0x835, 0x13ed, 0xc1d]);
        assert_eq!((list[0].level, list[0].class_ref, list[0].outfit), (1, 1001, 111));
        assert_eq!(db.character_count(a).unwrap(), 3);

        // only the owner can delete
        assert!(!db.delete_character(b, id).unwrap());
        assert!(db.delete_character(a, id).unwrap());
        assert_eq!(db.character_count(a).unwrap(), 2);
        assert!(matches!(db.create_character(b, &nc("Haru"), 1, 12).unwrap(), CreateOutcome::Created { .. }));
    }

    #[test]
    fn items_fill_free_slots_and_refuse_when_full() {
        let db = Db::open(":memory:").unwrap();
        let a = db.login_or_register("bag").unwrap();
        let nc = |name| NewCharacter { name, class: 1, appearance: [0x44d, 0x835, 0x13ed, 0xc1d], class_ref: 1001, outfit: 111 };
        let CreateOutcome::Created { id, .. } = db.create_character(a, &nc("Bag"), 1, 12).unwrap() else { panic!() };
        let first = db.add_items(id, 4, 3, &[(100, 1), (101, 2)]).unwrap().unwrap();
        assert_eq!(first.iter().map(|i| i.slot).collect::<Vec<_>>(), vec![0, 1]);
        assert!(db.add_items(id, 4, 3, &[(102, 1), (103, 1)]).unwrap().is_none(), "only one slot left");
        assert_eq!(db.items(id).unwrap().len(), 2, "failed add must not leave partial rows");
        assert_eq!(db.add_items(id, 4, 3, &[(102, 1)]).unwrap().unwrap()[0].slot, 2);
        assert!(db.delete_character(a, id).unwrap());
        assert!(db.items(id).unwrap().is_empty());
    }

    #[test]
    fn shop_buy_stacks_charges_and_sell_refunds() {
        let db = Db::open(":memory:").unwrap();
        let a = match db.login_with_password("shop", "pw", true).unwrap() {
            LoginOutcome::Registered(id) => id,
            o => panic!("{o:?}"),
        };
        let nc = NewCharacter { name: "Buyer", class: 1, appearance: [0; 4], class_ref: 0, outfit: 0 };
        let CreateOutcome::Created { id: c, .. } = db.create_character(a, &nc, 0, 4).unwrap() else { panic!() };
        let buy = |count, cost| ShopPurchase { item: 800004001, count, stack: 50, storage: 2, capacity: 2, cost };
        // 60 potions, stack 50: one full stack + 10, 600 Zenny.
        let ShopBuyOutcome::Bought { changed, balance } = db.shop_buy(c, &buy(60, 600), 1000).unwrap() else { panic!() };
        assert_eq!(balance, 400);
        assert_eq!(changed.iter().map(|i| i.count).collect::<Vec<_>>(), vec![50, 10]);
        // Tops up the 10-stack first; no slot left for more than 40.
        let ShopBuyOutcome::Bought { changed, balance } = db.shop_buy(c, &buy(40, 100), 1000).unwrap() else { panic!() };
        assert_eq!((changed.len(), changed[0].count, balance), (1, 50, 300));
        assert_eq!(db.shop_buy(c, &buy(1, 10), 1000).unwrap(), ShopBuyOutcome::BagFull);
        assert_eq!(db.zenny(c, 1000).unwrap(), 300, "a refused purchase costs nothing");
        assert_eq!(db.shop_buy(c, &ShopPurchase { capacity: 9, ..buy(1, 301) }, 1000).unwrap(), ShopBuyOutcome::NotEnoughZenny);
        // Selling a worn item is refused; a bag stack pays price x count.
        let (sold, balance) = db.shop_sell(c, &[(2, 0), (0, 1), (2, 7)], |st| st == 2, |_| 10, 1000).unwrap();
        assert_eq!((sold.len(), sold[0].count, balance), (1, 0, 800));
        assert_eq!(db.items(c).unwrap().len(), 1);
    }

    #[test]
    fn buyback_divide_combine_discard_line_up() {
        let db = Db::open(":memory:").unwrap();
        let a = db.login_or_register("bags").unwrap();
        let nc = NewCharacter { name: "Bags", class: 1, appearance: [0; 4], class_ref: 0, outfit: 0 };
        let CreateOutcome::Created { id: c, .. } = db.create_character(a, &nc, 0, 4).unwrap() else { panic!() };
        let any = |_: u32, _: u8, _: u16| true;
        db.add_items(c, 2, 24, &[(800004001, 10), (900, 1)]).unwrap().unwrap();
        // divide 4 off slot 0 into slot 5; can't split everything or into a used slot
        let (s, n) = db.divide_item(c, (2, 0), (2, 5), 4, any).unwrap().unwrap();
        assert_eq!((s.count, n.slot, n.count), (6, 5, 4));
        assert!(db.divide_item(c, (2, 0), (2, 6), 6, any).unwrap().is_none());
        assert!(db.divide_item(c, (2, 0), (2, 1), 1, any).unwrap().is_none());
        // combine back (stack 50): slot 5 disappears
        let (s, d) = db.combine_items(c, (2, 5), (2, 0), 4, 50).unwrap().unwrap();
        assert_eq!((s.count, d.count), (0, 10));
        assert!(db.combine_items(c, (2, 0), (2, 1), 0, 50).unwrap().is_none(), "different items");
        // line up packs from slot 0
        db.add_items(c, 2, 24, &[(5, 1)]).unwrap().unwrap(); // lands in slot 2
        db.discard_item(c, (2, 1), db.item_at(c, (2, 1)).unwrap().unwrap().serial, 0).unwrap().unwrap();
        let lined = db.line_up(c, 2).unwrap();
        assert_eq!(lined.iter().map(|i| (i.slot, i.item_id)).collect::<Vec<_>>(), vec![(0, 5), (1, 800004001)]);
        // discard 3 of 10 with the right serial only
        let pot = db.item_at(c, (2, 1)).unwrap().unwrap();
        assert!(db.discard_item(c, (2, 1), pot.serial + 99, 3).unwrap().is_none());
        assert_eq!(db.discard_item(c, (2, 1), pot.serial, 3).unwrap().unwrap().count, 7);
        // sell -> buyback -> repurchase at the sell price
        let (_, bal) = db.shop_sell(c, &[(2, 1)], |_| true, |_| 10, 1000).unwrap();
        assert_eq!(bal, 1070);
        let bb = db.buyback(c).unwrap();
        assert_eq!((bb.len(), bb[0].serial, bb[0].item_id, bb[0].count, bb[0].storage), (1, pot.serial, 800004001, 7, 2));
        let RepurchaseOutcome::Bought { item, balance, price } = db.repurchase(c, bb[0].serial, |_| 24, 1000).unwrap() else { panic!() };
        assert_eq!((item.serial, item.slot, item.count, balance, price), (pot.serial, 1, 7, 1000, 70));
        assert_eq!(db.item_at(c, (2, 1)).unwrap().unwrap().serial, pot.serial, "old serial back in the bag");
        assert!(db.buyback(c).unwrap().is_empty());
        assert_eq!(db.repurchase(c, bb[0].serial, |_| 24, 1000).unwrap(), RepurchaseOutcome::NotFound);
        // only the newest BUYBACK_MAX are kept
        for _ in 0..(BUYBACK_MAX + 3) {
            db.add_items(c, 2, 24, &[(900, 1)]).unwrap().unwrap();
            let slot = db.items(c).unwrap().iter().find(|i| i.item_id == 900 && i.storage == 2).unwrap().slot;
            db.shop_sell(c, &[(2, slot)], |_| true, |_| 1, 1000).unwrap();
        }
        assert_eq!(db.buyback(c).unwrap().len(), BUYBACK_MAX);
        assert!(db.delete_character(a, c).unwrap());
    }

    #[test]
    fn cash_starts_once_and_never_goes_negative() {
        let db = Db::open(":memory:").unwrap();
        let a = db.login_or_register("rich").unwrap();
        assert_eq!(db.cash(a, 1000).unwrap(), 1000);
        assert!(db.spend_cash(a, 300, 1000).unwrap());
        assert_eq!(db.cash(a, 1000).unwrap(), 700, "start cash is applied only once");
        assert!(!db.spend_cash(a, 701, 1000).unwrap());
        assert_eq!(db.cash(a, 1000).unwrap(), 700);
    }

    #[test]
    fn equip_and_unequip_swap_slots_and_refuse_wrong_places() {
        let db = Db::open(":memory:").unwrap();
        let a = db.login_or_register("wear").unwrap();
        let nc = |name| NewCharacter { name, class: 1, appearance: [0x44d, 0x835, 0x13ed, 0xc1d], class_ref: 1001, outfit: 111 };
        let CreateOutcome::Created { id, .. } = db.create_character(a, &nc("Wear"), 1, 12).unwrap() else { panic!() };
        db.seed_equipment(id, &[(6, 211010701)]).unwrap();
        db.seed_equipment(id, &[(6, 999)]).unwrap(); // second call is a no-op
        let costume = db.add_items(id, 4, 48, &[(213881001, 1)]).unwrap().unwrap()[0];
        // only costume 213881001 into shape slot 7 / back to bag 4; 211010701 into slot 6 / bag 4
        let fits = |item: u32, st: u8, sl: u16| match (item, st) {
            (213881001, 0) => sl == 7,
            (211010701, 0) => sl == 6,
            (_, 4) => sl < 48,
            _ => false,
        };
        let (_, _, ok) = db.move_item(a, id, (4, costume.slot), (0, 3), fits, &[]).unwrap();
        assert!(!ok, "wrong equip slot is refused");
        let (src, dest, ok) = db.move_item(a, id, (4, costume.slot), (0, 7), fits, &[]).unwrap();
        assert!(ok && src.is_none() && dest.unwrap().item_id == 213881001);
        // unequip the starter body onto an empty bag slot
        let (src, dest, ok) = db.move_item(a, id, (0, 6), (4, 5), fits, &[]).unwrap();
        assert!(ok && src.is_none() && dest.unwrap().item_id == 211010701);
        let worn: Vec<_> = db.items(id).unwrap().into_iter().filter(|i| i.storage == 0).map(|i| (i.slot, i.item_id)).collect();
        assert_eq!(worn, vec![(7, 213881001)]);
        // swap: bag item onto an occupied equip slot puts the worn one in the bag
        let (src, dest, ok) = db.move_item(a, id, (0, 7), (4, 5), fits, &[]).unwrap();
        assert!(!ok, "211010701 cannot go to shape slot 7");
        assert_eq!((src.unwrap().item_id, dest.unwrap().item_id), (213881001, 211010701));
        // soul weapon: seeded once, swapped with a bag weapon, never emptied
        db.ensure_weapon(id, (1, 0), 111011301).unwrap();
        db.ensure_weapon(id, (1, 0), 999).unwrap();
        let bought = db.add_items(id, 2, 24, &[(111011302, 1)]).unwrap().unwrap()[0];
        let wfits = |item: u32, st: u8, sl: u16| (item / 1000 == 111011 && ((st == 1 && sl == 0) || (st == 2 && sl < 24)));
        let keep = [(1u8, 0u16)];
        let (src, dest, ok) = db.move_item(a, id, (1, 0), (2, 10), wfits, &keep).unwrap();
        assert!(!ok && src.unwrap().item_id == 111011301 && dest.is_none(), "weapon slot is never emptied");
        let (src, dest, ok) = db.move_item(a, id, (2, bought.slot), (1, 0), wfits, &keep).unwrap();
        assert!(ok && src.unwrap().item_id == 111011301 && dest.unwrap().item_id == 111011302, "equip swaps");
    }

    #[test]
    fn using_a_box_swaps_it_for_its_contents() {
        let db = Db::open(":memory:").unwrap();
        let a = db.login_or_register("box").unwrap();
        let nc = |name| NewCharacter { name, class: 1, appearance: [0x44d, 0x835, 0x13ed, 0xc1d], class_ref: 1001, outfit: 111 };
        let CreateOutcome::Created { id, .. } = db.create_character(a, &nc("Box"), 1, 12).unwrap() else { panic!() };
        let boxed = db.add_items(id, 13, 384, &[(6000451, 1)]).unwrap().unwrap()[0];
        let (used, added) = db.use_item(id, boxed.serial, &[(213881001, 1, 4, 48)]).unwrap().unwrap();
        assert_eq!((used.count, used.slot), (0, 0));
        assert_eq!((added[0].item_id, added[0].storage), (213881001, 4));
        assert_eq!(db.items(id).unwrap().len(), 1, "the box is gone");
        assert!(db.use_item(id, boxed.serial, &[]).unwrap().is_none(), "cannot use it twice");
        // full bag: nothing changes
        let b2 = db.add_items(id, 13, 384, &[(6000451, 1)]).unwrap().unwrap()[0];
        assert!(db.use_item(id, b2.serial, &[(1, 1, 4, 1)]).unwrap().is_none());
        assert_eq!(db.items(id).unwrap().len(), 2);
    }

    #[test]
    fn migrates_old_schema() {
        let path = std::env::temp_dir().join(format!("swemu-mig-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE account (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL DEFAULT 0); INSERT INTO account(name) VALUES ('old');").unwrap();
        }
        let db = Db::open(path.to_str().unwrap()).unwrap();
        assert!(matches!(db.login_with_password("old", "pw", false).unwrap(), LoginOutcome::Registered(_)));
        assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION);
        drop(db);
        // Reopening keeps v2 and the data.
        let db = Db::open(path.to_str().unwrap()).unwrap();
        assert!(matches!(db.login_with_password("old", "pw", false).unwrap(), LoginOutcome::Ok(_)));
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bank_zenny_deposit_over_u64_preserves_both_balances() {
        let db = Db::open(":memory:").unwrap();
        let account = db.login_or_register("bank-u64").unwrap();
        let request = NewCharacter { name: "Wallet", class: 1, appearance: [0; 4], class_ref: 0, outfit: 0 };
        let CreateOutcome::Created { id: character, .. } = db.create_character(account, &request, 0, 4).unwrap() else { panic!() };
        db.set_zenny(character, 100).unwrap();
        let initial_bank = u64::MAX - 5;
        db.conn.execute("INSERT INTO bank_zenny(account_id,balance) VALUES (?1,?2)", params![account, initial_bank.to_string()]).unwrap();
        assert_eq!(
            db.transfer_bank_zenny(account, character, BankZennyDirection::Deposit, 10, 0).unwrap(),
            None
        );
        assert_eq!(db.zenny(character, 0).unwrap(), 100);
        assert_eq!(db.bank_zenny_balance(account).unwrap(), initial_bank as u128);
    }

    #[test]
    fn v6_migration_handles_missing_capacity_and_rejects_unrepresentable_slots() {
        let legacy_db = || {
            let conn = Connection::open(":memory:").unwrap();
            conn.execute_batch(
                "CREATE TABLE account(id INTEGER PRIMARY KEY);
                 CREATE TABLE character(id INTEGER PRIMARY KEY, account_id INTEGER, bank_zenny INTEGER);
                 CREATE TABLE item(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, character_id INTEGER, storage INTEGER,
                    slot INTEGER, item_id INTEGER, count INTEGER, created_at INTEGER,
                    UNIQUE(character_id, storage, slot)
                 );
                 CREATE TABLE storage_capacity(character_id INTEGER, storage INTEGER, slots INTEGER);
                 INSERT INTO account VALUES (1);
                 INSERT INTO character VALUES (1, 1, 0), (2, 1, 0);
                 PRAGMA user_version=5;",
            )
            .unwrap();
            conn
        };

        let out_of_range = legacy_db();
        out_of_range
            .execute(
                "INSERT INTO item(character_id,storage,slot,item_id,count,created_at)
                 VALUES (1,22,65535,1,1,0)",
                [],
            )
            .unwrap();
        assert!(migrate_v6(&out_of_range).is_err());
        assert_eq!(out_of_range.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 5);
        assert_eq!(out_of_range.query_row("SELECT COUNT(*) FROM item", [], |r| r.get::<_, i64>(0)).unwrap(), 1);

        let full = legacy_db();
        let tx = full.unchecked_transaction().unwrap();
        {
            let mut insert = tx
                .prepare("INSERT INTO item(character_id,storage,slot,item_id,count,created_at) VALUES (1,22,?1,1,1,0)")
                .unwrap();
            for slot in 0..u16::MAX {
                insert.execute(params![slot]).unwrap();
            }
        }
        tx.execute(
            "INSERT INTO item(character_id,storage,slot,item_id,count,created_at) VALUES (2,22,0,1,1,0)",
            [],
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(migrate_v6(&full).is_err());
        assert_eq!(full.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 5);
        assert_eq!(full.query_row("SELECT COUNT(*) FROM item", [], |r| r.get::<_, i64>(0)).unwrap(), 65_536);
        let sparse = legacy_db();
        sparse
            .execute(
                "INSERT INTO item(character_id,storage,slot,item_id,count,created_at)
                 VALUES (1,22,30,1,1,0)",
                [],
            )
            .unwrap();
        migrate_v6(&sparse).unwrap();
        let capacity = sparse
            .query_row("SELECT slots FROM storage_capacity WHERE account_id=1 AND storage=22", [], |r| r.get::<_, u16>(0))
            .unwrap();
        let stored_slot = sparse
            .query_row("SELECT slot FROM item WHERE account_id=1 AND storage=22", [], |r| r.get::<_, u16>(0))
            .unwrap();
        assert_eq!((capacity, stored_slot), (31, 30));

        for (invalid_setup, label) in [
            ("INSERT INTO storage_capacity VALUES (1,22,65536)", "capacity"),
            ("INSERT INTO item(character_id,storage,slot,item_id,count,created_at) VALUES (1,22,0,1,65536,0)", "count"),
            ("INSERT INTO character VALUES (3,1,9223372036854775807); UPDATE character SET bank_zenny=9223372036854775807 WHERE id IN (1,2)", "bank zenny"),
        ] {
            let invalid = legacy_db();
            if label == "bank zenny" {
                invalid.execute("INSERT INTO character VALUES (3,1,9223372036854775807)", []).unwrap();
                invalid.execute("UPDATE character SET bank_zenny=9223372036854775807 WHERE id IN (1,2)", []).unwrap();
            } else {
                invalid.execute(invalid_setup, []).unwrap();
            }
            assert!(migrate_v6(&invalid).is_err(), "{label}");
            assert_eq!(invalid.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 5, "{label}");
            let expected_items = if label == "count" { 1 } else { 0 };
            assert_eq!(invalid.query_row("SELECT COUNT(*) FROM item", [], |r| r.get::<_, i64>(0)).unwrap(), expected_items, "{label}");
            assert!(invalid.prepare("SELECT bank_zenny FROM character").is_ok(), "{label}");
            match label {
                "capacity" => assert_eq!(invalid.query_row("SELECT slots FROM storage_capacity", [], |r| r.get::<_, i64>(0)).unwrap(), 65536),
                "count" => assert_eq!(invalid.query_row("SELECT count FROM item", [], |r| r.get::<_, i64>(0)).unwrap(), 65536),
                "bank zenny" => assert_eq!(invalid.query_row("SELECT COUNT(*) FROM character WHERE bank_zenny=9223372036854775807", [], |r| r.get::<_, i64>(0)).unwrap(), 3),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn schema_v2_constraints_and_cascade() {
        let db = Db::open(":memory:").unwrap();
        assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION);
        let fk: i64 = db.conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).unwrap();
        assert_eq!(fk, 1);
        let acc = db.login_or_register("v2").unwrap();
        assert_eq!(acc, 1000, "account ids still start at 1000");
        db.conn
            .execute("INSERT INTO character(account_id, slot, name, class) VALUES (?1, 1, 'v2c', 1)", params![acc])
            .unwrap();
        let ch = db.conn.last_insert_rowid() as u32;
        db.conn.execute("INSERT INTO item(character_id, storage, slot, item_id, count) VALUES (?1, 2, 0, 1, 1)", params![ch]).unwrap();
        db.set_skill(ch, 10, 11, 0).unwrap();
        db.set_skill_deck(ch, 0, [11, 0, 0, 0]).unwrap();
        // CHECKs reject bad values.
        assert!(db.conn.execute("UPDATE item SET count=0 WHERE character_id=?1", params![ch]).is_err());
        assert!(db.conn.execute("UPDATE character SET zenny=-1 WHERE id=?1", params![ch]).is_err());
        assert!(db.conn.execute("UPDATE character SET level=0 WHERE id=?1", params![ch]).is_err());
        // Orphans are refused, deleting a character removes all its rows.
        assert!(db.conn.execute("INSERT INTO item(character_id, storage, slot, item_id) VALUES (999999, 2, 1, 1)", []).is_err());
        assert!(db.delete_character(acc, ch).unwrap());
        for t in ["item", "skill", "skill_deck", "buyback"] {
            let n: i64 = db.conn.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "{t}");
        }
    }
}
