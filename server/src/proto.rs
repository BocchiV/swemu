//! Typed payload parsers for client -> server packets.
//!
//! Layouts are taken from the 2.3.34.7 client's writer functions and checked
//! against payloads produced by those writers under emulation
//! (`crate::wire::golden`).

use crate::codec::{ReadError, Reader, Writer};
use crate::gamedata;
use std::fmt;

/// Constant the 2.3.34.7 client appends to LOGIN_REQ (`mov dword [..], 0x989746`
/// at 0x1805f598e). 2.3.29.7 sent 0x989741, so it tracks the client build.
pub const CLIENT_VERSION_2334: u32 = 0x0098_9746;

/// Upper bounds in UTF-16 code units. The wire allows up to 32767 bytes per
/// string; these keep a hostile peer from making us allocate that much.
pub const MAX_USER_UNITS: usize = 64;
pub const MAX_PASSWORD_UNITS: usize = 128;
pub const MAX_MAC_UNITS: usize = 64;

/// LOGIN_REQ (main 2, sub 1), sent by the ID/password dialog.
///
/// Writer FUN_1805f5840 (2.3.34.7):
/// ```text
/// wstr  user       u16 BYTE length + UTF-16LE, no terminator (FUN_18000e430)
/// wstr  password   same encoding
/// wstr  mac        adapter MAC as text "%02X-%02X-%02X-%02X-%02X-%02X" (FUN_1805b4120)
/// u32   version    0x989746
/// ```
/// The MAC is a wide *text* field, not 6 raw bytes; `mac` holds the parsed
/// bytes when the text has that shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginReq {
    pub user: String,
    pub password: Password,
    pub mac_text: String,
    pub mac: Option<[u8; 6]>,
    pub client_version: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Read(&'static str),
    TooLong { field: &'static str, units: usize, max: usize },
    OddLength(&'static str),
    InvalidUtf16(&'static str),
    EmbeddedNul(&'static str),
    Empty(&'static str),
    TrailingBytes(usize),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(m) => write!(f, "{m}"),
            Self::TooLong { field, units, max } => write!(f, "{field}: {units} UTF-16 units > {max}"),
            Self::OddLength(field) => write!(f, "{field}: odd UTF-16 byte length"),
            Self::InvalidUtf16(field) => write!(f, "{field}: invalid UTF-16"),
            Self::EmbeddedNul(field) => write!(f, "{field}: embedded NUL"),
            Self::Empty(field) => write!(f, "{field}: empty"),
            Self::TrailingBytes(n) => write!(f, "{n} unexpected trailing bytes"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ReadError> for ParseError {
    fn from(e: ReadError) -> Self {
        Self::Read(e.0)
    }
}

impl LoginReq {
    pub const MAIN: u8 = 2;
    pub const SUB: u8 = 1;

    pub fn parse(payload: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(payload);
        let user = wstr_strict(&mut r, "user", MAX_USER_UNITS)?;
        let password = Password(wstr_strict(&mut r, "password", MAX_PASSWORD_UNITS)?);
        let mac_text = wstr_strict(&mut r, "mac", MAX_MAC_UNITS)?;
        let client_version = r.u32()?;
        if !r.remaining().is_empty() {
            return Err(ParseError::TrailingBytes(r.remaining().len()));
        }
        if user.is_empty() {
            return Err(ParseError::Empty("user"));
        }
        let mac = parse_mac(&mac_text);
        Ok(Self { user, password, mac_text, mac, client_version })
    }
}

/// SERVER_LIST_REQ 2/3 — FUN_1805f5a40: u32 (client field +0x10138).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerListReq {
    pub value: u32,
}

impl ServerListReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let value = r.u32()?;
        end(&r)?;
        Ok(Self { value })
    }
}

/// SERVER_CONNECT_REQ 2/5 — FUN_1805f5b30: u16 server id picked in the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerConnectReq {
    pub server_id: u16,
}

impl ServerConnectReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let server_id = r.u16()?;
        end(&r)?;
        Ok(Self { server_id })
    }
}

/// ENTER_SERVER_REQ 2/0x13 — FUN_1805fe7d0, sent on the *game* connection:
/// u32 account id, u16 server id, u64 session key (from LOGIN_RESULT), u8 flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnterServerReq {
    pub account_id: u32,
    pub server_id: u16,
    pub session: u64,
    pub flag: u8,
}

impl EnterServerReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let v = Self { account_id: r.u32()?, server_id: r.u16()?, session: r.u64()?, flag: r.u8()? };
        end(&r)?;
        Ok(v)
    }
}

/// CHARACTER_LIST_REQ 3/0x11 — FUN_1805f5f90: u64 session key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharacterListReq {
    pub session: u64,
}

impl CharacterListReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let session = r.u64()?;
        end(&r)?;
        Ok(Self { session })
    }
}

fn end(r: &Reader<'_>) -> Result<(), ParseError> {
    match r.remaining().len() {
        0 => Ok(()),
        n => Err(ParseError::TrailingBytes(n)),
    }
}

// ---------------------------------------------------------------- characters

/// One character row as the 2.3.34.7 client serializes it (writer FUN_1800128b0,
/// reader FUN_180012e20 into a 0x310-byte struct; sub-readers FUN_180012490,
/// FUN_1800252c0, FUN_180047c90, FUN_1800127d0, FUN_180014620):
/// ```text
/// u32 id                     (creator sends -1)                     +0x08
/// wstr name                  (<= 40 bytes: FUN_18000e4b0 max 0x15)  +0x10
/// u8 class, u8, u32, u32                                            +0x2a..+0x30
/// u64 appearance (4 x u16: hair, eyes, skin, hair colour)           +0x38
/// u64, u16 class_ref (class table +0x123: 1001, 2001, ...)           +0x40, +0x48
/// u8 level, u8, u32, u8, u32, u8, u32, u8, u32                      +0x64..+0xa0
/// 28 x (u64, u32, u32)       (empty = (-1, -1, 0))                  +0xa8 / +0x188
/// u32, u32, u32, (u32, wstr <= 18 bytes, u32), 10 x u32, f32, f32   +0x268.., +0x68
/// u8, wstr (<= 40 bytes), u16 x3, u8, u32, u8, u32                  +0x298..+0x2d4
/// i8 n, n x (u32, u32, u8, u32, u8)                                 +0x2d8
/// u8 slot (1-based), u32, u32, u8, u32, u8, u8                      +0x2f8..+0x30d
/// ```
/// A freshly created character differs between classes only in class,
/// appearance and class_ref (checked on captured class 1 and class 2 rows);
/// the server writes every other field itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharacterInfo {
    pub id: u32,
    pub name: String,
    pub class: u8,
    pub level: u8,
    pub appearance: [u16; 4],
    pub class_ref: u16,
    pub slot: u8,
    /// Soul weapon item id (row +0x98), 0 = none.
    pub weapon: u32,
    /// Worn costume item ids by shape slot (row +0xa8, 14 x 16 bytes), 0 = empty.
    pub shape: [u32; SHAPE_SLOTS],
    /// Item serial per shape slot; 0 = derive one (starter rows not in the DB).
    pub shape_serial: [u64; SHAPE_SLOTS],
    /// Look (fashion) equip per slot: (serial, item id), item 0 = empty.
    pub look: [(u64, u32); SHAPE_SLOTS],
    /// GM level (row byte after level + u8 + u32; CHARACTER_INFO reader puts it
    /// at +0x26c, PlayScene copies it to +0x100d4). > 0 makes the chat box send
    /// tb_ChattingCommand commands whose level <= this as 7/0x0A.
    pub gm_level: u8,
    /// STAbility (current, max) x 5; see STARTER_ABILITY.
    pub ability: [(u32, u32); 5],
    /// STAbility move / attack speed rate (f32). 100.0 = normal: 1.0 made the
    /// character walk in slow motion (real client, 2026-10-18).
    /// Stored as f32 bit patterns so the struct stays `Eq`.
    pub speed: [u32; 2],
    /// Fatigue points (regular, bonus) shown as "FP" and spent on dungeons.
    pub fp: (u16, u16),
}

const ROW_RECORDS: usize = 28;
pub const SHAPE_SLOTS: usize = 14;

/// Starting (current, max) for the 5 STAbility slots: HP, soul gauge, soul
/// vapor, stamina, super armor (order of OpenWorker's AbilityValue; index 0 is
/// the HUD HP bar). Placeholder until stats are computed from tb_Status.
/// Normal move / attack speed rate (OpenWorker PersonRegistry uses 100.0).
pub const STARTER_SPEED: [u32; 2] = [100.0f32.to_bits(), 100.0f32.to_bits()];

/// Daily fatigue points (regular, bonus) until FP is tracked: the official
/// servers hand out 200 regular FP a day.
pub const STARTER_FP: (u16, u16) = (200, 0);

pub const STARTER_ABILITY: [(u32, u32); 5] = [(1000, 1000), (100, 100), (100, 100), (100, 100), (100, 100)];

/// Stable per-character serial for a starter item (non-zero, never -1).
fn item_serial(character: u32, slot: usize) -> u64 {
    (u64::from(character) << 8) | (slot as u64 + 1)
}

/// Shape slot for each tb_Create_Cloth column (head, body, hands, stocking,
/// foot, pants). Slot = equip slot type - 0x0B: HAIR_CAP 0x0C -> 1,
/// GLOVE 0x0F -> 4, COSTUME 0x11 -> 6, SOCKS 0x13 -> 8, SHOES 0x14 -> 9,
/// PANTS 0x16 -> 11 (same mapping as the reconstructed ReqCharacterCreate).
const CLOTH_COLUMN_SLOT: [usize; 6] = [1, 6, 4, 8, 9, 11];

/// Starter soul weapon and worn costume for a class and the creator's
/// "Coordinate" pick, from the client's own tables (gamedata.rs). A pick that
/// does not belong to the class falls back to the class's first set, so a
/// modified client cannot dress a character in another class's items.
pub fn starter_equipment(class: u8, outfit: u32) -> (u32, [u32; SHAPE_SLOTS]) {
    let mut shape = [0u32; SHAPE_SLOTS];
    let Some(&(_, weapon, choices)) = gamedata::CLASS_START.iter().find(|(c, _, _)| *c == class) else {
        return (0, shape);
    };
    let pick = choices.iter().copied().find(|&c| u32::from(c) == outfit).or(choices.first().copied());
    if let Some(set) = pick.and_then(|id| gamedata::CREATE_CLOTH.iter().find(|(c, _)| *c == id)) {
        for (column, &item) in set.1.iter().enumerate() {
            shape[CLOTH_COLUMN_SLOT[column]] = item;
        }
    }
    (weapon, shape)
}

impl CharacterInfo {
    pub fn encode(&self, w: &mut Writer) {
        w.u32(self.id).wstr(&self.name);
        w.u8(self.class).u8(0).u32(0).u32(0);
        for v in self.appearance {
            w.u16(v);
        }
        w.u64(0).u16(self.class_ref);
        let weapon = if self.weapon == 0 { u32::MAX } else { self.weapon };
        w.u8(self.level).u8(0).u32(0).u8(self.gm_level).u32(0).u8(0).u32(weapon).u8(0).u32(u32::MAX);
        // FUN_180012e20 reads 14 pairs: shape[i] (+0xa8 + 16 i), look[i] (+0x188 + 16 i),
        // each u64 serial, u32 item id, u32 dye. -1/-1 is an empty slot.
        for slot in 0..ROW_RECORDS / 2 {
            match (self.shape[slot], self.shape_serial[slot]) {
                (0, _) => w.u64(u64::MAX).u32(u32::MAX).u32(0),
                (item, 0) => w.u64(item_serial(self.id, slot)).u32(item).u32(0),
                (item, serial) => w.u64(serial).u32(item).u32(0),
            };
            match self.look[slot] {
                (_, 0) => w.u64(u64::MAX).u32(u32::MAX).u32(0),
                (serial, item) => w.u64(serial).u32(item).u32(0),
            };
        }
        w.u32(0).u32(0).u32(0);
        w.u32(0).wstr("").u32(0);
        // STAbility (reader FUN_1800127d0): 5 x {u32 cur, u32 max} interleaved
        // (cur -> +0x68 + 4i, max -> +0x7c + 4i), then f32 move / attack speed rate.
        // The HUD shows index 0 as the HP bar; all zero makes the character
        // unable to walk or run.
        for (cur, max) in self.ability {
            w.u32(cur).u32(max);
        }
        w.u32(self.speed[0]).u32(self.speed[1]);
        // Private shop (u8 type, wstr name), then FP: i16 regular -> row
        // +0x2c4, i16 bonus -> +0x2c6 (FUN_180012e20 at 0x1800131dd /
        // 0x18001320d). CHARACTER_INFO hands both to the HUD (FUN_1803d1180
        // via 0x180da185c); 0 showed "FP 0". Then i16 rank (+0x2c8), u8, ...
        w.u8(0).wstr("").u16(self.fp.0).u16(self.fp.1).u16(0).u8(0).u32(0).u8(0).u32(0);
        w.u8(0); // no list entries
        w.u8(self.slot).u32(0).u32(0).u8(0).u32(0).u8(0).u8(0);
    }
}

/// CREATE_CHARACTER_REQ 3/1 — FUN_1805f6070: a character row (FUN_1800128b0)
/// followed by u32 outfit (the "Coordinate" pick: 111, 211, ...).
///
/// The parser walks the whole row with the client's own limits and keeps only
/// what the player chooses in the creator; level, items and the rest are set
/// by the server, so a modified client cannot create a pre-equipped character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCharacterReq {
    pub name: String,
    pub class: u8,
    pub appearance: [u16; 4],
    pub class_ref: u16,
    pub slot: u8,
    pub outfit: u32,
}

impl CreateCharacterReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        r.u32()?; // id, -1 from the creator
        let name = client_wstr(&mut r, "name", 40)?;
        if name.is_empty() {
            return Err(ParseError::Empty("name"));
        }
        let class = r.u8()?;
        r.u8()?;
        r.u32()?;
        r.u32()?;
        let appearance = [r.u16()?, r.u16()?, r.u16()?, r.u16()?];
        r.u64()?;
        let class_ref = r.u16()?;
        r.bytes(1 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 4)?;
        r.bytes(ROW_RECORDS * 16)?;
        r.bytes(3 * 4)?;
        r.u32()?;
        client_wstr(&mut r, "title", 18)?;
        r.u32()?;
        r.bytes(12 * 4)?;
        r.u8()?;
        client_wstr(&mut r, "memo", 40)?;
        r.bytes(3 * 2 + 1 + 4 + 1 + 4)?;
        let n = r.u8()? as i8;
        if n > 0 {
            r.bytes(n as usize * (4 + 4 + 1 + 4 + 1))?;
        }
        let slot = r.u8()?;
        r.bytes(4 + 4 + 1 + 4 + 1 + 1)?;
        let outfit = r.u32()?;
        end(&r)?;
        Ok(Self { name, class, appearance, class_ref, slot, outfit })
    }
}

/// DELETE_CHARACTER_REQ 3/2 — FUN_1805f6160: u32 character id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteCharacterReq {
    pub id: u32,
}

impl DeleteCharacterReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let id = r.u32()?;
        end(&r)?;
        Ok(Self { id })
    }
}

/// SELECT_CHARACTER_REQ 3/0x13 — FUN_1805f6230, writer FUN_18001c5c0:
/// u32 character id, u32, u8 (app +0x10458), u32, u32 (17 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectCharacterReq {
    pub id: u32,
}

impl SelectCharacterReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let id = r.u32()?;
        r.u32()?;
        r.u8()?;
        r.u32()?;
        r.u32()?;
        end(&r)?;
        Ok(Self { id })
    }
}

/// ENTER_GAMESERVER_REQ 3/0x21 — FUN_1805fea10, writer FUN_18002c7b0, sent on
/// the world connection right after it opens (connect purpose 3):
/// u32 account (app +0x10138), u32 (+0x10150), u64 map instance id echoed from
/// SELECT_CHARACTER_RES (+0x104b8), u8 flag, u64 (+0x104a0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnterGameServerReq {
    pub account_id: u32,
    pub map_instance: u64,
}

impl EnterGameServerReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let account_id = r.u32()?;
        r.u32()?;
        let map_instance = r.u64()?;
        r.u8()?;
        r.u64()?;
        end(&r)?;
        Ok(Self { account_id, map_instance })
    }
}

/// Map instance id (UXMapID): bits 0-23 sequence, 24-31 channel, 32-47 map
/// (district) id, 48-63 server id. The client passes the channel byte to its
/// connect routine (FUN_180d9fcb0 -> FUN_1805f69f0).
pub fn map_instance_id(seq: u32, channel: u8, map: u16, server: u16) -> u64 {
    u64::from(seq & 0x00FF_FFFF) | u64::from(channel) << 24 | u64::from(map) << 32 | u64::from(server) << 48
}

/// First district for a new character: 10003 = F031_ROCCOTOWN (tb_district.res
/// row header u16 10003; 10001 = F001_TESTFIELD, 10021 = F021_CANDUSCITY),
/// start box 1000301 (the reconstructed server's default for 10003).
pub const START_DISTRICT: u16 = 10003;
pub const START_JUMP_ID: u32 = 1_000_301;

/// Where the world connection goes and which map it enters.
#[derive(Debug, Clone, PartialEq)]
pub struct WorldTarget<'a> {
    pub character_id: u32,
    pub account_id: u32,
    pub server_id: u32,
    pub jump_id: u32,
    pub map_instance: u64,
    pub host: &'a str,
    pub port: u16,
    pub district: u16,
    pub pos: [f32; 3],
    pub rot: f32,
}

/// Where a character stands when a world connection opens: map (district or
/// maze id), position, rotation (degrees) and the jump/box id it arrived by.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spot {
    pub map: u16,
    pub pos: [f32; 3],
    pub rot: f32,
    pub jump: u32,
}

/// Rocco Town start box: every login lands here.
pub fn start_spot() -> Spot {
    Spot { map: START_DISTRICT, pos: START_POS, rot: START_ROT, jump: START_JUMP_ID }
}

/// Mazes have ids 20000..30000; districts 10000..20000 (tb_Maze_Info /
/// tb_District; the reference server's GetWorldType makes the same cut).
pub fn is_maze(map: u16) -> bool {
    (20000..30000).contains(&map)
}

/// A maze's row (gamedata::MAZES): (min level, FP, start spot, escape spot).
pub struct MazeInfo {
    pub min_level: u8,
    pub fp: u16,
    pub start: Spot,
    pub escape: Option<Spot>,
    /// Maze id whose spawn rows hold this map's monsters (shared maps).
    pub spawn_key: u16,
}

pub fn maze(id: u16) -> Option<MazeInfo> {
    let &(_, lv, fp, jump, pos, rot, field, exit_box, key) = gamedata::MAZES.iter().find(|m| m.0 == id)?;
    let escape = if field == 0 { Some(start_spot()) } else { district_exit(field, exit_box) };
    Some(MazeInfo { min_level: lv, fp, start: Spot { map: id, pos, rot, jump }, escape, spawn_key: key })
}

/// A district arrival point (VStartEventBox / VPortalExitBox) by box id.
pub fn district_exit(district: u16, exit_box: u32) -> Option<Spot> {
    let &(d, b, pos, rot) = gamedata::DISTRICT_EXITS.iter().find(|e| e.0 == district && e.1 == exit_box)?;
    Some(Spot { map: d, pos, rot, jump: b })
}

/// WORLD_ENTER_REQ 4/0x01 (writer FUN_1805f4b40 -> FUN_18002c8e0, sent when
/// the player walks into a portal or picks a stage in the maze UI): u32 UAID,
/// u32 actor, u8 party type, u32 party id, u16 map id, u16 channel, i32 jump,
/// i32 portal, then the enter position, map instance, change type and next
/// position (C++ PS_ENTER_MAP_REQ). Only the head is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorldEnterReq {
    pub map: u16,
    pub portal: i32,
}

impl WorldEnterReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        r.u32()?;
        r.u32()?;
        r.u8()?;
        r.u32()?;
        let map = r.u16()?;
        r.u16()?;
        r.u32()?;
        let portal = r.u32()? as i32;
        Ok(Self { map, portal })
    }
}

/// UI strings the reference server's ReqWorldEnter answers with
/// (error 4/0x01 + id): 0xD6DB no such portal/map, 0xD6E4 level too low,
/// 0xD6E8 no soul weapon, 0xD704 not enough FP.
pub const MSG_ENTER_NO_MAP: u32 = 0xD6DB;
pub const MSG_ENTER_LEVEL: u32 = 0xD6E4;

/// Position block (reader FUN_180012610): u16 world id, u64 map instance,
/// f32 x, f32 y, f32 z (FUN_18000e740), f32 rotation.
fn pos_info(w: &mut Writer, district: u16, map_instance: u64) {
    pos_at(w, district, map_instance, [0.0; 3], 0.0);
}

fn pos_at(w: &mut Writer, district: u16, map_instance: u64, xyz: [f32; 3], rot: f32) {
    w.u16(district).u64(map_instance);
    for v in xyz {
        w.u32(v.to_bits());
    }
    w.u32(rot.to_bits());
}

/// Start position in F031_ROCCOTOWN: the map's only VStartEventBox
/// (World/Table/F031_ROCCOTOWN.vbatch in data09.v, m_ID 1000301):
/// box 10230.798,10058.951,90.452 .. 10630.798,10458.951,190.452, rotation 90.
/// Centre of the box, standing on its floor.
pub const START_POS: [f32; 3] = [10430.798, 10258.951, 90.452];
pub const START_ROT: f32 = 90.0;

/// CHARACTER_INFO_REQ 3/0x31 — FUN_1805f65c0: u32 character (app +0x10150), u8
/// (1 when app +0x104e8 == 0, i.e. first entry after the character select).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharacterInfoReq {
    pub character_id: u32,
}

impl CharacterInfoReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let character_id = r.u32()?;
        r.u8()?;
        end(&r)?;
        Ok(Self { character_id })
    }
}

/// CHARACTER_INFO_RES 3/0x32 — handler FUN_180da1170, reader FUN_180013560
/// into the player struct at DAT_181a1e3f8, then three u8 read inline:
/// ```text
/// FUN_1800134c0: character row (FUN_180012e20)            +0x000
///                position (FUN_180012610)                 +0x310 world id, +0x318 map, +0x320 xyz, +0x32c rot
///                f32, f32                                 +0x330, +0x334
/// u64, u64                                               +0x338, +0x340
/// u8 x4                                                  +0x368..+0x36b
/// u32, u32                                               +0x398, +0x3a0
/// u64 x3                                                 +0x348 .. +0x358
/// str8 (<= 0x14 bytes, FUN_18000e370 max 0x15)           +0x380
/// u64, u32 x3, u64, u64                                  +0x360, +0x36c..+0x374, +0x378, +0x3a8
/// then inline: u8 (player +0x10258), u8 world mode, u8 (DAT_181a2536e)
/// ```
/// The handler compares the world id (+0x310, -1 or 0 becomes 10001) and the
/// world-mode byte with the current scene, switches to LoadingScene/PlayScene,
/// places the player at +0x320 and sets the level from row +0x64.
/// The str8 must not be empty (FUN_18000e370 flags length 0 as an error).
/// The second u64 after the position (+0x340) is the Zenny balance: the
/// handler copies it to PlayScene +0xfb38, the same field ITEM_UPDATE_INVEN_
/// MONEY 8/0x20 (FUN_180dde8c0) overwrites.
pub fn character_info_res(row: &CharacterInfo, spot: &Spot, map_instance: u64, zenny: u64) -> Vec<u8> {
    let mut w = Writer::new();
    row.encode(&mut w);
    pos_at(&mut w, spot.map, map_instance, spot.pos, spot.rot);
    w.u32(0f32.to_bits()).u32(0f32.to_bits());
    w.u64(0).u64(zenny);
    w.u8(0).u8(0).u8(0).u8(0);
    w.u32(0).u32(0);
    w.u64(0).u64(0).u64(0);
    w.str8(" ");
    w.u64(0).u32(0).u32(0).u32(0).u64(0).u64(0);
    w.u8(0).u8(0).u8(0);
    w.finish()
}

/// GESTURE_SLOT_LOAD 0x23/0x02 — PlayScene handler FUN_180e2bd50:
/// FUN_1800207e0 (6 x u32 quick slots), FUN_180024940 (u8, u32, u8 n x u32,
/// u8 n x u32), FUN_18001c100, FUN_180038a90 (u16-counted lists). With every
/// list empty the readers consume exactly 73 bytes (Unicorn).
/// The 6 slots get the class's basic gestures from tb_Gesture: id = class * 1000
/// + 0..5 (Hello, Laugh, Sad, Cheer, Sit, Dance).
pub fn gesture_slot_load(class: u8) -> Vec<u8> {
    let mut w = Writer::new();
    for i in 0..6u32 {
        w.u32(u32::from(class) * 1000 + i);
    }
    w.u8(0).u32(0).u8(0).u8(0);
    let mut p = w.finish();
    p.resize(73, 0);
    p
}

/// DO_GESTURE 0x23/0x01 (writer FUN_1806034b0 -> FUN_180011680): 7 x u32 =
/// gesture id, f32 x, y, z, f32 rotation, two more u32 (captured: E8 03 00 00 = 1000 Hello).
pub struct GestureReq {
    pub body: [u8; 28],
}

impl GestureReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let mut body = [0u8; 28];
        for chunk in body.chunks_mut(4) {
            chunk.copy_from_slice(&r.u32()?.to_le_bytes());
        }
        end(&r)?;
        Ok(Self { body })
    }

}

/// GESTURE_SHOW 0x23/0x01 — handler FUN_180e2bb90: u32 actor (FUN_18000e5b0),
/// then FUN_18001b1b0 reads the same 7 x u32 the client sent. Without this
/// reply the client never plays the gesture (no animation, sound or chat line).
pub fn gesture_show(actor: u32, req: &GestureReq) -> Vec<u8> {
    let mut p = actor.to_le_bytes().to_vec();
    p.extend_from_slice(&req.body);
    p
}

/// Largest payload one frame can carry (u16 frame size minus header and pad).
pub const MAX_PAYLOAD: usize = 0xFFFF - 11 - 3 - 8;

/// One cash shop item as read by FUN_18000eb70 (verified with Unicorn, mixed
/// info counts consume exactly): u8 n_info, i32 index, u8 sell_active, i32 item,
/// i16 level, i32 order, u8 need_slot, i16 flags, i64 limit_time1, i64
/// limit_time2, u8 sell_count, i32 billing, n_info x {i32 item, i16 count,
/// i32 base_price, i32 price}.
fn cash_item(w: &mut Writer, p: &(u32, u32, u32, u32, &[(u32, u16, u32, u32)])) {
    let (id, item, order, billing, infos) = *p;
    w.u8(infos.len() as u8).u32(id).u8(1).u32(item).u16(1).u32(order).u8(1).u16(0);
    w.u64(0).u64(0).u8(0).u32(billing);
    for &(it, count, base, price) in infos {
        w.u32(it).u16(count).u32(base).u32(price);
    }
}

/// SHOP_CASH_LOAD 9/0x20 (handler FUN_180e0b0c0: u8 full_load + FUN_18000eb70)
/// pages for the whole tb_CashShop catalogue. The first frame
/// has u8 1 (full reload: FUN_180711c40 clears the list), later frames u8 0
/// (append); each frame stays under MAX_PAYLOAD.
pub fn shop_cash_load_pages(products: &[(u32, u32, u32, u32, &[(u32, u16, u32, u32)])]) -> Vec<Vec<u8>> {
    let mut pages = Vec::new();
    let mut rest = products;
    let mut first = true;
    loop {
        let mut body = Writer::new();
        let mut n = 0u32;
        let mut size = 5;
        while let Some(p) = rest.first() {
            let one = 1 + 4 + 1 + 4 + 2 + 4 + 1 + 2 + 8 + 8 + 1 + 4 + p.4.len() * 14;
            if size + one > MAX_PAYLOAD {
                break;
            }
            cash_item(&mut body, p);
            size += one;
            n += 1;
            rest = &rest[1..];
        }
        let mut w = Writer::new();
        w.u8(first as u8).u32(n).bytes(&body.finish());
        pages.push(w.finish());
        first = false;
        if rest.is_empty() {
            return pages;
        }
    }
}

/// ITEM_UPDATE_INVEN_MONEY 8/0x20 — PlayScene handler FUN_180dde8c0, reader
/// FUN_180015c10: u64 total Zenny (-> PlayScene +0xfb38), u32 bonus, u8 flow
/// (0 normal, 1 picked up; OpenWorker MoneyEarnFlow).
pub fn update_money(total: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(total).u32(0).u8(0);
    w.finish()
}

/// SHOP_BUY 9/0x01 request (writer FUN_18001f9f0): u32 NPC actor, u32
/// tb_Shop index, u16 count, u8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShopBuyReq {
    pub npc: u32,
    pub index: u32,
    pub count: u16,
}

impl ShopBuyReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let npc = r.u32()?;
        let index = r.u32()?;
        let count = r.u16()?;
        r.u8()?;
        end(&r)?;
        Ok(Self { npc, index, count })
    }
}

/// SHOP_BUY 9/0x01 reply — PlayScene handler FUN_180e09070: the changed item
/// list (FUN_18001e840, same as ITEM_UPDATE), u64 amount spent, u8 currency
/// (1 Zenny), u32 (non-zero: limit/cool-down message, FUN_180dcd130).
pub fn shop_buy_res(items: &[crate::db::ItemRecord], spent: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(&inventory_info(items));
    w.u64(spent).u8(1).u32(0);
    w.finish()
}

/// SHOP_SELL 9/0x02 request (writer FUN_18001fa50): u32 NPC actor, u8, then
/// FUN_18001f320: u8 n x {u8 storage, u16 slot}.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShopSellReq {
    pub npc: u32,
    pub slots: Vec<(u8, u16)>,
}

impl ShopSellReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let npc = r.u32()?;
        r.u8()?;
        let n = r.u8()?;
        let mut slots = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let st = r.u8()?;
            slots.push((st, r.u16()?));
        }
        end(&r)?;
        Ok(Self { npc, slots })
    }
}

/// SHOP_SELL 9/0x02 reply — handler FUN_180e09ba0 reads only the item list
/// (FUN_18001e840): sold stacks come back with count 0. The money follows in
/// 8/0x20. The client accepts storages 2, 4 and 0x0D here.
pub fn shop_sell_res(sold: &[crate::db::ItemRecord]) -> Vec<u8> {
    inventory_info(sold)
}

/// SHOP_REPURCHASER_LIST 9/0x03 — the client asks for the buyback list when
/// an NPC shop opens (u32 NPC actor). Reply handler FUN_180e0a220, reader
/// FUN_18001faa0: u8 n x {buyback entry}, then FUN_180021c80 and FUN_180021ec0
/// (two more counted lists); all empty = 5 zero bytes (checked under Unicorn).
/// Each buyback entry is one item (FUN_18001e000, 114 B); the two trailing
/// u16 counts are the socket and broach lists (none). Also sent after a sale
/// so the open shop shows the new entry (the handler clears and refills).
pub fn shop_repurchaser_list_empty() -> Vec<u8> {
    vec![0; 5]
}

pub fn shop_repurchaser_list(items: &[crate::db::ItemRecord]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(items.len().min(255) as u8);
    for it in items.iter().take(255) {
        item_body(&mut w, it.item_id, it.serial, it.count);
    }
    w.u16(0).u16(0);
    w.finish()
}

/// SHOP_REPURCHASER 9/0x04 request (writer FUN_1805f8ab0 -> FUN_18001fc20):
/// u32, then the buyback entry as an item (FUN_18001dd20: u32 id, u64
/// serial, u16 count, ...). Only the serial is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepurchaseReq {
    pub item_id: u32,
    pub serial: u64,
}

impl RepurchaseReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        r.u32()?;
        let item_id = r.u32()?;
        let serial = r.u64()?;
        Ok(Self { item_id, serial })
    }
}

/// SHOP_REPURCHASER 9/0x04 reply — handler FUN_180e0a480: an item list
/// (FUN_18001e840); each entry is put into its slot (FUN_180bac8c0) and the
/// buyback entry with the same serial is dropped (FUN_180d20c50 on entry
/// +0x10). Money follows in 8/0x20.
pub fn shop_repurchase_res(item: &crate::db::ItemRecord) -> Vec<u8> {
    inventory_info(std::slice::from_ref(item))
}

/// Storages the client lets you sell from (FUN_180e09ba0 compares 2, 4, 0x0D).
pub fn sellable_storage(st: u8) -> bool {
    matches!(st, storage::COMMON | storage::COSTUME | storage::CASH)
}

/// NPC shop row by tb_Shop index: (group, item, count per purchase, unit price).
pub fn npc_shop_row(index: u32) -> Option<(u32, u32, u16, u32)> {
    let i = gamedata::NPC_SHOP.binary_search_by_key(&index, |r| r.0).ok()?;
    let r = gamedata::NPC_SHOP[i];
    Some((r.1, r.2, r.3, r.4))
}

/// (sell price, buy price, stack max) of a tb_Item row.
pub fn item_prices(item_id: u32) -> Option<(u32, u32, u16)> {
    let i = gamedata::ITEM_STORAGE.binary_search_by_key(&item_id, |e| e.0).ok()?;
    let e = gamedata::ITEM_STORAGE[i];
    Some((e.3, e.4, e.5))
}

/// Cash shown in the shop while `unlimited_cash` is on (client prints it with %d).
pub const CASH_UNLIMITED: u32 = 999_999_999;

/// ITEM_UPDATE_CASH 8/0x33 — PlayScene handler FUN_180ddfb00 reads three u32:
/// cash (player +0xfb58, CashShopUI::SetCash), bonus cash (+0xfb5c, added to the
/// shown total) and soul point (+0xfb70, SetSoulPoint).
pub fn update_cash(cash: u32, bonus: u32, soul_point: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(cash).u32(bonus).u32(soul_point);
    w.finish()
}

/// SHOP_CASH_BUY 9/0x21 request (writer FUN_18000ee00): i32 n, n x {u32 shop
/// id, u8 option (index into the product's tb_CashBilling_Info entries), u16
/// quantity}, u8. Captured: 01000000 9C5D0000 00 0100 00.
pub struct CashBuyReq {
    pub items: Vec<(u32, u8, u16)>,
}

impl CashBuyReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let n = r.u32()?;
        if n > 64 {
            return Err(ParseError::TooLong { field: "cash buy list", units: n as usize, max: 64 });
        }
        let mut items = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let id = r.u32()?;
            let option = r.u8()?;
            let qty = r.u16()?;
            items.push((id, option, qty));
        }
        r.u8()?;
        end(&r)?;
        Ok(Self { items })
    }
}

/// SHOP_CASH_BUY 9/0x21 reply — handler FUN_180e0ba90: FUN_180021a20 (i16 n x
/// {u16, u64}) then FUN_1800224a0 (u8 n x u32). Empty = 3 bytes.
pub fn cash_buy_res() -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(0).u8(0);
    w.finish()
}

/// ITEM_INVEN_INFO request 8/0x01 (writer FUN_1805f6a90): u8 n + n storage
/// groups (real client: 00 03 01 02 04 0D).
pub struct InventoryInfoReq {
    pub groups: Vec<u8>,
}

impl InventoryInfoReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let n = r.u8()?;
        let mut groups = Vec::with_capacity(n as usize);
        for _ in 0..n {
            groups.push(r.u8()?);
        }
        end(&r)?;
        Ok(Self { groups })
    }
}

/// Slot count per storage group (OpenWorker StorageGroup / StorageFactory; the
/// equip groups use this client's 14 shape slots). 0 = unknown group.
pub fn storage_slots(group: u8) -> i16 {
    match group {
        0 | 3 => SHAPE_SLOTS as i16, // shape / look equip
        1 => 2,                      // ability equip
        2 | 5 => 24,                 // common bag / storage
        4 | 6 => 48,                 // costume bag / storage
        0x0B | 0x0D | 0x0E => 384,   // cube, cash bag, cash storage
        _ => 0,
    }
}

/// ITEM_OPEN_SLOT_INFO 8/0x0E — reader FUN_18001e600 (PlayScene handler
/// FUN_180dfa290): u8 n, n x {u8 group, i16 slots, u8 grade}. Without it the
/// inventory has no open slots.
pub fn open_slot_info(groups: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    let known: Vec<u8> = groups.iter().copied().filter(|&g| storage_slots(g) > 0).collect();
    w.u8(known.len() as u8);
    for g in known {
        w.u8(g).u16(storage_slots(g) as u16).u8(0);
    }
    w.finish()
}

/// One item as read by FUN_18001e000 (114 bytes; field order traced by running
/// the reader under Unicorn with a memory-read hook): u32 item, u64 serial,
/// u16 count, u8 bind, 5 x {i16 type, i32 value} options, u8, u8, u8, i64 due,
/// u8, u8, u8, i32 exp, str8 broach (length must be 1..=20, else err 1, so "0"
/// like OpenWorker), u8, u8, u8, u32, u32, u32, u8, u32, u8, u8, u32, u32,
/// u32, u32, u8, u64, u8. After the options: u8 upgrade, u8 endurance
/// (durability; C++ STItem byEndurance, OpenWorker sends 100), u8 sockets.
/// Endurance 0 showed every weapon as broken (empty red bar).
pub const ITEM_ENDURANCE: u8 = 100;

fn item_body(w: &mut Writer, item_id: u32, serial: u64, count: u16) {
    w.u32(item_id).u64(serial).u16(count).u8(0);
    for _ in 0..5 {
        w.u16(0).u32(0);
    }
    w.u8(0).u8(ITEM_ENDURANCE).u8(0).u64(0).u8(0).u8(0).u8(0).u32(0);
    w.u16(1).u8(0x30);
    w.u8(0).u8(0).u8(0).u32(0).u32(0).u32(0).u8(0).u32(0).u8(0).u8(0);
    w.u32(0).u32(0).u32(0).u32(0).u8(0).u64(0).u8(0);
}

/// ITEM_INVEN_INFO 8/0x01 — reader FUN_18001e840: i32 n, n x {u8 storage,
/// u16 slot, item (FUN_18001e000), u8}, u8. Empty inventory = 5 bytes.
pub fn inventory_info(items: &[crate::db::ItemRecord]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(items.len() as u32);
    for it in items {
        w.u8(it.storage).u16(it.slot);
        item_body(&mut w, it.item_id, it.serial, it.count);
        w.u8(0);
    }
    w.u8(0);
    w.finish()
}

/// ITEM_USE request 8/0x11 (writer FUN_18001eee0): u8 storage, u16 slot,
/// u64 serial, u8. Captured: 0D 0000 0100000000000000 01.
pub struct ItemUseReq {
    pub storage: u8,
    pub slot: u16,
    pub serial: u64,
}

impl ItemUseReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let storage = r.u8()?;
        let slot = r.u16()?;
        let serial = r.u64()?;
        r.u8()?;
        end(&r)?;
        Ok(Self { storage, slot, serial })
    }
}

/// ITEM_UPDATE 8/0x15 — handler FUN_180df95d0, same list as ITEM_INVEN_INFO
/// (FUN_18001e840). An entry with count 0 empties its slot (FUN_180baf4e0),
/// otherwise the slot is set (FUN_180bafc30).
pub fn item_update(items: &[crate::db::ItemRecord]) -> Vec<u8> {
    inventory_info(items)
}

/// ITEM_USE 8/0x11 reply — handler FUN_180dfbdb0: u32 used item id
/// (looked up in tb_Item), FUN_180020fb0 {7 x u32 rewards (0 = none), u8 n x
/// {u32 item, u16 count, u8}, 3 x u32}, then u64 (FUN_18000e5e0). Field order
/// traced under Unicorn; the item list is what the "obtained" popup shows.
pub fn item_use_res(used_item: u32, gained: &[(u32, u16)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(used_item);
    for _ in 0..7 {
        w.u32(0);
    }
    w.u8(gained.len() as u8);
    for &(item, count) in gained {
        w.u32(item).u16(count).u8(0);
    }
    w.u32(0).u32(0).u32(0).u64(0);
    w.finish()
}

/// Stat ids (OpenWorker STAT_TYPE; same numbering as the 2.3.34.7 handler's
/// "Wrong Stat index" bound 0x52).
pub mod stat {
    pub const HP_CUR: u16 = 0x01;
    pub const SG_CUR: u16 = 0x02;
    pub const ST_CUR: u16 = 0x03;
    pub const HP_MAX: u16 = 0x0A;
    pub const HP_REG: u16 = 0x0B;
    pub const SG_MAX: u16 = 0x0C;
    pub const ST_MAX: u16 = 0x0E;
    pub const ST_REG: u16 = 0x0F;
    pub const SV_CUR: u16 = 0x10;
    pub const SV_MAX: u16 = 0x11;
    pub const MSR: u16 = 0x12;
    pub const ASR: u16 = 0x13;
}

/// Starting stats sent on map load. Stamina (ST) is what running and dashing
/// spend: with ST max 0 the client never lets the character run. Values follow
/// tb_Status Con_ST_First_Value (100) / Con_ST_Reg and the 100.0 speed rate.
pub const STARTER_STATS: &[(u16, f32)] = &[
    (stat::HP_MAX, 1000.0),
    (stat::HP_CUR, 1000.0),
    (stat::SG_MAX, 100.0),
    (stat::SG_CUR, 100.0),
    (stat::SV_MAX, 100.0),
    (stat::SV_CUR, 100.0),
    (stat::ST_MAX, 100.0),
    (stat::ST_CUR, 100.0),
    (stat::ST_REG, 5.0),
    (stat::MSR, 100.0),
    (stat::ASR, 100.0),
];

/// CHARACTER_UPDATE_ORIGIN_STAT 3/0x51 — handler FUN_180ddac80: u32 actor
/// (must be the player), u8 n, n x {f32 value, u16 stat id}; ids >= 0x52 are
/// rejected ("Wrong Stat index"). Values land in the player's stat table.
pub fn update_origin_stat(actor: u32, stats: &[(u16, f32)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u8(stats.len() as u8);
    for &(id, v) in stats {
        w.u32(v.to_bits()).u16(id);
    }
    w.finish()
}

/// Storage group a cash shop item goes to, by tb_Item id range: costumes
/// (2xx_xxx_xxx) -> costume bag 4, everything else -> cash bag 0x0D.
pub fn cash_item_storage(item_id: u32) -> u8 {
    match item_class(item_id) {
        Some((inven, _)) => home_storage(inven),
        None if (200_000_000..300_000_000).contains(&item_id) => storage::COSTUME,
        None => storage::CASH,
    }
}

/// Storage groups (OpenWorker StorageGroup, same numbers as the 2.3.34.7
/// client's 8/0x01 and 8/0x02 switches).
pub mod storage {
    pub const SHAPE_EQUIP: u8 = 0;
    pub const ABILITY_EQUIP: u8 = 1;
    pub const COMMON: u8 = 2;
    pub const LOOK_EQUIP: u8 = 3;
    pub const COSTUME: u8 = 4;
    pub const CUBE: u8 = 0x0B;
    pub const CASH: u8 = 0x0D;
}

/// (Item_Inven_Type, Item_Slot_Type) of an item from tb_Item_Classify.
pub fn item_class(item_id: u32) -> Option<(u8, u8)> {
    gamedata::ITEM_STORAGE
        .binary_search_by_key(&item_id, |e| e.0)
        .ok()
        .map(|i| (gamedata::ITEM_STORAGE[i].1, gamedata::ITEM_STORAGE[i].2))
}

/// Bag for an Item_Inven_Type (OpenWorker UsableStorageType: 0 common,
/// 2 costume, 9 cube, 0x0D cash).
pub fn home_storage(inven: u8) -> u8 {
    match inven {
        2 => storage::COSTUME,
        9 => storage::CUBE,
        0x0D => storage::CASH,
        _ => storage::COMMON,
    }
}

/// Shape / look equip slot for an Item_Slot_Type: slot type - 0x0B
/// (HAIR_CAP 0x0C -> 1 ... PANTS 0x16 -> 11; real client sent slot 7 for a
/// type 0x12 costume). None for non-costume slot types.
pub fn equip_slot(slot_type: u8) -> Option<u16> {
    (0x0B..0x0B + SHAPE_SLOTS as u8).contains(&slot_type).then(|| u16::from(slot_type - 0x0B))
}

/// Gear slot (ABILITY_EQUIP, OpenWorker AbilityEquipSlot) for an
/// Item_Slot_Type: soul weapon (1) -> 0, sub weapon (2) -> 1.
pub fn ability_slot(slot_type: u8) -> Option<u16> {
    match slot_type {
        1 => Some(0),
        2 => Some(1),
        _ => None,
    }
}

/// The soul weapon slot: always holds a weapon (equip swaps, never empties).
pub const WEAPON_SLOT: (u8, u16) = (storage::ABILITY_EQUIP, 0);

/// May `item_id` sit in (storage, slot)? Costumes go to their shape / look
/// slot, weapons to their gear slot, everything goes back to its own bag.
pub fn item_fits(item_id: u32, st: u8, slot: u16) -> bool {
    let Some((inven, slot_type)) = item_class(item_id) else { return false };
    match st {
        storage::SHAPE_EQUIP | storage::LOOK_EQUIP => inven == 2 && equip_slot(slot_type) == Some(slot),
        storage::ABILITY_EQUIP => ability_slot(slot_type) == Some(slot),
        _ => st == home_storage(inven) && (slot as i16) < storage_slots(st),
    }
}

/// CHAT_GM_COMMAND request 7/0x0A (writer FUN_1805fa690 via the chat box
/// FUN_180479340): wstr command line, e.g. "/item 213881001".
pub fn parse_gm_command(p: &[u8]) -> Result<String, ParseError> {
    let mut r = Reader::new(p);
    let line = r.wstr()?;
    end(&r)?;
    Ok(line)
}

/// A parsed GM command line (leading '/' optional, case-insensitive name).
#[derive(Debug, Clone, PartialEq)]
pub enum GmCommand {
    /// /item <id> [count] — either order (the client's batch mode sends
    /// "/item 1 <id>"): the number that is a tb_Item id is the item.
    Item { item: u32, count: u16 },
    /// /cash <amount>
    Cash(u32),
    /// /movespeed <rate>, 100 = normal
    MoveSpeed(f32),
    /// /level <n> (1..=80): set the character level (applies on next map load)
    Level(u8),
    /// /killall: every monster of the maze instance dies (loot + EXP).
    KillAll,
    /// /die: the player drops to 0 HP (death / revive test).
    Die,
    /// /heal: full HP.
    Heal,
    /// /god: toggle invulnerability (monsters still attack, no HP loss).
    God,
    Help,
    Unknown(String),
}

pub fn parse_gm_line(line: &str) -> GmCommand {
    let mut it = line.trim().trim_start_matches('/').split_whitespace();
    let name = it.next().unwrap_or("").to_ascii_lowercase();
    let nums: Vec<u64> = it.filter_map(|t| t.parse().ok()).collect();
    match (name.as_str(), nums.as_slice()) {
        ("item", [a]) if item_class(*a as u32).is_some() => GmCommand::Item { item: *a as u32, count: 1 },
        ("item", [a, b]) => {
            // Item ids are 7-9 digits, counts are small: the larger number is
            // the item when both happen to be tb_Item ids (id 1 exists).
            let (item, count) = match (item_class(*a as u32).is_some(), item_class(*b as u32).is_some()) {
                (true, true) => (*a.max(b), *a.min(b)),
                (true, false) => (*a, *b),
                _ => (*b, *a),
            };
            if item_class(item as u32).is_some() {
                GmCommand::Item { item: item as u32, count: count.clamp(1, 9999) as u16 }
            } else {
                GmCommand::Unknown(line.to_string())
            }
        }
        ("cash", [n]) => GmCommand::Cash((*n).min(u64::from(u32::MAX)) as u32),
        ("movespeed", [n]) => GmCommand::MoveSpeed((*n as f32).clamp(10.0, 1000.0)),
        ("level", [n]) | ("levelup", [n]) => GmCommand::Level((*n).clamp(1, u64::from(max_level())) as u8),
        ("killall", _) | ("allkill", _) => GmCommand::KillAll,
        ("die", _) | ("suicide", _) => GmCommand::Die,
        ("heal", _) | ("hpfull", _) => GmCommand::Heal,
        ("god", _) | ("invincible", _) => GmCommand::God,
        ("help", _) | ("gm", _) => GmCommand::Help,
        _ => GmCommand::Unknown(line.to_string()),
    }
}

/// QUEST_COMPLETE_LIST 21/0x01 — handler FUN_180e14ad0: 256 raw bytes, one
/// bit per completed quest episode (OpenWorker CompletedEpisodeBits). The
/// handler also sets PlayScene flag +0x10c8 bit 0.
pub const QUEST_COMPLETE_BYTES: usize = 0x100;

pub fn quest_complete_list(done: &[u8; QUEST_COMPLETE_BYTES]) -> Vec<u8> {
    done.to_vec()
}

/// Completed-episode bits as the client reads them (FUN_18057ae90: byte i,
/// bit j -> index i * 8 + j; C++ GocQuest: Complete_Bit / 8, Complete_Bit % 8).
pub fn quest_complete_bits(bits: impl IntoIterator<Item = u16>) -> [u8; QUEST_COMPLETE_BYTES] {
    let mut done = [0u8; QUEST_COMPLETE_BYTES];
    for b in bits {
        if let Some(byte) = done.get_mut(b as usize / 8) {
            *byte |= 1 << (b % 8);
        }
    }
    done
}

/// Until quest progress exists, the story episodes that gate town NPCs
/// (Trisha, Janice, Eo — tb_NPC show condition) count as completed.
pub fn default_completed_episodes() -> [u8; QUEST_COMPLETE_BYTES] {
    quest_complete_bits(gamedata::NPC_UNLOCK_EPISODES.iter().map(|e| e.1))
}

/// QUEST_LIST 21/0x02 — handler FUN_180e14bb0: readers FUN_180038d70 +
/// FUN_180038f00; the empty list is 4 bytes (two empty i16 counts, checked
/// under Unicorn). Sets PlayScene flag +0x10c8 bit 1.
///
/// The PlayScene tick FUN_180466740 only spawns NPCs queued by 4/0x22 while
/// one of these flag bits is set: without both quest packets NPCs never show.
pub fn quest_list_empty() -> Vec<u8> {
    vec![0; 4]
}

#[cfg(test)]
mod ai_tests {
    use super::*;

    #[test]
    fn jp_ai_and_navmesh() {
        // Howler (30102003): Ai_MOB_0226_Howler, 3 skills (1301020030..32).
        let (ai, sk) = monster_ai(30102003);
        assert!(ai.is_some());
        assert_eq!(&sk[..3], &[1301020030, 1301020031, 1301020032]);
        let def = &gamedata::AIS[usize::from(ai.unwrap())];
        assert_eq!(def.groups.len(), 3);
        assert_eq!(def.check_ms, 100);
        // CZ43 navmesh: every spawn and the start box are walkable, far away is not.
        assert!(navmesh(21211).is_some());
        for &(x, y) in &[(9112.2, 25245.0), (9311.2, 21327.1), (8780.2, 15213.0), (8696.7, 12292.6)] {
            assert!(walkable(21211, x, y), "{x},{y}");
        }
        assert!(!walkable(21211, 20000.0, 20000.0));
        // A step toward an off-mesh point never leaves the mesh.
        let p = nav_step(21211, [9112.2, 25245.0, 10.0], [30000.0, 25245.0, 10.0], 500.0);
        assert!(walkable(21211, p[0], p[1]));
        // Most mazes have a navmesh, most spawned monsters a script.
        assert!(gamedata::NAVMESH.len() > 300);
        let scripted = gamedata::MONSTER_AI.iter().filter(|m| m.1 != u16::MAX).count();
        assert!(scripted > 3000, "{scripted}");
        // Spawn steps: CZ43 boxes 40291/40292 (Howler Very Hard) are step 2.
        let load = trigger_boxes(21211, None);
        assert!(!load.contains(&40291) && !load.contains(&40292) && load.contains(&40111));
        assert_eq!(step_boxes(21211, 10001, 2), vec![40291, 40292]);
        assert_eq!(step_ratio(21211, 10001, 1), 100);
        assert_eq!(max_step(21211, 10001), 2);
        // 3/0x34 player HP also lives in the u64.
        let p = stat_list(1, &[(stat::HP_MAX, 900.0), (stat::HP_CUR, 450.0)]);
        assert_eq!(u64::from_le_bytes(p[11..19].try_into().unwrap()), 900);
        assert_eq!(u64::from_le_bytes(p[25..33].try_into().unwrap()), 450);
        // 0x17/0x12 carries HP in the u64 the client reads.
        let p = monster_stat(0x4000_0001, 1234, 5000);
        assert_eq!(u64::from_le_bytes(p[11..19].try_into().unwrap()), 5000);
        assert_eq!(u64::from_le_bytes(p[25..33].try_into().unwrap()), 1234);
        // The step-2 Howler pair (21 units apart, radius 120) is pushed apart.
        let mut next = 0;
        let mut pair = monsters_for_boxes(21211, &[40291, 40292], &mut next);
        assert_eq!(pair.len(), 2);
        for _ in 0..4 {
            separate(21211, &mut pair);
        }
        let d = ((pair[0].pos[0] - pair[1].pos[0]).powi(2) + (pair[0].pos[1] - pair[1].pos[1]).powi(2)).sqrt();
        assert!(d >= 150.0, "{d}");
        assert!(pair.iter().all(|m| walkable(21211, m.pos[0], m.pos[1])));
        // Level cap from the client table, and EXP carries past 80.
        assert_eq!(max_level(), 100);
        assert_eq!(add_exp(80, 0, level_need(80).unwrap()).0, 81);
        assert_eq!(add_exp(100, 0, u32::MAX).0, 100);
        assert!(matches!(parse_gm_line("/level 95"), GmCommand::Level(95)));
        assert!(matches!(parse_gm_line("/level 250"), GmCommand::Level(100)));
    }
}

#[cfg(test)]
mod shop_tests {
    use super::*;

    #[test]
    fn shop_requests_and_tables() {
        // Captured shape of FUN_18001f9f0: actor, index, count, u8.
        let mut p = Vec::new();
        p.extend_from_slice(&0x2000_0005u32.to_le_bytes());
        p.extend_from_slice(&1191u32.to_le_bytes());
        p.extend_from_slice(&3u16.to_le_bytes());
        p.push(0);
        assert_eq!(ShopBuyReq::parse(&p).unwrap(), ShopBuyReq { npc: 0x2000_0005, index: 1191, count: 3 });
        let sell = [5, 0, 0, 0x20, 0, 2, 2, 3, 0, 0x0D, 1, 0];
        assert_eq!(ShopSellReq::parse(&sell).unwrap().slots, vec![(2, 3), (0x0D, 1)]);
        // tb_Shop 1191 (group 1006): HP potion 800004001 x1, price from tb_Item.
        let (group, item, count, price) = npc_shop_row(1191).unwrap();
        assert_eq!((group, item, count, price), (1006, 800004001, 1, 0));
        assert_eq!(item_prices(800004001), Some((10, 200, 50)));
        assert_eq!(item_prices(111011301), Some((54, 1080, 1)));
        assert_eq!(update_money(1234).len(), 13);
        let it = |slot, count| crate::db::ItemRecord { serial: 7, storage: 2, slot, item_id: 800004001, count };
        assert_eq!(shop_repurchaser_list(&[]), shop_repurchaser_list_empty());
        assert_eq!(shop_repurchaser_list(&[it(0, 3)]).len(), 1 + 114 + 4);
        assert_eq!(item_combine_res(1, &it(0, 0), &it(1, 5)).len(), 247);
        assert_eq!(item_divide_res(&it(0, 3), &it(1, 2)).len(), 134);
        assert_eq!(item_break_res(2, 3, 7).len(), 11);
        // Maze data from the client files: Control Zone 43 Awakening.
        let m = maze(21211).unwrap();
        assert_eq!((m.min_level, m.fp, m.start.jump), (2, 2, 2121101));
        assert_eq!(m.escape.unwrap().map, START_DISTRICT);
        assert!(is_maze(21211) && !is_maze(START_DISTRICT));
        let mut e = vec![0u8; 13];
        e.extend_from_slice(&21211u16.to_le_bytes());
        e.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x9E, 0x52, 0, 0]);
        assert_eq!(WorldEnterReq::parse(&e).unwrap(), WorldEnterReq { map: 21211, portal: 21150 });
        assert_eq!(parse_gm_line("/level 10"), GmCommand::Level(10));
        assert_eq!(character_level(1, 10), vec![1, 0, 0, 0, 10, 0, 0, 0, 1]);
        // Control Zone 43 has monsters on load and behind check box 80101.
        let mut next = 0;
        let load = maze_monsters(21211, None, &mut next);
        assert!(!load.is_empty() && load.iter().all(|m| m.actor & ACTOR_MONSTER != 0 && m.hp > 0));
        let more = maze_monsters(21211, Some(80101), &mut next);
        assert_eq!(more.iter().map(|m| m.spawn_box).collect::<Vec<_>>(), vec![40115, 40116]);
        // Every maze in the client data can be entered; variants that share
        // a map get its monsters.
        assert!(gamedata::MAZES.len() > 700, "{}", gamedata::MAZES.len());
        let with_mobs = gamedata::MAZES.iter().filter(|m| is_maze(m.0) && !maze_monsters(m.0, None, &mut 0).is_empty()).count();
        assert!(with_mobs > 500, "{with_mobs}");
        assert_eq!(world_monsters(&more).len(), 2 + 2 * 123);
        assert_eq!(active_skill_res().len(), 27);
        let req = ActiveSkillReq { skill: 1, pos: [0.0; 3], rot: 0.0 };
        assert_eq!(action_skill_bt(1, &req, &[Hit { actor: 2, damage: 5, hp: 1 }], 1).len(), 1 + 60 + 34);
        assert_eq!(parse_pre_targets(&[2, 1, 0, 0, 0x40, 2, 0, 0, 0x40]), vec![0x4000_0001, 0x4000_0002]);
        // Drops: Howler (rank 4) has 100 % gold.
        let mut seed = 7u32;
        let mut rand = |lo: u32, hi: u32| {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            lo + (seed >> 8) % (hi - lo + 1)
        };
        let mut sn = 0u64;
        let mut serial = || {
            sn += 1;
            sn
        };
        let d = roll_drops(30102003, [0.0; 3], &mut rand, &mut serial);
        assert!(d.iter().any(|x| x.item == DROP_ZENNY && (90..=116).contains(&x.count)));
        assert_eq!(drop_infos(1, &d).len(), 11 + 34 * d.len());
        assert_eq!(parse_pick_up(&[1, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0]).unwrap(), (1, 9));
        // Level 1 needs 217 EXP (GB tb_Levelup_Point).
        assert_eq!(add_exp(1, 200, 20), (2, 3));
        assert_eq!(add_exp(1, 0, 10), (1, 10));
        // Captured "Select Character": actor 1, account 1012, type 1.
        let g = [1, 0, 0, 0, 0xF4, 3, 0, 0, 1, 0, 0, 0, 0];
        assert_eq!(GoBackLobbyReq::parse(&g).unwrap(), GoBackLobbyReq { kind: 1 });
        // Captured MAZE_CREATE 4/0x41 (Control Zone 43 Awakening via portal
        // 21106): same head as WORLD_ENTER_REQ.
        let mut mc = vec![0u8; 13];
        mc.extend_from_slice(&[0xDB, 0x52, 0, 0, 0, 0, 0, 0, 0x72, 0x52, 0, 0]);
        assert_eq!(WorldEnterReq::parse(&mc).unwrap(), WorldEnterReq { map: 21211, portal: 21106 });
        assert_eq!(repair_npc_res(&it(0, 1), 0).len(), 3 + 114 + 1 + 8);
        assert_eq!(repair_list_res(&[], 0).len(), 13);
        assert_eq!(RepairNpcReq::parse(&[5, 0, 0, 0x20, 1, 0, 0]).unwrap().at, (1, 0));
        assert_eq!(item_line_up_res(2, &[it(0, 1), it(1, 1)]).len(), 3 + 2 * 13);
        let mut c = vec![2, 0xA1, 0x11, 0xB0, 0x2F, 0, 0, 0, 2, 0xA1, 0x11, 0xB0, 0x2F, 1, 0, 0];
        c.extend_from_slice(&4u16.to_le_bytes());
        assert_eq!(ItemCombineReq::parse(&c).unwrap(), ItemCombineReq { src: (2, 0), dest: (2, 1), count: 4 });
        let d = [2, 0xA1, 0x11, 0xB0, 0x2F, 0, 0, 2, 5, 0, 3, 0];
        assert_eq!(ItemDivideReq::parse(&d).unwrap(), ItemDivideReq { src: (2, 0), dest: (2, 5), count: 3 });
    }
}

#[cfg(test)]
mod quest_bit_tests {
    use super::*;

    #[test]
    fn complete_bits_match_client_layout() {
        let done = quest_complete_bits([0, 19, 43, 2047]);
        assert_eq!(done[0], 1);
        assert_eq!(done[2], 1 << 3);
        assert_eq!(done[5], 1 << 3);
        assert_eq!(done[255], 0x80);
        assert_eq!(done.iter().map(|b| b.count_ones()).sum::<u32>(), 4);
        // Trisha's episode 100185 (bit 43) is among the unlocked ones.
        let d = default_completed_episodes();
        assert!(gamedata::NPC_UNLOCK_EPISODES.iter().any(|e| e.0 == 100185));
        assert_eq!(d[43 / 8] & (1 << (43 % 8)), 1 << 3);
    }
}

/// Actor id type bits (bits 29..31; OpenWorker ActorComponent): 0 player,
/// 1 NPC, 2 monster.
pub const ACTOR_NPC: u32 = 1 << 29;

/// WORLD_OTHER_INFOS_NPC 4/0x22 — handler FUN_180deea80: i16 count, then per
/// NPC the reader FUN_180056ab0 (49 bytes, traced under Unicorn; out offset in
/// brackets): u32 actor [+0], f32 x, y, z, rotation [+0x18..+0x24]
/// (FUN_18000e740), u64 [+0x30], u64 [+0x38], u32 waypoint [+0x40], u32 sector
/// [+0x44], u8 level [+0x48], u32 NPC table id [+0x28] (OpenWorker order:
/// actor, position, rotation, hp, waypoint, sector, level, prototype).
pub fn world_npcs(npcs: &[(u32, [f32; 3], f32, u32, u32)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(npcs.len() as u16);
    for (i, &(id, pos, rot, waypoint, sector)) in npcs.iter().enumerate() {
        w.u32(ACTOR_NPC | (i as u32 + 1));
        for v in pos {
            w.u32(v.to_bits());
        }
        w.u32(rot.to_bits());
        w.u64(100).u64(100).u32(waypoint).u32(sector).u8(1).u32(id);
    }
    w.finish()
}

/// NPCs placed on a district's map (gamedata, from the map's .vbatch).
pub fn district_npcs(district: u16) -> &'static [(u32, [f32; 3], f32, u32, u32)] {
    gamedata::DISTRICT_NPCS.iter().find(|d| d.0 == district).map_or(&[], |d| d.1)
}

/// Longest chat line the client accepts (FUN_18000e4b0 max 0xFF UTF-16 units).
pub const CHAT_MAX_UNITS: usize = 0xFF;

/// CHAT_NORMAL request 7/0x01 (writer FUN_1805f9bd0; captured
/// 01 0A00 "hello" 00): u8 appearance (1 normal), wstr message, u8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatReq {
    pub appearance: u8,
    pub message: String,
}

impl ChatReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let appearance = r.u8()?;
        let message = r.wstr()?;
        r.u8()?;
        end(&r)?;
        Ok(Self { appearance, message })
    }
}

/// Chat text as it may be shown: control characters dropped, cut to the
/// client's limit (counted in UTF-16 units), surrounding blanks trimmed.
pub fn clean_chat(text: &str) -> String {
    let mut out = String::new();
    let mut units = 0;
    for c in text.chars().filter(|c| !c.is_control()) {
        units += c.len_utf16();
        if units > CHAT_MAX_UNITS {
            break;
        }
        out.push(c);
    }
    out.trim().to_string()
}

/// CHAT_NORMAL 7/0x01 reply — handler FUN_180df0c30 (inline reads): u32 actor,
/// u16, u32 chat type, wstr message, u8 n item links (clamped to 3), then n x
/// FUN_180016130 (3 x u8, u64, wstr <= 64, item, ...). The type picks where the
/// speaker's name comes from (switch at 0x180df102f): 1 = normal, name read
/// from the actor in the world (FUN_180452a70, actor +0x390); 3/4/6/11 = other
/// channels. Type 0 matched no case, so the name stayed empty and the chat line
/// showed "undefined" (real client, 2026-10-18).
/// Sending 1 link without one made the client read past the packet and abort
/// (0xC0000417, 2026-10-18), so plain chat always sends 0 links.
pub const CHAT_TYPE_NORMAL: u32 = 1;

pub fn chat_normal(actor: u32, message: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u16(0).u32(CHAT_TYPE_NORMAL).wstr(message).u8(0);
    w.finish()
}

/// ITEM_MOVE request 8/0x02 (writer FUN_18001ea70; captured equip:
/// 04 A9 90 BF 0C 0000 00 | 00 A9 90 BF 0C 0700 00): 2 x {u8 storage, u32
/// item, u16 slot, u8}.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemMoveReq {
    pub src: (u8, u16),
    pub dest: (u8, u16),
}

impl ItemMoveReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let mut side = || -> Result<(u8, u16), ParseError> {
            let st = r.u8()?;
            r.u32()?;
            let slot = r.u16()?;
            r.u8()?;
            Ok((st, slot))
        };
        let src = side()?;
        let dest = side()?;
        end(&r)?;
        Ok(Self { src, dest })
    }
}

/// ITEM_MOVE reply 8/0x02 — handler FUN_180df52d0, reader FUN_18001ef50: u8 n,
/// n x {src {u8 storage, u32 item now there (-1 empty), u16 slot, u8},
/// dest {same}, u8 src bind, u8 dest bind} (18 bytes; OpenWorker
/// ItemMoveResponse). The handler *applies* each entry as a move (switch on
/// the src storage at 0x180df56f8, then on the dest storage at 0x180df5c0b),
/// so it must only describe a move that happened: replying "unchanged" to a
/// refused weapon move took the soul weapon out of its slot and the client
/// hung (2026-10-18, twice). Refusals get `item_move_refused` instead.
/// ITEM_MOVE reply with no entries: the handler runs its loop zero times and
/// changes nothing (the client keeps the item where it was).
pub fn item_move_refused() -> Vec<u8> {
    vec![0]
}

pub fn item_move_res(src: (u8, u16, Option<u32>), dest: (u8, u16, Option<u32>)) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(1);
    for (st, slot, item) in [src, dest] {
        w.u8(st).u32(item.unwrap_or(u32::MAX)).u16(slot).u8(0);
    }
    w.u8(0).u8(0);
    w.finish()
}

/// ITEM_COMBINE 8/0x03 request (writer FUN_18001ed40): the ITEM_MOVE pair
/// (FUN_18001ea70) + u16 count to move from src onto dest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemCombineReq {
    pub src: (u8, u16),
    pub dest: (u8, u16),
    pub count: u16,
}

impl ItemCombineReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        if p.len() < 2 {
            return Err(ParseError::TrailingBytes(0));
        }
        let (mv, tail) = p.split_at(p.len() - 2);
        let m = ItemMoveReq::parse(mv)?;
        Ok(Self { src: m.src, dest: m.dest, count: u16::from_le_bytes([tail[0], tail[1]]) })
    }
}

/// ITEM_COMBINE 8/0x03 reply — reader FUN_18001f050 (traced under Unicorn):
/// 2 x {u32 actor, u8 storage, u16 slot, item, u8, u8} + u8 = 247 bytes
/// (OpenWorker's older layout lacks the two u8 per side). The handler sets
/// each side's slot from its item (FUN_180bb1b40; count 0 empties it).
pub fn item_combine_res(actor: u32, src: &crate::db::ItemRecord, dest: &crate::db::ItemRecord) -> Vec<u8> {
    let mut w = Writer::new();
    for it in [src, dest] {
        w.u32(actor).u8(it.storage).u16(it.slot);
        item_body(&mut w, it.item_id, it.serial, it.count);
        w.u8(0).u8(0);
    }
    w.u8(0);
    w.finish()
}

/// ITEM_DIVIDE 8/0x04 request (writer FUN_18001ecb0): u8 src storage, u32
/// item, u16 src slot, u8 dest storage, u16 dest slot, u16 count (12 B; one
/// byte shorter than OpenWorker's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemDivideReq {
    pub src: (u8, u16),
    pub dest: (u8, u16),
    pub count: u16,
}

impl ItemDivideReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let st = r.u8()?;
        r.u32()?;
        let sl = r.u16()?;
        let dst = r.u8()?;
        let dsl = r.u16()?;
        let count = r.u16()?;
        end(&r)?;
        Ok(Self { src: (st, sl), dest: (dst, dsl), count })
    }
}

/// ITEM_DIVIDE 8/0x04 reply — reader FUN_18001ed80: u32 item, u8 src
/// storage, u16 src slot, u16 src count left, u64 src serial, u8 dest
/// storage, u16 dest slot, dest item (134 B; C++ PS_RES_ITEM_DIVIDE + serial).
pub fn item_divide_res(src: &crate::db::ItemRecord, dest: &crate::db::ItemRecord) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(src.item_id).u8(src.storage).u16(src.slot).u16(src.count).u64(src.serial);
    w.u8(dest.storage).u16(dest.slot);
    item_body(&mut w, dest.item_id, dest.serial, dest.count);
    w.finish()
}

/// ITEM_BREAK 8/0x05 request (writer FUN_1805f6de0): u8 storage, u16 slot,
/// u64 serial, u32 count = throw an item away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemBreakReq {
    pub at: (u8, u16),
    pub serial: u64,
    pub count: u32,
}

impl ItemBreakReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let st = r.u8()?;
        let sl = r.u16()?;
        let serial = r.u64()?;
        let count = r.u32()?;
        end(&r)?;
        Ok(Self { at: (st, sl), serial, count })
    }
}

/// ITEM_BREAK 8/0x05 reply — handler FUN_180df75f0 reads u8 storage, u16
/// slot, u64 serial inline and empties that slot (FUN_180baf4e0). A partly
/// thrown-away stack is sent as ITEM_UPDATE 8/0x15 instead.
pub fn item_break_res(storage: u8, slot: u16, serial: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(storage).u16(slot).u64(serial);
    w.finish()
}

/// Bags the player may throw items out of / sort (not the equip slots).
pub fn bag_storage(st: u8) -> bool {
    matches!(st, storage::COMMON | storage::COSTUME | storage::CASH)
}

/// ITEM_LINE_UP 8/0x25 reply (request = u8 storage, writer FUN_1805f72a0) —
/// handler FUN_180dfd7c0, reader FUN_1800204b0: u8 storage, u16 n, n x {u8
/// storage, u16 slot, u64 serial, u16 count}. The handler empties the bag
/// and puts each listed serial at its slot, so the list must hold every item.
pub fn item_line_up_res(storage: u8, items: &[crate::db::ItemRecord]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(storage).u16(items.len() as u16);
    for it in items {
        w.u8(it.storage).u16(it.slot).u64(it.serial).u16(it.count);
    }
    w.finish()
}

/// ITEM_REPAIR_NPC 0x18/0x09 request (writer FUN_1805fb4b0): u32 NPC actor,
/// u8 storage, u16 slot (FUN_18001f280) = repair one item at an NPC (Zyte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairNpcReq {
    pub at: (u8, u16),
}

impl RepairNpcReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        r.u32()?;
        let st = r.u8()?;
        let sl = r.u16()?;
        end(&r)?;
        Ok(Self { at: (st, sl) })
    }
}

/// ITEM_REPAIR_NPC 0x18/0x09 reply — handler FUN_180e11ae0: FUN_18001e790
/// {u8 storage, u16 slot, item, u8} then u64 Zenny paid (shown in the
/// message). Endurance is always full (ITEM_ENDURANCE) until combat wears
/// gear down, so a repair costs 0 and only refreshes the item.
pub fn repair_npc_res(it: &crate::db::ItemRecord, paid: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(it.storage).u16(it.slot);
    item_body(&mut w, it.item_id, it.serial, it.count);
    w.u8(0).u64(paid);
    w.finish()
}

/// ITEM_REPAIR_EQUIP 0x18/0x10 / ITEM_REPAIR_ALL 0x18/0x11 (request u32 NPC
/// actor) — handlers FUN_180e12520 / FUN_180e12b10: item list (FUN_18001e840)
/// then u64 Zenny paid.
pub fn repair_list_res(items: &[crate::db::ItemRecord], paid: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(&inventory_info(items)).u64(paid);
    w.finish()
}

/// CHARACTER_LEVEL 3/0x36 — handler FUN_180ddb400, reader FUN_18002d680:
/// u32 actor, u32 level, u8 flag. The client sets the actor's level at once
/// (FUN_1803fa660; OpenWorker PersonLevelResponse) and refreshes the UI.
pub fn character_level(actor: u32, level: u8) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u32(u32::from(level)).u8(1);
    w.finish()
}

/// CHARACTER_GOBACK_LOBBY 3/0x60 request (writer FUN_180602d60 ->
/// FUN_180034ae0, menu "Select Character"/"Change Character"): u32 actor,
/// u32 account, u8 type, u32 (OpenWorker PersonChangeServerRequest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoBackLobbyReq {
    pub kind: u8,
}

impl GoBackLobbyReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        r.u32()?;
        r.u32()?;
        Ok(Self { kind: r.u8()? })
    }
}

/// CHARACTER_GOBACK_LOBBY 3/0x60 reply — handler FUN_180e2afc0, reader
/// FUN_180034b40: u32 actor, u32 account, str8 host, u16 port, u8 type, u32,
/// u8 ok. ok != 0: type 0 reconnects to the login side and opens the server
/// select (LoginScene state 4); type 1/2 show LoadingScene, reconnect to the
/// game server and open the character select (state 5). The type is echoed.
/// ok == 0 shows UI string 0xBF6C and stays in the world.
pub fn goback_lobby_res(actor: u32, account: u32, host: &str, port: u16, kind: u8) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u32(account).str8(host).u16(port).u8(kind).u32(0).u8(1);
    w.finish()
}

// ---------------------------------------------------------------- combat

/// Actor id type bits 29..31: 1 NPC, 2 monster (OpenWorker ActorType).
pub const ACTOR_MONSTER: u32 = 2 << 29;

/// A monster living in a maze instance (server-side state).
#[derive(Debug, Clone, PartialEq)]
pub struct Monster {
    pub actor: u32,
    pub id: u32,
    pub level: u8,
    pub rank: u8,
    pub hp: i64,
    pub max_hp: i64,
    pub pos: [f32; 3],
    pub rot: f32,
    pub sector: u32,
    pub waypoint: u32,
    pub spawn_box: u32,
    /// Physical attack (tb_Monster PATK, else derived from the level).
    pub patk: i64,
    /// First monster skill (tb_Monster Monster_Skill1_ID) and its reach.
    pub skill: u32,
    pub range: f32,
    /// Run speed (units / s) and the distance it notices the player at.
    pub speed: f32,
    pub sight: f32,
    /// Counts for a sector clear (XMaze::IsSectorClearConditionBox).
    pub counts: bool,
    // AI state (maze.rs)
    pub home: [f32; 3],
    pub aggro: bool,
    pub moving: bool,
    pub next_act: u64,
    pub next_move: u64,
    /// AI script (index into gamedata::AIS) and the 10 skill slots.
    pub ai: Option<u16>,
    pub skills: [u32; 10],
    pub spawned_ms: u64,
    pub attacked: bool,
    /// Last skill slot used and when each slot is ready again.
    pub cooldowns: [u64; 10],
    /// Body radius (tb_Monster Monster_CollisionRadius, world units).
    pub radius: f32,
}

/// AI script and skill slots of a monster (tb_Monster Monster_AI_ID,
/// Monster_Skill1..10_ID).
pub fn monster_ai(id: u32) -> (Option<u16>, [u32; 10]) {
    match gamedata::MONSTER_AI.binary_search_by_key(&id, |m| m.0) {
        Ok(i) => {
            let (_, ai, sk, _) = gamedata::MONSTER_AI[i];
            (if ai == u16::MAX { None } else { Some(ai) }, sk)
        }
        Err(_) => (None, [0; 10]),
    }
}

/// Body radius of a monster (default 60 when the table has none).
pub fn monster_radius(id: u32) -> f32 {
    gamedata::MONSTER_AI
        .binary_search_by_key(&id, |m| m.0)
        .ok()
        .map(|i| f32::from(gamedata::MONSTER_AI[i].3))
        .filter(|r| *r > 0.0)
        .unwrap_or(60.0)
}

/// Push overlapping monsters apart (each pair at least the sum of their
/// radii, never off the navmesh). Returns the indices that moved.
pub fn separate(key: u16, mons: &mut [Monster]) -> Vec<usize> {
    let mut moved = Vec::new();
    let n = mons.len();
    for i in 0..n {
        if mons[i].hp <= 0 {
            continue;
        }
        for j in (i + 1)..n {
            if mons[j].hp <= 0 {
                continue;
            }
            let (a, b) = (mons[i].pos, mons[j].pos);
            let (dx, dy) = (b[0] - a[0], b[1] - a[1]);
            let d = (dx * dx + dy * dy).sqrt();
            let want = (mons[i].radius + mons[j].radius) * 0.8;
            if d >= want {
                continue;
            }
            // Same point: split along a fixed, actor-dependent direction.
            let (ux, uy) = if d < 1.0 {
                let ang = (mons[j].actor.wrapping_mul(2654435761) % 360) as f32 * std::f32::consts::PI / 180.0;
                (ang.cos(), ang.sin())
            } else {
                (dx / d, dy / d)
            };
            let push = (want - d) / 2.0;
            let na = [a[0] - ux * push, a[1] - uy * push, a[2]];
            let nb = [b[0] + ux * push, b[1] + uy * push, b[2]];
            if walkable(key, na[0], na[1]) {
                mons[i].pos = na;
                moved.push(i);
            }
            if walkable(key, nb[0], nb[1]) {
                mons[j].pos = nb;
                moved.push(j);
            }
        }
    }
    moved.sort_unstable();
    moved.dedup();
    moved
}

/// Navmesh of a maze (spawn key) as (vertices, faces).
pub fn navmesh(key: u16) -> Option<(&'static [[f32; 2]], &'static [&'static [u16]])> {
    gamedata::NAVMESH.iter().find(|n| n.0 == key).map(|n| (n.1, n.2))
}

fn in_poly(p: [f32; 2], verts: &[[f32; 2]], face: &[u16]) -> bool {
    let mut inside = false;
    let n = face.len();
    for i in 0..n {
        let a = verts[face[i] as usize];
        let b = verts[face[(i + 1) % n] as usize];
        if (a[1] > p[1]) != (b[1] > p[1]) && p[0] < (b[0] - a[0]) * (p[1] - a[1]) / (b[1] - a[1]) + a[0] {
            inside = !inside;
        }
    }
    inside
}

/// Is (x, y) on the walkable navmesh of this maze? Maps without a navmesh
/// count as walkable everywhere.
pub fn walkable(key: u16, x: f32, y: f32) -> bool {
    match navmesh(key) {
        Some((v, faces)) => faces.iter().any(|f| in_poly([x, y], v, f)),
        None => true,
    }
}

/// Step from `from` toward `to` by at most `step`, staying on the navmesh:
/// the straight step, else the same step slid along x or y, else stay.
pub fn nav_step(key: u16, from: [f32; 3], to: [f32; 3], step: f32) -> [f32; 3] {
    let (dx, dy) = (to[0] - from[0], to[1] - from[1]);
    let d = (dx * dx + dy * dy).sqrt();
    if d < 1.0 {
        return from;
    }
    let s = step.min(d);
    let (ux, uy) = (dx / d, dy / d);
    for (mx, my) in [(ux, uy), (ux.signum(), 0.0), (0.0, uy.signum())] {
        let (nx, ny) = (from[0] + mx * s, from[1] + my * s);
        if walkable(key, nx, ny) {
            return [nx, ny, from[2]];
        }
    }
    from
}

/// HP when the tb_Monster has none for a GB-era monster: grows with the
/// level and the rank (0 slave/normal .. 4 boss, 5 raid).
fn derived_hp(level: u8, rank: u8) -> i64 {
    // Follows the rank-1 medians (lv 10 ~435, 20 ~3600, 50 ~7700).
    let l = i64::from(level);
    let base = 50 + 40 * l + 6 * l * l;
    let mult = [6, 10, 20, 30, 60, 100, 10];
    base * mult[usize::from(rank.min(6))] / 10
}

/// Attack when the table has none (GB-only monsters).
fn derived_patk(level: u8) -> i64 {
    let l = i64::from(level);
    10 + 4 * l + (6 * l * l) / 10
}

/// The maze id whose spawn rows hold `map`'s boxes (variants share maps).
pub fn spawn_key(map: u16) -> u16 {
    maze(map).map_or(map, |m| m.spawn_key)
}

/// Monsters for maze `maze`: spawn boxes that appear when the map loads
/// (`check = None`) or the boxes a VCheckMonsterSpawnBox releases. One
/// monster per box (m_iMaxEntityCount is 1 in the boxes seen so far), first
/// slot id; actor ids continue from `next`.
pub fn maze_monsters(maze: u16, check: Option<u32>, next: &mut u32) -> Vec<Monster> {
    let key = spawn_key(maze);
    monsters_for_boxes(key, &trigger_boxes(key, check), next)
}

/// Spawn boxes released on map load (`None`) or by a check box.
pub fn trigger_boxes(key: u16, check: Option<u32>) -> Vec<u32> {
    match check {
        // Map load: Immediate boxes of the first spawn step only.
        None => gamedata::MAZE_SPAWNS.iter().filter(|s| s.0 == key && s.2 && s.8 <= 1).map(|s| s.1).collect(),
        Some(c) => gamedata::MAZE_CHECKS.iter().find(|k| k.0 == key && k.1 == c).map_or(Vec::new(), |k| k.2.to_vec()),
    }
}

/// One monster per spawn box (first slot id); actor ids continue from `next`.
pub fn monsters_for_boxes(key: u16, boxes: &[u32], next: &mut u32) -> Vec<Monster> {
    let mut out = Vec::new();
    for &b in boxes {
        let Some(&(_, bid, _, ids, pos, rot, sector, waypoint, _)) = gamedata::MAZE_SPAWNS.iter().find(|s| s.0 == key && s.1 == b) else {
            continue;
        };
        let Some(&id) = ids.first() else { continue };
        let row = gamedata::MONSTERS.iter().find(|m| m.0 == id);
        let (level, rank, hp, patk, skill, speed, sight, counts) =
            row.map_or((1, 1, 0, 0, 0, 0, 0, true), |m| (m.1, m.2, m.3, m.4, m.5, m.6, m.7, m.8));
        let max_hp = if hp > 0 { i64::from(hp) } else { derived_hp(level, rank) };
        let patk = if patk > 0 { i64::from(patk) } else { derived_patk(level) };
        let range = skill_row(skill).map_or(250.0, |s| f32::from(s.3.max(150)));
        *next += 1;
        out.push(Monster {
            actor: ACTOR_MONSTER | *next,
            id,
            level,
            rank,
            hp: max_hp,
            max_hp,
            pos,
            rot,
            sector,
            waypoint,
            spawn_box: bid,
            patk,
            skill,
            range: range.min(600.0),
            speed: if speed > 0 { f32::from(speed) } else { 300.0 },
            sight: if sight > 0 { (sight as f32).min(1500.0) } else { 1000.0 },
            counts,
            home: pos,
            aggro: false,
            moving: false,
            next_act: 0,
            next_move: 0,
            ai: monster_ai(id).0,
            skills: monster_ai(id).1,
            spawned_ms: 0,
            attacked: false,
            cooldowns: [0; 10],
            radius: monster_radius(id),
        });
    }
    out
}

/// tb_Skill combat row: (skill, damage ratio %, basic damage, range, cooldown ms).
pub fn skill_row(skill: u32) -> Option<&'static (u32, u16, u32, u16, u32, u8, u16)> {
    gamedata::SKILLS.binary_search_by_key(&skill, |s| s.0).ok().map(|i| &gamedata::SKILLS[i])
}

/// Sectors of a maze map in order: (sector id, boss sector, exit portal).
pub fn maze_sectors(key: u16) -> Vec<(u32, bool, u32)> {
    gamedata::MAZE_SECTORS.iter().filter(|s| s.0 == key).map(|s| (s.1, s.3, s.4)).collect()
}

/// Sector a spawn box belongs to.
pub fn box_sector(key: u16, b: u32) -> Option<u32> {
    gamedata::MAZE_SPAWNS.iter().find(|s| s.0 == key && s.1 == b).map(|s| s.6)
}

/// Does this box spawn a monster that counts for a sector clear?
pub fn box_counts(key: u16, b: u32) -> bool {
    gamedata::MAZE_SPAWNS
        .iter()
        .find(|s| s.0 == key && s.1 == b)
        .and_then(|s| s.3.first())
        .is_some_and(|id| gamedata::MONSTERS.iter().find(|m| m.0 == *id).is_none_or(|m| m.8))
}

/// Kill ratio (%) that completes spawn step `step` (1-based) of a sector;
/// 0 = no such step.
pub fn step_ratio(key: u16, sector: u32, step: u8) -> u8 {
    gamedata::MAZE_SECTORS
        .iter()
        .find(|s| s.0 == key && s.1 == sector)
        .and_then(|s| s.5.get(usize::from(step.max(1) - 1)).copied())
        .unwrap_or(0)
}

/// Immediate boxes of a sector that belong to spawn step `step`.
pub fn step_boxes(key: u16, sector: u32, step: u8) -> Vec<u32> {
    gamedata::MAZE_SPAWNS.iter().filter(|s| s.0 == key && s.2 && s.6 == sector && s.8 == step).map(|s| s.1).collect()
}

/// Highest spawn step any box of a sector uses.
pub fn max_step(key: u16, sector: u32) -> u8 {
    gamedata::MAZE_SPAWNS.iter().filter(|s| s.0 == key && s.6 == sector).map(|s| s.8).max().unwrap_or(1)
}

/// WaitSignal boxes of a sector that no check box releases (boss waves the
/// maze Lua starts by timer / cutscene, e.g. CZ43 boss box 40100).
pub fn sector_wait_boxes(key: u16, sector: u32, spawned: &[u32]) -> Vec<u32> {
    gamedata::MAZE_SPAWNS
        .iter()
        .filter(|s| s.0 == key && !s.2 && s.6 == sector && s.8 <= 1 && !spawned.contains(&s.1))
        .filter(|s| !gamedata::MAZE_CHECKS.iter().any(|c| c.0 == key && c.2.contains(&s.1)))
        .map(|s| s.1)
        .collect()
}

/// Portal box ids of a maze map.
pub fn maze_portal_ids(key: u16) -> Vec<u32> {
    gamedata::MAZE_PORTALS.iter().filter(|p| p.0 == key).map(|p| p.1).collect()
}

/// Landing point for a WARP_REQ: any of its ids may name the portal (its
/// jump box is used) or the landing box itself.
pub fn warp_target(key: u16, ids: &[u32]) -> Option<([f32; 3], f32)> {
    let jump = ids.iter().find_map(|&i| {
        gamedata::MAZE_PORTALS.iter().find(|p| p.0 == key && p.1 == i && !p.3).map(|p| p.5)
    });
    let land = |b: u32| gamedata::MAZE_JUMPS.iter().find(|j| j.0 == key && j.1 == b).map(|j| (j.2, j.3));
    jump.and_then(land).or_else(|| ids.iter().find_map(|&i| if i > 1000 { land(i) } else { None }))
}

/// Clear reward of a maze (tb_Maze_Info), else a level-based fallback.
pub fn maze_reward(map: u16, level: u8) -> (u32, u32) {
    match gamedata::MAZE_REWARDS.iter().find(|r| r.0 == map) {
        Some(&(_, e, m)) if e > 0 || m > 0 => (e, m),
        _ => (level_need(level).unwrap_or(1000) / 8, 200 * u32::from(level.max(1))),
    }
}

/// Clear rank 0 F .. 5 SS (SoulMeter SWPacketMazeEnd): fast clears rank high.
pub fn clear_rank(secs: u32, kills: u32) -> u8 {
    let pace = if kills == 0 { u32::MAX } else { secs / kills.max(1) };
    match pace {
        0..=3 => 5,
        4..=5 => 4,
        6..=8 => 3,
        9..=12 => 2,
        13..=20 => 1,
        _ => 0,
    }
}

/// Character max HP (tb_Status Con_HP_First_Value per class, growing
/// with the level).
pub fn player_max_hp(class: u8, level: u8) -> i64 {
    let first = gamedata::CLASS_STATUS.iter().find(|c| c.0 == class).map_or(1000, |c| i64::from(c.1));
    let l = i64::from(level.max(1));
    first + 150 * (l - 1) + 8 * l * l
}

/// Player attack for a level until gear stats are summed.
pub fn player_attack(level: u8) -> i64 {
    let l = i64::from(level.max(1));
    40 + 20 * l + 2 * l * l
}

/// Damage of a player skill on a monster: the CMoverEx formula
/// (attack, +-10 %, then x Skill_Add_Damage_RAT % + basic damage, then the
/// target's defence curve 1 - def / (def + 50 * level)).
pub fn skill_damage(skill: u32, level: u8, target_level: u8, roll: u32) -> i64 {
    let (ratio, basic) = skill_row(skill).map_or((100, 0), |s| (i64::from(s.1.max(30)), i64::from(s.2)));
    let atk = player_attack(level) * (90 + i64::from(roll % 21)) / 100;
    let raw = (atk + basic) * ratio / 100;
    let def = 2 * i64::from(target_level);
    (raw - raw * def / (def + 50 * i64::from(target_level.max(1)))).max(1)
}

/// A monster's hit on the player (same defence curve with the player's level).
pub fn monster_damage(m: &Monster, player_level: u8, roll: u32) -> i64 {
    let ratio = skill_row(m.skill).map_or(100, |s| i64::from(s.1.max(30)));
    let raw = m.patk * ratio / 100 * (90 + i64::from(roll % 21)) / 100;
    let def = 5 * i64::from(player_level.max(1));
    (raw - raw * def / (def + 50 * i64::from(player_level.max(1)))).max(1)
}

/// SECTOR_CLEAR 17/0x52 — handler FUN_180e03350 (u32 sector, u8 1; calls
/// the map Lua OnSectorClearFromServer, boss sector -> EndMazeProcess1).
/// SECTOR_INFOS 17/0x53 — handler FUN_180e035e0 (XMaze::SendSectorInfos):
/// u32 n active sectors, n x u32 sector id, u32 sector the player stands in.
pub fn sector_infos(active: &[u32], current: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(active.len() as u32);
    for &s in active {
        w.u32(s);
    }
    w.u32(current);
    w.finish()
}

/// GATE_INFOS 17/0x54 — handler FUN_180e03720 (XMaze::SendGateInfos):
/// u8 first load, u32 n open gates, n x u32.
pub fn gate_infos(first: bool, open: &[u32]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(u8::from(first)).u32(open.len() as u32);
    for &g in open {
        w.u32(g);
    }
    w.finish()
}

/// DIE_MONSTERS 17/0x68 — handler FUN_180e03920 (XMaze::SendDieMonsters):
/// u32 n, n x u32 spawn box of a monster already killed in this instance.
pub fn die_monsters(boxes: &[u32]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(boxes.len() as u32);
    for &b in boxes {
        w.u32(b);
    }
    w.finish()
}

/// USE_REVIVE_COUNT 17/0x70 — handler FUN_180dff5a0 (
/// XMaze::SendUseReviveCount): u8 revives used in this maze.
pub fn use_revive_count(n: u8) -> Vec<u8> {
    vec![n]
}

/// Sector of a maze map that contains (x, y) (XMaze sector rect lookup).
pub fn sector_at(key: u16, pos: [f32; 3]) -> Option<u32> {
    gamedata::MAZE_SECTORS
        .iter()
        .find(|s| s.0 == key && s.2[0] <= pos[0] && pos[0] <= s.2[2] && s.2[1] <= pos[1] && pos[1] <= s.2[3])
        .map(|s| s.1)
}

pub fn sector_clear(sector: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(sector).u8(1);
    w.finish()
}

/// POTAL_INFOS 17/0x55 — handler FUN_180e03a80 (XMaze::SendPotalInfos):
/// u32 n open, u32 n closed, open ids, closed ids.
pub fn portal_infos(open: &[u32], all: &[u32]) -> Vec<u8> {
    let closed: Vec<u32> = all.iter().copied().filter(|p| !open.contains(p)).collect();
    let mut w = Writer::new();
    w.u32(open.len() as u32).u32(closed.len() as u32);
    for &p in open.iter().chain(&closed) {
        w.u32(p);
    }
    w.finish()
}

/// MAZE_REWARD_INFO 17/0x75 — handler FUN_180e045a0 ("EndMazeProcess2"),
/// reader FUN_18001fd00 (210 B with empty item lists): u8 rank, 12 x u32 (
/// PS_REWARD_SCORE: play point, clear point, clear time 1/10 s, difficulty,
/// total combo, play EXP, play gold, special EXP, special gold, total EXP,
/// total money, total ether), then the reward item blocks (zero = none).
pub fn maze_reward_info(rank: u8, tenths: u32, combo: u32, exp: u32, money: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(rank);
    let play = 1000u32.saturating_sub(tenths / 10).max(100);
    for v in [play, play, tenths, 0, combo, exp, money, 0, 0, exp, money, 0] {
        w.u32(v);
    }
    let mut out = w.finish();
    out.resize(210, 0);
    out
}

/// MONSTER_TARGET_CHANGE_BT 0x17/0x22 — handler FUN_180deba40: u32 monster,
/// u32 target (SoulMeter AGGRO_CHANGED).
pub fn monster_target(monster: u32, target: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(monster).u32(target);
    w.finish()
}

/// MOVE_BT 5/0x02 — reader FUN_180010b60 (47 B, ST_MOVE): u32 actor, u64
/// map, f32 x/y/z, f32 yaw, f32 target x/y, u8 run, f32 pitch, f32 speed,
/// u8 change motion, u8 update pos.
pub fn move_bt(actor: u32, map: u64, pos: [f32; 3], yaw: f32, to: [f32; 3], speed: f32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u64(map);
    for v in [pos[0], pos[1], pos[2], yaw, to[0], to[1]] {
        w.u32(v.to_bits());
    }
    w.u8(1).u32(0f32.to_bits()).u32(speed.to_bits()).u8(1).u8(0);
    w.finish()
}

/// MOVE_STOP_BT 5/0x04 — reader FUN_180010e90 (33 B, ST_MOVE_STOP): u32
/// actor, u64 map, f32 x/y/z, f32 yaw, f32 pitch, u8 check-can-move.
pub fn move_stop_bt(actor: u32, map: u64, pos: [f32; 3], yaw: f32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u64(map);
    for v in [pos[0], pos[1], pos[2], yaw, 0.0] {
        w.u32(v.to_bits());
    }
    w.u8(0);
    w.finish()
}

/// ACTIVE_SKILL_BT 6/0x10 — reader FUN_1800197b0 (42 B, OpenWorker
/// ActiveSkillValue): u32 actor, u32 skill, f32 x/y/z/rot, i16 motion, u8
/// swap, u8 input, u32 divergence, u32 parent, u8 deck, u32 trap, u8.
pub fn monster_skill_bt(actor: u32, skill: u32, pos: [f32; 3], rot: f32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u32(skill);
    for v in [pos[0], pos[1], pos[2], rot] {
        w.u32(v.to_bits());
    }
    w.u16(0xFFFF).u8(0).u8(0).u32(0).u32(0).u8(0).u32(0).u8(0);
    w.finish()
}

/// ACTION_SKILL_BT 6/0x13 for a monster hitting the player.
pub fn monster_hit_bt(actor: u32, skill: u32, pos: [f32; 3], rot: f32, target: u32, dmg: i64, hp_left: i64) -> Vec<u8> {
    let req = ActiveSkillReq { skill, pos, rot };
    action_skill_bt(actor, &req, &[Hit { actor: target, damage: dmg, hp: hp_left }], 0)
}

/// CHARACTER_UPDATE_STAT_LIST 3/0x34 — handler FUN_180dd9890, reader
/// FUN_1800138d0: u32 actor, u8 n x {f32 value, u16 stat, u64}.
/// MONSTER_UPDATE_STAT 0x17/0x12 — handler FUN_180deb4e0, entries {f32,
/// u16 stat, u64}: for stat 0x01 (HP) and 0x0A (max HP) the client takes the
/// u64 (cvtsi2sd [entry+8] -> CMover SetHP +0x568 / SetMaxHP +0x570), not the
/// f32. Sending 0 there zeroed the monster's HP and max HP on every hit, so
/// the HP bar never showed.
pub fn monster_stat(actor: u32, hp: i64, max_hp: i64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u8(2);
    for (id, v) in [(stat::HP_MAX, max_hp.max(1)), (stat::HP_CUR, hp.max(0))] {
        w.u32((v as f32).to_bits()).u16(id).u64(v as u64);
    }
    w.finish()
}

/// Stamina / SG / HP a skill costs (CMySkillList::UseSkill): (stat, cost).
pub fn skill_cost(skill: u32) -> Option<(u16, f32)> {
    let s = skill_row(skill)?;
    let stat = match s.5 {
        1 => stat::HP_CUR,
        2 => stat::SG_CUR,
        3 => stat::ST_CUR,
        _ => return None,
    };
    (s.6 > 0).then_some((stat, f32::from(s.6)))
}

pub fn stat_list(actor: u32, stats: &[(u16, f32)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u8(stats.len() as u8);
    // Entry {f32, u16 stat, u64}: the 3/0x34 handler (FUN_180dd9890) and
    // 0x17/0x12 read HP (0x01) / max HP (0x0A) from the u64 and every other
    // stat from the f32, so both carry the value (a 0 u64 zeroed the HP bar on
    // level-up, /heal and revive).
    for &(id, v) in stats {
        w.u32(v.to_bits()).u16(id).u64(v.max(0.0) as u64);
    }
    w.finish()
}

/// CHARACTER_DIE 3/0x41 — handler FUN_180ddcdc0: u32 victim, u32 attacker,
/// u32 PvP kill count (OpenWorker PersonDieResponse).
pub fn character_die(victim: u32, attacker: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(victim).u32(attacker).u32(0);
    w.finish()
}

/// CHARACTER_REVIVE_BT 3/0x44 — reader FUN_180015000 (PS_RES_REVIVE,
/// 25 B on the wire): u32 actor, u32 owner, u8 type, f32 x/y/z, f32 rot.
pub fn revive_bt(actor: u32, kind: u8, pos: [f32; 3], rot: f32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u32(actor).u8(kind);
    for v in [pos[0], pos[1], pos[2], rot] {
        w.u32(v.to_bits());
    }
    w.finish()
}

/// WARP_RES 4/0x08 — handler FUN_180dcdc80: u32 actor (must be the
/// player), then reader FUN_18002c830: u8 result (1 = refused), f32 x/y/z,
/// f32 rot, u32.
pub fn warp_res(actor: u32, result: u8, pos: [f32; 3], rot: f32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u8(result);
    for v in [pos[0], pos[1], pos[2], rot] {
        w.u32(v.to_bits());
    }
    w.u32(0);
    w.finish()
}

/// ITEM_UPDATE_BP 8/0x31 — handler FUN_180ddf0d0, reader FUN_180015880 (
/// PS_BP_UPDATE): u32 actor, u64 BP, wstr name (empty), u8 type.
pub fn update_bp(actor: u32, bp: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u64(bp).u16(0).u8(0);
    w.finish()
}

/// ITEM_UPDATE_ETHER 8/0x32 — handler FUN_180ddf910: u64 ether.
pub fn update_ether(ether: u64) -> Vec<u8> {
    ether.to_le_bytes().to_vec()
}

/// Positions in client movement packets: C 5/0x01, 5/0x03, 5/0x22 carry
/// f32 x/y/z at 12 (after u32 actor + u64 map); C 6/0x47 SKILL_SYNC_POSITION
/// at 0.
pub fn parse_move_pos(sub: u8, p: &[u8]) -> Option<[f32; 3]> {
    let at = match sub {
        0x01 | 0x03 | 0x22 => 12,
        _ => return None,
    };
    pos_from(p, at)
}

pub fn pos_from(p: &[u8], at: usize) -> Option<[f32; 3]> {
    let b = p.get(at..at + 12)?;
    let f = |i: usize| f32::from_le_bytes(b[i..i + 4].try_into().unwrap());
    Some([f(0), f(4), f(8)])
}

/// WORLD_OTHER_INFOS_MONSTER 4/0x23 — handler FUN_180dedaf0: i16 n x monster
/// (reader FUN_180056d80): the 49 B NPC block (FUN_180056ab0: u32 actor, f32
/// x/y/z/rot, i64 hp, i64 max hp, u32 waypoint, u32 sector, u8 level, u32
/// table id), u32 parent actor, u32 spawn box, u32 motion class, u32, u8
/// battle pose, u8 n stats (0), f64 super armor cur/max, u8, u64, u64, u32,
/// u32, u8 (OpenWorker STMonsterInfo; zeros pass the reader, 108 B).
/// Monster motion classes (XActionResMgr::RegisterAnimInfo keys).
pub const MOTION_IDLE: u32 = 2;
/// STAT_TYPE ids (SoulMeter PacketInfo.h StatType, OpenWorker STAT_TYPE).
pub const STAT_CUR_HP: u8 = 0x01;
pub const STAT_MAX_HP: u8 = 0x0a;

pub fn world_monsters(mons: &[Monster]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(mons.len() as u16);
    for m in mons {
        w.u32(m.actor);
        for v in m.pos {
            w.u32(v.to_bits());
        }
        w.u32(m.rot.to_bits());
        w.u64(m.hp as u64).u64(m.max_hp as u64).u32(m.waypoint).u32(m.sector).u8(m.level).u32(m.id);
        // STMonsterInfo tail (reader FUN_180056d80, trace with read_trace.py;
        // names from the STMonsterInfo + SoulMeter's live-traffic struct):
        // u32 parent, u32 spawn box, u32 motion class, u32, u8 battle pose,
        // f64 cur/max super armor, u8 n x {u8 stat, f32 value}, 2 x u64,
        // 2 x f32, u8 n x 14 B. Motion class 0 is N_Spawn: the client keeps
        // replaying the spawn animation until a motion change arrives, so the
        // monster loops, cannot be hit and fades out. 2 = N_Idle_01.
        w.u32(0).u32(m.spawn_box).u32(MOTION_IDLE).u32(0).u8(0);
        w.u64(0).u64(0);
        // Stats the client reads for the HP bar (SoulMeter StatType 0x01
        // CurrentHP, 0x0a MaxHP). Without them the monster counts as 0 HP.
        let stats = [(STAT_CUR_HP, m.hp.max(0) as f32), (STAT_MAX_HP, m.max_hp.max(1) as f32), (0x12, 100.0f32)];
        w.u8(stats.len() as u8);
        for (id, v) in stats {
            w.u8(id).u32(v.to_bits());
        }
        w.u64(0).u64(0).u32(0).u32(0).u8(0);
    }
    w.finish()
}

/// SKILL ACTIVE_SKILL_REQ 6/0x08 (writer FUN_1805f23c0; OpenWorker
/// ActiveSkillValue): u32 skill, u32, f32 x/y/z, f32 rot, i16 motion, u8, ...
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ActiveSkillReq {
    pub skill: u32,
    pub pos: [f32; 3],
    pub rot: f32,
}

impl ActiveSkillReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let skill = r.u32()?;
        r.u32()?;
        let mut pos = [0f32; 3];
        for v in &mut pos {
            *v = f32::from_bits(r.u32()?);
        }
        let rot = f32::from_bits(r.u32()?);
        Ok(Self { skill, pos, rot })
    }
}

/// ACTIVE_SKILL_RES 6/0x09 — handler FUN_180dcf530: u16 error, u32
/// divergence, u8 swap, then a 20 B block (FUN_180011da0: u16, u16, f32 x4,
/// only used on errors). Error 0 lets the client run the skill it asked for;
/// unanswered, the first attack hangs and no further skill is sent.
pub fn active_skill_res() -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(0).u32(0).u8(0).u16(u16::MAX).u16(u16::MAX).u32(0).u32(0).u32(0).u32(0);
    w.finish()
}

/// PRE_TARGET_LIST 6/0x36 (writer FUN_1805f2ee0; OpenWorker
/// SkillPreTargetListRequest): u8 n x u32 actor the client's hit test chose.
pub fn parse_pre_targets(p: &[u8]) -> Vec<u32> {
    let n = p.first().copied().unwrap_or(0) as usize;
    p.get(1..1 + n * 4)
        .map(|b| b.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect())
        .unwrap_or_default()
}

/// One hit in ACTION_SKILL_BT.
pub struct Hit {
    pub actor: u32,
    pub damage: i64,
    pub hp: i64,
}

/// ACTION_SKILL_BT 6/0x13 — handler FUN_180dd0770: damage list (reader
/// FUN_180019c50: i8 n x 60 B {u32 target, u8 reaction, u8 flag, i64 damage,
/// i64 attribute damage, i64 hp left, f32 x3 extra move, f32 fly speed, u8,
/// u64, u8 defence type, f32 super armor}), then the action (FUN_180019910,
/// 34 B: u32 attacker, f32 x/y/z/rot, i16 motion, u8, u8, u32 skill, i16
/// trigger, u16 continuous hit, u8 counter, u8 penetrate). Order of fields
/// from the reference server CMover::send_eSUB_CMD_ACTION_SKILL.
/// Hit result flags (SoulMeter SWPACKETDAMAGE_DAMAGETYPE): bit 0 MISS, bit 2
/// CRIT, high nibble soul stone type. 1 made every hit a miss: no flinch,
/// no damage number (the "monsters do not take hits" report).
pub const HIT_NORMAL: u8 = 0;

pub fn action_skill_bt(attacker: u32, req: &ActiveSkillReq, hits: &[Hit], combo: u16) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(hits.len().min(100) as u8);
    for h in hits.iter().take(100) {
        w.u32(h.actor).u8(1).u8(HIT_NORMAL).u64(h.damage as u64).u64(0).u64(h.hp.max(0) as u64);
        w.u32(0).u32(0).u32(0).u32(0).u8(0).u64(0).u8(4).u32(0);
    }
    w.u32(attacker);
    for v in req.pos {
        w.u32(v.to_bits());
    }
    w.u32(req.rot.to_bits()).u16(0).u8(0).u8(0).u32(req.skill).u16(0).u16(combo).u8(0).u8(0);
    w.finish()
}

/// MONSTER_DIE 0x17/0x11 — handler FUN_180deb180: u32 actor, u16, u8.
pub fn monster_die(actor: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u16(0).u8(0);
    w.finish()
}

/// CHARACTER_EXP 3/0x37 — handler FUN_180ddbd60, reader FUN_1800252c0: u64
/// EXP, u32 gained, u32 bonus (OpenWorker PersonExpResponse).
pub fn character_exp(exp: u64, gained: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(exp).u32(gained).u32(0);
    w.finish()
}

/// Zenny drop object id (CDropProcess: 800000001 gold, 800000002 soul
/// vapor, 800000003 BP, 800000004 ether).
pub const DROP_ZENNY: u32 = 800_000_001;
pub const DROP_SOUL_VAPOR: u32 = 800_000_002;
pub const DROP_BP: u32 = 800_000_003;
pub const DROP_ETHER: u32 = 800_000_004;

/// One item lying on the ground.
#[derive(Debug, Clone, PartialEq)]
pub struct GroundItem {
    pub serial: u64,
    pub item: u32,
    pub count: u32,
    pub pos: [f32; 3],
}

/// Roll a monster's drops like the reference server's
/// CDropProcess::MakeDropItems: gold (chance /10000, min..max), then each of
/// the drop's groups (chance /10000) picks one item by its chance and count
/// range. Ether / soul vapor / BP are not handed out yet. `rand(lo, hi)`
/// returns an inclusive random number.
pub fn roll_drops(monster: u32, pos: [f32; 3], rand: &mut dyn FnMut(u32, u32) -> u32, serial: &mut dyn FnMut() -> u64) -> Vec<GroundItem> {
    let Some(&(_, did)) = gamedata::MONSTER_DROPS.iter().find(|m| m.0 == monster) else { return Vec::new() };
    let Some(&(_, gch, gmin, gmax, groups, sv, eth, bp)) = gamedata::DROPS.iter().find(|d| d.0 == did) else { return Vec::new() };
    let mut out = Vec::new();
    let at = |i: usize| [pos[0] + 40.0 * (i as f32 % 3.0 - 1.0), pos[1] + 40.0 * ((i / 3) as f32 % 3.0 - 1.0), pos[2]];
    if u32::from(gch) >= rand(1, 10_000) && gmax > 0 {
        let n = rand(u32::from(gmin.min(gmax)), u32::from(gmax)).max(1);
        out.push(GroundItem { serial: serial(), item: DROP_ZENNY, count: n, pos: at(0) });
    }
    // Soul vapor, ether and BP (CDropProcess: SV/Et/BP chance, min, max;
    // tb_Drop stores BP as chance, max, min).
    for (obj, [ch, a, b]) in [(DROP_SOUL_VAPOR, sv), (DROP_ETHER, eth), (DROP_BP, bp)] {
        if ch > 0 && u32::from(ch) >= rand(1, 10_000) && a.max(b) > 0 {
            let n = rand(u32::from(a.min(b)), u32::from(a.max(b))).max(1);
            let i = out.len();
            out.push(GroundItem { serial: serial(), item: obj, count: n, pos: at(i) });
        }
    }
    for &(gid, ch) in groups {
        if u32::from(ch) < rand(1, 10_000) {
            continue;
        }
        let Some(&(_, items)) = gamedata::DROP_GROUPS.iter().find(|g| g.0 == gid) else { continue };
        let mut r = rand(1, 10_000) as i64;
        for &(item, c, lo, hi) in items {
            r -= i64::from(c);
            if r <= 0 {
                let n = rand(u32::from(lo.min(hi)), u32::from(hi.max(1))).max(1);
                let i = out.len();
                out.push(GroundItem { serial: serial(), item, count: n, pos: at(i) });
                break;
            }
        }
    }
    out
}

/// DROP_INFOS 20/0x01 — handler FUN_180e10b90, reader FUN_18001f680: u32
/// group, u8 boss drop, u8 n x 34 B {f32 x/y/z, u32 object, u32 count, u32
/// bonus, u64 serial, u8, u8}, u32 jackpot object, u8 jackpot multiplier
/// (PS_DROP_INFOS / ST_DROP_ITEM_INFO; the two u8 are GB additions).
pub fn drop_infos(group: u32, drops: &[GroundItem]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(group).u8(0).u8(drops.len().min(255) as u8);
    for d in drops.iter().take(255) {
        for v in d.pos {
            w.u32(v.to_bits());
        }
        w.u32(d.item).u32(d.count).u32(0).u64(d.serial).u8(0).u8(0);
    }
    w.u32(0).u8(0);
    w.finish()
}

/// DROP_PICK_UP 20/0x02 request (writer FUN_1805fb350 -> FUN_180055a30): u32
/// group, u64 serial.
pub fn parse_pick_up(p: &[u8]) -> Result<(u32, u64), ParseError> {
    let mut r = Reader::new(p);
    Ok((r.u32()?, r.u64()?))
}

/// DROP_PICK_UP 20/0x02 reply — handler FUN_180e10d70, reader FUN_180027220:
/// u64 serial, u32 result (0 = picked up, the client removes the drop).
pub fn pick_up_res(serial: u64, result: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(serial).u32(result);
    w.finish()
}

/// Damage of one skill hit until skills and stats are computed from
/// tb_Skill / tb_Status: grows with the character level, +-20 %.
pub fn hit_damage(level: u8, roll: u32) -> i64 {
    let base = 25 + 15 * i64::from(level);
    base * (80 + i64::from(roll % 41)) / 100
}

/// EXP for a kill (tb_Monster_EXP by monster level, column by rank).
pub fn kill_exp(level: u8, rank: u8) -> u32 {
    gamedata::MONSTER_EXP
        .iter()
        .find(|e| e.0 == level)
        .map_or(1, |e| e.1[usize::from(rank.min(6))].max(1))
}

/// Level cap of this client: the last row of tb_Levelup_Point (100 in
/// 2.3.34.7; mazes require up to Lv.99). The old fixed 80 cap is gone.
pub fn max_level() -> u8 {
    gamedata::LEVEL_EXP.iter().map(|e| e.0).max().unwrap_or(80)
}

/// EXP needed to leave `level` (GB tb_Levelup_Point); None at the cap.
pub fn level_need(level: u8) -> Option<u32> {
    gamedata::LEVEL_EXP.iter().find(|e| e.0 == level).map(|e| e.1).filter(|&n| n > 0)
}

/// Add EXP: returns the new (level, exp into that level).
pub fn add_exp(mut level: u8, mut exp: u64, gained: u32) -> (u8, u64) {
    exp += u64::from(gained);
    while let Some(need) = level_need(level) {
        if exp < u64::from(need) || level >= max_level() {
            break;
        }
        exp -= u64::from(need);
        level += 1;
    }
    (level, exp)
}

/// MAZE_LUA_FUNCTION 17/0x7E (u32 VLuaFunctionBox id, sent when the player
/// walks into one, e.g. Rocco Town 90001 OnCinemaTalk) -> 17/0x7F u32 box id
/// (handler FUN_180e05550; OpenWorker MazeLuaFunctionResponse). The box's Lua
/// script is not run yet.
pub fn maze_lua_function_res(box_id: u32) -> Vec<u8> {
    box_id.to_le_bytes().to_vec()
}

/// Requests the client sends on entering the world (or when a panel opens)
/// whose reply is a list we have nothing for yet. Each empty size is what the
/// reply handler's reader accepts with err 0 and pos == len (`re/empty_reply.py`
/// + Unicorn read traces): all-zero = every count 0.
///  3/0x23 CHARACTER_LOAD_TITLE  FUN_180e246e0 -> FUN_180013bc0 (u8, u16 n, u16 n)
///  3/0x7B CASH_MILEAGE          FUN_180e2dec0 -> FUN_1800269f0 (u8 n)
/// 0x20/0x10 POST_INFO           FUN_180e27ce0 (u16 unread, u16 unread account)
/// 0x20/0x02 POST_RECV_LIST      FUN_180e28220 -> FUN_18003d100 (u8 n)
/// 0x20/0x14 POST_ACCOUNT_LIST   FUN_180e28400 -> FUN_18003db20 (u16 n)
/// 0x19/0x41 FRIEND_RECRUIT_LIST FUN_180e278a0 -> FUN_18003c490 (u8 n)
/// 0x19/0x44 FRIEND_RECRUIT_INFO FUN_180e27a30 -> FUN_180049c30 (u8)
/// 0x19/0x51 FRIEND_RECOMMAND    FUN_180e27640 -> FUN_18003cbd0 (u32, u8 n)
/// 0x12/0x36 PARTY_RECRUIT_LIST  FUN_180e32b10 -> FUN_180035cd0 (u16 n, u8)
/// 0x12/0x37 PARTY_RECRUIT_MY_APPLY_LIST FUN_180e32be0 (same reader)
/// 0x2B/0x03 EXCHANGE_INTEREST_LIST FUN_180e3e040 -> FUN_1800494d0 (u32, u16 n)
/// 0x2B/0x08 EXCHANGE_MY_LIST    FUN_180e3e5a0 -> FUN_18004d520 (u16 n, u8)
/// 0x2B/0x10 EXCHANGE_MY_INFO    FUN_180e4f390 -> FUN_18004da80 (105 B of
///           i64/u32 totals, all 0)
/// 0x18/0x58 ITEM_OVERCLOCK_BONUS_RATE_LIST FUN_180de3aa0 -> FUN_1800269f0
/// Unanswered, the matching panel (mail, friends, party board, market,
/// titles) waits forever.
pub fn empty_list_reply(main: u8, sub: u8) -> Option<usize> {
    Some(match (main, sub) {
        (0x03, 0x23) => 5,
        (0x03, 0x7B) => 1,
        (0x20, 0x10) => 4,
        (0x20, 0x02) => 1,
        (0x20, 0x14) => 2,
        (0x19, 0x41) => 1,
        (0x19, 0x44) => 1,
        (0x19, 0x51) => 5,
        (0x12, 0x36) | (0x12, 0x37) => 3,
        (0x2B, 0x03) => 6,
        (0x2B, 0x08) => 3,
        (0x2B, 0x10) => 105,
        (0x18, 0x58) => 1,
        // CHARACTER_QUICK_CHANGE_LIST 3/0x5B (handler FUN_180e48e10, reader
        // FUN_18002fea0): zero characters to switch to quickly.
        (0x03, 0x5B) => 10,
        // Panels OpenWorker answers (FriendLoad, FriendLoadBlocklist,
        // LeagueList, RankingTimeAttack/Pvp, ItemBankInfo, event 42/0x50);
        // sizes from the client handlers with empty lists (empty_reply.py).
        (0x19, 0x01) => 4,
        (0x19, 0x02) => 1,
        (0x22, 0x03) => 2,
        (0x2C, 0x01) => 52,
        (0x2C, 0x02) => 18,
        (0x08, 0x10) => 5,
        (0x2A, 0x50) => 4,
        _ => return None,
    })
}

/// CHARACTER_UPDATE_SPECIAL_OPTION_LIST 3/0x47 (request u32 actor) — reply
/// handler FUN_180e2ead0: u32 actor (looked up in the world), u8 n x {u16
/// option, f32 value}. None for now.
pub fn special_option_list(actor: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(actor).u8(0);
    w.finish()
}

/// SHOP_BANNER_LOAD 9/0x28 — handler FUN_180e0b940, reader FUN_18000f290:
/// u32 banner count. OpenWorker sends it right after SHOP_CASH_LOAD.
pub fn shop_banner_load_empty() -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(0);
    w.finish()
}

/// SKILL_LOAD_INFO 6/0x70 — the packet that actually starts the world load.
///
/// CHARACTER_INFO_RES (FUN_180da1170) only *queues* the next scene: it writes
/// "LoadingScene"/"PlayScene" into the scene manager's pending name
/// (DAT_1819671e0 +0x58). The one function that applies the pending name is
/// FUN_180f3aa10 (pending -> FUN_180f3a800 SetScene, then clears it), and its
/// only caller is the 6/0x70 handler FUN_180dd5170 (registered for opcode
/// 0x0670 in FUN_180db4940), at its very end. Without 6/0x70 the client stays
/// on the character select screen while the world connection idles.
///
/// Reader FUN_18001aa90 (all lists empty here):
/// ```text
/// u32 character, u16 x5, u16 n + n x {u32, u32, u8},
/// u16 n + n x {u32, u32, u8}, u8 n + n x FUN_18001a830,
/// FUN_18001b8f0 (u8, u8 n + ...), u16 n + n x {u32, u32, ...}
/// ```
/// With no entries the reader consumes exactly 23 bytes (checked in Unicorn).
///
/// The first {u32 skill, u32, u8} list is the learned skill set: the handler
/// FUN_180dd5170 feeds each id to FUN_1804fa8d0, which records the skill's
/// level under its type (player skill table +0x3a0[type]). Dash input
/// (FUN_1803b9bb0) checks type 10 there first, so with an empty list the
/// character could never dash (double-tap W did nothing, 2026-10-18).
pub fn skill_load_info(character_id: u32, skills: &[u32]) -> Vec<u8> {
    let list: Vec<(u32, u32)> = skills.iter().map(|&s| (s, 0)).collect();
    skill_load_full(character_id, &SkillState { skills: list, total_sp: 0, free_sp: 0, deck_slots: 0, decks: Vec::new(), bonus: [0; 4] })
}

/// Skill tree state of a character (PS_SKILL_LOAD).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SkillState {
    /// (skill id, divergence)
    pub skills: Vec<(u32, u32)>,
    pub total_sp: u16,
    pub free_sp: u16,
    pub deck_slots: u16,
    pub decks: Vec<(u16, [u32; 4])>,
    pub bonus: [u16; 4],
}

/// SKILL_LOAD_INFO 6/0x70 (reader FUN_18001aa90, PS_SKILL_LOAD): u32
/// actor, u16 total SP, u16 free SP, u16 deck slot count, u16 x2, u16 n x
/// {u32 skill, u32 divergence, u8}, u16 n x {...}, u8 n decks x {u16 pos,
/// 4 x u32}, u8, u8, u16.
pub fn skill_load_full(character_id: u32, st: &SkillState) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(character_id).u16(st.total_sp).u16(st.free_sp).u16(st.deck_slots).u16(0).u16(0);
    w.u16(st.skills.len() as u16);
    for &(id, div) in &st.skills {
        w.u32(id).u32(div).u8(0);
    }
    w.u16(0);
    w.u8(st.decks.len().min(6) as u8);
    for (pos, s) in st.decks.iter().take(6) {
        w.u16(*pos);
        for v in s {
            w.u32(*v);
        }
    }
    w.u8(0).u8(0);
    w.u16(0);
    w.finish()
}

/// A tb_Skill row of the learnable tree.
pub fn tree_row(skill: u32) -> Option<&'static (u32, u32, u8, u8, u8, u8, u8, u32)> {
    gamedata::SKILL_TREE.binary_search_by_key(&skill, |s| s.0).ok().map(|i| &gamedata::SKILL_TREE[i])
}

/// Skill points a character earns up to `level` (tb_Levelup_Point).
pub fn skill_points_for(level: u8) -> u16 {
    gamedata::LEVEL_SKILL_POINTS.iter().filter(|p| p.0 <= level).map(|p| u16::from(p.1)).sum()
}

/// Points spent on a skill at its level (each level of the group costs its
/// row's Req_Skill_Point).
pub fn skill_spent(skill: u32) -> u16 {
    let Some(r) = tree_row(skill) else { return 0 };
    gamedata::SKILL_TREE.iter().filter(|s| s.1 == r.1 && s.2 <= r.2).map(|s| u16::from(s.5)).sum()
}

/// Why a learn request is refused (None = allowed). CSkillProcess
/// ReqSkillLearn checks class, level, points, previous skill and the
/// max level of the group.
pub fn learn_check(skill: u32, class: u8, level: u8, free_sp: u16, have: &[(u32, u32)]) -> Option<&'static str> {
    let Some(r) = tree_row(skill) else { return Some("unknown skill") };
    if r.3 != class {
        return Some("other class");
    }
    if level < r.4 {
        return Some("level too low");
    }
    if r.2 > r.6.max(1) {
        return Some("over max level");
    }
    let cur = have.iter().find(|(s, _)| tree_row(*s).is_some_and(|t| t.1 == r.1)).map(|(s, _)| *s);
    let cost = skill_spent(skill).saturating_sub(cur.map_or(0, skill_spent));
    if cost > free_sp {
        return Some("not enough skill points");
    }
    if r.7 != 0 && !have.iter().any(|(s, _)| *s == r.7 || tree_row(*s).is_some_and(|t| tree_row(r.7).is_some_and(|p| p.1 == t.1 && t.2 >= p.2))) {
        return Some("previous skill missing");
    }
    None
}

/// SKILL_LEARN 6/0x71 reply (reader FUN_18001a780, PS_RES_SKILL_LEARN):
/// u32 skill, u32 divergence, u8 type, u8 result, u8, u8.
pub fn skill_learn_res(skill: u32, divergence: u32, ok: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(skill).u32(divergence).u8(0).u8(u8::from(ok)).u8(0).u8(0);
    w.finish()
}

/// SKILL_RESET 6/0x72 reply (handler FUN_180dd6300): the full PS_SKILL_LOAD
/// then u8 result.
pub fn skill_reset_res(character_id: u32, st: &SkillState) -> Vec<u8> {
    let mut v = skill_load_full(character_id, st);
    v.push(1);
    v
}

/// SKILL_UPDATE_DECK 6/0x75 reply (reader FUN_18001aa00, Unicorn: a 1 in
/// the first byte makes it read 18 more): u8 n x {u16 pos, 4 x u32}, the
/// decks now stored (empty = refused). OpenWorker's bool is the 2.3.29 form.
pub fn skill_update_deck_res(decks: &[(u16, [u32; 4])]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(decks.len().min(6) as u8);
    for (pos, d) in decks.iter().take(6) {
        w.u16(*pos);
        for v in d {
            w.u32(*v);
        }
    }
    w.finish()
}

/// SKILL_ADD_DECK_SLOT 6/0x76 reply (handler FUN_180dd72a0): u16 slot count.
pub fn skill_add_deck_slot_res(n: u16) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

/// SKILL_DIVERGENCE_LEARN 6/0x77 reply (reader FUN_18004d370): u32 skill,
/// u32 divergence, u32, u8 result.
pub fn skill_divergence_res(skill: u32, divergence: u32, ok: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(skill).u32(divergence).u32(0).u8(u8::from(ok));
    w.finish()
}

/// SKILL_DECK_BONUS 6/0x79 reply (reader FUN_18001b3f0): u8 result.
pub fn skill_deck_bonus_res(ok: bool) -> Vec<u8> {
    vec![u8::from(ok)]
}

/// SKILL_PASSIVE 6/0x07 reply (handler FUN_180dcf4b0): i16 error.
pub fn skill_passive_res(err: i16) -> Vec<u8> {
    err.to_le_bytes().to_vec()
}

/// C 6/0x75 SKILL_UPDATE_DECK (writer FUN_1805f3f00 -> FUN_18001a920): u8 n
/// x {u16 pos, 4 x u32}.
pub fn parse_deck_update(p: &[u8]) -> Option<Vec<(u16, [u32; 4])>> {
    let mut r = Reader::new(p);
    let n = r.u8().ok()?;
    let mut out = Vec::new();
    for _ in 0..n.min(6) {
        let pos = r.u16().ok()?;
        out.push((pos, [r.u32().ok()?, r.u32().ok()?, r.u32().ok()?, r.u32().ok()?]));
    }
    Some(out)
}

/// Default skills of a class (tb_Character_Info), empty for unknown classes.
pub fn class_skills(class: u8) -> &'static [u32] {
    crate::gamedata::CLASS_SKILLS.iter().find(|(c, _)| *c == class).map_or(&[], |(_, s)| *s)
}

/// SYSTEM_PING 1/0x06 from the client (writer FUN_1805f0580, every second
/// once in the world): u64 GetTickCount64, u64, u32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingReq {
    pub tick: u64,
}

impl PingReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let tick = r.u64()?;
        r.u64()?;
        r.u32()?;
        end(&r)?;
        Ok(Self { tick })
    }
}

/// SYSTEM_PING reply 1/0x06 — PlayScene handler FUN_180decc20: one u64
/// (FUN_18000e5e0); the client shows GetTickCount64() - value as its ping.
pub fn ping_res(tick: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(tick);
    w.finish()
}

/// SELECT_CHARACTER_RES 3/0x14 — handler FUN_180d9fcb0, reader FUN_18002cb70
/// (map info FUN_18002d270, party info after it):
/// ```text
/// u32 character, u32 account, u32 server, u32 jump id, u32 portal,
/// u64 map instance, u64 parent instance, str8 host (FUN_18000e370, <= 0x201),
/// u16 port, position (FUN_180012610), u8 type,
/// u8, u8, u32 result, u8 party type, u32 party id, u8 n x u16, u32
/// ```
/// result 0: the client stores the map instance (FUN_1805eefb0) and connects
/// to host:port with purpose 3 (FUN_1805f69f0), then sends ENTER_GAMESERVER_REQ.
/// Otherwise it shows UI string `result` (50104 = "Login failed").
pub fn select_character_res(t: &WorldTarget<'_>, result: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(t.character_id).u32(t.account_id).u32(t.server_id).u32(t.jump_id).u32(0);
    w.u64(t.map_instance).u64(0).str8(t.host).u16(t.port);
    pos_at(&mut w, t.district, t.map_instance, t.pos, t.rot);
    w.u8(0); // type
    w.u8(0).u8(0).u32(result);
    w.u8(0).u32(0).u8(0).u32(0); // no party
    w.finish()
}

/// WORLD_ENTER_RES 4/0x02 — PlayScene handler FUN_180dcd530 reads the same
/// block as SELECT_CHARACTER_RES (FUN_18002cb70) plus two u8 (class scene,
/// PvP; OpenWorker WorldEnterResponse writes false, false). Result 0: the
/// client stores the new map instance (FUN_1805eefb0), drops this connection
/// and connects to host:port (FUN_1805f69f0), then sends ENTER_GAMESERVER_REQ
/// + CHARACTER_INFO_REQ again, like after the character select. Otherwise it
/// shows UI string `result` and stays (OpenWorker EnterMapResultValue.Error).
pub fn world_enter_res(t: &WorldTarget<'_>, result: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(&select_character_res(t, result)).u8(0).u8(0);
    w.finish()
}

/// SELECT_CHARACTER_RES carrying only an error (UI string id). The host must
/// not be empty even here: FUN_18000e370 flags a length <= 0 as a read error
/// (err=1). With result != 0 the client never connects to it.
pub fn select_character_fail(result: u32, host: &str) -> Vec<u8> {
    select_character_res(
        &WorldTarget { character_id: 0, account_id: 0, server_id: 0, jump_id: 0, map_instance: 0, host, port: 0, district: 0, pos: [0.0; 3], rot: 0.0 },
        result,
    )
}

/// UI string 50104 (0xc3b8): "Login failed".
pub const MSG_LOGIN_FAILED: u32 = 50104;

/// ENTER_GAMESERVER_RES 3/0x22 — handler FUN_180da0f70 (runs only while the
/// login scene is active): u32 result, u8, position (FUN_180012610), u8, u32.
/// result 0 -> FUN_180da40f0 starts loading the world.
pub fn enter_gameserver_res(result: u32, district: u16, map_instance: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(result).u8(0);
    pos_info(&mut w, district, map_instance);
    w.u8(0).u32(0);
    w.finish()
}

/// What the client asks for in SECOND_PASSWORD 3/0x17 (writer FUN_180607230:
/// u8 kind, str8 pin). Kinds from the callers:
/// 1 = set a new PIN (FUN_1807a8fb0 after the confirm step, panel +0x108 == 1),
/// 2 = verify (panel +0x108 == 2), 3 = "Set Later" (FUN_1807b4820,
/// FUN_180da7de0, empty pin), 4 = sent while the account is blocked (FUN_1807a59f0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondPwKind {
    Set,
    Verify,
    Later,
    Blocked,
    /// Any other value (FUN_1807a8fb0 sends 0 when the panel mode is neither
    /// set nor verify); answered with the current state, never fatal.
    Other(u8),
}

/// SECOND_PASSWORD 3/0x17 from the client. The PIN is six digits built with
/// _itoa per digit (FUN_1807a8fb0). Debug output never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct SecondPasswordReq {
    pub kind: SecondPwKind,
    pub pin: Password,
}

impl fmt::Debug for SecondPasswordReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecondPasswordReq").field("kind", &self.kind).field("pin", &"<redacted>").finish()
    }
}

impl SecondPasswordReq {
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(p);
        let kind = match r.u8()? {
            1 => SecondPwKind::Set,
            2 => SecondPwKind::Verify,
            3 => SecondPwKind::Later,
            4 => SecondPwKind::Blocked,
            k => SecondPwKind::Other(k),
        };
        let n = usize::from(r.u16()?);
        if n > 6 {
            return Err(ParseError::TooLong { field: "second password", units: n, max: 6 });
        }
        let raw = r.bytes(n)?;
        end(&r)?;
        let pin = std::str::from_utf8(raw).map_err(|_| ParseError::InvalidUtf16("second password"))?.to_string();
        let needs_pin = matches!(kind, SecondPwKind::Set | SecondPwKind::Verify);
        if needs_pin && !(pin.len() == 6 && pin.bytes().all(|b| b.is_ascii_digit())) {
            return Err(ParseError::Read("second password must be 6 digits"));
        }
        Ok(Self { kind, pin: Password(pin) })
    }
}

/// Server rule for character names. The creator asks for "between 2-12
/// Characters"; only letters and digits (any script) are accepted.
pub fn valid_character_name(name: &str) -> bool {
    let n = name.chars().count();
    (2..=12).contains(&n) && name.chars().all(char::is_alphanumeric)
}

/// `[u16 byte_len][UTF-16LE]` with the client's own limit (FUN_18000e4b0
/// accepts byte_len <= 2*max-2). The length is checked before reading.
fn client_wstr(r: &mut Reader<'_>, field: &'static str, max_bytes: usize) -> Result<String, ParseError> {
    let byte_len = usize::from(r.u16()?);
    if byte_len % 2 != 0 {
        return Err(ParseError::OddLength(field));
    }
    if byte_len > max_bytes {
        return Err(ParseError::TooLong { field, units: byte_len / 2, max: max_bytes / 2 });
    }
    let raw = r.bytes(byte_len)?;
    let s = char::decode_utf16(raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])))
        .collect::<Result<String, _>>()
        .map_err(|_| ParseError::InvalidUtf16(field))?;
    if s.contains('\0') {
        return Err(ParseError::EmbeddedNul(field));
    }
    Ok(s)
}

// ---------------------------------------------------------------- server -> client

/// Error codes LOGIN_RESULT understands (handler FUN_180d9e2e0). Anything not
/// listed shows as a generic numbered error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LoginError {
    Ok = 0,
    /// Client text id 0xc3b9: wrong ID or password.
    BadCredentials = 1,
    /// Client text id 0xc73f.
    Rejected = 2,
}

/// LOGIN_RESULT 2/2. Reader FUN_180015130 (2.3.34.7):
/// ```text
/// u32 account_id, u8 flag, raw[18] mac, wstr msg (<=1024 units), u32 error,
/// u8 login_type, wstr auth_id (<=20 units), u64 session, u8 gm_power,
/// u16 birth_year, u8 birth_month, u8 birth_day, u64, u8
/// ```
/// On error 0 with an empty message the client stores account/session and
/// immediately sends SERVER_LIST_REQ.
pub struct LoginResult<'a> {
    pub account_id: u32,
    pub error: LoginError,
    pub message: &'a str,
    pub auth_id: &'a str,
    pub session: u64,
}

impl LoginResult<'_> {
    pub const MAIN: u8 = 2;
    pub const SUB: u8 = 2;

    pub fn encode(&self) -> Vec<u8> {
        let auth: String = self.auth_id.chars().take(20).collect();
        let mut w = crate::codec::Writer::new();
        w.u32(self.account_id).u8(1).zeros(18).wstr(self.message).u32(self.error as u32).u8(0);
        w.wstr(&auth).u64(self.session).u8(0).u16(2000).u8(1).u8(1).u64(0).u8(0);
        w.finish()
    }
}

/// One row of SERVER_LIST 2/4. Reader FUN_180034ea0 (2.3.34.7), 0x228-byte entry:
/// ```text
/// u16 id, u16 port, str8 name (<=20 bytes), str8 host (<=512 bytes), u32 load, u32 flags
/// ```
/// then the list reader (FUN_180034cc0) reads one more u8 per row.
/// `load` drives the colour/gauge in the list panel: 0 red, 1 white, 2 green, 3 orange, 4 red.
pub struct ServerEntry<'a> {
    pub id: u16,
    pub port: u16,
    pub name: &'a str,
    pub host: &'a str,
    pub load: u32,
    pub flags: u32,
    pub characters: u8,
}

/// SERVER_LIST 2/4 — FUN_180034cc0: u8, i8 count, rows.
pub fn server_list(rows: &[ServerEntry<'_>]) -> Vec<u8> {
    let mut w = crate::codec::Writer::new();
    w.u8(0).u8(rows.len().min(127) as u8);
    for s in rows.iter().take(127) {
        debug_assert!(!s.name.is_empty() && s.name.len() <= 20 && s.host.len() <= 512);
        w.u16(s.id).u16(s.port).str8(s.name).str8(s.host).u32(s.load).u32(s.flags).u8(s.characters);
    }
    w.finish()
}

/// SERVER_CONNECT_RES 2/0x11 in the 2.3.29 notes is ENTER_SERVER in 2.3.34.7.
/// Handler FUN_180d9ede0 reads `str8 (1..=19 bytes)` + `u16`, then connects to
/// the host/port of the *selected SERVER_LIST row* (not these fields) and sends
/// ENTER_SERVER_REQ there.
pub fn enter_server(ip: &str, port: u16) -> Vec<u8> {
    debug_assert!(!ip.is_empty() && ip.len() < 20);
    let mut w = crate::codec::Writer::new();
    w.str8(ip).u16(port);
    w.finish()
}

/// ENTER_SERVER_RES 2/0x14 — reader FUN_1800312c0 + FUN_180017540:
/// u8 result (0 = ok), u32 account id, u32 value, u16 count, count x (u32, u8).
/// On result 0 the client sends CHARACTER_LIST_REQ.
pub fn enter_server_res(result: u8, account_id: u32) -> Vec<u8> {
    let mut w = crate::codec::Writer::new();
    w.u8(result).u32(account_id).u32(0).u16(0);
    w.finish()
}

/// Second password state as the character select panel understands it
/// (panel +0x100, set from CHARACTER_LIST_RES and SECOND_PASSWORD; FUN_1807a59f0
/// acts on it when the player presses Game Start or Delete).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecondPwState {
    /// No PIN yet: shows "Second PW has not been set. Do you want to set it now?".
    NotSet = 0,
    /// PIN set: the PIN pad asks for it.
    Locked = 1,
    /// Verified for this session: Game Start enters the game directly.
    Unlocked = 2,
    /// "Account Blocked".
    Blocked = 3,
}

/// CHARACTER_LIST_RES 3/0x12 — reader FUN_180016d40:
/// ```text
/// i8 count, count x row (FUN_180012e20, see CharacterInfo),
/// u32 select_id ("SelectUCID", FUN_180da7200), u8 second_pw_state (panel +0x100),
/// u8 trade_pw_state (InventoryDialog +0x1a90), u64 list_time, u32, u64, u16,
/// i16 n1 x (u32, wstr<=39, u8, u64), i16 n2 x (u16, u8, u8, u8), u8
/// ```
/// Handler FUN_180d9fa10: while the creator is open (scene 7) this list means
/// "character created" and the client moves on to scene 8 (ClassConfirm);
/// otherwise it fills the character select panel (slot-1 indexes a 12-entry
/// array, FUN_1807a9b00).
pub fn character_list(rows: &[CharacterInfo], select_id: u32, second_pw: SecondPwState) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(rows.len().min(i8::MAX as usize) as u8);
    for row in rows.iter().take(i8::MAX as usize) {
        row.encode(&mut w);
    }
    w.u32(select_id).u8(second_pw as u8).u8(0).u64(0).u32(0).u64(0).u16(0).u16(0).u16(0).u8(0);
    w.finish()
}

/// SECOND_PASSWORD 3/0x17 reply — handler FUN_180da07c0, reader FUN_180054a50:
/// u32 result, u8 state. The state is stored in the panel; with result 0 and
/// a state other than Blocked the client re-runs the pending action
/// (FUN_1807a59f0), so Unlocked + result 0 continues into the game. Otherwise
/// FUN_1807a5fd0 shows an error: for state Locked always "Invalid Second PW"
/// (0xc23c), for NotSet the UI string `result`, for Blocked "Account Blocked".
pub fn second_password_res(result: u32, state: SecondPwState) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(result).u8(state as u8);
    w.finish()
}

/// UI string 0xc23d: "Second PW incorrect.\nPlease re-enter."
pub const MSG_SECOND_PW_INCORRECT: u32 = 0xc23d;

/// CHARACTER_CHECK_NAME 3/0x57 — reader FUN_180014010: wstr name (max 0x15),
/// u8 result. Handler FUN_180797860: 0 shows "ID can be used." (UI string
/// 0xd7a2); anything else shows "There is already an ID with the same name."
/// (0xd7a1) and clears the name box, leaving the player in the creator.
pub fn check_name(name: &str, taken: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.wstr(name).u8(u8::from(taken));
    w.finish()
}

/// CHARACTER_REPRESENTATIVE_CHECK 3/0x0D — handler FUN_180da04d0 reads one
/// u32; 0 means "no restriction" (other values are message ids).
pub fn representative_check() -> Vec<u8> {
    0u32.to_le_bytes().to_vec()
}

/// DELETE_CHARACTER_RES 3/0x03 — handler FUN_180d9f7b0 reads one u32: seconds
/// until a delayed delete completes; 0 = deleted now, no message.
pub fn delete_character_res() -> Vec<u8> {
    0u32.to_le_bytes().to_vec()
}

/// `[u16 byte_len][UTF-16LE]` with bounds, alignment and content checks.
/// The length is checked before any bytes are consumed or allocated.
fn wstr_strict(r: &mut Reader<'_>, field: &'static str, max_units: usize) -> Result<String, ParseError> {
    let byte_len = usize::from(r.u16()?);
    if byte_len % 2 != 0 {
        return Err(ParseError::OddLength(field));
    }
    let units = byte_len / 2;
    if units > max_units {
        return Err(ParseError::TooLong { field, units, max: max_units });
    }
    let raw = r.bytes(byte_len)?;
    let s = char::decode_utf16(raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])))
        .collect::<Result<String, _>>()
        .map_err(|_| ParseError::InvalidUtf16(field))?;
    if s.contains('\0') {
        return Err(ParseError::EmbeddedNul(field));
    }
    Ok(s)
}

/// "0A-1B-2C-3D-4E-5F" -> bytes. Anything else -> None.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split('-');
    for b in &mut out {
        let p = parts.next()?;
        // from_str_radix alone would also accept a leading '+'.
        if p.len() != 2 || !p.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// Cleartext password. `Debug` is redacted and the buffer is wiped on drop so it
/// does not end up in logs or linger in freed memory.
#[derive(Clone, PartialEq, Eq)]
pub struct Password(String);

impl Password {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Password(<{} chars redacted>)", self.0.chars().count())
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        // SAFETY: only zero bytes are written, which keeps the String valid UTF-8.
        let bytes = unsafe { self.0.as_mut_vec() };
        for b in bytes.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{golden, SendPolicy, SeqPolicy, WireCodec};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn wstr(s: &str) -> Vec<u8> {
        let u: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        [(u.len() as u16).to_le_bytes().to_vec(), u].concat()
    }

    /// Payload bytes produced by the client's own writer (FUN_18000e430 x3 + u32).
    #[test]
    fn parses_client_written_payload() {
        let req = LoginReq::parse(&hex(golden::LOGIN_PAYLOAD)).unwrap();
        assert_eq!(req.user, golden::LOGIN_USER);
        assert_eq!(req.password.expose(), golden::LOGIN_PASSWORD);
        assert_eq!(req.mac_text, golden::LOGIN_MAC);
        assert_eq!(req.mac, Some([0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F]));
        assert_eq!(req.client_version, CLIENT_VERSION_2334);
    }

    /// Full path: encrypted frame from the client's encrypt routine -> codec -> parser.
    #[test]
    fn end_to_end_login_frame() {
        let (_, _, wire) = golden::VECTORS.iter().find(|v| v.0 == "login_mode1").unwrap();
        let mut codec = WireCodec::new(SendPolicy::default()).with_seq_policy(SeqPolicy::Any);
        let pkt = codec.decode(&mut BytesMut::from(&hex(wire)[..])).unwrap().unwrap();
        assert_eq!((pkt.main, pkt.sub), (LoginReq::MAIN, LoginReq::SUB));
        let req = LoginReq::parse(&pkt.payload).unwrap();
        assert_eq!(req.user, "haru");
    }

    #[test]
    fn password_never_printed() {
        let req = LoginReq::parse(&hex(golden::LOGIN_PAYLOAD)).unwrap();
        let dbg = format!("{req:?}");
        assert!(!dbg.contains(golden::LOGIN_PASSWORD), "{dbg}");
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn rejects_bad_payloads() {
        let ok_tail = [wstr("pw"), wstr("00-11-22-33-44-55"), CLIENT_VERSION_2334.to_le_bytes().to_vec()].concat();

        let long = [wstr(&"a".repeat(MAX_USER_UNITS + 1)), ok_tail.clone()].concat();
        assert!(matches!(LoginReq::parse(&long), Err(ParseError::TooLong { field: "user", .. })));

        let odd = [vec![3, 0, b'a', 0, b'b'], ok_tail.clone()].concat();
        assert_eq!(LoginReq::parse(&odd), Err(ParseError::OddLength("user")));

        let lone_surrogate = [vec![2, 0, 0x00, 0xD8], ok_tail.clone()].concat();
        assert_eq!(LoginReq::parse(&lone_surrogate), Err(ParseError::InvalidUtf16("user")));

        let nul = [wstr("a\0b"), ok_tail.clone()].concat();
        assert_eq!(LoginReq::parse(&nul), Err(ParseError::EmbeddedNul("user")));

        let empty = [wstr(""), ok_tail.clone()].concat();
        assert_eq!(LoginReq::parse(&empty), Err(ParseError::Empty("user")));

        let trailing = [wstr("u"), ok_tail.clone(), vec![0]].concat();
        assert_eq!(LoginReq::parse(&trailing), Err(ParseError::TrailingBytes(1)));

        let full = [wstr("u"), ok_tail].concat();
        for cut in 0..full.len() {
            assert!(LoginReq::parse(&full[..cut]).is_err(), "truncated at {cut} must fail");
        }
        assert!(LoginReq::parse(&full).is_ok());
    }

    /// CREATE_CHARACTER_REQ captured from the real 2.3.34.7 client (creator,
    /// class 1, name "Alt", outfit 111). The client's own row reader accepted it.
    const CREATE_CAPTURE: &str = include_str!("../tests/fixtures/create_character_req.hex");

    #[test]
    fn parses_captured_create_character() {
        let p = hex(CREATE_CAPTURE.trim());
        assert_eq!(p.len(), 619);
        let req = CreateCharacterReq::parse(&p).unwrap();
        assert_eq!(req.name, "Alt");
        assert_eq!((req.class, req.class_ref, req.slot, req.outfit), (1, 1001, 1, 111));
        assert_eq!(req.appearance, [0x44d, 0x835, 0x13ed, 0xc1d]);
        for cut in [0, 10, 300, 618] {
            assert!(CreateCharacterReq::parse(&p[..cut]).is_err(), "truncated at {cut}");
        }
        assert_eq!(CreateCharacterReq::parse(&[p.clone(), vec![0]].concat()), Err(ParseError::TrailingBytes(1)));
    }

    /// The server's own row encoding must reproduce what the client wrote for
    /// a new character, apart from the fields the server sets (id).
    #[test]
    fn inventory_item_is_114_bytes() {
        let it = crate::db::ItemRecord { serial: 7, storage: 4, slot: 0, item_id: 213110091, count: 1 };
        // i32 n + (u8 + u16 + 114 + u8) + u8
        assert_eq!(inventory_info(&[it]).len(), 4 + 3 + 114 + 1 + 1);
        assert_eq!(inventory_info(&[]).len(), 5);
    }

    #[test]
    fn cash_shop_pages_cover_catalogue_and_fit_a_frame() {
        let products = crate::gamedata::CASH_SHOP;
        let pages = shop_cash_load_pages(products);
        assert!(pages.len() > 1, "catalogue is larger than one frame");
        let mut total = 0;
        for (i, p) in pages.iter().enumerate() {
            assert!(p.len() <= MAX_PAYLOAD);
            assert_eq!(p[0], (i == 0) as u8, "only the first page is a full reload");
            total += u32::from_le_bytes(p[1..5].try_into().unwrap()) as usize;
        }
        assert_eq!(total, products.len());
    }

    #[test]
    fn encoded_row_matches_client_row() {
        let p = hex(CREATE_CAPTURE.trim());
        let req = CreateCharacterReq::parse(&p).unwrap();
        let info = CharacterInfo {
            id: u32::MAX,
            name: req.name,
            class: req.class,
            level: 1,
            appearance: req.appearance,
            class_ref: req.class_ref,
            slot: req.slot,
            weapon: 0,
            shape: [0; SHAPE_SLOTS],
            shape_serial: [0; SHAPE_SLOTS],
            look: [(0, 0); SHAPE_SLOTS],
            gm_level: 0,
            ability: [(0, 0); 5],
            speed: [1.0f32.to_bits(), 1.0f32.to_bits()],
            fp: (0, 0),
        };
        let mut w = Writer::new();
        info.encode(&mut w);
        let row = w.finish();
        let client_row = &p[..p.len() - 4];
        let diff: Vec<usize> = (0..row.len().max(client_row.len())).filter(|&i| row.get(i) != client_row.get(i)).collect();
        assert!(diff.is_empty(), "row differs from the client's at {diff:x?}");
    }

    #[test]
    fn rejects_bad_create_requests() {
        let p = hex(CREATE_CAPTURE.trim());
        // name longer than the client's 20-unit buffer
        let mut long = p[..4].to_vec();
        long.extend(wstr(&"a".repeat(21)));
        long.extend_from_slice(&p[4 + 2 + 6..]);
        assert!(matches!(CreateCharacterReq::parse(&long), Err(ParseError::TooLong { field: "name", .. })));
        // empty name
        let mut empty = p[..4].to_vec();
        empty.extend(wstr(""));
        empty.extend_from_slice(&p[4 + 2 + 6..]);
        assert_eq!(CreateCharacterReq::parse(&empty), Err(ParseError::Empty("name")));
    }

    /// Shapes from the real client: 3/0x13 captured from the user's Game Start
    /// (17 bytes), 3/0x21 from writer FUN_18002c7b0 (u32, u32, u64, u8, u64).
    #[test]
    fn select_and_enter_requests() {
        let captured = hex("0100000000000000010000000000000000");
        assert_eq!(SelectCharacterReq::parse(&captured).unwrap().id, 1);
        assert!(SelectCharacterReq::parse(&captured[..16]).is_err());
        assert!(SelectCharacterReq::parse(&[captured.clone(), vec![0]].concat()).is_err());

        let minst = map_instance_id(0x123456, 1, START_DISTRICT, 1);
        assert_eq!(minst, 0x0001_2713_0112_3456);
        let mut req = Vec::new();
        req.extend(1012u32.to_le_bytes());
        req.extend(0u32.to_le_bytes());
        req.extend(minst.to_le_bytes());
        req.push(1);
        req.extend(0u64.to_le_bytes());
        let r = EnterGameServerReq::parse(&req).unwrap();
        assert_eq!((r.account_id, r.map_instance), (1012, minst));
        assert!(EnterGameServerReq::parse(&req[..24]).is_err());
    }

    #[test]
    fn select_character_res_layout() {
        let t = WorldTarget {
            character_id: 7,
            account_id: 1012,
            server_id: 1,
            jump_id: START_JUMP_ID,
            map_instance: 0x0001_2713_0100_0001,
            host: "192.168.0.100",
            port: 10200,
            district: START_DISTRICT,
            pos: START_POS,
            rot: START_ROT,
        };
        let p = select_character_res(&t, 0);
        // 5 x u32, 2 x u64, str8 host, u16 port, pos (2+8+16), u8, u8, u8, u32, u8, u32, u8, u32
        assert_eq!(p.len(), 20 + 16 + 2 + 13 + 2 + 26 + 1 + 2 + 4 + 1 + 4 + 1 + 4);
        assert_eq!(u64::from_le_bytes(p[20..28].try_into().unwrap()), t.map_instance);
        assert_eq!(&p[38..51], b"192.168.0.100");
        assert_eq!(enter_gameserver_res(0, START_DISTRICT, t.map_instance).len(), 4 + 1 + 26 + 1 + 4);
    }

    /// 3/0x31 captured from the user's client (01 00 00 00 00: character 1, u8 0); the
    /// reply was checked against reader FUN_180013560 + three u8 in Unicorn
    /// (740 + 3 bytes consumed, err 0) and is re-checked by e2e_client.py.
    #[test]
    fn character_info_layout() {
        let req = CharacterInfoReq::parse(&hex("0100000000")).unwrap();
        assert_eq!(req.character_id, 1);
        assert!(CharacterInfoReq::parse(&hex("01000000")).is_err());
        let row = CharacterInfo {
            id: 1,
            name: "Alt".into(),
            class: 1,
            level: 1,
            appearance: [0; 4],
            class_ref: 0,
            slot: 1,
            weapon: 0,
            shape: [0; SHAPE_SLOTS],
            shape_serial: [0; SHAPE_SLOTS],
            look: [(0, 0); SHAPE_SLOTS],
            gm_level: 0,
            ability: [(0, 0); 5],
            speed: [1.0f32.to_bits(), 1.0f32.to_bits()],
            fp: (0, 0),
        };
        let mut w = Writer::new();
        row.encode(&mut w);
        let row_len = w.finish().len();
        let p = character_info_res(&row, &start_spot(), 0x0001_2713_0100_0001, 0);
        // row, pos 26, f32 x2, u64 x2, u8 x4, u32 x2, u64 x3, str8 " ", u64, u32 x3, u64 x2, u8 x3
        assert_eq!(p.len(), row_len + 26 + 8 + 16 + 4 + 8 + 24 + 3 + 8 + 12 + 16 + 3);
        assert_eq!(u16::from_le_bytes(p[row_len..row_len + 2].try_into().unwrap()), START_DISTRICT);
        let x = f32::from_le_bytes(p[row_len + 10..row_len + 14].try_into().unwrap());
        assert_eq!(x, START_POS[0]);
    }

    /// Starter gear comes from the client tables: Haru (class 1) with the
    /// first creator pick 111 wears PC_A_EQ_Basic1 and holds 111011301; a pick
    /// from another class falls back to the class's own first set.
    #[test]
    fn starter_equipment_from_tables() {
        let (weapon, shape) = starter_equipment(1, 111);
        assert_eq!(weapon, 111011301);
        assert_eq!(shape[6], 211010701, "body costume in the COSTUME slot");
        assert_eq!(shape[9], 211011201, "shoes in the SHOES slot");
        assert_eq!(shape[11], 211010801, "pants in the PANTS slot");
        assert_eq!(starter_equipment(1, 211), starter_equipment(1, 111));
        assert_eq!(starter_equipment(3, 321).1[6], 231020701);
        assert_eq!(starter_equipment(99, 111), (0, [0; SHAPE_SLOTS]));

        // The row with gear still has the client's exact length and carries the ids.
        let base = CharacterInfo {
            id: 5,
            name: "Alt".into(),
            class: 1,
            level: 1,
            appearance: [1101, 2101, 5101, 3101],
            class_ref: 1001,
            slot: 1,
            weapon: 0,
            shape: [0; SHAPE_SLOTS],
            shape_serial: [0; SHAPE_SLOTS],
            look: [(0, 0); SHAPE_SLOTS],
            gm_level: 0,
            ability: [(0, 0); 5],
            speed: [1.0f32.to_bits(), 1.0f32.to_bits()],
            fp: (0, 0),
        };
        let geared = CharacterInfo { weapon, shape, ..base.clone() };
        let (mut a, mut b) = (Writer::new(), Writer::new());
        base.encode(&mut a);
        geared.encode(&mut b);
        let (a, b) = (a.finish(), b.finish());
        assert_eq!(a.len(), b.len());
        let find = |hay: &[u8], v: u32| hay.windows(4).any(|w| w == v.to_le_bytes());
        assert!(find(&b, 111011301) && find(&b, 211010701) && !find(&a, 211010701));
    }

    /// 6/0x70 with empty lists is exactly what reader FUN_18001aa90 consumes
    /// (23 bytes, Unicorn); 1/0x06 shape from the user's capture (20 bytes).
    #[test]
    fn skill_load_and_ping() {
        let p = skill_load_info(7, &[]);
        assert_eq!(p.len(), 23);
        let skills = class_skills(1);
        assert!(skills.contains(&12100011), "class 1 knows the dash skill");
        let p = skill_load_info(7, skills);
        assert_eq!(p.len(), 23 + 9 * skills.len());
        assert_eq!(u16::from_le_bytes([p[14], p[15]]) as usize, skills.len());
        assert_eq!(u32::from_le_bytes(p[16..20].try_into().unwrap()), skills[0]);
        assert_eq!(u32::from_le_bytes(p[0..4].try_into().unwrap()), 7);
        let ping = hex(concat!("73294704", "000000000000000000000000", "8f000000"));
        assert_eq!(ping.len(), 20);
        let ping = &ping[..];
        let req = PingReq::parse(ping).unwrap();
        assert_eq!(req.tick, 0x0447_2973);
        assert_eq!(ping_res(req.tick), 0x0447_2973u64.to_le_bytes().to_vec());
        assert!(PingReq::parse(&ping[..19]).is_err());
    }

    #[test]
    fn second_password_requests() {
        // Shapes written by FUN_180607230: u8 kind, str8 pin.
        let set = SecondPasswordReq::parse(&[1, 6, 0, b'1', b'3', b'5', b'7', b'9', b'0']).unwrap();
        assert_eq!((set.kind, set.pin.expose()), (SecondPwKind::Set, "135790"));
        let later = SecondPasswordReq::parse(&[3, 0, 0]).unwrap();
        assert_eq!(later.kind, SecondPwKind::Later);
        assert_eq!(SecondPasswordReq::parse(&[0, 0, 0]).unwrap().kind, SecondPwKind::Other(0));
        assert!(!format!("{set:?}").contains("135790"));
        // malformed
        assert!(SecondPasswordReq::parse(&[2, 3, 0, b'1', b'2', b'3']).is_err(), "verify needs 6 digits");
        assert!(SecondPasswordReq::parse(&[1, 6, 0, b'a', b'b', b'c', b'd', b'e', b'f']).is_err());
        assert!(SecondPasswordReq::parse(&[2, 7, 0, b'1', b'2', b'3', b'4', b'5', b'6', b'7']).is_err());
        assert!(SecondPasswordReq::parse(&[3, 0, 0, 0]).is_err(), "trailing byte");
        assert!(SecondPasswordReq::parse(&[2, 6, 0, b'1']).is_err(), "truncated");
    }

    #[test]
    fn character_name_rule() {
        for ok in ["Alt", "Haru1", "Çağrı", "하루", "ab", "abcdefghijkl"] {
            assert!(valid_character_name(ok), "{ok}");
        }
        for bad in ["a", "abcdefghijklm", "a b", "GM_", "", "a\u{200b}b"] {
            assert!(!valid_character_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn mac_text_shapes() {
        assert_eq!(parse_mac("0a-1B-2c-3D-4e-5F"), Some([0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F]));
        assert_eq!(parse_mac(""), None);
        assert_eq!(parse_mac("0A-1B-2C-3D-4E"), None);
        assert_eq!(parse_mac("0A-1B-2C-3D-4E-5F-60"), None);
        assert_eq!(parse_mac("0A:1B:2C:3D:4E:5F"), None);
        assert_eq!(parse_mac("+A-1B-2C-3D-4E-5F"), None);
    }

    #[test]
    fn gm_commands_parse() {
        assert_eq!(parse_gm_line("/item 213881001"), GmCommand::Item { item: 213881001, count: 1 });
        assert_eq!(parse_gm_line("/item 213881001 5"), GmCommand::Item { item: 213881001, count: 5 });
        assert_eq!(parse_gm_line("/item 1 213881001"), GmCommand::Item { item: 213881001, count: 1 }, "batch order");
        assert!(matches!(parse_gm_line("/item 7"), GmCommand::Unknown(_)), "7 is not a tb_Item id");
        assert_eq!(parse_gm_line("/CASH 500"), GmCommand::Cash(500));
        assert_eq!(parse_gm_line("movespeed 150"), GmCommand::MoveSpeed(150.0));
        let mut w = Writer::new();
        w.wstr("/item 6000451");
        assert_eq!(parse_gm_command(&w.finish()).unwrap(), "/item 6000451");
    }

    #[test]
    fn gm_byte_sits_at_the_captured_offset() {
        // Captured 3/0x32 for "Alt": the CHARACTER_INFO reader stores row byte 46 at +0x26c.
        let mut row = CharacterInfo {
            id: 1,
            name: "Alt".into(),
            class: 1,
            level: 1,
            appearance: [0; 4],
            class_ref: 0,
            slot: 1,
            weapon: 0,
            shape: [0; SHAPE_SLOTS],
            shape_serial: [0; SHAPE_SLOTS],
            look: [(0, 0); SHAPE_SLOTS],
            gm_level: 0,
            ability: [(0, 0); 5],
            speed: [0; 2],
            fp: (0, 0),
        };
        let mut a = Writer::new();
        row.encode(&mut a);
        row.gm_level = 1;
        let mut b = Writer::new();
        row.encode(&mut b);
        let (a, b) = (a.finish(), b.finish());
        let diff: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
        assert_eq!(diff, vec![46]);
    }

    #[test]
    fn rocco_town_npcs_encode() {
        let npcs = district_npcs(START_DISTRICT);
        assert_eq!(npcs.len(), 36, "F031_ROCCOTOWN.vbatch has 36 immediate NPC slots");
        let p = world_npcs(npcs);
        assert_eq!(p.len(), 2 + 36 * 49);
        assert_eq!(&p[0..2], &36u16.to_le_bytes());
        assert_eq!(u32::from_le_bytes(p[2..6].try_into().unwrap()), ACTOR_NPC | 1);
        assert_eq!(u32::from_le_bytes(p[47..51].try_into().unwrap()), npcs[0].0, "table id ends the entry");
    }

    /// Real client chat capture (2026-10-18): normal chat "hello".
    #[test]
    fn chat_capture_and_reply() {
        let cap = [0x01, 0x0A, 0x00, b'h', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0, 0x00];
        let req = ChatReq::parse(&cap).unwrap();
        assert_eq!((req.appearance, req.message.as_str()), (1, "hello"));
        assert_eq!(clean_chat("  selam\u{7}  "), "selam");
        assert_eq!(clean_chat(&"ş".repeat(300)).chars().count(), CHAT_MAX_UNITS);
        let res = chat_normal(7, "hi");
        assert_eq!(res, [7, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 0, b'h', 0, b'i', 0, 0], "type 1 (name from actor), no item links");
    }

    /// Real client equip capture (2026-10-18): costume 213881001 from costume
    /// bag slot 0 to shape slot 7; tb_Item_Classify says slot type 0x12.
    #[test]
    fn item_move_capture_and_equip_rules() {
        let cap = [0x04, 0xA9, 0x90, 0xBF, 0x0C, 0, 0, 0, 0, 0xA9, 0x90, 0xBF, 0x0C, 0x07, 0, 0];
        let req = ItemMoveReq::parse(&cap).unwrap();
        assert_eq!((req.src, req.dest), ((4, 0), (0, 7)));
        assert_eq!(item_class(213881001), Some((2, 0x12)));
        assert!(item_fits(213881001, storage::SHAPE_EQUIP, 7));
        assert!(item_fits(213881001, storage::LOOK_EQUIP, 7));
        assert!(!item_fits(213881001, storage::SHAPE_EQUIP, 6));
        assert!(item_fits(213881001, storage::COSTUME, 47) && !item_fits(213881001, storage::COSTUME, 48));
        assert!(!item_fits(213881001, storage::CASH, 0), "costumes do not go to the cash bag");
        assert!(!item_fits(6000451, storage::SHAPE_EQUIP, 0), "a box is not wearable");
        assert_eq!(cash_item_storage(6000451), storage::CASH);
        assert_eq!(cash_item_storage(213881001), storage::COSTUME);
        // 2 x {u8, u32, u16, u8} + 2 x u8 bind
        let res = item_move_res((4, 0, None), (0, 7, Some(213881001)));
        assert_eq!(res.len(), 1 + 8 + 8 + 2);
        assert_eq!(&res[1..9], &[4, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0]);
    }
}
