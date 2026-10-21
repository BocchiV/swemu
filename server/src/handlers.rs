//! Packet handlers for the 2.3.34.7 login -> game-server -> character list flow.
//!
//! Every layout cites the client function that reads or writes it (SoulWorker64.dll
//! 2.3.34.7, Ghidra base 0x180000000); see proto.rs and docs/re-log.md. The client's
//! own readers run against these replies in re/e2e_client.py.
//!
//! Flow (login port):
//!   C 2/1  LOGIN_REQ          -> S 2/2  LOGIN_RESULT (account, session ticket)
//!   C 2/3  SERVER_LIST_REQ    -> S 2/4  SERVER_LIST
//!   C 2/5  SERVER_CONNECT_REQ -> S 2/0x11 ENTER_SERVER; client reconnects to the row's host:port
//! Flow (game port):
//!   C 2/0x13 ENTER_SERVER_REQ (account, server, ticket) -> S 2/0x14 ENTER_SERVER_RES
//!   C 3/0x11 CHARACTER_LIST_REQ (ticket)               -> S 3/0x12 CHARACTER_LIST_RES
//!   C 3/0x0D REPRESENTATIVE_CHECK (empty)              -> S 3/0x0D u32 0
//!   C 3/0x01 CREATE_CHARACTER_REQ (row + outfit)       -> S 3/0x12 list (scene 7 -> 8)
//!                                                         or S 3/0x57 CHECK_NAME (name taken)
//!   C 3/0x02 DELETE_CHARACTER_REQ (id)                 -> S 3/0x03 u32 0, S 3/0x12 list
//!   C 3/0x17 SECOND_PASSWORD (kind, pin)               -> S 3/0x17 (result, state)
//!   C 3/0x13 SELECT_CHARACTER_REQ (id)                 -> S 3/0x14 world host:port + map instance
//! Flow (world connection, same game port, opened by the client after 3/0x14):
//!   C 3/0x21 ENTER_GAMESERVER_REQ (account, map instance) -> S 3/0x22 ENTER_GAMESERVER_RES

use crate::db::{CreateOutcome, LoginOutcome, NewCharacter};
use crate::proto::{
    self, CharacterInfo, CharacterInfoReq, CharacterListReq, CreateCharacterReq, DeleteCharacterReq, EnterGameServerReq,
    EnterServerReq,
    LoginError, LoginReq, LoginResult, PingReq, SecondPasswordReq, SecondPwKind, SecondPwState, SelectCharacterReq, ServerConnectReq,
    ServerListReq, WorldTarget,
};
use crate::session::{Role, Session};
use crate::wire::Packet;
use anyhow::Result;
use tracing::{info, warn};

pub const MAIN_SYSTEM: u8 = 1;
pub const MAIN_LOGIN: u8 = 2;
pub const MAIN_CHARACTER: u8 = 3;
pub const MAIN_SKILL: u8 = 6;
pub const MAIN_WORLD: u8 = 4;
pub const MAIN_SHOP: u8 = 9;
pub const MAIN_ITEM: u8 = 8;
pub const MAIN_CHAT: u8 = 7;
pub const MAIN_CHANNEL: u8 = 0xF1;
pub const MAIN_QUEST: u8 = 0x15;
pub const MAIN_MAZE: u8 = 0x11;
pub const MAIN_MONSTER: u8 = 0x17;
pub const MAIN_DROP: u8 = 0x14;
pub const MAIN_GESTURE: u8 = 0x23;

/// The character select panel holds 12 slots (FUN_1807a9b00: slot-1 < 12).
pub const MAX_CHARACTER_SLOTS: u8 = 12;

pub fn dispatch(s: &mut Session, f: &Packet) -> Result<()> {
    match (s.role, f.main, f.sub) {
        // Reply to a server KEEP_ALIVE (handler FUN_180deca80 -> FUN_1805f0240).
        // The server never sends one yet, so this only appears if that changes.
        (_, MAIN_SYSTEM, 0x05) => {}
        (_, MAIN_SYSTEM, 0x06) => {
            let req = PingReq::parse(&f.payload)?;
            s.send(MAIN_SYSTEM, 0x06, proto::ping_res(req.tick));
        }

        (Role::Login, LoginReq::MAIN, LoginReq::SUB) => login(s, LoginReq::parse(&f.payload)?),
        (Role::Login, MAIN_LOGIN, 0x23) => {
            // LOGIN_FOR_VFUN (launcher token). The token cannot be verified offline,
            // so accepting it would let anyone log in as anyone.
            warn!(conn = s.id, "LOGIN_FOR_VFUN refused (allow_launcher_token=false); use the ID/password dialog");
            reply_login_error(s, LoginError::Rejected);
        }
        (Role::Login, MAIN_LOGIN, 0x03) => {
            let req = ServerListReq::parse(&f.payload)?;
            let Some(account) = require_login(s) else { return Ok(()) };
            if req.value != account {
                warn!(conn = s.id, got = req.value, account, "SERVER_LIST_REQ account mismatch");
            }
            send_server_list(s);
        }
        (Role::Login, MAIN_LOGIN, 0x05) => {
            let req = ServerConnectReq::parse(&f.payload)?;
            if require_login(s).is_none() {
                return Ok(());
            }
            if req.server_id != s.shared.cfg.server_id {
                warn!(conn = s.id, server = req.server_id, "SERVER_CONNECT_REQ for unknown server");
                return Ok(());
            }
            let cfg = s.shared.cfg.clone();
            s.send(MAIN_LOGIN, 0x11, proto::enter_server(&cfg.public_ip, cfg.game_port));
        }

        (Role::Game, MAIN_LOGIN, 0x13) => enter_server(s, EnterServerReq::parse(&f.payload)?),
        (Role::Game, MAIN_CHARACTER, 0x11) => {
            let req = CharacterListReq::parse(&f.payload)?;
            if s.session_key != Some(req.session) {
                warn!(conn = s.id, "CHARACTER_LIST_REQ without a valid game session; closing");
                s.close = true;
                return Ok(());
            }
            send_character_list(s);
        }
        (Role::Game, MAIN_CHARACTER, 0x0D) => {
            if require_game(s).is_some() {
                s.send(MAIN_CHARACTER, 0x0D, proto::representative_check());
            }
        }
        (Role::Game, MAIN_CHARACTER, 0x01) => {
            let req = CreateCharacterReq::parse(&f.payload)?;
            create_character(s, req);
        }
        (Role::Game, MAIN_CHARACTER, 0x02) => {
            let req = DeleteCharacterReq::parse(&f.payload)?;
            delete_character(s, req);
        }
        (Role::Game, MAIN_CHARACTER, 0x17) => {
            let req = SecondPasswordReq::parse(&f.payload)?;
            second_password(s, req);
        }
        (Role::Game, MAIN_CHARACTER, 0x13) => {
            let req = SelectCharacterReq::parse(&f.payload)?;
            select_character(s, req);
        }
        (Role::Game, MAIN_CHARACTER, 0x21) => {
            let req = EnterGameServerReq::parse(&f.payload)?;
            enter_gameserver(s, req);
        }
        (Role::Game, MAIN_CHARACTER, 0x31) => {
            let req = CharacterInfoReq::parse(&f.payload)?;
            character_info(s, req);
        }
        // WORLD_OBJECT_REQ (writer FUN_1805f4e00, empty): sent once the map has
        // loaded in PlayScene, so per-player UI data goes out here.
        (Role::Game, MAIN_WORLD, 0x06) => world_loaded(s),
        // WORLD_ENTER_REQ 4/0x01 and MAZE_CREATE_REQ 4/0x41 (maze stage
        // picked in the portal UI) share the PS_ENTER_MAP_REQ head; both are
        // answered with WORLD_ENTER_RES 4/0x02 (OpenWorker WorldService).
        (Role::Game, MAIN_WORLD, sub @ (0x01 | 0x41)) => {
            let req = proto::WorldEnterReq::parse(&f.payload)?;
            info!(conn = s.id, sub, map = req.map, portal = req.portal, "world enter request");
            world_enter(s, req);
        }
        (Role::Game, MAIN_CHARACTER, 0x60) => {
            let req = proto::GoBackLobbyReq::parse(&f.payload)?;
            go_back_lobby(s, req);
        }
        (Role::Game, MAIN_MAZE, 0x23) => {
            info!(conn = s.id, "exit maze request");
            exit_maze(s);
        }
        (Role::Game, MAIN_MAZE, 0x7E) => {
            let id = f.payload.get(0..4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
            if s.character_id.is_some() {
                s.send(MAIN_MAZE, 0x7F, proto::maze_lua_function_res(id));
            }
        }
        (Role::Game, MAIN_GESTURE, 0x01) => {
            let req = proto::GestureReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                s.send(MAIN_GESTURE, 0x01, proto::gesture_show(character, &req));
            }
        }
        // CHANNEL_INFO_REQ F1/01 (empty) arrives once the map has loaded.
        // OpenWorker answers it with the district's NPC list (ChannelService).
        (Role::Game, MAIN_CHANNEL, 0x01) => {
            if s.character_id.is_some() {
                let map = s.spot.map_or(proto::START_DISTRICT, |p| p.map);
                let npcs = proto::district_npcs(map);
                info!(conn = s.id, npcs = npcs.len(), "channel info: sending district NPCs");
                s.send(MAIN_WORLD, 0x22, proto::world_npcs(npcs));
                if proto::is_maze(map) {
                    spawn_monsters(s, map, None);
                }
                send_maze_state(s);
            }
        }
        // 17/0x22 (empty, writer FUN_1805f7950): sent once a maze map has
        // loaded on the same connection; no reply handler in PlayScene.
        // Spawn the maze's map-load monsters here.
        (Role::Game, MAIN_MAZE, 0x22) => {
            if let Some(map) = s.spot.map(|p| p.map).filter(|&m| proto::is_maze(m)) {
                spawn_monsters(s, map, None);
                send_maze_state(s);
            }
        }
        // EVENT_SPAWN_BOX_REQ 17/0x31 (writer FUN_1805f5330): u32 check box
        // the player walked into -> the spawn boxes it releases (OpenWorker
        // MazeService MazeEventSpawnBoxRequest).
        (Role::Game, MAIN_MAZE, 0x31) => {
            let id = f.payload.get(0..4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
            if let Some(map) = s.spot.map(|p| p.map).filter(|&m| proto::is_maze(m)) {
                spawn_monsters(s, map, Some(id));
            }
        }
        // Movement: positions feed the monster AI (no reply is expected for
        // a single player; 5/0x01 move, 5/0x03 stop, 5/0x22 position).
        (Role::Game, 5, sub @ (0x01 | 0x03 | 0x22)) => {
            if let Some(pos) = proto::parse_move_pos(sub, &f.payload) {
                crate::maze::player_moved(s, pos);
            }
        }
        // SKILL_SYNC_POSITION_REQ 6/0x47 (writer FUN_1805f3610): f32 x/y/z
        // first; answered with 6/0x48 (reader u32 actor + 4 x f32).
        (Role::Game, MAIN_SKILL, 0x47) => {
            if let (Some(character), Some(pos)) = (s.character_id, proto::pos_from(&f.payload, 0)) {
                crate::maze::player_moved(s, pos);
                let mut w = crate::codec::Writer::new();
                w.u32(character);
                for v in [pos[0], pos[1], pos[2], 0.0f32] {
                    w.u32(v.to_bits());
                }
                s.send(MAIN_SKILL, 0x48, w.finish());
            }
        }
        // REVIVE_REQ 3/0x42 (writer FUN_1805f6740: u32 actor, u8 type).
        (Role::Game, MAIN_CHARACTER, 0x42) => {
            let kind = f.payload.get(4).copied().unwrap_or(0);
            if s.dead {
                crate::maze::revive(s, kind);
            }
        }
        // WARP_REQ 4/0x07 (writer FUN_1805f4e60): JumpPos portal in a maze.
        (Role::Game, MAIN_WORLD, 0x07) => {
            let mut r = crate::codec::Reader::new(&f.payload);
            let ids = [r.u32().unwrap_or(0), r.u32().unwrap_or(0), r.u32().unwrap_or(0)];
            crate::maze::warp(s, ids);
        }
        (Role::Game, MAIN_DROP, 0x02) => {
            let (group, serial) = proto::parse_pick_up(&f.payload)?;
            pick_up(s, group, serial);
        }
        (Role::Game, MAIN_SKILL, 0x36) => {
            s.pre_targets = proto::parse_pre_targets(&f.payload);
        }
        (Role::Game, MAIN_SKILL, 0x08) => {
            let req = proto::ActiveSkillReq::parse(&f.payload)?;
            s.send(MAIN_SKILL, 0x09, proto::active_skill_res());
            crate::maze::spend_skill_cost(s, req.skill);
            skill_hit(s, req);
        }
        // PASSIVE_SKILL_REQ 6/0x06 (u32 skill first): the dash / emergency
        // evade (e.g. 12040011, tb_Skill cost 20 stamina) arrives here.
        (Role::Game, MAIN_SKILL, 0x06) => {
            if let Some(b) = f.payload.get(0..4) {
                crate::maze::spend_skill_cost(s, u32::from_le_bytes(b.try_into().unwrap()));
            }
        }
        // PASSIVE_SKILL_END 6/0x05 -> 6/0x07 error 0 (OpenWorker SkillService).
        (Role::Game, MAIN_SKILL, 0x05) => {
            s.send(MAIN_SKILL, 0x07, proto::skill_passive_res(0));
        }
        (Role::Game, MAIN_SKILL, sub @ (0x71 | 0x72 | 0x75 | 0x76 | 0x77 | 0x79)) => {
            skill_tree(s, sub, &f.payload);
        }
        (Role::Game, MAIN_CHAT, 0x01) => {
            let req = proto::ChatReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                let text = proto::clean_chat(&req.message);
                if !text.is_empty() {
                    info!(conn = s.id, character, chat = %text, "chat");
                    // Single player for now: the speaker sees their own line.
                    s.send(MAIN_CHAT, 0x01, proto::chat_normal(character, &text));
                }
            }
        }
        (Role::Game, MAIN_CHAT, 0x0A) => {
            let line = proto::parse_gm_command(&f.payload)?;
            if let Some(character) = s.character_id {
                gm_command(s, character, &line);
            }
        }
        (Role::Game, MAIN_ITEM, 0x02) => {
            let req = proto::ItemMoveReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                move_item(s, character, req);
            }
        }
        (Role::Game, MAIN_ITEM, 0x03) => {
            let req = proto::ItemCombineReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                combine_items(s, character, req);
            }
        }
        (Role::Game, MAIN_ITEM, 0x04) => {
            let req = proto::ItemDivideReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                divide_item(s, character, req);
            }
        }
        (Role::Game, MAIN_ITEM, 0x05) => {
            let req = proto::ItemBreakReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                discard_item(s, character, req);
            }
        }
        (Role::Game, MAIN_ITEM, 0x25) => {
            let st = *f.payload.first().ok_or(proto::ParseError::TrailingBytes(0))?;
            if let Some(character) = s.character_id {
                line_up(s, character, st);
            }
        }
        (Role::Game, MAIN_ITEM, 0x11) => {
            let req = proto::ItemUseReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                use_item(s, character, &req);
            }
        }
        (Role::Game, MAIN_ITEM, 0x01) => {
            let req = proto::InventoryInfoReq::parse(&f.payload)?;
            if s.character_id.is_some() {
                s.send(MAIN_ITEM, 0x0E, proto::open_slot_info(&req.groups));
                send_inventory(s);
            }
        }
        (Role::Game, MAIN_SHOP, 0x01) => {
            let req = proto::ShopBuyReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                shop_buy(s, character, req);
            }
        }
        (Role::Game, MAIN_SHOP, 0x02) => {
            let req = proto::ShopSellReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                shop_sell(s, character, &req);
            }
        }
        (Role::Game, MAIN_SHOP, 0x03) => {
            if let Some(character) = s.character_id {
                send_buyback(s, character);
            }
        }
        (Role::Game, MAIN_SHOP, 0x04) => {
            let req = proto::RepurchaseReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                repurchase(s, character, req);
            }
        }
        (Role::Game, MAIN_SHOP, 0x20) => {
            if s.character_id.is_some() {
                send_cash_shop(s);
            }
        }
        (Role::Game, MAIN_SHOP, 0x21) => {
            let req = proto::CashBuyReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                cash_buy(s, character, &req);
            }
        }

        (Role::Game, 0x18, 0x09) => {
            let req = proto::RepairNpcReq::parse(&f.payload)?;
            if let Some(character) = s.character_id {
                let items = s.shared.db.lock().unwrap().items(character).unwrap_or_default();
                match items.iter().find(|i| (i.storage, i.slot) == req.at) {
                    Some(it) => {
                        info!(conn = s.id, at = ?req.at, item = it.item_id, "repair (already full)");
                        s.send(0x18, 0x09, proto::repair_npc_res(it, 0));
                    }
                    None => warn!(conn = s.id, at = ?req.at, "repair: empty slot"),
                }
            }
        }
        (Role::Game, 0x18, sub @ (0x10 | 0x11)) => {
            if let Some(character) = s.character_id {
                let items = s.shared.db.lock().unwrap().items(character).unwrap_or_default();
                let gear: Vec<_> = items.into_iter().filter(|i| i.storage == proto::storage::ABILITY_EQUIP).collect();
                info!(conn = s.id, items = gear.len(), all = sub == 0x11, "repair equipment (already full)");
                s.send(0x18, sub, proto::repair_list_res(&gear, 0));
            }
        }
        (Role::Game, 0x03, 0x47) => {
            let mut r = crate::codec::Reader::new(&f.payload);
            let actor = r.u32().map_err(|_| proto::ParseError::Read("special option actor"))?;
            if s.character_id.is_some() {
                s.send(0x03, 0x47, proto::special_option_list(actor));
            }
        }
        (Role::Game, main, sub) if s.character_id.is_some() && proto::empty_list_reply(main, sub).is_some() => {
            let n = proto::empty_list_reply(main, sub).unwrap_or(0);
            s.send(main, sub, vec![0; n]);
        }
        _ => warn!(conn = s.id, op = format!("0x{:04X}", f.opcode()), len = f.payload.len(), "UNHANDLED"),
    }
    Ok(())
}

fn require_login(s: &mut Session) -> Option<u32> {
    if s.account_id.is_none() {
        warn!(conn = s.id, "request before login; closing");
        s.close = true;
    }
    s.account_id
}

/// Account of a game connection that presented a valid ticket.
fn require_game(s: &mut Session) -> Option<u32> {
    match (s.account_id, s.session_key) {
        (Some(account), Some(_)) => Some(account),
        _ => {
            warn!(conn = s.id, "character request before ENTER_SERVER; closing");
            s.close = true;
            None
        }
    }
}

fn send_character_list(s: &mut Session) {
    let Some(account) = require_game(s) else { return };
    let rows = match s.shared.db.lock().unwrap().characters(account) {
        Ok(rows) => rows,
        Err(e) => {
            warn!(conn = s.id, "db: {e:#}");
            Vec::new()
        }
    };
    let rows: Vec<CharacterInfo> = rows.into_iter().map(|c| character_row(s, c)).collect();
    let select = rows.first().map_or(0, |c| c.id);
    let pw = second_pw_state(s, account);
    s.send(MAIN_CHARACTER, 0x12, proto::character_list(&rows, select, pw));
}

/// Wrong second passwords allowed per connection before it is closed.
const MAX_SECOND_PW_FAILURES: u32 = 5;

fn second_pw_state(s: &Session, account: u32) -> SecondPwState {
    if s.second_pw_unlocked {
        return SecondPwState::Unlocked;
    }
    match s.shared.db.lock().unwrap().has_second_password(account) {
        Ok(true) => SecondPwState::Locked,
        Ok(false) => SecondPwState::NotSet,
        Err(e) => {
            warn!(conn = s.id, "db: {e:#}");
            SecondPwState::Locked
        }
    }
}

/// SECOND_PASSWORD 3/0x17. Replying (0, Unlocked) makes the client redo the
/// pending action (Game Start / Delete); (0, Locked) opens the PIN pad;
/// (0, NotSet) asks the player to create a PIN.
fn second_password(s: &mut Session, req: SecondPasswordReq) {
    let Some(account) = require_game(s) else { return };
    let looked_up = s.shared.db.lock().unwrap().has_second_password(account);
    let has_pin = match looked_up {
        Ok(v) => v,
        Err(e) => {
            warn!(conn = s.id, "db: {e:#}");
            s.send(MAIN_CHARACTER, 0x17, proto::second_password_res(proto::MSG_SECOND_PW_INCORRECT, SecondPwState::Locked));
            return;
        }
    };
    let (result, state) = match (req.kind, has_pin) {
        // First PIN for the account.
        (SecondPwKind::Set, false) => {
            let stored = s.shared.db.lock().unwrap().set_second_password(account, req.pin.expose());
            match stored {
                Ok(true) => {
                    info!(conn = s.id, account, "second password set");
                    s.second_pw_unlocked = true;
                    (0, SecondPwState::Unlocked)
                }
                Ok(false) => (0, SecondPwState::Locked),
                Err(e) => {
                    warn!(conn = s.id, "db: {e:#}");
                    (proto::MSG_SECOND_PW_INCORRECT, SecondPwState::NotSet)
                }
            }
        }
        // A PIN already exists: never overwrite it, ask for it instead.
        (SecondPwKind::Set | SecondPwKind::Later, true) => (0, SecondPwState::Locked),
        (SecondPwKind::Verify, true) => {
            let checked = s.shared.db.lock().unwrap().verify_second_password(account, req.pin.expose());
            let ok = checked.unwrap_or_else(|e| {
                warn!(conn = s.id, "db: {e:#}");
                false
            });
            if ok {
                info!(conn = s.id, account, "second password ok");
                s.second_pw_unlocked = true;
                s.second_pw_failures = 0;
                (0, SecondPwState::Unlocked)
            } else {
                s.second_pw_failures += 1;
                warn!(conn = s.id, account, failures = s.second_pw_failures, "wrong second password");
                if s.second_pw_failures >= MAX_SECOND_PW_FAILURES {
                    s.close = true;
                }
                (proto::MSG_SECOND_PW_INCORRECT, SecondPwState::Locked)
            }
        }
        (SecondPwKind::Verify, false) => (0, SecondPwState::NotSet),
        // "Set Later" while no PIN exists: continue without one.
        (SecondPwKind::Later, false) => {
            info!(conn = s.id, account, "second password skipped (none set)");
            s.second_pw_unlocked = true;
            (0, SecondPwState::Unlocked)
        }
        (SecondPwKind::Blocked, _) => (0, SecondPwState::Locked),
        (SecondPwKind::Other(k), _) => {
            warn!(conn = s.id, kind = k, "SECOND_PASSWORD with unknown kind; replying with current state");
            (0, second_pw_state(s, account))
        }
    };
    s.send(MAIN_CHARACTER, 0x17, proto::second_password_res(result, state));
}

/// SELECT_CHARACTER_REQ 3/0x13 (Game Start). The client gates this on its own
/// PIN state; the server checks it again, plus character ownership, then sends
/// the world address with a one-time map instance id.
fn select_character(s: &mut Session, req: SelectCharacterReq) {
    let Some(account) = require_game(s) else { return };
    // A PIN that exists must have been entered on this connection; with no PIN
    // there is nothing to protect.
    if second_pw_state(s, account) == SecondPwState::Locked {
        warn!(conn = s.id, account, "SELECT_CHARACTER_REQ before the second password was entered");
        s.send(MAIN_CHARACTER, 0x14, proto::select_character_fail(proto::MSG_LOGIN_FAILED, &s.shared.cfg.public_ip.clone()));
        return;
    }
    let owned = s.shared.db.lock().unwrap().characters(account);
    let owned = match owned {
        Ok(rows) => rows.iter().any(|c| c.id == req.id),
        Err(e) => {
            warn!(conn = s.id, "db: {e:#}");
            false
        }
    };
    if !owned {
        warn!(conn = s.id, account, id = req.id, "SELECT_CHARACTER_REQ for a character the account does not own");
        s.send(MAIN_CHARACTER, 0x14, proto::select_character_fail(proto::MSG_LOGIN_FAILED, &s.shared.cfg.public_ip.clone()));
        return;
    }
    let cfg = s.shared.cfg.clone();
    let spot = proto::start_spot();
    let map_instance = s.shared.issue_world_ticket(account, req.id, s.peer.ip(), spot, cfg.server_id);
    info!(conn = s.id, account, id = req.id, district = spot.map, "character selected; sending world address");
    let target = world_target(req.id, account, &cfg, map_instance, &spot);
    s.send(MAIN_CHARACTER, 0x14, proto::select_character_res(&target, 0));
}

fn world_target<'a>(character: u32, account: u32, cfg: &'a crate::config::Config, map_instance: u64, spot: &proto::Spot) -> WorldTarget<'a> {
    WorldTarget {
        character_id: character,
        account_id: account,
        server_id: u32::from(cfg.server_id),
        jump_id: spot.jump,
        map_instance,
        host: &cfg.public_ip,
        port: cfg.game_port,
        district: spot.map,
        pos: spot.pos,
        rot: spot.rot,
    }
}

/// Send the client to another map: a new world ticket for `spot` and
/// WORLD_ENTER_RES 4/0x02. The client reconnects and enters like after the
/// character select (ENTER_GAMESERVER_REQ -> CHARACTER_INFO at `spot`).
fn change_world(s: &mut Session, account: u32, character: u32, spot: proto::Spot) {
    let cfg = s.shared.cfg.clone();
    let map_instance = s.shared.issue_world_ticket(account, character, s.peer.ip(), spot, cfg.server_id);
    info!(conn = s.id, account, character, from = s.spot.map(|p| p.map), to = spot.map, jump = spot.jump, "changing world");
    let target = world_target(character, account, &cfg, map_instance, &spot);
    s.send(MAIN_WORLD, 0x02, proto::world_enter_res(&target, 0));
    // The real client keeps this connection when the new map is on the same
    // server (no reconnect seen in packets.log): it loads the map and sends
    // MAZE_LOADED 17/0x22 here. Move the session now; a reconnect with the
    // ticket would set the same spot again.
    s.spot = Some(spot);
    s.map_instance = Some(map_instance);
    crate::maze::reset(s);
    s.player_pos = Some(spot.pos);
    // Leaving a maze dead or hurt: back on your feet with full HP.
    s.dead = false;
    s.player_hp = s.player_max_hp;
}

fn refuse_world_enter(s: &mut Session, msg: u32) {
    let host = s.shared.cfg.public_ip.clone();
    let mut w = proto::select_character_fail(msg, &host);
    w.extend_from_slice(&[0, 0]);
    s.send(MAIN_WORLD, 0x02, w);
}

/// WORLD_ENTER_REQ 4/0x01: portal or maze stage picked. Checks follow the
/// reference server's CWorldProcess::ReqWorldEnter (maze branch): the
/// maze must exist, the level must reach Req_Min_Lv, a soul weapon must be
/// worn. FP, quest, enter-count and party checks come with those systems.
fn world_enter(s: &mut Session, req: proto::WorldEnterReq) {
    let (Some(account), Some(character)) = (s.account_id, s.character_id) else { return };
    let here = s.spot.unwrap_or_else(proto::start_spot);
    if req.map == here.map {
        return;
    }
    let level = s
        .shared
        .db
        .lock()
        .unwrap()
        .characters(account)
        .ok()
        .and_then(|r| r.into_iter().find(|c| c.id == character))
        .map_or(1, |c| c.level);
    if proto::is_maze(req.map) {
        let Some(m) = proto::maze(req.map) else {
            warn!(conn = s.id, map = req.map, portal = req.portal, "world enter: maze not in the client data");
            refuse_world_enter(s, proto::MSG_ENTER_NO_MAP);
            return;
        };
        if level < m.min_level {
            warn!(conn = s.id, map = req.map, level, need = m.min_level, "world enter: level too low");
            refuse_world_enter(s, proto::MSG_ENTER_LEVEL);
            return;
        }
        change_world(s, account, character, m.start);
    } else {
        // District (portal or maze exit): only districts with known exits.
        let Some(spot) = proto::district_exit(req.map, req.map as u32 * 100 + 1) else {
            warn!(conn = s.id, map = req.map, portal = req.portal, "world enter: district not supported yet");
            refuse_world_enter(s, proto::MSG_ENTER_NO_MAP);
            return;
        };
        change_world(s, account, character, spot);
    }
}

fn spawn_monsters(s: &mut Session, maze: u16, check: Option<u32>) {
    let key = proto::spawn_key(maze);
    let boxes = proto::trigger_boxes(key, check);
    // A box spawns once per instance (repeated check boxes are ignored).
    crate::maze::spawn_boxes(s, key, &boxes, if check.is_some() { "check box" } else { "map load" });
    // Sectors without any counted monster (cinematics, empty rooms) clear
    // right away so their exit portal opens.
    crate::maze::after_kills(s);
}

/// Player HP and the maze's portal state after a (re)load.
fn send_maze_state(s: &mut Session) {
    let (Some(character), Some(spot)) = (s.character_id, s.spot) else { return };
    crate::maze::send_hp(s, character);
    let _ = spot;
    crate::maze::send_object_state(s);
}

/// A skill went off: hit the monsters the client named in PRE_TARGET_LIST,
/// else the live monsters within reach of the skill position. Broadcast the
/// damage (6/0x13), kill monsters at 0 HP (0x17/0x11) and grant EXP / levels
/// (3/0x37, 3/0x36). Combat formulas are placeholders until tb_Skill /
/// tb_Status are ported from the GameServer.
fn skill_hit(s: &mut Session, req: proto::ActiveSkillReq) {
    const REACH: f32 = 450.0;
    let Some(character) = s.character_id else { return };
    if s.monsters.is_empty() {
        return;
    }
    let targets = std::mem::take(&mut s.pre_targets);
    let near = |m: &proto::Monster| {
        let (dx, dy) = (m.pos[0] - req.pos[0], m.pos[1] - req.pos[1]);
        dx * dx + dy * dy <= REACH * REACH
    };
    if s.dead {
        return;
    }
    let (level, exp) = s.shared.db.lock().unwrap().level_exp(character).unwrap_or((1, 0));
    crate::maze::player_moved(s, req.pos);
    let mut hits = Vec::new();
    let mut dead = Vec::new();
    let mut roll = req.skill ^ s.monster_seq.wrapping_mul(2654435761) ^ u32::from(s.combo);
    for m in s.monsters.iter_mut() {
        let chosen = if targets.is_empty() { near(m) } else { targets.contains(&m.actor) };
        if !chosen || m.hp <= 0 {
            continue;
        }
        roll = roll.wrapping_mul(1103515245).wrapping_add(12345);
        let dmg = proto::skill_damage(req.skill, level, m.level, roll >> 8);
        m.hp = (m.hp - dmg).max(0);
        hits.push(proto::Hit { actor: m.actor, damage: dmg, hp: m.hp });
        if m.hp == 0 {
            dead.push((m.actor, m.level, m.rank));
        }
    }
    if hits.is_empty() {
        s.combo = 0;
        return;
    }
    s.combo = s.combo.saturating_add(1);
    s.max_combo = s.max_combo.max(u32::from(s.combo));
    s.send(MAIN_SKILL, 0x13, proto::action_skill_bt(character, &req, &hits, s.combo));
    for h in &hits {
        let max = s.monsters.iter().find(|m| m.actor == h.actor).map_or(h.hp.max(1), |m| m.max_hp);
        s.send(MAIN_MONSTER, 0x12, proto::monster_stat(h.actor, h.hp, max));
    }
    let struck: Vec<u32> = hits.iter().map(|h| h.actor).collect();
    crate::maze::monsters_hit(s, &struck);
    if dead.is_empty() {
        return;
    }
    s.kills += dead.len() as u32;
    let fallen: Vec<(u32, [f32; 3])> = s.monsters.iter().filter(|m| m.hp <= 0).map(|m| (m.id, m.pos)).collect();
    let boxes: Vec<u32> = s.monsters.iter().filter(|m| m.hp <= 0).map(|m| m.spawn_box).collect();
    s.dead_boxes.extend(boxes);
    s.monsters.retain(|m| m.hp > 0);
    let mut gained = 0u32;
    for (actor, lv, rank) in dead {
        s.send(MAIN_MONSTER, 0x11, proto::monster_die(actor));
        gained += proto::kill_exp(lv, rank);
    }
    for (monster, pos) in fallen {
        drop_loot(s, monster, pos);
    }
    let (new_level, new_exp) = proto::add_exp(level, exp, gained);
    let _ = s.shared.db.lock().unwrap().set_level_exp(character, new_level, new_exp);
    info!(conn = s.id, character, gained, level = new_level, exp = new_exp, "monsters killed");
    s.send(MAIN_CHARACTER, 0x37, proto::character_exp(new_exp, gained));
    if new_level != level {
        crate::maze::level_up(s, character, new_level);
    }
    crate::maze::after_kills(s);
}

/// GM /killall: every live monster dies with loot and EXP (sector flow test).
fn kill_all(s: &mut Session, character: u32) {
    let (level, exp) = s.shared.db.lock().unwrap().level_exp(character).unwrap_or((1, 0));
    let fallen: Vec<(u32, u8, u8, u32, [f32; 3])> =
        s.monsters.iter().filter(|m| m.hp > 0).map(|m| (m.actor, m.level, m.rank, m.id, m.pos)).collect();
    let boxes: Vec<u32> = s.monsters.iter().map(|m| m.spawn_box).collect();
    s.dead_boxes.extend(boxes);
    s.monsters.clear();
    s.kills += fallen.len() as u32;
    let mut gained = 0u32;
    for &(actor, lv, rank, _, _) in &fallen {
        s.send(MAIN_MONSTER, 0x11, proto::monster_die(actor));
        gained += proto::kill_exp(lv, rank);
    }
    for &(_, _, _, id, pos) in &fallen {
        drop_loot(s, id, pos);
    }
    let (new_level, new_exp) = proto::add_exp(level, exp, gained);
    let _ = s.shared.db.lock().unwrap().set_level_exp(character, new_level, new_exp);
    s.send(MAIN_CHARACTER, 0x37, proto::character_exp(new_exp, gained));
    if new_level != level {
        crate::maze::level_up(s, character, new_level);
    }
    gm_say(s, character, &format!("killed {} monsters", fallen.len()));
    crate::maze::after_kills(s);
}

fn next_rand(s: &mut Session) -> u64 {
    // xorshift64*
    let mut x = s.rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    s.rng = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

/// Drops for a killed monster (DROP_INFOS 20/0x01), kept until picked up.
fn drop_loot(s: &mut Session, monster: u32, pos: [f32; 3]) {
    let mut st = s.rng;
    let mut rand = |lo: u32, hi: u32| {
        st ^= st >> 12;
        st ^= st << 25;
        st ^= st >> 27;
        let v = st.wrapping_mul(0x2545_F491_4F6C_DD1D);
        lo + (v >> 33) as u32 % (hi.saturating_sub(lo) + 1)
    };
    let base = next_rand(s);
    let mut k = 0u64;
    let mut serial = || {
        k += 1;
        (base & 0x7FFF_FFFF_0000_0000) | k
    };
    let drops = proto::roll_drops(monster, pos, &mut rand, &mut serial);
    s.rng = st | 1;
    if drops.is_empty() {
        return;
    }
    s.drop_group += 1;
    let group = s.drop_group;
    info!(conn = s.id, monster, group, drops = drops.len(), "monster drops");
    s.send(MAIN_DROP, 0x01, proto::drop_infos(group, &drops));
    s.drops.extend(drops.into_iter().map(|d| (group, d)));
}

/// DROP_PICK_UP 20/0x02: Zenny goes to the wallet (8/0x20), items into
/// their home bag (8/0x15). A full bag leaves the item on the ground.
fn pick_up(s: &mut Session, group: u32, serial: u64) {
    let Some(character) = s.character_id else { return };
    let Some(i) = s.drops.iter().position(|(g, d)| d.serial == serial && (group == 0 || *g == group)) else {
        s.send(MAIN_DROP, 0x02, proto::pick_up_res(serial, 1));
        return;
    };
    let item = s.drops[i].1.clone();
    if matches!(item.item, proto::DROP_SOUL_VAPOR | proto::DROP_ETHER | proto::DROP_BP) {
        let db = s.shared.db.lock().unwrap();
        let total = db.add_currency(character, item.item, u64::from(item.count));
        drop(db);
        let Ok(total) = total else { return };
        s.drops.remove(i);
        s.send(MAIN_DROP, 0x02, proto::pick_up_res(serial, 0));
        match item.item {
            proto::DROP_ETHER => s.send(MAIN_ITEM, 0x32, proto::update_ether(total)),
            proto::DROP_BP => s.send(MAIN_ITEM, 0x31, proto::update_bp(character, total)),
            _ => {
                // Soul vapor fills the SV gauge (stat 0x10).
                let sv = (total.min(100)) as f32;
                s.send(MAIN_CHARACTER, 0x34, proto::stat_list(character, &[(proto::stat::SV_CUR, sv)]));
            }
        }
        info!(conn = s.id, character, item = item.item, count = item.count, total, "picked up currency");
        return;
    }
    if item.item == proto::DROP_ZENNY {
        let db = s.shared.db.lock().unwrap();
        let now = db.zenny(character, s.shared.cfg.start_zenny).unwrap_or(0);
        let total = now.saturating_add(u64::from(item.count));
        let ok = db.set_zenny(character, total).is_ok();
        drop(db);
        if ok {
            s.drops.remove(i);
            s.send(MAIN_DROP, 0x02, proto::pick_up_res(serial, 0));
            s.send(MAIN_ITEM, 0x20, proto::update_money(total));
        }
        return;
    }
    let st = proto::cash_item_storage(item.item);
    let count = item.count.min(u32::from(u16::MAX)) as u16;
    let added = s.shared.db.lock().unwrap().add_items(character, st, proto::storage_slots(st) as u16, &[(item.item, count)]);
    match added {
        Ok(Some(added)) => {
            s.drops.remove(i);
            info!(conn = s.id, character, item = item.item, count, storage = st, "picked up");
            s.send(MAIN_DROP, 0x02, proto::pick_up_res(serial, 0));
            s.send(MAIN_ITEM, 0x15, proto::item_update(&added));
        }
        Ok(None) => s.send(MAIN_DROP, 0x02, proto::pick_up_res(serial, 1)),
        Err(e) => warn!(conn = s.id, error = %e, "pick up: db error"),
    }
}

/// CHARACTER_GOBACK_LOBBY 3/0x60: menu "Select Character" / "Change
/// Character". The client reconnects to this game server with its login
/// session key, so the account's tickets are kept alive.
fn go_back_lobby(s: &mut Session, req: proto::GoBackLobbyReq) {
    let (Some(account), Some(character)) = (s.account_id, s.character_id) else { return };
    s.shared.refresh_tickets(account);
    let cfg = s.shared.cfg.clone();
    info!(conn = s.id, account, character, kind = req.kind, "back to the character select");
    s.send(MAIN_CHARACTER, 0x60, proto::goback_lobby_res(character, account, &cfg.public_ip, cfg.game_port, req.kind));
}

/// EXIT_MAZE_REQ 17/0x23 (leave a maze: menu or escape box): back to the
/// maze's escape point in its district (VMazeEscapeBox m_iField / m_iEvent-
/// Object, OpenWorker MazeService MazeExitRequest), else the town start.
fn exit_maze(s: &mut Session) {
    let (Some(account), Some(character)) = (s.account_id, s.character_id) else { return };
    let here = s.spot.unwrap_or_else(proto::start_spot);
    let back = proto::maze(here.map).and_then(|m| m.escape).unwrap_or_else(proto::start_spot);
    change_world(s, account, character, back);
}

/// ENTER_GAMESERVER_REQ 3/0x21: first packet on the world connection. The map
/// instance id from SELECT_CHARACTER_RES works once, for the same account and IP.
fn enter_gameserver(s: &mut Session, req: EnterGameServerReq) {
    if s.account_id.is_some() {
        warn!(conn = s.id, "ENTER_GAMESERVER_REQ on a connection that is already signed in; closing");
        s.close = true;
        return;
    }
    let Some((character, spot)) = s.shared.take_world_ticket(req.map_instance, req.account_id, s.peer.ip()) else {
        warn!(conn = s.id, account = req.account_id, "ENTER_GAMESERVER_REQ with an unknown or expired map instance");
        s.send(MAIN_CHARACTER, 0x22, proto::enter_gameserver_res(proto::MSG_LOGIN_FAILED, 0, 0));
        s.close = true;
        return;
    };
    s.account_id = Some(req.account_id);
    s.character_id = Some(character);
    s.map_instance = Some(req.map_instance);
    s.spot = Some(spot);
    info!(conn = s.id, account = req.account_id, character, map = spot.map, "entered world");
    s.send(MAIN_CHARACTER, 0x22, proto::enter_gameserver_res(0, spot.map, req.map_instance));
}

/// CHARACTER_INFO_REQ 3/0x31 on the world connection: the full player record
/// that LoginScene uses to switch to LoadingScene and place the player.
fn character_info(s: &mut Session, req: CharacterInfoReq) {
    let (Some(account), Some(character), Some(map_instance)) = (s.account_id, s.character_id, s.map_instance) else {
        warn!(conn = s.id, "CHARACTER_INFO_REQ before ENTER_GAMESERVER; closing");
        s.close = true;
        return;
    };
    if req.character_id != character {
        warn!(conn = s.id, account, asked = req.character_id, character, "CHARACTER_INFO_REQ for another character; closing");
        s.close = true;
        return;
    }
    let rows = s.shared.db.lock().unwrap().characters(account);
    let Some(c) = rows.ok().and_then(|rows| rows.into_iter().find(|c| c.id == character)) else {
        warn!(conn = s.id, account, character, "character vanished; closing");
        s.close = true;
        return;
    };
    let class = c.class;
    s.class = class;
    s.level = c.level;
    s.player_max_hp = proto::player_max_hp(class, c.level);
    s.player_hp = s.player_max_hp;
    s.dead = false;
    let row = character_row(s, c);
    let spot = s.spot.unwrap_or_else(proto::start_spot);
    s.player_pos = Some(spot.pos);
    crate::maze::reset(s);
    info!(conn = s.id, account, character, map = spot.map, "sending character info");
    let zenny = s.shared.db.lock().unwrap().zenny(character, s.shared.cfg.start_zenny).unwrap_or(0);
    s.send(MAIN_CHARACTER, 0x32, proto::character_info_res(&row, &spot, map_instance, zenny));
    // Quest state comes right after the character (OpenWorker PersonService);
    // the client spawns district NPCs only once these flags are set.
    s.send(MAIN_QUEST, 0x01, proto::quest_complete_list(&proto::default_completed_episodes()));
    s.send(MAIN_QUEST, 0x02, proto::quest_list_empty());
    // CHARACTER_INFO_RES only queues LoadingScene; 6/0x70 applies it.
    let st = skill_state(s, character, class);
    s.send(MAIN_SKILL, 0x70, proto::skill_load_full(character, &st));
}

/// Learned skills (class defaults until the first learn), points and decks.
fn skill_state(s: &mut Session, character: u32, class: u8) -> proto::SkillState {
    let db = s.shared.db.lock().unwrap();
    let level = db.level_exp(character).map_or(1, |l| l.0);
    let mut learned: Vec<(u32, u32)> = db.skills(character).unwrap_or_default().into_iter().map(|(_, s, d)| (s, d)).collect();
    let decks = db.skill_decks(character).unwrap_or_default();
    let (deck_slots, bonus) = db.deck_meta(character).unwrap_or((3, [0; 4]));
    drop(db);
    for &d in proto::class_skills(class) {
        let grp = proto::tree_row(d).map_or(d, |r| r.1);
        if !learned.iter().any(|(sk, _)| *sk == d || proto::tree_row(*sk).is_some_and(|r| r.1 == grp)) {
            learned.push((d, 0));
        }
    }
    let total = proto::skill_points_for(level);
    let spent: u16 = learned.iter().map(|(sk, _)| proto::skill_spent(*sk)).sum();
    proto::SkillState { skills: learned, total_sp: total, free_sp: total.saturating_sub(spent), deck_slots, decks, bonus }
}

/// Skill tree requests (OpenWorker SkillService rules, CSkillProcess
/// checks): learn 6/0x71, reset 6/0x72, deck 6/0x75, deck slot 6/0x76,
/// divergence 6/0x77, deck bonus 6/0x79.
fn skill_tree(s: &mut Session, sub: u8, p: &[u8]) {
    let Some(character) = s.character_id else { return };
    let class = s.class;
    let u32_at = |o: usize| p.get(o..o + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
    match sub {
        0x71 => {
            let (skill, div) = (u32_at(0), u32_at(4));
            let st = skill_state(s, character, class);
            let level = s.shared.db.lock().unwrap().level_exp(character).map_or(1, |l| l.0);
            match proto::learn_check(skill, class, level, st.free_sp, &st.skills) {
                None => {
                    let grp = proto::tree_row(skill).map_or(skill, |r| r.1);
                    let _ = s.shared.db.lock().unwrap().set_skill(character, grp, skill, div);
                    info!(conn = s.id, character, skill, "skill learned");
                    s.send(MAIN_SKILL, 0x71, proto::skill_learn_res(skill, div, true));
                    let st = skill_state(s, character, class);
                    s.send(MAIN_SKILL, 0x70, proto::skill_load_full(character, &st));
                }
                Some(why) => {
                    info!(conn = s.id, character, skill, why, "skill learn refused");
                    s.send(MAIN_SKILL, 0x71, proto::skill_learn_res(skill, div, false));
                }
            }
        }
        0x72 => {
            let _ = s.shared.db.lock().unwrap().clear_skills(character);
            let st = skill_state(s, character, class);
            info!(conn = s.id, character, free_sp = st.free_sp, "skills reset");
            s.send(MAIN_SKILL, 0x72, proto::skill_reset_res(character, &st));
        }
        0x75 => {
            let stored = match proto::parse_deck_update(p) {
                Some(decks) => {
                    let st = skill_state(s, character, class);
                    let known = |id: u32| id == 0 || st.skills.iter().any(|(sk, _)| *sk == id);
                    if decks.iter().all(|(_, d)| d.iter().all(|&id| known(id))) {
                        let db = s.shared.db.lock().unwrap();
                        for (pos, d) in &decks {
                            let _ = db.set_skill_deck(character, *pos, *d);
                        }
                        decks
                    } else {
                        Vec::new()
                    }
                }
                None => Vec::new(),
            };
            s.send(MAIN_SKILL, 0x75, proto::skill_update_deck_res(&stored));
        }
        0x76 => {
            let n = p.get(0..2).map_or(3, |b| u16::from_le_bytes([b[0], b[1]])).clamp(1, 6);
            let db = s.shared.db.lock().unwrap();
            let (_, bonus) = db.deck_meta(character).unwrap_or((3, [0; 4]));
            let _ = db.set_deck_meta(character, n, bonus);
            drop(db);
            s.send(MAIN_SKILL, 0x76, proto::skill_add_deck_slot_res(n));
        }
        0x77 => {
            let (skill, div) = (u32_at(0), u32_at(4));
            let st = skill_state(s, character, class);
            let ok = st.skills.iter().any(|(sk, _)| *sk == skill);
            if ok {
                let grp = proto::tree_row(skill).map_or(skill, |r| r.1);
                let _ = s.shared.db.lock().unwrap().set_skill(character, grp, skill, div);
            }
            s.send(MAIN_SKILL, 0x77, proto::skill_divergence_res(skill, div, ok));
        }
        0x79 => {
            let mut bonus = [0u16; 4];
            for (i, b) in bonus.iter_mut().enumerate() {
                *b = p.get(i * 2..i * 2 + 2).map_or(0, |x| u16::from_le_bytes([x[0], x[1]]));
            }
            let db = s.shared.db.lock().unwrap();
            let (slots, _) = db.deck_meta(character).unwrap_or((3, [0; 4]));
            let _ = db.set_deck_meta(character, slots, bonus);
            drop(db);
            s.send(MAIN_SKILL, 0x79, proto::skill_deck_bonus_res(true));
        }
        _ => {}
    }
}

/// The client finished loading the map (4/0x06). Gesture quick slots are filled
/// with the class's basic gestures.
fn world_loaded(s: &mut Session) {
    let (Some(account), Some(character)) = (s.account_id, s.character_id) else { return };
    let rows = s.shared.db.lock().unwrap().characters(account);
    let Some(class) = rows.ok().and_then(|r| r.into_iter().find(|c| c.id == character)).map(|c| c.class) else {
        return;
    };
    info!(conn = s.id, account, character, "world loaded; sending gesture slots and cash shop");
    s.send(MAIN_GESTURE, 0x02, proto::gesture_slot_load(class));
    // Stamina + speed: without ST the client cannot run (double-tap / dash).
    s.send(MAIN_CHARACTER, 0x51, proto::update_origin_stat(character, proto::STARTER_STATS));
    // Real max HP for the class and level (overrides the starter 1000).
    crate::maze::send_hp(s, character);
    let (ether, bp) = s.shared.db.lock().unwrap().currencies(character).unwrap_or((0, 0));
    s.send(MAIN_ITEM, 0x32, proto::update_ether(ether));
    s.send(MAIN_ITEM, 0x31, proto::update_bp(character, bp));
    // The cash shop must be loaded before the player opens it: CashShopUI_cl::
    // SetVisible (FUN_180749fe0) draws the shop in the same frame (FUN_18074c100
    // -> FUN_180752d50 indexes the tab list filled by the 9/0x20 handler), so a
    // reply to the click arrives too late and the client crashes (dump 16:00:47,
    // AV at 0x180753356). Sending it here sets the "loaded" flag (CashShop+0xf0).
    send_cash_shop(s);
}

/// Whole tb_CashShop catalogue (paged 9/0x20) + banners + the cash balance.
fn send_cash_shop(s: &mut Session) {
    for page in proto::shop_cash_load_pages(crate::gamedata::CASH_SHOP) {
        s.send(MAIN_SHOP, 0x20, page);
    }
    s.send(MAIN_SHOP, 0x28, proto::shop_banner_load_empty());
    send_cash_balance(s);
}

/// Deliver bought products into the character's bags (costume or cash bag,
/// lowest free slot) and charge the account, then resend inventory + balance.
/// The chosen option picks one tb_CashBilling_Info entry (item, count, price).
fn cash_buy(s: &mut Session, character: u32, req: &proto::CashBuyReq) {
    let Some(account) = s.account_id else { return };
    let (unlimited, start) = (s.shared.cfg.unlimited_cash, s.shared.cfg.start_cash);
    let mut delivered = Vec::new();
    for &(shop_id, option, qty) in &req.items {
        let Some(p) = crate::gamedata::CASH_SHOP.iter().find(|p| p.0 == shop_id) else {
            warn!(conn = s.id, shop_id, "cash shop buy: unknown product");
            continue;
        };
        let Some(&(item, count, _, price)) = p.4.get(option as usize).or(p.4.first()) else { continue };
        let qty = qty.clamp(1, 99);
        let total = price.saturating_mul(u32::from(qty));
        let storage = proto::cash_item_storage(item);
        let capacity = proto::storage_slots(storage) as u16;
        let items = vec![(item, count.max(1)); qty as usize];
        let db = s.shared.db.lock().unwrap();
        if !unlimited && db.cash(account, start).unwrap_or(0) < total {
            drop(db);
            warn!(conn = s.id, shop_id, total, "cash shop buy refused: not enough cash");
            continue;
        }
        let result = db.add_items(character, storage, capacity, &items);
        match result {
            Ok(Some(added)) => {
                if !unlimited {
                    let _ = db.spend_cash(account, total, start);
                }
                delivered.extend(added);
            }
            Ok(None) => warn!(conn = s.id, shop_id, storage, "cash shop buy: bag full"),
            Err(e) => warn!(conn = s.id, shop_id, error = %e, "cash shop buy: db error"),
        }
    }
    info!(conn = s.id, character, products = ?req.items, delivered = delivered.len(), "cash shop buy");
    s.send(MAIN_SHOP, 0x21, proto::cash_buy_res());
    send_inventory(s);
    send_cash_balance(s);
}

/// NPC shop purchase (9/0x01): the tb_Shop row decides item, count and price
/// (unit price 0 = the item's tb_Item Buy_Price). Only Zenny rows are sold.
fn shop_buy(s: &mut Session, character: u32, req: proto::ShopBuyReq) {
    let Some((_, item, per, unit)) = proto::npc_shop_row(req.index) else {
        warn!(conn = s.id, index = req.index, "shop buy: unknown or non-Zenny tb_Shop row");
        return;
    };
    let Some((_, buy_price, stack)) = proto::item_prices(item) else { return };
    let qty = req.count.clamp(1, 999);
    let unit = if unit > 0 { unit } else { buy_price };
    let storage = proto::cash_item_storage(item);
    let purchase = crate::db::ShopPurchase {
        item,
        count: per.max(1).saturating_mul(qty),
        stack,
        storage,
        capacity: proto::storage_slots(storage) as u16,
        cost: u64::from(unit) * u64::from(qty),
    };
    let start = s.shared.cfg.start_zenny;
    let outcome = s.shared.db.lock().unwrap().shop_buy(character, &purchase, start);
    match outcome {
        Ok(crate::db::ShopBuyOutcome::Bought { changed, balance }) => {
            info!(conn = s.id, character, index = req.index, item, count = purchase.count, cost = purchase.cost, balance, "shop buy");
            s.send(MAIN_SHOP, 0x01, proto::shop_buy_res(&changed, purchase.cost));
            s.send(MAIN_ITEM, 0x20, proto::update_money(balance));
        }
        Ok(o) => warn!(conn = s.id, character, index = req.index, outcome = ?o, "shop buy refused"),
        Err(e) => warn!(conn = s.id, error = %e, "shop buy: db error"),
    }
}

/// NPC shop sale (9/0x02): whole stacks for tb_Item Sell_Price each.
fn shop_sell(s: &mut Session, character: u32, req: &proto::ShopSellReq) {
    let start = s.shared.cfg.start_zenny;
    let price = |item| proto::item_prices(item).map_or(0, |p| u64::from(p.0));
    let result = s.shared.db.lock().unwrap().shop_sell(character, &req.slots, proto::sellable_storage, price, start);
    match result {
        Ok((sold, balance)) => {
            info!(conn = s.id, character, sold = sold.len(), balance, "shop sell");
            s.send(MAIN_SHOP, 0x02, proto::shop_sell_res(&sold));
            s.send(MAIN_ITEM, 0x20, proto::update_money(balance));
            send_buyback(s, character);
        }
        Err(e) => warn!(conn = s.id, error = %e, "shop sell: db error"),
    }
}

/// SHOP_REPURCHASER_LIST 9/0x03: the character's buyback list.
fn send_buyback(s: &mut Session, character: u32) {
    let list = s.shared.db.lock().unwrap().buyback(character).unwrap_or_default();
    s.send(MAIN_SHOP, 0x03, proto::shop_repurchaser_list(&list));
}

/// SHOP_REPURCHASER 9/0x04: buy a sold stack back for its sell price, into
/// the bag it was sold from. Refused = the list is sent again unchanged.
fn repurchase(s: &mut Session, character: u32, req: proto::RepurchaseReq) {
    let start = s.shared.cfg.start_zenny;
    let cap = |st: u8| proto::storage_slots(st).max(0) as u16;
    let result = s.shared.db.lock().unwrap().repurchase(character, req.serial, cap, start);
    match result {
        Ok(crate::db::RepurchaseOutcome::Bought { item, balance, price }) => {
            info!(conn = s.id, character, item = item.item_id, count = item.count, price, balance, "shop buyback");
            s.send(MAIN_SHOP, 0x04, proto::shop_repurchase_res(&item));
            s.send(MAIN_ITEM, 0x20, proto::update_money(balance));
        }
        Ok(o) => {
            warn!(conn = s.id, character, serial = req.serial, outcome = ?o, "shop buyback refused");
            send_buyback(s, character);
        }
        Err(e) => warn!(conn = s.id, error = %e, "shop buyback: db error"),
    }
}

/// Current contents of some slots as ITEM_UPDATE (refresh after a refusal;
/// 8/0x15 sets slots, it does not move anything).
fn refresh_slots(s: &mut Session, character: u32, slots: &[(u8, u16)]) {
    let items = s.shared.db.lock().unwrap().items(character).unwrap_or_default();
    let now: Vec<_> = items.into_iter().filter(|i| slots.contains(&(i.storage, i.slot))).collect();
    if !now.is_empty() {
        s.send(MAIN_ITEM, 0x15, proto::item_update(&now));
    }
}

/// ITEM_COMBINE 8/0x03: stack `count` of src onto the same item at dest.
fn combine_items(s: &mut Session, character: u32, req: proto::ItemCombineReq) {
    let items = s.shared.db.lock().unwrap().items(character).unwrap_or_default();
    let stack = items
        .iter()
        .find(|i| (i.storage, i.slot) == req.src)
        .and_then(|i| proto::item_prices(i.item_id))
        .map_or(1, |p| p.2.max(1));
    let result = s.shared.db.lock().unwrap().combine_items(character, req.src, req.dest, req.count, stack);
    match result {
        Ok(Some((a, b))) => {
            info!(conn = s.id, src = ?req.src, dest = ?req.dest, item = b.item_id, left = a.count, now = b.count, "item combine");
            s.send(MAIN_ITEM, 0x03, proto::item_combine_res(character, &a, &b));
        }
        Ok(None) => {
            warn!(conn = s.id, src = ?req.src, dest = ?req.dest, count = req.count, "item combine refused");
            refresh_slots(s, character, &[req.src, req.dest]);
        }
        Err(e) => warn!(conn = s.id, error = %e, "item combine: db error"),
    }
}

/// ITEM_DIVIDE 8/0x04: split a stack into an empty slot.
fn divide_item(s: &mut Session, character: u32, req: proto::ItemDivideReq) {
    let result = s.shared.db.lock().unwrap().divide_item(character, req.src, req.dest, req.count, proto::item_fits);
    match result {
        Ok(Some((a, b))) => {
            info!(conn = s.id, src = ?req.src, dest = ?req.dest, item = a.item_id, left = a.count, split = b.count, "item divide");
            s.send(MAIN_ITEM, 0x04, proto::item_divide_res(&a, &b));
        }
        Ok(None) => {
            warn!(conn = s.id, src = ?req.src, dest = ?req.dest, count = req.count, "item divide refused");
            refresh_slots(s, character, &[req.src]);
        }
        Err(e) => warn!(conn = s.id, error = %e, "item divide: db error"),
    }
}

/// ITEM_BREAK 8/0x05: throw an item (or part of a stack) away. Only bag
/// items: worn costumes and the soul weapon cannot be thrown away.
fn discard_item(s: &mut Session, character: u32, req: proto::ItemBreakReq) {
    if !proto::bag_storage(req.at.0) {
        warn!(conn = s.id, at = ?req.at, "item discard refused: not a bag slot");
        refresh_slots(s, character, &[req.at]);
        return;
    }
    let result = s.shared.db.lock().unwrap().discard_item(character, req.at, req.serial, req.count);
    match result {
        Ok(Some(left)) => {
            info!(conn = s.id, at = ?req.at, item = left.item_id, count = req.count, left = left.count, "item discard");
            if left.count == 0 {
                s.send(MAIN_ITEM, 0x05, proto::item_break_res(req.at.0, req.at.1, req.serial));
            } else {
                s.send(MAIN_ITEM, 0x15, proto::item_update(&[left]));
            }
        }
        Ok(None) => {
            warn!(conn = s.id, at = ?req.at, serial = req.serial, "item discard refused: no such item");
            refresh_slots(s, character, &[req.at]);
        }
        Err(e) => warn!(conn = s.id, error = %e, "item discard: db error"),
    }
}

/// ITEM_LINE_UP 8/0x25: the bag's sort button.
fn line_up(s: &mut Session, character: u32, st: u8) {
    if !proto::bag_storage(st) {
        warn!(conn = s.id, storage = st, "line up refused: not a bag");
        return;
    }
    let result = s.shared.db.lock().unwrap().line_up(character, st);
    match result {
        Ok(items) => {
            info!(conn = s.id, storage = st, items = items.len(), "item line up");
            s.send(MAIN_ITEM, 0x25, proto::item_line_up_res(st, &items));
        }
        Err(e) => warn!(conn = s.id, error = %e, "line up: db error"),
    }
}

/// ITEM_USE: boxes (tb_Item_Package) are swapped for their contents. Anything
/// else is answered with an empty use so the client does not wait.
fn use_item(s: &mut Session, character: u32, req: &proto::ItemUseReq) {
    let item_id = {
        let items = s.shared.db.lock().unwrap().items(character).unwrap_or_default();
        items.iter().find(|i| i.serial == req.serial).map(|i| i.item_id)
    };
    let Some(item_id) = item_id else {
        warn!(conn = s.id, serial = req.serial, storage = req.storage, slot = req.slot, "item use: not this character's item");
        return;
    };
    let Some(&(_, contents)) = crate::gamedata::ITEM_PACKAGE.iter().find(|p| p.0 == item_id) else {
        info!(conn = s.id, item_id, "item use: not a box (no effect implemented)");
        s.send(MAIN_ITEM, 0x11, proto::item_use_res(item_id, &[]));
        return;
    };
    let gain: Vec<(u32, u16, u8, u16)> = contents
        .iter()
        .map(|&(it, c)| {
            let st = proto::cash_item_storage(it);
            (it, c.clamp(1, u16::MAX as u32) as u16, st, proto::storage_slots(st) as u16)
        })
        .collect();
    let result = s.shared.db.lock().unwrap().use_item(character, req.serial, &gain);
    match result {
        Ok(Some((used, added))) => {
            info!(conn = s.id, item_id, opened = added.len(), "item use: box opened");
            let mut update = vec![used];
            update.extend(added.iter().copied());
            s.send(MAIN_ITEM, 0x15, proto::item_update(&update));
            let got: Vec<(u32, u16)> = added.iter().map(|i| (i.item_id, i.count)).collect();
            s.send(MAIN_ITEM, 0x11, proto::item_use_res(item_id, &got));
        }
        Ok(None) => warn!(conn = s.id, item_id, "item use: bag full"),
        Err(e) => warn!(conn = s.id, item_id, error = %e, "item use: db error"),
    }
}

/// ITEM_MOVE: drag between bag slots, equip (bag -> shape/look/gear slot) and
/// unequip. A done move is answered with what the two slots hold now; a
/// refused one with an empty reply (the client applies entries as moves).
fn move_item(s: &mut Session, character: u32, req: proto::ItemMoveReq) {
    let result =
        s.shared.db.lock().unwrap().move_item(character, req.src, req.dest, proto::item_fits, &[proto::WEAPON_SLOT]);
    let (src_item, dest_item) = match result {
        Ok((a, b, moved)) => {
            info!(conn = s.id, src = ?req.src, dest = ?req.dest, item = b.map(|i| i.item_id), moved, "item move");
            if !moved {
                s.send(MAIN_ITEM, 0x02, proto::item_move_refused());
                return;
            }
            (a, b)
        }
        Err(e) => {
            warn!(conn = s.id, error = %e, "item move: db error");
            s.send(MAIN_ITEM, 0x02, proto::item_move_refused());
            return;
        }
    };
    s.send(
        MAIN_ITEM,
        0x02,
        proto::item_move_res(
            (req.src.0, req.src.1, src_item.map(|i| i.item_id)),
            (req.dest.0, req.dest.1, dest_item.map(|i| i.item_id)),
        ),
    );
}

/// GM level of the session's account: 1 if its name is in cfg.gm_accounts.
fn gm_level(s: &Session) -> u8 {
    let Some(account) = s.account_id else { return 0 };
    let name = s.shared.db.lock().unwrap().account_name(account).ok().flatten().unwrap_or_default();
    u8::from(s.shared.cfg.gm_accounts.iter().any(|g| g.eq_ignore_ascii_case(&name)))
}

/// Answer a GM command in the speaker's chat window.
fn gm_say(s: &mut Session, character: u32, text: &str) {
    s.send(MAIN_CHAT, 0x01, proto::chat_normal(character, &proto::clean_chat(&format!("[GM] {text}"))));
}

/// CHAT_GM_COMMAND 7/0x0A. The client only sends these for a GM row, but the
/// server checks again: a modified client must not get GM powers.
fn gm_command(s: &mut Session, character: u32, line: &str) {
    if gm_level(s) == 0 {
        warn!(conn = s.id, character, line, "GM command from a non-GM account; ignored");
        return;
    }
    info!(conn = s.id, character, line, "GM command");
    match proto::parse_gm_line(line) {
        proto::GmCommand::Item { item, count } => {
            let st = proto::cash_item_storage(item);
            let added = s.shared.db.lock().unwrap().add_items(character, st, proto::storage_slots(st) as u16, &[(item, count)]);
            match added {
                Ok(Some(added)) => {
                    s.send(MAIN_ITEM, 0x15, proto::item_update(&added));
                    gm_say(s, character, &format!("item {item} x{count} -> bag {st}"));
                }
                Ok(None) => gm_say(s, character, "bag full"),
                Err(e) => {
                    warn!(conn = s.id, error = %e, "GM item: db error");
                    gm_say(s, character, "db error");
                }
            }
        }
        proto::GmCommand::Cash(n) => {
            if let Some(account) = s.account_id {
                let ok = s.shared.db.lock().unwrap().set_cash(account, n).is_ok();
                send_cash_balance(s);
                gm_say(s, character, if ok { "cash set" } else { "db error" });
            }
        }
        proto::GmCommand::MoveSpeed(rate) => {
            s.send(MAIN_CHARACTER, 0x51, proto::update_origin_stat(character, &[(proto::stat::MSR, rate)]));
            gm_say(s, character, &format!("move speed {rate}"));
        }
        proto::GmCommand::Level(n) => {
            let r = s.shared.db.lock().unwrap().set_level(character, n);
            match r {
                Ok(()) => {
                    crate::maze::level_up(s, character, n);
                    gm_say(s, character, &format!("level {n}"));
                }
                Err(e) => gm_say(s, character, &format!("db error: {e}")),
            }
        }
        proto::GmCommand::KillAll => kill_all(s, character),
        proto::GmCommand::Die => crate::maze::gm_die(s, character),
        proto::GmCommand::Heal => {
            if s.dead {
                // Dead: stand up in place (revive packet) instead of a full
                // HP bar on a corpse.
                crate::maze::revive(s, 0);
            } else {
                s.player_hp = s.player_max_hp;
                crate::maze::send_hp(s, character);
            }
            gm_say(s, character, "HP full");
        }
        proto::GmCommand::God => {
            s.god = !s.god;
            gm_say(s, character, if s.god { "god mode on" } else { "god mode off" });
        }
        proto::GmCommand::Help => {
            gm_say(s, character, "/item <id> [count], /cash <n>, /movespeed <rate>, /level <n>, /killall, /die, /heal, /god")
        }
        proto::GmCommand::Unknown(l) => gm_say(s, character, &format!("unknown or not yet supported: {l}")),
    }
}

fn send_inventory(s: &mut Session) {
    let Some(character) = s.character_id else { return };
    let items = s.shared.db.lock().unwrap().items(character).unwrap_or_default();
    s.send(MAIN_ITEM, 0x01, proto::inventory_info(&items));
}

fn send_cash_balance(s: &mut Session) {
    let cash = match s.account_id {
        _ if s.shared.cfg.unlimited_cash => proto::CASH_UNLIMITED,
        Some(account) => s.shared.db.lock().unwrap().cash(account, s.shared.cfg.start_cash).unwrap_or(0),
        None => 0,
    };
    s.send(MAIN_ITEM, 0x33, proto::update_cash(cash, 0, 0));
}

/// A stored character as the client's row: starter weapon and the costume
/// picked in the creator come from the client's tables (proto::starter_equipment).
fn character_row(s: &Session, c: crate::db::CharacterRecord) -> CharacterInfo {
    let (weapon, starter) = proto::starter_equipment(c.class, c.outfit);
    let mut worn_weapon = weapon;
    let mut shape = [0u32; proto::SHAPE_SLOTS];
    let mut shape_serial = [0u64; proto::SHAPE_SLOTS];
    let mut look = [(0u64, 0u32); proto::SHAPE_SLOTS];
    {
        let db = s.shared.db.lock().unwrap();
        let worn: Vec<(u16, u32)> =
            starter.iter().enumerate().filter(|&(_, &i)| i != 0).map(|(sl, &i)| (sl as u16, i)).collect();
        if let Err(e) = db.seed_equipment(c.id, &worn) {
            warn!(conn = s.id, character = c.id, error = %e, "seed equipment");
        }
        if let Err(e) = db.ensure_weapon(c.id, proto::WEAPON_SLOT, weapon) {
            warn!(conn = s.id, character = c.id, error = %e, "seed weapon");
        }
        for it in db.items(c.id).unwrap_or_default() {
            let slot = usize::from(it.slot);
            match it.storage {
                proto::storage::SHAPE_EQUIP if slot < proto::SHAPE_SLOTS => {
                    shape[slot] = it.item_id;
                    shape_serial[slot] = it.serial;
                }
                proto::storage::LOOK_EQUIP if slot < proto::SHAPE_SLOTS => look[slot] = (it.serial, it.item_id),
                st if (st, it.slot) == proto::WEAPON_SLOT => worn_weapon = it.item_id,
                _ => {}
            }
        }
    }
    CharacterInfo {
        id: c.id,
        name: c.name,
        class: c.class,
        level: c.level,
        appearance: c.appearance,
        class_ref: c.class_ref,
        slot: c.slot,
        weapon: worn_weapon,
        shape,
        shape_serial,
        look,
        gm_level: gm_level(s),
        ability: {
            let mut a = proto::STARTER_ABILITY;
            let hp = s.player_max_hp.clamp(1, i64::from(u32::MAX)) as u32;
            a[0] = (hp, hp);
            a
        },
        speed: proto::STARTER_SPEED,
        fp: proto::STARTER_FP,
    }
}

fn create_character(s: &mut Session, req: CreateCharacterReq) {
    let Some(account) = require_game(s) else { return };
    if !proto::valid_character_name(&req.name) {
        warn!(conn = s.id, name = %req.name, "CREATE_CHARACTER_REQ with invalid name");
        s.send(MAIN_CHARACTER, 0x57, proto::check_name(&req.name, true));
        return;
    }
    let new = NewCharacter {
        name: &req.name,
        class: req.class,
        appearance: req.appearance,
        class_ref: req.class_ref,
        outfit: req.outfit,
    };
    let outcome = s.shared.db.lock().unwrap().create_character(account, &new, req.slot, MAX_CHARACTER_SLOTS);
    match outcome {
        Ok(CreateOutcome::Created { id, slot }) => {
            info!(conn = s.id, account, id, slot, name = %req.name, class = req.class, "character created");
            send_character_list(s);
        }
        Ok(CreateOutcome::NameTaken) => {
            info!(conn = s.id, name = %req.name, "character name taken");
            s.send(MAIN_CHARACTER, 0x57, proto::check_name(&req.name, true));
        }
        Ok(CreateOutcome::NoFreeSlot) => {
            warn!(conn = s.id, account, "no free character slot");
            send_character_list(s);
        }
        Err(e) => {
            warn!(conn = s.id, "db: {e:#}");
            send_character_list(s);
        }
    }
}

fn delete_character(s: &mut Session, req: DeleteCharacterReq) {
    let Some(account) = require_game(s) else { return };
    match s.shared.db.lock().unwrap().delete_character(account, req.id) {
        Ok(true) => info!(conn = s.id, account, id = req.id, "character deleted"),
        Ok(false) => warn!(conn = s.id, account, id = req.id, "DELETE_CHARACTER_REQ for a character the account does not own"),
        Err(e) => warn!(conn = s.id, "db: {e:#}"),
    }
    s.send(MAIN_CHARACTER, 0x03, proto::delete_character_res());
    send_character_list(s);
}

fn login(s: &mut Session, req: LoginReq) {
    if s.account_id.is_some() {
        warn!(conn = s.id, "second LOGIN_REQ on an authenticated connection ignored");
        return;
    }
    let cfg = s.shared.cfg.clone();
    let outcome = s.shared.db.lock().unwrap().login_with_password(&req.user, req.password.expose(), cfg.auto_register);
    let account = match outcome {
        Ok(LoginOutcome::Ok(id)) => id,
        Ok(LoginOutcome::Registered(id)) => {
            info!(conn = s.id, user = %req.user, account = id, "account registered");
            id
        }
        Ok(LoginOutcome::WrongPassword | LoginOutcome::NoSuchAccount) => {
            s.login_failures += 1;
            warn!(conn = s.id, user = %req.user, failures = s.login_failures, "login failed");
            reply_login_error(s, LoginError::BadCredentials);
            if s.login_failures >= cfg.max_login_failures {
                warn!(conn = s.id, "too many failed logins; closing");
                s.close = true;
            }
            return;
        }
        Err(e) => {
            warn!(conn = s.id, "db: {e:#}");
            reply_login_error(s, LoginError::Rejected);
            return;
        }
    };
    let session = s.shared.issue_ticket(account);
    s.account_id = Some(account);
    info!(conn = s.id, user = %req.user, account, mac = %req.mac_text, ver = format!("0x{:X}", req.client_version), "login ok");
    let res = LoginResult { account_id: account, error: LoginError::Ok, message: "", auth_id: &req.user, session };
    s.send(LoginResult::MAIN, LoginResult::SUB, res.encode());
}

fn reply_login_error(s: &mut Session, error: LoginError) {
    let res = LoginResult { account_id: 0, error, message: "", auth_id: "", session: 0 };
    s.send(LoginResult::MAIN, LoginResult::SUB, res.encode());
}

fn send_server_list(s: &mut Session) {
    let cfg = s.shared.cfg.clone();
    // The "Character" counter on the server select card.
    let characters = match s.account_id {
        Some(account) => s.shared.db.lock().unwrap().characters(account).map_or(0, |r| r.len().min(255) as u8),
        None => 0,
    };
    let row = proto::ServerEntry {
        id: cfg.server_id,
        port: cfg.game_port,
        name: &cfg.server_name,
        host: &cfg.public_ip,
        load: 1,
        flags: 0,
        characters,
    };
    s.send(MAIN_LOGIN, 0x04, proto::server_list(&[row]));
}

fn enter_server(s: &mut Session, req: EnterServerReq) {
    let ok = req.server_id == s.shared.cfg.server_id && s.shared.check_ticket(req.session, req.account_id);
    if !ok {
        warn!(conn = s.id, account = req.account_id, server = req.server_id, "ENTER_SERVER_REQ with invalid ticket");
        s.send(MAIN_LOGIN, 0x14, proto::enter_server_res(1, req.account_id));
        s.close = true;
        return;
    }
    s.account_id = Some(req.account_id);
    s.session_key = Some(req.session);
    info!(conn = s.id, account = req.account_id, "entered game server");
    s.send(MAIN_LOGIN, 0x14, proto::enter_server_res(0, req.account_id));
}
