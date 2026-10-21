//! Per-connection loop: framed decode (wire::WireCodec), packet log, dispatch.

use crate::codec::hexdump;
use crate::config::Config;
use crate::wire::{Header, Outgoing, Packet, SendPolicy, WireCodec};
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Login,
    Game,
}

/// Silence allowed before the first packet. The client opens the login
/// connection as soon as the login screen loads (FUN_180b05fe0 -> FUN_18005c560)
/// but sends LOGIN_REQ only after the player types ID/password, so the login
/// port must wait; the game port gets ENTER_SERVER_REQ immediately on connect.
const LOGIN_FIRST_PACKET_SECS: u64 = 30 * 60;
const GAME_FIRST_PACKET_SECS: u64 = 30;
/// Idle timeout once the connection is established. The 2.3.34.7 client sends
/// nothing unprompted (its KEEP_ALIVE is only a reply, FUN_180deca80), so a
/// player resting on a menu must not be dropped.
const IDLE_SECS: u64 = 60 * 60;
/// Largest frame a client may send (its biggest login packet is ~4.5 KiB).
const MAX_CLIENT_FRAME: usize = 16 * 1024;

/// C->S opcodes whose payload carries credentials or tokens; never hexdumped.
/// 3/0x17 SECOND_PASSWORD and 3/0x18 TRADE_PASSWORD carry the PIN as text.
const REDACTED_C2S: &[(u8, u8)] = &[(2, 0x01), (2, 0x07), (2, 0x08), (2, 0x22), (2, 0x23), (3, 0x17), (3, 0x18)];

struct Ticket {
    account: u32,
    expires: Instant,
}

/// One-shot pass from SELECT_CHARACTER_RES to the world connection's
/// ENTER_GAMESERVER_REQ, keyed by the map instance id (UXMapID) the server put
/// in SELECT_CHARACTER_RES; the client echoes it back (app +0x104b8).
struct WorldTicket {
    account: u32,
    character: u32,
    peer: IpAddr,
    spot: crate::proto::Spot,
    expires: Instant,
}

/// The world connection must arrive within this time after SELECT_CHARACTER_RES.
const WORLD_TICKET_SECS: u64 = 120;

pub struct Shared {
    pub cfg: Arc<Config>,
    packet_log: Mutex<std::fs::File>,
    next_conn: AtomicU32,
    pub db: Mutex<crate::db::Db>,
    tickets: Mutex<HashMap<u64, Ticket>>,
    world_tickets: Mutex<HashMap<u64, WorldTicket>>,
}

impl Shared {
    pub fn new(cfg: Arc<Config>) -> Result<Self> {
        let path = std::path::Path::new(&cfg.log_dir).join("packets.log");
        let f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        let db = crate::db::Db::open(&cfg.db_path)?;
        Ok(Self {
            cfg,
            packet_log: Mutex::new(f),
            next_conn: AtomicU32::new(1),
            db: Mutex::new(db),
            tickets: Mutex::new(HashMap::new()),
            world_tickets: Mutex::new(HashMap::new()),
        })
    }

    /// Map instance id for the world connection (UXMapID bitfield, see
    /// proto::map_instance_id) with a random 24-bit sequence, remembered for
    /// one ENTER_GAMESERVER_REQ from the same account and IP.
    pub fn issue_world_ticket(&self, account: u32, character: u32, peer: IpAddr, spot: crate::proto::Spot, server: u16) -> u64 {
        let now = Instant::now();
        let mut t = self.world_tickets.lock().unwrap();
        t.retain(|_, v| v.expires > now);
        loop {
            let mut b = [0u8; 4];
            getrandom::getrandom(&mut b).expect("OS RNG");
            let seq = u32::from_le_bytes(b) & 0x00FF_FFFF;
            let key = crate::proto::map_instance_id(seq.max(1), 1, spot.map, server);
            if let std::collections::hash_map::Entry::Vacant(e) = t.entry(key) {
                e.insert(WorldTicket { account, character, peer, spot, expires: now + Duration::from_secs(WORLD_TICKET_SECS) });
                return key;
            }
        }
    }

    /// Single use: the ticket is removed whether or not it matches.
    pub fn take_world_ticket(&self, key: u64, account: u32, peer: IpAddr) -> Option<(u32, crate::proto::Spot)> {
        let v = self.world_tickets.lock().unwrap().remove(&key)?;
        (v.account == account && v.peer == peer && v.expires > Instant::now()).then_some((v.character, v.spot))
    }

    /// Random 64-bit ticket the client carries from the login server to the game
    /// server (LOGIN_RESULT session -> ENTER_SERVER_REQ / CHARACTER_LIST_REQ).
    pub fn issue_ticket(&self, account: u32) -> u64 {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).expect("OS RNG");
        let key = u64::from_le_bytes(b) | 1;
        let ttl = Duration::from_secs(self.cfg.session_ttl_secs);
        let mut t = self.tickets.lock().unwrap();
        let now = Instant::now();
        t.retain(|_, v| v.expires > now);
        t.insert(key, Ticket { account, expires: now + ttl });
        key
    }

    /// Keep an account's login tickets alive (the client reuses its session
    /// key when it goes back to the character select from the world).
    pub fn refresh_tickets(&self, account: u32) {
        let ttl = Duration::from_secs(self.cfg.session_ttl_secs);
        let until = Instant::now() + ttl;
        for v in self.tickets.lock().unwrap().values_mut().filter(|v| v.account == account) {
            v.expires = until;
        }
    }

    pub fn check_ticket(&self, key: u64, account: u32) -> bool {
        let t = self.tickets.lock().unwrap();
        matches!(t.get(&key), Some(v) if v.account == account && v.expires > Instant::now())
    }

    pub fn log_packet(&self, conn: u32, role: Role, dir: &str, main: u8, sub: u8, header: Option<&Header>, payload: &[u8]) {
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let hdr = header
            .map(|h| format!(" mode={} key={} seq={} flag={}", h.mode, h.key, h.seq, h.flag))
            .unwrap_or_default();
        let body = if dir == "C->S" && REDACTED_C2S.contains(&(main, sub)) {
            format!("  <{} bytes redacted: credentials>\n", payload.len())
        } else {
            hexdump(payload)
        };
        let line = format!(
            "[{}.{:03}] #{conn} {role:?} {dir} op=0x{:04X} (main={main} sub=0x{sub:02X}){hdr} len={}\n{body}",
            ts.as_secs(),
            ts.subsec_millis(),
            u16::from(main) << 8 | u16::from(sub),
            payload.len(),
        );
        if let Ok(mut file) = self.packet_log.lock() {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

pub struct Session {
    pub id: u32,
    pub role: Role,
    pub peer: SocketAddr,
    pub shared: Arc<Shared>,
    out: Vec<Outgoing>,
    pub account_id: Option<u32>,
    /// Ticket accepted on the game connection.
    pub session_key: Option<u64>,
    pub login_failures: u32,
    /// Second password entered correctly (or skipped while none is set) on this connection.
    pub second_pw_unlocked: bool,
    pub second_pw_failures: u32,
    /// Character this connection entered the world with (after ENTER_GAMESERVER_REQ).
    pub character_id: Option<u32>,
    /// Map instance accepted by ENTER_GAMESERVER_REQ.
    pub map_instance: Option<u64>,
    /// Map and position this world connection entered at (from the ticket).
    pub spot: Option<crate::proto::Spot>,
    /// Monsters alive in this connection's maze instance (single player).
    pub monsters: Vec<crate::proto::Monster>,
    /// Last actor id handed out to a monster.
    pub monster_seq: u32,
    /// Targets of the next skill hit (PRE_TARGET_LIST 6/0x36).
    pub pre_targets: Vec<u32>,
    /// Hits in a row (continuous hit counter shown by the client).
    pub combo: u16,
    /// Items lying on the ground in this maze instance: (drop group, item).
    pub drops: Vec<(u32, crate::proto::GroundItem)>,
    pub drop_group: u32,
    /// Game RNG state (drops, damage rolls).
    pub rng: u64,
    /// Maze instance state (maze.rs): boxes already spawned, cleared
    /// sectors, open portals, clear flag, kill / combo counters.
    pub spawned_boxes: Vec<u32>,
    pub cleared_sectors: Vec<u32>,
    pub enabled_portals: Vec<u32>,
    pub maze_done: bool,
    pub kills: u32,
    pub max_combo: u32,
    pub maze_started_ms: u64,
    /// Player state the server tracks for combat.
    pub class: u8,
    pub level: u8,
    pub player_hp: i64,
    pub player_max_hp: i64,
    /// Stamina (dash / evade) and soul gauge: current, max, regen per second
    /// (tb_Status Con_ST_First_Value / Con_ST_Reg, CGocAttribute::OnUpdate).
    pub stamina: f32,
    pub stamina_max: f32,
    pub stamina_reg: f32,
    pub sg: f32,
    pub sg_max: f32,
    pub last_regen_ms: u64,
    /// Spawn boxes whose monster died (17/0x68 on reload) and revives used.
    pub dead_boxes: Vec<u32>,
    /// Current spawn step per sector (CSector m_nNowStepSpawn, 1-based).
    pub sector_steps: Vec<(u32, u8)>,
    pub revives: u8,
    pub dead: bool,
    /// GM /god: no HP loss.
    pub god: bool,
    pub player_pos: Option<[f32; 3]>,
    pub last_ai_ms: u64,
    pub clock: Instant,
    /// Set by a handler to drop the connection after flushing replies.
    pub close: bool,
}

impl Session {
    pub fn send(&mut self, main: u8, sub: u8, payload: Vec<u8>) {
        self.shared.log_packet(self.id, self.role, "S->C", main, sub, None, &payload);
        self.out.push(Outgoing::new(main, sub, payload));
    }
}

/// Only machines on the local network may connect (the server has no internet hardening yet).
pub fn peer_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_private() || v4.is_loopback()),
    }
}

pub async fn run(shared: Arc<Shared>, role: Role, sock: TcpStream, peer: SocketAddr) -> Result<()> {
    if !peer_allowed(peer.ip()) {
        warn!(?role, %peer, "refused non-LAN connection");
        return Ok(());
    }
    sock.set_nodelay(true).ok();
    let id = shared.next_conn.fetch_add(1, Ordering::Relaxed);
    info!(conn = id, ?role, %peer, "connected");
    let mut s = Session {
        id,
        role,
        peer,
        shared: shared.clone(),
        out: Vec::new(),
        account_id: None,
        session_key: None,
        login_failures: 0,
        second_pw_unlocked: false,
        second_pw_failures: 0,
        character_id: None,
        map_instance: None,
        spot: None,
        monsters: Vec::new(),
        monster_seq: 0,
        pre_targets: Vec::new(),
        combo: 0,
        drops: Vec::new(),
        drop_group: 0,
        rng: {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).expect("OS RNG");
            u64::from_le_bytes(b) | 1
        },
        close: false,
        spawned_boxes: Vec::new(),
        cleared_sectors: Vec::new(),
        enabled_portals: Vec::new(),
        maze_done: false,
        kills: 0,
        max_combo: 0,
        maze_started_ms: 0,
        class: 1,
        level: 1,
        player_hp: 1000,
        player_max_hp: 1000,
        stamina: 100.0,
        stamina_max: 100.0,
        stamina_reg: 5.0,
        sg: 100.0,
        sg_max: 100.0,
        last_regen_ms: 0,
        dead_boxes: Vec::new(),
        sector_steps: Vec::new(),
        revives: 0,
        dead: false,
            god: false,
        player_pos: None,
        last_ai_ms: 0,
        clock: Instant::now(),
    };
    // The client starts in mode 1 and refuses plaintext from then on, so the
    // server always answers encrypted (XOR, like the client's own default).
    let codec = WireCodec::new(SendPolicy { random_padding: true, ..SendPolicy::default() }).with_max_frame(MAX_CLIENT_FRAME);
    let mut framed = Framed::new(sock, codec);

    let first = Duration::from_secs(match role {
        Role::Login => LOGIN_FIRST_PACKET_SECS,
        Role::Game => GAME_FIRST_PACKET_SECS,
    });
    let mut deadline = tokio::time::Instant::now() + first;
    // Maze AI tick (monsters chase / attack the player between packets).
    let mut ai = tokio::time::interval(Duration::from_millis(200));
    ai.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            next = framed.next() => {
                deadline = tokio::time::Instant::now() + Duration::from_secs(IDLE_SECS);
                match next {
                    None => {
                        info!(conn = id, "disconnected");
                        return Ok(());
                    }
                    Some(Err(e)) => {
                        // The stream cannot be resynchronised after a bad frame: close it.
                        warn!(conn = id, "protocol error, closing connection: {e}");
                        return Ok(());
                    }
                    Some(Ok(pkt)) => handle(&mut s, &pkt),
                }
            }
            _ = ai.tick() => {
                if role == Role::Game {
                    crate::maze::tick(&mut s);
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                info!(conn = id, "timed out");
                return Ok(());
            }
        }
        flush(&mut framed, &mut s).await?;
        if s.close {
            info!(conn = id, "closed by server");
            return Ok(());
        }
    }
}

fn handle(s: &mut Session, pkt: &Packet) {
    s.shared.log_packet(s.id, s.role, "C->S", pkt.main, pkt.sub, Some(&pkt.header), &pkt.payload);
    if let Err(e) = crate::handlers::dispatch(s, pkt) {
        warn!(conn = s.id, op = format!("0x{:04X}", pkt.opcode()), "bad packet, closing: {e:#}");
        s.close = true;
    }
}

async fn flush(framed: &mut Framed<TcpStream, WireCodec>, s: &mut Session) -> Result<()> {
    if s.out.is_empty() {
        return Ok(());
    }
    for pkt in s.out.drain(..) {
        framed.feed(pkt).await.context("encode")?;
    }
    framed.flush().await.context("write")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_lan_peers() {
        for ok in ["127.0.0.1", "192.168.1.20", "10.1.2.3", "172.16.0.9", "::1", "::ffff:192.168.0.2"] {
            assert!(peer_allowed(ok.parse().unwrap()), "{ok}");
        }
        for bad in ["8.8.8.8", "100.64.0.1", "2001:db8::1", "::ffff:1.1.1.1"] {
            assert!(!peer_allowed(bad.parse().unwrap()), "{bad}");
        }
    }
}
