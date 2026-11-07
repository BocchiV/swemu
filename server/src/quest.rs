//! Quest episodes (main 0x15) and story-maze clear tracking.
//!
//! Data: GB tb_Quest_Episode / tb_Quest_Condition (gamedata QUEST_EPISODES,
//! QUEST_CONDITIONS; layout in re/quest_data.py), monster quest groups from
//! tb_Monster, story mazes from tb_Maze_Info (MAZE_CLEAR_GROUPS).
//!
//! Rules follow the reference 2020 GameServer (CQuestProcess::ReqQuest*,
//! CGocQuest::AcceptQuest / UpdateConditionType / UpdateMazeCondition /
//! CompleteEpisode, CGocRecode::UpdateClearInfo) and OpenWorker's quest
//! module; packet layouts are the 2.3.34.7 client readers' (see proto.rs).
//! Progress the server sees itself: hunt conditions (type 3) on kills and
//! sector-clear conditions (type 10, target 9) when a maze sector clears.
//! Everything else (talk, move, collect ...) is reported by the client with
//! QUEST_EVENT_UPDATE 21/0x08.

use crate::db::QuestProgress;
use crate::gamedata;
use crate::handlers::{MAIN_CHARACTER, MAIN_ITEM, MAIN_MAZE, MAIN_QUEST};
use crate::proto::{self, QuestEntry, QuestReward, QUEST_CONDITION_SLOTS};
use crate::session::Session;
use std::collections::BTreeMap;
use tracing::{info, warn};

/// CGocQuest keeps at most this many episodes in progress (the client's
/// quest log has the same limit).
pub const MAX_ACTIVE: usize = 8;

/// Tutorial chain of classes 1-6 (tb_Quest_Episode Before_Episode chain
/// 100001..100017): "The Fall" .. "Unimagined", played in the tutorial maze
/// 21111 and then 21112 (Lilium Room).
pub const TUTORIAL_EPISODES: [u32; 9] = [100001, 100002, 100005, 100007, 100009, 100011, 100013, 100015, 100017];
/// First story episode of classes 1-6 ("15 Years").
pub const STARTER_EPISODE: u32 = 100020;
pub const TUTORIAL_MAZE_FALL: u16 = 21111;
pub const TUTORIAL_MAZE_LILIUM: u16 = 21112;

/// How a class starts (2020 tb_Character_Info Maze_ID / Character_Start_-
/// Quest_ID / Character_Skip_Quest_ID; GB 2.3.34.7 keeps only the maze, so the
/// later classes' chains come from the episodes that use their maze).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartChain {
    /// Tutorial episodes in order.
    pub tutorial: &'static [u32],
    /// First story episode after the tutorial.
    pub story: u32,
    /// The class's tutorial maze (tb_Character_Info Maze_ID).
    pub maze: u16,
    /// Town the story starts in and its start box (the maze's escape box).
    pub town: u16,
    pub town_box: u32,
}

const CHAIN_BASE: StartChain =
    StartChain { tutorial: &TUTORIAL_EPISODES, story: STARTER_EPISODE, maze: TUTORIAL_MAZE_FALL, town: 10003, town_box: 1000301 };
/// Chii (7) and Ephnel (8): "Destiny Again I/II" in 21113 / 21114, then "A
/// child called SoulWorker" (NPC 101194) in Candus City.
const CHAIN_CHII: StartChain = StartChain { tutorial: &[570005, 570007], story: 570010, maze: 21113, town: 10021, town_box: 1002101 };
const CHAIN_EPHNEL: StartChain = StartChain { maze: 21114, ..CHAIN_CHII };
/// Nabi (9) and Dhana (10): "Home in the East" in 21115 (T05_RESTROOM), then
/// "2nd Generation SoulWorker" (NPC 101532) in Tower of Lord.
const CHAIN_NABI: StartChain = StartChain { tutorial: &[800005], story: 800010, maze: 21115, town: 10071, town_box: 1007101 };

pub fn start_chain(class: u8) -> StartChain {
    match class {
        7 => CHAIN_CHII,
        8 => CHAIN_EPHNEL,
        9 | 10 => CHAIN_NABI,
        _ => CHAIN_BASE,
    }
}

const CHAINS: [StartChain; 4] = [CHAIN_BASE, CHAIN_CHII, CHAIN_EPHNEL, CHAIN_NABI];

/// Any class's tutorial episode?
pub fn is_tutorial(ep: u32) -> bool {
    CHAINS.iter().any(|c| c.tutorial.contains(&ep))
}

/// Map a tutorial episode is played on, for `class` (None = town).
pub fn tutorial_maze(class: u8, ep: u32) -> Option<u16> {
    let c = start_chain(class);
    if !c.tutorial.contains(&ep) {
        return None;
    }
    Some(match ep {
        100005..=100015 => TUTORIAL_MAZE_LILIUM,
        100017 => return None,
        _ => c.maze,
    })
}

/// Episode that follows `ep` in its tutorial chain (the last one leads to the
/// chain's first story episode).
pub fn next_in_chain(ep: u32) -> Option<u32> {
    CHAINS.iter().find_map(|c| {
        let i = c.tutorial.iter().position(|&e| e == ep)?;
        Some(c.tutorial.get(i + 1).copied().unwrap_or(c.story))
    })
}

/// Leaving the first tutorial maze continues in the second one.
pub fn tutorial_next_maze(map: u16) -> Option<u16> {
    (map == TUTORIAL_MAZE_FALL).then_some(TUTORIAL_MAZE_LILIUM)
}

/// Where a character enters the world on Game Start: a brand-new character
/// (`fresh` = level 1, no EXP, no quest at all) or one with a tutorial
/// episode in progress goes to that episode's tutorial maze; everyone else to
/// the town start.
pub fn login_map(class: u8, active: &[u32], done: &[u32], fresh: bool) -> Option<u16> {
    if active.is_empty() && done.is_empty() {
        return fresh.then_some(start_chain(class).maze);
    }
    active.iter().filter_map(|&ep| tutorial_maze(class, ep)).min()
}

/// The town a class's story starts in (its tutorial maze's escape point).
pub fn start_town(class: u8) -> proto::Spot {
    let c = start_chain(class);
    proto::district_exit(c.town, c.town_box).unwrap_or_else(proto::start_spot)
}

/// Condition types / targets (OpenWorker QuestConditionType / -Target).
const HUNT: u8 = 3;
const CLEAR: u8 = 10;
const TARGET_MONSTER: u8 = 1;
const TARGET_MAZE: u8 = 7;
const TARGET_MONSTER_GROUP: u8 = 8;
const TARGET_SECTOR: u8 = 9;

/// One tb_Quest_Episode row.
#[derive(Debug, Clone, Copy)]
pub struct Episode {
    pub id: u32,
    pub bit: u16,
    pub conditions: &'static [u32],
    pub exp: u32,
    pub zenny: u32,
    pub ether: u32,
    pub bp: u32,
    pub items: &'static [(u32, u32)],
}

pub fn episode(id: u32) -> Option<Episode> {
    let t = gamedata::QUEST_EPISODES;
    let i = t.binary_search_by_key(&id, |e| e.0).ok()?;
    let (id, bit, conditions, exp, zenny, ether, bp, items) = t[i];
    Some(Episode { id, bit, conditions, exp, zenny, ether, bp, items })
}

/// One tb_Quest_Condition row.
#[derive(Debug, Clone, Copy)]
pub struct Condition {
    pub id: u32,
    pub kind: u8,
    pub target_kind: u8,
    pub target: u32,
    count: u8,
    pub mazes: &'static [u16],
}

impl Condition {
    /// Steps needed (a count of 0 in the table means one step, like the 
    /// server's GetConditionMaxCount).
    pub fn needed(&self) -> u8 {
        self.count.max(1)
    }
}

pub fn condition(id: u32) -> Option<Condition> {
    let t = gamedata::QUEST_CONDITIONS;
    let i = t.binary_search_by_key(&id, |c| c.0).ok()?;
    let (id, kind, target_kind, target, count, mazes) = t[i];
    Some(Condition { id, kind, target_kind, target, count, mazes })
}

/// Episode completes by itself once its conditions are done (no finish NPC).
pub fn auto_finish(ep: u32) -> bool {
    gamedata::QUEST_AUTO_FINISH.binary_search(&ep).is_ok()
}

/// Episodes the game starts by itself when `ep` is completed.
pub fn auto_start_after(ep: u32) -> impl Iterator<Item = u32> {
    gamedata::QUEST_AUTO_START.iter().filter(move |e| e.0 == ep).map(|e| e.1)
}

/// Quest groups a monster's kill counts for (tb_Monster Quest_Group_1..5).
pub fn monster_groups(monster: u32) -> &'static [u32] {
    let t = gamedata::MONSTER_QUEST_GROUPS;
    t.binary_search_by_key(&monster, |m| m.0).map_or(&[], |i| t[i].1)
}

/// Something that happened in a maze that may advance a condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuestEvent {
    /// A monster died (tb_Monster id) on map `maze` (spawn key `key`).
    Kill { monster: u32, maze: u16, key: u16 },
    /// A maze sector was cleared.
    SectorClear { sector: u32, maze: u16, key: u16 },
}

fn in_maze(c: &Condition, maze: u16, key: u16) -> bool {
    c.mazes.is_empty() || c.mazes.contains(&maze) || c.mazes.contains(&key)
}

/// Does `ev` count one step for condition `c`? (CGocQuest::Update-
/// ConditionType: hunt by monster id, by quest group or any kill in a maze;
/// UpdateMazeCondition: sector clears.)
pub fn counts(c: &Condition, ev: QuestEvent) -> bool {
    match ev {
        QuestEvent::Kill { monster, maze, key } if c.kind == HUNT && in_maze(c, maze, key) => match c.target_kind {
            TARGET_MAZE => c.target == u32::from(maze) || c.target == u32::from(key),
            TARGET_MONSTER_GROUP => monster_groups(monster).contains(&c.target),
            TARGET_MONSTER => c.target == monster,
            _ => false,
        },
        QuestEvent::SectorClear { sector, maze, key } => {
            c.kind == CLEAR && c.target_kind == TARGET_SECTOR && c.target == sector && in_maze(c, maze, key)
        }
        _ => false,
    }
}

/// Condition slot of `cond` in an episode.
fn slot(ep: &Episode, cond: u32) -> Option<usize> {
    ep.conditions.iter().take(QUEST_CONDITION_SLOTS).position(|&c| c == cond)
}

/// Apply events to one quest; returns the (condition, new step) pairs that
/// changed (last value per condition).
pub fn apply(q: &mut QuestProgress, events: &[QuestEvent]) -> Vec<(u32, u8)> {
    let Some(ep) = episode(q.episode) else { return Vec::new() };
    if q.failed {
        return Vec::new();
    }
    let mut changed: Vec<(u32, u8)> = Vec::new();
    for (i, &cid) in ep.conditions.iter().take(QUEST_CONDITION_SLOTS).enumerate() {
        let Some(c) = condition(cid) else { continue };
        let n = events.iter().filter(|&&ev| counts(&c, ev)).count();
        if n == 0 || q.steps[i] >= c.needed() {
            continue;
        }
        let step = (usize::from(q.steps[i]) + n).min(usize::from(c.needed())) as u8;
        q.steps[i] = step;
        changed.push((c.id, step));
    }
    changed
}

/// QUEST_EVENT_UPDATE: the client reports a condition step (param > 0 = the
/// absolute count, else one more), capped at the condition's count.
pub fn event_update(q: &mut QuestProgress, cond: u32, param: i64) -> Option<(u32, u8)> {
    let ep = episode(q.episode)?;
    let i = slot(&ep, cond)?;
    let need = condition(cond).map_or(1, |c| c.needed());
    let old = q.steps[i];
    let new = if param > 0 { old.max(param.min(i64::from(need)) as u8) } else { old.saturating_add(1).min(need) };
    if new == old {
        return None;
    }
    q.steps[i] = new;
    Some((cond, new))
}

/// Finished condition slots as the QUEST_LIST mask (bit i = slot i done).
pub fn done_mask(q: &QuestProgress) -> u16 {
    let Some(ep) = episode(q.episode) else { return 0 };
    ep.conditions
        .iter()
        .take(QUEST_CONDITION_SLOTS)
        .enumerate()
        .filter(|&(i, &c)| condition(c).is_some_and(|c| q.steps[i] >= c.needed()))
        .fold(0, |m, (i, _)| m | 1 << i)
}

/// Every condition of the episode reached its count.
pub fn all_done(q: &QuestProgress) -> bool {
    episode(q.episode).is_some_and(|ep| {
        let n = ep.conditions.iter().take(QUEST_CONDITION_SLOTS).filter(|&&c| condition(c).is_some()).count();
        done_mask(q).count_ones() as usize == n
    })
}

pub fn entry(q: &QuestProgress) -> QuestEntry {
    let mut conditions = [(0u32, 0u8); QUEST_CONDITION_SLOTS];
    if let Some(ep) = episode(q.episode) {
        for (i, &c) in ep.conditions.iter().take(QUEST_CONDITION_SLOTS).enumerate() {
            conditions[i] = (c, q.steps[i]);
        }
    }
    QuestEntry { episode: q.episode, helper: q.helper, done_mask: done_mask(q), failed: q.failed, conditions }
}

/// QUEST_COMPLETE_LIST bits: completed episodes plus the NPC-gating episodes
/// that were always reported done before quests existed (keeps Trisha, Janice
/// and Eo visible).
pub fn completed_bits(done: &[u32]) -> [u8; proto::QUEST_COMPLETE_BYTES] {
    let bits = done.iter().filter_map(|&e| episode(e).map(|e| e.bit));
    proto::quest_complete_bits(bits.chain(gamedata::NPC_UNLOCK_EPISODES.iter().map(|e| e.1)))
}

/// Story mazes grouped by Maze_Group for MAZE_CLEAR_INFO.
pub fn clear_groups(cleared: impl IntoIterator<Item = u16>) -> Vec<(u32, Vec<u32>)> {
    let t = gamedata::MAZE_CLEAR_GROUPS;
    let mut groups: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for maze in cleared {
        if let Ok(i) = t.binary_search_by_key(&maze, |m| m.0) {
            let list = groups.entry(u32::from(t[i].1)).or_default();
            if !list.contains(&u32::from(maze)) {
                list.push(u32::from(maze));
            }
        }
    }
    groups.into_iter().collect()
}

// ---- session side -------------------------------------------------------

/// QUEST_COMPLETE_LIST 21/0x01 + QUEST_LIST 21/0x02 (the client spawns
/// district NPCs only once both arrived).
pub fn send_state(s: &mut Session, character: u32) {
    let db = s.shared.db.lock().unwrap();
    let done = db.completed_quests(character).unwrap_or_default();
    let active = db.quests(character).unwrap_or_default();
    drop(db);
    s.send(MAIN_QUEST, 0x01, proto::quest_complete_list(&completed_bits(&done)));
    let entries: Vec<QuestEntry> = active.iter().map(entry).collect();
    s.send(MAIN_QUEST, 0x02, proto::quest_list(&entries));
}

/// Episode a character of `class` should get now: the first tutorial
/// episode for a new (`fresh`) character, the next tutorial episode when the
/// chain was interrupted, else the chain's first story episode once the
/// tutorial is behind it (even with other episodes in progress, since NPC
/// offers depend on it).
pub fn next_episode(class: u8, active: &[u32], done: &[u32], fresh: bool) -> Option<u32> {
    let c = start_chain(class);
    if active.iter().any(|&e| is_tutorial(e)) {
        return None;
    }
    if active.is_empty() && done.is_empty() {
        return Some(if fresh { c.tutorial[0] } else { c.story });
    }
    if done.iter().any(|e| c.tutorial.contains(e)) {
        if let Some(&ep) = c.tutorial.iter().find(|e| !done.contains(e)) {
            return active.is_empty().then_some(ep);
        }
    }
    (!done.contains(&c.story) && !active.contains(&c.story)).then_some(c.story)
}

/// On CHARACTER_INFO: a character with no episode in progress gets the next
/// one (tutorial chain first, then the story; CompleteQuestForNewChar
/// gives the first episode to a new character).
pub fn ensure_started(s: &mut Session, character: u32) {
    let db = s.shared.db.lock().unwrap();
    if !s.shared.cfg.tutorial_start {
        // Tutorial off: the whole chain counts as done (NPC offers and the
        // story start depend on it) and a tutorial episode left from an
        // earlier start is closed.
        let active = db.quests(character).unwrap_or_default();
        // A tutorial episode of another class (characters started before the
        // per-class chains) is dropped too.
        for q in active.iter().filter(|q| is_tutorial(q.episode)) {
            let _ = db.delete_quest(character, q.episode);
        }
        for &ep in start_chain(s.class).tutorial {
            if let Err(e) = db.complete_quest(character, ep) {
                warn!(conn = s.id, character, episode = ep, error = %e, "quest: tutorial completion failed");
            }
        }
    }
    // Quests saved before the helper flag was set show in the tracker too.
    let mut quests = db.quests(character).unwrap_or_default();
    if !quests.is_empty() && quests.iter().all(|q| !q.helper) {
        for q in &mut quests {
            q.helper = true;
            let _ = db.save_quest(character, q);
        }
    }
    let active: Vec<u32> = quests.iter().map(|q| q.episode).collect();
    let done = db.completed_quests(character).unwrap_or_default();
    let fresh = s.shared.cfg.tutorial_start && db.level_exp(character).map_or(false, |le| le == (1, 0));
    let chain = start_chain(s.class);
    let Some(ep) = next_episode(s.class, &active, &done, fresh).filter(|&ep| episode(ep).is_some()) else { return };
    if ep == chain.story && done.is_empty() {
        // A character from before the quest system skips the tutorial.
        for &t in chain.tutorial {
            if let Err(e) = db.complete_quest(character, t) {
                warn!(conn = s.id, character, episode = t, error = %e, "quest: tutorial completion failed");
            }
        }
    }
    match db.save_quest(character, &QuestProgress::new(ep)) {
        Ok(()) => info!(conn = s.id, character, episode = ep, "quest: episode started"),
        Err(e) => warn!(conn = s.id, character, episode = ep, error = %e, "quest: starting episode failed"),
    }
}

/// On login: episodes without a finish NPC whose conditions were already
/// all done (e.g. saved before auto-finish existed) complete now.
pub fn finish_pending(s: &mut Session, character: u32) {
    let ready: Vec<u32> = s
        .shared
        .db
        .lock()
        .unwrap()
        .quests(character)
        .unwrap_or_default()
        .iter()
        .filter(|q| auto_finish(q.episode) && all_done(q))
        .map(|q| q.episode)
        .collect();
    for ep in ready {
        complete(s, character, ep, false);
    }
}

/// Game Start spot for a character of `class` (see login_map): its tutorial
/// maze while the tutorial runs, else None (the caller uses start_town).
pub fn login_spot(s: &Session, character: u32, class: u8) -> Option<proto::Spot> {
    if !s.shared.cfg.tutorial_start {
        return None;
    }
    let db = s.shared.db.lock().unwrap();
    let active: Vec<u32> = db.quests(character).unwrap_or_default().iter().map(|q| q.episode).collect();
    let done = db.completed_quests(character).unwrap_or_default();
    let fresh = s.shared.cfg.tutorial_start && db.level_exp(character).map_or(false, |le| le == (1, 0));
    drop(db);
    login_map(class, &active, &done, fresh).and_then(proto::maze).map(|m| m.start)
}

/// Quest requests 21/0x02..0x11 (client writers: OpenWorker Quest*Request).
pub fn request(s: &mut Session, sub: u8, p: &[u8]) {
    let Some(character) = s.character_id else { return };
    let u32_at = |o: usize| p.get(o..o + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
    match sub {
        0x02 => send_state(s, character),
        0x03 => accept(s, character, u32_at(0)),
        0x05 => {
            complete(s, character, u32_at(0), true);
        }
        0x06 => give_up(s, character, u32_at(0)),
        0x08 => match proto::QuestEventReq::parse(p) {
            Ok(req) => event(s, character, req),
            Err(e) => warn!(conn = s.id, error = %e, "quest event update: bad payload"),
        },
        0x09 => {
            if let Some((add, ep)) = proto::parse_quest_helper(p) {
                set_flag(s, character, ep, |q| q.helper = add);
                s.send(MAIN_QUEST, 0x09, proto::quest_helper_res(add, ep));
            }
        }
        0x11 => {
            let ep = u32_at(0);
            if set_flag(s, character, ep, |q| q.failed = true) {
                info!(conn = s.id, character, episode = ep, "quest failed");
                s.send(MAIN_QUEST, 0x11, proto::quest_episode_res(ep));
            }
        }
        _ => info!(conn = s.id, sub, "unhandled quest request"),
    }
}

/// Update one active quest; false if it is not active.
fn set_flag(s: &mut Session, character: u32, ep: u32, f: impl FnOnce(&mut QuestProgress)) -> bool {
    let db = s.shared.db.lock().unwrap();
    let Some(mut q) = db.quests(character).unwrap_or_default().into_iter().find(|q| q.episode == ep) else {
        return false;
    };
    f(&mut q);
    db.save_quest(character, &q).is_ok()
}

/// QUEST_ACCEPT 21/0x03 (u32 episode).
fn accept(s: &mut Session, character: u32, ep: u32) {
    if episode(ep).is_none() {
        warn!(conn = s.id, character, episode = ep, "quest accept: unknown episode");
        return;
    }
    let db = s.shared.db.lock().unwrap();
    let active = db.quests(character).unwrap_or_default();
    if active.iter().any(|q| q.episode == ep) {
        drop(db);
        s.send(MAIN_QUEST, 0x03, proto::quest_accept_res(ep, true));
        return;
    }
    if active.len() >= MAX_ACTIVE {
        drop(db);
        warn!(conn = s.id, character, episode = ep, "quest accept: too many active episodes");
        return;
    }
    let saved = db.save_quest(character, &QuestProgress::new(ep));
    drop(db);
    match saved {
        Ok(()) => {
            info!(conn = s.id, character, episode = ep, "quest accepted");
            s.send(MAIN_QUEST, 0x03, proto::quest_accept_res(ep, true));
            send_state(s, character);
        }
        Err(e) => warn!(conn = s.id, character, episode = ep, error = %e, "quest accept: db error"),
    }
}

/// QUEST_GIVE_UP 21/0x06 (u32 episode).
fn give_up(s: &mut Session, character: u32, ep: u32) {
    let removed = s.shared.db.lock().unwrap().delete_quest(character, ep);
    match removed {
        Ok(true) => {
            info!(conn = s.id, character, episode = ep, "quest given up");
            s.send(MAIN_QUEST, 0x06, proto::quest_episode_res(ep));
            send_state(s, character);
        }
        Ok(false) => {}
        Err(e) => warn!(conn = s.id, character, episode = ep, error = %e, "quest give up: db error"),
    }
}

/// QUEST_EVENT_UPDATE 21/0x08: client-side condition progress.
fn event(s: &mut Session, character: u32, req: proto::QuestEventReq) {
    let db = s.shared.db.lock().unwrap();
    let Some(mut q) = db.quests(character).unwrap_or_default().into_iter().find(|q| q.episode == req.episode) else {
        drop(db);
        info!(conn = s.id, character, episode = req.episode, "quest event update: episode not active");
        return;
    };
    let change = event_update(&mut q, req.condition, req.param);
    let saved = change.is_none() || db.save_quest(character, &q).is_ok();
    drop(db);
    if let (Some(c), true) = (change, saved) {
        info!(conn = s.id, character, episode = req.episode, condition = c.0, step = c.1, "quest condition update");
        s.send(MAIN_QUEST, 0x07, proto::quest_update(&[c]));
    }
    s.send(MAIN_QUEST, 0x08, Vec::new());
    if saved && auto_finish(req.episode) && all_done(&q) {
        complete(s, character, req.episode, false);
    }
}

/// Server-seen progress (kills, sector clears) for every active quest.
pub fn progress(s: &mut Session, events: &[QuestEvent]) {
    let Some(character) = s.character_id else { return };
    if events.is_empty() {
        return;
    }
    let db = s.shared.db.lock().unwrap();
    let mut changes = Vec::new();
    for mut q in db.quests(character).unwrap_or_default() {
        let c = apply(&mut q, events);
        if !c.is_empty() && db.save_quest(character, &q).is_ok() {
            changes.extend(c);
        }
    }
    let finished: Vec<u32> = db
        .quests(character)
        .unwrap_or_default()
        .iter()
        .filter(|q| auto_finish(q.episode) && all_done(q))
        .map(|q| q.episode)
        .collect();
    drop(db);
    if !changes.is_empty() {
        info!(conn = s.id, character, conditions = changes.len(), "quest conditions advanced");
        s.send(MAIN_QUEST, 0x07, proto::quest_update(&changes));
    }
    for ep in finished {
        complete(s, character, ep, false);
    }
}

/// Kills on the current map.
pub fn on_kills(s: &mut Session, monsters: &[u32]) {
    let Some(maze) = s.spot.map(|p| p.map) else { return };
    let key = proto::spawn_key(maze);
    let events: Vec<QuestEvent> = monsters.iter().map(|&monster| QuestEvent::Kill { monster, maze, key }).collect();
    progress(s, &events);
}

pub fn on_sector_clear(s: &mut Session, sector: u32) {
    let Some(maze) = s.spot.map(|p| p.map) else { return };
    progress(s, &[QuestEvent::SectorClear { sector, maze, key: proto::spawn_key(maze) }]);
}

/// QUEST_EPISODE_COMPLETE 21/0x05 (u32 episode, u32 select reward) and GM
/// /questcomplete: mark done, grant tb_Quest_Episode rewards (EXP x
/// exp_rate, Zenny, ether, BP, items), answer 21/0x05 and resend the quest
/// state. Like the contributor build and the client flow, the client decides
/// when an episode is finished; unfinished server-tracked conditions are
/// logged, not refused. Returns false for an unknown or already completed
/// episode.
pub fn complete(s: &mut Session, character: u32, ep: u32, from_client: bool) -> bool {
    let Some(e) = episode(ep) else {
        warn!(conn = s.id, character, episode = ep, "quest complete: unknown episode");
        return false;
    };
    let db = s.shared.db.lock().unwrap();
    if let Some(q) = db.quests(character).unwrap_or_default().into_iter().find(|q| q.episode == ep) {
        if !all_done(&q) {
            info!(conn = s.id, character, episode = ep, mask = done_mask(&q), "quest complete: conditions not all seen by the server");
        }
    }
    let first = match db.complete_quest(character, ep) {
        Ok(first) => first,
        Err(err) => {
            drop(db);
            warn!(conn = s.id, character, episode = ep, error = %err, "quest complete: db error");
            return false;
        }
    };
    drop(db);
    if !first {
        info!(conn = s.id, character, episode = ep, from_client, "quest complete: already completed");
        send_state(s, character);
        return false;
    }
    let reward = grant(s, character, &e);
    info!(conn = s.id, character, episode = e.id, exp = reward.exp, zenny = reward.zenny, ether = reward.ether, bp = reward.bp,
          items = reward.items.len(), "quest episode completed");
    s.send(MAIN_QUEST, 0x05, proto::quest_episode_complete_res(ep, &reward));
    send_state(s, character);
    // Next episodes the game starts by itself (tb_Quest_Episode Auto_Start)
    // and the tutorial chain's hand-over.
    let mut next: Vec<u32> = auto_start_after(ep).collect();
    next.extend(next_in_chain(ep));
    next.dedup();
    let done = s.shared.db.lock().unwrap().completed_quests(character).unwrap_or_default();
    for n in next {
        if !done.contains(&n) {
            accept(s, character, n);
        }
    }
    true
}

/// Pay out an episode's rewards and send the stat / wallet / bag updates.
fn grant(s: &mut Session, character: u32, e: &Episode) -> QuestReward {
    let exp = s.shared.cfg.scale_exp(e.exp);
    let start_zenny = s.shared.cfg.start_zenny;
    let mut reward = QuestReward { exp, zenny: e.zenny, bp: e.bp, ether: e.ether, items: Vec::new() };
    let db = s.shared.db.lock().unwrap();
    let (level, cur) = db.level_exp(character).unwrap_or((1, 0));
    let (new_level, new_exp) = proto::add_exp(level, cur, exp);
    if exp > 0 {
        let _ = db.set_level_exp(character, new_level, new_exp);
    }
    let zenny = (e.zenny > 0)
        .then(|| {
            let total = db.zenny(character, start_zenny).unwrap_or(0).saturating_add(u64::from(e.zenny));
            db.set_zenny(character, total).ok().map(|_| total)
        })
        .flatten();
    let ether = (e.ether > 0).then(|| db.add_currency(character, proto::DROP_ETHER, u64::from(e.ether)).ok()).flatten();
    let bp = (e.bp > 0).then(|| db.add_currency(character, proto::DROP_BP, u64::from(e.bp)).ok()).flatten();
    let mut added = Vec::new();
    for &(item, count) in e.items {
        if proto::item_class(item).is_none() {
            continue; // reward slots that are not tb_Item rows (e.g. ids 11..15)
        }
        let count = count.min(u32::from(u16::MAX)) as u16;
        let st = proto::cash_item_storage(item);
        match db.add_items(character, st, proto::storage_slots(st) as u16, &[(item, count)]) {
            Ok(Some(rows)) => {
                added.extend(rows);
                reward.items.push((item, count));
            }
            Ok(None) => warn!(conn = s.id, character, item, "quest reward: bag full"),
            Err(err) => warn!(conn = s.id, character, item, error = %err, "quest reward: db error"),
        }
    }
    drop(db);
    if exp > 0 {
        s.send(MAIN_CHARACTER, 0x37, proto::character_exp(new_exp, exp));
        if new_level != level {
            crate::maze::level_up(s, character, new_level);
        }
    }
    if let Some(total) = zenny {
        s.send(MAIN_ITEM, 0x20, proto::update_money(total));
    }
    if let Some(total) = ether {
        s.send(MAIN_ITEM, 0x32, proto::update_ether(total));
    }
    if let Some(total) = bp {
        s.send(MAIN_ITEM, 0x31, proto::update_bp(character, total));
    }
    if !added.is_empty() {
        s.send(MAIN_ITEM, 0x15, proto::item_update(&added));
    }
    reward
}

/// MAZE_CLEAR_INFO 17/0x64 with every cleared story maze (or all of them
/// with `unlock_all_mazes`), reset flag set: the full state.
pub fn send_clear_info(s: &mut Session, character: u32) {
    let cleared: Vec<u16> = if s.shared.cfg.unlock_all_mazes {
        gamedata::MAZE_CLEAR_GROUPS.iter().map(|m| m.0).collect()
    } else {
        s.shared.db.lock().unwrap().cleared_mazes(character).unwrap_or_default()
    };
    s.send(MAIN_MAZE, 0x64, proto::maze_clear_info(&clear_groups(cleared), character, true));
}

/// A maze was finished: remember it and send its group (CGocRecode::
/// UpdateClearInfo sends the updated group entry).
pub fn on_maze_cleared(s: &mut Session, character: u32, maze: u16) {
    let db = s.shared.db.lock().unwrap();
    if let Err(e) = db.mark_maze_cleared(character, maze) {
        drop(db);
        warn!(conn = s.id, character, maze, error = %e, "maze clear: db error");
        return;
    }
    let cleared = db.cleared_mazes(character).unwrap_or_default();
    drop(db);
    let Some(group) = clear_groups([maze]).first().map(|g| g.0) else { return };
    let groups: Vec<(u32, Vec<u32>)> = clear_groups(cleared).into_iter().filter(|g| g.0 == group).collect();
    s.send(MAIN_MAZE, 0x64, proto::maze_clear_info(&groups, character, false));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_cover_the_story_start() {
        let e = episode(STARTER_EPISODE).unwrap();
        assert_eq!(e.bit, 10);
        assert!(!e.conditions.is_empty());
        for ep in TUTORIAL_EPISODES {
            assert!(episode(ep).is_some(), "{ep}");
        }
        // NPC-gating episodes keep their client bits.
        for &(ep, bit, _) in gamedata::NPC_UNLOCK_EPISODES {
            assert_eq!(episode(ep).map(|e| e.bit), Some(bit));
        }
        assert!(gamedata::QUEST_EPISODES.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(gamedata::QUEST_CONDITIONS.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(gamedata::MONSTER_QUEST_GROUPS.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(gamedata::MAZE_CLEAR_GROUPS.windows(2).all(|w| w[0].0 < w[1].0));
    }

    /// An episode with a hunt-by-group condition (first in table order).
    fn group_hunt() -> (Episode, Condition) {
        gamedata::QUEST_EPISODES
            .iter()
            .filter_map(|e| episode(e.0))
            .find_map(|e| {
                let c = condition(*e.conditions.first()?)?;
                (c.kind == HUNT && c.target_kind == TARGET_MONSTER_GROUP && c.needed() > 1 && !c.mazes.is_empty()).then_some((e, c))
            })
            .unwrap()
    }

    #[test]
    fn kills_advance_hunt_conditions_in_their_maze_only() {
        let (e, c) = group_hunt();
        let monster = gamedata::MONSTER_QUEST_GROUPS.iter().find(|m| m.1.contains(&c.target)).unwrap().0;
        let maze = c.mazes[0];
        let mut q = QuestProgress::new(e.id);
        let elsewhere = QuestEvent::Kill { monster, maze: 1, key: 1 };
        assert!(apply(&mut q, &[elsewhere]).is_empty(), "kills outside the condition's mazes do not count");
        let kill = QuestEvent::Kill { monster, maze, key: maze };
        assert_eq!(apply(&mut q, &[kill]), [(c.id, 1)]);
        let many = vec![kill; 300];
        assert_eq!(apply(&mut q, &many), [(c.id, c.needed())], "capped at the count");
        assert!(apply(&mut q, &[kill]).is_empty(), "a finished condition stays put");
        assert_eq!(done_mask(&q) & 1, 1);
        q.failed = true;
        q.steps[0] = 0;
        assert!(apply(&mut q, &[kill]).is_empty(), "failed quests do not progress");
    }

    #[test]
    fn sector_clears_advance_clear_conditions() {
        // 1000111: clear sector 10007 of maze 21112 (tb_Quest_Condition).
        let c = condition(1000111).unwrap();
        assert_eq!((c.kind, c.target_kind, c.target, c.mazes), (CLEAR, TARGET_SECTOR, 10007, &[21112u16][..]));
        assert!(counts(&c, QuestEvent::SectorClear { sector: 10007, maze: 21112, key: 21112 }));
        assert!(!counts(&c, QuestEvent::SectorClear { sector: 10007, maze: 21111, key: 21111 }));
        assert!(!counts(&c, QuestEvent::SectorClear { sector: 10006, maze: 21112, key: 21112 }));
        assert!(!counts(&c, QuestEvent::Kill { monster: 10007, maze: 21112, key: 21112 }));
    }

    #[test]
    fn client_event_updates_are_capped() {
        let e = episode(STARTER_EPISODE).unwrap();
        let cond = e.conditions[0];
        let need = condition(cond).unwrap().needed();
        let mut q = QuestProgress::new(e.id);
        assert_eq!(event_update(&mut q, cond, 0), Some((cond, 1)));
        assert_eq!(event_update(&mut q, cond, 99), if need > 1 { Some((cond, need)) } else { None });
        assert_eq!(event_update(&mut q, cond, 0), None);
        assert_eq!(event_update(&mut q, 4242, 0), None, "condition not in the episode");
        assert!(all_done(&q));
        let en = entry(&q);
        assert_eq!(en.conditions[0], (cond, need));
        assert_eq!(en.done_mask, 1);
    }

    #[test]
    fn complete_bits_keep_npc_unlocks() {
        let bits = completed_bits(&[STARTER_EPISODE]);
        assert_eq!(bits[1] & (1 << 2), 1 << 2, "100020 = bit 10");
        for &(_, bit, _) in gamedata::NPC_UNLOCK_EPISODES {
            assert_ne!(bits[bit as usize / 8] & (1 << (bit % 8)), 0);
        }
    }

    #[test]
    fn clear_groups_follow_maze_group() {
        let (m1, g1, _) = gamedata::MAZE_CLEAR_GROUPS[0];
        let same: Vec<u16> = gamedata::MAZE_CLEAR_GROUPS.iter().filter(|m| m.1 == g1).map(|m| m.0).collect();
        let g = clear_groups(same.iter().copied().chain([m1, 1]));
        assert_eq!(g, [(u32::from(g1), same.iter().map(|&m| u32::from(m)).collect::<Vec<_>>())]);
        assert!(clear_groups([1u16]).is_empty(), "non-story maps are not reported");
    }

    #[test]
    fn new_characters_start_the_tutorial_in_its_maze() {
        assert_eq!(next_episode(1, &[], &[], true), Some(100001));
        assert_eq!(login_map(1, &[], &[], true), Some(TUTORIAL_MAZE_FALL));
        assert!(proto::maze(TUTORIAL_MAZE_FALL).is_some() && proto::maze(TUTORIAL_MAZE_LILIUM).is_some());
        // Characters from before the quest system skip it.
        assert_eq!(next_episode(1, &[], &[], false), Some(STARTER_EPISODE));
        assert_eq!(login_map(1, &[], &[], false), None);
        // In progress: the episode's maze, Lilium Room after the fall.
        assert_eq!(login_map(1, &[100002], &[100001], false), Some(TUTORIAL_MAZE_FALL));
        assert_eq!(login_map(1, &[100009], &[100001, 100002, 100005, 100007], false), Some(TUTORIAL_MAZE_LILIUM));
        assert_eq!(login_map(1, &[100017], &[], false), None);
        assert_eq!(tutorial_next_maze(TUTORIAL_MAZE_FALL), Some(TUTORIAL_MAZE_LILIUM));
        assert_eq!(tutorial_next_maze(TUTORIAL_MAZE_LILIUM), None);
    }

    #[test]
    fn tutorial_chain_hands_over_to_the_story() {
        for w in TUTORIAL_EPISODES.windows(2) {
            assert_eq!(next_in_chain(w[0]), Some(w[1]));
        }
        assert_eq!(next_in_chain(100017), Some(STARTER_EPISODE));
        assert_eq!(next_in_chain(STARTER_EPISODE), None);
        // Interrupted chain resumes; nothing new while an episode runs.
        assert_eq!(next_episode(1, &[], &[100001, 100002], true), Some(100005));
        assert_eq!(next_episode(1, &[], &TUTORIAL_EPISODES, false), Some(STARTER_EPISODE));
        assert_eq!(next_episode(1, &[100005], &[100001], true), None);
        // The story start comes even with side episodes running.
        assert_eq!(next_episode(1, &[100150], &TUTORIAL_EPISODES, false), Some(STARTER_EPISODE));
        assert_eq!(next_episode(1, &[STARTER_EPISODE], &TUTORIAL_EPISODES, false), None);
        let all: Vec<u32> = TUTORIAL_EPISODES.iter().copied().chain([STARTER_EPISODE]).collect();
        assert_eq!(next_episode(1, &[], &all, false), None);
    }

    #[test]
    fn auto_finish_and_auto_start_follow_the_table() {
        // 800010 "2nd Generation SoulWorker" has no finish NPC; 800012 starts after it.
        assert!(auto_finish(800010) && auto_finish(800005) && !auto_finish(800012) && !auto_finish(STARTER_EPISODE));
        assert_eq!(auto_start_after(800010).collect::<Vec<_>>(), [800012]);
        assert_eq!(auto_start_after(100007).collect::<Vec<_>>(), [100009]);
        assert!(gamedata::QUEST_AUTO_FINISH.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn later_classes_have_their_own_start() {
        // Chii / Ephnel: Candus City; Nabi / Dhana: Tower of Lord.
        for (class, maze, story, town) in [(7u8, 21113u16, 570010u32, 10021u16), (8, 21114, 570010, 10021), (9, 21115, 800010, 10071), (10, 21115, 800010, 10071)] {
            let c = start_chain(class);
            assert_eq!((c.maze, c.story, c.town), (maze, story, town), "class {class}");
            assert!(proto::maze(maze).is_some(), "maze {maze}");
            assert_eq!(start_town(class).map, town, "class {class} start town in DISTRICT_EXITS");
            assert!(episode(story).is_some() && c.tutorial.iter().all(|&e| episode(e).is_some()));
            assert_eq!(next_episode(class, &[], &[], false), Some(story));
            assert_eq!(next_episode(class, &[], &[], true), Some(c.tutorial[0]));
            assert_eq!(login_map(class, &[], &[], true), Some(maze));
        }
        assert_eq!(next_in_chain(570007), Some(570010));
        assert_eq!(next_in_chain(800005), Some(800010));
        assert_eq!(start_town(1).map, 10003);
        // A Dhana with the old chain's leftovers gets her own story start.
        assert_eq!(next_episode(10, &[100150], &TUTORIAL_EPISODES, false), Some(800010));
    }
}
