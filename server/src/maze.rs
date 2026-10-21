//! Maze play loop (category 1): monster AI, sector flow, player damage /
//! death / revive, in-maze warps, clear reward.
//!
//! Single player per connection: the maze instance lives in the Session and
//! a 200 ms tick (session::run) drives the monsters.
//!
//! Logic sources: reference server (XMaze::SendPotalInfos / SendSector-
//! Infos, CMoverEx damage, CGocRecode::MazeReward, PS_RES_REVIVE) via the
//! public reconstructions; packet layouts are proven with the
//! 2.3.34.7 client readers (re/reader_check.py, re/multi_trace.py).

use crate::handlers::{MAIN_CHARACTER, MAIN_ITEM, MAIN_MAZE, MAIN_MONSTER, MAIN_SKILL, MAIN_WORLD};
use crate::proto;
use crate::session::Session;
use tracing::info;

const MAIN_MOVE: u8 = 5;
/// AI step and monster attack pacing.
const AI_STEP_MS: u64 = 200;
const ATTACK_EVERY_MS: u64 = 1800;
/// A monster that lost its target walks back at most this far from home.
const LEASH: f32 = 2500.0;

/// Milliseconds since the connection opened.
pub fn now(s: &Session) -> u64 {
    s.clock.elapsed().as_millis() as u64
}

/// Forget the maze instance (map change).
pub fn reset(s: &mut Session) {
    s.monsters.clear();
    s.drops.clear();
    s.pre_targets.clear();
    s.combo = 0;
    s.spawned_boxes.clear();
    s.cleared_sectors.clear();
    s.enabled_portals.clear();
    s.maze_done = false;
    s.kills = 0;
    s.max_combo = 0;
    s.player_pos = None;
    s.dead_boxes.clear();
    s.sector_steps.clear();
    s.revives = 0;
    s.maze_started_ms = now(s);
}

/// The maze state the server sends with the object info on load
/// (XMaze::SendObjectInfo order: sectors 17/0x53, gates 17/0x54, dead
/// monsters 17/0x68, portals 17/0x55, revive count 17/0x70).
pub fn send_object_state(s: &mut Session) {
    let Some(spot) = s.spot else { return };
    if !proto::is_maze(spot.map) {
        return;
    }
    let key = proto::spawn_key(spot.map);
    let sectors: Vec<u32> = proto::maze_sectors(key).into_iter().map(|x| x.0).collect();
    let here = s.player_pos.unwrap_or(spot.pos);
    let current = proto::sector_at(key, here).or_else(|| sectors.first().copied()).unwrap_or(0);
    s.send(MAIN_MAZE, 0x53, proto::sector_infos(&sectors, current));
    s.send(MAIN_MAZE, 0x54, proto::gate_infos(true, &[]));
    let dead = s.dead_boxes.clone();
    s.send(MAIN_MAZE, 0x68, proto::die_monsters(&dead));
    let all = proto::maze_portal_ids(key);
    let open = s.enabled_portals.clone();
    s.send(MAIN_MAZE, 0x55, proto::portal_infos(&open, &all));
    s.send(MAIN_MAZE, 0x70, proto::use_revive_count(s.revives));
}

/// Monsters for `boxes` that were not spawned yet in this instance.
pub fn spawn_boxes(s: &mut Session, key: u16, boxes: &[u32], why: &str) {
    let fresh: Vec<u32> = boxes.iter().copied().filter(|b| !s.spawned_boxes.contains(b)).collect();
    if fresh.is_empty() {
        return;
    }
    let mut seq = s.monster_seq;
    let mut mons = proto::monsters_for_boxes(key, &fresh, &mut seq);
    s.monster_seq = seq;
    // Monsters spawned on one point would stand inside each other: spread
    // them by body radius (against each other and the ones already up).
    for _ in 0..4 {
        let mut all: Vec<proto::Monster> = s.monsters.iter().filter(|m| m.hp > 0).cloned().collect();
        let base = all.len();
        all.extend(mons.iter().cloned());
        proto::separate(key, &mut all);
        for (i, m) in mons.iter_mut().enumerate() {
            m.pos = all[base + i].pos;
        }
    }
    s.spawned_boxes.extend(fresh.iter().copied());
    if mons.is_empty() {
        return;
    }
    info!(conn = s.id, key, why, monsters = mons.len(), "spawning maze monsters");
    s.send(MAIN_WORLD, 0x23, proto::world_monsters(&mons));
    let t = now(s);
    for mut m in mons {
        m.home = m.pos;
        m.next_act = t + 1000;
        m.spawned_ms = t;
        s.monsters.push(m);
    }
}

/// Everything that must happen after monsters died (from a skill or a GM
/// /killall): sector clear -> open the sector's exit portal, release the
/// next sector's waves, end the maze after the boss sector.
pub fn after_kills(s: &mut Session) {
    let Some(spot) = s.spot else { return };
    if !proto::is_maze(spot.map) || s.maze_done {
        return;
    }
    let key = proto::spawn_key(spot.map);
    advance_steps(s, key);
    for (sector, boss, exit) in proto::maze_sectors(key) {
        if s.cleared_sectors.contains(&sector) {
            continue;
        }
        // Later spawn steps still due: the sector is not done yet.
        let step = s.sector_steps.iter().find(|x| x.0 == sector).map_or(1, |x| x.1);
        if step < proto::max_step(key, sector) {
            continue;
        }
        // A sector is clear when no counted monster of it is alive and at
        // least one was spawned there (otherwise later waves are still due).
        let spawned = s.spawned_boxes.iter().any(|b| proto::box_sector(key, *b) == Some(sector));
        let alive = s.monsters.iter().any(|m| m.sector == sector && m.counts && m.hp > 0);
        if !spawned || alive {
            continue;
        }
        // Waiting waves of this sector (WaitSignal boxes) come first: the
        // maze Lua releases them as the sector's kill ratio steps pass.
        let waves = proto::sector_wait_boxes(key, sector, &s.spawned_boxes);
        if !waves.is_empty() {
            spawn_boxes(s, key, &waves, "sector wave");
            continue;
        }
        s.cleared_sectors.push(sector);
        info!(conn = s.id, key, sector, boss, exit, "sector cleared");
        s.send(MAIN_MAZE, 0x52, proto::sector_clear(sector));
        if exit != 0 && !s.enabled_portals.contains(&exit) {
            s.enabled_portals.push(exit);
        }
        let all = proto::maze_portal_ids(key);
        s.send(MAIN_MAZE, 0x55, proto::portal_infos(&s.enabled_portals, &all));
        if boss {
            finish_maze(s);
            return;
        }
    }
}

/// CSector::CheckStepCondition: when the share of a sector's spawned
/// (counted) monsters that died reaches m_iConditionKillRatio_<step>Step,
/// the next step's boxes spawn.
fn advance_steps(s: &mut Session, key: u16) {
    for (sector, _, _) in proto::maze_sectors(key) {
        let step = s.sector_steps.iter().find(|x| x.0 == sector).map_or(1, |x| x.1);
        if step >= proto::max_step(key, sector) {
            continue;
        }
        let need = proto::step_ratio(key, sector, step);
        if need == 0 {
            continue;
        }
        let spawned: Vec<u32> = s
            .spawned_boxes
            .iter()
            .copied()
            .filter(|b| proto::box_sector(key, *b) == Some(sector) && proto::box_counts(key, *b))
            .collect();
        if spawned.is_empty() {
            continue;
        }
        let dead = spawned.iter().filter(|b| s.dead_boxes.contains(b)).count();
        if dead * 100 < spawned.len() * usize::from(need) {
            continue;
        }
        let next = step + 1;
        match s.sector_steps.iter_mut().find(|x| x.0 == sector) {
            Some(x) => x.1 = next,
            None => s.sector_steps.push((sector, next)),
        }
        let boxes = proto::step_boxes(key, sector, next);
        info!(conn = s.id, key, sector, step = next, boxes = boxes.len(), "sector spawn step");
        spawn_boxes(s, key, &boxes, "spawn step");
    }
}

/// Boss sector cleared: maze reward (17/0x75) and the EXP / Zenny it gives.
fn finish_maze(s: &mut Session) {
    let (Some(character), Some(spot)) = (s.character_id, s.spot) else { return };
    s.maze_done = true;
    let secs = ((now(s).saturating_sub(s.maze_started_ms)) / 100) as u32;
    let (exp, money) = proto::maze_reward(spot.map, s.level);
    let rank = proto::clear_rank(secs / 10, s.kills);
    let db = s.shared.db.lock().unwrap();
    let (level, cur) = db.level_exp(character).unwrap_or((1, 0));
    let (new_level, new_exp) = proto::add_exp(level, cur, exp);
    let _ = db.set_level_exp(character, new_level, new_exp);
    let zenny = db.zenny(character, s.shared.cfg.start_zenny).unwrap_or(0).saturating_add(u64::from(money));
    let _ = db.set_zenny(character, zenny);
    drop(db);
    info!(conn = s.id, character, maze = spot.map, secs, rank, exp, money, "maze cleared");
    s.send(MAIN_MAZE, 0x75, proto::maze_reward_info(rank, secs, s.max_combo, exp, money));
    s.send(MAIN_CHARACTER, 0x37, proto::character_exp(new_exp, exp));
    s.send(MAIN_ITEM, 0x20, proto::update_money(zenny));
    if new_level != level {
        level_up(s, character, new_level);
    }
}

/// Level changed: tell the client and refill HP at the new maximum.
pub fn level_up(s: &mut Session, character: u32, level: u8) {
    s.level = level;
    s.send(MAIN_CHARACTER, 0x36, proto::character_level(character, level));
    s.player_max_hp = proto::player_max_hp(s.class, level);
    s.player_hp = s.player_max_hp;
    s.dead = false;
    send_hp(s, character);
}

pub fn send_hp(s: &mut Session, character: u32) {
    let (hp, max) = (s.player_hp.max(0) as f32, s.player_max_hp as f32);
    s.send(MAIN_CHARACTER, 0x34, proto::stat_list(character, &[(proto::stat::HP_MAX, max), (proto::stat::HP_CUR, hp)]));
}

/// Position from the client's own movement / sync packets.
pub fn player_moved(s: &mut Session, pos: [f32; 3]) {
    if pos.iter().all(|v| v.is_finite()) {
        s.player_pos = Some(pos);
    }
}

/// C 4/0x07 WARP_REQ (writer FUN_1805f4e60, three u32): a JumpPos portal
/// inside the maze. Answered with S 4/0x08 at the portal's landing box.
pub fn warp(s: &mut Session, ids: [u32; 3]) {
    let (Some(character), Some(spot)) = (s.character_id, s.spot) else { return };
    let key = proto::spawn_key(spot.map);
    match proto::warp_target(key, &ids) {
        Some((pos, rot)) => {
            info!(conn = s.id, ?ids, ?pos, "maze warp");
            s.player_pos = Some(pos);
            s.send(MAIN_WORLD, 0x08, proto::warp_res(character, 0, pos, rot));
        }
        None => {
            info!(conn = s.id, ?ids, "maze warp: unknown target");
            s.send(MAIN_WORLD, 0x08, proto::warp_res(character, 1, spot.pos, spot.rot));
        }
    }
}

/// C 3/0x42 REVIVE_REQ (u32 actor, u8 type): stand up where the player fell
/// (type 0) or at the maze start, full HP (PS_RES_REVIVE broadcast).
pub fn revive(s: &mut Session, kind: u8) {
    let (Some(character), Some(spot)) = (s.character_id, s.spot) else { return };
    let (pos, rot) = match (kind, s.player_pos) {
        (0, Some(p)) => (p, spot.rot),
        _ => (spot.pos, spot.rot),
    };
    s.dead = false;
    s.player_hp = s.player_max_hp;
    s.player_pos = Some(pos);
    s.revives = s.revives.saturating_add(1);
    info!(conn = s.id, character, kind, "revive");
    s.send(MAIN_CHARACTER, 0x44, proto::revive_bt(character, kind, pos, rot));
    send_hp(s, character);
    // Monsters forget the corpse.
    for m in s.monsters.iter_mut() {
        m.aggro = false;
    }
}

/// Player takes a hit; at 0 HP the death packet goes out.
fn hurt(s: &mut Session, character: u32, attacker: u32, dmg: i64) {
    if s.dead || (s.god && attacker != character) {
        return;
    }
    s.player_hp = (s.player_hp - dmg).max(0);
    send_hp(s, character);
    if s.player_hp == 0 {
        s.dead = true;
        info!(conn = s.id, character, attacker, "player died");
        s.send(MAIN_CHARACTER, 0x41, proto::character_die(character, attacker));
    }
}

/// GM /die: drop to 0 HP at once.
pub fn gm_die(s: &mut Session, character: u32) {
    let hp = s.player_hp;
    hurt(s, character, character, hp.max(1));
}

/// A skill (6/0x06 passive such as the dash / evade 12040011, or 6/0x08)
/// spends its tb_Skill cost; the client shows the new value (3/0x34).
pub fn spend_skill_cost(s: &mut Session, skill: u32) {
    let (Some(character), Some((stat, cost))) = (s.character_id, proto::skill_cost(skill)) else { return };
    let value = match stat {
        proto::stat::ST_CUR => {
            s.stamina = (s.stamina - cost).max(0.0);
            s.stamina
        }
        proto::stat::SG_CUR => {
            s.sg = (s.sg - cost).max(0.0);
            s.sg
        }
        _ => {
            s.player_hp = (s.player_hp - cost as i64).max(1);
            s.player_hp as f32
        }
    };
    s.last_regen_ms = now(s);
    s.send(MAIN_CHARACTER, 0x34, proto::stat_list(character, &[(stat, value)]));
}

/// Once a second: stamina (and SG) refill by their regen (
/// CGocAttribute::OnUpdate adds stat 0x0F to stat 0x03 every interval).
fn regen(s: &mut Session) {
    let Some(character) = s.character_id else { return };
    let t = now(s);
    if t < s.last_regen_ms + 1000 {
        return;
    }
    s.last_regen_ms = t;
    let mut out = Vec::new();
    if s.stamina < s.stamina_max {
        s.stamina = (s.stamina + s.stamina_reg).min(s.stamina_max);
        out.push((proto::stat::ST_CUR, s.stamina));
    }
    if s.sg < s.sg_max {
        s.sg = (s.sg + 2.0).min(s.sg_max);
        out.push((proto::stat::SG_CUR, s.sg));
    }
    if !out.is_empty() {
        s.send(MAIN_CHARACTER, 0x34, proto::stat_list(character, &out));
    }
}

/// 200 ms tick: monsters that see the player walk to them and attack.
pub fn tick(s: &mut Session) {
    regen(s);
    let (Some(character), Some(pos)) = (s.character_id, s.player_pos) else { return };
    if s.monsters.is_empty() || s.maze_done {
        return;
    }
    let t = now(s);
    if t < s.last_ai_ms + AI_STEP_MS {
        return;
    }
    let dt = (t - s.last_ai_ms).min(1000) as f32 / 1000.0;
    s.last_ai_ms = t;
    let map_instance = s.map_instance.unwrap_or(0);
    let level = s.level;
    let dead = s.dead;
    let god = s.god;
    let mut hp_left = s.player_hp;
    let mut out: Vec<(u8, u8, Vec<u8>)> = Vec::new();
    let mut hits: Vec<(u32, i64)> = Vec::new();
    let mut roll = (t as u32).wrapping_mul(2654435761) ^ s.monster_seq;
    let nav_key = s.spot.map_or(0, |sp| proto::spawn_key(sp.map));
    for m in s.monsters.iter_mut().filter(|m| m.hp > 0 && m.counts) {
        let d = dist(m.pos, pos);
        if !m.aggro && !dead && d <= m.sight {
            m.aggro = true;
            out.push((MAIN_MONSTER, 0x22, proto::monster_target(m.actor, character)));
        }
        if !m.aggro || dead {
            if m.moving && dist(m.pos, m.home) < 50.0 {
                m.moving = false;
                out.push((MAIN_MOVE, 0x04, proto::move_stop_bt(m.actor, map_instance, m.pos, m.rot)));
            }
            continue;
        }
        if dist(m.pos, m.home) > LEASH {
            // Too far from home: give up and walk back.
            m.aggro = false;
            m.moving = true;
            out.push((MAIN_MOVE, 0x02, proto::move_bt(m.actor, map_instance, m.pos, yaw(m.pos, m.home), m.home, m.speed)));
            m.pos = m.home;
            continue;
        }
        // FSM: ATTACK picks a skill slot (script conditions), whose
        // range decides whether to close in first.
        let (slot, skill, reach) = pick_skill(m, d, t, roll);
        roll = roll.wrapping_mul(1103515245).wrapping_add(12345);
        if d > reach {
            // Chase on the navmesh: step towards the player.
            let step = (m.speed * dt).min(d - reach * 0.8);
            m.rot = yaw(m.pos, pos);
            let next = proto::nav_step(nav_key, m.pos, [pos[0], pos[1], m.pos[2]], step);
            m.pos = [next[0], next[1], pos[2]];
            if !m.moving || t >= m.next_move {
                m.moving = true;
                m.next_move = t + 600;
                out.push((MAIN_MOVE, 0x02, proto::move_bt(m.actor, map_instance, m.pos, m.rot, pos, m.speed)));
            }
            continue;
        }
        if m.moving {
            m.moving = false;
            out.push((MAIN_MOVE, 0x04, proto::move_stop_bt(m.actor, map_instance, m.pos, m.rot)));
        }
        if t < m.next_act {
            continue;
        }
        if skill == 0 {
            // The script picked an idle / common action: wait a beat.
            m.next_act = t + u64::from(ai_def(m).map_or(800, |a| a.select_ms.1.max(300)));
            continue;
        }
        // Attack: the skill animation (6/0x10) and its damage (6/0x13). The
        // next pick waits the script's SELECT_ACTION + ATTACK life times
        // (RegisterStateVars) and the skill's own cooldown (tb_Skill).
        let (sel, att) = ai_def(m).map_or(((800, 1200), (600, 900)), |a| (a.select_ms, a.attack_ms));
        let jitter = |lo: u32, hi: u32, r: u32| u64::from(lo + r % (hi.saturating_sub(lo) + 1));
        m.next_act = t + jitter(sel.0, sel.1, roll) + jitter(att.0, att.1, roll >> 7) + 600;
        if slot < 10 {
            let cd = proto::skill_row(skill).map_or(0, |r| u64::from(r.4));
            m.cooldowns[slot] = t + cd;
        }
        m.rot = yaw(m.pos, pos);
        roll = roll.wrapping_mul(1103515245).wrapping_add(12345);
        let saved = m.skill;
        m.skill = skill;
        let dmg = proto::monster_damage(m, level, roll >> 8);
        m.skill = saved;
        if !god {
            hp_left = (hp_left - dmg).max(0);
        }
        out.push((MAIN_SKILL, 0x10, proto::monster_skill_bt(m.actor, skill, m.pos, m.rot)));
        out.push((MAIN_SKILL, 0x13, proto::monster_hit_bt(m.actor, skill, m.pos, m.rot, character, dmg, hp_left)));
        hits.push((m.actor, dmg));
        if hp_left == 0 {
            break;
        }
    }
    // Bodies do not overlap (collision radius): monsters that crowd the
    // player or each other are pushed apart; a moved one gets a stop at its
    // new place so the client shows them side by side.
    for i in proto::separate(nav_key, &mut s.monsters) {
        let m = &s.monsters[i];
        if !m.moving {
            out.push((MAIN_MOVE, 0x04, proto::move_stop_bt(m.actor, map_instance, m.pos, m.rot)));
        }
    }
    for (main, sub, p) in out {
        s.send(main, sub, p);
    }
    for (attacker, dmg) in hits {
        hurt(s, character, attacker, dmg);
    }
}

fn ai_def(m: &proto::Monster) -> Option<&'static crate::gamedata::AiDef> {
    m.ai.and_then(|i| crate::gamedata::AIS.get(usize::from(i)))
}

/// Value of a FSM variable for a monster (see gamedata::AIS).
fn fsm_var(m: &proto::Monster, var: u8, dist: f32, t: u64, roll: u32) -> i32 {
    match var {
        0 => (roll % 10_000) as i32,
        1 => ((m.hp.max(0) * 100) / m.max_hp.max(1)) as i32,
        2 => dist as i32,
        3 => 0,
        4 => t.saturating_sub(m.spawned_ms) as i32,
        5 => i32::from(m.attacked),
        _ => i32::MIN,
    }
}

fn holds(m: &proto::Monster, conds: &[(u8, u8, i32)], dist: f32, t: u64, roll: u32) -> bool {
    conds.iter().enumerate().all(|(i, &(var, op, val))| {
        let v = fsm_var(m, var, dist, t, roll.rotate_left(i as u32 * 7));
        if v == i32::MIN {
            return false;
        }
        match op {
            0 => v < val,
            1 => v > val,
            2 => v <= val,
            3 => v >= val,
            4 => v == val,
            _ => v != val,
        }
    })
}

/// AI pick: the first ATTACK transition whose conditions hold names a
/// skill group; inside it the first slot whose skill conditions hold (and
/// is off cooldown) is used. Returns (slot index, skill id, its reach);
/// skill 0 = idle action. Monsters without a script use their first slot.
fn pick_skill(m: &proto::Monster, dist: f32, t: u64, roll: u32) -> (usize, u32, f32) {
    let reach = |skill: u32| proto::skill_row(skill).map_or(m.range, |s| f32::from(s.3.max(150)).min(900.0));
    let first = (0usize, m.skills[0].max(m.skill), m.range);
    let Some(ai) = ai_def(m) else { return first };
    let mut r = roll;
    for &(group, conds) in ai.picks {
        r = r.wrapping_mul(1103515245).wrapping_add(12345);
        if !holds(m, conds, dist, t, r >> 4) {
            continue;
        }
        if group == 255 {
            return (10, 0, m.range);
        }
        let Some(slots) = ai.groups.get(usize::from(group)) else { continue };
        for &slot in slots.iter() {
            let i = usize::from(slot.max(1) - 1);
            let Some(&skill) = m.skills.get(i) else { continue };
            if skill == 0 || t < m.cooldowns[i] {
                continue;
            }
            let sc: Vec<_> = ai.slots.iter().filter(|(g, s, _)| *g == group && *s == slot).collect();
            r = r.wrapping_mul(1103515245).wrapping_add(12345);
            if sc.is_empty() || sc.iter().any(|(_, _, c)| holds(m, c, dist, t, r >> 4)) {
                return (i, skill, reach(skill));
            }
        }
    }
    // Nothing matched: fall back to the first ready slot.
    for (i, &skill) in m.skills.iter().enumerate() {
        if skill != 0 && t >= m.cooldowns[i] {
            return (i, skill, reach(skill));
        }
    }
    first
}

fn dist(a: [f32; 3], b: [f32; 3]) -> f32 {
    ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2)).sqrt()
}

fn yaw(from: [f32; 3], to: [f32; 3]) -> f32 {
    (to[1] - from[1]).atan2(to[0] - from[0]).to_degrees()
}

/// Remember the attacker for the aggro check.
pub fn monsters_hit(s: &mut Session, actors: &[u32]) {
    let t = now(s);
    for m in s.monsters.iter_mut().filter(|m| actors.contains(&m.actor)) {
        m.attacked = true;
        if !m.aggro {
            m.aggro = true;
            m.next_act = m.next_act.max(t + 800);
        }
    }
}
