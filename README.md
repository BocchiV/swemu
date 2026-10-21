# swemu — SoulWorker server emulator (Rust)

An open-source server for the **SoulWorker GB/Steam 2.3.34.7** client, written
from scratch in Rust: one process, SQLite, no Docker, no MSSQL.

The game client is used unmodified apart from its login address: point
`General.ini` at your swemu and play. Every packet layout swemu sends was proven
against the 2.3.34.7 client's own packet readers (run under Unicorn, see `re/`).

> Unofficial community project. SoulWorker and all game assets belong to their
> owners. This repository contains **no game files and no game data**: you need
> your own copy of the client.

**Discord:** [swemu Development](https://discord.gg/pawFNMPMty) for protocol notes, packet captures, bug
reports and screenshots of swemu in action.

## Status

| Area | State |
|---|---|
| Login, server list, character create/delete/select, 2nd password (PIN) | basic version works, needs further development |
| World entry, towns, NPCs, NPC shops, buy/sell/buyback, repair | basic version works, needs further development |
| Inventory, equip, bag tools, item boxes, cash shop catalogue | basic version works, needs further development |
| Chat, gestures, GM commands (`/help`) | basic version works, needs further development |
| Maze (dungeon) entry/exit, all mazes enterable, sectors, portals | basic version works, needs further development |
| Level / EXP, drops and loot pickup | basic version works, needs further development |
| **Combat** | **buggy, help wanted**: hit/kill/EXP flow exists, but monster AI is weak, damage and HP bars do not always show correctly |
| Skill damage, stat formulas from equipment, potions, maze clear reward screen | missing / incomplete |
| Quests, party, friends, guilds, PvP | missing |

Nothing is finished: even the areas marked "basic version works" are early and
need more work (missing edge cases, unverified behaviour, placeholder values).
All characters are selectable in the creator.

## Build and run

Requirements: Rust (stable, edition 2024), Python 3.12 for the tools.

```
# 1. Generate the client-derived source files (see below)
# 2. Build
cd server
cargo build --release
# 3. Run (creates swemu.json + data/swemu.db in the working directory)
cd ../run   # any working directory
../server/target/release/swemu
```

Ports: login 15001, game 10200. The 2.3.34.7 client only accepts a login IP
that starts with `192.168` or `172.30.` (anything else, including 127.0.0.1, is
replaced by the client), so run swemu on your LAN address.

Client side: in `Soulworker_GB/General.ini` set `[Network Info] IP=<your LAN IP>`
and `PORT=15001`, then start `SoulWorker.exe VFunQA:: MultiExecuteClient`
(this shows the ID/password panel and sends the login to swemu).

## Generating game data

These files are generated from **your own client** and are not in the repository:

| File | Generator |
|---|---|
| `server/src/wire/tables.rs`, `server/src/wire/golden.rs` | `python re/emu_wire.py --emit-rust server/src/wire` |
| `server/src/gamedata.rs` | `python re/gen_gamedata.py` |

Setup:

```
cd re
python -m venv .venv && .venv/Scripts/pip install unicorn capstone cryptography pefile
mkdir -p targets/gb2334 && cp <client>/SoulWorker64.dll targets/gb2334/
set SW_CLIENT=<path to Soulworker_GB>          # folder that contains datas/
```

Some content (monster stats, drop tables, maze rewards, monster AI scripts)
comes from server-side tables that the client does not ship. Point
`SW_SERVER_DATA` at a folder with `res/` (server .res tables) and `Scripts/AI/`,
and `SW_TB_HEADERS` at the `TB_*.h` table headers. Without them the generator
uses level-based fallbacks where it can.

## Tests

```
cd server && cargo test                      # unit tests (need the generated files)
python re/e2e_client.py --host <ip> --port 15001 --aes --gm-user <gm account>
```

`e2e_client.py` plays the whole flow (login to maze combat) with the client's own
encryption and runs every server reply through the client's packet reader.

## Layout

| Path | Purpose |
|---|---|
| `server/` | the Rust server (crate `swemu`) |
| `re/` | reverse-engineering and data tools (Unicorn/Capstone, Python) |
| `docs/re-log.md` | packet layouts and client function addresses (2.3.34.7) |
| `docs/database.md` | SQLite schema |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and join the [Discord](https://discord.gg/pawFNMPMty). Rust is preferred, but C++/C# code and
plain packet notes are welcome too; they get ported to Rust.

## License

[AGPL-3.0](LICENSE). If you run a modified swemu for others, you must publish
your changes.
