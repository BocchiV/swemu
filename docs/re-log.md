# RE finding ledger

Each claim lists its evidence. "prior" = carried over from earlier sessions'
notes (C++ recon comments / memory files) and must be re-confirmed with REA
before relying on it for new work.

## Targets (re/targets)

| File | SHA-256 (prefix) | Notes |
|---|---|---|
| SoulWorker.exe | 31bd57d57689 | x64 launcher, 2952 procs (REA ev_de59fc56…) |
| SoulWorker64.dll | 44a6bcb9ab27 | = `SoulWorker64.dll.original` (unpatched); live client uses a patched copy 6caf5910… |
| SWLoading.exe | 630b683ca06a | 32-bit loading child |

## Wire protocol — 2.3.34.7 (current target, re/targets/gb2334, sha256 cbe04466…)

Verified by REA/Ghidra decompile **and** by running the client's own routines
under Unicorn (`re/emu_wire.py`, all checks pass; `re/e2e_client.py` passes
against the running server). Implemented in `server/src/wire/` + `server/src/proto.rs`;
`wire/tables.rs` and `wire/golden.rs` are generated from the DLL by `emu_wire.py --emit-rust`.

| Claim | Evidence |
|---|---|
| 11-byte header: u16 magic 0x0033, u16 size (incl. header), u8 flag, u8 key, u8 mode, u32 seq (LE) | pktinit FUN_18005b5f0; encoders FUN_18005b680/700/7e0 `size = len + 0xb` |
| Client sends flag=1; key = rolling u8 (+1 per send), seq = u32 (+1 per send, first = 1) | FUN_1805ef010, FUN_18005c680 |
| Modes 0/1/3 only (dispatch FUN_18005d170) | decompile |
| Mode 1: body ^= XOR_TABLE[key&15][i&15], table DAT_18194fa30 | emulated vs reference, 40 random pkts |
| Mode 3: AES-128-CTR, key AES_KEYS[key&15] (DAT_18194fc40), counter block = seq LE4, flag, key, size LE2, "SWPK", 0x00000000; 32-bit BE counter | FUN_18005d8f0 emulated == `cryptography` AES-CTR, 96 cases |
| Whole body (main/sub/pad included) is encrypted | encoders encrypt from offset 0xb |
| Body = main, sub, pad (<8; client uses rand()%8), pad filler bytes, payload | FUN_1805efa90 rejects pad >= 8, skips with FUN_18000e290 |
| Client refuses mode-0 frames once its mode != 0; adopts the mode of received frames | FUN_18005d1c0 (writes this+0x100c0) |
| LOGIN_REQ 2/1 = wstr user, wstr password, wstr MAC text "%02X-%02X-..." , u32 0x989746 | FUN_1805f5840 asm + FUN_1805b4120 format string; payload emulated |
| wstr = u16 BYTE length + UTF-16LE, no terminator | FUN_18000e430 (lstrlenW*2) |

## Login / game-server flow — 2.3.34.7 (implemented in server/src/handlers.rs)

Static RE (REA/Ghidra + capstone) and every server reply checked by the client's own
reader under Unicorn (`re/e2e_client.py` -> `re/reader_check.py`: each reader consumes
the payload exactly with its error flag clear).

| Step | Layout / rule | Evidence |
|---|---|---|
| Client start | `SoulWorker.exe` only loads SoulWorker64.dll and calls `SoulWorkerRun`. The DLL needs >= 1 command-line argument, otherwise "Run SoulWorker Client By Launcher!! -- [3]". No Steam/GameGuard gate in the plain (non-Steam) mode | FUN_180f17d70, FUN_1804b18c0 |
| Launch args (login path) | Per-arg parser sets app+0x738 mode: 0 none, 1 `MultiExecuteClient`/`SkipTWNAuthen`, 2 `--ip` (Steam), 3 `VFunQA::` (also flag +0x66e), 4 `fromVLauncher::`. After the logos the LoginScene opens the **Login panel only if +0x66e is set**, else Server Select (FUN_180da6cd0). Mode 4 sends LOGIN_FOR_VFUN 2/0x23 with a launcher token (FUN_180f1b790); mode 3 posts ID/password to valofe.com (FUN_180becd00); any other mode makes the Login button send LOGIN_REQ 2/1 (FUN_180beee20). So swemu needs `VFunQA:: MultiExecuteClient` **in that order** (mode 1 + flag). With a plain arg the client shows "No server currently Available" and never sends a packet. Verified by running the parser under Unicorn: `re/launch_check.py` | FUN_1804b2ce0, FUN_180da6cd0, FUN_180beee20 |
| C 2/0x23 LOGIN_FOR_VFUN (launcher path, refused by swemu) | wstr token, str8 MAC text, u32 0x989746, u32, u16 region, u32, str8 "launcher" (built by the client's writer under Unicorn) | FUN_1805f5d40, FUN_1800169d0 |
| Login IP | General.ini `[Network Info] IP`/`PORT` (defaults 203.168.1.107:25001). Value must start with "192.168" or "172.30." or be on the built-in official list, else it is replaced by 192.168.1.1. **127.0.0.1 does not work.** | FUN_1804a8a70, FUN_1804b4ea0 |
| C 2/1 LOGIN_REQ | wstr user, wstr password, wstr MAC text, u32 0x989746 | FUN_1805f5840 |
| S 2/2 LOGIN_RESULT | u32 account, u8, raw[18], wstr msg(<=1024), u32 err, u8, wstr auth(<=20), u64 session, u8, u16, u8, u8, u64, u8. err 1 = wrong ID/PW text, 2 = other | reader FUN_180015130, handler FUN_180d9e2e0 |
| C 2/3 SERVER_LIST_REQ | u32 (account) | FUN_1805f5a40 |
| S 2/4 SERVER_LIST | u8, i8 count, rows {u16 id, u16 port, str8 name(<=20), str8 host(<=512), u32 load, u32 flags, u8} | FUN_180034cc0, FUN_180034ea0 |
| C 2/5 SERVER_CONNECT_REQ | u16 server id | FUN_1805f5b30 |
| S 2/0x11 ENTER_SERVER | str8(<=19) + u16; the client then connects to the *row's* host:port. (Old notes called this SERVER_CONNECT_RES.) | FUN_180d9ede0 |
| C 2/0x13 ENTER_SERVER_REQ (game port) | u32 account, u16 server, u64 session, u8 | FUN_1805fe7d0 |
| S 2/0x14 ENTER_SERVER_RES | u8 result, u32 account, u32, u16 n, n x (u32,u8); 0 -> client sends 3/0x11 | FUN_1800312c0, FUN_180017540, FUN_180d9eee0 |
| C 3/0x11 CHARACTER_LIST_REQ | u64 session | FUN_1805f5f90 |
| S 3/0x12 CHARACTER_LIST_RES | i8 count, rows(0x310 each, FUN_180012e20 — not yet mapped), u32, u8, u8, u64, u32, u64, u16, i16 n1 x (u32, wstr<=39, u8, u64), i16 n2 x (u16,u8,u8,u8), u8 | FUN_180016d40 |
| Keepalive | 1/5 is a *server-initiated* ping; the client only replies. The client sends nothing unprompted while idle. | FUN_180deca80 |

Opcode map of all client senders/receivers: `re/out/opmap.txt` (from `re/opmap.py`).

## Wire protocol — 2.3.29.7 (old client, superseded)

| Claim | Status | Evidence |
|---|---|---|
| 6-byte header: ver u16, size u16 (incl. header), tos u8, key u8 | prior + implemented | C++ recon Packet.h comments (client OnRecv FUN_18005a9e0 rejects size<6; decrypt FUN_18005af20 uses size-6 from offset 6) |
| Body XOR with 16x16 table row `key&0xF`, index `i&0xF` | prior + implemented | table dumped from DLL RVA 0x5F8EB0; matches sw_server_v22.py |
| Client sends ver=49 | prior | sw_server_v22.py notes |
| wstring = `[u16 byte_len][UTF-16LE]` | srv-recon | Parse.h WriteWideString / GetWString |
| str8 = `[u16 len][bytes]` | srv-recon | Parse.h WriteByteString |

## Login flow

| Step | Status | Evidence |
|---|---|---|
| Client never sends LOGIN_REQ on game socket; server must push LOGIN_RES after accept | prior | LoginServer.cpp OnAccect comment; v22 "client silent 3s" branch |
| LOGIN_RES 2/2 layout (PS_LOGIN_RES serializer) | srv-recon | PSCommon.h:1508 |
| SERVER_LIST 2/4: reserved u8, u8, u8 count; id,port,str8 name,str8 host,u32 status,u32 flags2,u8 chars | prior client-RE | FUN_180033a90/FUN_180033c70 hook + LoginServer.cpp:2233 notes |
| Server row click sends 2/5 only; does not progress | prior | VFUN_TRANSFER_NOTES.md |
| **BLOCKER**: "VFUN Transfer" login dialog rejects every stub reply with "Incorrect ID / PASSWORD. [10000]" | prior | VFUN_TRANSFER_NOTES.md; request = `POST /api/vfun/login?` form `service_code=vfun&input_user_id=..&input_user_password=..` |

## Verified this session

- 2026-10-18 (2.3.34.7 login flow): `cargo test` 23/23. Running server passes
  `re/e2e_client.py` (mode 1 and `--aes`): login, wrong password refused, server
  list, ENTER_SERVER, forged ticket refused, real ticket accepted, empty character
  list; all four replies accepted by the client's own readers. `tools/client_sim.py`
  passes in both modes. Abuse checks: request before login, oversized frame, garbage,
  5 wrong passwords, LOGIN_FOR_VFUN, game port without ticket -> all closed/refused.
  Passwords are Argon2id-hashed and never appear in logs. Real client not yet run.

- 2026-10-18 (2.3.34.7): `cargo test` 17/17 (incl. 38 golden frames made by the
  client's encrypt code). Running server passes `tools/client_sim.py` (mode 1 and
  `--aes`) and `re/e2e_client.py` (client's own encrypt/decrypt under Unicorn, both
  modes). Credential packets are redacted in packets.log; a bad frame closes the
  connection. Still NOT tested with the real game client.
- 2026-10-18: `swemu` Rust server passes `tools/client_sim.py` (LOGIN_RES push,
  SERVER_LIST parse, SERVER_CONNECT_RES -> 127.0.0.1:10200, keepalive echo,
  game port reachable). Simulator only — not yet tested with the real client.
- REA Ghidra provider ready (doctor: Ghidra 12.1.2, JDK 21.0.11, native authority OK).
- REA `analyze` of SoulWorker.exe completed (ev_de59fc56…): PDB name SoulWorker.pdb
  referenced but not loaded; 2952 procedures, 1521 strings.

## Open questions

1. What does the client's `/api/vfun/login` response parser check? (needs REA on SoulWorker64.dll)
2. After VFun login: which call yields AuthCode and how is it delivered to the game socket?
3. Character list / create / select packet layouts (client-side readers).

## Character creator — 2.3.34.7 (verified)

C->S (opmap): 3/0x01 CREATE_CHARACTER_REQ (FUN_1805f6070), 3/0x02 DELETE (FUN_1805f6160, u32 id),
3/0x0D REPRESENTATIVE_CHECK (FUN_1805f6450, empty), 3/0x13 SELECT_CHARACTER_REQ (FUN_1805f6230).

CREATE payload = character row (writer FUN_1800128b0 / reader FUN_180012e20, 0x310 struct) + u32 outfit
(Coordinate: 111, 211...). Captured from the real client (5x619 bytes, server/tests/fixtures/create_character_req.hex):
- u32 id=-1, wstr name (FUN_18000e4b0 max 0x15 -> <=40 bytes), u8 class, u8, u32, u32,
  u64 appearance = 4xu16 (+0x158 hair, +0x168 , +0x15c, +0x160 from the creator panel), u64, u16 class_ref
  (class table +0x123 = 1001/2001), then u8 level(0 from creator) ... 28x(u64 -1,u32 -1,u32 0),
  ... 10xu32 0, f32 1.0, f32 1.0, ..., i8 n=0, u8 slot (=+0x13c+1), ..., u32 outfit.
- Class 1 vs class 2 rows differ only at class, appearance, class_ref and outfit.
- The server writes the row itself (proto::CharacterInfo::encode); test encoded_row_matches_client_row
  proves the encoding is byte-identical to the client's own creator output.

No CREATE_CHARACTER_RES exists. LoginScene dispatcher FUN_180d9d590 main 3 cases (sub-3):
0->3/0x03 DELETE_RES (u32 seconds), 1->3/0x04 KICK_OUT, 10->3/0x0D REPRESENTATIVE_CHECK (u32 msg id, 0=ok),
0xf->3/0x12 CHARACTER_LIST_RES, 0x11->3/0x14 SELECT_RES, 0x54->3/0x57 CHECK_NAME, ...
CHARACTER_LIST_RES handler FUN_180d9fa10: if scene==7 (Customizing) the list means "created" -> scene 8.
CHECK_NAME 3/0x57 = wstr name + u8; handler FUN_180797860: 0 -> UI 0xd7a2 "ID can be used.",
else 0xd7a1 "There is already an ID with the same name." and clears the name box.
Select panel FUN_1807a9b00: slot-1 indexes 12 entries -> slots 1..=12 only.

UI strings: tb_UI_String_ENG.res in data11.v = u32 count, count x {u32 id, u8, u16 units, UTF-16LE}; re/strtab.py.

Verified: cargo test 28/28; e2e_client.py (mode1 and --aes) ALL OK on a separate instance: create, duplicate
name (case-insensitive) -> 3/0x57, 1-letter name refused, list shows 1, delete -> 3/0x03 + empty list; every
reply consumed exactly by the client's readers (3/0x12 661/661 with one row).

## Second password (PIN pad) — 2.3.34.7 (verified)

C 3/0x17 SECOND_PASSWORD (writer FUN_180607230): u8 kind, str8 pin (6 ASCII digits, FUN_1807a8fb0 _itoa per digit).
kind 1 = set new PIN, 2 = verify, 3 = "Set Later" (empty pin; FUN_1807b4820 / FUN_180da7de0), 4 = sent when blocked.
S 3/0x17 reply (handler FUN_180da07c0, reader FUN_180054a50): u32 result, u8 state -> panel +0x100.
state: 0 not set ("Second PW has not been set..." 0xc239), 1 locked (PIN pad), 2 unlocked (Game Start -> FUN_1807ada40
-> 3/0x13 SELECT_CHARACTER_REQ), 3 blocked (0xc23e). result 0 + state != 3 -> client re-runs the pending action;
else FUN_1807a5fd0 shows an error (state 1 always 0xc23c; result 0xc23d = "Second PW incorrect. Please re-enter.").
CHARACTER_LIST_RES byte after select_id is this same state.
Server: PIN stored Argon2id (account.second_pw_hash), never overwritten by kind 1, "Set Later" only skips when no PIN
exists, 5 wrong PINs close the connection; 3/0x17 and 3/0x18 payloads are redacted in packets.log.

## Game Start -> world connection — 2.3.34.7 (implemented, verified under emulation)

C 3/0x13 SELECT_CHARACTER_REQ (FUN_1805f6230, writer FUN_18001c5c0): u32 char id, u32, u8 (+0x10458), u32, u32.
Captured from the real client: `01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00` (17 bytes).
S 3/0x14 SELECT_CHARACTER_RES (handler FUN_180d9fcb0, reader FUN_18002cb70 -> FUN_18002d270):
u32 char, u32 account, u32 server, u32 jump id, u32 portal, u64 map instance, u64 parent instance,
str8 host (FUN_18000e370: len must be 1..=0x200, len<=0 sets err=1 even on failure replies),
u16 port, position (FUN_180012610: u16 world id, u64 map instance, f32 x,y,z, f32 rot), u8 type,
then u8, u8, u32 result, u8 party type, u32 party id, u8 n x u16, u32 = 96 bytes with a 13-char host.
result 0 -> FUN_1805eefb0 stores the map instance at app +0x104b8, FUN_1805f69f0(host, port, channel byte,
purpose 3) opens a new connection; connect dispatcher FUN_1805ef3f0 purpose 3 sends 3/0x21.
result != 0 -> UI string (50104 = "Login failed").
Map instance = UXMapID: bits 0-23 seq, 24-31 channel, 32-47 district, 48-63 server.
Start district 10003 = F031_ROCCOTOWN (tb_district.res row header u16), jump id 1000301 (old C++ server default).

C 3/0x21 ENTER_GAMESERVER_REQ (FUN_1805fea10, writer FUN_18002c7b0): u32 account (+0x10138), u32 (+0x10150),
u64 map instance (+0x104b8), u8 flag, u64 (+0x104a0).
S 3/0x22 ENTER_GAMESERVER_RES (handler FUN_180da0f70, inline reads): u32 result, u8, position, u8, u32.
result 0 -> FUN_180da40f0 (InGamePanel, world load). Only runs while the login scene is active.

Server: the map instance is a one-time ticket bound to account + peer IP, 120 s; forged or reused -> 3/0x22 50104
and close. Game Start with a locked PIN or someone else's character -> 3/0x14 50104.
Verified: cargo test 32/32; e2e mode 1 and AES ALL OK; client readers consume 3/0x14 96/96 and 3/0x22 36/36, err=0.
NOT verified with the real client yet. After 3/0x22 the world needs character info / inventory / district
packets (receive_eSUB_CMD_CHARACTER_INFO_RES FUN_180da1170, ITEM_INVEN_INFO FUN_180df3ac0, WORLD_ENTER_RES
FUN_180dcd530); expect the next UNHANDLED opcodes there.

## CHARACTER_INFO 3/0x31 -> 3/0x32 — 2.3.34.7 (verified)
- C 3/0x31 (FUN_1805f65c0): u32 character id (app +0x10150), u8 (app +0x104e8 == 0). Real capture: `01 00 00 00 00`.
- S 3/0x32 handler FUN_180da1170: reader FUN_180013560 into player struct DAT_181a1e3f8, then three u8 inline
  (player +0x10258, world mode, DAT_181a2536e). Reader = FUN_1800134c0 (row FUN_180012e20 + pos FUN_180012610)
  + f32 x2 + u64 x2 + u8 x4 + u32 x2 + u64 x3 + str8 (1..0x14, empty = err) + u64 + u32 x3 + u64 x2.
- World id at struct +0x310 (-1/0 -> 10001), position +0x320. Start position F031_ROCCOTOWN VStartEventBox 1000301
  (World/Table/F031_ROCCOTOWN.vbatch, data09.v): box centre 10430.798,10258.951,90.452, rot 90.
- Unicorn: 755/755 bytes, err 0 (e2e_client.py both modes). Server checks the info request is for the character
  the world connection entered with.

## Entering the world: SKILL_LOAD_INFO 6/0x70 + ping — 2.3.34.7 (verified statically + client readers)
- CHARACTER_INFO_RES (FUN_180da1170) does not switch scenes: it only writes "LoadingScene"/"PlayScene" into the
  scene manager's pending name (DAT_1819671e0 +0x58). The only code that applies the pending name is
  FUN_180f3aa10 (-> SetScene FUN_180f3a800, then clears it); its only caller is the 6/0x70 handler FUN_180dd5170
  (opcode table FUN_180db4940: 0x0670 -> 0x180dd5170), as its last call. Symptom without it: world connection up,
  1/0x06 every second, client never leaves the character select screen.
- S 6/0x70 reader FUN_18001aa90: u32 character, u16 x5, u16 n x{u32,u32,u8}, u16 n x{u32,u32,u8}, u8 n x FUN_18001a830,
  FUN_18001b8f0 (u8, u8 n ...), u16 n x{...}. All lists empty = 23 bytes (Unicorn 23/23, err 0).
- C 1/0x06 ping (writer FUN_1805f0580): u64 tick, u64, u32. S 1/0x06 (PlayScene FUN_180decc20): u64 tick echo.

## Starter weapon + creator costume — 2.3.34.7 (verified with the client's row reader)
- The character row carries soul weapon id at +0x98 (u8 upgrade, u32 id) and 14 shape slots at +0xa8 (16 B each:
  u64 serial, u32 item id, u32 dye), interleaved with 14 look slots (+0x188). All -1 = naked, no weapon.
- tb_Character_Info (data11.v): per class u32 Item_ID_Weapon_01 then u32 Default_Cloth_ID_01..04 (creator picks).
  tb_Create_Cloth: {u16 id, u32 x6 items (head, body, hands, stocking, foot, pants), wstr icon}.
  Column -> shape slot = equip slot type - 0x0B: [1, 6, 4, 8, 9, 11].
- re/gen_gamedata.py regenerates server/src/gamedata.rs from the tables (no files extracted).
- Row reader FUN_180012e20 on a server row: weapon 111011301 at +0x98, items in shape slots 6/8/9/11, err 0.

## PlayScene first wave — 2.3.34.7 (verified: client readers under Unicorn, e2e both modes)

| Claim | Evidence |
|---|---|
| CHARACTER_INFO STAbility = 5 x {u32 cur, u32 max} interleaved (cur -> +0x68+4i, max -> +0x7c+4i), then f32 move speed rate, f32 attack speed rate; index 0 is the HUD HP bar | reader FUN_1800127d0 |
| C 4/0x06 (empty) is sent once the map has loaded | writer FUN_1805f4e00; real client log |
| S 0x23/0x02 GESTURE_SLOT_LOAD: 6 x u32 quick slots, then FUN_180024940 (u8, u32, u8 n x u32, u8 n x u32), FUN_18001c100, FUN_180038a90 (u16-counted lists); empty lists = 73 B. Basic gestures = class*1000 + 0..5 (tb_Gesture: Hello, Laugh, Sad, Cheer, Sit, Dance) | handler FUN_180e2bd50; reader_check 73/73 err 0 |
| C 9/0x20 -> S 9/0x20 SHOP_CASH_LOAD: u8 (1 = full load) + FUN_18000eb70 (u32 count + items); empty = 5 B. Unanswered = cash shop click crash | handler FUN_180e0b0c0; reader_check 5/5 err 0 |
