# Contributing

Three ways to help, pick whichever fits you.

## 1. Rust code (preferred)

- Fork, branch, open a pull request.
- `cargo test` must pass. If you add or change a packet, add a test and register
  the client reader in `re/reader_check.py` so `e2e_client.py` checks it.
- Packet layouts must match the **2.3.34.7** client. Note the client function
  (reader/handler address) you verified it against in the doc comment, like the
  existing code does.

## 2. C++ / C# / other languages

Not a Rust person? Write it in the language you know (most SoulWorker server
work is C++ or C#) and open a pull request that puts it under `contrib/<topic>/`
or attaches it to an issue. Describe what it does and which packets it uses;
it gets ported to Rust and merged into the server.

## 3. No code: packets and behaviour

Equally valuable:

- packet layouts ("main/sub, field list, what the client does with it"),
- how something behaves in the real game (screenshots, short clips, numbers),
- packet captures of the official game for a feature that is missing.

Open an issue with the `protocol` or `behaviour` label.

## Do not commit

- game files or anything extracted from them (tables, models, textures, sounds),
- generated files (`gamedata.rs`, `wire/tables.rs`, `wire/golden.rs`),
- databases, configs with real accounts/IPs, logs, archive passwords.

## Wanted right now

Combat: monster AI, damage display and HP bars, skill damage, stat formulas,
potions, maze clear rewards. Then quests and party.
