#!/usr/bin/env python
"""End-to-end check against a running swemu using the CLIENT'S OWN code
(Unicorn-emulated SoulWorker64.dll 2.3.34.7) for everything that touches bytes:

  C->S  payloads from the client's writers (LOGIN_REQ via FUN_18000e430) and
        frames from its encryptors FUN_18005b700 (mode 1) / FUN_18005b7e0 (mode 3)
  S->C  every frame goes through the client's decryptor FUN_18005d1c0, and every
        known payload through the client's own reader (reader_check.py), which must
        consume it exactly with no error flag.

Flow: LOGIN_REQ -> LOGIN_RESULT -> SERVER_LIST_REQ -> SERVER_LIST -> SERVER_CONNECT_REQ
      -> ENTER_SERVER, then a second socket to the listed host:port:
      ENTER_SERVER_REQ(ticket) -> ENTER_SERVER_RES -> CHARACTER_LIST_REQ -> CHARACTER_LIST_RES.
Also checks a wrong password is refused and a forged ticket is rejected.

   .venv/Scripts/python.exe e2e_client.py [--aes] [--host IP] [--port N]
"""
import socket, struct, sys, os, time
from emu_wire import Emu, DLL, F_ENC1, F_ENC3, F_DEC, HDR, client_encrypt, client_login_payload
from reader_check import check_payloads


class ClientConn:
    def __init__(self, emu, host, port, mode):
        self.emu, self.mode = emu, mode
        self.fn = F_ENC3 if mode == 3 else F_ENC1
        self.s = socket.create_connection((host, port), timeout=15)
        self.key = self.seq = 0
        self.buf = b""
        self.replies = []
        self.side = []

    def send(self, main, sub, payload, pad=5):
        self.key = (self.key + 1) & 0xFF
        self.seq += 1
        body = bytes([main, sub, pad]) + b"\xEE" * pad + payload
        self.s.sendall(client_encrypt(self.emu, self.fn, 1, self.key, self.mode, self.seq, body))

    def recv(self, raw=False):
        while True:
            m, s, p = self._recv()
            if raw or not is_side(m, s, p):
                return m, s, p
            self.side.append((m, s, p))

    def take_side(self, main, sub):
        got = [p for m, s, p in self.side if (m, s) == (main, sub)]
        self.side = [x for x in self.side if (x[0], x[1]) != (main, sub)]
        return got

    def _recv(self):
        emu = self.emu
        while True:
            b = self.buf
            if len(b) >= HDR and len(b) >= struct.unpack_from("<H", b, 2)[0]:
                size = struct.unpack_from("<H", b, 2)[0]
                frame, self.buf = b[:size], b[size:]
                emu.reset_heap()
                this = emu.alloc(0x10200)
                src, dst = emu.alloc(frame), emu.alloc(size + 16)
                assert emu.call(F_DEC, this, self.mode, frame[5], src, dst) & 0xFF == 1, \
                    f"client decrypt REJECTED server frame {frame[:16].hex()}"
                body = emu.read(dst + HDR, size - HDR)
                assert body[2] < 8, f"client would drop: pad {body[2]}"
                m, s, p = body[0], body[1], body[3 + body[2]:]
                self.replies.append((m, s, p))
                return m, s, p
            chunk = self.s.recv(65536)
            assert chunk, "server closed the connection"
            self.buf += chunk

    def closed_by_server(self):
        self.s.settimeout(5)
        try:
            return self.s.recv(1) == b""
        except (ConnectionResetError, ConnectionAbortedError):
            return True


SIDE = {(0x11, 0x53), (0x11, 0x54), (0x11, 0x68), (0x11, 0x70), (0x17, 0x12), (8, 0x31), (8, 0x32), (5, 0x02), (5, 0x04), (6, 0x10), (0x17, 0x22), (3, 0x34), (3, 0x41), (0x11, 0x52), (0x11, 0x55), (0x11, 0x75)}


def is_side(m, s, p):
    """Unsolicited maze packets: AI moves / attacks, HP, sector flow."""
    if (m, s) in SIDE:
        return True
    if (m, s) == (6, 0x13) and p:
        # ACTION_SKILL_BT from a monster: attacker after n x 60 B hits.
        o = 1 + 60 * p[0]
        return len(p) >= o + 4 and struct.unpack_from("<I", p, o)[0] & (2 << 29) != 0
    return False


def str8(b, o):
    n = struct.unpack_from("<H", b, o)[0]
    return b[o + 2:o + 2 + n].decode(), o + 2 + n


def wstr_at(b, o):
    n = struct.unpack_from("<H", b, o)[0]
    return b[o + 2:o + 2 + n].decode("utf-16-le"), o + 2 + n


def parse_login_result(p):
    account = struct.unpack_from("<I", p, 0)[0]
    msg, o = wstr_at(p, 4 + 1 + 18)
    err = struct.unpack_from("<I", p, o)[0]
    auth, o = wstr_at(p, o + 4 + 1)
    session = struct.unpack_from("<Q", p, o)[0]
    return account, err, msg, auth, session


def main():
    argv = sys.argv[1:]
    mode = 3 if "--aes" in argv else 1
    host = argv[argv.index("--host") + 1] if "--host" in argv else None
    port = int(argv[argv.index("--port") + 1]) if "--port" in argv else 15001
    if host is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
        host = s.getsockname()[0]
        s.close()
    emu = Emu(DLL)
    # --gm-user NAME: log in as an account listed in the server's gm_accounts
    # (exact name; use a fresh test DB) and expect GM commands to work.
    gm_user = argv[argv.index("--gm-user") + 1] if "--gm-user" in argv else None
    gm_expected = gm_user is not None
    user = gm_user or "e2e_" + os.urandom(3).hex()
    mac = "0A-1B-2C-3D-4E-5F"

    # 1. wrong password on an existing account is refused
    c = ClientConn(emu, host, port, mode)
    c.send(2, 1, client_login_payload(emu, user, "right-pass", mac))
    m, sub, p = c.recv()
    acc, err, *_ = parse_login_result(p)
    assert (m, sub, err) == (2, 2, 0), (m, sub, err)
    c.s.close()
    c = ClientConn(emu, host, port, mode)
    c.send(2, 1, client_login_payload(emu, user, "wrong-pass", mac))
    _, _, p = c.recv()
    assert parse_login_result(p)[1] == 1, "wrong password must give error 1"
    print(f"[ok] new account '{user}' registered; wrong password refused (error 1)")
    c.s.close()

    # 2. full login flow
    c = ClientConn(emu, host, port, mode)
    c.send(2, 1, client_login_payload(emu, user, "right-pass", mac))
    m, sub, p = c.recv()
    account, err, msg, auth, session = parse_login_result(p)
    assert (m, sub, err, msg) == (2, 2, 0, ""), (m, sub, err, msg)
    print(f"[ok] LOGIN_RESULT account={account} auth={auth!r} ticket={session:#x}")

    c.send(2, 3, struct.pack("<I", account))
    m, sub, p = c.recv()
    assert (m, sub) == (2, 4) and p[1] >= 1, (m, sub, p[:2].hex())
    sid, sport = struct.unpack_from("<HH", p, 2)
    name, o = str8(p, 6)
    shost, o = str8(p, o)
    print(f"[ok] SERVER_LIST id={sid} name={name!r} host={shost}:{sport}")
    assert shost.startswith(("192.168", "172.30.")), "client ignores other login IPs"

    c.send(2, 5, struct.pack("<H", sid))
    m, sub, p = c.recv()
    assert (m, sub) == (2, 0x11), (m, sub)
    print("[ok] ENTER_SERVER 2/0x11 -> client connects to the listed host:port")

    # 3. forged ticket is rejected on the game port
    g = ClientConn(emu, shost, sport, mode)
    g.send(2, 0x13, struct.pack("<IHQB", account, sid, session ^ 0xFFFF, 0))
    m, sub, p = g.recv()
    assert (m, sub, p[0]) == (2, 0x14, 1), (m, sub, p[:1])
    assert g.closed_by_server()
    print("[ok] forged ticket -> ENTER_SERVER_RES result=1 and connection closed")

    # 4. real ticket
    g = ClientConn(emu, shost, sport, mode)
    g.send(2, 0x13, struct.pack("<IHQB", account, sid, session, 0))
    m, sub, p = g.recv()
    assert (m, sub, p[0]) == (2, 0x14, 0), (m, sub, p[:1])
    print("[ok] ENTER_SERVER_REQ -> ENTER_SERVER_RES result=0")
    g.send(3, 0x11, struct.pack("<Q", session))
    m, sub, p = g.recv()
    assert (m, sub, p[0]) == (3, 0x12, 0), (m, sub)
    print("[ok] CHARACTER_LIST_REQ -> CHARACTER_LIST_RES (0 characters)")

    # 5. character creator: REPRESENTATIVE_CHECK, CREATE (payload from the
    #    real client's creator), duplicate name, list, delete
    g.send(3, 0x0D, b"")
    m, sub, p = g.recv()
    assert (m, sub, p) == (3, 0x0D, b"\0\0\0\0"), (m, sub, p)
    print("[ok] REPRESENTATIVE_CHECK -> 3/0x0D u32 0")

    cname = "E2e" + os.urandom(3).hex()
    g.send(3, 0x01, create_payload(cname))
    m, sub, p = g.recv()
    assert (m, sub) == (3, 0x12) and p[0] == 1, (m, sub, p[:1])
    cid = struct.unpack_from("<I", p, 1)[0]
    got, _ = wstr_at(p, 5)
    assert got == cname, got
    print(f"[ok] CREATE_CHARACTER_REQ -> CHARACTER_LIST_RES with '{got}' id={cid}")

    g.send(3, 0x01, create_payload(cname.upper()))
    m, sub, p = g.recv()
    assert (m, sub) == (3, 0x57) and p[-1] == 1, (m, sub, p)
    print("[ok] same name again -> CHARACTER_CHECK_NAME taken (client shows 'already an ID with the same name')")

    g.send(3, 0x01, create_payload("x"))
    m, sub, p = g.recv()
    assert (m, sub) == (3, 0x57) and p[-1] == 1, (m, sub, p)
    print("[ok] 1-letter name refused")

    g.send(3, 0x11, struct.pack("<Q", session))
    m, sub, p = g.recv()
    assert (m, sub, p[0]) == (3, 0x12, 1), (m, sub, p[:1])
    print("[ok] character list now has 1 character")

    g.send(3, 0x02, struct.pack("<I", cid))
    m, sub, p = g.recv()
    assert (m, sub, p) == (3, 0x03, b"\0\0\0\0"), (m, sub, p)
    m, sub, p = g.recv()
    assert (m, sub, p[0]) == (3, 0x12, 0), (m, sub, p[:1])
    print("[ok] DELETE_CHARACTER_REQ -> DELETE_CHARACTER_RES + empty list")

    # 6. second password (3/0x17: u8 kind, str8 pin -> u32 result, u8 state)
    g.send(3, 0x17, b"\x03\x00\x00")               # "Set Later" with no PIN
    m, sub, p = g.recv()
    assert (m, sub, p) == (3, 0x17, struct.pack("<IB", 0, 2)), (m, sub, p)
    print("[ok] SECOND_PASSWORD 'Set Later' (no PIN) -> result 0, state 2 (unlocked)")
    pin = "".join(str(d) for d in os.urandom(6))[:6].ljust(6, "7")
    g.send(3, 0x17, b"\x01" + struct.pack("<H", 6) + pin.encode())
    m, sub, p = g.recv()
    assert (m, sub, p) == (3, 0x17, struct.pack("<IB", 0, 2)), (m, sub, p)
    print("[ok] SECOND_PASSWORD set -> unlocked")
    replies_g1 = g.replies
    g.s.close()

    # 7. new game connection: list says locked; wrong PIN refused; right PIN unlocks
    c2 = ClientConn(emu, host, port, mode)
    c2.send(2, 1, client_login_payload(emu, user, "right-pass", mac))
    account, err, _, _, session = parse_login_result(c2.recv()[2])
    assert err == 0
    g = ClientConn(emu, shost, sport, mode)
    g.send(2, 0x13, struct.pack("<IHQB", account, sid, session, 0))
    assert g.recv()[2][0] == 0
    g.send(3, 0x11, struct.pack("<Q", session))
    m, sub, p = g.recv()
    assert (m, sub, p[0]) == (3, 0x12, 0) and p[5] == 1, (m, sub, p[:6].hex())
    print("[ok] CHARACTER_LIST_RES second_pw_state=1 (locked) after reconnect")
    cname2 = "Sel" + os.urandom(3).hex()
    g.send(3, 0x01, create_payload(cname2))
    m, sub, p = g.recv()
    assert (m, sub) == (3, 0x12) and p[0] == 1, (m, sub, p[:1])
    cid2 = struct.unpack_from("<I", p, 1)[0]
    g.send(3, 0x13, struct.pack("<IIBII", cid2, 0, 0, 0, 0))
    m, sub, p = g.recv()
    assert (m, sub) == (3, 0x14) and select_result(p)[3] == 50104, (m, sub, select_result(p))
    print("[ok] Game Start while the PIN is locked -> SELECT_CHARACTER_RES 'Login failed' (50104)")
    wrong = "".join("0123456789"[(int(ch) + 1) % 10] for ch in pin)
    g.send(3, 0x17, b"\x02" + struct.pack("<H", 6) + wrong.encode())
    m, sub, p = g.recv()
    assert (m, sub, p) == (3, 0x17, struct.pack("<IB", 0xC23D, 1)), (m, sub, p)
    print("[ok] wrong PIN -> 'Second PW incorrect' (0xc23d), still locked")
    g.send(3, 0x17, b"\x03\x00\x00")
    m, sub, p = g.recv()
    assert (m, sub, p) == (3, 0x17, struct.pack("<IB", 0, 1)), (m, sub, p)
    print("[ok] 'Set Later' cannot skip an existing PIN")
    g.send(3, 0x17, b"\x01" + struct.pack("<H", 6) + wrong.encode())
    m, sub, p = g.recv()
    assert (m, sub, p) == (3, 0x17, struct.pack("<IB", 0, 1)), (m, sub, p)
    print("[ok] 'set' cannot overwrite an existing PIN")
    g.send(3, 0x17, b"\x02" + struct.pack("<H", 6) + pin.encode())
    m, sub, p = g.recv()
    assert (m, sub, p) == (3, 0x17, struct.pack("<IB", 0, 2)), (m, sub, p)
    print("[ok] right PIN -> unlocked")

    # 8. Game Start: SELECT_CHARACTER -> world address -> ENTER_GAMESERVER
    g.send(3, 0x13, struct.pack("<IIBII", 0x7FFFFFF0, 0, 0, 0, 0))
    m, sub, p = g.recv()
    assert (m, sub) == (3, 0x14) and select_result(p)[3] == 50104, (m, sub, select_result(p))
    print("[ok] selecting a character the account does not own -> 'Login failed'")
    g.send(3, 0x13, struct.pack("<IIBII", cid2, 0, 0, 0, 0))
    m, sub, p = g.recv()
    whost, wport, minst, res = select_result(p)
    assert (m, sub, res) == (3, 0x14, 0), (m, sub, res)
    assert whost.startswith(("192.168", "172.30.")) and (minst >> 32) & 0xFFFF == 10003, (whost, hex(minst))
    print(f"[ok] SELECT_CHARACTER_RES -> world {whost}:{wport}, map instance {minst:#x} (district 10003)")

    w = ClientConn(emu, whost, wport, mode)
    w.send(3, 0x21, struct.pack("<IIQBQ", account, 0, minst ^ 1, 1, 0))
    m, sub, p = w.recv()
    assert (m, sub) == (3, 0x22) and struct.unpack_from("<I", p, 0)[0] == 50104, (m, sub, p[:4])
    assert w.closed_by_server()
    print("[ok] ENTER_GAMESERVER_REQ with a forged map instance -> refused and closed")
    replies_w1 = w.replies
    # The forged try did not burn the real ticket (different key), so the real one works once.
    w = ClientConn(emu, whost, wport, mode)
    w.send(3, 0x21, struct.pack("<IIQBQ", account, 0, minst, 1, 0))
    m, sub, p = w.recv()
    assert (m, sub) == (3, 0x22) and struct.unpack_from("<I", p, 0)[0] == 0, (m, sub, p[:4])
    print("[ok] ENTER_GAMESERVER_REQ -> ENTER_GAMESERVER_RES result 0 (client starts loading the world)")
    w.send(3, 0x31, struct.pack("<IB", cid2 ^ 0x40, 1))
    assert w.closed_by_server(), "CHARACTER_INFO_REQ for another character must close the connection"
    print("[ok] CHARACTER_INFO_REQ for a character not entered with -> closed")
    replies_w2 = w.replies
    # fresh ticket for the real info request
    g.send(3, 0x13, struct.pack("<IIBII", cid2, 0, 0, 0, 0))
    m, sub, p = g.recv()
    whost, wport, minst3, res = select_result(p)
    assert (m, sub, res) == (3, 0x14, 0), (m, sub, res)
    w3 = ClientConn(emu, whost, wport, mode)
    w3.send(3, 0x21, struct.pack("<IIQBQ", account, 0, minst3, 1, 0))
    m, sub, p = w3.recv()
    assert (m, sub) == (3, 0x22) and struct.unpack_from("<I", p, 0)[0] == 0, (m, sub, p[:4])
    w3.send(3, 0x31, struct.pack("<IB", cid2, 1))
    m, sub, p = w3.recv()
    assert (m, sub) == (3, 0x32), (m, sub)
    assert struct.unpack_from("<I", p, 0)[0] == cid2, "info row must be the selected character"
    print(f"[ok] CHARACTER_INFO_REQ -> CHARACTER_INFO_RES {len(p)} bytes (character {cid2})")
    # Zenny = 2nd u64 after the position; 78 bytes of tail follow it
    # (u8 x4, u32 x2, u64 x3, str8 " ", u64, u32 x3, u64 x2, u8 x3).
    info_payload, zenny_off = p, len(p) - 78 - 8
    # FP: the row's two i16 after the private-shop wstr; find them by value.
    assert struct.pack("<HHH", 200, 0, 0) in p, "FP 200/0 in the character row"
    open(os.path.join(os.environ.get("TEMP", "."), "swemu_charinfo.hex"), "w").write(p.hex())
    m, sub, p = w3.recv()
    assert (m, sub) == (0x15, 0x01) and len(p) == 256, (m, sub, len(p))
    on = [i * 8 + j for i in range(256) for j in range(8) if p[i] >> j & 1]
    assert on == [19, 29, 43], on  # NPC-unlocking story episodes (Janice, Eo, Trisha)
    m, sub, p = w3.recv()
    assert (m, sub) == (0x15, 0x02) and p == bytes(4), (m, sub, p)
    print("[ok] QUEST_COMPLETE_LIST 21/0x01 + QUEST_LIST 21/0x02 (they let the client spawn NPCs)")
    m, sub, p = w3.recv()
    assert (m, sub) == (6, 0x70) and struct.unpack_from("<I", p, 0)[0] == cid2, (m, sub, p[:4])
    print("[ok] SKILL_LOAD_INFO 6/0x70 follows (this is what switches the client to LoadingScene)")
    w3.send(1, 0x06, struct.pack("<QQI", 0x1122334455, 0, 0x8F))
    m, sub, p = w3.recv()
    assert (m, sub, p) == (1, 0x06, struct.pack("<Q", 0x1122334455)), (m, sub, p)
    print("[ok] SYSTEM_PING 1/0x06 echoed")
    w3.send(4, 0x06, b"")
    m, sub, p = w3.recv()
    assert (m, sub) == (0x23, 0x02) and struct.unpack_from("<I", p, 0)[0] % 1000 == 0, (m, sub, p[:4])
    print(f"[ok] map loaded (4/0x06) -> GESTURE_SLOT_LOAD 0x23/0x02, first gesture {struct.unpack_from('<I', p, 0)[0]}")
    m, sub, p = w3.recv()
    assert (m, sub) == (3, 0x51) and struct.unpack_from("<I", p, 0)[0] == cid2 and p[4] > 0, (m, sub, p[:5])
    print(f"[ok] UPDATE_ORIGIN_STAT 3/0x51 on map load: {p[4]} stats (stamina + speed)")
    shop_items, last_cash = recv_cash_shop(w3)
    print(f"[ok] cash shop pushed on map load: {shop_items} products (9/0x20 pages) + 9/0x28 + cash balance 8/0x33")
    gesture = bytes.fromhex("E803000007C5244672752046 92E2B442 8766BE42 380A2FC1 00000000".replace(" ", ""))
    w3.send(0x23, 0x01, gesture)
    m, sub, p = w3.recv()
    assert (m, sub) == (0x23, 0x01) and p[4:] == gesture and struct.unpack_from("<I", p, 0)[0] == cid2, (m, sub, p)
    print("[ok] DO_GESTURE 0x23/0x01 -> GESTURE_SHOW echoed with the actor id")
    w3.send(9, 0x20, b"")
    assert recv_cash_shop(w3)[0] == shop_items
    print("[ok] SHOP_CASH_LOAD 9/0x20 on click answered with the same catalogue")
    # shop 23964 = box 6000451 for 1000 cash; option 0, quantity 1 (real client capture)
    cash_before = last_cash
    w3.send(9, 0x21, struct.pack("<IIBHB", 1, 23964, 0, 1, 0))
    m, sub, p = w3.recv()
    assert (m, sub) == (9, 0x21), (m, sub)
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x01), (m, sub)
    n = struct.unpack_from("<I", p, 0)[0]
    inv = [(p[4 + i * 118], struct.unpack_from("<I", p, 4 + i * 118 + 3)[0], struct.unpack_from("<Q", p, 4 + i * 118 + 7)[0]) for i in range(n)]
    box = [x for x in inv if x[1] == 6000451]
    assert box and box[0][0] == 0x0D, inv
    m, sub, p = w3.recv()
    cash_after = struct.unpack_from("<I", p, 0)[0]
    assert (m, sub) == (8, 0x33) and cash_after == cash_before - 1000, (m, sub, cash_before, cash_after)
    print(f"[ok] SHOP_CASH_BUY: box 6000451 in the cash bag, cash {cash_before} -> {cash_after}")
    serial = box[0][2]
    w3.send(8, 0x11, struct.pack("<BHQB", 0x0D, 0, serial, 1))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x15), (m, sub)
    p2 = p
    upd = [(struct.unpack_from("<I", p, 4 + i * 118 + 3)[0], struct.unpack_from("<H", p, 4 + i * 118 + 15)[0]) for i in range(struct.unpack_from("<I", p, 0)[0])]
    assert (6000451, 0) in upd and (213881001, 1) in upd, upd
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x11) and struct.unpack_from("<I", p, 0)[0] == 6000451, (m, sub, p[:4])
    print("[ok] ITEM_USE 8/0x11 opened the box: ITEM_UPDATE 8/0x15 removes it and adds costume 213881001")
    cos = [u for u in [(p2[4 + i * 118], struct.unpack_from("<H", p2, 4 + i * 118 + 1)[0], struct.unpack_from("<I", p2, 4 + i * 118 + 3)[0]) for i in range(struct.unpack_from("<I", p2, 0)[0])] if u[2] == 213881001][0]
    # equip: real client capture shape (costume bag -> shape slot 7)
    w3.send(8, 0x02, struct.pack("<BIHBBIHB", cos[0], 213881001, cos[1], 0, 0, 213881001, 7, 0))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x02) and p[0] == 1, (m, sub, p)
    src = struct.unpack_from("<BiH", p, 1); dst = struct.unpack_from("<BiH", p, 9)
    assert src == (cos[0], -1, cos[1]) and dst == (0, 213881001, 7), (src, dst)
    print("[ok] ITEM_MOVE 8/0x02 equip: costume 213881001 -> shape slot 7")
    # wrong slot is refused: the reply restores both slots
    w3.send(8, 0x02, struct.pack("<BIHBBIHB", 0, 213881001, 7, 0, 0, 0xFFFFFFFF, 3, 0))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x02) and p == b"\x00", p
    print("[ok] ITEM_MOVE to a wrong slot is refused (empty reply, nothing moves)")
    # unequip back to the costume bag
    w3.send(8, 0x02, struct.pack("<BIHBBIHB", 0, 213881001, 7, 0, cos[0], 0xFFFFFFFF, cos[1], 0))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x02) and struct.unpack_from("<BiH", p, 9) == (cos[0], 213881001, cos[1]), p
    print("[ok] ITEM_MOVE 8/0x02 unequip: back to the costume bag")
    w3.send(7, 0x01, b"\x01" + struct.pack("<H", 20) + "Merhaba şğüı".encode("utf-16-le")[:20] + b"\x00")
    m, sub, p = w3.recv()
    assert (m, sub) == (7, 0x01) and struct.unpack_from("<I", p, 0)[0] == cid2, (m, sub, p[:4])
    assert struct.unpack_from("<I", p, 6)[0] == 1, ("chat type 1 = name from the speaker actor", p[:10])
    ln = struct.unpack_from("<H", p, 10)[0]
    assert p[12:12 + ln].decode("utf-16-le") == "Merhaba şğ" and p[12 + ln] == 0 and len(p) == 13 + ln, p
    print("[ok] CHAT_NORMAL 7/0x01 -> echoed to the speaker with the actor id")
    gm = "/item 6000451 2".encode("utf-16-le")
    w3.send(7, 0x0A, struct.pack("<H", len(gm)) + gm)
    if gm_expected:
        m, sub, p = w3.recv()
        assert (m, sub) == (8, 0x15), (m, sub)
        got = [(struct.unpack_from("<I", p, 4 + i * 118 + 3)[0], struct.unpack_from("<H", p, 4 + i * 118 + 15)[0]) for i in range(struct.unpack_from("<I", p, 0)[0])]
        assert got == [(6000451, 2)], got
        m, sub, p = w3.recv()
        assert (m, sub) == (7, 0x01), (m, sub)
        print("[ok] GM 7/0x0A '/item 6000451 2' -> ITEM_UPDATE + [GM] chat reply")
    else:
        w3.send(1, 0x06, struct.pack("<QQI", 0x77, 0, 0))
        m, sub, p = w3.recv()
        assert (m, sub) == (1, 0x06), ("non-GM must get no reply to 7/0x0A", m, sub)
        print("[ok] GM 7/0x0A from a non-GM account is ignored")
    w3.send(0xF1, 0x01, b"")
    m, sub, p = w3.recv()
    assert (m, sub) == (4, 0x22) and struct.unpack_from("<H", p, 0)[0] == 36 and len(p) == 2 + 36 * 49, (m, sub, p[:2], len(p))
    print("[ok] CHANNEL_INFO F1/01 -> WORLD_OTHER_INFOS_NPC 4/0x22 with Rocco Town's 36 NPCs")
    w3.send(8, 0x01, bytes([6, 0, 3, 1, 2, 4, 0x0D]))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x0E) and p[0] == 6, (m, sub, p[:1])
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x01), (m, sub)
    print("[ok] ITEM_INVEN_INFO 8/0x01 -> OPEN_SLOT_INFO 8/0x0E (6 groups) + empty inventory")
    # NPC shop: tb_Shop 1191 = HP potion 800004001 (Buy_Price 200, stack 50).
    zen0 = struct.unpack_from("<Q", info_payload, zenny_off)[0]
    assert zen0 == 1_000_000, zen0
    w3.send(9, 0x03, struct.pack("<I", 0x20000005))
    m, sub, p = w3.recv()
    assert (m, sub) == (9, 0x03) and p == bytes(5), (m, sub, p)
    print("[ok] SHOP_REPURCHASER_LIST 9/0x03 (sent when a shop opens) -> empty buyback list")
    w3.send(9, 0x01, struct.pack("<IIHB", 0x20000005, 1191, 3, 0))
    m, sub, p = w3.recv()
    assert (m, sub) == (9, 0x01), (m, sub)
    n = struct.unpack_from("<I", p, 0)[0]
    got = [(p[4 + i * 118], struct.unpack_from("<I", p, 4 + i * 118 + 3)[0], struct.unpack_from("<H", p, 4 + i * 118 + 15)[0]) for i in range(n)]
    assert got == [(2, 800004001, 3)] and struct.unpack_from("<QBI", p, 4 + n * 118 + 1) == (600, 1, 0), (got, p[-13:])
    pot_slot = struct.unpack_from("<H", p, 5)[0]
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x20) and struct.unpack_from("<Q", p, 0)[0] == zen0 - 600, (m, sub, p)
    print("[ok] SHOP_BUY 9/0x01: 3 HP potions into the common bag, 600 Zenny spent (8/0x20)")
    w3.send(9, 0x02, struct.pack("<IBBBH", 0x20000005, 0, 1, 2, pot_slot))
    m, sub, p = w3.recv()
    assert (m, sub) == (9, 0x02) and struct.unpack_from("<I", p, 0)[0] == 1 and struct.unpack_from("<H", p, 4 + 15)[0] == 0, (m, sub, p[:24])
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x20) and struct.unpack_from("<Q", p, 0)[0] == zen0 - 600 + 30, (m, sub, p)
    m, sub, p = w3.recv()
    assert (m, sub) == (9, 0x03) and p[0] == 1 and len(p) == 1 + 114 + 4, (m, sub, p[:8])
    bb_item = p[1:115]
    assert struct.unpack_from("<IQH", bb_item, 0)[::2] == (800004001, 3), bb_item[:14].hex()
    print("[ok] SHOP_SELL 9/0x02: potions sold for 3 x 10 Zenny, slot emptied, buyback list 9/0x03 has them")
    w3.send(9, 0x04, struct.pack("<I", 0x20000005) + bb_item)
    m, sub, p = w3.recv()
    assert (m, sub) == (9, 0x04) and struct.unpack_from("<I", p, 0)[0] == 1, (m, sub, p[:8])
    pot_slot = struct.unpack_from("<H", p, 5)[0]
    pot_id, pot_serial, pot_count = struct.unpack_from("<IQH", p, 7)
    assert (p[4], pot_id, pot_count) == (2, 800004001, 3) and pot_serial == struct.unpack_from("<Q", bb_item, 4)[0], p[:20].hex()
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x20) and struct.unpack_from("<Q", p, 0)[0] == zen0 - 600, (m, sub, p)
    w3.send(9, 0x03, struct.pack("<I", 0x20000005))
    m, sub, p = w3.recv()
    assert (m, sub) == (9, 0x03) and p == bytes(5), (m, sub, p[:8])
    print("[ok] SHOP_REPURCHASER 9/0x04: potions bought back for 30 Zenny with their old serial; buyback empty")
    # Soul weapon (the move the real client hung on): bag -> gear slot (1, 0)
    # swaps with the worn one; moving it out to an empty slot is refused.
    w3.send(9, 0x01, struct.pack("<IIHB", 0x20000005, 1, 1, 0))
    m, sub, p = w3.recv()
    assert (m, sub) == (9, 0x01) and struct.unpack_from("<I", p, 4 + 3)[0] == 111011301, (m, sub, p[:12])
    wslot = (p[4], struct.unpack_from("<H", p, 5)[0])
    w3.recv()  # 8/0x20
    w3.send(8, 0x02, struct.pack("<BIHBBIHB", wslot[0], 111011301, wslot[1], 0, 1, 111011301, 0, 0))
    m, sub, p = w3.recv()
    src = struct.unpack_from("<BiH", p, 1); dst = struct.unpack_from("<BiH", p, 9)
    assert (m, sub) == (8, 0x02) and src == (wslot[0], 111011301, wslot[1]) and dst == (1, 111011301, 0), (src, dst)
    w3.send(8, 0x02, struct.pack("<BIHBBIHB", 1, 111011301, 0, 0, 2, 0xFFFFFFFF, 20, 0))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x02) and p == b"\x00", p
    print("[ok] ITEM_MOVE soul weapon: bag <-> gear slot (1, 0) swaps; emptying the slot is refused")
    # Bag tools on the 3 potions: divide, combine, throw away, sort.
    w3.send(8, 0x04, struct.pack("<BIHBHH", 2, pot_id, pot_slot, 2, 23, 1))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x04) and len(p) == 134, (m, sub, len(p))
    assert struct.unpack_from("<IBHH", p, 0) == (pot_id, 2, pot_slot, 2) and struct.unpack_from("<BH", p, 17) == (2, 23), p[:24].hex()
    assert struct.unpack_from("<I", p, 20)[0] == pot_id and struct.unpack_from("<H", p, 32)[0] == 1
    w3.send(8, 0x04, struct.pack("<BIHBHH", 2, pot_id, pot_slot, 2, 22, 2))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x15) and struct.unpack_from("<H", p, 4 + 15)[0] == 2, (m, sub, p[:24])
    print("[ok] ITEM_DIVIDE 8/0x04: 1 potion split off to slot 23; splitting a whole stack is refused (8/0x15 refresh)")
    w3.send(8, 0x03, struct.pack("<BIHBBIHBH", 2, pot_id, 23, 0, 2, pot_id, pot_slot, 0, 1))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x03) and len(p) == 247, (m, sub, len(p))
    src = struct.unpack_from("<BH", p, 4) + (struct.unpack_from("<H", p, 7 + 12)[0],)
    dst = struct.unpack_from("<BH", p, 123 + 4) + (struct.unpack_from("<H", p, 123 + 7 + 12)[0],)
    assert src == (2, 23, 0) and dst == (2, pot_slot, 3), (src, dst)
    print("[ok] ITEM_COMBINE 8/0x03: slot 23 stacked back onto the potions (3)")
    w3.send(8, 0x05, struct.pack("<BHQI", 2, pot_slot, pot_serial, 1))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x15) and struct.unpack_from("<H", p, 4 + 15)[0] == 2, (m, sub, p[:24])
    w3.send(8, 0x05, struct.pack("<BHQI", 2, pot_slot, pot_serial, 2))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x05) and p == struct.pack("<BHQ", 2, pot_slot, pot_serial), (m, sub, p.hex())
    w3.send(8, 0x05, struct.pack("<BHQI", 1, 0, 0, 1))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x15) and p[4] == 1 and struct.unpack_from("<I", p, 7)[0] == 111011301, (m, sub, p[:12])
    print("[ok] ITEM_BREAK 8/0x05: 1 thrown away (8/0x15), the rest empties the slot; the soul weapon cannot be thrown away")
    w3.send(8, 0x25, bytes([2]))
    m, sub, p = w3.recv()
    assert (m, sub) == (8, 0x25) and p[0] == 2, (m, sub, p[:4])
    n = struct.unpack_from("<H", p, 1)[0]
    slots = [struct.unpack_from("<BH", p, 3 + i * 13) for i in range(n)]
    assert n >= 1 and slots == [(2, i) for i in range(n)], slots
    print(f"[ok] ITEM_LINE_UP 8/0x25: common bag sorted, {n} item(s) packed from slot 0")
    # Panel lists the client asks for on entering the world (real payloads).
    panels = [((3, 0x23), b"", 5), ((3, 0x7B), b"", 1), ((0x20, 0x10), b"", 4), ((0x20, 0x02), b"", 1),
              ((0x20, 0x14), b"", 2), ((0x19, 0x41), bytes(7), 1), ((0x19, 0x44), b"", 1), ((0x19, 0x51), b"", 5),
              ((0x12, 0x36), b"", 3), ((0x12, 0x37), b"", 3), ((0x2B, 0x03), bytes(4), 6), ((0x2B, 0x08), bytes(4), 3),
              ((0x2B, 0x10), b"", 105), ((0x18, 0x58), b"", 1)]
    for (pm, ps), body, size in panels:
        w3.send(pm, ps, body)
        m, sub, p = w3.recv()
        assert (m, sub) == (pm, ps) and p == bytes(size), (pm, ps, m, sub, p[:8])
    w3.send(3, 0x47, struct.pack("<I", cid2))
    m, sub, p = w3.recv()
    assert (m, sub) == (3, 0x47) and p == struct.pack("<IB", cid2, 0), (m, sub, p)
    print(f"[ok] {len(panels) + 1} panel lists (titles, mail, friends, party board, market, ...) answered empty")
    w3.send(0x18, 0x09, struct.pack("<IBH", 0x20000005, 1, 0))
    m, sub, p = w3.recv()
    assert (m, sub) == (0x18, 0x09) and p[0] == 1 and struct.unpack_from("<I", p, 3)[0] == 111011301 and len(p) == 126, (m, sub, len(p))
    for rs in (0x10, 0x11):
        w3.send(0x18, rs, struct.pack("<I", 0x20000005))
        m, sub, p = w3.recv()
        assert (m, sub) == (0x18, rs) and struct.unpack_from("<I", p, 0)[0] == 1 and p[-8:] == bytes(8), (m, sub, p[:8])
    print("[ok] ITEM_REPAIR_NPC / EQUIP / ALL 0x18/0x09,0x10,0x11: soul weapon refreshed, cost 0 (durability is full)")
    # Maze entry (Control Zone 43 Awakening 21211, Lv.2): a level-1 character
    # is refused; WORLD_ENTER_REQ 4/0x01 = u32 uaid, u32 actor, u8, u32, u16
    # map, u16 channel, i32 jump, i32 portal, ... (PS_ENTER_MAP_REQ head).
    def enter_req(mapid, portal):
        return struct.pack("<IIBIHHii", account, cid2, 0, 0, mapid, 0, 0, portal) + bytes(40)
    w3.send(0x11, 0x7E, struct.pack("<I", 90001))
    m, sub, p = w3.recv()
    assert (m, sub) == (0x11, 0x7F) and p == struct.pack("<I", 90001), (m, sub, p)
    w3.send(4, 0x01, enter_req(21211, 21211))
    m, sub, p = w3.recv()
    assert (m, sub) == (4, 0x02) and select_result(p[:-2])[3] == 0xD6E4, (m, sub, p[:8])
    print("[ok] WORLD_ENTER 4/0x01 -> 4/0x02: level 1 refused for Control Zone 43 (Lv.2, UI 0xD6E4)")
    if gm_expected:
        lv = "/level 10".encode("utf-16-le")
        w3.send(7, 0x0A, struct.pack("<H", len(lv)) + lv)
        m, sub, p = w3.recv()
        assert (m, sub) == (3, 0x36) and p == struct.pack("<IIB", cid2, 10, 1), (m, sub, p)
        w3.recv()
        print("[ok] GM /level 10 -> CHARACTER_LEVEL 3/0x36 at once")
    w3.send(4, 0x41, enter_req(21211, 21106))
    m, sub, p = w3.recv()
    whost4, wport4, minst4, res4 = select_result(p[:-2])
    if not gm_expected:
        assert (m, sub) == (4, 0x02) and res4 == 0xD6E4, (m, sub, res4)
    else:
        assert (m, sub, res4) == (4, 0x02, 0) and (minst4 >> 32) & 0xFFFF == 21211, (m, sub, res4, hex(minst4))
        # The real client stays on this connection and sends 17/0x22 once the
        # maze has loaded -> monsters must follow on the same connection.
        w3.send(0x11, 0x22, b"")
        m, sub, p = w3.recv()
        assert (m, sub) == (4, 0x23) and struct.unpack_from("<H", p, 0)[0] > 0, (m, sub)
        w3.send(0x11, 0x31, struct.pack("<I", 80101))
        m, sub, p = w3.recv()
        assert (m, sub) == (4, 0x23) and struct.unpack_from("<H", p, 0)[0] == 2, (m, sub)
        print("[ok] same connection: 17/0x22 maze loaded -> 4/0x23 monsters; check box 80101 -> 2 more")
        # The client reconnects with the new map instance and lands at the
        # maze start box (2121101).
        w4 = ClientConn(emu, whost4, wport4, mode)
        w4.send(3, 0x21, struct.pack("<IIQBQ", account, 0, minst4, 1, 0))
        m, sub, p = w4.recv()
        assert (m, sub) == (3, 0x22) and struct.unpack_from("<I", p, 0)[0] == 0, (m, sub, p[:4])
        w4.send(3, 0x31, struct.pack("<IB", cid2, 1))
        m, sub, p = w4.recv()
        assert (m, sub) == (3, 0x32), (m, sub)
        assert struct.pack("<H", 21211) + struct.pack("<Q", minst4) in p, "CHARACTER_INFO places the player in the maze"
        while True:  # quest lists + skills
            m, sub, _ = w4.recv()
            if (m, sub) == (6, 0x70):
                break
        print("[ok] maze 21211 entered: 4/0x02 -> reconnect -> CHARACTER_INFO in map 21211 (GM /level 10)")
        # Monsters fight back now: keep the scripted combat alive.
        gm_cmd(w4, "/god", {(7, 0x01)})
        # Map loaded -> NPCs + monsters; walk into check box 80101 -> 2 more.
        w4.send(0xF1, 0x01, b"")
        m, sub, _ = w4.recv()
        assert (m, sub) == (4, 0x22), (m, sub)
        m, sub, p = w4.recv()
        assert (m, sub) == (4, 0x23) and struct.unpack_from("<H", p, 0)[0] > 0, (m, sub)
        load_mons = [(struct.unpack_from("<I", p, 2 + i * 123)[0], *struct.unpack_from("<ff", p, 2 + i * 123 + 4),
                      struct.unpack_from("<I", p, 2 + i * 123 + 45)[0])
                     for i in range(struct.unpack_from("<H", p, 0)[0])]
        w4.send(0x11, 0x31, struct.pack("<I", 80101))
        m, sub, p = w4.recv()
        assert (m, sub) == (4, 0x23) and struct.unpack_from("<H", p, 0)[0] == 2, (m, sub, p[:2])
        tx, ty = struct.unpack_from("<ff", p, 2 + 4)
        target = struct.unpack_from("<I", p, 2)[0]
        print(f"[ok] maze monsters: 4/0x23 on map load and for check box 80101 (2 monsters, first {target:#x})")
        # Attack it until it dies (skill 0x00B8C8BB as captured).
        died = False
        for _ in range(40):
            w4.send(6, 0x36, struct.pack("<BI", 1, target))
            w4.send(6, 0x08, struct.pack("<IIffff", 0x00B8C8BB, 1, tx, ty, 10.0, 0.0) + bytes(26))
            m, sub, _ = w4.recv()
            assert (m, sub) == (6, 0x09), (m, sub)
            m, sub, p = w4.recv()
            assert (m, sub) == (6, 0x13) and p[0] == 1, (m, sub)
            hp = struct.unpack_from("<q", p, 1 + 4 + 2 + 16)[0]
            if hp == 0:
                m, sub, p = w4.recv()
                assert (m, sub, struct.unpack_from("<I", p, 0)[0]) == (0x17, 0x11, target), (m, sub)
                # EXP (3/0x37), maybe 3/0x36, then maybe DROP_INFOS 20/0x01.
                got = {}
                for _ in range(3):
                    w4.send(1, 0x06, struct.pack("<QQI", 0x55, 0, 0))
                    while True:
                        m, sub, p = w4.recv()
                        if (m, sub) == (1, 0x06):
                            break
                        got[(m, sub)] = p
                    if (0x14, 0x01) in got or (3, 0x37) in got:
                        break
                assert (3, 0x37) in got and struct.unpack_from("<I", got[(3, 0x37)], 8)[0] > 0, got.keys()
                if (0x14, 0x01) in got:
                    dp = got[(0x14, 0x01)]
                    group, n = struct.unpack_from("<I", dp, 0)[0], dp[5]
                    obj, cnt, _, serial = struct.unpack_from("<IIIQ", dp, 6 + 12)
                    w4.send(0x14, 0x02, struct.pack("<IQ", group, serial))
                    m, sub, p = w4.recv()
                    assert (m, sub) == (0x14, 0x02) and p == struct.pack("<QI", serial, 0), (m, sub, p)
                    m, sub, p = w4.recv(raw=True)
                    assert (m, sub) in ((8, 0x20), (8, 0x15), (8, 0x31), (8, 0x32), (3, 0x34)), (m, sub)
                    print(f"[ok] drop: 20/0x01 ({n} items, first {obj} x{cnt}) -> pick up 20/0x02 -> {m}/{sub:#x}")
                died = True
                break
        assert died, "monster never died"
        print("[ok] combat: 6/0x08 -> 6/0x09 + 6/0x13 damage until 0x17/0x11 MONSTER_DIE + 3/0x37 EXP")
        # Loot: kill map-load monsters (Howlers drop gold 100 %) until a
        # DROP_INFOS arrives, then pick the first drop up.
        dropped = None
        for actor, mx, my, mid in sorted(load_mons, key=lambda m: m[3] != 30102003):
            for _ in range(60):
                w4.send(6, 0x36, struct.pack("<BI", 1, actor))
                w4.send(6, 0x08, struct.pack("<IIffff", 0x00B8C8BB, 1, mx, my, 10.0, 0.0) + bytes(26))
                w4.send(1, 0x06, struct.pack("<QQI", 0x66, 0, 0))
                dead = False
                while True:
                    m, sub, p = w4.recv()
                    if (m, sub) == (1, 0x06):
                        break
                    if (m, sub) == (0x17, 0x11):
                        dead = True
                    if (m, sub) == (0x14, 0x01):
                        dropped = p
                if dead:
                    break
            if dropped:
                break
        assert dropped, "no monster dropped anything"
        group, n = struct.unpack_from("<I", dropped, 0)[0], dropped[5]
        obj, cnt, _, serial = struct.unpack_from("<IIIQ", dropped, 6 + 12)
        w4.send(0x14, 0x02, struct.pack("<IQ", group, serial))
        m, sub, p = w4.recv()
        assert (m, sub) == (0x14, 0x02) and p == struct.pack("<QI", serial, 0), (m, sub, p)
        m, sub, p = w4.recv(raw=True)
        want = {800000001: (8, 0x20), 800000002: (3, 0x34), 800000003: (8, 0x31), 800000004: (8, 0x32)}.get(obj, (8, 0x15))
        assert (m, sub) == want, (m, sub, obj)
        print(f"[ok] loot: DROP_INFOS 20/0x01 ({n} items, first {obj} x{cnt}) -> DROP_PICK_UP 20/0x02 -> {m}/{sub:#x}")
        w4.send(0x14, 0x02, struct.pack("<IQ", group, serial))
        m, sub, p = w4.recv()
        assert (m, sub) == (0x14, 0x02) and p == struct.pack("<QI", serial, 1), (m, sub, p)
        print("[ok] loot: picking the same drop twice is refused (result 1)")
        maze_play_checks(w4, cid2, load_mons)
        w4.send(0x11, 0x23, struct.pack("<IQiiiB", cid2, minst4, 0, 0, 0, 0))
        m, sub, p = w4.recv()
        whost5, wport5, minst5, res5 = select_result(p[:-2])
        assert (m, sub, res5) == (4, 0x02, 0) and (minst5 >> 32) & 0xFFFF == 10003, (m, sub, res5, hex(minst5))
        print("[ok] EXIT_MAZE 17/0x23 -> 4/0x02 back to Rocco Town (escape box 1000302)")
        w4.send(3, 0x5B, b"")
        m, sub, p = w4.recv()
        assert (m, sub, p) == (3, 0x5B, bytes(10)), (m, sub, p)
        w4.send(3, 0x60, struct.pack("<IIBI", cid2, account, 1, 0))
        m, sub, p = w4.recv()
        assert (m, sub) == (3, 0x60) and p[-1] == 1 and p[-6] == 1, (m, sub, p)
        print("[ok] CHARACTER_GOBACK_LOBBY 3/0x60 -> back to the character select (type 1 echoed)")
        w3.replies += w4.replies + w4.side
    w2 = ClientConn(emu, whost, wport, mode)
    w2.send(3, 0x21, struct.pack("<IIQBQ", account, 0, minst, 1, 0))
    m, sub, p = w2.recv()
    assert struct.unpack_from("<I", p, 0)[0] == 50104 and w2.closed_by_server()
    print("[ok] the same map instance cannot be used twice")

    # 9. every reply through the client's own readers
    bad = check_payloads(c.replies + c2.replies + replies_g1 + g.replies + replies_w1 + replies_w2 + w2.replies
                         + w3.replies + w3.side, emu)
    assert not bad, f"client readers rejected: {bad}"
    print("ALL OK")


def gm_cmd(conn, line, until):
    """Send a GM chat command; collect replies until a (main, sub) in `until`."""
    t = line.encode("utf-16-le")
    conn.send(7, 0x0A, struct.pack("<H", len(t)) + t)
    got = {}
    while True:
        m, sub, p = conn.recv(raw=True)
        got.setdefault((m, sub), []).append(p)
        if (m, sub) in until:
            return got


def pump(conn, rounds=1):
    """Let the server tick: ping 1/0x06 and keep everything that arrives."""
    got = {}
    for i in range(rounds):
        conn.send(1, 0x06, struct.pack("<QQI", 0x77 + i, 0, 0))
        while True:
            m, sub, p = conn.recv(raw=True)
            if (m, sub) == (1, 0x06):
                break
            got.setdefault((m, sub), []).append(p)
        time.sleep(0.25)
    return got


def maze_play_checks(w4, cid, load_mons):
    """Category 1: monster AI, player death / revive, sector flow, warp, maze reward."""
    dead = {struct.unpack_from("<I", p, 0)[0] for m, s, p in w4.replies + w4.side if (m, s) == (0x17, 0x11)}
    alive = [m for m in load_mons if m[0] not in dead]
    assert alive, "every map-load monster died already"
    actor, mx, my, _ = alive[0]
    gm_cmd(w4, "/god", {(7, 0x01)})  # off: the AI check needs HP loss
    gm_cmd(w4, "/heal", {(7, 0x01)})
    # Stand next to a monster (SKILL_SYNC_POSITION 6/0x47 sets the position).
    w4.send(6, 0x47, struct.pack("<fff", mx + 120.0, my, 30.0) + bytes(16))
    m, sub, p = w4.recv()
    assert (m, sub) == (6, 0x48) and struct.unpack_from("<I", p, 0)[0] == cid, (m, sub)
    got = pump(w4, 14)
    side = {}
    for m, s, p in w4.side:
        side.setdefault((m, s), []).append(p)
    w4.side.clear()
    for k, v in got.items():
        side.setdefault(k, []).extend(v)
    assert (0x17, 0x22) in side, f"no monster noticed the player: {sorted(side)}"
    assert struct.unpack_from("<I", side[(0x17, 0x22)][0], 4)[0] == cid
    hits = [p for p in side.get((6, 0x13), []) if is_side(6, 0x13, p)]
    assert (6, 0x10) in side and hits, f"no monster attack: {sorted(side)}"
    # 3/0x34: u32 actor, u8 n x {f32 value, u16 stat, u64}; HP_MAX first, HP_CUR second.
    hp = [struct.unpack_from("<f", p, 5 + 14)[0] for p in side.get((3, 0x34), []) if struct.unpack_from("<I", p, 0)[0] == cid and p[4] >= 2]
    assert hp and min(hp) < max(hp), hp
    bars = side.get((0x17, 0x12), [])
    # The client's 0x17/0x12 handler takes HP / max HP from the u64 of each
    # entry (f32 value, u16 stat, u64): both must be set and max > 0.
    for p in bars:
        n = p[4]
        vals = {struct.unpack_from("<H", p, 5 + 14 * i + 4)[0]: struct.unpack_from("<Q", p, 5 + 14 * i + 6)[0] for i in range(n)}
        assert vals.get(0x0A, 0) > 0 and 0x01 in vals and vals[0x01] <= vals[0x0A], vals
    print(f"[ok] monster HP bar: {len(bars)} x MONSTER_UPDATE_STAT 0x17/0x12, HP/max in the u64 the client reads")
    print(f"[ok] monster AI: target 0x17/0x22 -> skill 6/0x10 + hit 6/0x13 ({len(hits)}x), player HP {max(hp):.0f} -> {min(hp):.0f} (3/0x34)")
    # Death and revive (stand up first if the AI already killed us).
    if min(hp) == 0:
        gm_cmd(w4, "/heal", {(7, 0x01)})
    w4.side.clear()
    got = gm_cmd(w4, "/die", {(3, 0x41)})
    p = got[(3, 0x41)][0]
    assert struct.unpack_from("<I", p, 0)[0] == cid, p
    w4.send(3, 0x42, struct.pack("<IB", cid, 1))
    while True:
        m, sub, p = w4.recv()
        if (m, sub) == (3, 0x44):
            break
    assert struct.unpack_from("<IIB", p, 0) == (cid, cid, 1), p
    print("[ok] death: GM /die -> CHARACTER_DIE 3/0x41; REVIVE 3/0x42 -> 3/0x44 at the maze start, full HP")
    # Skill tree: Soulum special dash attack 12120011 needs level 13 -> refused
    # at Lv.10, learned after /level 13; deck update, reset.
    w4.send(6, 0x71, struct.pack("<II", 12120011, 0))
    while True:
        m, sub, p = w4.recv()
        if (m, sub) == (6, 0x71):
            break
    assert struct.unpack_from("<IIBB", p, 0)[3] == 0, p
    gm_cmd(w4, "/level 13", {(3, 0x36)})
    w4.send(6, 0x71, struct.pack("<II", 12120011, 0))
    while True:
        m, sub, p = w4.recv()
        if (m, sub) == (6, 0x71):
            break
    assert struct.unpack_from("<IIBB", p, 0)[3] == 1, p
    while True:
        m, sub, p = w4.recv()
        if (m, sub) == (6, 0x70):
            break
    total, free = struct.unpack_from("<HH", p, 4)
    n = struct.unpack_from("<H", p, 14)[0]
    ids = [struct.unpack_from("<I", p, 16 + 9 * i)[0] for i in range(n)]
    assert 12120011 in ids and free == total - 1, (total, free, ids)
    print(f"[ok] skill learn 6/0x71: 12120011 refused at Lv.10, learned at Lv.13 -> 6/0x70 SP {free}/{total}")
    w4.send(6, 0x75, struct.pack("<BH4I", 1, 0, 12120011, 0, 0, 0))
    m, sub, p = w4.recv()
    assert (m, sub) == (6, 0x75) and p == struct.pack("<BH4I", 1, 0, 12120011, 0, 0, 0), (m, sub, p)
    w4.send(6, 0x75, struct.pack("<BH4I", 1, 1, 99999999, 0, 0, 0))
    m, sub, p = w4.recv()
    assert (m, sub, p) == (6, 0x75, bytes(1)), (m, sub, p)
    w4.send(6, 0x72, b"")
    m, sub, p = w4.recv()
    assert (m, sub) == (6, 0x72) and struct.unpack_from("<H", p, 4)[0] == struct.unpack_from("<H", p, 6)[0], p[:8]
    print("[ok] skill deck 6/0x75 (known skill ok, unknown refused), reset 6/0x72 refunds every point")
    # Dash / emergency evade 12040011 (6/0x06) spends 20 stamina (tb_Skill).
    w4.side.clear()
    w4.send(6, 0x06, struct.pack("<I", 12040011) + bytes(50))
    got = pump(w4, 1)
    st = [struct.unpack_from("<fH", p, 5) for p in got.get((3, 0x34), []) + w4.take_side(3, 0x34)
          if struct.unpack_from("<I", p, 0)[0] == cid and p[4] >= 1]
    assert any(k == 0x03 and v <= 80.0 for v, k in st), st
    print(f"[ok] dash 6/0x06 skill 12040011 -> stamina {[round(v) for v, k in st if k == 3]} (3/0x34)")
    gm_cmd(w4, "/god", {(7, 0x01)})
    # Sector flow: clear everything that is up, walk into the last room's
    # check box, clear it, the boss wave follows, clear it -> reward.
    # Spawn steps (CSector::CheckStepCondition): killing step 1 brings
    # step 2 (e.g. the Howler Very Hard pair 40291/40292); a second /killall
    # clears it.
    gm_cmd(w4, "/killall", {(7, 0x01)})
    got = pump(w4, 2)
    step2 = sum(struct.unpack_from("<H", p, 0)[0] for p in got.get((4, 0x23), []))
    assert step2 >= 2, f"step-2 monsters did not spawn: {step2}"
    gm_cmd(w4, "/killall", {(7, 0x01)})
    got2 = pump(w4, 2)
    for k, v in got2.items():
        got.setdefault(k, []).extend(v)
    print(f"[ok] spawn steps: step 1 killed -> {step2} step-2 monsters spawn (4/0x23), then cleared")
    side = {}
    for m, s, p in w4.side:
        side.setdefault((m, s), []).append(p)
    w4.side.clear()
    for k, v in got.items():
        side.setdefault(k, []).extend(v)
    cleared = [struct.unpack_from("<I", p, 0)[0] for p in side.get((0x11, 0x52), [])]
    assert {10001, 10002} <= set(cleared), cleared
    portals = side[(0x11, 0x55)][-1]
    n_open = struct.unpack_from("<I", portals, 0)[0]
    opened = struct.unpack_from(f"<{n_open}I", portals, 8)
    assert {30001, 30002} <= set(opened), opened
    print(f"[ok] sectors {cleared} cleared (17/0x52) -> exit portals {sorted(opened)} open (17/0x55)")
    w4.send(4, 0x07, struct.pack("<III", 30002, 0, 0))
    m, sub, p = w4.recv()
    assert (m, sub) == (4, 0x08) and struct.unpack_from("<IB", p, 0) == (cid, 0), (m, sub, p[:5])
    wx, wy = struct.unpack_from("<ff", p, 5)
    assert abs(wx - 8758.2) < 1 and abs(wy - 13965.8) < 1, (wx, wy)
    print(f"[ok] WARP 4/0x07 portal 30002 -> 4/0x08 landing box 2121103 ({wx:.0f}, {wy:.0f})")
    w4.send(0x11, 0x31, struct.pack("<I", 80301))
    m, sub, p = w4.recv()
    assert (m, sub) == (4, 0x23) and struct.unpack_from("<H", p, 0)[0] == 3, (m, sub)
    gm_cmd(w4, "/killall", {(7, 0x01)})
    boss = None
    for _ in range(6):
        got = pump(w4, 1)
        if (4, 0x23) in got:
            boss = got[(4, 0x23)][0]
            break
    assert boss and struct.unpack_from("<I", boss, 2 + 45)[0] == 30102003, "boss wave (box 40100) did not spawn"
    print("[ok] boss wave: room 3 cleared -> box 40100 (30102003) spawns")
    gm_cmd(w4, "/killall", {(7, 0x01)})
    got = pump(w4, 2)
    side = {}
    for m, s, p in w4.side:
        side.setdefault((m, s), []).append(p)
    w4.side.clear()
    for k, v in got.items():
        side.setdefault(k, []).extend(v)
    assert 10003 in [struct.unpack_from("<I", p, 0)[0] for p in side.get((0x11, 0x52), [])], sorted(side)
    reward = side.get((0x11, 0x75))
    assert reward and len(reward[0]) == 210, sorted(side)
    exp, money = struct.unpack_from("<II", reward[0], 1 + 4 * 5)
    assert exp > 0 and money > 0, (exp, money)
    print(f"[ok] boss sector 10003 cleared -> MAZE_REWARD_INFO 17/0x75 (rank {reward[0][0]}, EXP {exp}, Zenny {money})")
    gm_cmd(w4, "/god", {(7, 0x01)})


def recv_cash_shop(conn):
    """9/0x20 pages (first has full_load=1) until 9/0x28, then 8/0x33. Returns the product count."""
    total, first = 0, True
    while True:
        m, sub, p = conn.recv()
        if (m, sub) == (9, 0x28):
            break
        assert (m, sub) == (9, 0x20) and p[0] == (1 if first else 0), (m, sub, p[:1])
        total += struct.unpack_from("<I", p, 1)[0]
        first = False
    m, sub, p = conn.recv()
    assert (m, sub) == (8, 0x33) and len(p) == 12, (m, sub, len(p))
    return total, struct.unpack_from("<I", p, 0)[0]


def select_result(p):
    """SELECT_CHARACTER_RES -> (host, port, map instance, result)."""
    minst = struct.unpack_from("<Q", p, 20)[0]
    host, o = str8(p, 36)
    port = struct.unpack_from("<H", p, o)[0]
    o += 2 + (2 + 8 + 16) + 1 + 2           # position, type, two u8
    return host, port, minst, struct.unpack_from("<I", p, o)[0]


FIXTURE = os.path.join(os.path.dirname(__file__), "..", "server", "tests", "fixtures", "create_character_req.hex")


def create_payload(name):
    """The real client's CREATE_CHARACTER_REQ with the name swapped."""
    p = bytes.fromhex(open(FIXTURE).read().strip())
    n = struct.unpack_from("<H", p, 4)[0]
    w = name.encode("utf-16-le")
    return p[:4] + struct.pack("<H", len(w)) + w + p[6 + n:]


if __name__ == "__main__":
    main()
