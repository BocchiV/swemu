#!/usr/bin/env python
"""Independent client simulator for swemu, SoulWorker 2.3.34.7 wire format.

Own implementation (Python + `cryptography`), NOT derived from the Rust code.
Cipher tables are read straight from the client DLL copy in re/targets/gb2334.

Flow: LOGIN_REQ 2/1 -> LOGIN_RESULT 2/2 -> SERVER_LIST_REQ 2/3 -> 2/4
      -> SERVER_CONNECT_REQ 2/5 -> ENTER_SERVER 2/0x11
      -> (game port) ENTER_SERVER_REQ 2/0x13 -> 2/0x14 -> CHARACTER_LIST_REQ 3/0x11 -> 3/0x12
Exit 0 and "ALL OK" on success.

   python client_sim.py [--aes] [--user NAME --password PW] [host] [port]
"""
import os, socket, struct, sys

sys.path.insert(0, os.path.dirname(__file__))
from pe import PE  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

DLL = os.path.join(os.path.dirname(__file__), "..", "re", "targets", "gb2334", "SoulWorker64.dll")
_pe = PE(DLL)
XOR = [_pe.read(0x18194FA30 + 16 * r, 16) for r in range(16)]
AES = [_pe.read(0x18194FC40 + 16 * r, 16) for r in range(16)]
HDR = 11


def crypt(mode, hdr, body):
    key = hdr[5]
    if mode == 1:
        row = XOR[key & 15]
        return bytes(b ^ row[i & 15] for i, b in enumerate(body))
    if mode == 3:
        nonce = hdr[7:11] + hdr[4:6] + hdr[2:4] + b"SWPK" + b"\0" * 4
        c = Cipher(algorithms.AES(AES[key & 15]), modes.CTR(nonce)).encryptor()
        return c.update(body) + c.finalize()
    return body


class Conn:
    def __init__(self, host, port, mode):
        self.s = socket.create_connection((host, port), timeout=15)
        self.mode, self.key, self.seq, self.buf = mode, 0, 0, b""

    def send(self, main, sub, payload=b"", pad=3):
        self.key = (self.key + 1) & 0xFF
        self.seq += 1
        body = bytes([main, sub, pad]) + os.urandom(pad) + payload
        hdr = struct.pack("<HHBBBI", 0x33, HDR + len(body), 1, self.key, self.mode, self.seq)
        self.s.sendall(hdr + crypt(self.mode, hdr, body))

    def recv(self):
        while True:
            if len(self.buf) >= HDR:
                magic, size = struct.unpack_from("<HH", self.buf)
                assert magic == 0x33, f"bad magic {magic:#x}"
                if len(self.buf) >= size:
                    hdr, body, self.buf = self.buf[:HDR], self.buf[HDR:size], self.buf[size:]
                    mode = hdr[6]
                    assert mode in (1, 3), f"server sent mode {mode}; the client refuses plaintext"
                    body = crypt(mode, hdr, body)
                    pad = body[2]
                    assert pad < 8, pad
                    return body[0], body[1], body[3 + pad:]
            chunk = self.s.recv(65536)
            assert chunk, "server closed the connection"
            self.buf += chunk


def wstr(s):
    b = s.encode("utf-16-le")
    return struct.pack("<H", len(b)) + b


def rd_wstr(b, o):
    n = struct.unpack_from("<H", b, o)[0]
    return b[o + 2:o + 2 + n].decode("utf-16-le"), o + 2 + n


def str8(b, o):
    n = struct.unpack_from("<H", b, o)[0]
    return b[o + 2:o + 2 + n].decode(), o + 2 + n


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("192.0.2.1", 9))
    ip = s.getsockname()[0]
    s.close()
    return ip


def opt(name, default):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def main():
    flags = {"--user", "--password"}
    args, skip = [], False
    for a in sys.argv[1:]:
        if skip:
            skip = False
            continue
        if a in flags:
            skip = True
            continue
        if not a.startswith("--"):
            args.append(a)
    host = args[0] if args else lan_ip()
    port = int(args[1]) if len(args) > 1 else 15001
    mode = 3 if "--aes" in sys.argv else 1
    user = opt("--user", "sim_" + os.urandom(3).hex())
    password = opt("--password", "simpass")

    c = Conn(host, port, mode)
    c.send(2, 1, wstr(user) + wstr(password) + wstr("0A-1B-2C-3D-4E-5F") + struct.pack("<I", 0x989746))
    m, s, p = c.recv()
    assert (m, s) == (2, 2), (m, s)
    account = struct.unpack_from("<I", p, 0)[0]
    msg, o = rd_wstr(p, 4 + 1 + 18)
    err = struct.unpack_from("<I", p, o)[0]
    _, o = rd_wstr(p, o + 5)
    session = struct.unpack_from("<Q", p, o)[0]
    assert err == 0, f"LOGIN_RESULT error={err}"
    print(f"LOGIN_RESULT ok account={account} (client mode {mode})")

    c.send(2, 3, struct.pack("<I", account))
    m, s, p = c.recv()
    assert (m, s) == (2, 4) and p[1] == 1, (m, s, p[:2].hex())
    sid, sport = struct.unpack_from("<HH", p, 2)
    name, o = str8(p, 6)
    shost, o = str8(p, o)
    print(f"SERVER_LIST ok id={sid} name={name} host={shost}:{sport}")

    c.send(2, 5, struct.pack("<H", sid))
    m, s, p = c.recv()
    assert (m, s) == (2, 0x11), (m, s)
    print("ENTER_SERVER ok")

    g = Conn(shost, sport, mode)
    g.send(2, 0x13, struct.pack("<IHQB", account, sid, session, 0))
    m, s, p = g.recv()
    assert (m, s, p[0]) == (2, 0x14, 0), (m, s, p[:1])
    print("ENTER_SERVER_RES ok")
    g.send(3, 0x11, struct.pack("<Q", session))
    m, s, p = g.recv()
    assert (m, s) == (3, 0x12), (m, s)
    print(f"CHARACTER_LIST_RES ok ({p[0]} characters)")
    print("ALL OK")


if __name__ == "__main__":
    main()
