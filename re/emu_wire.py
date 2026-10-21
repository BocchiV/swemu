#!/usr/bin/env python
"""Run the 2.3.34 client's own wire-crypto functions under Unicorn and compare
them with an independent reference implementation (Python + `cryptography`).

   .venv/Scripts/python.exe emu_wire.py            -> runs all checks
   .venv/Scripts/python.exe emu_wire.py --vectors  -> also prints golden vectors

Target: re/targets/gb2334/SoulWorker64.dll (sha256 cbe04466...).
Functions (Ghidra image base 0x180000000):
  FUN_18005d8f0  AES-128-CTR core (key, iv16, buf, len)
  FUN_18005b680  encrypt mode 0 (pkt, out, &outlen)
  FUN_18005b700  encrypt mode 1 / XOR
  FUN_18005b7e0  encrypt mode 3 / AES-CTR
  FUN_18005d1c0  decrypt (this, cur_mode, key_idx, src, dst) -> bool
"""
import hashlib, os, random, struct, sys
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DLL = os.path.join(os.path.dirname(__file__), "targets", "gb2334", "SoulWorker64.dll")
SHA = "cbe044661fa7d1b7b5d41cfda9015932fff4dac0943510f2b91aa0563fa35634"

XOR_TABLE_VA = 0x18194FA30   # 16 rows x 16 bytes
AES_KEYS_VA = 0x18194FC40    # 16 keys x 16 bytes
F_AES = 0x18005D8F0
F_ENC0, F_ENC1, F_ENC3 = 0x18005B680, 0x18005B700, 0x18005B7E0
F_DEC = 0x18005D1C0

STUB = 0x7_0000_0000      # import stubs
STACK = 0x7_1000_0000
HEAP = 0x7_2000_0000
RET = 0x7_3000_0000       # sentinel return address
CHKSTK = 0x1812BB690      # MSVC __chkstk

# Allocators the payload readers use to grow std::vector (bump-allocated, never freed).
ALLOC_FUNCS = {"??2@YAPEAX_K@Z", "??_U@YAPEAX_K@Z", "malloc", "VBaseAlloc_rel"}
FREE_FUNCS = {"??3@YAXPEAX@Z", "??3@YAXPEAX_K@Z", "??_V@YAXPEAX@Z", "free", "VBaseDealloc_rel"}


class Emu:
    def __init__(self, path):
        d = open(path, "rb").read()
        assert hashlib.sha256(d).hexdigest() == SHA, "unexpected DLL"
        self.d = d
        e = struct.unpack_from("<I", d, 0x3C)[0]
        nsec = struct.unpack_from("<H", d, e + 6)[0]
        optsz = struct.unpack_from("<H", d, e + 20)[0]
        opt = e + 24
        self.base = struct.unpack_from("<Q", d, opt + 24)[0]
        size_img = struct.unpack_from("<I", d, opt + 56)[0]
        size_hdr = struct.unpack_from("<I", d, opt + 60)[0]
        imp_rva = struct.unpack_from("<I", d, opt + 112 + 8)[0]
        u = Uc(UC_ARCH_X86, UC_MODE_64)
        u.mem_map(self.base, (size_img + 0xFFF) & ~0xFFF)
        u.mem_write(self.base, d[:size_hdr])
        so = opt + optsz
        self.secs = []
        for i in range(nsec):
            o = so + i * 40
            vsz, va, rsz, raw = struct.unpack_from("<IIII", d, o + 8)
            u.mem_write(self.base + va, d[raw:raw + min(rsz, max(vsz, rsz))])
            self.secs.append((va, max(vsz, rsz), raw, rsz))
        u.mem_map(STUB, 0x100000)
        u.mem_map(STACK, 0x100000)
        u.mem_map(HEAP, 0x4000000)
        u.mem_map(RET, 0x1000)
        u.mem_write(STUB, b"\xC3" * 0x100000)  # every stub is a plain `ret`
        u.mem_write(RET, b"\xF4")              # hlt
        self.u = u
        self.stubs = {}
        self._bind_imports(imp_rva)
        u.hook_add(UC_HOOK_CODE, self._on_stub, begin=STUB, end=STUB + 0xFFFFF)
        u.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_unmapped)
        # __chkstk (0x1812bb690) probes the TEB stack limit via gs:[0x10], which is
        # not set up here. The emulated stack is fully mapped, so make it a no-op.
        u.mem_write(CHKSTK, b"\xC3")
        self.heap = HEAP

    def _rva2off(self, rva):
        for va, vs, raw, rs in self.secs:
            if va <= rva < va + vs:
                return raw + (rva - va)
        raise ValueError(hex(rva))

    def _cstr(self, rva):
        o = self._rva2off(rva)
        return self.d[o:self.d.index(b"\0", o)].decode()

    def _bind_imports(self, imp_rva):
        n = 0
        o = self._rva2off(imp_rva)
        while True:
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", self.d, o)
            if name_rva == 0:
                break
            dll = self._cstr(name_rva)
            thunk = oft or ft
            i = 0
            while True:
                v = struct.unpack_from("<Q", self.d, self._rva2off(thunk) + i * 8)[0]
                if v == 0:
                    break
                fn = f"#{v & 0xFFFF}" if v >> 63 else self._cstr((v & 0x7FFFFFFF) + 2)
                addr = STUB + n * 16
                self.stubs[addr] = f"{dll}!{fn}"
                self.u.mem_write(self.base + ft + i * 8, struct.pack("<Q", addr))
                n += 1
                i += 1
            o += 20

    def _on_stub(self, u, addr, size, _):
        name = self.stubs.get(addr)
        if name is None:
            return
        fn = name.split("!")[1]
        a, b, c = u.reg_read(UC_X86_REG_RCX), u.reg_read(UC_X86_REG_RDX), u.reg_read(UC_X86_REG_R8)
        if fn in ("memcpy", "memmove"):
            if c:
                u.mem_write(a, bytes(u.mem_read(b, c)))
            u.reg_write(UC_X86_REG_RAX, a)
        elif fn == "memset":
            u.mem_write(a, bytes([b & 0xFF]) * c)
            u.reg_write(UC_X86_REG_RAX, a)
        elif fn == "lstrlenW":
            n = 0
            while bytes(u.mem_read(a + 2 * n, 2)) != b"\0\0":
                n += 1
            u.reg_write(UC_X86_REG_RAX, n)
        elif fn in ALLOC_FUNCS or "VBaseAlloc" in fn:
            u.reg_write(UC_X86_REG_RAX, self.alloc(max(a, 1)))
        elif fn in FREE_FUNCS or "VBaseDealloc" in fn:
            pass
        elif fn == "strstr":
            hay, needle = self._read_c(a), self._read_c(b)
            i = hay.find(needle)
            u.reg_write(UC_X86_REG_RAX, 0 if i < 0 else a + i)
        elif fn == "_strlwr":
            u.mem_write(a, self._read_c(a).lower())
            u.reg_write(UC_X86_REG_RAX, a)
        elif fn == "strcpy_s":  # (dst, size, src) -> 0 on success; item readers copy short strings
            src = self._read_c(c, limit=max(b, 1))
            u.mem_write(a, src[: max(b - 1, 0)] + b"\0")
            u.reg_write(UC_X86_REG_RAX, 0 if len(src) < b else 34)  # 34 = ERANGE
        else:
            raise RuntimeError(f"unhandled import {name}")

    def _read_c(self, addr, limit=0x4000):
        """NUL-terminated byte string from emulator memory."""
        out = bytearray()
        while len(out) < limit:
            ch = bytes(self.u.mem_read(addr + len(out), 1))
            if ch == b"\0":
                break
            out += ch
        return bytes(out)

    def _on_unmapped(self, u, access, addr, size, value, _):
        rip = u.reg_read(UC_X86_REG_RIP)
        raise RuntimeError(f"unmapped access {addr:#x} at rip {rip:#x}")

    def alloc(self, data_or_size):
        data = bytes(data_or_size) if not isinstance(data_or_size, int) else b"\0" * data_or_size
        addr = self.heap
        self.u.mem_write(addr, data)
        self.heap += (len(data) + 0x10F) & ~0xF
        return addr

    def reset_heap(self, keep=0):
        self.heap = HEAP + keep

    def read(self, addr, n):
        return bytes(self.u.mem_read(addr, n))

    def call(self, fn, *args):
        u = self.u
        sp = STACK + 0x80000
        regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        stack_args = list(args[4:])
        sp -= 8 * (4 + len(stack_args)) + 8
        sp &= ~0xF
        sp -= 8
        u.mem_write(sp, struct.pack("<Q", RET))
        for i, v in enumerate(stack_args):
            u.mem_write(sp + 8 + 0x20 + 8 * i, struct.pack("<Q", v))
        for r, v in zip(regs, args):
            u.reg_write(r, v)
        u.reg_write(UC_X86_REG_RSP, sp)
        u.emu_start(fn, RET, timeout=20_000_000)
        return u.reg_read(UC_X86_REG_RAX)

    def table(self, va):
        return [self.read(va + 16 * r, 16) for r in range(16)]


# ---------------- independent reference (mirrors swemu/server/src/wire.rs) ----------------
HDR = 11

def ref_nonce(hdr11):
    seq = hdr11[7:11]
    size = hdr11[2:4]
    return bytes(seq) + bytes([hdr11[4], hdr11[5]]) + bytes(size) + b"SWPK" + b"\0" * 4

def ref_aes_ctr(key, nonce, data):
    c = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return c.update(data) + c.finalize()

def ref_encode(xor_tab, aes_keys, ver, flag, key_idx, mode, seq, body):
    size = HDR + len(body)
    hdr = struct.pack("<HHBBBI", ver, size, flag, key_idx, mode, seq)
    if mode == 1:
        row = xor_tab[key_idx & 0xF]
        enc = bytes(b ^ row[i & 0xF] for i, b in enumerate(body))
    elif mode == 3:
        enc = ref_aes_ctr(aes_keys[key_idx & 0xF], ref_nonce(hdr), body)
    else:
        enc = bytes(body)
    return hdr + enc


def build_pkt_struct(emu, ver, flag, key_idx, mode, seq, body):
    """In-memory packet object as laid out by FUN_18005b5f0 (pktinit)."""
    s = bytearray(0x40)
    struct.pack_into("<HHBBBI", s, 0, ver, 0, flag, key_idx, mode, seq)
    bp = emu.alloc(body if body else b"\0")
    struct.pack_into("<Q", s, 0x0B, bp)
    struct.pack_into("<H", s, 0x17, len(body))
    return emu.alloc(s)


F_WSTR = 0x18000E430  # payload writer: u16 byte length + UTF-16LE (lstrlenW, no terminator)


def client_encrypt(emu, fn, flag, key_idx, mode, seq, body):
    emu.reset_heap()
    p = build_pkt_struct(emu, 0x33, flag, key_idx, mode, seq, body)
    out, lenp = emu.alloc(0x10000), emu.alloc(8)
    assert emu.call(fn, p, out, lenp) & 0xFF == 1
    return emu.read(out, struct.unpack("<H", emu.read(lenp, 2))[0])


def client_login_payload(emu, user, password, mac):
    """LOGIN_REQ 2/1 payload exactly as FUN_1805f5840 builds it: three FUN_18000e430
    calls (user, password, MAC text) then a raw u32 0x989746."""
    emu.reset_heap()
    buf = emu.alloc(0x1000)
    w = emu.alloc(struct.pack("<QIH", buf, 0, 0) + b"\0" * 0x12)
    for s in (user, password, mac):
        emu.call(F_WSTR, w, emu.alloc(s.encode("utf-16-le") + b"\0\0"))
    pos = struct.unpack("<H", emu.read(w + 0xC, 2))[0]
    return emu.read(buf, pos) + struct.pack("<I", 0x989746)


def golden(emu):
    """Frames produced by the client's own encrypt functions, for Rust unit tests."""
    login = client_login_payload(emu, "haru", "pässwörd", "0A-1B-2C-3D-4E-5F")
    cases = [
        ("LOGIN_MODE1", F_ENC1, 1, 0x01, 1, 1, bytes([2, 1, 0]) + login),
        ("AES_PAD5", F_ENC3, 1, 0x27, 3, 0x102, bytes([2, 3, 5]) + bytes(range(0xA1, 0xA6)) + bytes(4) + bytes(range(40))),
        ("AES_ROW_MASK", F_ENC3, 1, 0xF3, 3, 0xDEADBEEF, bytes([1, 5, 0]) + b"keepalive-payload-xyz"),
        ("XOR_PAD7", F_ENC1, 1, 0xFE, 1, 7, bytes([9, 9, 7]) + bytes(7) + b"after-pad"),
        ("PLAIN", F_ENC0, 1, 0x00, 0, 2, bytes([1, 5, 0]) + b"\x01\x02\x03\x04"),
    ]
    print(f"\n// login payload ({len(login)} bytes)\nLOGIN_PAYLOAD = \"{login.hex()}\"")
    for name, fn, flag, key, mode, seq, body in cases:
        wire = client_encrypt(emu, fn, flag, key, mode, seq, body)
        print(f"{name}: body={body.hex()}\n{name}: wire={wire.hex()}")


def emit_rust(emu, outdir):
    """Write src/wire/tables.rs and src/wire/golden.rs straight from the DLL so no
    table byte is ever transcribed by hand."""
    rnd = random.Random(0x2334)
    rows = lambda t: "\n".join("    [" + ", ".join(f"0x{b:02X}" for b in r) + "]," for r in t)
    head = (f"//! GENERATED by swemu/re/emu_wire.py --emit-rust from SoulWorker64.dll 2.3.34.7\n"
            f"//! (sha256 {SHA}). Do not edit by hand.\n")
    tables = head + f"""
/// Mode 1 XOR rows, `DAT_18194fa30` (16 x 16). Row = header key byte & 0x0F.
pub const XOR_TABLE: [[u8; 16]; 16] = [
{rows(emu.table(XOR_TABLE_VA))}
];

/// Mode 3 AES-128 keys, `DAT_18194fc40` (16 x 16). Key = header key byte & 0x0F.
pub const AES_KEYS: [[u8; 16]; 16] = [
{rows(emu.table(AES_KEYS_VA))}
];
"""
    user, pw, mac = "haru", "pässwörd", "0A-1B-2C-3D-4E-5F"
    login = client_login_payload(emu, user, pw, mac)
    cases = [
        ("login_mode1", F_ENC1, 1, 0x01, 1, 1, bytes([2, 1, 0]) + login),
        ("aes_pad5", F_ENC3, 1, 0x27, 3, 0x102, bytes([2, 3, 5]) + bytes(range(0xA1, 0xA6)) + bytes(range(40))),
        ("aes_key_hi_nibble", F_ENC3, 1, 0xF3, 3, 0xDEADBEEF, bytes([1, 5, 0]) + b"keepalive-payload-xyz"),
        ("xor_pad7", F_ENC1, 1, 0xFE, 1, 7, bytes([9, 9, 7]) + bytes(7) + b"after-pad"),
        ("plain", F_ENC0, 1, 0x00, 0, 2, bytes([1, 5, 0]) + b"\x01\x02\x03\x04"),
        ("aes_multiblock", F_ENC3, 1, 0x05, 3, 0x7FFFFFFF, bytes([3, 1, 0]) + bytes(rnd.getrandbits(8) for _ in range(1000))),
    ]
    for mode, fn in ((1, F_ENC1), (3, F_ENC3)):
        for row in range(16):
            pad = rnd.randrange(8)
            body = bytes([rnd.randrange(1, 256), rnd.randrange(256), pad])
            body += bytes(rnd.getrandbits(8) for _ in range(pad + rnd.randrange(0, 70)))
            key = row | (rnd.randrange(16) << 4)
            cases.append((f"{'xor' if mode == 1 else 'aes'}_row{row:02}", fn, 1, key, mode, rnd.getrandbits(32), body))
    out = [head, "//! Every `wire` frame below was produced by the client's own encrypt routine\n",
           "//! (FUN_18005b680 / FUN_18005b700 / FUN_18005b7e0) running under Unicorn.\n\n",
           f"/// LOGIN_REQ 2/1 payload built by the client's writer for ({user!r}, {pw!r}, {mac!r}).\n",
           f"pub const LOGIN_PAYLOAD: &str = \"{login.hex()}\";\n",
           f"pub const LOGIN_USER: &str = {json_str(user)};\npub const LOGIN_PASSWORD: &str = {json_str(pw)};\n",
           f"pub const LOGIN_MAC: &str = {json_str(mac)};\n\n",
           "/// (name, plaintext body = main|sub|pad|pad bytes|payload, wire frame)\n",
           "pub const VECTORS: &[(&str, &str, &str)] = &[\n"]
    for name, fn, flag, key, mode, seq, body in cases:
        wire = client_encrypt(emu, fn, flag, key, mode, seq, body)
        out.append(f"    (\"{name}\", \"{body.hex()}\", \"{wire.hex()}\"),\n")
    out.append("];\n")
    os.makedirs(outdir, exist_ok=True)
    open(os.path.join(outdir, "tables.rs"), "w", encoding="utf-8", newline="\n").write(tables)
    open(os.path.join(outdir, "golden.rs"), "w", encoding="utf-8", newline="\n").write("".join(out))
    print(f"[ok] wrote tables.rs and golden.rs ({len(cases)} vectors) to {outdir}")


def json_str(s):
    import json
    return json.dumps(s, ensure_ascii=False)


def main():
    rnd = random.Random(2334)
    emu = Emu(DLL)
    xor_tab = emu.table(XOR_TABLE_VA)
    aes_keys = emu.table(AES_KEYS_VA)
    ok = 0

    # 1. AES core == standard AES-128-CTR (128-bit BE counter) for every key row.
    for row in range(16):
        for n in (1, 15, 16, 17, 100, 4096):
            iv = bytes(rnd.getrandbits(8) for _ in range(12)) + b"\0\0\0\0"
            data = bytes(rnd.getrandbits(8) for _ in range(n))
            kp, ivp, bp = emu.alloc(aes_keys[row]), emu.alloc(iv), emu.alloc(data)
            emu.call(F_AES, kp, ivp, bp, n)
            assert emu.read(bp, n) == ref_aes_ctr(aes_keys[row], iv, data), (row, n)
            ok += 1
    print(f"[ok] AES core matches AES-128-CTR for 16 keys x 6 lengths ({ok} cases)")

    # 2. Client encrypt (send path) == reference encoder, all three modes.
    vectors = []
    for mode, fn in ((0, F_ENC0), (1, F_ENC1), (3, F_ENC3)):
        for t in range(40):
            emu.reset_heap()
            key_idx = rnd.getrandbits(8)
            seq = rnd.getrandbits(32)
            pad = rnd.randrange(8)
            body = bytes([2, 1, pad]) + bytes(rnd.getrandbits(8) for _ in range(pad + rnd.randrange(0, 300)))
            p = build_pkt_struct(emu, 0x33, 1, key_idx, mode, seq, body)
            out = emu.alloc(0x10000)
            lenp = emu.alloc(8)
            r = emu.call(fn, p, out, lenp)
            n = struct.unpack("<H", emu.read(lenp, 2))[0]
            got = emu.read(out, n)
            exp = ref_encode(xor_tab, aes_keys, 0x33, 1, key_idx, mode, seq, body)
            assert r & 0xFF == 1 and got == exp, (mode, t, got.hex(), exp.hex())
            if t == 0:
                vectors.append((mode, key_idx, seq, body, got))
        print(f"[ok] client encrypt mode {mode} == reference (40 random packets)")

    # 3. Server-encoded frames are accepted and decrypted by the client's own receive path.
    emu.reset_heap()
    this = emu.alloc(0x10200)
    keep = emu.heap - HEAP
    for mode in (1, 3):
        for t in range(40):
            emu.reset_heap(keep)
            key_idx = rnd.getrandbits(8)
            body = bytes([1, 5, 0]) + bytes(rnd.getrandbits(8) for _ in range(rnd.randrange(0, 500)))
            wire = ref_encode(xor_tab, aes_keys, 0x33, 2, key_idx, mode, rnd.getrandbits(32), body)
            src, dst = emu.alloc(wire), emu.alloc(len(wire) + 16)
            r = emu.call(F_DEC, this, 1, key_idx, src, dst)
            assert r & 0xFF == 1
            assert emu.read(dst + HDR, len(body)) == body, (mode, t)
            assert struct.unpack("<I", emu.read(this + 0x100C0, 4))[0] == mode
        print(f"[ok] client decrypt accepts server mode {mode} frames and switches send mode to {mode}")

    # 4. Plaintext (mode 0) is rejected once the connection is encrypted; accepted before.
    wire = ref_encode(xor_tab, aes_keys, 0x33, 2, 0, 0, 0, bytes([1, 5, 0]))
    src, dst = emu.alloc(wire), emu.alloc(64)
    assert emu.call(F_DEC, this, 1, 0, src, dst) & 0xFF == 0
    assert emu.call(F_DEC, this, 0, 0, src, dst) & 0xFF == 1
    print("[ok] mode-0 frame rejected when client mode != 0, accepted when client mode == 0")

    if "--golden" in sys.argv:
        golden(emu)

    if "--emit-rust" in sys.argv:
        emit_rust(emu, sys.argv[sys.argv.index("--emit-rust") + 1])

    if "--vectors" in sys.argv:
        print("\nXOR_TABLE:")
        for r in xor_tab:
            print("    [" + ", ".join(f"0x{b:02X}" for b in r) + "],")
        print("AES_KEYS:")
        for r in aes_keys:
            print("    [" + ", ".join(f"0x{b:02X}" for b in r) + "],")
        for mode, key_idx, seq, body, got in vectors:
            print(f"\nmode={mode} key={key_idx} seq={seq:#x}\n body={body[:40].hex()}... ({len(body)})\n wire={got[:48].hex()}... ({len(got)})")
    print("ALL OK")


if __name__ == "__main__":
    main()
