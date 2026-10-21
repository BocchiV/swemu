//! Body ciphers for modes 1 (XOR) and 3 (AES-128-CTR).
//!
//! Both operate in place on the body (everything after the 11-byte header,
//! main/sub/pad included) and are their own inverse.
//!
//! Evidence (SoulWorker64.dll 2.3.34.7, Ghidra base 0x180000000):
//! - XOR: FUN_18005b700 (send) / FUN_18005d1c0 (recv): `body[i] ^= XOR_TABLE[key & 0xF][i & 0xF]`.
//! - AES: FUN_18005b7e0 (send) / FUN_18005d1c0 (recv) build a 16-byte counter block
//!   `seq(LE u32) | flag | key | size(LE u16) | "SWPK" | 00 00 00 00` and call
//!   FUN_18005d8f0, which is textbook AES-128 (FIPS S-box at 0x1816f0eb0, Rcon at
//!   0x1816f0fb0, key schedule FUN_18005d5a0, MixColumns FUN_18005d680) in CTR mode
//!   with a 32-bit big-endian counter in bytes 12..16 (it increments bytes 15..12 only).
//!   That is exactly `ctr::Ctr32BE<Aes128>`; re/emu_wire.py checks it against the
//!   client's own code under emulation.

use super::tables::{AES_KEYS, XOR_TABLE};
use super::{Header, Mode};
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};

type Aes128Ctr32Be = ctr::Ctr32BE<Aes128>;

/// Literal in the counter block: `local_30 = 0x4b505753` stored little-endian.
const NONCE_TAG: [u8; 4] = *b"SWPK";

/// Apply (or remove — the operation is symmetric) the body cipher for `mode`.
pub fn apply(mode: Mode, header: &Header, body: &mut [u8]) {
    match mode {
        Mode::Plain => {}
        Mode::Xor => xor_in_place(header.key, body),
        Mode::Aes => aes_ctr_in_place(header, body),
    }
}

pub fn xor_in_place(key: u8, body: &mut [u8]) {
    let row = &XOR_TABLE[usize::from(key & 0x0F)];
    for chunk in body.chunks_mut(16) {
        for (b, k) in chunk.iter_mut().zip(row) {
            *b ^= k;
        }
    }
}

/// Counter block the client derives from the cleartext header.
pub fn aes_nonce(header: &Header) -> [u8; 16] {
    let mut n = [0u8; 16];
    n[0..4].copy_from_slice(&header.seq.to_le_bytes());
    n[4] = header.flag;
    n[5] = header.key;
    n[6..8].copy_from_slice(&header.size.to_le_bytes());
    n[8..12].copy_from_slice(&NONCE_TAG);
    n
}

pub fn aes_ctr_in_place(header: &Header, body: &mut [u8]) {
    let key = &AES_KEYS[usize::from(header.key & 0x0F)];
    let nonce = aes_nonce(header);
    let mut cipher = Aes128Ctr32Be::new(key.into(), (&nonce).into());
    cipher.apply_keystream(body);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_layout() {
        let h = Header { magic: 0x33, size: 0x0123, flag: 1, key: 0xF3, mode: 3, seq: 0xDEADBEEF };
        assert_eq!(
            aes_nonce(&h),
            [0xEF, 0xBE, 0xAD, 0xDE, 0x01, 0xF3, 0x23, 0x01, b'S', b'W', b'P', b'K', 0, 0, 0, 0]
        );
    }

    #[test]
    fn ciphers_are_involutions() {
        let h = Header { magic: 0x33, size: 600, flag: 2, key: 0x9A, mode: 3, seq: 77 };
        let plain: Vec<u8> = (0..589u32).map(|i| (i * 7 + 3) as u8).collect();
        for mode in [Mode::Xor, Mode::Aes] {
            let mut b = plain.clone();
            apply(mode, &h, &mut b);
            assert_ne!(b, plain, "{mode:?} must change the body");
            apply(mode, &h, &mut b);
            assert_eq!(b, plain, "{mode:?} must round-trip");
        }
    }
}
