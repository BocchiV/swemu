//! Little-endian payload reader/writer with the string encodings the GB client uses.
//!
//! String encodings seen so far (each one must be confirmed per-packet against
//! the client's decompiled reader before relying on it):
//! - `str8`:  `[u16 byte_len][bytes]` (no terminator) — SERVER_LIST Name/Host,
//!   SERVER_CONNECT_RES ip (std::string serializer in the reconstructed server).
//! - `wstr`:  `[u16 byte_len][UTF-16LE]` — std::wstring serializer
//!   (Parse.h WriteWideString/GetWString: the prefix is a BYTE count).

#[derive(Debug)]
pub struct ReadError(pub &'static str);

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "payload read error: {}", self.0)
    }
}
impl std::error::Error for ReadError {}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
        if self.pos + n > self.buf.len() {
            return Err(ReadError("unexpected end of payload"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, ReadError> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, ReadError> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32, ReadError> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, ReadError> {
        let b = self.bytes(8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }
    pub fn str8(&mut self) -> Result<String, ReadError> {
        let n = self.u16()? as usize;
        let b = self.bytes(n)?;
        Ok(String::from_utf8_lossy(b).trim_end_matches('\0').to_string())
    }
    pub fn wstr(&mut self) -> Result<String, ReadError> {
        // [u16 BYTE length][UTF-16LE] — Parse.h GetWString/WriteWideString.
        let n = self.u16()? as usize;
        if n % 2 != 0 {
            return Err(ReadError("odd utf-16 byte length"));
        }
        let b = self.bytes(n)?;
        let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Ok(String::from_utf16_lossy(&units).trim_end_matches('\0').to_string())
    }
}

#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    pub fn zeros(&mut self, n: usize) -> &mut Self {
        self.buf.resize(self.buf.len() + n, 0);
        self
    }
    pub fn str8(&mut self, s: &str) -> &mut Self {
        self.u16(s.len() as u16);
        self.bytes(s.as_bytes())
    }
    pub fn wstr(&mut self, s: &str) -> &mut Self {
        let units: Vec<u16> = s.encode_utf16().collect();
        self.u16((units.len() * 2) as u16);
        for u in units {
            self.u16(u);
        }
        self
    }
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

pub fn hexdump(data: &[u8]) -> String {
    let mut s = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02X}")).collect();
        let asc: String = chunk.iter().map(|&b| if (32..127).contains(&b) { b as char } else { '.' }).collect();
        s.push_str(&format!("  {:04X}: {:<48} {}\n", i * 16, hex.join(" "), asc));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_roundtrip() {
        let mut w = Writer::new();
        w.str8("127.0.0.1").wstr("Haru").u32(0xDEADBEEF);
        let b = w.finish();
        let mut r = Reader::new(&b);
        assert_eq!(r.str8().unwrap(), "127.0.0.1");
        assert_eq!(r.wstr().unwrap(), "Haru");
        assert_eq!(r.u32().unwrap(), 0xDEADBEEF);
        assert!(r.remaining().is_empty());
    }

    #[test]
    fn short_read_errors() {
        let mut r = Reader::new(&[1]);
        assert!(r.u16().is_err());
    }
}
