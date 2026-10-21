use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Address to listen on. "auto" = this machine's LAN address (see `public_ip`).
    pub bind_ip: String,
    /// Address the client is told to connect to (login IP and game host).
    /// The 2.3.34.7 client only accepts a login IP that starts with "192.168"
    /// or "172.30." (or is on its built-in official list); anything else,
    /// including 127.0.0.1, is silently replaced by 192.168.1.1
    /// (FUN_1804b4ea0). "auto" picks this machine's address on the default route.
    pub public_ip: String,
    pub login_port: u16,
    pub game_port: u16,
    /// Local VFun HTTP stub (0 disables).
    pub vfun_port: u16,
    pub server_id: u16,
    /// 1..=20 bytes (client reader limit, FUN_180034ea0).
    pub server_name: String,
    pub db_path: String,
    pub log_dir: String,
    /// First ID/password login with an unknown name creates the account.
    pub auto_register: bool,
    /// Accept LOGIN_FOR_VFUN (2/0x23) launcher tokens without a password.
    /// Off by default: the token is not verified against any VFun service.
    pub allow_launcher_token: bool,
    /// Login -> game server ticket lifetime.
    pub session_ttl_secs: u64,
    /// Connection is closed after this many failed logins.
    pub max_login_failures: u32,
    /// Buying never spends cash. Off by default: each account has a real
    /// balance that starts at `start_cash`.
    pub unlimited_cash: bool,
    /// Cash a new account starts with (test server: effectively unlimited).
    pub start_cash: u32,
    /// Account names (case-insensitive) that get GM level 1: the client then
    /// sends tb_ChattingCommand commands (/item ...) as 7/0x0A.
    pub gm_accounts: Vec<String>,
    /// Zenny (game money) a new character starts with.
    #[serde(default = "default_start_zenny")]
    pub start_zenny: u64,
}

fn default_start_zenny() -> u64 {
    1_000_000
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_ip: "auto".into(),
            public_ip: "auto".into(),
            login_port: 15001,
            game_port: 10200,
            vfun_port: 0,
            server_id: 1,
            server_name: "SoulWorker".into(),
            db_path: "data/swemu.db".into(),
            log_dir: "log".into(),
            auto_register: true,
            allow_launcher_token: false,
            session_ttl_secs: 1800,
            max_login_failures: 5,
            unlimited_cash: false,
            start_cash: 999_999_999,
            gm_accounts: Vec::new(),
            start_zenny: default_start_zenny(),
        }
    }
}

impl Config {
    pub fn load_or_default(path: &str) -> anyhow::Result<Self> {
        let mut c = match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let c = Self::default();
                std::fs::write(path, serde_json::to_string_pretty(&c)?)?;
                c
            }
            Err(e) => return Err(e.into()),
        };
        c.resolve()?;
        Ok(c)
    }

    /// Replace "auto" addresses and check the values the client will reject.
    pub fn resolve(&mut self) -> anyhow::Result<()> {
        if self.public_ip == "auto" {
            self.public_ip = detect_lan_ip()?;
        }
        if self.bind_ip == "auto" {
            self.bind_ip = self.public_ip.clone();
        }
        if !client_accepts_login_ip(&self.public_ip) {
            anyhow::bail!(
                "public_ip {} is refused by the 2.3.34.7 client (needs 192.168.x.x or 172.30.x.x); \
                 set public_ip/bind_ip to this machine's LAN address or \"auto\"",
                self.public_ip
            );
        }
        if self.server_name.is_empty() || self.server_name.len() > 20 {
            anyhow::bail!("server_name must be 1..=20 bytes (client limit)");
        }
        Ok(())
    }
}

/// Mirrors FUN_1804b4ea0's non-list rule: first 7 characters "192.168" or "172.30.".
pub fn client_accepts_login_ip(ip: &str) -> bool {
    ip.starts_with("192.168") || ip.starts_with("172.30.")
}

/// Local address of the default route, without sending any packet.
fn detect_lan_ip() -> anyhow::Result<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.connect("192.0.2.1:9")?; // TEST-NET-1, never actually contacted
    let ip = sock.local_addr()?.ip().to_string();
    if !client_accepts_login_ip(&ip) {
        anyhow::bail!("detected LAN address {ip} is not 192.168.x.x/172.30.x.x; set public_ip manually");
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_ip_rule_matches_client() {
        assert!(client_accepts_login_ip("192.168.0.100"));
        assert!(client_accepts_login_ip("172.30.0.5"));
        assert!(!client_accepts_login_ip("127.0.0.1"));
        assert!(!client_accepts_login_ip("10.0.0.2"));
        assert!(!client_accepts_login_ip("172.31.0.1"));
    }

    #[test]
    fn resolve_rejects_loopback() {
        let mut c = Config { public_ip: "127.0.0.1".into(), bind_ip: "127.0.0.1".into(), ..Config::default() };
        assert!(c.resolve().is_err());
        let mut c = Config { public_ip: "192.168.5.5".into(), bind_ip: "auto".into(), ..Config::default() };
        c.resolve().unwrap();
        assert_eq!(c.bind_ip, "192.168.5.5");
    }
}
