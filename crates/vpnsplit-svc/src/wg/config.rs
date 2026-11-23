//! Разбор обычного конфига WireGuard (.conf).
//!
//! Формат взят стандартный, чтобы можно было положить рядом тот же файл,
//! который понимает официальный клиент, без переписывания.
//!
//! Собственный разбор base64 и INI сделан намеренно: крейт пока без внешних
//! зависимостей, кроме windows-sys, а объём задачи здесь — полсотни строк.

use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

pub const KEY_LEN: usize = 32;

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Syntax { line: usize, message: String },
    Missing(&'static str),
    BadKey(&'static str),
    Resolve { endpoint: String, source: std::io::Error },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "не удалось прочитать конфиг: {e}"),
            ConfigError::Syntax { line, message } => write!(f, "строка {line}: {message}"),
            ConfigError::Missing(field) => write!(f, "в конфиге нет обязательного поля {field}"),
            ConfigError::BadKey(field) => {
                write!(f, "поле {field} не является ключом base64 длиной 32 байта")
            }
            ConfigError::Resolve { endpoint, source } => {
                write!(f, "не удалось разрешить endpoint {endpoint}: {source}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Подсеть: адрес и длина префикса.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IpNet {
    pub addr: IpAddr,
    pub cidr: u8,
}

#[derive(Clone, Debug)]
pub struct TunnelConfig {
    pub private_key: [u8; KEY_LEN],
    pub listen_port: u16,
    /// Адреса, назначаемые на WG-интерфейс.
    pub addresses: Vec<IpNet>,
    pub mtu: u32,
    /// Используется DNS-прокси на Этапе 8.
    #[allow(dead_code)]
    pub dns: Vec<IpAddr>,
    pub peer: PeerConfig,
}

#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub public_key: [u8; KEY_LEN],
    pub preshared_key: Option<[u8; KEY_LEN]>,
    pub allowed_ips: Vec<IpNet>,
    /// Исходная строка endpoint, как её написал пользователь.
    pub endpoint_raw: String,
    pub endpoint: SocketAddr,
    pub persistent_keepalive: u16,
}

impl TunnelConfig {
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut section = String::new();
        let mut private_key = None;
        let mut listen_port = 0u16;
        let mut addresses = Vec::new();
        let mut mtu = vpnsplit_core::WG_MTU;
        let mut dns = Vec::new();
        let mut public_key = None;
        let mut preshared_key = None;
        let mut allowed_ips = Vec::new();
        let mut endpoint_raw = None;
        let mut keepalive = 0u16;

        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                section = name.trim().to_ascii_lowercase();
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| ConfigError::Syntax {
                line: line_no,
                message: "ожидалось «ключ = значение»".to_owned(),
            })?;
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();

            let syntax = |message: String| ConfigError::Syntax { line: line_no, message };

            match (section.as_str(), key.as_str()) {
                ("interface", "privatekey") => {
                    private_key = Some(decode_key(value).ok_or(ConfigError::BadKey("PrivateKey"))?)
                }
                ("interface", "listenport") => {
                    listen_port = value.parse().map_err(|_| syntax("ListenPort не число".into()))?
                }
                ("interface", "address") => {
                    for part in value.split(',') {
                        addresses.push(parse_net(part.trim()).map_err(syntax)?);
                    }
                }
                ("interface", "mtu") => {
                    mtu = value.parse().map_err(|_| syntax("MTU не число".into()))?
                }
                ("interface", "dns") => {
                    for part in value.split(',') {
                        let part = part.trim();
                        dns.push(part.parse().map_err(|_| syntax(format!("DNS: «{part}» не адрес")))?);
                    }
                }
                ("peer", "publickey") => {
                    public_key = Some(decode_key(value).ok_or(ConfigError::BadKey("PublicKey"))?)
                }
                ("peer", "presharedkey") => {
                    preshared_key = Some(decode_key(value).ok_or(ConfigError::BadKey("PresharedKey"))?)
                }
                ("peer", "allowedips") => {
                    for part in value.split(',') {
                        allowed_ips.push(parse_net(part.trim()).map_err(syntax)?);
                    }
                }
                ("peer", "endpoint") => endpoint_raw = Some(value.to_owned()),
                ("peer", "persistentkeepalive") => {
                    keepalive = value.parse().map_err(|_| syntax("PersistentKeepalive не число".into()))?
                }
                _ => {} // неизвестные ключи игнорируются, как и в официальном клиенте
            }
        }

        let endpoint_raw = endpoint_raw.ok_or(ConfigError::Missing("Peer.Endpoint"))?;
        let endpoint = endpoint_raw
            .to_socket_addrs()
            .map_err(|source| ConfigError::Resolve {
                endpoint: endpoint_raw.clone(),
                source,
            })?
            .next()
            .ok_or_else(|| ConfigError::Resolve {
                endpoint: endpoint_raw.clone(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "пустой ответ резолвера"),
            })?;

        Ok(TunnelConfig {
            private_key: private_key.ok_or(ConfigError::Missing("Interface.PrivateKey"))?,
            listen_port,
            addresses,
            mtu,
            dns,
            peer: PeerConfig {
                public_key: public_key.ok_or(ConfigError::Missing("Peer.PublicKey"))?,
                preshared_key,
                allowed_ips,
                endpoint_raw,
                endpoint,
                persistent_keepalive: keepalive,
            },
        })
    }
}

fn strip_comment(line: &str) -> &str {
    match line.find(['#', ';']) {
        Some(pos) => &line[..pos],
        None => line,
    }
}

fn parse_net(text: &str) -> Result<IpNet, String> {
    let (addr_text, cidr_text) = match text.split_once('/') {
        Some((a, c)) => (a, Some(c)),
        None => (text, None),
    };
    let addr: IpAddr = addr_text
        .parse()
        .map_err(|_| format!("«{addr_text}» не является IP-адресом"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let cidr = match cidr_text {
        Some(c) => c.parse().map_err(|_| format!("«{c}» не является длиной префикса"))?,
        None => max,
    };
    if cidr > max {
        return Err(format!("длина префикса {cidr} больше {max}"));
    }
    Ok(IpNet { addr, cidr })
}

/// Разбор base64 ключа WireGuard: ровно 44 символа, 32 байта на выходе.
fn decode_key(text: &str) -> Option<[u8; KEY_LEN]> {
    let bytes = decode_base64(text.trim())?;
    if bytes.len() != KEY_LEN {
        return None;
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    Some(key)
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for ch in text.bytes() {
        if ch == b'=' {
            break;
        }
        let value = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
[Interface]
PrivateKey = 6GjYPQOCqPdW1h0cJWMrmNxDLhPNeMBPYxOhBDSHPWs=
Address = 10.8.0.2/32, fd00::2/128
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = Xo1eYOYNbrgLq0rq6kuOg1BvzSNNEIyrCOJHxBEXaXo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:51820   # комментарий
PersistentKeepalive = 25
";

    #[test]
    fn parses_a_standard_wireguard_config() {
        let cfg = TunnelConfig::parse(SAMPLE).expect("конфиг должен разобраться");
        assert_eq!(cfg.mtu, 1420);
        assert_eq!(cfg.addresses.len(), 2);
        assert_eq!(cfg.addresses[0].cidr, 32);
        assert_eq!(cfg.dns.len(), 1);
        assert_eq!(cfg.peer.allowed_ips.len(), 2);
        assert_eq!(cfg.peer.persistent_keepalive, 25);
        assert_eq!(cfg.peer.endpoint.port(), 51820);
    }

    #[test]
    fn comments_do_not_leak_into_values() {
        let cfg = TunnelConfig::parse(SAMPLE).unwrap();
        assert_eq!(cfg.peer.endpoint_raw, "127.0.0.1:51820");
    }

    #[test]
    fn keys_are_exactly_32_bytes() {
        let cfg = TunnelConfig::parse(SAMPLE).unwrap();
        assert_eq!(cfg.private_key.len(), KEY_LEN);
        assert_ne!(cfg.private_key, [0u8; KEY_LEN]);
        assert_ne!(cfg.peer.public_key, [0u8; KEY_LEN]);
    }

    #[test]
    fn missing_endpoint_is_reported() {
        let text = "[Interface]\nPrivateKey = 6GjYPQOCqPdW1h0cJWMrmNxDLhPNeMBPYxOhBDSHPWs=\n[Peer]\nPublicKey = Xo1eYOYNbrgLq0rq6kuOg1BvzSNNEIyrCOJHxBEXaXo=\n";
        assert!(matches!(
            TunnelConfig::parse(text),
            Err(ConfigError::Missing("Peer.Endpoint"))
        ));
    }

    #[test]
    fn bad_base64_is_reported_as_bad_key() {
        let text = "[Interface]\nPrivateKey = not-base64!!\n";
        assert!(matches!(
            TunnelConfig::parse(text),
            Err(ConfigError::BadKey("PrivateKey"))
        ));
    }

    #[test]
    fn prefix_length_is_validated() {
        let text = "[Interface]\nAddress = 10.0.0.1/33\n";
        assert!(matches!(
            TunnelConfig::parse(text),
            Err(ConfigError::Syntax { line: 2, .. })
        ));
    }
}
