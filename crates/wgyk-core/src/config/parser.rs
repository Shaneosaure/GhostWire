//! Parser INI pour le format `wg-quick`.
//!
//! Le format est volontairement simple : sections `[Interface]` /
//! `[Peer]`, paires `Clé = Valeur`, commentaires `#` ou `;`.
//! Plusieurs sections `[Peer]` sont autorisées dans un même fichier.
//!
//! On n'utilise PAS la crate `ini` car (a) elle tire des deps inutiles,
//! (b) elle ne préserve pas l'ordre des sections, et (c) elle ne sait
//! pas gérer plusieurs sections du même nom (or `[Peer]` apparaît N fois).

use std::net::SocketAddr;
use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD, Engine};
use ipnet::IpNet;
use secrecy::SecretBox;
use thiserror::Error;

use super::{
    EndpointSpec, InterfaceConfig, PeerConfig, WgConfig, WgKeyBytes, WgPrivateKey,
};

/// Erreurs de parsing — détaillées pour aider l'utilisateur à corriger
/// son fichier sans qu'on ait à logger le contenu (qui est sensible).
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("ligne {line}: section inconnue : '{name}'")]
    UnknownSection { line: usize, name: String },

    #[error("ligne {line}: clé/valeur attendues, trouvé : '{raw}'")]
    MalformedLine { line: usize, raw: String },

    #[error("ligne {line}: clé '{key}' inattendue dans la section [{section}]")]
    UnknownKey { line: usize, key: String, section: &'static str },

    #[error("ligne {line}: valeur invalide pour '{key}' : {detail}")]
    InvalidValue { line: usize, key: String, detail: String },

    #[error("section [Interface] manquante")]
    MissingInterface,

    #[error("section [Interface] : clé 'PrivateKey' obligatoire manquante")]
    MissingPrivateKey,

    #[error("aucun [Peer] défini — la config n'a pas de destination")]
    NoPeers,

    #[error("[Peer]: clé 'PublicKey' obligatoire manquante")]
    PeerMissingPublicKey,

    #[error("ligne {line}: clé '{key}' présente plusieurs fois dans la même section")]
    DuplicateKey { line: usize, key: String },
}

/// Point d'entrée principal : transforme un buffer INI en `WgConfig`.
pub fn parse(input: &str) -> Result<WgConfig, ConfigError> {
    let mut iface_builder: Option<InterfaceBuilder> = None;
    let mut peer_builders: Vec<PeerBuilder> = Vec::new();
    let mut current = Section::None;

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        // En-tête de section : [Interface] ou [Peer].
        if let Some(section_name) = line
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .map(str::trim)
        {
            current = match section_name {
                "Interface" => {
                    if iface_builder.is_some() {
                        return Err(ConfigError::DuplicateKey {
                            line: line_no,
                            key: "[Interface] dupliquée".into(),
                        });
                    }
                    iface_builder = Some(InterfaceBuilder::default());
                    Section::Interface
                }
                "Peer" => {
                    peer_builders.push(PeerBuilder::default());
                    Section::Peer
                }
                other => {
                    return Err(ConfigError::UnknownSection {
                        line: line_no,
                        name: other.to_string(),
                    })
                }
            };
            continue;
        }

        // Paire clé = valeur.
        let (key, value) = split_kv(line).ok_or_else(|| ConfigError::MalformedLine {
            line: line_no,
            raw: line.to_string(),
        })?;

        match current {
            Section::None => {
                return Err(ConfigError::UnknownSection {
                    line: line_no,
                    name: "(racine)".into(),
                });
            }
            Section::Interface => iface_builder
                .as_mut()
                .expect("set just above")
                .set(line_no, key, value)?,
            Section::Peer => peer_builders
                .last_mut()
                .expect("pushed at section start")
                .set(line_no, key, value)?,
        }
    }

    let interface = iface_builder
        .ok_or(ConfigError::MissingInterface)?
        .build()?;
    if peer_builders.is_empty() {
        return Err(ConfigError::NoPeers);
    }
    let peers = peer_builders
        .into_iter()
        .map(PeerBuilder::build)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(WgConfig { interface, peers })
}

#[derive(Copy, Clone)]
enum Section {
    None,
    Interface,
    Peer,
}

/// Retire `#...` et `;...` en fin de ligne.
fn strip_comment(s: &str) -> &str {
    s.split_once(['#', ';'])
        .map(|(before, _)| before)
        .unwrap_or(s)
}

/// `Foo = Bar` → `("Foo", "Bar")`. Renvoie None si pas de `=`.
fn split_kv(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), v.trim()))
}

/// Décode une clé WireGuard base64 (44 caractères → 32 octets).
fn parse_wg_key(key_name: &str, line_no: usize, raw: &str) -> Result<WgKeyBytes, ConfigError> {
    let bytes = STANDARD.decode(raw).map_err(|e| ConfigError::InvalidValue {
        line: line_no,
        key: key_name.into(),
        detail: format!("base64 invalide : {e}"),
    })?;
    if bytes.len() != 32 {
        return Err(ConfigError::InvalidValue {
            line: line_no,
            key: key_name.into(),
            detail: format!("attendu 32 octets, trouvé {}", bytes.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_endpoint(line_no: usize, raw: &str) -> Result<EndpointSpec, ConfigError> {
    // Tente d'abord SocketAddr (gère IPv4 et `[v6]:port`).
    if let Ok(addr) = SocketAddr::from_str(raw) {
        return Ok(EndpointSpec::Resolved(addr));
    }
    // Sinon, host:port — on sépare au DERNIER ':' pour ne pas casser IPv6.
    let (host, port_str) = raw.rsplit_once(':').ok_or_else(|| ConfigError::InvalidValue {
        line: line_no,
        key: "Endpoint".into(),
        detail: "format attendu : host:port".into(),
    })?;
    let port: u16 = port_str.parse().map_err(|_| ConfigError::InvalidValue {
        line: line_no,
        key: "Endpoint".into(),
        detail: format!("port invalide : '{port_str}'"),
    })?;
    Ok(EndpointSpec::Hostname {
        host: host.trim_matches(|c| c == '[' || c == ']').to_string(),
        port,
    })
}

// ── Builders ─────────────────────────────────────────────────────────

#[derive(Default)]
struct InterfaceBuilder {
    private_key: Option<WgKeyBytes>,
    addresses: Vec<IpNet>,
    listen_port: Option<u16>,
    mtu: Option<u16>,
    dns: Vec<std::net::IpAddr>,
}

impl InterfaceBuilder {
    fn set(&mut self, line: usize, key: &str, value: &str) -> Result<(), ConfigError> {
    match key.to_ascii_lowercase().as_str() {
        "privatekey" => {
            if self.private_key.is_some() {
                return Err(ConfigError::DuplicateKey { line, key: key.into() });
            }
            self.private_key = Some(parse_wg_key("PrivateKey", line, value)?);
        }
        "address" => {
            for part in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let net = IpNet::from_str(part).map_err(|e| ConfigError::InvalidValue {
                    line, key: "Address".into(), detail: e.to_string(),
                })?;
                self.addresses.push(net);
            }
        }
        "listenport" => {
            self.listen_port = Some(value.parse().map_err(|_| ConfigError::InvalidValue {
                line, key: "ListenPort".into(),
                detail: format!("port invalide : '{value}'"),
            })?);
        }
        "mtu" => {
            self.mtu = Some(value.parse().map_err(|_| ConfigError::InvalidValue {
                line, key: "MTU".into(),
                detail: format!("MTU invalide : '{value}'"),
            })?);
        }
        "dns" => {
            for part in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let ip = std::net::IpAddr::from_str(part).map_err(|e| {
                    ConfigError::InvalidValue {
                        line, key: "DNS".into(), detail: e.to_string(),
                    }
                })?;
                self.dns.push(ip);
            }
        }
        "postup" | "postdown" | "preup" | "predown" | "table" | "saveconfig" => {
            tracing::debug!(target: "wgyk_core::config", "ignoré : {key}");
        }
        other => {
            return Err(ConfigError::UnknownKey {
                line, key: other.into(), section: "Interface",
            });
        }
    }
    Ok(())
  }

    fn build(self) -> Result<InterfaceConfig, ConfigError> {
        let pk = self.private_key.ok_or(ConfigError::MissingPrivateKey)?;
        Ok(InterfaceConfig {
            private_key: SecretBox::new(Box::new(WgPrivateKey(pk))),
            addresses: self.addresses,
            listen_port: self.listen_port,
            mtu: self.mtu,
            dns: self.dns,
        })
    }
}

#[derive(Default)]
struct PeerBuilder {
    public_key: Option<WgKeyBytes>,
    preshared_key: Option<WgKeyBytes>,
    allowed_ips: Vec<IpNet>,
    endpoint: Option<EndpointSpec>,
    persistent_keepalive: Option<u16>,
}

impl PeerBuilder {
    fn set(&mut self, line: usize, key: &str, value: &str) -> Result<(), ConfigError> {
    match key.to_ascii_lowercase().as_str() {
        "publickey" => {
            if self.public_key.is_some() {
                return Err(ConfigError::DuplicateKey { line, key: key.into() });
            }
            self.public_key = Some(parse_wg_key("PublicKey", line, value)?);
        }
        "presharedkey" => {
            self.preshared_key = Some(parse_wg_key("PresharedKey", line, value)?);
        }
        "allowedips" => {
            for part in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let net = IpNet::from_str(part).map_err(|e| ConfigError::InvalidValue {
                    line, key: "AllowedIPs".into(), detail: e.to_string(),
                })?;
                self.allowed_ips.push(net);
            }
        }
        "endpoint" => {
            self.endpoint = Some(parse_endpoint(line, value)?);
        }
        "persistentkeepalive" => {
            self.persistent_keepalive =
                Some(value.parse().map_err(|_| ConfigError::InvalidValue {
                    line, key: "PersistentKeepalive".into(),
                    detail: format!("entier attendu : '{value}'"),
                })?);
        }
        other => {
            return Err(ConfigError::UnknownKey {
                line, key: other.into(), section: "Peer",
            });
        }
    }
    Ok(())
}

    fn build(self) -> Result<PeerConfig, ConfigError> {
        Ok(PeerConfig {
            public_key: self.public_key.ok_or(ConfigError::PeerMissingPublicKey)?,
            preshared_key: self
                .preshared_key
                .map(|k| SecretBox::new(Box::new(WgPrivateKey(k)))),
            allowed_ips: self.allowed_ips,
            endpoint: self.endpoint,
            persistent_keepalive: self.persistent_keepalive,
        })
    }
}

// ── Tests unitaires ───────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    // Clés factices valides : 32 octets, base64 standard avec padding.
    const KEY_PRIV: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const KEY_PUB1: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const KEY_PUB2: &str = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const KEY_PSK:  &str = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn parse_full_fixture() {
        let fixture = format!("
[Interface]
PrivateKey = {KEY_PRIV}
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = {KEY_PUB1}
PresharedKey = {KEY_PSK}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
");
        let cfg = parse(&fixture).expect("parse OK");
        assert_eq!(cfg.interface.addresses.len(), 2);
        assert_eq!(cfg.interface.listen_port, Some(51820));
        assert_eq!(cfg.interface.mtu, Some(1420));
        assert_eq!(cfg.interface.dns.len(), 2);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].allowed_ips.len(), 2);
        assert_eq!(cfg.peers[0].persistent_keepalive, Some(25));
        assert_eq!(
            cfg.interface.private_key.expose_secret().as_bytes().len(),
            32
        );
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let input = format!("
# c'est un commentaire
; aussi un commentaire

[Interface]
PrivateKey = {KEY_PRIV}  # inline aussi
Address = 10.0.0.2/32

[Peer]
PublicKey = {KEY_PUB1}
AllowedIPs = 10.0.0.0/24
");
        parse(&input).expect("commentaires OK");
    }

    #[test]
    fn endpoint_ipv4_resolved() {
        let input = format!("
[Interface]
PrivateKey = {KEY_PRIV}
Address = 10.0.0.2/32
[Peer]
PublicKey = {KEY_PUB1}
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.1:51820
");
        let cfg = parse(&input).expect("ok");
        match &cfg.peers[0].endpoint {
            Some(EndpointSpec::Resolved(addr)) => assert_eq!(addr.port(), 51820),
            other => panic!("attendu Resolved, eu {other:?}"),
        }
    }

    #[test]
    fn endpoint_hostname_unresolved() {
        let input = format!("
[Interface]
PrivateKey = {KEY_PRIV}
Address = 10.0.0.2/32
[Peer]
PublicKey = {KEY_PUB1}
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
");
        let cfg = parse(&input).expect("ok");
        match &cfg.peers[0].endpoint {
            Some(EndpointSpec::Hostname { host, port }) => {
                assert_eq!(host, "vpn.example.com");
                assert_eq!(*port, 51820);
            }
            other => panic!("attendu Hostname, eu {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_interface() {
        let input = format!(
            "[Peer]\nPublicKey = {KEY_PUB1}\nAllowedIPs = 0.0.0.0/0\n"
        );
        let err = parse(&input).unwrap_err();
        assert!(matches!(err, ConfigError::MissingInterface));
    }

    #[test]
    fn rejects_missing_private_key() {
        let input = format!(
            "[Interface]\nAddress = 10.0.0.2/32\n\
             [Peer]\nPublicKey = {KEY_PUB1}\nAllowedIPs = 0.0.0.0/0\n"
        );
        let err = parse(&input).unwrap_err();
        assert!(matches!(err, ConfigError::MissingPrivateKey));
    }

    #[test]
    fn rejects_unknown_key() {
        let input = format!("
[Interface]
PrivateKey = {KEY_PRIV}
WeirdField = 42
");
        let err = parse(&input).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownKey { .. }));
    }

    #[test]
    fn multiple_peers() {
        let input = format!("
[Interface]
PrivateKey = {KEY_PRIV}
Address = 10.0.0.2/32
[Peer]
PublicKey = {KEY_PUB1}
AllowedIPs = 10.1.0.0/24
[Peer]
PublicKey = {KEY_PUB2}
AllowedIPs = 10.2.0.0/24
");
        let cfg = parse(&input).expect("ok");
        assert_eq!(cfg.peers.len(), 2);
        // Vérifie que les deux clés publiques sont bien distinctes.
        assert_ne!(cfg.peers[0].public_key, cfg.peers[1].public_key);
    }


#[test]
fn case_insensitive_keys() {
    let input = format!("
[Interface]
PRIVATEKEY = {KEY_PRIV}
address = 10.0.0.2/32
[Peer]
PublicKey = {KEY_PUB1}
PreSharedKey = {KEY_PSK}
allowedips = 0.0.0.0/0
PersistentKeepalive = 25
");
    let cfg = parse(&input).expect("casse mixte OK");
    assert!(cfg.peers[0].preshared_key.is_some());
    assert_eq!(cfg.peers[0].persistent_keepalive, Some(25));
}
}

