//! Hillstone VPN client core: TLS control channel + protocol state machine.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

/// TCP 建连超时：连到不可达/拒绝的服务器时不能无限等待 OS 的 TCP 超时
/// （可达数分钟），否则用户会长时间无响应。VPN 服务器应在该时间内可达。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

use crate::error::ProtocolError;
use crate::message::{MessageBuilder, MessageType, ParsedMessage, Payload};

/// A route advertised by the server in a SET_ROUTE message: destination
/// network + prefix length. In split-tunnel mode only these subnets are
/// routed via the VPN; the default route stays on the regular uplink so
/// normal internet access keeps working while connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Route {
    pub dest: Ipv4Addr,
    pub prefix: u8,
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.dest, self.prefix)
    }
}

/// Result of `wait_network` / SET_IP phase: client's assigned private IP,
/// the server's gateway inside the tunnel, DNS servers, and the UDP port the
/// server will use for the ESP data channel.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub client_ip: Ipv4Addr,
    pub netmask: u8,
    pub gateway: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub server_udp_port: u16,
    /// Subnets the server wants routed through the tunnel (SET_ROUTE).
    /// Empty when the server advertised nothing (or nothing parseable); in
    /// split-tunnel mode that routes only the VPN subnet itself via the
    /// tunnel — the default route always stays on the uplink.
    pub routes: Vec<Route>,
}

/// Result of `exchange_key` / NEW_KEY phase: SPI values + keymat for ESP.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub inbound_spi: u32,
    pub outbound_spi: u32,
    pub keymat: [u8; 48],
    pub crypt_size: usize,
    pub iv_size: usize,
    pub auth_size: usize,
}

/// VPN client control plane.
///
/// Holds the TLS-wrapped TCP socket and the negotiated state. Methods are
/// async; the data plane (UDP/ESP) is layered on top by `hillstonux-net`.
pub struct ClientCore {
    tls: Option<TlsStream<TcpStream>>,
    /// Address the server hostname resolved to in `connect_tcp`. The control
    /// plane and the data plane must use the same address.
    resolved_ip: Option<IpAddr>,
    pub server_udp_port: u16,
}

impl ClientCore {
    pub fn new() -> Self {
        Self {
            tls: None,
            resolved_ip: None,
            server_udp_port: 0,
        }
    }

    /// Open a TLS connection to the VPN server. Does NOT verify the server
    /// certificate (matches Python `ClientCore.__init__` which uses
    /// `CERT_NONE`).
    pub async fn connect_tcp(&mut self, host: &str, port: u16) -> Result<(), ProtocolError> {
        // Prefer IPv4, matching the Python reference (`socket.gethostbyname`
        // is AF_INET only) and the IPv4-only data plane. A dual-stack host
        // whose first getaddrinfo result is IPv6 must still work.
        let addrs = tokio::net::lookup_host(format!("{}:{}", host, port)).await?;
        let mut first = None;
        let mut ipv4 = None;
        for addr in addrs {
            first.get_or_insert(addr);
            if addr.is_ipv4() {
                ipv4 = Some(addr);
                break;
            }
        }
        let ip = ipv4
            .or(first)
            .ok_or_else(|| ProtocolError::Tls(format!("could not resolve host: {}", host)))?;
        self.resolved_ip = Some(ip.ip());

        // 带超时建连：不可达服务器不应无限阻塞到 OS TCP 超时。
        // 报错同时带上原始主机名和解析结果，避免只看到 IP 时无法判断
        // 是域名解析错了还是端口不通。
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(ip))
            .await
            .map_err(|_| {
                ProtocolError::Tls(format!(
                    "connect to {}:{} ({}) timed out",
                    host,
                    port,
                    ip.ip()
                ))
            })?
            .map_err(|e| {
                ProtocolError::Tls(format!(
                    "connect to {}:{} ({}) failed: {}",
                    host,
                    port,
                    ip.ip(),
                    e
                ))
            })?;

        // Build a TLS client config with no certificate verification, matching
        // the Python client's `ssl.CERT_NONE`.
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = rustls_pki_types::ServerName::try_from(host.to_owned())
            .map_err(|e| ProtocolError::Tls(format!("invalid server name: {}", e)))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| ProtocolError::Tls(format!("tls handshake failed: {}", e)))?;

        self.tls = Some(tls);
        Ok(())
    }

    /// Address that `connect_tcp` resolved the server hostname to.
    ///
    /// The data plane needs this IPv4 address for the route bypass and the
    /// UDP peer; parsing the original hostname only works for IP literals.
    pub fn resolved_ip(&self) -> Option<IpAddr> {
        self.resolved_ip
    }

    /// Send AUTH and verify server responds with STATUS=0.
    pub async fn auth(
        &mut self,
        user: &str,
        pass: &str,
        host_id: &str,
        host_name: &str,
    ) -> Result<(), ProtocolError> {
        let mut m = MessageBuilder::new(MessageType::Auth);
        m.push_int(Payload::AuthType, 2, 1);
        m.push_string(Payload::Username, user);
        m.push_string(Payload::Password, pass);
        m.push_string(Payload::ClientVer, "1.0.0");
        m.push_string(Payload::HostId, host_id);
        m.push_string(Payload::HostName, host_name);
        self.send(&m.finish()).await?;

        let resp = self.recv().await?;
        let status = resp
            .fields
            .get(&Payload::Status)
            .ok_or(ProtocolError::NotAPacket)?;
        if status != b"\0\0\0\0" {
            let code = u32::from_be_bytes(status.as_slice().try_into().unwrap_or([0, 0, 0, 0]));
            return Err(ProtocolError::AuthFailed(code));
        }
        Ok(())
    }

    /// Send CLNT_INFO with our (placeholder) public IP and the server's IP.
    pub async fn client_info(&mut self) -> Result<(), ProtocolError> {
        let server_ip: Ipv4Addr = match self.resolved_ip {
            Some(IpAddr::V4(ip)) => ip,
            Some(IpAddr::V6(ip)) => {
                return Err(ProtocolError::Tls(format!(
                    "IPv6 server address {} is not supported",
                    ip
                )))
            }
            None => return Err(ProtocolError::Tls("server address not resolved".into())),
        };
        let mut m = MessageBuilder::new(MessageType::ClntInfo);
        m.push_ipv4(Payload::CltPubIpv4, Ipv4Addr::new(127, 0, 0, 1));
        m.push_ipv4(Payload::SvrPubIpv4, server_ip);
        self.send(&m.finish()).await?;

        let resp = self.recv().await?;
        let status = resp
            .fields
            .get(&Payload::Status)
            .ok_or(ProtocolError::NotAPacket)?;
        if status != b"\0\0\0\0" {
            let code = u32::from_be_bytes(status.as_slice().try_into().unwrap_or([0, 0, 0, 0]));
            return Err(ProtocolError::ClientInfoFailed(code));
        }
        Ok(())
    }

    /// Block until the server sends KEY_DONE, collecting SET_IP/SET_ROUTE
    /// along the way.
    pub async fn wait_network(&mut self) -> Result<NetworkConfig, ProtocolError> {
        let mut client_ip = None;
        let mut netmask_prefix = None;
        let mut gateway = None;
        let mut dns = Vec::new();
        let mut server_udp_port = None;
        let mut routes_raw: Vec<u8> = Vec::new();

        loop {
            let resp = self.recv().await?;
            if resp.msg_t == MessageType::None {
                continue;
            }
            if let Some(s) = resp.fields.get(&Payload::Status) {
                if s != b"\0\0\0\0" {
                    let code = u32::from_be_bytes(s.as_slice().try_into().unwrap_or([0, 0, 0, 0]));
                    return Err(ProtocolError::NetworkInfoFailed(code));
                }
            }
            match resp.msg_t {
                MessageType::SetIp => {
                    let ip_bytes: [u8; 4] = resp
                        .fields
                        .get(&Payload::CltPrivIpv4)
                        .and_then(|v| v.as_slice().try_into().ok())
                        .ok_or(ProtocolError::NotAPacket)?;
                    client_ip = Some(Ipv4Addr::from(ip_bytes));

                    let mask_bytes: [u8; 4] = resp
                        .fields
                        .get(&Payload::NetmaskIpv4)
                        .and_then(|v| v.as_slice().try_into().ok())
                        .ok_or(ProtocolError::NotAPacket)?;
                    let mask = Ipv4Addr::from(mask_bytes);
                    netmask_prefix = Some(mask_prefix_len(mask));

                    let gw_bytes: [u8; 4] = resp
                        .fields
                        .get(&Payload::SvrPrivIpv4)
                        .and_then(|v| v.as_slice().try_into().ok())
                        .ok_or(ProtocolError::NotAPacket)?;
                    gateway = Some(Ipv4Addr::from(gw_bytes));

                    if let Some(p) = resp.fields.get(&Payload::SvrUdpPort) {
                        if p.len() == 2 {
                            let port = u16::from_be_bytes([p[0], p[1]]);
                            server_udp_port = Some(port);
                            self.server_udp_port = port;
                        }
                    }

                    if let Some(d) = resp.fields.get(&Payload::DnsIpv4) {
                        for chunk in d.chunks(4) {
                            if chunk.len() == 4 {
                                // 长度已确认为 4，直接按字节构造地址。
                                dns.push(Ipv4Addr::from([chunk[0], chunk[1], chunk[2], chunk[3]]));
                            }
                        }
                    }
                }
                MessageType::KeyDone => break,
                MessageType::SetRoute => {
                    // The raw payload is logged in hex so the wire format can
                    // be verified against a capture; parsing is defensive.
                    if let Some(r) = resp.fields.get(&Payload::RouteIpv4) {
                        let hex: String = r.iter().map(|b| format!("{:02x}", b)).collect();
                        tracing::debug!(len = r.len(), ?hex, "SET_ROUTE received");
                        routes_raw = r.clone();
                    }
                }
                _ => {}
            }
        }

        let routes = parse_route_ipv4(&routes_raw);

        Ok(NetworkConfig {
            client_ip: client_ip.ok_or(ProtocolError::NotAPacket)?,
            netmask: netmask_prefix.ok_or(ProtocolError::NotAPacket)?,
            gateway: gateway.ok_or(ProtocolError::NotAPacket)?,
            dns,
            server_udp_port: server_udp_port.ok_or(ProtocolError::NotAPacket)?,
            routes,
        })
    }

    /// Exchange key material via NEW_KEY with PLAIN mode (matches Python).
    pub async fn exchange_key(&mut self) -> Result<KeyMaterial, ProtocolError> {
        // Send NEW_KEY with random 48-byte keymat + inbound SPI + inbound CPI.
        let mut keymat = [0u8; 48];
        use rand::Rng;
        rand::rng().fill_bytes(&mut keymat);
        let inbound_spi: u32 = rand::random();
        let inbound_cpi: u16 = rand::random();

        let mut m = MessageBuilder::new(MessageType::NewKey);
        m.push_int(Payload::KeyExchMode, 2, 3); // KEY_EXCH_PLAIN
        m.push_bytes(Payload::Keymat, keymat.to_vec());
        m.push_int(Payload::Spi, 4, inbound_spi as u64);
        m.push_int(Payload::IpcompCpi, 2, inbound_cpi as u64);
        self.send(&m.finish()).await?;

        let resp = self.recv().await?;

        let ipcomp_alg = resp
            .fields
            .get(&Payload::IpcompAlg)
            .ok_or(ProtocolError::NotAPacket)?;
        if ipcomp_alg != b"\0\0" {
            return Err(ProtocolError::UnsupportedAlgorithm { enc: 0, auth: 0 });
        }

        let enc_alg = resp
            .fields
            .get(&Payload::EncAlg)
            .ok_or(ProtocolError::NotAPacket)?;
        let auth_alg = resp
            .fields
            .get(&Payload::AuthAlg)
            .ok_or(ProtocolError::NotAPacket)?;

        let (crypt_size, iv_size) = match enc_alg.as_slice() {
            b"\0\x0c" => (0x10, 0x10), // AES-CBC
            b"\0\x03" => (0x18, 8),    // 3DES
            _ => {
                return Err(ProtocolError::UnsupportedAlgorithm {
                    enc: u16::from_be_bytes([enc_alg[0], enc_alg[1]]),
                    auth: u16::from_be_bytes([auth_alg[0], auth_alg[1]]),
                });
            }
        };

        let auth_size = match auth_alg.as_slice() {
            b"\0\x01" => 0x10, // HMAC-MD5-96
            b"\0\x02" => 0x14, // HMAC-SHA1-96
            _ => {
                return Err(ProtocolError::UnsupportedAlgorithm {
                    enc: u16::from_be_bytes([enc_alg[0], enc_alg[1]]),
                    auth: u16::from_be_bytes([auth_alg[0], auth_alg[1]]),
                });
            }
        };

        let outbound_spi = resp
            .fields
            .get(&Payload::Spi)
            .and_then(|v| v.as_slice().try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(ProtocolError::NotAPacket)?;

        Ok(KeyMaterial {
            inbound_spi,
            outbound_spi,
            keymat,
            crypt_size,
            iv_size,
            auth_size,
        })
    }

    /// Send CLNT_LOGOUT. Best-effort; ignores errors.
    pub async fn logout(&mut self) -> Result<(), ProtocolError> {
        let mut m = MessageBuilder::new(MessageType::ClntLogout);
        m.push_int(Payload::Disconnect, 2, 0);
        self.send(&m.finish()).await?;
        Ok(())
    }

    /// Send a KEEP_ALIVE on the control channel. The Python reference
    /// sends this every ~10s during the connected session; the server
    /// replies with `KEEP_ALIVE` of its own. We don't currently consume
    /// the reply — the data-plane traffic serves as the liveness signal
    /// in practice. Best-effort: errors are returned but not fatal here.
    pub async fn send_keepalive(&mut self) -> Result<(), ProtocolError> {
        let m = MessageBuilder::new(MessageType::KeepAlive);
        self.send(&m.finish()).await?;
        Ok(())
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        use tokio::io::AsyncWriteExt;
        let tls = self.tls.as_mut().ok_or(ProtocolError::NotAPacket)?;
        tls.write_all(bytes).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<ParsedMessage, ProtocolError> {
        use tokio::io::AsyncReadExt;
        let tls = self.tls.as_mut().ok_or(ProtocolError::NotAPacket)?;
        let mut header = [0u8; 8];
        tls.read_exact(&mut header).await?;
        let size = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let body_len = size.saturating_sub(8);
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            tls.read_exact(&mut body).await?;
        }
        let mut packet = Vec::with_capacity(size);
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&body);
        crate::message::unpack(&packet)
    }
}

impl Default for ClientCore {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the prefix length (number of leading 1 bits) of an IPv4 netmask.
fn mask_prefix_len(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    bits.leading_ones() as u8
}

/// Parse the raw `ROUTE_IPV4` payload of a SET_ROUTE message into a route
/// list.
///
/// Wire formats (the production server sends the 12-byte variant):
///
/// - a sequence of 8-byte `(dest_ipv4, netmask_ipv4)` pairs — the same
///   layout SET_IP uses for its address/mask fields;
/// - a sequence of 12-byte `(dest_ipv4, netmask_ipv4, extra)` entries,
///   where the trailing 4-byte field carries no routing information and is
///   ignored (kept visible in debug logs).
///
/// Some builds may prepend a 4-byte header (route count or payload length);
/// when the header value is consistent with the payload it is stripped
/// before parsing. Parsing is defensive: an interpretation is accepted only
/// if every netmask is a strict prefix mask; an unparseable payload yields
/// an empty list (with a warning that includes the raw bytes in hex), and
/// callers treat an empty list as "the server advertised no routes" — in
/// split-tunnel mode only the VPN subnet itself is then routed via the
/// tunnel, and the default route stays on the uplink. An entry of
/// `0.0.0.0/0` means the server itself wants full tunnel.
pub(crate) fn parse_route_ipv4(raw: &[u8]) -> Vec<Route> {
    if raw.is_empty() {
        return Vec::new();
    }
    // Candidate (body, entry-size) interpretations in priority order:
    // 8-byte pairs and 12-byte entries, each with or without a leading
    // 4-byte count/length header. The first interpretation whose netmasks
    // are all strict prefix masks wins.
    let mut candidates: Vec<(&[u8], usize)> = Vec::new();
    if raw.len().is_multiple_of(8) {
        candidates.push((raw, 8));
    }
    if raw.len().is_multiple_of(12) {
        candidates.push((raw, 12));
    }
    if raw.len() >= 12 {
        let header = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let body_len = raw.len() - 4;
        let consistent = header == raw.len() as u32
            || header == body_len as u32
            || (body_len.is_multiple_of(8) && header == (body_len / 8) as u32)
            || (body_len.is_multiple_of(12) && header == (body_len / 12) as u32);
        if consistent {
            if body_len.is_multiple_of(8) {
                candidates.push((&raw[4..], 8));
            }
            if body_len.is_multiple_of(12) {
                candidates.push((&raw[4..], 12));
            }
        }
    }
    for (body, size) in candidates {
        // A real route list has only strict prefix netmasks; require that
        // before accepting an interpretation (a wrong guess almost always
        // yields invalid masks).
        if !body
            .chunks_exact(size)
            .all(|entry| is_prefix_mask([entry[4], entry[5], entry[6], entry[7]]))
        {
            continue;
        }
        let routes: Vec<Route> = body
            .chunks_exact(size)
            .map(|entry| {
                let mask = Ipv4Addr::from([entry[4], entry[5], entry[6], entry[7]]);
                Route {
                    dest: Ipv4Addr::from([entry[0], entry[1], entry[2], entry[3]]),
                    prefix: mask_prefix_len(mask),
                }
            })
            .collect();
        if size == 12 {
            let extras: Vec<String> = body
                .as_chunks::<12>()
                .0
                .iter()
                .map(|entry| format!("{:?}", &entry[8..12]))
                .collect();
            tracing::debug!(
                ?extras,
                "SET_ROUTE: 12-byte entries, trailing 4-byte field ignored"
            );
        }
        return routes;
    }
    let hex: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
    tracing::warn!(
        len = raw.len(),
        %hex,
        "SET_ROUTE payload not parseable as route entries; ignoring \
         (split-tunnel keeps the uplink default route)"
    );
    Vec::new()
}

/// True when the 4 mask bytes form a strict prefix netmask (contiguous 1s
/// followed by contiguous 0s, e.g. 255.255.252.0). Used to tell a real
/// route list apart from an unrecognized payload layout.
fn is_prefix_mask(mask: [u8; 4]) -> bool {
    let bits = u32::from_be_bytes(mask);
    let expected = match bits.leading_ones() {
        32 => u32::MAX,
        0 => 0,
        prefix => u32::MAX << (32 - prefix),
    };
    bits == expected
}

/// `ServerCertVerifier` that accepts any certificate without verification.
/// Mirrors Python `ssl.CERT_NONE`.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

use std::sync::Arc;

#[cfg(test)]
mod route_parse_tests {
    use super::*;

    fn pair(dest: [u8; 4], mask: [u8; 4]) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&dest);
        out[4..].copy_from_slice(&mask);
        out
    }

    #[test]
    fn empty_payload_yields_no_routes() {
        assert!(parse_route_ipv4(&[]).is_empty());
    }

    #[test]
    fn parses_dest_mask_pairs() {
        let raw = [
            pair([10, 1, 111, 0], [255, 255, 255, 0]),
            pair([10, 250, 252, 0], [255, 255, 252, 0]),
        ]
        .concat();
        let routes = parse_route_ipv4(&raw);
        assert_eq!(
            routes,
            vec![
                Route {
                    dest: Ipv4Addr::new(10, 1, 111, 0),
                    prefix: 24
                },
                Route {
                    dest: Ipv4Addr::new(10, 250, 252, 0),
                    prefix: 22
                },
            ]
        );
    }

    #[test]
    fn zero_mask_means_default_route() {
        let raw = pair([0, 0, 0, 0], [0, 0, 0, 0]);
        let routes = parse_route_ipv4(&raw);
        assert_eq!(
            routes,
            vec![Route {
                dest: Ipv4Addr::UNSPECIFIED,
                prefix: 0
            }]
        );
    }

    #[test]
    fn malformed_length_is_ignored() {
        // Not a whole number of 8-byte pairs or 12-byte entries.
        assert!(parse_route_ipv4(&[1, 2, 3, 4, 5, 6, 7]).is_empty());
        // 20 bytes: not a multiple of 8 or 12, and no consistent header.
        assert!(parse_route_ipv4(&[0u8; 20]).is_empty());
    }

    #[test]
    fn twelve_byte_zero_entry_is_default_route() {
        // A single 12-byte all-zero entry: 0.0.0.0/0 — the server
        // explicitly wants full tunnel.
        let routes = parse_route_ipv4(&[0u8; 12]);
        assert_eq!(
            routes,
            vec![Route {
                dest: Ipv4Addr::UNSPECIFIED,
                prefix: 0
            }]
        );
    }

    #[test]
    fn production_36_byte_payload_is_parsed() {
        // Exact 36-byte payload captured from the production server
        // (2026-10-23): three 12-byte (dest, mask, extra) entries.
        let raw = [
            0x0a, 0x01, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0x0a, 0xff,
            0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x23, 0x0a, 0xfd, 0x00, 0x00,
            0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x23,
        ];
        let routes = parse_route_ipv4(&raw);
        assert_eq!(
            routes,
            vec![
                Route {
                    dest: Ipv4Addr::new(10, 1, 0, 0),
                    prefix: 16
                },
                Route {
                    dest: Ipv4Addr::new(10, 255, 0, 0),
                    prefix: 24
                },
                Route {
                    dest: Ipv4Addr::new(10, 253, 0, 0),
                    prefix: 24
                },
            ]
        );
    }

    #[test]
    fn count_header_format_is_parsed() {
        // 4-byte count header (4 routes) + four (dest, mask) pairs — 36
        // bytes, the length the production server advertises.
        let mut raw = vec![0u8, 0, 0, 4];
        raw.extend_from_slice(&pair([10, 0, 0, 0], [255, 0, 0, 0]));
        raw.extend_from_slice(&pair([10, 250, 252, 0], [255, 255, 252, 0]));
        raw.extend_from_slice(&pair([172, 16, 0, 0], [255, 240, 0, 0]));
        raw.extend_from_slice(&pair([192, 168, 0, 0], [255, 255, 0, 0]));
        assert_eq!(raw.len(), 36);
        let routes = parse_route_ipv4(&raw);
        assert_eq!(
            routes,
            vec![
                Route {
                    dest: Ipv4Addr::new(10, 0, 0, 0),
                    prefix: 8
                },
                Route {
                    dest: Ipv4Addr::new(10, 250, 252, 0),
                    prefix: 22
                },
                Route {
                    dest: Ipv4Addr::new(172, 16, 0, 0),
                    prefix: 12
                },
                Route {
                    dest: Ipv4Addr::new(192, 168, 0, 0),
                    prefix: 16
                },
            ]
        );
    }

    #[test]
    fn length_header_format_is_parsed() {
        // 4-byte body-length header (32) + four (dest, mask) pairs.
        let mut raw = vec![0u8, 0, 0, 32];
        raw.extend_from_slice(&pair([10, 1, 0, 0], [255, 255, 0, 0]));
        raw.extend_from_slice(&pair([10, 2, 0, 0], [255, 255, 0, 0]));
        raw.extend_from_slice(&pair([10, 3, 0, 0], [255, 255, 0, 0]));
        raw.extend_from_slice(&pair([10, 4, 0, 0], [255, 255, 0, 0]));
        let routes = parse_route_ipv4(&raw);
        assert_eq!(routes.len(), 4);
        assert_eq!(
            routes[0],
            Route {
                dest: Ipv4Addr::new(10, 1, 0, 0),
                prefix: 16
            }
        );
        assert_eq!(
            routes[3],
            Route {
                dest: Ipv4Addr::new(10, 4, 0, 0),
                prefix: 16
            }
        );
    }

    #[test]
    fn inconsistent_header_is_rejected() {
        // A 4-byte prefix that is neither a count nor a length, followed by
        // pairs: the header-less interpretation fails (not a multiple of 8)
        // and the header interpretation is inconsistent → rejected.
        let mut raw = vec![0u8, 0, 0, 9];
        raw.extend_from_slice(&pair([10, 1, 0, 0], [255, 255, 0, 0]));
        raw.extend_from_slice(&pair([10, 2, 0, 0], [255, 255, 0, 0]));
        raw.extend_from_slice(&pair([10, 3, 0, 0], [255, 255, 0, 0]));
        raw.extend_from_slice(&pair([10, 4, 0, 0], [255, 255, 0, 0]));
        assert!(parse_route_ipv4(&raw).is_empty());
    }
}
