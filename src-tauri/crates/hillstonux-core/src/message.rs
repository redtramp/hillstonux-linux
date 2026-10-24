//! Hillstone protocol message type and payload tag enumerations, plus the
//! `MessageBuilder` used to encode outgoing TLV messages with byte-level
//! parity to the Python `hillstone.Message.finish()` implementation.

use std::net::Ipv4Addr;

/// Message type identifiers (1 byte, see Python `MessageType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    None = 0x00,
    Auth = 0x01,
    ClntInfo = 0x02,
    SetIp = 0x03,
    SetRoute = 0x04,
    NewKey = 0x05,
    KeyDone = 0x06,
    ClntLogout = 0x07,
    ServDisconn = 0x08,
    KeepAlive = 0x09,
    Rekey = 0x0A,
    HostCheck = 0x0B,
    HostCheckUpd = 0x0C,
    ChPwd = 0x0D,
    ChPwdResp = 0x0E,
    SmsAuthReq = 0x0F,
    SmsAuthReqRsp = 0x10,
    SmsReq = 0x11,
    SmsReqRsp = 0x12,
    RsaNewPin = 0x13,
    RsaNewPinRsp = 0x14,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x00 => MessageType::None,
            0x01 => MessageType::Auth,
            0x02 => MessageType::ClntInfo,
            0x03 => MessageType::SetIp,
            0x04 => MessageType::SetRoute,
            0x05 => MessageType::NewKey,
            0x06 => MessageType::KeyDone,
            0x07 => MessageType::ClntLogout,
            0x08 => MessageType::ServDisconn,
            0x09 => MessageType::KeepAlive,
            0x0A => MessageType::Rekey,
            0x0B => MessageType::HostCheck,
            0x0C => MessageType::HostCheckUpd,
            0x0D => MessageType::ChPwd,
            0x0E => MessageType::ChPwdResp,
            0x0F => MessageType::SmsAuthReq,
            0x10 => MessageType::SmsAuthReqRsp,
            0x11 => MessageType::SmsReq,
            0x12 => MessageType::SmsReqRsp,
            0x13 => MessageType::RsaNewPin,
            0x14 => MessageType::RsaNewPinRsp,
            _ => return None,
        })
    }
}

/// TLV payload tags (2 bytes, see Python `Payload`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Payload {
    Username = 1,
    Password = 2,
    ChalPassword = 3,
    Status = 4,
    CltPubIpv4 = 5,
    SvrPubIpv4 = 6,
    CltPrivIpv4 = 7,
    SvrPrivIpv4 = 8,
    SvrUdpPort = 9,
    IpSubnet = 10,
    NetmaskIpv4 = 11,
    GatewayIpv4 = 12,
    RouteMetrics = 13,
    IpsecSetting = 14,
    ModpGroup = 15,
    Keymat = 16,
    DnsIpv4 = 17,
    WinsIpv4 = 18,
    RouteIpv4 = 19,
    PerfeSrvIpv4 = 20,
    CommSrvIpv4 = 21,
    KeyExchMode = 32,
    Spi = 48,
    EncAlg = 49,
    AuthAlg = 50,
    SessionId = 51,
    EnErroMsg = 53,
    ChErroMsg = 54,
    AliveStatus = 64,
    AuthType = 81,
    Cookie = 82,
    Disconnect = 83,
    ClientVer = 84,
    HostId = 96,
    HostName = 97,
    HostCheckMd5 = 112,
    HostCheckResult = 115,
    HostCheckResultSize = 116,
    IpcompCpi = 128,
    IpcompAlg = 129,
    AllowPwd = 132,
    NeedSmsAuth = 133,
    SmsAuthCode = 134,
    ClientAutoConnect = 136,
}

/// Builder for an outgoing Hillstone protocol message.
///
/// Wire format (matches Python `hillstone.Message.finish()`):
///
/// ```text
/// | magic (1) | reply (1) | msg_t (2) | size (4) | TLV0 | TLV1 | ... |
/// ```
///
/// Each TLV is `key (2) | len (2) | value (len) | pad to 4-byte alignment`,
/// where padding aligns the cumulative data length to a 4-byte boundary,
/// NOT each individual TLV.
#[derive(Debug, Clone)]
pub struct MessageBuilder {
    reply: bool,
    msg_t: MessageType,
    data: Vec<(Payload, Vec<u8>)>,
}

impl MessageBuilder {
    pub fn new(msg_t: MessageType) -> Self {
        Self {
            reply: false,
            msg_t,
            data: Vec::new(),
        }
    }

    pub fn reply(msg_t: MessageType) -> Self {
        Self {
            reply: true,
            msg_t,
            data: Vec::new(),
        }
    }

    pub fn push_int(&mut self, key: Payload, size: usize, v: u64) {
        let bytes = v.to_be_bytes();
        let start = bytes.len().saturating_sub(size);
        self.data.push((key, bytes[start..].to_vec()));
    }

    pub fn push_ipv4(&mut self, key: Payload, ip: Ipv4Addr) {
        self.data.push((key, ip.octets().to_vec()));
    }

    pub fn push_string(&mut self, key: Payload, s: &str) {
        self.push_bytes(key, s.as_bytes().to_vec());
    }

    pub fn push_bytes(&mut self, key: Payload, b: Vec<u8>) {
        self.data.push((key, b));
    }

    /// Encode the message into wire bytes.
    pub fn finish(self) -> Vec<u8> {
        // Build TLV data with cumulative 4-byte alignment padding.
        let mut data = Vec::new();
        for (key, value) in &self.data {
            data.extend_from_slice(&(*key as u16).to_be_bytes());
            data.extend_from_slice(&(value.len() as u16).to_be_bytes());
            data.extend_from_slice(value);
            let padding = (4 - (data.len() % 4)) % 4;
            data.resize(data.len() + padding, 0);
        }

        // Header: magic | reply | msg_t | size (whole packet incl. header).
        let size = (data.len() + 8) as u32;
        let mut out = Vec::with_capacity(data.len() + 8);
        out.push(0x22);
        out.push(if self.reply { 0x02 } else { 0x00 });
        out.extend_from_slice(&(self.msg_t as u16).to_be_bytes());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&data);
        out
    }
}

/// A decoded incoming packet.
///
/// Produced by [`unpack`] from raw wire bytes. `fields` is keyed by payload
/// tag; later TLVs with the same key overwrite earlier ones (matching Python
/// behaviour).
#[derive(Debug, Clone)]
pub struct ParsedMessage {
    pub msg_t: MessageType,
    pub is_reply: bool,
    pub fields: std::collections::HashMap<Payload, Vec<u8>>,
}

/// Decode a wire packet into its message type and payload fields.
///
/// Mirrors Python `hillstone.Unpack()`:
/// - 8-byte header: magic (1) | reply (1) | msg_t (2) | size (4, big-endian)
/// - Body: TLV stream. Each entry is `key (2) | len (2) | value (len)`, with
///   per-TLV padding to the next 4-byte boundary based on value length.
///
/// The all-zero packet (magic=0, reply=0, msg_t=0, size=0) is decoded as
/// `MessageType::None` with empty fields; the `is_reply` flag is `false` for
/// this sentinel (Python returns `true` here but no caller uses that branch).
pub fn unpack(packet: &[u8]) -> Result<ParsedMessage, crate::error::ProtocolError> {
    if packet.len() < 8 {
        return Err(crate::error::ProtocolError::NotAPacket);
    }
    let magic = packet[0];
    let reply = packet[1];
    let msg_t_raw = u16::from_be_bytes([packet[2], packet[3]]);
    let size = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) as usize;

    // Special case: all-zero sentinel packet (Python `if magic == 0 and ...`).
    if magic == 0 && reply == 0 && msg_t_raw == 0 && size == 0 {
        return Ok(ParsedMessage {
            msg_t: MessageType::None,
            is_reply: false,
            fields: std::collections::HashMap::new(),
        });
    }

    if magic != 0x22 {
        return Err(crate::error::ProtocolError::NotAPacket);
    }

    let msg_t = MessageType::from_u8(msg_t_raw as u8).ok_or(
        crate::error::ProtocolError::UnexpectedMessage(MessageType::None),
    )?;

    let data = packet
        .get(8..size.min(packet.len()))
        .ok_or(crate::error::ProtocolError::NotAPacket)?;

    let mut fields = std::collections::HashMap::new();
    let mut cur = 0;
    while cur + 4 <= data.len() {
        let key_raw = u16::from_be_bytes([data[cur], data[cur + 1]]);
        let value_len = u16::from_be_bytes([data[cur + 2], data[cur + 3]]) as usize;
        let value_start = cur + 4;
        let value_end = value_start.saturating_add(value_len).min(data.len());
        let value = data.get(value_start..value_end).unwrap_or(&[]);

        // Map raw tag to Payload enum. Unknown tags still decode — store under
        // a placeholder; we don't error on unknown TLVs to match Python which
        // happily indexes `unpacked[Payload(key)]`.
        if let Some(payload) = payload_from_u16(key_raw) {
            fields.insert(payload, value.to_vec());
        }

        let padding = (4 - (value_len % 4)) % 4;
        cur = value_start + value_len + padding;
    }

    Ok(ParsedMessage {
        msg_t,
        is_reply: reply == 0x02,
        fields,
    })
}

fn payload_from_u16(v: u16) -> Option<Payload> {
    Some(match v {
        1 => Payload::Username,
        2 => Payload::Password,
        3 => Payload::ChalPassword,
        4 => Payload::Status,
        5 => Payload::CltPubIpv4,
        6 => Payload::SvrPubIpv4,
        7 => Payload::CltPrivIpv4,
        8 => Payload::SvrPrivIpv4,
        9 => Payload::SvrUdpPort,
        10 => Payload::IpSubnet,
        11 => Payload::NetmaskIpv4,
        12 => Payload::GatewayIpv4,
        13 => Payload::RouteMetrics,
        14 => Payload::IpsecSetting,
        15 => Payload::ModpGroup,
        16 => Payload::Keymat,
        17 => Payload::DnsIpv4,
        18 => Payload::WinsIpv4,
        19 => Payload::RouteIpv4,
        20 => Payload::PerfeSrvIpv4,
        21 => Payload::CommSrvIpv4,
        32 => Payload::KeyExchMode,
        48 => Payload::Spi,
        49 => Payload::EncAlg,
        50 => Payload::AuthAlg,
        51 => Payload::SessionId,
        53 => Payload::EnErroMsg,
        54 => Payload::ChErroMsg,
        64 => Payload::AliveStatus,
        81 => Payload::AuthType,
        82 => Payload::Cookie,
        83 => Payload::Disconnect,
        84 => Payload::ClientVer,
        96 => Payload::HostId,
        97 => Payload::HostName,
        112 => Payload::HostCheckMd5,
        115 => Payload::HostCheckResult,
        116 => Payload::HostCheckResultSize,
        128 => Payload::IpcompCpi,
        129 => Payload::IpcompAlg,
        132 => Payload::AllowPwd,
        133 => Payload::NeedSmsAuth,
        134 => Payload::SmsAuthCode,
        136 => Payload::ClientAutoConnect,
        _ => return None,
    })
}
