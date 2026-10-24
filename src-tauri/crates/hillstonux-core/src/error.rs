//! Protocol errors returned by Hillstone VPN client operations.

use crate::message::MessageType;
use std::fmt;

#[derive(Debug)]
pub enum ProtocolError {
    Io(std::io::Error),
    Tls(String),
    NotAPacket,
    AuthFailed(u32),
    ClientInfoFailed(u32),
    NetworkInfoFailed(u32),
    KeyExchangeFailed(u32),
    UnsupportedAlgorithm { enc: u16, auth: u16 },
    UnexpectedMessage(MessageType),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Io(e) => write!(f, "io error: {}", e),
            ProtocolError::Tls(m) => write!(f, "tls error: {}", m),
            ProtocolError::NotAPacket => write!(f, "not a valid packet"),
            ProtocolError::AuthFailed(code) => write!(f, "authentication failed (code={})", code),
            ProtocolError::ClientInfoFailed(code) => {
                write!(f, "client info failed (code={})", code)
            }
            ProtocolError::NetworkInfoFailed(code) => {
                write!(f, "network info failed (code={})", code)
            }
            ProtocolError::KeyExchangeFailed(code) => {
                write!(f, "key exchange failed (code={})", code)
            }
            ProtocolError::UnsupportedAlgorithm { enc, auth } => write!(
                f,
                "unsupported algorithm combination: enc=0x{:02x}, auth=0x{:02x}",
                enc, auth
            ),
            ProtocolError::UnexpectedMessage(mt) => {
                write!(f, "unexpected message type: {:?}", mt)
            }
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProtocolError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(e: std::io::Error) -> Self {
        ProtocolError::Io(e)
    }
}
