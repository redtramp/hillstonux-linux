//! Hillstone Secure Connect VPN protocol core.
//!
//! Pure logic library: protocol message encode/decode, ESP/IPsec encapsulation,
//! and configuration types. No I/O, no socket, no system calls.

pub mod client;
pub mod error;
pub mod ipsec;
pub mod message;

pub fn hello_world() -> &'static str {
    "hello"
}
