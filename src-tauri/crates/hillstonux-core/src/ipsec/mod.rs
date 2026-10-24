//! ESP/IPsec primitives: keymat expansion, ESP packet encaps/decaps.

pub mod esp;
pub mod keymat;

pub use esp::{decrypt_packet, encrypt_packet, EncAlg};
pub use keymat::{expand, ExpandedKeys};
