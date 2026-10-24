//! Hillstonux daemon library.
//!
//! Provides:
//! - `ipc`: request/response/event types shared with the GUI client.
//! - `server`: unix-domain socket server with length-prefix JSON framing.
//!
//! The binary entry point is `main.rs`, which wires up signal handling,
//! logging, and (eventually) the connection `Controller`.

pub mod controller;
pub mod data_plane;
pub mod instance;
pub mod ipc;
pub mod privhelper;
pub mod privops;
pub mod server;
