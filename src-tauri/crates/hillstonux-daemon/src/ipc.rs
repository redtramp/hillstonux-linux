//! IPC types shared between the daemon and the GUI client.
//!
//! Wire format over the unix domain socket:
//! - Length-prefix framing: 4-byte big-endian length, then UTF-8 JSON payload
//! - One connection per client; the daemon serializes requests
//! - Events from the daemon are pushed on the same connection

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectParams {
    pub server: String,
    pub port: u16,
    pub user: String,
    /// 已解析出的明文密码（由 GUI 从密钥环取出后通过本地 0600 socket 传入，
    /// 仅在本机进程间可信传递）。
    #[serde(default)]
    pub password: String,
    /// Reference into the Secret Service — kept for backwards compatibility.
    #[serde(default)]
    pub password_ref: String,
    /// true = 全隧道（接管默认路由，与 Python 参考实现行为一致）；
    /// false（默认）= 分流，只把服务端 SET_ROUTE 下发的子网走隧道，
    /// 外网保持直连。旧版本 GUI 不携带该字段时按 false 处理。
    #[serde(default)]
    pub full_tunnel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcRequest {
    Connect { id: u64, params: ConnectParams },
    Disconnect { id: u64 },
    State { id: u64 },
    Ping { id: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcResponse {
    Ok {
        id: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
    Err {
        id: u64,
        code: u32,
        message: String,
    },
    Event(VpnEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VpnEvent {
    StateChanged { state: VpnStateDto },
    LogLine { level: LogLevel, msg: String },
    Stats { bytes_in: u64, bytes_out: u64 },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum VpnStateDto {
    Idle,
    Connecting {
        step: String,
    },
    Handshaking,
    Connected {
        since_secs: u64,
        bytes_in: u64,
        bytes_out: u64,
    },
    Reconnecting {
        attempt: u32,
        next_in_secs: u64,
    },
    Disconnecting,
    Error {
        code: u32,
        message: String,
    },
}

/// Length-prefix framing helpers. Each frame: [len: u32 BE][json bytes].
pub mod framing {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub async fn write_frame<W: AsyncWriteExt + Unpin, T: serde::Serialize>(
        writer: &mut W,
        msg: &T,
    ) -> std::io::Result<()> {
        let json = serde_json::to_vec(msg).map_err(std::io::Error::other)?;
        let len = (json.len() as u32).to_be_bytes();
        writer.write_all(&len).await?;
        writer.write_all(&json).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn read_frame<R: AsyncReadExt + Unpin, T: serde::de::DeserializeOwned>(
        reader: &mut R,
    ) -> std::io::Result<T> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut json = vec![0u8; len];
        reader.read_exact(&mut json).await?;
        serde_json::from_slice(&json).map_err(std::io::Error::other)
    }
}
