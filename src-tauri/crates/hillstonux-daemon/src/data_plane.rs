//! VPN data plane: two async tasks bridging TUN ↔ ESP-over-UDP.
//!
//! Task A (outbound): read IP packets from TUN → encapsulate via outbound
//! SA (sa_out + out_iv) → send to the server's UDP port.
//!
//! Task B (inbound): receive ESP packets from UDP → verify + decapsulate
//! via inbound SA (sa_in + IV from packet) → write plaintext to TUN.
//!
//! Both tasks honour a `tokio::sync::watch` shutdown channel set by
//! `Controller::disconnect()`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use hillstonux_core::ipsec::{decrypt_packet, encrypt_packet, EncAlg, ExpandedKeys};
use hillstonux_net::{EspSocket, TunDevice};
use thiserror::Error;
use tokio::sync::{mpsc, watch};

#[derive(Debug, Error)]
pub enum DataPlaneError {
    #[error("tun io: {0}")]
    TunIo(String),
}

/// Parameters for spawning the data-plane tasks.
pub struct SpawnParams {
    /// The TUN device (wrapped in Arc so both tasks can share it).
    pub tun: Arc<TunDevice>,
    pub udp: EspSocket,
    /// Server (IP, UDP port) to send encrypted packets to.
    pub server: SocketAddr,
    /// Outbound ESP SecurityAssociation: crypt_key, auth_key, IV. The SPI
    /// embedded in the packet header is `out_spi` (this is the SPI the
    /// peer will use as their inbound selector).
    pub sa_out: ExpandedKeys,
    pub out_spi: u32,
    /// Inbound ESP SecurityAssociation: crypt_key, auth_key. IV is read
    /// from each inbound packet header.
    pub sa_in: ExpandedKeys,
    /// Algorithm selection (matches what `ClientCore::exchange_key` reported).
    pub enc_alg: EncAlg,
    pub use_sha1: bool,
    pub iv_size: usize,
    /// Channel used by Controller::connect to ask tasks to exit, and by
    /// Controller::disconnect to fire the signal.
    pub shutdown: watch::Receiver<bool>,
    /// Stats are forwarded via this channel back to the Controller.
    pub stats_tx: mpsc::UnboundedSender<StatsEvent>,
}
/// Reports byte counters back to the controller so it can emit `Stats`
/// events and update the `Connected` state's bytes_in/out fields.
#[derive(Debug, Clone, Copy)]
pub enum StatsEvent {
    BytesIn(u64),
    BytesOut(u64),
}

/// Spawn the two data-plane tasks and return their JoinHandles. The
/// handles complete when the tasks observe the shutdown signal.
pub fn spawn(params: SpawnParams) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    let SpawnParams {
        tun,
        udp,
        server,
        sa_out,
        out_spi,
        sa_in,
        enc_alg,
        use_sha1,
        iv_size,
        shutdown,
        stats_tx,
    } = params;

    let seq = Arc::new(AtomicU32::new(1));

    // Task A: TUN -> UDP (encrypt)
    let tun_a = tun.clone();
    let udp_a = udp.clone();
    let stats_a = stats_tx.clone();
    let seq_a = seq.clone();
    let shutdown_a = shutdown.clone();
    let task_a = tokio::spawn(async move {
        outbound_loop(
            tun_a, udp_a, server, sa_out, out_spi, enc_alg, use_sha1, seq_a, stats_a, shutdown_a,
        )
        .await;
    });

    // Task B: UDP -> TUN (decrypt)
    let tun_b = tun;
    let udp_b = udp;
    let stats_b = stats_tx;
    let shutdown_b = shutdown;
    let task_b = tokio::spawn(async move {
        inbound_loop(
            udp_b, tun_b, sa_in, enc_alg, use_sha1, iv_size, stats_b, shutdown_b,
        )
        .await;
    });

    (task_a, task_b)
}

#[allow(clippy::too_many_arguments)]
async fn outbound_loop(
    tun: Arc<TunDevice>,
    udp: EspSocket,
    server: SocketAddr,
    sa_out: ExpandedKeys,
    out_spi: u32,
    enc_alg: EncAlg,
    use_sha1: bool,
    seq: Arc<AtomicU32>,
    stats_tx: mpsc::UnboundedSender<StatsEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut scratch = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("outbound: shutdown received");
                    break;
                }
            }
            read_result = tokio::task::spawn_blocking({
                let tun = tun.clone();
                let mut buf = std::mem::take(&mut scratch);
                move || {
                    let n = match tun.recv(&mut buf) {
                        Ok(n) => n,
                        Err(e) => return Err((buf, DataPlaneError::TunIo(e.to_string()))),
                    };
                    Ok((buf, n))
                }
            }) => {
                match read_result {
                    Ok(Ok((returned_buf, n))) => {
                        scratch = returned_buf;
                        if n == 0 { continue; }
                        let pkt = scratch[..n].to_vec();
                        let seq_no = seq.fetch_add(1, Ordering::Relaxed);
                        let encrypted = encrypt_packet(
                            out_spi,
                            seq_no,
                            &sa_out.out_crypt_key,
                            &sa_out.out_auth_key,
                            &sa_out.out_iv,
                            sa_out.out_iv.len(),
                            enc_alg,
                            use_sha1,
                            &pkt,
                        );
                        if let Err(e) = udp.send_to(&encrypted, server).await {
                            tracing::warn!(?e, "outbound udp send failed");
                            continue;
                        }
                        let _ = stats_tx.send(StatsEvent::BytesOut(n as u64));
                    }
                    Ok(Err((returned_buf, e))) => {
                        scratch = returned_buf;
                        tracing::warn!(?e, "outbound tun read error");
                    }
                    Err(e) => {
                        tracing::warn!(?e, "outbound tun spawn_blocking join error");
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn inbound_loop(
    udp: EspSocket,
    tun: Arc<TunDevice>,
    sa_in: ExpandedKeys,
    enc_alg: EncAlg,
    use_sha1: bool,
    iv_size: usize,
    stats_tx: mpsc::UnboundedSender<StatsEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("inbound: shutdown received");
                    break;
                }
            }
            recv_result = udp.recv_from(&mut buf) => {
                match recv_result {
                    Ok((n, _from)) => {
                        let pkt = buf[..n].to_vec();
                        let plaintext = match decrypt_packet(
                            &sa_in.in_crypt_key,
                            &sa_in.in_auth_key,
                            iv_size,
                            enc_alg,
                            use_sha1,
                            &pkt,
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::debug!(?e, "inbound decrypt failed (likely stray)");
                                continue;
                            }
                        };
                        let plain_len = plaintext.len();
                        let tun_clone = tun.clone();
                        let stats = stats_tx.clone();
                        let write_result = tokio::task::spawn_blocking(move || {
                            tun_clone.send(&plaintext).map_err(|e| DataPlaneError::TunIo(e.to_string()))
                        }).await;
                        match write_result {
                            Ok(Ok(n)) => {
                                let _ = stats.send(StatsEvent::BytesIn(n as u64));
                            }
                            Ok(Err(e)) => {
                                tracing::warn!(?e, "inbound tun write failed");
                            }
                            Err(e) => {
                                tracing::warn!(?e, "inbound tun write join error");
                            }
                        }
                        let _ = plain_len;
                    }
                    Err(e) => {
                        tracing::warn!(?e, "inbound udp recv failed");
                    }
                }
            }
        }
    }
}
