//! Tauri commands. Defined here (not in `lib.rs`) so the `#[tauri::command]`
//! macro only expands once — `lib.rs` and `main.rs` are two compilation
//! units in the same crate, and the macro generates a function-name symbol
//! that can't be defined in both.

use crate::config::{self, LoginConfig};
use crate::ipc_client::{IpcClient, IpcRequestParams};
use crate::profile::{self, ProfilesFile};
use hillstonux_daemon::ipc::{IpcResponse, VpnStateDto};
use tauri::State;

/// Look up the daemon's default unix-socket path. The frontend uses this
/// to know where to connect.
#[tauri::command]
pub fn daemon_socket_path() -> String {
    if let Some(p) = std::env::var_os("HILLSTONUX_SOCKET") {
        return p.to_string_lossy().into_owned();
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let mut p = std::path::PathBuf::from(dir);
        p.push("hillstonux");
        p.push("hillstonux.sock");
        return p.to_string_lossy().into_owned();
    }
    "/tmp/hillstonux.sock".to_string()
}

/// Return the current app version (from tauri.conf.json).
#[tauri::command]
pub fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Load the active profile from `~/.config/hillstonux/profiles.toml`. The
/// frontend calls this once at startup to populate the form fields.
#[tauri::command]
pub fn load_profiles() -> Result<ProfilesFile, String> {
    profile::load().map_err(|e| e.to_string())
}

/// Save the given profiles file back to disk. Used when the user edits
/// server / username / auto-connect preferences. Passwords are NOT saved
/// here — use `save_password` first to put them in the keyring, then
/// `save_profiles` to persist the profile metadata.
#[tauri::command]
pub fn save_profiles(file: ProfilesFile) -> Result<(), String> {
    profile::save(&file).map_err(|e| e.to_string())
}

/// Store a password in the OS keyring under the given profile's account.
/// Returns the opaque account string to be stored in `Profile::password_ref`.
#[tauri::command]
pub fn save_password(profile_name: String, password: String) -> Result<String, String> {
    crate::secret::save(&profile_name, &password).map_err(|e| e.to_string())
}

/// Retrieve the cleartext password for a profile from the keyring.
/// The frontend uses this to resolve the plaintext before sending vpn_connect.
#[tauri::command]
pub fn get_password(profile_name: String) -> Result<String, String> {
    crate::secret::get(&profile_name).map_err(|e| e.to_string())
}

/// Delete a profile's password from the keyring.
#[tauri::command]
pub fn delete_password(profile_name: String) -> Result<(), String> {
    crate::secret::delete(&profile_name).map_err(|e| e.to_string())
}

/// Load the login config from `~/.config/hillstonux/config.json`. Returns an
/// empty/default config when the file is absent, so the form rehydrates to
/// blanks on first launch.
#[tauri::command]
pub fn load_config() -> Result<LoginConfig, String> {
    config::load().map_err(|e| e.to_string())
}

/// Persist the login config back to `~/.config/hillstonux/config.json`.
/// Called by the GUI whenever the user connects, so edits made on the login
/// screen survive a restart. The file is written with `0600`.
#[tauri::command]
pub fn save_config(cfg: LoginConfig) -> Result<(), String> {
    config::save(&cfg).map_err(|e| e.to_string())
}

// ----------------------------------------------------------------------------
// Daemon bridge commands. These proxy IpcRequests over the shared IpcClient
// held in Tauri state. The event pump (spawned in `lib.rs::build_app`) reads
// streamed VpnEvents off the same connection and re-emits them as Tauri
// events named `vpn-event`.

fn map_err(e: crate::ipc_client::IpcError) -> String {
    e.to_string()
}

fn unwrap(resp: IpcResponse) -> Result<serde_json::Value, String> {
    match resp {
        IpcResponse::Ok { data, .. } => Ok(data.unwrap_or(serde_json::Value::Null)),
        IpcResponse::Err { code, message, .. } => Err(format!("daemon error {code}: {message}")),
        IpcResponse::Event(_) => Err("unexpected event frame on reply".into()),
    }
}

/// Ask the daemon to start a VPN connection. Returns immediately; the
/// connection progress arrives as `vpn-event` Tauri events.
#[tauri::command]
pub async fn vpn_connect(
    ipc: State<'_, IpcClient>,
    params: hillstonux_daemon::ipc::ConnectParams,
) -> Result<(), String> {
    let resp = ipc
        .request(IpcRequestParams::Connect {
            server: &params.server,
            port: params.port,
            user: &params.user,
            password: &params.password,
            password_ref: &params.password_ref,
            full_tunnel: params.full_tunnel,
        })
        .await
        .map_err(map_err)?;
    unwrap(resp).map(|_| ())
}

/// Ask the daemon to disconnect. Returns once the data-plane tasks have
/// stopped and routes/DNS have been restored.
#[tauri::command]
pub async fn vpn_disconnect(ipc: State<'_, IpcClient>) -> Result<(), String> {
    let resp = ipc
        .request(IpcRequestParams::Disconnect)
        .await
        .map_err(map_err)?;
    unwrap(resp).map(|_| ())
}

/// Query the daemon for its current state. Used by the frontend on startup
/// to render the correct phase without waiting for the first event.
#[tauri::command]
pub async fn vpn_state(ipc: State<'_, IpcClient>) -> Result<VpnStateDto, String> {
    let resp = ipc
        .request(IpcRequestParams::State)
        .await
        .map_err(map_err)?;
    let value = unwrap(resp)?;
    serde_json::from_value(value).map_err(|e| e.to_string())
}
