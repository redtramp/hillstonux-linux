//! Login-config persistence: load/save the GUI login form to a JSON file.
//!
//! The file lives at `config.json` next to the GUI executable (so it can be
//! hand-edited alongside the app, matching the upstream Python client). When
//! that directory is not writable — for example a system-installed `/usr/bin`
//! layout run by a non-root user — we fall back to
//! `$XDG_CONFIG_HOME/hillstonux/config.json`.
//!
//! The GUI reads this on startup to rehydrate the login form, and writes it
//! back whenever the user connects (so edits made on the login screen are
//! persisted for next launch). It is also meant to be hand-edited: the file
//! is created with `0600` so only the owning user can read the (plaintext)
//! password.
//!
//! SECURITY NOTE: the password is stored in plaintext to keep the file fully
//! self-contained and manually editable. If you need the password in the OS
//! keyring instead, keep it out of this file and resolve it separately.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoginConfig {
    pub server: String,
    pub port: u16,
    // Accept both `username` and the hand-written shorthand `user`.
    #[serde(default, alias = "user")]
    pub username: String,
    // Accept both `password` and the hand-written shorthand `pass`.
    #[serde(default, alias = "pass")]
    pub password: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(String),
}

pub fn config_path() -> PathBuf {
    let explicit = std::env::var_os("HILLSTONUX_CONFIG").map(PathBuf::from);
    let exe_sibling = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join("config.json")));
    let exe_dir_writable = exe_sibling
        .as_ref()
        .and_then(|p| p.parent())
        .map(dir_writable)
        .unwrap_or(false);
    let user_config = dirs::config_dir().map(|base| base.join("hillstonux").join("config.json"));
    select_config_path(explicit, exe_sibling, exe_dir_writable, user_config)
}

/// Pick the config file to use.
///
/// Order:
/// 1. explicit `HILLSTONUX_CONFIG` override,
/// 2. an existing `config.json` next to the executable,
/// 3. that path when the executable directory is writable (first save),
/// 4. the per-user path (read-only installs such as `/usr/bin`).
fn select_config_path(
    explicit: Option<PathBuf>,
    exe_sibling: Option<PathBuf>,
    exe_dir_writable: bool,
    user_config: Option<PathBuf>,
) -> PathBuf {
    if let Some(path) = explicit {
        return path;
    }
    if let Some(path) = exe_sibling.as_ref().filter(|p| p.exists()) {
        return path.clone();
    }
    if exe_dir_writable {
        if let Some(path) = exe_sibling {
            return path;
        }
    }
    user_config.unwrap_or_else(|| PathBuf::from("config.json"))
}

/// Best-effort probe: can we create/write a file inside `dir`?
fn dir_writable(dir: &Path) -> bool {
    if dir.exists() {
        // Opening a directory for write succeeds when we have write permission
        // on it (the permission needed to add/remove files).
        std::fs::OpenOptions::new().write(true).open(dir).is_ok()
    } else {
        std::fs::create_dir_all(dir).is_ok()
    }
}

pub fn load() -> Result<LoginConfig, ConfigError> {
    let path = config_path();
    if !path.exists() {
        return Ok(LoginConfig::default());
    }
    let raw = std::fs::read_to_string(&path)?;
    serde_json::from_str(&raw).map_err(|e| ConfigError::Json(e.to_string()))
}

pub fn save(cfg: &LoginConfig) -> Result<(), ConfigError> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(cfg).map_err(|e| ConfigError::Json(e.to_string()))?;
    // Restrict to the owning user: the file contains the (plaintext) password.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(raw.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, raw)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hillstonux-config-test-{}-{}",
            std::process::id(),
            name
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("config.json")
    }

    #[test]
    fn explicit_override_wins_even_when_other_configs_exist() {
        let user = temp_config("explicit-user");
        let exe = temp_config("explicit-exe");
        std::fs::write(&user, "{}").unwrap();
        std::fs::write(&exe, "{}").unwrap();
        let explicit = temp_config("explicit-env");
        assert_eq!(
            select_config_path(Some(explicit.clone()), Some(exe), true, Some(user)),
            explicit
        );
    }

    #[test]
    fn exe_sibling_wins_over_user_config() {
        let user = temp_config("exe-wins-user");
        let exe = temp_config("exe-wins-exe");
        std::fs::write(&user, "{}").unwrap();
        std::fs::write(&exe, "{}").unwrap();
        assert_eq!(
            select_config_path(None, Some(exe.clone()), true, Some(user)),
            exe
        );
    }

    #[test]
    fn writable_exe_dir_is_used_for_the_first_save() {
        let user = temp_config("first-save-user");
        let exe = temp_config("first-save-exe"); // deliberately not created
        assert_eq!(
            select_config_path(None, Some(exe.clone()), true, Some(user)),
            exe
        );
    }

    #[test]
    fn read_only_exe_dir_falls_back_to_the_user_config() {
        let user = temp_config("readonly-user");
        let exe = temp_config("readonly-exe"); // deliberately not created
        assert_eq!(
            select_config_path(None, Some(exe), false, Some(user.clone())),
            user
        );
    }
}
