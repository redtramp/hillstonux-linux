//! Profile persistence: load/save the active VPN profile to a TOML file
//! under `$XDG_CONFIG_HOME/hillstonux/profiles.toml`.
//!
//! MVP: a single profile (named "default"). Multi-profile support is in the
//! TOML structure but not exposed in the UI yet.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub username: String,
    /// Reference into the Secret Service. The GUI resolves this back to a
    /// cleartext password via `secret::load` before forwarding to the daemon.
    pub password_ref: String,
    pub auto_connect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Settings {
    pub minimize_to_tray: bool,
    pub start_minimized: bool,
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfilesFile {
    pub settings: Settings,
    pub profile: Option<Profile>,
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml error: {0}")]
    Toml(String),
    #[error("path error: {0}")]
    Path(String),
}

pub fn profiles_path() -> Result<PathBuf, ProfileError> {
    let base = dirs::config_dir().ok_or_else(|| ProfileError::Path("no XDG_CONFIG_HOME".into()))?;
    let p = base.join("hillstonux").join("profiles.toml");
    Ok(p)
}

pub fn load() -> Result<ProfilesFile, ProfileError> {
    let path = profiles_path()?;
    if !path.exists() {
        return Ok(ProfilesFile::default());
    }
    let raw = std::fs::read_to_string(&path)?;
    let parsed: ProfilesFile =
        toml::from_str(&raw).map_err(|e| ProfileError::Toml(e.to_string()))?;
    Ok(parsed)
}

pub fn save(file: &ProfilesFile) -> Result<(), ProfileError> {
    let path = profiles_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let raw = toml::to_string_pretty(file).map_err(|e| ProfileError::Toml(e.to_string()))?;
    // Restrict permissions: profiles.toml contains the server/username, not
    // the password, but the password_ref is enough to look it up — keep it
    // user-readable only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
        {
            use std::io::Write;
            let _ = f.write_all(raw.as_bytes());
        }
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

    #[test]
    fn roundtrip_profiles_file() {
        let f = ProfilesFile {
            profile: Some(Profile {
                name: "default".into(),
                server: "sslvpn.example.com".into(),
                port: 4433,
                username: "alice".into(),
                password_ref: "libsecret:hillstonux:default".into(),
                auto_connect: false,
            }),
            ..Default::default()
        };
        let s = toml::to_string(&f).unwrap();
        let back: ProfilesFile = toml::from_str(&s).unwrap();
        assert_eq!(back.profile.unwrap().server, "sslvpn.example.com");
    }
}
