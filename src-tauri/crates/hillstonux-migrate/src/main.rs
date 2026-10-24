//! One-shot migration tool: convert the Python `hillstonux` `config.json`
//! into the Rust `~/.config/hillstonux/profiles.toml` + a Secret Service
//! entry for the password.
//!
//! Usage:
//!     hillstonux-migrate <path/to/config.json>
//!
//! Reads `server`, `port`, `user`, `pass` from the JSON. Stores `pass` in
//! the OS keyring under account `hillstonux:default`. Generates a TOML
//! profile referencing that account. Renames the original JSON to
//! `<path>.migrated.bak`. Prints a summary and exits 0 on success.
//!
//! Idempotent: re-running on a migrated config will overwrite both the TOML
//! profile and the keyring entry with the values from the JSON. It will NOT
//! re-rename the backup file (a second run sees no JSON to migrate and
//! exits with an error message).

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use keyring::Entry;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PyConfig {
    server: String,
    port: u16,
    user: String,
    pass: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Profile {
    name: String,
    server: String,
    port: u16,
    username: String,
    password_ref: String,
    #[serde(default)]
    auto_connect: bool,
    #[serde(default)]
    custom_routes: Vec<String>,
}

#[derive(Debug, serde::Serialize, Default)]
struct Settings {
    #[serde(default)]
    auto_reconnect: bool,
    #[serde(default = "default_max_attempts")]
    max_reconnect_attempts: u32,
}

#[allow(dead_code)] // referenced as serde default in case user overrides in TOML
fn default_max_attempts() -> u32 {
    5
}

#[derive(Debug, serde::Serialize)]
struct ProfilesFile {
    settings: Settings,
    profile: Profile,
}

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: hillstonux-migrate <config.json>")?;

    let cfg = load_and_validate(&path)?;
    let profile_name = "default";
    let password_ref = store_password(profile_name, &cfg.pass)?;

    let profile = Profile {
        name: profile_name.into(),
        server: cfg.server,
        port: cfg.port,
        username: cfg.user,
        password_ref: password_ref.clone(),
        auto_connect: false,
        custom_routes: Vec::new(),
    };
    let file = ProfilesFile {
        settings: Settings::default(),
        profile: profile.clone(),
    };

    let toml_path = profiles_toml_path()?;
    if let Some(parent) = toml_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating config dir {}", parent.display()))?;
    }
    let raw = toml::to_string_pretty(&file)?;
    std::fs::write(&toml_path, raw).with_context(|| format!("writing {}", toml_path.display()))?;

    let backup = backup_path(&path);
    std::fs::rename(&path, &backup)
        .with_context(|| format!("renaming {} -> {}", path, backup.display()))?;

    println!("Migration complete:");
    println!("  profile:    {} (user={})", profile.name, profile.username);
    println!("  server:     {}:{}", profile.server, profile.port);
    println!("  password:   stored in keyring as `{}`", password_ref);
    println!("  TOML:       {}", toml_path.display());
    println!("  backup:     {}", backup.display());
    Ok(())
}

fn load_and_validate(raw_path: &str) -> Result<PyConfig> {
    // Defence-in-depth: validate the input path before opening it.
    //
    // - Canonicalize to resolve any `..` segments and symlinks.
    // - Refuse non-regular files (devices, directories, sockets, symlinks-to-other).
    // - Require the file to live under one of the conventional Hillstone
    //   config locations. Refuse paths the user almost certainly didn't mean,
    //   like `/etc/passwd`.
    let canonical =
        std::fs::canonicalize(raw_path).with_context(|| format!("canonicalizing {}", raw_path))?;
    let meta =
        std::fs::metadata(&canonical).with_context(|| format!("stat {}", canonical.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", canonical.display());
    }

    // Allow only conventional locations:
    //   /etc/hillstonux/...
    //   $HOME/.hillstonux/...
    //   anywhere under the current working directory (for dev / testing)
    //   the Python project's own `config.json` (in case someone passes the
    //   absolute path to the upstream repo's copy)
    let canon_str = canonical.to_string_lossy();
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    let home_str = home.to_string_lossy().into_owned();
    let cwd = std::env::current_dir().unwrap_or_default();
    let cwd_str = cwd.to_string_lossy().into_owned();

    let allowed = [
        "/etc/hillstonux/".to_string(),
        format!("{}/.hillstonux/", home_str),
        format!("{}/", cwd_str),
        format!("{}/hillstonux/", cwd_str),
        format!("{}/hillstonux/hillstonux/", cwd_str),
    ];
    if !allowed.iter().any(|prefix| canon_str.starts_with(prefix)) {
        bail!(
            "{} is outside the conventional Hillstone config locations; \
             refusing to read it. Pass a path under /etc/hillstonux, \
             $HOME/.hillstonux, or the project working directory.",
            canonical.display()
        );
    }

    let raw = std::fs::read_to_string(&canonical)
        .with_context(|| format!("reading {}", canonical.display()))?;
    let cfg: PyConfig = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {} as JSON", canonical.display()))?;
    if cfg.server.is_empty() || cfg.user.is_empty() {
        bail!("config.json is missing server or user");
    }
    Ok(cfg)
}

fn store_password(profile: &str, password: &str) -> Result<String> {
    let account = format!("hillstonux:{}", profile);
    let entry =
        Entry::new("hillstonux", &account).map_err(|e| anyhow::anyhow!("keyring init: {}", e))?;
    entry
        .set_password(password)
        .map_err(|e| anyhow::anyhow!("keyring set: {}", e))?;
    Ok(format!("libsecret:{}", account))
}

fn profiles_toml_path() -> Result<PathBuf> {
    let base = dirs::config_dir().context("no $XDG_CONFIG_HOME / home directory")?;
    Ok(base.join("hillstonux").join("profiles.toml"))
}

fn backup_path(original: &str) -> PathBuf {
    let mut p = PathBuf::from(original);
    let new_name = match p.file_name().and_then(|n| n.to_str()) {
        Some(name) => format!("{}.migrated.bak", name),
        None => "config.json.migrated.bak".to_string(),
    };
    p.set_file_name(new_name);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_path_appends_suffix() {
        let p = backup_path("/home/u/.hillstonux/config.json");
        assert_eq!(
            p.to_str().unwrap(),
            "/home/u/.hillstonux/config.json.migrated.bak"
        );
    }

    #[test]
    fn backup_path_handles_relative() {
        let p = backup_path("./config.json");
        assert!(p.to_str().unwrap().ends_with("config.json.migrated.bak"));
    }

    #[test]
    fn rejects_path_traversal() {
        // Pass `/etc/passwd` — a real file but not in any allowed location.
        // We expect load_and_validate to refuse it before opening.
        let result = load_and_validate("/etc/passwd");
        assert!(
            result.is_err(),
            "expected refusal of /etc/passwd, got {:?}",
            result
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("outside the conventional") || msg.contains("not a regular file"),
            "unexpected error: {}",
            msg
        );
    }

    #[test]
    fn rejects_nonexistent_path() {
        let result = load_and_validate("/tmp/hillstonux-does-not-exist-12345.json");
        assert!(result.is_err());
    }
}
