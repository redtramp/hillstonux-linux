//! Secret Service integration via the `keyring` crate.
//!
//! Each profile's password is stored under a unique account string derived
//! from the profile name, so multiple profiles can coexist without conflict.

use keyring::Entry;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("keyring error: {0}")]
    Keyring(String),
    #[error("no password stored for profile {0}")]
    NotFound(String),
    #[error("platform does not support Secret Service")]
    Unsupported,
}

const SERVICE: &str = "hillstonux";

/// Store `password` under `profile` in the OS keyring.
pub fn save(profile: &str, password: &str) -> Result<String, SecretError> {
    let account = account_name(profile);
    let entry = Entry::new(SERVICE, &account).map_err(|e| SecretError::Keyring(e.to_string()))?;
    entry
        .set_password(password)
        .map_err(|e| SecretError::Keyring(e.to_string()))?;
    Ok(account)
}

/// Look up the password for `profile`. Returns the account string the
/// caller can stash in `password_ref` so the daemon can resolve it later.
pub fn load(profile: &str) -> Result<String, SecretError> {
    let account = account_name(profile);
    let entry = Entry::new(SERVICE, &account).map_err(|e| SecretError::Keyring(e.to_string()))?;
    match entry.get_password() {
        Ok(_) => Ok(account),
        Err(keyring::Error::NoEntry) => Err(SecretError::NotFound(profile.to_string())),
        Err(e) => Err(SecretError::Keyring(e.to_string())),
    }
}

/// Delete the password for `profile`. Idempotent: no error if missing.
/// Retrieve the cleartext password for profile from the OS keyring.
/// The frontend calls this to resolve the plaintext before forwarding it to
/// the daemon over the local trusted socket.
pub fn get(profile: &str) -> Result<String, SecretError> {
    let account = account_name(profile);
    let entry = Entry::new(SERVICE, &account).map_err(|e| SecretError::Keyring(e.to_string()))?;
    entry.get_password().map_err(|e| match e {
        keyring::Error::NoEntry => SecretError::NotFound(profile.to_string()),
        e => SecretError::Keyring(e.to_string()),
    })
}

pub fn delete(profile: &str) -> Result<(), SecretError> {
    let account = account_name(profile);
    let entry = Entry::new(SERVICE, &account).map_err(|e| SecretError::Keyring(e.to_string()))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(SecretError::Keyring(e.to_string())),
    }
}

fn account_name(profile: &str) -> String {
    // Restrict to a safe charset; some Secret Service backends reject ':'.
    profile
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_name_replaces_special_chars() {
        assert_eq!(account_name("office"), "office");
        assert_eq!(account_name("home network"), "home_network");
        assert_eq!(account_name("a:b:c"), "a_b_c");
    }
}
