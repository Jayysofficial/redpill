//! Per-client PSK management.
//!
//! Each user has a 32-byte PSK stored as a 64-char hex file in `users_dir`.
//! Filename (minus `.key` extension) is the username.
//! Auth: trial-verify all PSKs against client HMAC. O(N) per handshake - fine for ≤253 users.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{info, warn};

use crate::auth::Authenticator;

type HmacSha256 = Hmac<Sha256>;

/// Maps PSK → username. Thread-safe behind RwLock in ServerState.
#[derive(Clone)]
pub struct UserStore {
    /// PSK (32 bytes) → username
    users: HashMap<[u8; 32], String>,
    dir: PathBuf,
}

/// Result of a successful multi-user auth.
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub username: String,
}

impl UserStore {
    /// Load all `*.key` files from the given directory.
    /// Each file contains a 64-char hex PSK.
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let mut users = HashMap::new();

        if !dir.exists() {
            anyhow::bail!("users directory does not exist: {}", dir.display());
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("key") {
                continue;
            }
            let username = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow::anyhow!("invalid filename: {}", path.display()))?;

            let content = std::fs::read_to_string(&path)?;
            let psk = parse_hex(content.trim())?;

            if users.contains_key(&psk) {
                warn!("Duplicate PSK for user '{username}', skipping");
                continue;
            }
            users.insert(psk, username);
        }

        info!("Loaded {} user(s) from {}", users.len(), dir.display());
        Ok(Self {
            users,
            dir: dir.to_path_buf(),
        })
    }

    /// Reload all users from disk.
    pub fn reload(&mut self) -> anyhow::Result<()> {
        let new = Self::load(&self.dir)?;
        self.users = new.users;
        Ok(())
    }

    /// Trial-verify: try each PSK against the client's HMAC.
    /// Returns the username on success, None on failure.
    pub fn verify(&self, nonce: &[u8; 32], mac: &[u8; 32]) -> Option<AuthResult> {
        for (psk, username) in &self.users {
            let mut hmac = HmacSha256::new_from_slice(psk).expect("HMAC key length valid");
            hmac.update(nonce);
            if hmac.verify_slice(mac).is_ok() {
                return Some(AuthResult {
                    username: username.clone(),
                });
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    pub fn usernames(&self) -> Vec<&str> {
        self.users.values().map(|s| s.as_str()).collect()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Add a user: generate random PSK, write to file, add to store.
    /// Returns the hex PSK.
    pub fn add_user(&mut self, name: &str) -> anyhow::Result<String> {
        if self.users.values().any(|u| u == name) {
            anyhow::bail!("user '{name}' already exists");
        }

        let mut psk = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut psk);
        let hex = psk.iter().map(|b| format!("{b:02x}")).collect::<String>();

        let path = self.dir.join(format!("{name}.key"));
        std::fs::write(&path, &hex)?;
        self.users.insert(psk, name.to_string());

        info!("Added user '{name}' (PSK file: {})", path.display());
        Ok(hex)
    }

    /// Remove a user: delete key file and remove from store.
    pub fn remove_user(&mut self, name: &str) -> anyhow::Result<()> {
        let psk = self
            .users
            .iter()
            .find(|(_, u)| u.as_str() == name)
            .map(|(k, _)| *k)
            .ok_or_else(|| anyhow::anyhow!("user '{name}' not found"))?;

        self.users.remove(&psk);
        let path = self.dir.join(format!("{name}.key"));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }

        info!("Removed user '{name}'");
        Ok(())
    }
}

impl Authenticator for UserStore {
    fn verify_auth(&self, nonce: &[u8; 32], mac: &[u8; 32]) -> Option<String> {
        self.verify(nonce, mac).map(|r| r.username)
    }
}

fn parse_hex(hex: &str) -> anyhow::Result<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        anyhow::bail!("PSK must be exactly 64 hex characters, got {}", hex.len());
    }
    let mut psk = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)?;
        psk[i] = u8::from_str_radix(s, 16)?;
    }
    Ok(psk)
}
