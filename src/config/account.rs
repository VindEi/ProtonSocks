use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireguardConfig {
    pub private_key: String,
    pub public_key: String,
    pub client_ip: String,
    pub dns: String,
    pub server_name: String,
    pub server_public_key: String,
    pub server_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub uid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountConfig {
    pub id: String,
    pub label: String,
    pub username: String,
    pub country: String,
    pub tier: u8,
    pub port: u16,
    pub tokens: AuthTokens,
    pub wireguard: WireguardConfig,
    pub created_at: u64,
}

impl AccountConfig {
    pub fn get_accounts_dir(config_dir: &Path) -> PathBuf {
        config_dir.join("accounts")
    }

    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse JSON in {}: {}", path.display(), e))
    }

    pub fn save(&self, config_dir: &Path) -> Result<PathBuf, String> {
        let accounts_dir = Self::get_accounts_dir(config_dir);
        fs::create_dir_all(&accounts_dir)
            .map_err(|e| format!("Failed to create accounts dir: {}", e))?;

        let file_path = accounts_dir.join(format!("{}.json", self.id));
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize account {}: {}", self.id, e))?;

        fs::write(&file_path, json)
            .map_err(|e| format!("Failed to write {}: {}", file_path.display(), e))?;

        Ok(file_path)
    }

    pub fn delete(&self, config_dir: &Path) -> Result<(), String> {
        let file_path = Self::get_accounts_dir(config_dir).join(format!("{}.json", self.id));
        if file_path.exists() {
            fs::remove_file(&file_path)
                .map_err(|e| format!("Failed to delete {}: {}", file_path.display(), e))?;
        }
        Ok(())
    }

    pub fn load_all(config_dir: &Path) -> Vec<Self> {
        let accounts_dir = Self::get_accounts_dir(config_dir);
        if !accounts_dir.exists() {
            return Vec::new();
        }

        let mut list = Vec::new();
        if let Ok(entries) = fs::read_dir(accounts_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(account) = Self::load_from_file(&path) {
                        list.push(account);
                    }
                }
            }
        }
        list.sort_by_key(|a| a.port);
        list
    }

    pub fn next_available_port(accounts: &[Self], base_port: u16) -> u16 {
        let mut candidate = base_port + 1;
        let mut used_ports: Vec<u16> = accounts.iter().map(|a| a.port).collect();
        used_ports.sort_unstable();
        while used_ports.contains(&candidate) {
            candidate += 1;
        }
        candidate
    }
}
