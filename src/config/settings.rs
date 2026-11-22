use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonSettings {
    pub base_port: u16,
    pub bind_address: String,
    pub auth_required: bool,
    pub auth_username: String,
    pub auth_password: String,
    pub benchmark_interval_hours: u64,
    pub auto_best_metric: String, // "ping" or "speed"
    pub best_account_id: Option<String>,
}

impl Default for DaemonSettings {
    fn default() -> Self {
        Self {
            base_port: 25000,
            bind_address: "127.0.0.1".to_string(),
            auth_required: false,
            auth_username: String::new(),
            auth_password: String::new(),
            benchmark_interval_hours: 4,
            auto_best_metric: "ping".to_string(),
            best_account_id: None,
        }
    }
}

impl DaemonSettings {
    pub fn get_default_config_dir() -> PathBuf {
        if let Ok(dir) = std::env::var("PROTON_SOCKS_DIR") {
            PathBuf::from(dir)
        } else if cfg!(windows) {
            PathBuf::from("C:\\ProgramData\\proton-socks")
        } else {
            PathBuf::from("/etc/proton-socks")
        }
    }

    pub fn load_or_default(config_dir: &Path) -> Self {
        let config_file = config_dir.join("config.json");
        if config_file.exists() {
            if let Ok(content) = fs::read_to_string(&config_file) {
                if let Ok(settings) = serde_json::from_str::<DaemonSettings>(&content) {
                    return settings;
                }
            }
        }
        Self::default()
    }

    pub fn save(&self, config_dir: &Path) -> std::io::Result<()> {
        fs::create_dir_all(config_dir)?;
        let config_file = config_dir.join("config.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(config_file, json)
    }

    pub fn is_open_interface(&self) -> bool {
        self.bind_address == "0.0.0.0" || self.bind_address == "::"
    }

    pub fn validate_security(&mut self) -> Result<(), String> {
        // Enforce credentials if binding on open network
        if self.is_open_interface() {
            self.auth_required = true;
            if self.auth_username.trim().is_empty() || self.auth_password.trim().is_empty() {
                return Err("Listening on 0.0.0.0 requires non-empty username and password.".to_string());
            }
        }
        Ok(())
    }
}
