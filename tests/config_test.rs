use proton_socks::config::{AccountConfig, AuthTokens, DaemonSettings, WireguardConfig};
use tempfile::tempdir;

#[test]
fn test_settings_save_and_load() {
    let dir = tempdir().unwrap();
    let config_dir = dir.path();

    let mut settings = DaemonSettings::default();
    settings.base_port = 26000;
    settings.bind_address = "127.0.0.1".to_string();
    settings.auto_best_metric = "speed".to_string();
    settings.save(config_dir).unwrap();

    let loaded = DaemonSettings::load_or_default(config_dir);
    assert_eq!(loaded.base_port, 26000);
    assert_eq!(loaded.bind_address, "127.0.0.1");
    assert_eq!(loaded.auto_best_metric, "speed");
}

#[test]
fn test_security_validation_on_open_interface() {
    let mut settings = DaemonSettings::default();
    settings.bind_address = "0.0.0.0".to_string();
    settings.auth_username = String::new();
    settings.auth_password = String::new();

    // Must fail without credentials
    assert!(settings.validate_security().is_err());

    // Must succeed when credentials are provided
    settings.auth_username = "admin".to_string();
    settings.auth_password = "supersecretpassword".to_string();
    assert!(settings.validate_security().is_ok());
    assert!(settings.auth_required);
}

#[test]
fn test_modular_account_lifecycle() {
    let dir = tempdir().unwrap();
    let config_dir = dir.path();

    let account = AccountConfig {
        id: "acc_1_nl".to_string(),
        label: "Proton-NL".to_string(),
        username: "testuser".to_string(),
        country: "NL".to_string(),
        tier: 0,
        port: 25001,
        tokens: AuthTokens {
            access_token: "tok1".to_string(),
            refresh_token: "tok2".to_string(),
            uid: "uid123".to_string(),
        },
        wireguard: WireguardConfig {
            private_key: "priv".to_string(),
            public_key: "pub".to_string(),
            client_ip: "10.2.0.2/32".to_string(),
            dns: "10.2.0.1".to_string(),
            server_name: "NL-FREE#1".to_string(),
            server_public_key: "serverpub".to_string(),
            server_endpoint: "1.2.3.4:51820".to_string(),
        },
        created_at: 1700000000,
    };

    // Save
    account.save(config_dir).unwrap();

    // Load all
    let all = AccountConfig::load_all(config_dir);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, "acc_1_nl");
    assert_eq!(all[0].port, 25001);

    // Port allocation calculation
    let next = AccountConfig::next_available_port(&all, 25000);
    assert_eq!(next, 25002);

    // Delete
    account.delete(config_dir).unwrap();
    let remaining = AccountConfig::load_all(config_dir);
    assert_eq!(remaining.len(), 0);
}
