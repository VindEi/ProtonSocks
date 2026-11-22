use crate::api::client::ProtonApiClient;
use crate::api::srp::ProtonSrp;
use crate::benchmark::BenchmarkRunner;
use crate::config::{AccountConfig, AuthTokens, DaemonSettings, WireguardConfig};
use crate::menu::views::MenuViews;
use colored::Colorize;
use inquire::{Confirm, CustomType, Password, Select, Text};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct MenuPrompts {
    pub config_dir: PathBuf,
}

impl MenuPrompts {
    pub fn new(config_dir: PathBuf) -> Self {
        Self { config_dir }
    }

    pub async fn run_main_loop(&self) {
        loop {
            MenuViews::print_banner();
            let mut settings = DaemonSettings::load_or_default(&self.config_dir);
            let accounts = AccountConfig::load_all(&self.config_dir);

            let options = vec![
                "[1] Dashboard & Status",
                "[2] Add Proton Account (API or .conf)",
                "[3] Remove Account",
                "[4] Run Ping & Speed Benchmark",
                "[5] Set Auto-Best Mode (Ping vs Speed)",
                "[6] Settings (Ports, Bind IP, Auth)",
                "[7] Check for Updates / Update",
                "[8] Exit",
            ];

            let ans = Select::new("Select an action:", options).prompt();
            match ans {
                Ok("[1] Dashboard & Status") => {
                    MenuViews::render_dashboard(&settings, &accounts);
                    let _ = Text::new("Press Enter to return to menu...").prompt();
                }
                Ok("[2] Add Proton Account (API or .conf)") => {
                    self.flow_add_account(&mut settings, &accounts).await;
                }
                Ok("[3] Remove Account") => {
                    self.flow_remove_account(&accounts).await;
                }
                Ok("[4] Run Ping & Speed Benchmark") => {
                    self.flow_benchmark(&settings, &accounts).await;
                }
                Ok("[5] Set Auto-Best Mode (Ping vs Speed)") => {
                    self.flow_set_auto_best(&mut settings).await;
                }
                Ok("[6] Settings (Ports, Bind IP, Auth)") => {
                    self.flow_settings(&mut settings).await;
                }
                Ok("[7] Check for Updates / Update") => {
                    self.flow_update().await;
                }
                Ok("[8] Exit") | Err(_) => {
                    println!("{}", "Goodbye!".green());
                    break;
                }
                _ => {}
            }
        }
    }

    async fn flow_add_account(&self, settings: &mut DaemonSettings, accounts: &[AccountConfig]) {
        let methods = vec![
            "Automated API Login (Username + Password + 2FA)",
            "Import WireGuard .conf file",
        ];
        let method = match Select::new("Choose import method:", methods).prompt() {
            Ok(m) => m,
            Err(_) => return,
        };

        let next_port = AccountConfig::next_available_port(accounts, settings.base_port);

        if method.starts_with("Import") {
            let path_str = match Text::new("Enter path to WireGuard .conf file:").prompt() {
                Ok(p) => p,
                Err(_) => return,
            };
            let content = match fs::read_to_string(&path_str) {
                Ok(c) => c,
                Err(e) => {
                    println!("{}", format!("Failed to read file: {}", e).red());
                    let _ = Text::new("Press Enter to continue...").prompt();
                    return;
                }
            };
            let wg = match ProtonApiClient::parse_wg_conf(&content) {
                Ok(w) => w,
                Err(e) => {
                    println!("{}", format!("Parse error: {}", e).red());
                    let _ = Text::new("Press Enter to continue...").prompt();
                    return;
                }
            };

            let country = match Text::new("Enter Country Code (e.g. NL, US, JP):").prompt() {
                Ok(c) => c.trim().to_uppercase(),
                Err(_) => return,
            };

            let id = format!("acc_{}_{}", accounts.len() + 1, country.to_lowercase());
            let account = AccountConfig {
                id: id.clone(),
                label: format!("Proton-{}", country),
                username: "imported_user".to_string(),
                country,
                tier: 0,
                port: next_port,
                tokens: AuthTokens {
                    access_token: String::new(),
                    refresh_token: String::new(),
                    uid: String::new(),
                },
                wireguard: wg,
                created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            };

            match account.save(&self.config_dir) {
                Ok(_) => println!("{}", format!("Account {} added successfully on Port {}!", id, next_port).green().bold()),
                Err(e) => println!("{}", format!("Failed to save account: {}", e).red()),
            }
            let _ = Text::new("Press Enter to continue...").prompt();
            return;
        }

        // Automated API Login
        let username = match Text::new("Proton Username:").prompt() {
            Ok(u) => u.trim().to_string(),
            Err(_) => return,
        };
        let password = match Password::new("Proton Password:").prompt() {
            Ok(p) => p,
            Err(_) => return,
        };
        let country = match Text::new("Target Country (e.g. NL, US, JP, CH):").prompt() {
            Ok(c) => c.trim().to_uppercase(),
            Err(_) => return,
        };

        println!("{}", "Connecting to Proton API & computing SRP-6a proofs...".cyan());
        let client = ProtonApiClient::new();

        let info = match client.fetch_auth_info(&username).await {
            Ok(i) => i,
            Err(e) => {
                println!("{}", format!("Auth info failed: {}", e).red());
                let _ = Text::new("Press Enter to continue...").prompt();
                return;
            }
        };

        let modulus = info.modulus.unwrap_or_else(|| ProtonSrp::DEFAULT_MODULUS_HEX.to_string());
        let server_ephemeral = info.server_ephemeral.unwrap_or_default();
        let salt = info.salt.unwrap_or_default();
        let srp_session = info.srp_session.unwrap_or_default();
        let version = info.version.unwrap_or(4);

        let proofs = match ProtonSrp::compute_proofs(&password, &modulus, &server_ephemeral, &salt, version) {
            Ok(p) => p,
            Err(e) => {
                println!("{}", format!("SRP computation failed: {}", e).red());
                let _ = Text::new("Press Enter to continue...").prompt();
                return;
            }
        };

        let mut auth_resp = match client.authenticate(&username, &proofs, &srp_session).await {
            Ok(r) => r,
            Err(e) => {
                println!("{}", format!("Login failed: {}", e).red());
                let _ = Text::new("Press Enter to continue...").prompt();
                return;
            }
        };

        // Handle 2FA if required
        if auth_resp.two_factor == Some(1) || auth_resp.code == 9001 {
            let totp = match Text::new("Enter 6-digit 2FA code:").prompt() {
                Ok(t) => t.trim().to_string(),
                Err(_) => return,
            };
            let uid = auth_resp.uid.as_deref().unwrap_or_default();
            let tok = auth_resp.access_token.as_deref().unwrap_or_default();
            auth_resp = match client.submit_2fa(uid, tok, &totp).await {
                Ok(r) => r,
                Err(e) => {
                    println!("{}", format!("2FA verification failed: {}", e).red());
                    let _ = Text::new("Press Enter to continue...").prompt();
                    return;
                }
            };
        }

        let uid = auth_resp.uid.unwrap_or_default();
        let access_token = auth_resp.access_token.unwrap_or_default();
        let refresh_token = auth_resp.refresh_token.unwrap_or_default();

        println!("{}", "Detecting subscription tier and logical servers...".cyan());
        let tier = client.get_user_tier(&uid, &access_token).await.unwrap_or(0);
        let best_server = match client.get_best_logical_server(&access_token, &country, tier).await {
            Ok(s) => s,
            Err(e) => {
                println!("{}", format!("Server lookup failed: {}", e).red());
                let _ = Text::new("Press Enter to continue...").prompt();
                return;
            }
        };

        println!("{}", "Registering userspace WireGuard certificate...".cyan());
        let (priv_key, pub_key) = ProtonApiClient::generate_wireguard_keypair();
        let cert_resp = match client.register_wireguard_key(&access_token, &pub_key).await {
            Ok(c) => c,
            Err(e) => {
                println!("{}", format!("Key registration failed: {}", e).red());
                let _ = Text::new("Press Enter to continue...").prompt();
                return;
            }
        };

        let server_physical = best_server.servers.and_then(|s| s.into_iter().next())
            .ok_or_else(|| "No physical server found".to_string());
        let server_physical = match server_physical {
            Ok(p) => p,
            Err(e) => {
                println!("{}", format!("Physical server lookup failed: {}", e).red());
                let _ = Text::new("Press Enter to continue...").prompt();
                return;
            }
        };

        let server_endpoint = format!("{}:51820", server_physical.entry_ip);
        let server_pub_key = server_physical.public_key.unwrap_or_default();

        let id = format!("acc_{}_{}", accounts.len() + 1, country.to_lowercase());
        let new_account = AccountConfig {
            id: id.clone(),
            label: format!("Proton-{}-Tier{}", country, tier),
            username,
            country,
            tier,
            port: next_port,
            tokens: AuthTokens {
                access_token,
                refresh_token,
                uid,
            },
            wireguard: WireguardConfig {
                private_key: priv_key,
                public_key: pub_key,
                client_ip: cert_resp.ip.unwrap_or_else(|| "10.2.0.2/32".to_string()),
                dns: cert_resp.dns.unwrap_or_else(|| "10.2.0.1".to_string()),
                server_name: best_server.name,
                server_public_key: server_pub_key,
                server_endpoint,
            },
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };

        match new_account.save(&self.config_dir) {
            Ok(_) => println!("{}", format!("Account {} registered successfully on Port {}!", id, next_port).green().bold()),
            Err(e) => println!("{}", format!("Failed to save account: {}", e).red()),
        }

        let _ = Text::new("Press Enter to continue...").prompt();
    }

    async fn flow_remove_account(&self, accounts: &[AccountConfig]) {
        if accounts.is_empty() {
            println!("{}", "No accounts available to remove.".yellow());
            let _ = Text::new("Press Enter to continue...").prompt();
            return;
        }

        let items: Vec<String> = accounts.iter().map(|a| format!("{} - {} (Port {})", a.id, a.country, a.port)).collect();
        let selected = match Select::new("Select account to remove:", items).prompt() {
            Ok(s) => s,
            Err(_) => return,
        };

        let id = selected.split_whitespace().next().unwrap_or_default();
        if let Some(target) = accounts.iter().find(|a| a.id == id) {
            let confirm = Confirm::new(&format!("Are you sure you want to delete {}?", id))
                .with_default(false)
                .prompt();
            if confirm.unwrap_or(false) {
                let _ = target.delete(&self.config_dir);
                println!("{}", format!("Account {} deleted.", id).green());
            }
        }
        let _ = Text::new("Press Enter to continue...").prompt();
    }

    async fn flow_benchmark(&self, settings: &DaemonSettings, accounts: &[AccountConfig]) {
        if accounts.is_empty() {
            println!("{}", "No accounts configured to test.".yellow());
            let _ = Text::new("Press Enter to continue...").prompt();
            return;
        }

        let test_speed = Confirm::new("Include throughput speed test (1MB payload)?")
            .with_default(true)
            .prompt()
            .unwrap_or(false);

        println!("{}", "Running live benchmarks across all active accounts...".cyan());
        let proxy_host = if settings.bind_address == "0.0.0.0" { "127.0.0.1" } else { &settings.bind_address };
        let results = BenchmarkRunner::run_all(accounts, proxy_host, test_speed).await;

        MenuViews::render_benchmarks(&results);
        let _ = Text::new("Press Enter to continue...").prompt();
    }

    async fn flow_set_auto_best(&self, settings: &mut DaemonSettings) {
        let modes = vec!["Lowest Ping (ms)", "Highest Speed (Mbps)"];
        let choice = match Select::new("Select optimization metric for Port 25000:", modes).prompt() {
            Ok(c) => c,
            Err(_) => return,
        };

        settings.auto_best_metric = if choice.starts_with("Highest") {
            "speed".to_string()
        } else {
            "ping".to_string()
        };

        let _ = settings.save(&self.config_dir);
        println!("{}", format!("Auto-Best metric set to: {}", settings.auto_best_metric).green());
        let _ = Text::new("Press Enter to continue...").prompt();
    }

    async fn flow_settings(&self, settings: &mut DaemonSettings) {
        let options = vec![
            "Change Base Port (Current: Auto-Best)",
            "Toggle Bind Address (127.0.0.1 vs 0.0.0.0)",
            "Set / Change SOCKS5 Credentials",
            "Set Optimization Timer Interval (Hours)",
        ];

        let sel = match Select::new("Choose setting to modify:", options).prompt() {
            Ok(s) => s,
            Err(_) => return,
        };

        if sel.starts_with("Change Base Port") {
            if let Ok(port) = CustomType::<u16>::new("Enter new Base Port:").with_default(settings.base_port).prompt() {
                settings.base_port = port;
            }
        } else if sel.starts_with("Toggle Bind Address") {
            let addrs = vec!["127.0.0.1 (Localhost only, safe)", "0.0.0.0 (Open to network, STRICT AUTH ENFORCED)"];
            if let Ok(choice) = Select::new("Select listening interface:", addrs).prompt() {
                if choice.starts_with("0.0.0.0") {
                    settings.bind_address = "0.0.0.0".to_string();
                    settings.auth_required = true;
                    println!("{}", "WARNING: When listening on 0.0.0.0, SOCKS5 authentication is MANDATORY.".yellow().bold());
                    if settings.auth_username.is_empty() {
                        settings.auth_username = Text::new("Create SOCKS5 Username:").prompt().unwrap_or_default();
                    }
                    if settings.auth_password.is_empty() {
                        settings.auth_password = Text::new("Create SOCKS5 Password:").prompt().unwrap_or_default();
                    }
                } else {
                    settings.bind_address = "127.0.0.1".to_string();
                }
            }
        } else if sel.starts_with("Set / Change SOCKS5 Credentials") {
            settings.auth_required = true;
            settings.auth_username = Text::new("SOCKS5 Username:").prompt().unwrap_or_default();
            settings.auth_password = Text::new("SOCKS5 Password:").prompt().unwrap_or_default();
        } else if sel.starts_with("Set Optimization Timer") {
            if let Ok(hours) = CustomType::<u64>::new("Benchmark interval (hours):").with_default(settings.benchmark_interval_hours).prompt() {
                settings.benchmark_interval_hours = hours;
            }
        }

        let _ = settings.save(&self.config_dir);
        println!("{}", "Settings saved successfully!".green());
        let _ = Text::new("Press Enter to continue...").prompt();
    }

    pub async fn flow_update(&self) {
        println!("{}", "Checking for updates...".cyan());

        let candidate_dirs = [
            std::env::current_dir().unwrap_or_default(),
            PathBuf::from("/opt/proton-socks"),
            PathBuf::from("/opt/ProtonSocks"),
        ];

        let mut repo_dir: Option<PathBuf> = None;
        for dir in &candidate_dirs {
            if dir.join(".git").exists() {
                repo_dir = Some(dir.clone());
                break;
            }
        }

        let repo_dir = match repo_dir {
            Some(d) => d,
            None => {
                println!("{}", "Error: Source git repository not found in current directory or /opt/proton-socks.".red());
                println!("To update manually, run: git pull && sudo bash install.sh");
                let _ = Text::new("Press Enter to continue...").prompt();
                return;
            }
        };

        let fetch_res = std::process::Command::new("git")
            .arg("fetch")
            .current_dir(&repo_dir)
            .output();

        match fetch_res {
            Ok(output) if output.status.success() => {
                let local_head = std::process::Command::new("git")
                    .args(["rev-parse", "HEAD"])
                    .current_dir(&repo_dir)
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();

                let remote_head = std::process::Command::new("git")
                    .args(["rev-parse", "@{u}"])
                    .current_dir(&repo_dir)
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();

                if !local_head.is_empty() && local_head == remote_head {
                    println!("{}", "You are already on the latest version!".green());
                    let _ = Text::new("Press Enter to continue...").prompt();
                    return;
                }

                println!("{}", "A new update is available!".yellow().bold());
                let confirm = Confirm::new("Do you want to pull updates and recompile now?")
                    .with_default(true)
                    .prompt();

                if !confirm.unwrap_or(false) {
                    return;
                }

                println!("{}", "Pulling latest code...".cyan());
                let pull_status = std::process::Command::new("git")
                    .arg("pull")
                    .current_dir(&repo_dir)
                    .status();

                if pull_status.is_err() || !pull_status.unwrap().success() {
                    println!("{}", "Failed to pull updates from git.".red());
                    let _ = Text::new("Press Enter to continue...").prompt();
                    return;
                }

                println!("{}", "Compiling release binary with cargo...".cyan());
                let build_status = std::process::Command::new("cargo")
                    .args(["build", "--release"])
                    .current_dir(&repo_dir)
                    .status();

                if build_status.is_err() || !build_status.unwrap().success() {
                    println!("{}", "Compilation failed. Ensure Rust and build dependencies are installed.".red());
                    let _ = Text::new("Press Enter to continue...").prompt();
                    return;
                }

                let src_bin = repo_dir.join("target/release/proton-socks");
                if src_bin.exists() {
                    let _ = std::fs::copy(&src_bin, "/usr/local/bin/proton-socks");
                    let _ = std::process::Command::new("chmod")
                        .args(["755", "/usr/local/bin/proton-socks"])
                        .status();
                    let _ = std::process::Command::new("ln")
                        .args(["-sf", "/usr/local/bin/proton-socks", "/usr/local/bin/psocks"])
                        .status();
                    let _ = std::process::Command::new("ln")
                        .args(["-sf", "/usr/local/bin/proton-socks", "/usr/local/bin/ProtonSocks"])
                        .status();

                    let _ = std::process::Command::new("systemctl")
                        .args(["restart", "proton-socks"])
                        .status();

                    println!("{}", "Update applied successfully! Service restarted.".green().bold());
                } else {
                    println!("{}", "Could not find compiled binary.".red());
                }
            }
            _ => {
                println!("{}", "Failed to fetch updates from git repository.".red());
            }
        }

        let _ = Text::new("Press Enter to continue...").prompt();
    }
}
