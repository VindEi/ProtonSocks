use crate::benchmark::BenchmarkResult;
use crate::config::{AccountConfig, DaemonSettings};
use colored::Colorize;
use tabled::{settings::Style, Table, Tabled};

#[derive(Tabled)]
struct AccountDashboardRow {
    #[tabled(rename = "Port")]
    port: u16,
    #[tabled(rename = "Account ID")]
    id: String,
    #[tabled(rename = "Country")]
    country: String,
    #[tabled(rename = "Server Name")]
    server: String,
    #[tabled(rename = "Endpoint")]
    endpoint: String,
    #[tabled(rename = "Gateway Type")]
    role: String,
}

pub struct MenuViews;

impl MenuViews {
    pub fn print_banner() {
        println!("{}", r#"
  ____            _               ____             _        
 |  _ \ _ __ ___ | |_ ___  _ __  / ___|  ___   ___| | _____ 
 | |_) | '__/ _ \| __/ _ \| '_ \ \___ \ / _ \ / __| |/ / __|
 |  __/| | | (_) | || (_) | | | | ___) | (_) | (__|   <\__ \ 
 |_|   |_|  \___/ \__\___/|_| |_||____/ \___/ \___|_|\_\___/
        Pure-Rust Userspace Proton VPN SOCKS5 Gateway
"#.cyan().bold());
    }

    pub fn render_dashboard(settings: &DaemonSettings, accounts: &[AccountConfig]) {
        println!("\n{}", "=== [ PROTON-SOCKS DASHBOARD ] ===".green().bold());
        println!(
            "Bind Address: {} | Base Port (Auto-Best): {} | Metric: {} | Auth Enforced: {}",
            settings.bind_address.yellow(),
            settings.base_port.to_string().yellow(),
            settings.auto_best_metric.yellow(),
            if settings.auth_required { "YES (Active)".green().bold() } else { "NO (Localhost)".white() }
        );

        if accounts.is_empty() {
            println!("\n{}", "No Proton accounts configured yet. Select [2] Add Proton Account to start.".yellow());
            return;
        }

        let mut rows = Vec::new();

        let best_id = settings.best_account_id.as_deref().unwrap_or("Dynamic (First available)");
        rows.push(AccountDashboardRow {
            port: settings.base_port,
            id: format!("* {}", best_id),
            country: "AUTO".to_string(),
            server: "Auto-Selected Best Gateway".to_string(),
            endpoint: "Routes to fastest account".to_string(),
            role: "Auto-Best Gateway".to_string(),
        });

        for acc in accounts {
            let is_winner = settings.best_account_id.as_deref() == Some(&acc.id);
            let role_label = if is_winner {
                format!("Dedicated Port (Active Winner *)")
            } else {
                format!("Dedicated Country Port")
            };

            rows.push(AccountDashboardRow {
                port: acc.port,
                id: acc.id.clone(),
                country: acc.country.clone(),
                server: acc.wireguard.server_name.clone(),
                endpoint: acc.wireguard.server_endpoint.clone(),
                role: role_label,
            });
        }

        let table = Table::new(rows).with(Style::rounded()).to_string();
        println!("\n{}", table);
    }

    pub fn render_benchmarks(results: &[BenchmarkResult]) {
        println!("\n{}", "=== [ LIVE BENCHMARK RESULTS ] ===".cyan().bold());
        let table = Table::new(results).with(Style::rounded()).to_string();
        println!("{}\n", table);
    }
}
