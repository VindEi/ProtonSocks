pub mod api;
pub mod benchmark;
pub mod config;
pub mod daemon;
pub mod menu;
pub mod proxy;
pub mod tunnel;

use clap::{Parser, Subcommand};
use config::{AccountConfig, DaemonSettings};
use daemon::DaemonScheduler;
use menu::{MenuPrompts, MenuViews};
use proxy::{AuthPolicy, ProxyRouter, Socks5Server};
use std::path::PathBuf;
use tunnel::AccountTunnel;

#[derive(Parser)]
#[command(name = "proton-socks")]
#[command(author = "VindEi")]
#[command(version = "0.1.0")]
#[command(about = "Pure-Rust userspace WireGuard SOCKS5 proxy gateway for Proton VPN", long_about = None)]
struct Cli {
    #[arg(short, long, help = "Custom configuration directory (default: /etc/proton-socks)")]
    config_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Launch interactive terminal menu")]
    Menu,

    #[command(about = "Run multi-port proxy server and 4-hour optimization background daemon")]
    Daemon,

    #[command(about = "Run ping and throughput benchmark across all active accounts")]
    Benchmark {
        #[arg(long, help = "Include throughput download test")]
        speed: bool,
    },

    #[command(about = "List configured accounts and assigned ports")]
    List,

    #[command(about = "Check for updates and rebuild from repository")]
    Update,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config_dir = cli.config_dir.unwrap_or_else(DaemonSettings::get_default_config_dir);

    match cli.command.unwrap_or(Commands::Menu) {
        Commands::Menu => {
            let prompts = MenuPrompts::new(config_dir);
            prompts.run_main_loop().await;
        }

        Commands::Update => {
            let prompts = MenuPrompts::new(config_dir);
            prompts.flow_update().await;
        }

        Commands::List => {
            let settings = DaemonSettings::load_or_default(&config_dir);
            let accounts = AccountConfig::load_all(&config_dir);
            MenuViews::render_dashboard(&settings, &accounts);
        }

        Commands::Benchmark { speed } => {
            let settings = DaemonSettings::load_or_default(&config_dir);
            let accounts = AccountConfig::load_all(&config_dir);
            if accounts.is_empty() {
                println!("No accounts configured. Use 'proton-socks menu' to add one.");
                return Ok(());
            }
            let proxy_host = if settings.bind_address == "0.0.0.0" { "127.0.0.1" } else { &settings.bind_address };
            let results = benchmark::BenchmarkRunner::run_all(&accounts, proxy_host, speed).await;
            MenuViews::render_benchmarks(&results);
        }

        Commands::Daemon => {
            println!("Starting Proton-Socks Daemon in Userspace (No Root Required)...");
            let mut settings = DaemonSettings::load_or_default(&config_dir);
            if let Err(e) = settings.validate_security() {
                eprintln!("[Security Error] {}", e);
                std::process::exit(1);
            }

            let accounts = AccountConfig::load_all(&config_dir);
            if accounts.is_empty() {
                println!("Warning: No accounts configured in {}/accounts. Add accounts via 'proton-socks menu'.", config_dir.display());
            }

            let router = ProxyRouter::new(settings.base_port);
            router.set_best_account(settings.best_account_id.clone()).await;

            // Start userspace WireGuard tunnels for all accounts
            for acc in &accounts {
                println!("[Tunnel] Initializing WireGuard session for {} ({}) on Port {}...", acc.id, acc.country, acc.port);
                match AccountTunnel::start(acc.id.clone(), acc.wireguard.clone()).await {
                    Ok(tunnel) => {
                        router.register_tunnel(acc.port, tunnel).await;
                    }
                    Err(e) => {
                        eprintln!("[Tunnel Error] Failed to start tunnel for {}: {}", acc.id, e);
                    }
                }
            }

            // Authentication policy
            let auth_policy = if settings.auth_required {
                AuthPolicy::new(&settings.auth_username, &settings.auth_password)
            } else {
                AuthPolicy::none()
            };

            let server = Socks5Server::new(
                settings.bind_address.clone(),
                auth_policy,
                router.clone(),
            );

            // Bind base port 25000 (Auto-Best gateway)
            server.listen_port(settings.base_port).await?;

            // Bind dedicated ports for each account
            for acc in &accounts {
                server.listen_port(acc.port).await?;
            }

            // Spawn background 4-hour benchmark & reconnection scheduler
            let scheduler = DaemonScheduler::new(config_dir, router);
            scheduler.spawn_loop();

            println!("[Daemon] Running successfully. Press Ctrl+C to terminate.");
            tokio::signal::ctrl_c().await?;
            println!("\n[Daemon] Shutting down gracefully.");
        }
    }

    Ok(())
}
