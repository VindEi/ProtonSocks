use crate::benchmark::BenchmarkRunner;
use crate::config::{AccountConfig, DaemonSettings};
use crate::proxy::ProxyRouter;
use std::path::PathBuf;
use std::time::Duration;

pub struct DaemonScheduler {
    pub config_dir: PathBuf,
    pub router: ProxyRouter,
}

impl DaemonScheduler {
    pub fn new(config_dir: PathBuf, router: ProxyRouter) -> Self {
        Self { config_dir, router }
    }

    pub fn spawn_loop(self) {
        tokio::spawn(async move {
            loop {
                let settings = DaemonSettings::load_or_default(&self.config_dir);
                let interval_hours = if settings.benchmark_interval_hours == 0 {
                    4
                } else {
                    settings.benchmark_interval_hours
                };

                // Wait for the scheduled interval
                tokio::time::sleep(Duration::from_secs(interval_hours * 3600)).await;

                println!("[Daemon] Running scheduled {}-hour benchmark & optimization cycle...", interval_hours);
                let accounts = AccountConfig::load_all(&self.config_dir);
                if accounts.is_empty() {
                    continue;
                }

                let proxy_host = if settings.bind_address == "0.0.0.0" {
                    "127.0.0.1"
                } else {
                    &settings.bind_address
                };

                let test_speed = settings.auto_best_metric == "speed";
                let results = BenchmarkRunner::run_all(&accounts, proxy_host, test_speed).await;

                if let Some(winner_id) = BenchmarkRunner::pick_winner(&results, &settings.auto_best_metric) {
                    println!("[Daemon] Optimization cycle complete! Winner: {}", winner_id);
                    self.router.set_best_account(Some(winner_id.clone())).await;

                    let mut updated_settings = settings.clone();
                    updated_settings.best_account_id = Some(winner_id);
                    let _ = updated_settings.save(&self.config_dir);
                }
            }
        });
    }
}
