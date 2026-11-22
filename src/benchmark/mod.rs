pub mod latency;
pub mod throughput;

pub use latency::LatencyProbe;
pub use throughput::ThroughputProbe;

use crate::config::AccountConfig;
use std::time::Duration;
use tabled::Tabled;

#[derive(Debug, Clone, Tabled)]
pub struct BenchmarkResult {
    #[tabled(rename = "Account ID")]
    pub account_id: String,
    #[tabled(rename = "Country")]
    pub country: String,
    #[tabled(rename = "Port")]
    pub port: u16,
    #[tabled(rename = "Ping (ms)")]
    pub ping_display: String,
    #[tabled(rename = "Speed (Mbps)")]
    pub speed_display: String,
    #[tabled(rename = "Status")]
    pub status: String,

    #[tabled(skip)]
    pub ping_ms: Option<u64>,
    #[tabled(skip)]
    pub speed_mbps: Option<f64>,
}

pub struct BenchmarkRunner;

impl BenchmarkRunner {
    pub async fn run_single(
        account: &AccountConfig,
        proxy_host: &str,
        test_speed: bool,
    ) -> BenchmarkResult {
        let timeout = Duration::from_secs(5);

        // Ping test
        let (ping_ms, ping_display, status) = match LatencyProbe::measure(proxy_host, account.port, timeout).await {
            Ok(ms) => (Some(ms), format!("{} ms", ms), "OK".to_string()),
            Err(e) => (None, "FAIL".to_string(), format!("Error: {}", e)),
        };

        // Speed test
        let (speed_mbps, speed_display) = if test_speed && ping_ms.is_some() {
            let speed_timeout = Duration::from_secs(10);
            match ThroughputProbe::measure(proxy_host, account.port, speed_timeout).await {
                Ok(mbps) => (Some(mbps), format!("{:.2} Mbps", mbps)),
                Err(_) => (None, "N/A".to_string()),
            }
        } else {
            (None, "N/A".to_string())
        };

        BenchmarkResult {
            account_id: account.id.clone(),
            country: account.country.clone(),
            port: account.port,
            ping_display,
            speed_display,
            status,
            ping_ms,
            speed_mbps,
        }
    }

    pub async fn run_all(
        accounts: &[AccountConfig],
        proxy_host: &str,
        test_speed: bool,
    ) -> Vec<BenchmarkResult> {
        let mut results = Vec::new();
        for acc in accounts {
            results.push(Self::run_single(acc, proxy_host, test_speed).await);
        }
        results
    }

    pub fn pick_winner(results: &[BenchmarkResult], metric: &str) -> Option<String> {
        if metric == "speed" {
            // Find highest speed
            results
                .iter()
                .filter_map(|r| r.speed_mbps.map(|s| (s, &r.account_id)))
                .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(_, id)| id.clone())
        } else {
            // Default: lowest ping
            results
                .iter()
                .filter_map(|r| r.ping_ms.map(|p| (p, &r.account_id)))
                .min_by_key(|(p, _)| *p)
                .map(|(_, id)| id.clone())
        }
    }
}
