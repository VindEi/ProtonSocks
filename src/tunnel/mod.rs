pub mod netstack;
pub mod session;

pub use netstack::{NetstackEngine, NetstackHandle};
pub use session::WireguardSession;

use crate::config::WireguardConfig;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct AccountTunnel {
    pub account_id: String,
    pub netstack: NetstackHandle,
}

impl AccountTunnel {
    pub async fn start(account_id: String, config: WireguardConfig) -> Result<Self, String> {
        let (outbound_ip_tx, outbound_ip_rx) = mpsc::channel(128);
        let (inbound_ip_tx, inbound_ip_rx) = mpsc::channel(128);

        let netstack_engine = NetstackEngine::new(&config.client_ip)?;
        let netstack = netstack_engine.spawn(inbound_ip_rx, outbound_ip_tx);

        let session = WireguardSession::new(config);
        tokio::spawn(async move {
            if let Err(e) = session.start(outbound_ip_rx, inbound_ip_tx).await {
                eprintln!("[Tunnel Error] Session failed: {}", e);
            }
        });

        Ok(Self {
            account_id,
            netstack,
        })
    }
}
