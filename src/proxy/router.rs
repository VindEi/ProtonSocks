use crate::tunnel::AccountTunnel;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct ProxyRouter {
    pub base_port: u16,
    port_map: Arc<RwLock<HashMap<u16, AccountTunnel>>>,
    account_map: Arc<RwLock<HashMap<String, AccountTunnel>>>,
    best_account_id: Arc<RwLock<Option<String>>>,
}

impl ProxyRouter {
    pub fn new(base_port: u16) -> Self {
        Self {
            base_port,
            port_map: Arc::new(RwLock::new(HashMap::new())),
            account_map: Arc::new(RwLock::new(HashMap::new())),
            best_account_id: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn register_tunnel(&self, port: u16, tunnel: AccountTunnel) {
        let mut pmap = self.port_map.write().await;
        let mut amap = self.account_map.write().await;
        pmap.insert(port, tunnel.clone());
        amap.insert(tunnel.account_id.clone(), tunnel);
    }

    pub async fn unregister_account(&self, account_id: &str) {
        let mut amap = self.account_map.write().await;
        amap.remove(account_id);

        let mut pmap = self.port_map.write().await;
        pmap.retain(|_, t| t.account_id != account_id);

        let mut best = self.best_account_id.write().await;
        if best.as_deref() == Some(account_id) {
            *best = None;
        }
    }

    pub async fn set_best_account(&self, account_id: Option<String>) {
        let mut best = self.best_account_id.write().await;
        *best = account_id;
    }

    pub async fn get_best_account_id(&self) -> Option<String> {
        let best = self.best_account_id.read().await;
        best.clone()
    }

    pub async fn get_tunnel_for_port(&self, port: u16) -> Option<AccountTunnel> {
        if port == self.base_port {
            // Base port: route to the best account if set, otherwise first available
            let best = self.best_account_id.read().await;
            if let Some(ref best_id) = *best {
                let amap = self.account_map.read().await;
                if let Some(t) = amap.get(best_id) {
                    return Some(t.clone());
                }
            }
            let amap = self.account_map.read().await;
            return amap.values().next().cloned();
        }

        let pmap = self.port_map.read().await;
        pmap.get(&port).cloned()
    }

    pub async fn list_ports(&self) -> Vec<u16> {
        let pmap = self.port_map.read().await;
        let mut ports: Vec<u16> = pmap.keys().copied().collect();
        ports.sort_unstable();
        ports
    }
}
