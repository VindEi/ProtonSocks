use crate::config::WireguardConfig;
use boringtun::noise::{Tunn, TunnResult};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct WireguardSession {
    pub config: WireguardConfig,
}

impl WireguardSession {
    pub fn new(config: WireguardConfig) -> Self {
        Self { config }
    }

    pub fn parse_key32(b64: &str) -> Result<[u8; 32], String> {
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
            .map_err(|e| format!("Base64 decode error for key: {}", e))?;
        if decoded.len() != 32 {
            return Err(format!("Invalid key length {}, expected 32 bytes", decoded.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }

    pub async fn start(
        self,
        mut outbound_ip_rx: mpsc::Receiver<Vec<u8>>,
        inbound_ip_tx: mpsc::Sender<Vec<u8>>,
    ) -> Result<(), String> {
        let priv_bytes = Self::parse_key32(&self.config.private_key)?;
        let peer_pub_bytes = Self::parse_key32(&self.config.server_public_key)?;

        let static_private = StaticSecret::from(priv_bytes);
        let peer_public = PublicKey::from(peer_pub_bytes);

        let tunn = Tunn::new(
            static_private,
            peer_public,
            None,
            Some(25), // keepalive 25 seconds
            0,
            None,
        ).map_err(|e| format!("Failed to create boringtun tunnel: {:?}", e))?;

        let tunn = Arc::new(tokio::sync::Mutex::new(tunn));

        let endpoint_addr: SocketAddr = self.config.server_endpoint.parse()
            .map_err(|e| format!("Invalid server endpoint {}: {}", self.config.server_endpoint, e))?;

        let udp_socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| format!("Failed to bind local UDP socket: {}", e))?;
        udp_socket.connect(endpoint_addr).await
            .map_err(|e| format!("Failed to connect UDP socket to {}: {}", endpoint_addr, e))?;
        let udp_socket = Arc::new(udp_socket);

        // Initial handshake trigger
        {
            let mut buf = [0u8; 2048];
            let mut t = tunn.lock().await;
            let res = t.format_handshake_initiation(&mut buf, false);
            if let TunnResult::WriteToNetwork(packet) = res {
                let _ = udp_socket.send(packet).await;
            }
        }

        // Spawn timer worker for keepalives and re-handshaking
        let tunn_timer = Arc::clone(&tunn);
        let udp_timer = Arc::clone(&udp_socket);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            let mut buf = [0u8; 2048];
            loop {
                interval.tick().await;
                let mut t = tunn_timer.lock().await;
                let res = t.update_timers(&mut buf);
                if let TunnResult::WriteToNetwork(packet) = res {
                    let _ = udp_timer.send(packet).await;
                }
            }
        });

        // Spawn task to handle outgoing IP packets -> encapsulate -> send to UDP
        let tunn_encap = Arc::clone(&tunn);
        let udp_encap = Arc::clone(&udp_socket);
        tokio::spawn(async move {
            let mut send_buf = [0u8; 4096];
            while let Some(ip_packet) = outbound_ip_rx.recv().await {
                let mut t = tunn_encap.lock().await;
                let res = t.encapsulate(&ip_packet, &mut send_buf);
                if let TunnResult::WriteToNetwork(packet) = res {
                    let _ = udp_encap.send(packet).await;
                }
            }
        });

        // Main loop: receive UDP packets -> decapsulate -> send plain IP packet to channel
        let mut recv_udp_buf = [0u8; 4096];
        let mut decaps_buf = [0u8; 4096];
        loop {
            match udp_socket.recv(&mut recv_udp_buf).await {
                Ok(n) => {
                    let mut t = tunn.lock().await;
                    let res = t.decapsulate(None, &recv_udp_buf[..n], &mut decaps_buf);
                    match res {
                        TunnResult::WriteToNetwork(packet) => {
                            let _ = udp_socket.send(packet).await;
                        }
                        TunnResult::WriteToTunnelV4(packet, _) => {
                            let _ = inbound_ip_tx.send(packet.to_vec()).await;
                        }
                        TunnResult::WriteToTunnelV6(packet, _) => {
                            let _ = inbound_ip_tx.send(packet.to_vec()).await;
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}
