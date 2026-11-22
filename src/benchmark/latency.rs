use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct LatencyProbe;

impl LatencyProbe {
    pub const TARGET_DOMAIN: &'static str = "cp.cloudflare.com";
    pub const TARGET_PORT: u16 = 80;

    /// Tests latency (RTT in milliseconds) through the local SOCKS5 proxy port
    pub async fn measure(
        proxy_host: &str,
        proxy_port: u16,
        timeout: Duration,
    ) -> Result<u64, String> {
        tokio::time::timeout(timeout, async {
            let start = Instant::now();

            let mut stream = TcpStream::connect(format!("{}:{}", proxy_host, proxy_port)).await
                .map_err(|e| format!("Proxy connection failed: {}", e))?;

            // 1. SOCKS5 Greeting: [VER, NMETHODS, METHOD_NO_AUTH]
            stream.write_all(&[0x05, 0x01, 0x00]).await
                .map_err(|e| format!("Greeting write failed: {}", e))?;

            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await
                .map_err(|e| format!("Greeting read failed: {}", e))?;
            if resp[0] != 0x05 || resp[1] != 0x00 {
                return Err("SOCKS5 auth negotiation failed".to_string());
            }

            // 2. SOCKS5 Connect to cp.cloudflare.com:80
            let domain_bytes = Self::TARGET_DOMAIN.as_bytes();
            let mut req = vec![
                0x05, 0x01, 0x00, 0x03, // VER, CMD=CONNECT, RSV, ATYP=DOMAIN
                domain_bytes.len() as u8,
            ];
            req.extend_from_slice(domain_bytes);
            req.extend_from_slice(&Self::TARGET_PORT.to_be_bytes());

            stream.write_all(&req).await
                .map_err(|e| format!("Connect write failed: {}", e))?;

            let mut reply_header = [0u8; 4];
            stream.read_exact(&mut reply_header).await
                .map_err(|e| format!("Connect reply failed: {}", e))?;
            if reply_header[1] != 0x00 {
                return Err(format!("Proxy connect rejected with code: {}", reply_header[1]));
            }

            // Consume remaining address bytes of reply
            match reply_header[3] {
                0x01 => {
                    let mut dummy = [0u8; 6]; // 4 IP + 2 Port
                    stream.read_exact(&mut dummy).await.map_err(|e| e.to_string())?;
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await.map_err(|e| e.to_string())?;
                    let mut dummy = vec![0u8; len[0] as usize + 2];
                    stream.read_exact(&mut dummy).await.map_err(|e| e.to_string())?;
                }
                _ => {}
            }

            // 3. Send HTTP HEAD /generate_204
            let http_req = format!(
                "HEAD /generate_204 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                Self::TARGET_DOMAIN
            );
            stream.write_all(http_req.as_bytes()).await
                .map_err(|e| format!("HTTP request failed: {}", e))?;

            let mut http_resp = [0u8; 12];
            stream.read_exact(&mut http_resp).await
                .map_err(|e| format!("HTTP response read failed: {}", e))?;

            let duration = start.elapsed();
            Ok(duration.as_millis() as u64)
        }).await.map_err(|_| "Latency probe timed out".to_string())?
    }
}
