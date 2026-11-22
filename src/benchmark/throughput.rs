use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct ThroughputProbe;

impl ThroughputProbe {
    pub const TARGET_DOMAIN: &'static str = "speed.cloudflare.com";
    pub const TARGET_PORT: u16 = 80;
    pub const TEST_BYTES: usize = 1_048_576; // 1 MB payload for fast responsive benchmark

    /// Measures download throughput (Mbps) through the local SOCKS5 proxy port
    pub async fn measure(
        proxy_host: &str,
        proxy_port: u16,
        timeout: Duration,
    ) -> Result<f64, String> {
        tokio::time::timeout(timeout, async {
            let mut stream = TcpStream::connect(format!("{}:{}", proxy_host, proxy_port)).await
                .map_err(|e| format!("Proxy connect error: {}", e))?;

            // 1. SOCKS5 Greeting
            stream.write_all(&[0x05, 0x01, 0x00]).await
                .map_err(|e| e.to_string())?;

            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await.map_err(|e| e.to_string())?;
            if resp[0] != 0x05 || resp[1] != 0x00 {
                return Err("SOCKS5 greeting failed".to_string());
            }

            // 2. Connect to speed.cloudflare.com:80
            let domain_bytes = Self::TARGET_DOMAIN.as_bytes();
            let mut req = vec![
                0x05, 0x01, 0x00, 0x03,
                domain_bytes.len() as u8,
            ];
            req.extend_from_slice(domain_bytes);
            req.extend_from_slice(&Self::TARGET_PORT.to_be_bytes());
            stream.write_all(&req).await.map_err(|e| e.to_string())?;

            let mut reply_header = [0u8; 4];
            stream.read_exact(&mut reply_header).await.map_err(|e| e.to_string())?;
            if reply_header[1] != 0x00 {
                return Err("Proxy connect failed".to_string());
            }

            match reply_header[3] {
                0x01 => {
                    let mut dummy = [0u8; 6];
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

            // 3. Request download payload
            let http_get = format!(
                "GET /__down?bytes={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                Self::TEST_BYTES,
                Self::TARGET_DOMAIN
            );
            stream.write_all(http_get.as_bytes()).await.map_err(|e| e.to_string())?;

            let start = Instant::now();
            let mut total_read = 0usize;
            let mut buf = [0u8; 16384];

            loop {
                let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                total_read += n;
            }

            let elapsed_secs = start.elapsed().as_secs_f64();
            if elapsed_secs <= 0.001 || total_read < 1000 {
                return Err("Insufficient data received".to_string());
            }

            // Calculate Mbps = (bits / seconds) / 1_000_000
            let bits = (total_read as f64) * 8.0;
            let mbps = (bits / elapsed_secs) / 1_000_000.0;
            Ok((mbps * 100.0).round() / 100.0)
        }).await.map_err(|_| "Speed probe timed out".to_string())?
    }
}
