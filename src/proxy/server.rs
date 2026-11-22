use crate::proxy::auth::{AuthPolicy, Socks5Auth};
use crate::proxy::router::ProxyRouter;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

pub struct Socks5Server {
    pub bind_address: String,
    pub auth_policy: AuthPolicy,
    pub router: ProxyRouter,
}

impl Socks5Server {
    pub fn new(bind_address: String, auth_policy: AuthPolicy, router: ProxyRouter) -> Self {
        Self {
            bind_address,
            auth_policy,
            router,
        }
    }

    pub async fn listen_port(&self, port: u16) -> io::Result<()> {
        let addr = format!("{}:{}", self.bind_address, port);
        let listener = TcpListener::bind(&addr).await?;
        println!("[SOCKS5] Listening on {}", addr);

        let router = self.router.clone();
        let auth_policy = self.auth_policy.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _client_addr)) => {
                        let r = router.clone();
                        let a = auth_policy.clone();
                        tokio::spawn(async move {
                            if let Err(_e) = Self::handle_client(stream, port, r, a).await {
                                // SOCKS client disconnected or auth failed
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[SOCKS5 Error] Accept failed on port {}: {}", port, e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_client(
        mut stream: TcpStream,
        listen_port: u16,
        router: ProxyRouter,
        auth_policy: AuthPolicy,
    ) -> io::Result<()> {
        // 1. SOCKS5 Authentication Handshake
        Socks5Auth::handshake(&mut stream, &auth_policy).await?;

        // 2. Request Details
        // +----+-----+-------+------+----------+----------+
        // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+
        let mut req_header = [0u8; 4];
        stream.read_exact(&mut req_header).await?;

        if req_header[0] != 0x05 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected SOCKS5 request version"));
        }

        if req_header[1] != 0x01 {
            // Only CONNECT (0x01) is supported
            stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Command not supported"));
        }

        let atyp = req_header[3];
        let target_ip: IpAddr = match atyp {
            0x01 => {
                // IPv4: 4 bytes
                let mut ip_bytes = [0u8; 4];
                stream.read_exact(&mut ip_bytes).await?;
                IpAddr::V4(Ipv4Addr::from(ip_bytes))
            }
            0x03 => {
                // Domain: 1 byte len + string
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain_bytes = vec![0u8; len[0] as usize];
                stream.read_exact(&mut domain_bytes).await?;
                let domain = String::from_utf8_lossy(&domain_bytes).to_string();

                // Resolve hostname
                match tokio::net::lookup_host(format!("{}:80", domain)).await {
                    Ok(mut addrs) => match addrs.next() {
                        Some(addr) => addr.ip(),
                        None => {
                            stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                            return Err(io::Error::new(io::ErrorKind::NotFound, "Host unreachable"));
                        }
                    },
                    Err(_) => {
                        stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                        return Err(io::Error::new(io::ErrorKind::NotFound, "Host unreachable"));
                    }
                }
            }
            _ => {
                // Address type not supported
                stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "Address type not supported"));
            }
        };

        let mut port_bytes = [0u8; 2];
        stream.read_exact(&mut port_bytes).await?;
        let target_port = u16::from_be_bytes(port_bytes);
        let target_addr = SocketAddr::new(target_ip, target_port);

        // 3. Find tunnel for port
        let tunnel = match router.get_tunnel_for_port(listen_port).await {
            Some(t) => t,
            None => {
                stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "No active tunnel for port"));
            }
        };

        // 4. Connect through userspace netstack
        let (client_tx, mut client_rx) = mpsc::channel(64);
        let to_netstack_tx = match tunnel.netstack.connect_stream(target_addr, client_tx).await {
            Ok(tx) => tx,
            Err(e) => {
                stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, e));
            }
        };

        // 5. Send success response
        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

        // 6. Split stream and pump data bidirectionally
        let (mut stream_reader, mut stream_writer) = stream.into_split();

        let reader_task = tokio::spawn(async move {
            let mut buf = [0u8; 16384];
            loop {
                match stream_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if to_netstack_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let writer_task = tokio::spawn(async move {
            while let Some(chunk) = client_rx.recv().await {
                if stream_writer.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        tokio::select! {
            _ = reader_task => {},
            _ = writer_task => {},
        }

        Ok(())
    }
}
