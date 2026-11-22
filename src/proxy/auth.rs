use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct AuthPolicy {
    pub required: bool,
    pub username: String,
    pub password: String,
}

impl AuthPolicy {
    pub fn none() -> Self {
        Self {
            required: false,
            username: String::new(),
            password: String::new(),
        }
    }

    pub fn new(username: &str, password: &str) -> Self {
        Self {
            required: true,
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

pub struct Socks5Auth;

impl Socks5Auth {
    pub async fn handshake<S>(stream: &mut S, policy: &AuthPolicy) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // 1. Version identifier / method selection message
        // +----+----------+----------+
        // |VER | NMETHODS | METHODS  |
        // +----+----------+----------+
        // | 1  |    1     | 1 to 255 |
        // +----+----------+----------+
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x05 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Only SOCKS5 is supported"));
        }

        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        if !policy.required {
            // No authentication required
            if methods.contains(&0x00) {
                stream.write_all(&[0x05, 0x00]).await?;
                return Ok(());
            }
        }

        // Username / password authentication required (0x02)
        if methods.contains(&0x02) {
            stream.write_all(&[0x05, 0x02]).await?;

            // Subnegotiation: RFC 1929
            // +----+------+----------+------+----------+
            // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            // +----+------+----------+------+----------+
            let mut auth_ver = [0u8; 1];
            stream.read_exact(&mut auth_ver).await?;
            if auth_ver[0] != 0x01 {
                stream.write_all(&[0x01, 0x01]).await?;
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid subnegotiation version"));
            }

            let mut ulen = [0u8; 1];
            stream.read_exact(&mut ulen).await?;
            let mut uname = vec![0u8; ulen[0] as usize];
            stream.read_exact(&mut uname).await?;
            let uname_str = String::from_utf8_lossy(&uname);

            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).await?;
            let mut passwd = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut passwd).await?;
            let passwd_str = String::from_utf8_lossy(&passwd);

            if uname_str == policy.username && passwd_str == policy.password {
                // Success: 0x01, 0x00
                stream.write_all(&[0x01, 0x00]).await?;
                Ok(())
            } else {
                // Failure: 0x01, 0x01
                stream.write_all(&[0x01, 0x01]).await?;
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "SOCKS5 authentication failed"))
            }
        } else {
            // No acceptable methods: 0x05, 0xFF
            stream.write_all(&[0x05, 0xFF]).await?;
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "No acceptable authentication methods"))
        }
    }
}
