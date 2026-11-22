use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Cidr};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex};

pub struct PacketDevice {
    pub rx_queue: VecDeque<Vec<u8>>,
    pub tx_sender: mpsc::Sender<Vec<u8>>,
}

impl Device for PacketDevice {
    type RxToken<'a> = PacketRxToken where Self: 'a;
    type TxToken<'a> = PacketTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(packet) = self.rx_queue.pop_front() {
            let rx = PacketRxToken { packet };
            let tx = PacketTxToken { sender: &self.tx_sender };
            Some((rx, tx))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(PacketTxToken { sender: &self.tx_sender })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1420;
        caps
    }
}

pub struct PacketRxToken {
    packet: Vec<u8>,
}

impl RxToken for PacketRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.packet)
    }
}

pub struct PacketTxToken<'a> {
    sender: &'a mpsc::Sender<Vec<u8>>,
}

impl<'a> TxToken for PacketTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        let _ = self.sender.try_send(buffer);
        result
    }
}

pub enum NetstackCommand {
    Connect {
        target: SocketAddr,
        reply: oneshot::Sender<Result<mpsc::Sender<Vec<u8>>, String>>,
        client_data_tx: mpsc::Sender<Vec<u8>>,
    },
}

#[derive(Clone)]
pub struct NetstackHandle {
    cmd_tx: mpsc::Sender<NetstackCommand>,
}

impl NetstackHandle {
    pub async fn connect_stream(
        &self,
        target: SocketAddr,
        client_data_tx: mpsc::Sender<Vec<u8>>,
    ) -> Result<mpsc::Sender<Vec<u8>>, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx.send(NetstackCommand::Connect {
            target,
            reply: reply_tx,
            client_data_tx,
        }).await.map_err(|e| format!("Netstack loop closed: {}", e))?;

        reply_rx.await.map_err(|e| format!("Netstack dropped response: {}", e))?
    }
}

pub struct NetstackEngine {
    client_ip: Ipv4Address,
}

impl NetstackEngine {
    pub fn new(client_ip_str: &str) -> Result<Self, String> {
        let ip_part = client_ip_str.split('/').next().unwrap_or(client_ip_str);
        let std_ip: std::net::Ipv4Addr = ip_part.parse()
            .map_err(|e| format!("Invalid client IP {}: {}", client_ip_str, e))?;
        let octets = std_ip.octets();
        Ok(Self {
            client_ip: Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]),
        })
    }

    pub fn spawn(
        self,
        mut inbound_ip_rx: mpsc::Receiver<Vec<u8>>,
        outbound_ip_tx: mpsc::Sender<Vec<u8>>,
    ) -> NetstackHandle {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(128);

        tokio::spawn(async move {
            let mut device = PacketDevice {
                rx_queue: VecDeque::new(),
                tx_sender: outbound_ip_tx,
            };

            let mut config = Config::new(HardwareAddress::Ip);
            config.random_seed = rand::random();
            let mut iface = Interface::new(config, &mut device, Instant::now());
            iface.update_ip_addrs(|addrs| {
                addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(self.client_ip, 32))).unwrap();
            });

            let mut sockets = SocketSet::new(vec![]);
            let mut active_connections: HashMap<
                smoltcp::iface::SocketHandle,
                (
                    mpsc::Receiver<Vec<u8>>, // data from client to write to socket
                    mpsc::Sender<Vec<u8>>,   // data from socket to send to client
                    Option<oneshot::Sender<Result<mpsc::Sender<Vec<u8>>, String>>>,
                ),
            > = HashMap::new();

            let mut next_ephemeral_port: u16 = 40000;

            loop {
                // Drain any incoming IP packets from boringtun
                while let Ok(packet) = inbound_ip_rx.try_recv() {
                    device.rx_queue.push_back(packet);
                }

                // Check for new connection commands
                while let Ok(cmd) = cmd_rx.try_recv() {
                    match cmd {
                        NetstackCommand::Connect { target, reply, client_data_tx } => {
                            let rx_buf = TcpSocketBuffer::new(vec![0; 65535]);
                            let tx_buf = TcpSocketBuffer::new(vec![0; 65535]);
                            let mut socket = TcpSocket::new(rx_buf, tx_buf);

                            let local_port = next_ephemeral_port;
                            next_ephemeral_port = if next_ephemeral_port >= 65000 { 40000 } else { next_ephemeral_port + 1 };

                            let target_ip = match target.ip() {
                                std::net::IpAddr::V4(v4) => {
                                    let o = v4.octets();
                                    Ipv4Address::new(o[0], o[1], o[2], o[3])
                                }
                                _ => continue, // IPv4 supported
                            };

                            let remote_endpoint = (target_ip, target.port());
                            let local_endpoint = (self.client_ip, local_port);

                            if let Err(e) = socket.connect(iface.context(), remote_endpoint, local_endpoint) {
                                let _ = reply.send(Err(format!("Socket connect error: {:?}", e)));
                                continue;
                            }

                            let handle = sockets.add(socket);
                            let (to_netstack_tx, to_netstack_rx) = mpsc::channel(64);
                            active_connections.insert(handle, (to_netstack_rx, client_data_tx, Some(reply)));
                        }
                    }
                }

                // Pump data between Tokio channels and smoltcp sockets
                let mut sockets_to_remove = Vec::new();
                for (&handle, (client_rx, client_tx, pending_reply)) in active_connections.iter_mut() {
                    let socket = sockets.get_mut::<TcpSocket>(handle);

                    // Check if newly connected
                    if socket.is_active() && pending_reply.is_some() {
                        let reply = pending_reply.take().unwrap();
                        let (to_netstack_tx, _) = mpsc::channel(64);
                        let _ = reply.send(Ok(to_netstack_tx));
                    }

                    // Receive data from smoltcp socket and push to client
                    if socket.can_recv() {
                        let _ = socket.recv(|data| {
                            if !data.is_empty() {
                                let _ = client_tx.try_send(data.to_vec());
                            }
                            (data.len(), ())
                        });
                    }

                    // Send data from client to smoltcp socket
                    if socket.can_send() {
                        while let Ok(chunk) = client_rx.try_recv() {
                            let _ = socket.send_slice(&chunk);
                        }
                    }

                    // Close handling
                    if socket.state() == TcpState::Closed || socket.state() == TcpState::TimeWait {
                        sockets_to_remove.push(handle);
                    }
                }

                for handle in sockets_to_remove {
                    active_connections.remove(&handle);
                    sockets.remove(handle);
                }

                let timestamp = Instant::now();
                iface.poll(timestamp, &mut device, &mut sockets);

                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        NetstackHandle { cmd_tx }
    }
}
