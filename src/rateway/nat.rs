use super::{
    adapter::{flatten, write_packet, AtewayAdapterTask},
    builtin::NAT_PORT_RANGE,
    AtewayIoError, AtewayIoSocket,
};
use crate::{
    racsma::{
        builtin::SOCKET_BROADCAST_ADDRESS, AcsmaIoSocket, AcsmaSocketConfig, AcsmaSocketReader,
        AcsmaSocketWriter,
    },
    rather::encode::{DecodeToBytes, EncodeFromBytes},
    raudio::AsioDevice,
};
use anyhow::Result;
use futures::future::BoxFuture;
use ipnet::Ipv4Net;
use lru::LruCache;
use packet::{
    ether, icmp,
    ip::{self, Protocol},
    tcp, udp, Packet, PacketMut,
};
use parking_lot::Mutex;
use pcap::{Active, Capture, Device};
use std::{
    collections::HashMap,
    future::Future,
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroUsize,
    ops::Range,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task,
};

#[derive(Clone)]
pub struct AtewayNatConfig {
    pub name: String,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub host: Ipv4Addr,
    pub socket_config: AcsmaSocketConfig,
    pub route_config: Option<HashMap<u16, SocketAddrV4>>,
}

impl AtewayNatConfig {
    pub fn new(
        name: String,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        host: Ipv4Addr,
        socket_config: AcsmaSocketConfig,
        route_config: Option<HashMap<u16, SocketAddrV4>>,
    ) -> Self {
        Self {
            name,
            address,
            netmask,
            host,
            socket_config,
            route_config,
        }
    }
}

pub struct AtewayIoNat {
    config: AtewayNatConfig,
    device: AsioDevice,
    inner: Option<BoxFuture<'static, Result<()>>>,
}

impl AtewayIoNat {
    pub fn new(config: AtewayNatConfig, device: AsioDevice) -> Self {
        Self {
            config,
            device,
            inner: None,
        }
    }
}

impl Future for AtewayIoNat {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.inner.is_none() {
            let config = this.config.clone();
            let device = this.device.clone();
            let inner = Box::pin(nat_daemon(config, device));
            this.inner.replace(inner);
        }
        let inner = this.inner.as_mut().unwrap();
        match inner.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.inner.take();
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(super) fn find_device(ip: Ipv4Addr) -> Result<Device> {
    for device in Device::list()? {
        if device.addresses.iter().any(|addr| addr.addr == ip) {
            return Ok(device);
        }
    }
    Err(AtewayIoError::DeviceNotFound(ip).into())
}

async fn nat_daemon(config: AtewayNatConfig, device: AsioDevice) -> Result<()> {
    let table = Arc::new(Mutex::new(AtewayNatTable::new(
        NAT_PORT_RANGE,
        config.route_config.clone(),
    )));

    let (tx_socket, rx_socket) =
        AcsmaIoSocket::try_from_device(config.socket_config.clone(), &device)?;

    let raw_socket = AtewayIoSocket::try_new(config.host)?;

    let device = find_device(config.host)?;
    let mut cap = Capture::from_device(device)?.immediate_mode(true).open()?;
    cap.filter(&format!("ip dst host {}", config.host), true)?;

    let (write_tx, write_rx) = mpsc::unbounded_channel();

    let write_handle = tokio::spawn(write_daemon(config.clone(), tx_socket, write_rx));
    let receive_handle = tokio::spawn(receive_daemon(
        config.clone(),
        write_tx.clone(),
        rx_socket,
        raw_socket,
        table.clone(),
    ));
    let send_handle = tokio::spawn(send_daemon(config, write_tx, cap, table));

    tokio::try_join!(
        flatten(write_handle),
        flatten(receive_handle),
        flatten(send_handle)
    )?;
    Ok(())
}

async fn write_daemon(
    config: AtewayNatConfig,
    tx_socket: AcsmaSocketWriter,
    mut write_rx: UnboundedReceiver<AtewayAdapterTask>,
) -> Result<()> {
    let net = Ipv4Net::with_netmask(config.address, config.netmask)?;
    while let Some((packet, tx)) = write_rx.recv().await {
        let ip = packet.destination();
        let dest = if ip == net.broadcast() || ip.is_broadcast() {
            Ok(SOCKET_BROADCAST_ADDRESS)
        } else if net.contains(&ip) {
            log::debug!("Resolving MAC address: {}", ip);
            tx_socket
                .arp(u32::from_be_bytes(ip.octets()) as usize)
                .await
        } else {
            Ok(config.socket_config.mac)
        };

        let result = match dest {
            Ok(inner) => {
                log::debug!("Resolve MAC address: {} -> {}", ip, inner);
                tx_socket.write(inner, &packet.as_ref().encode()).await
            }
            Err(err) => Err(err),
        };
        let _ = tx.send(result);
    }
    Ok(())
}

async fn receive_daemon(
    config: AtewayNatConfig,
    write_tx: UnboundedSender<AtewayAdapterTask>,
    mut rx_socket: AcsmaSocketReader,
    mut raw_socket: AtewayIoSocket,
    table: Arc<Mutex<AtewayNatTable>>,
) -> Result<()> {
    let net = Ipv4Net::with_netmask(config.address, config.netmask)?;

    while let Ok(packet) = rx_socket.read_unchecked().await {
        let bytes = DecodeToBytes::decode(&packet);
        if let Ok(ip::Packet::V4(mut packet)) = ip::Packet::new(bytes) {
            let src = packet.source();
            let dest = packet.destination();
            let protocol = packet.protocol();

            if dest == config.address {
                if protocol == Protocol::Icmp {
                    log::debug!("Receive packet {} -> {} ({:?})", src, dest, protocol);
                    let mut icmp = icmp::Packet::new(packet.payload_mut())?;
                    if let Some(mut echo) = icmp.echo_mut().ok().filter(|echo| echo.is_request()) {
                        log::debug!("Reply to ICMP echo request");
                        echo.make_reply()?.checked();
                        packet
                            .set_destination(src)?
                            .set_source(dest)?
                            .update_checksum()?;
                        if let Err(err) = write_packet(&write_tx, packet.to_owned()).await {
                            log::warn!("Packet dropped {}", err);
                        }
                    }
                }
            } else if !net.contains(&dest) {
                let mut packet = packet.to_owned();
                packet.set_source(config.host)?;

                if protocol == Protocol::Icmp {
                    log::debug!("Receive packet {} -> {} ({:?})", src, dest, protocol);
                    let mut icmp = icmp::Packet::new(packet.payload_mut())?;
                    if let Ok(mut echo) = icmp.echo_mut() {
                        let mut guard = table.lock();
                        let port = guard.forward((src, echo.identifier()));
                        log::debug!(
                            "Forward {}:{} to {}:{}",
                            src,
                            echo.identifier(),
                            config.host,
                            port
                        );
                        echo.set_identifier(port)?.checked();
                    } else {
                        continue;
                    }
                } else if protocol == Protocol::Udp {
                    log::debug!("Receive packet {} -> {} ({:?})", src, dest, protocol);
                    let enclosing = packet.to_owned();
                    let mut udp = udp::Packet::new(packet.payload_mut())?;
                    let mut guard = table.lock();
                    let port = guard.forward((src, udp.source()));
                    log::debug!(
                        "Forward {}:{} to {}:{}",
                        src,
                        udp.source(),
                        config.host,
                        port
                    );
                    udp.set_source(port)?.checked(&ip::Packet::V4(enclosing));
                } else if protocol == Protocol::Tcp {
                    log::debug!("Receive packet {} -> {} ({:?})", src, dest, protocol);
                    let enclosing = packet.to_owned();
                    let mut tcp = tcp::Packet::new(packet.payload_mut())?;
                    let mut guard = table.lock();
                    let port = guard.forward((src, tcp.source()));
                    log::debug!(
                        "Forward {}:{} to {}:{}",
                        src,
                        tcp.source(),
                        config.host,
                        port
                    );
                    tcp.set_source(port)?.checked(&ip::Packet::V4(enclosing));
                } else {
                    continue;
                }

                packet.update_checksum()?;
                raw_socket.send(packet.as_ref())?;
            }
        }
    }
    Ok(())
}

async fn send_daemon(
    config: AtewayNatConfig,
    write_tx: UnboundedSender<AtewayAdapterTask>,
    mut cap: Capture<Active>,
    table: Arc<Mutex<AtewayNatTable>>,
) -> Result<()> {
    while let Ok(capture) = task::block_in_place(|| cap.next_packet()) {
        let eth = ether::Packet::new(capture.data)?;
        if eth.protocol() == ether::Protocol::Ipv4 {
            let mut packet = ip::v4::Packet::new(eth.payload().to_owned())?;
            let src = packet.source();
            let dest = packet.destination();
            let protocol = packet.protocol();

            if dest == config.host {
                if protocol == Protocol::Icmp {
                    let mut icmp = icmp::Packet::new(packet.payload_mut())?;
                    if let Ok(mut echo) = icmp.echo_mut() {
                        let mut guard = table.lock();
                        if let Some((addr, port)) = guard.backward(echo.identifier()) {
                            log::debug!("Send packet {} -> {} ({:?})", src, dest, protocol);
                            log::debug!(
                                "Backward {}:{} to {}:{}",
                                config.address,
                                echo.identifier(),
                                src,
                                port
                            );
                            echo.set_identifier(port)?.checked();
                            packet.set_destination(addr)?;
                        } else {
                            continue;
                        }
                    }
                } else if protocol == Protocol::Udp {
                    let mut enclosing = packet.to_owned();
                    let mut udp = udp::Packet::new(packet.payload_mut())?;
                    let mut guard = table.lock();
                    if let Some((addr, port)) = guard.backward(udp.destination()) {
                        log::debug!("Send packet {} -> {} ({:?})", src, dest, protocol);
                        log::debug!(
                            "Backward {}:{} to {}:{}",
                            config.host,
                            udp.destination(),
                            addr,
                            port
                        );

                        enclosing.set_destination(addr)?;
                        udp.set_destination(port)?
                            .checked(&ip::Packet::V4(enclosing));
                        packet.set_destination(addr)?;
                    } else {
                        continue;
                    }
                } else if protocol == Protocol::Tcp {
                    let mut enclosing = packet.to_owned();
                    let mut tcp = tcp::Packet::new(packet.payload_mut())?;
                    let mut guard = table.lock();
                    if let Some((addr, port)) = guard.backward(tcp.destination()) {
                        log::debug!("Send packet {} -> {} ({:?})", src, dest, protocol);
                        log::debug!(
                            "Backward {}:{} to {}:{}",
                            config.host,
                            tcp.destination(),
                            addr,
                            port
                        );

                        enclosing.set_destination(addr)?;
                        tcp.set_destination(port)?
                            .checked(&ip::Packet::V4(enclosing));
                        packet.set_destination(addr)?;
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }

                packet.update_checksum()?;
                if let Err(err) = write_packet(&write_tx, packet.to_owned()).await {
                    log::warn!("Packet dropped {}", err);
                }
            }
        }
    }

    Ok(())
}

type AtewayNatEntry = (Ipv4Addr, u16);

struct AtewayNatDynTable(LruCache<u16, Option<AtewayNatEntry>>);

impl AtewayNatDynTable {
    fn new(range: Range<u16>, exclude: &HashMap<u16, AtewayNatEntry>) -> Self {
        let len = range.len();
        let mut table = if len > 0 {
            LruCache::new(NonZeroUsize::new(len).unwrap())
        } else {
            LruCache::unbounded()
        };
        for port in range {
            if exclude.contains_key(&port) {
                continue;
            }
            table.put(port, None);
        }
        Self(table)
    }

    fn forward(&mut self, entry: AtewayNatEntry) -> u16 {
        let pair = self.0.iter().find(|(_, &v)| v == Some(entry));
        match pair {
            Some((&port, _)) => {
                self.0.promote(&port);
                port
            }
            None => {
                let (port, _) = self.0.pop_lru().unwrap();
                self.0.put(port, Some(entry));
                port
            }
        }
    }

    fn backward(&mut self, port: u16) -> Option<AtewayNatEntry> {
        match self.0.get(&port) {
            Some(Some(entry)) => Some(*entry),
            _ => None,
        }
    }
}

struct AtewayStaticTable(HashMap<u16, AtewayNatEntry>);

impl AtewayStaticTable {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn forward(&self, entry: AtewayNatEntry) -> Option<u16> {
        self.0.iter().find(|(_, &v)| v == entry).map(|(&k, _)| k)
    }

    fn backward(&self, port: u16) -> Option<AtewayNatEntry> {
        self.0.get(&port).copied()
    }
}

struct AtewayNatTable {
    dyn_table: AtewayNatDynTable,
    static_table: AtewayStaticTable,
}

impl AtewayNatTable {
    fn new(range: Range<u16>, routes: Option<HashMap<u16, SocketAddrV4>>) -> Self {
        let mut static_table = AtewayStaticTable::new();
        if let Some(map) = routes {
            for (port, addr) in map {
                static_table.0.insert(port, (*addr.ip(), addr.port()));
            }
        }

        Self {
            dyn_table: AtewayNatDynTable::new(range, &static_table.0),
            static_table,
        }
    }

    fn forward(&mut self, entry: AtewayNatEntry) -> u16 {
        self.static_table
            .forward(entry)
            .unwrap_or_else(|| self.dyn_table.forward(entry))
    }

    fn backward(&mut self, port: u16) -> Option<AtewayNatEntry> {
        self.static_table
            .backward(port)
            .or_else(|| self.dyn_table.backward(port))
    }
}
