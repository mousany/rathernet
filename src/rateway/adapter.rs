use super::AtewayIoError;
use crate::{
    racsma::{
        builtin::SOCKET_BROADCAST_ADDRESS, AcsmaIoSocket, AcsmaSocketConfig, AcsmaSocketReader,
        AcsmaSocketWriter,
    },
    rather::encode::{DecodeToBytes, EncodeFromBytes},
    raudio::AsioDevice,
};
use anyhow::Result;
use futures::{
    future::BoxFuture,
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use ipnet::Ipv4Net;
use packet::{
    icmp,
    ip::{self, v4::Packet as Ipv4Packet, Protocol},
    PacketMut,
};
use std::{
    future::Future,
    net::Ipv4Addr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        oneshot::{self, Sender},
    },
    task::JoinHandle,
};
use tokio_util::codec::Framed;
use tun::{AsyncDevice, Configuration, TunPacket, TunPacketCodec};

#[derive(Clone)]
pub struct AtewayAdapterConfig {
    pub name: String,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub socket_config: AcsmaSocketConfig,
}

impl AtewayAdapterConfig {
    pub fn new(
        name: String,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
        socket_config: AcsmaSocketConfig,
    ) -> Self {
        Self {
            name,
            address,
            netmask,
            gateway,
            socket_config,
        }
    }
}

pub struct AtewayIoAdaper {
    config: AtewayAdapterConfig,
    device: AsioDevice,
    inner: Option<BoxFuture<'static, Result<()>>>,
}

impl AtewayIoAdaper {
    pub fn new(config: AtewayAdapterConfig, device: AsioDevice) -> Self {
        Self {
            config,
            device,
            inner: None,
        }
    }
}

impl Future for AtewayIoAdaper {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.inner.is_none() {
            let config = this.config.clone();
            let device = this.device.clone();
            let inner = Box::pin(adapter_daemon(config, device));
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

async fn adapter_daemon(config: AtewayAdapterConfig, device: AsioDevice) -> Result<()> {
    let (tx_socket, rx_socket) =
        AcsmaIoSocket::try_from_device(config.socket_config.clone(), &device)?;

    let dev = {
        let mut tun_config = Configuration::default();
        tun_config
            .name(&config.name)
            .address(config.address)
            .netmask(config.netmask)
            .up();
        #[cfg(target_os = "windows")]
        tun_config.platform(|config| {
            config.initialize();
        });
        tun::create_as_async(&tun_config)
    }?;
    let (tx_tun, rx_tun) = dev.into_framed().split();

    let (write_tx, write_rx) = mpsc::unbounded_channel();

    let write_handle = tokio::spawn(write_daemon(config.clone(), tx_socket, write_rx));
    let receive_handle = tokio::spawn(receive_daemon(
        config.clone(),
        write_tx.clone(),
        rx_socket,
        tx_tun,
    ));
    let send_handle = tokio::spawn(send_daemon(config, write_tx, rx_tun));

    tokio::try_join!(
        flatten(write_handle),
        flatten(receive_handle),
        flatten(send_handle)
    )?;
    Ok(())
}

pub(super) async fn flatten<T>(handle: JoinHandle<Result<T>>) -> Result<T> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(err.into()),
    }
}

pub(super) type AtewayAdapterTask = (Ipv4Packet<Vec<u8>>, Sender<Result<()>>);

async fn write_daemon(
    config: AtewayAdapterConfig,
    tx_socket: AcsmaSocketWriter,
    mut write_rx: UnboundedReceiver<AtewayAdapterTask>,
) -> Result<()> {
    let gateway_mac = tx_socket
        .arp(u32::from_be_bytes(config.gateway.octets()) as usize)
        .await
        .map_err(|_| AtewayIoError::GatewayUnreachable(config.gateway));
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
            gateway_mac.map_err(|err| err.into())
        };

        let result = match dest {
            Ok(inner) => {
                log::debug!("Resolve MAC address: {} -> {}", ip, inner);
                tx_socket.write(inner, &packet.as_ref().encode()).await
            }
            Err(err) => Err(err),
        };
        tx.send(result).ok();
    }
    Ok(())
}

async fn receive_daemon(
    config: AtewayAdapterConfig,
    write_tx: UnboundedSender<AtewayAdapterTask>,
    mut rx_socket: AcsmaSocketReader,
    mut tx_tun: SplitSink<Framed<AsyncDevice, TunPacketCodec>, TunPacket>,
) -> Result<()> {
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

                        if let Err(err) = write_packet(&write_tx, packet).await {
                            log::warn!("Packet dropped {}", err);
                        }
                        continue;
                    }
                } else if protocol == Protocol::Udp {
                    log::debug!("Receive packet {} -> {} ({:?})", src, dest, protocol);
                } else if protocol == Protocol::Tcp {
                    log::debug!("Receive packet {} -> {} ({:?})", src, dest, protocol);
                } else {
                    continue;
                }

                let packet = TunPacket::new(packet.as_ref().to_owned());
                tx_tun.send(packet).await?;
            }
        }
    }
    Ok(())
}

async fn send_daemon(
    config: AtewayAdapterConfig,
    write_tx: UnboundedSender<AtewayAdapterTask>,
    mut rx_tun: SplitStream<Framed<AsyncDevice, TunPacketCodec>>,
) -> Result<()> {
    while let Some(Ok(packet)) = rx_tun.next().await {
        let bytes = packet.get_bytes();
        if let Ok(ip::Packet::V4(packet)) = ip::Packet::new(bytes) {
            let src = packet.source();
            let dest = packet.destination();
            let protocol = packet.protocol();

            if src == config.address {
                if protocol != Protocol::Icmp
                    && protocol != Protocol::Udp
                    && protocol != Protocol::Tcp
                {
                    continue;
                }
                log::debug!("Send packet {} -> {} ({:?})", src, dest, protocol);

                if let Err(err) = write_packet(&write_tx, packet.to_owned()).await {
                    log::warn!("Packet dropped {}", err);
                }
            }
        }
    }
    Ok(())
}

pub(super) async fn write_packet(
    write_tx: &UnboundedSender<AtewayAdapterTask>,
    packet: Ipv4Packet<Vec<u8>>,
) -> Result<()> {
    let (tx, rx) = oneshot::channel();
    write_tx.send((packet, tx))?;
    rx.await??;
    Ok(())
}
