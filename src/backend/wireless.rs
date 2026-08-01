use std::{net::Ipv4Addr, sync::Arc};

use idevice::{
    IdeviceError,
    remote_pairing::{
        PAIRABLE_HOST_SERVICE_TYPE, PairableHost, PairableHostInfo, RemotePairingClient,
        RpPairingFile, RpPairingSocket, connect_tls_psk_tunnel_native,
    },
    tcp::adapter::Adapter,
};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use tokio::{
    net::TcpListener,
    sync::{Mutex, oneshot},
};
use tracing::{debug, info};

use super::{Event, Events, WirelessStatus, discovery, host_label, link::Link};

const MODEL: &str = "Mac17,7";

pub struct HostIdentity {
    info: PairableHostInfo,
    pairing_file: RpPairingFile,
}

impl HostIdentity {
    pub fn generate() -> Self {
        Self {
            info: PairableHostInfo::generate(host_label(), MODEL),
            pairing_file: RpPairingFile::generate(host_label()),
        }
    }
}

pub struct WirelessDevice {
    pub udid: String,
    pub name: String,
    pub pairing_file: RpPairingFile,
}

pub async fn accept_pairing(
    identity: &HostIdentity,
    events: &Events,
) -> Result<WirelessDevice, IdeviceError> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    let _advert = Advertisement::start(identity, listener.local_addr()?.port());
    events.send(Event::Wireless(WirelessStatus::Advertising(
        identity.info.name.clone(),
    )));

    let (stream, address) = listener.accept().await?;
    info!("device connected from {address}");
    events.send(Event::Wireless(WirelessStatus::Connected));

    let mut pairing_file = identity.pairing_file.clone();
    let mut host = PairableHost::new(RpPairingSocket::new_device(stream), identity.info.clone());
    let peer = host
        .accept(&mut pairing_file, |pin| async {
            events.send(Event::Wireless(WirelessStatus::Pin(pin)));
        })
        .await?;

    Ok(WirelessDevice {
        udid: peer.remotepairing_udid,
        name: peer.name,
        pairing_file,
    })
}

pub async fn pair_apple_tv(
    events: &Events,
    addresses: discovery::Addresses,
    pin_receiver: oneshot::Receiver<String>,
) -> Result<WirelessDevice, IdeviceError> {
    let host = host_label();
    let mut pairing_file = RpPairingFile::generate(host);
    let stream = addresses.connect().await?;
    let mut client = RemotePairingClient::new(RpPairingSocket::new(stream), host);
    let pin_receiver = Arc::new(Mutex::new(pin_receiver));
    let events = events.clone();
    client
        .connect(&mut pairing_file, || {
            let events = events.clone();
            let pin_receiver = pin_receiver.clone();
            async move {
                events.send(Event::Wireless(WirelessStatus::EnterPin(host.to_string())));
                (&mut *pin_receiver.lock().await).await.unwrap_or_default()
            }
        })
        .await?;

    let peer = client.paired_peer_device()?;
    Ok(WirelessDevice {
        udid: peer.remotepairing_udid.clone(),
        name: peer.name.clone(),
        pairing_file,
    })
}

pub async fn open_link(pairing_file: &mut RpPairingFile) -> Result<Link, IdeviceError> {
    let alt_irk = pairing_file
        .alt_irk
        .as_ref()
        .ok_or_else(|| IdeviceError::UnexpectedResponse("pairing file has no alt_irk".into()))?;

    let addresses = discovery::find_remote_pairing(alt_irk)
        .await
        .ok_or(IdeviceError::DeviceNotFound)?;

    let mut control = RemotePairingClient::new(
        RpPairingSocket::new(addresses.connect().await?),
        host_label(),
    );
    control.attempt_pair_verify().await?;
    control.validate_pairing(pairing_file).await?;

    let tunnel_port = control.create_tcp_listener().await?;
    debug!("device is listening for a tunnel on {tunnel_port}");
    let tunnel = connect_tls_psk_tunnel_native(
        addresses.connect_to(tunnel_port).await?,
        control.encryption_key(),
    )
    .await?;

    let client_ip = tunnel.info.client_address.parse()?;
    let server_ip = tunnel.info.server_address.parse()?;
    let mtu = tunnel.info.mtu as usize;
    let rsd_port = tunnel.info.server_rsd_port;

    let mut adapter = Adapter::new(Box::new(tunnel.into_inner()), client_ip, server_ip);
    adapter.set_mss(mtu.saturating_sub(60));
    Link::over_remote_pairing(adapter.to_async_handle(), rsd_port, control).await
}

struct Advertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Advertisement {
    fn start(identity: &HostIdentity, port: u16) -> Self {
        let identifier = identity.pairing_file.identifier.clone();
        let txt_records = identity.info.mdns_txt_records(&identifier);
        let properties: Vec<_> = txt_records
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();

        let daemon = ServiceDaemon::new().expect("failed to start mDNS daemon");
        daemon
            .set_service_name_len_max(30)
            .expect("failed to raise the service name limit");

        let service = ServiceInfo::new(
            PAIRABLE_HOST_SERVICE_TYPE,
            &identifier,
            &format!("idevice-{}.local.", &identifier[..8]),
            "",
            port,
            &properties[..],
        )
        .expect("invalid mDNS service")
        .enable_addr_auto();

        let fullname = service.get_fullname().to_string();
        daemon.register(service).expect("failed to advertise");
        info!("advertising {fullname} on port {port}");

        Self { daemon, fullname }
    }
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}
