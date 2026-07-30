use std::{
    net::{IpAddr, SocketAddr, SocketAddrV6},
    time::Duration,
};

use idevice::{IdeviceError, pairing_file::PairingFile, remote_pairing::PeerDevice};
use mdns_sd::{ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent};
use tokio::net::TcpStream;
use tracing::debug;

const REMOTE_PAIRING: &str = "_remotepairing._tcp.local.";
const LOCKDOWN: &str = "_apple-mobdev2._tcp.local.";
pub(super) const LOCKDOWN_PORT: u16 = 62078;
const BROWSE_TIMEOUT: Duration = Duration::from_secs(6);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

pub struct Addresses(SocketAddr);

impl Addresses {
    pub fn one(ip: IpAddr, port: u16) -> Self {
        Self(SocketAddr::new(ip, port))
    }

    pub async fn connect(&self) -> Result<TcpStream, IdeviceError> {
        self.connect_port(None).await
    }

    pub async fn connect_to(&self, port: u16) -> Result<TcpStream, IdeviceError> {
        self.connect_port(Some(port)).await
    }

    async fn connect_port(&self, port: Option<u16>) -> Result<TcpStream, IdeviceError> {
        let mut address = self.0;
        if let Some(port) = port {
            address.set_port(port);
        }

        debug!("connecting to {address}");
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(IdeviceError::Socket(e)),
            Err(_) => Err(IdeviceError::Socket(std::io::ErrorKind::TimedOut.into())),
        }
    }
}

pub async fn find_remote_pairing(alt_irk: &[u8]) -> Option<Addresses> {
    browse(REMOTE_PAIRING, |service| {
        let identifier = service.get_property_val_str("identifier")?;
        let auth_tag = service.get_property_val_str("authTag")?;
        if PeerDevice::validate_auth_tag(alt_irk, identifier, auth_tag) {
            address(service)
        } else {
            None
        }
    })
    .await
}

pub async fn find_lockdown(pairing_file: &PairingFile) -> Option<Addresses> {
    let mac = &pairing_file.wifi_mac_address;
    let host_id = pairing_file.host_id.as_bytes();

    browse(LOCKDOWN, |service| {
        let named = service
            .fullname
            .split_once('@')
            .is_some_and(|(instance, _)| instance.eq_ignore_ascii_case(mac));
        if named || matches_auth_tag(service, host_id) {
            address(service)
        } else {
            None
        }
    })
    .await
}

fn matches_auth_tag(service: &ResolvedService, host_id: &[u8]) -> bool {
    let Some(identifier) = service.get_property_val_str("identifier") else {
        return false;
    };
    let tags: Vec<&[u8]> = service
        .txt_properties
        .iter()
        .filter(|property| property.key() == "authTag")
        .filter_map(|property| property.val())
        .collect();

    idevice::mdns::txt_record_matches(host_id, identifier.as_bytes(), &tags)
}

fn address(service: &ResolvedService) -> Option<Addresses> {
    let port = service.port;
    service.addresses.iter().next().map(|ip| {
        Addresses(match ip {
            ScopedIp::V6(v6) => {
                SocketAddr::V6(SocketAddrV6::new(*v6.addr(), port, 0, v6.scope_id().index))
            }
            ip => SocketAddr::new(ip.to_ip_addr(), port),
        })
    })
}

async fn browse<T>(
    service_type: &str,
    mut pick: impl FnMut(&ResolvedService) -> Option<T>,
) -> Option<T> {
    let daemon = ServiceDaemon::new().ok()?;
    let receiver = daemon.browse(service_type).ok()?;
    let deadline = tokio::time::Instant::now() + BROWSE_TIMEOUT;

    let found = loop {
        match tokio::time::timeout_at(deadline, receiver.recv_async()).await {
            Ok(Ok(ServiceEvent::ServiceResolved(service))) => {
                debug!("resolved {}", service.fullname);
                if let Some(found) = pick(&service) {
                    break Some(found);
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => break None,
        }
    };

    let _ = daemon.shutdown();
    found
}
