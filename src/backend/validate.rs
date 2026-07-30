use std::net::IpAddr;

use idevice::{Idevice, IdeviceError, lockdown::LockdownClient, pairing_file::PairingFile};

use super::{discovery, host_label};

pub async fn lockdown_over_lan(file: &PairingFile, ip: Option<IpAddr>) -> Result<(), IdeviceError> {
    let addresses = match ip {
        Some(ip) => discovery::Addresses::one(ip, discovery::LOCKDOWN_PORT),
        None => discovery::find_lockdown(file)
            .await
            .ok_or(IdeviceError::DeviceNotFound)?,
    };

    let stream = addresses.connect().await?;
    LockdownClient::new(Idevice::new(Box::new(stream), host_label()))
        .start_session(file)
        .await
        .map(|_| ())
}
