use futures_util::StreamExt;
use idevice::{
    IdeviceError, IdeviceService,
    lockdown::LockdownClient,
    pairing_file::PairingFile,
    provider::IdeviceProvider,
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection, UsbmuxdDevice, UsbmuxdListenEvent},
};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, warn};

use super::{
    DeviceInfo, host_label,
    link::{device_info, value},
};

const DESCRIBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

pub struct UsbDevice {
    pub device: UsbmuxdDevice,
    pub name: String,
    pub info: DeviceInfo,
}

pub async fn list() -> Result<Vec<UsbDevice>, IdeviceError> {
    let devices = UsbmuxdConnection::default().await?.get_devices().await?;
    let described = futures_util::future::join_all(devices.iter().map(describe)).await;

    Ok(devices
        .into_iter()
        .zip(described)
        .filter_map(|(device, described)| {
            described.map(|(name, info)| UsbDevice { device, name, info })
        })
        .collect())
}

pub async fn buid() -> Result<String, IdeviceError> {
    UsbmuxdConnection::default().await?.get_buid().await
}

pub async fn pair_record(udid: &str) -> Result<PairingFile, IdeviceError> {
    UsbmuxdConnection::default()
        .await?
        .get_pair_record(udid)
        .await
}

pub async fn watch(changes: UnboundedSender<()>) {
    if let Err(e) = listen(&changes).await {
        warn!("usbmuxd listen stopped: {}", super::message(&e));
    }
}

async fn listen(changes: &UnboundedSender<()>) -> Result<(), IdeviceError> {
    let mut connection = UsbmuxdConnection::default().await?;
    let mut stream = connection.listen().await?;

    while let Some(event) = stream.next().await {
        match event? {
            UsbmuxdListenEvent::Connected(_) | UsbmuxdListenEvent::Disconnected(_) => {
                changes.send(()).expect("device watcher stopped");
            }
        }
    }
    Ok(())
}

async fn describe(device: &UsbmuxdDevice) -> Option<(String, DeviceInfo)> {
    match tokio::time::timeout(DESCRIBE_TIMEOUT, ask(device)).await {
        Ok(Ok(described)) => Some(described),
        Ok(Err(e)) => {
            debug!("no details for {}: {}", device.udid, super::message(&e));
            None
        }
        Err(_) => {
            debug!("describing {} timed out", device.udid);
            None
        }
    }
}

async fn ask(device: &UsbmuxdDevice) -> Result<(String, DeviceInfo), IdeviceError> {
    let provider = device.to_provider(UsbmuxdAddr::default(), host_label());
    let mut client = LockdownClient::connect(&provider).await?;
    if device.connection_type != Connection::Usb {
        client
            .start_session(&provider.get_pairing_file().await?)
            .await?;
    }

    let name = value(&mut client, "DeviceName").await?;
    let info = device_info(&mut client).await?;
    Ok((name, info))
}
