use super::{DeviceKey, Events, host_label, link::Link};
use idevice::{
    IdeviceError, RemoteXpcClient,
    pairing_file::PairingFile,
    remote_pairing::{RemotePairingClient, RpPairingFile},
};

const RP_FILE_NAME: &str = "rp_pairing_file.plist";
const TUNNEL_SERVICE: &str = "com.apple.internal.dt.coredevice.untrusted.tunnelservice";

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum PairingKind {
    Lockdown,
    #[default]
    Remote,
}

impl PairingKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Lockdown => "Lockdown",
            Self::Remote => "Remote pairing",
        }
    }
}

#[derive(Clone)]
pub enum Payload {
    Lockdown(Box<PairingFile>),
    Remote(Box<RpPairingFile>),
}

impl Payload {
    pub fn bytes(&self) -> Result<Vec<u8>, IdeviceError> {
        match self {
            Self::Lockdown(file) => file.clone().serialize(),
            Self::Remote(file) => Ok(file.to_bytes()),
        }
    }

    pub fn result(&self, udid: &str) -> Result<PairingResult, IdeviceError> {
        let bytes = self.bytes()?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| IdeviceError::UnexpectedResponse("pairing file is not UTF-8".into()))?
            .trim_end()
            .to_owned();
        Ok(PairingResult {
            text,
            file_name: match self {
                Self::Lockdown(_) => format!("{udid}.plist"),
                Self::Remote(_) => RP_FILE_NAME.into(),
            },
            bytes,
        })
    }
}

pub struct PairingResult {
    pub bytes: Vec<u8>,
    pub text: String,
    pub file_name: String,
}

pub async fn lockdown_file(
    link: &mut Link,
    udid: &str,
    events: &Events,
    key: &DeviceKey,
) -> Result<PairingFile, IdeviceError> {
    let system_buid = match link {
        Link::Usbmuxd { .. } => alter(super::usb::buid().await?),
        Link::Rsd { .. } => uuid(),
    };

    let mut client = link.lockdown().await?;
    events.progress(key, "Tap “Trust” on your device if it asks");

    let mut file = client.pair(uuid(), system_buid, Some(host_label())).await?;
    file.udid = Some(udid.to_string());
    Ok(file)
}

pub async fn stored_lockdown_file(udid: &str) -> Result<PairingFile, IdeviceError> {
    let mut file = super::usb::pair_record(udid).await?;
    file.udid = Some(udid.to_string());
    Ok(file)
}

pub async fn remote_file(
    link: &mut Link,
    events: &Events,
    key: &DeviceKey,
) -> Result<RpPairingFile, IdeviceError> {
    let mut file = RpPairingFile::generate(host_label());
    for message in [
        "Trust this computer on your device",
        "Saving the pairing on the device",
    ] {
        events.progress(key, message);
        tunnel_service_client(link)
            .await?
            .connect(&mut file, || async { "000000".to_string() })
            .await?;
    }

    Ok(file)
}

pub async fn verify_remote(link: &mut Link, file: &mut RpPairingFile) -> Result<(), IdeviceError> {
    let mut client = tunnel_service_client(link).await?;
    client.attempt_pair_verify().await?;
    client.validate_pairing(file).await
}

async fn tunnel_service_client(
    link: &mut Link,
) -> Result<RemotePairingClient<RemoteXpcClient<Box<dyn idevice::ReadWrite>>>, IdeviceError> {
    let stream = link.connect_rsd_service(TUNNEL_SERVICE).await?;
    let mut xpc = RemoteXpcClient::new(stream).await?;
    xpc.do_handshake().await?;
    let _ = xpc.recv_root().await;

    Ok(RemotePairingClient::new(xpc, host_label()))
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string().to_uppercase()
}

fn alter(mut buid: String) -> String {
    let first = if buid.starts_with('F') { "A" } else { "F" };
    buid.replace_range(..1, first);
    buid
}
