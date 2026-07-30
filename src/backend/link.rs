use std::sync::Arc;

use idevice::{
    IdeviceError, IdeviceService, ReadWrite, RsdService,
    core_device_proxy::CoreDeviceProxy,
    lockdown::LockdownClient,
    provider::{IdeviceProvider, RsdProvider, UsbmuxdProvider},
    remote_pairing::{RemotePairingClient, RpPairingSocket},
    rsd::RsdHandshake,
    tcp::handle::AdapterHandle,
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdDevice},
};
use tokio::{net::TcpStream, sync::Mutex};
use tracing::trace;

use super::{DeviceInfo, host_label};

type TunnelControl = Arc<Mutex<RemotePairingClient<RpPairingSocket<TcpStream>>>>;

#[derive(Clone)]
pub enum Link {
    Usbmuxd {
        provider: UsbmuxdProvider,
        needs_session: bool,
    },
    Rsd {
        handle: AdapterHandle,
        rsd: RsdHandshake,
        _tunnel_control: Option<TunnelControl>,
    },
}

impl Link {
    pub fn usbmuxd(device: &UsbmuxdDevice) -> Self {
        Self::Usbmuxd {
            provider: device.to_provider(UsbmuxdAddr::default(), host_label()),
            needs_session: device.connection_type != Connection::Usb,
        }
    }

    pub async fn over_core_device(provider: &dyn IdeviceProvider) -> Result<Self, IdeviceError> {
        let proxy = CoreDeviceProxy::connect(provider).await?;
        let rsd_port = proxy.tunnel_info().server_rsd_port;
        let handle = proxy.create_software_tunnel()?.to_async_handle();
        Self::rsd(handle, rsd_port, None).await
    }

    pub async fn over_remote_pairing(
        handle: AdapterHandle,
        rsd_port: u16,
        control: RemotePairingClient<RpPairingSocket<TcpStream>>,
    ) -> Result<Self, IdeviceError> {
        Self::rsd(handle, rsd_port, Some(Arc::new(Mutex::new(control)))).await
    }

    async fn rsd(
        mut handle: AdapterHandle,
        rsd_port: u16,
        tunnel_control: Option<TunnelControl>,
    ) -> Result<Self, IdeviceError> {
        let rsd = RsdHandshake::new(handle.connect(rsd_port).await?).await?;
        trace!(
            "tunnel services: {:?}",
            rsd.services.keys().collect::<Vec<_>>()
        );

        Ok(Self::Rsd {
            handle,
            rsd,
            _tunnel_control: tunnel_control,
        })
    }

    pub async fn service<T: IdeviceService + RsdService>(&mut self) -> Result<T, IdeviceError> {
        match self {
            Self::Usbmuxd { provider, .. } => T::connect(provider).await,
            Self::Rsd { handle, rsd, .. } => rsd.connect::<T>(handle).await,
        }
    }

    pub async fn connect_rsd_service(
        &mut self,
        name: &str,
    ) -> Result<Box<dyn ReadWrite>, IdeviceError> {
        let Self::Rsd { handle, rsd, .. } = self else {
            return Err(IdeviceError::ServiceNotFound);
        };
        let port = rsd
            .services
            .get(name)
            .ok_or(IdeviceError::ServiceNotFound)?
            .port;
        handle.connect_to_service_port(port).await
    }

    pub async fn lockdown(&mut self) -> Result<LockdownClient, IdeviceError> {
        self.lockdown_client(true).await
    }

    pub async fn info(&mut self) -> Result<DeviceInfo, IdeviceError> {
        device_info(&mut self.lockdown_client(false).await?).await
    }

    async fn lockdown_client(&mut self, privileged: bool) -> Result<LockdownClient, IdeviceError> {
        let mut client = self.service::<LockdownClient>().await?;
        if let Self::Usbmuxd {
            provider,
            needs_session,
        } = self
            && (privileged || *needs_session)
        {
            let pairing_file = provider.get_pairing_file().await?;
            client.start_session(&pairing_file).await?;
        }
        Ok(client)
    }

    pub async fn developer_mode(&mut self) -> Result<bool, IdeviceError> {
        self.lockdown()
            .await?
            .get_value(
                Some("DeveloperModeStatus"),
                Some("com.apple.security.mac.amfi"),
            )
            .await?
            .as_boolean()
            .ok_or_else(|| {
                IdeviceError::UnexpectedResponse("DeveloperModeStatus not a boolean".into())
            })
    }

    pub async fn enable_wireless_debugging(&mut self) -> Result<(), IdeviceError> {
        self.lockdown()
            .await?
            .set_value(
                "EnableWifiDebugging",
                true.into(),
                Some("com.apple.mobile.wireless_lockdown"),
            )
            .await
    }

    pub async fn unique_chip_id(&mut self) -> Result<u64, IdeviceError> {
        self.lockdown()
            .await?
            .get_value(Some("UniqueChipID"), None)
            .await?
            .as_unsigned_integer()
            .ok_or_else(|| IdeviceError::UnexpectedResponse("UniqueChipID not an integer".into()))
    }
}

pub async fn device_info(client: &mut LockdownClient) -> Result<DeviceInfo, IdeviceError> {
    Ok(DeviceInfo {
        model: value(client, "ProductType").await?,
        version: format!(
            "{} ({})",
            value(client, "ProductVersion").await?,
            value(client, "BuildVersion").await?
        ),
        udid: value(client, "UniqueDeviceID").await?,
    })
}

pub async fn value(client: &mut LockdownClient, key: &str) -> Result<String, IdeviceError> {
    client
        .get_value(Some(key), None)
        .await?
        .as_string()
        .map(str::to_owned)
        .ok_or_else(|| IdeviceError::UnexpectedResponse(format!("{key} not a string")))
}
