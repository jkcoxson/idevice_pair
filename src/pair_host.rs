use std::net::Ipv4Addr;

use idevice::{
    IdeviceError,
    remote_pairing::{
        PAIRABLE_HOST_SERVICE_TYPE, PairableHost, PairableHostInfo, RpPairingFile, RpPairingSocket,
    },
};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use rust_i18n::t;
use tokio::{net::TcpListener, sync::mpsc::UnboundedSender, sync::oneshot};

use crate::{GuiCommands, PairingPayload};

fn status(gui_sender: &UnboundedSender<GuiCommands>, message: impl Into<String>) {
    let _ = gui_sender.send(GuiCommands::WirelessPairingStatus(message.into()));
}

pub async fn run_pairable_host(
    name: String,
    model: String,
    mut cancel: oneshot::Receiver<()>,
    gui_sender: UnboundedSender<GuiCommands>,
) {
    match pairable_host_session(&name, &model, &mut cancel, &gui_sender).await {
        Ok(Some(pairing_file)) => {
            let _ = gui_sender.send(GuiCommands::WirelessPairingResult(Ok(
                PairingPayload::Remote(pairing_file),
            )));
        }
        Ok(None) => {
            let _ = gui_sender.send(GuiCommands::WirelessPairingStopped);
        }
        Err(e) => {
            let _ = gui_sender.send(GuiCommands::WirelessPairingResult(Err(e)));
        }
    }
}

async fn pairable_host_session(
    name: &str,
    model: &str,
    cancel: &mut oneshot::Receiver<()>,
    gui_sender: &UnboundedSender<GuiCommands>,
) -> Result<Option<RpPairingFile>, IdeviceError> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(IdeviceError::Socket)?;
    let port = listener.local_addr().map_err(IdeviceError::Socket)?.port();

    let mut pairing_file = RpPairingFile::generate(name);
    let host_info = PairableHostInfo::generate(name, model);
    let service_identifier = pairing_file.identifier.clone();

    let mdns = ServiceDaemon::new()
        .map_err(|e| IdeviceError::InternalError(format!("mDNS daemon: {e}")))?;
    mdns.set_service_name_len_max(30)
        .map_err(|e| IdeviceError::InternalError(format!("mDNS config: {e}")))?;
    let hostname = format!("idevice-{}.local.", &service_identifier[..8]);
    let txt = host_info.mdns_txt_records(&service_identifier);
    let properties: Vec<(&str, &str)> = txt.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let service_info = ServiceInfo::new(
        PAIRABLE_HOST_SERVICE_TYPE,
        &service_identifier,
        &hostname,
        "",
        port,
        &properties[..],
    )
    .map_err(|e| IdeviceError::InternalError(format!("mDNS service: {e}")))?
    .enable_addr_auto();
    mdns.register(service_info)
        .map_err(|e| IdeviceError::InternalError(format!("mDNS register: {e}")))?;

    status(gui_sender, t!("wireless_pair_waiting", name = name));

    let accepted = tokio::select! {
        _ = &mut *cancel => None,
        res = listener.accept() => Some(res.map_err(IdeviceError::Socket)?),
    };
    let (stream, _peer) = match accepted {
        Some(conn) => conn,
        None => {
            let _ = mdns.shutdown();
            return Ok(None);
        }
    };

    status(gui_sender, t!("wireless_pair_connected"));

    let socket = RpPairingSocket::new_device(stream);
    let mut host = PairableHost::new(socket, host_info);

    let pin_sender = gui_sender.clone();
    let peer_device = tokio::select! {
        _ = &mut *cancel => {
            let _ = mdns.shutdown();
            return Ok(None);
        }
        res = host.accept(&mut pairing_file, move |pin| async move {
            let _ = pin_sender.send(GuiCommands::WirelessPairingPin(pin));
        }) => res?,
    };

    let _ = mdns.shutdown();
    status(
        gui_sender,
        t!("wireless_pair_paired", name = peer_device.name.clone()),
    );
    Ok(Some(pairing_file))
}
