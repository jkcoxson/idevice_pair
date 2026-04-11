// Jackson Coxson
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    thread,
};

use egui::{Color32, ComboBox, RichText};
use futures_util::{FutureExt, StreamExt};
use log::error;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::unbounded_channel;

use idevice::{
    Idevice, IdeviceError, IdeviceService, RemoteXpcClient,
    core_device_proxy::CoreDeviceProxy,
    house_arrest::HouseArrestClient,
    installation_proxy::InstallationProxyClient,
    lockdown::LockdownClient,
    pairing_file::PairingFile,
    provider::IdeviceProvider,
    remote_pairing::{RemotePairingClient, RpPairingFile},
    rsd::RsdHandshake,
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection, UsbmuxdDevice, UsbmuxdListenEvent},
};
use rfd::FileDialog;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

mod discover;
mod mount;

rust_i18n::i18n!("locales", fallback = "en");
use rust_i18n::t;

const RP_PAIRING_FILE_NAME: &str = "rp_pairing_file.plist";
const STIKDEBUG_APPSTORE_BUNDLE_ID: &str = "com.stik.sj";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PairingMode {
    Lockdown,
    RemotePairing,
}

impl PairingMode {
    fn label(self) -> &'static str {
        match self {
            Self::Lockdown => "Lockdown",
            Self::RemotePairing => "RPPairing",
        }
    }

    fn default_file_name(self, udid: &str) -> String {
        match self {
            Self::Lockdown => format!("{udid}.plist"),
            Self::RemotePairing => RP_PAIRING_FILE_NAME.to_string(),
        }
    }
}

#[derive(Clone)]
enum PairingPayload {
    Lockdown(PairingFile),
    Remote(RpPairingFile),
}

impl PairingPayload {
    fn bytes(&self) -> Result<Vec<u8>, IdeviceError> {
        match self {
            Self::Lockdown(pairing_file) => pairing_file.clone().serialize(),
            Self::Remote(pairing_file) => Ok(pairing_file.to_bytes()),
        }
    }

    fn display_string(&self) -> Result<String, IdeviceError> {
        let serialized = String::from_utf8_lossy(&self.bytes()?).to_string();
        Ok(serialized.trim_end().to_string())
    }

    fn as_lockdown(&self) -> Option<PairingFile> {
        match self {
            Self::Lockdown(pairing_file) => Some(pairing_file.clone()),
            Self::Remote(_) => None,
        }
    }
}

fn supported_apps_for_mode(mode: PairingMode) -> HashMap<String, String> {
    let mut supported_apps = HashMap::new();
    match mode {
        PairingMode::Lockdown => {
            supported_apps.insert(
                "SideStore".to_string(),
                "ALTPairingFile.mobiledevicepairing".to_string(),
            );
            supported_apps.insert(
                "LiveContainer".to_string(),
                "SideStore/Documents/ALTPairingFile.mobiledevicepairing".to_string(),
            );
            supported_apps.insert("SparseBox".to_string(), "pairingFile.plist".to_string());
            supported_apps.insert("ByeTunes".to_string(), "pairingFile.plist".to_string());
            supported_apps.insert("StikDebug".to_string(), "pairingFile.plist".to_string());
        }
        PairingMode::RemotePairing => {
            supported_apps.insert(
                "StikDebug (Sideloaded)".to_string(),
                RP_PAIRING_FILE_NAME.to_string(),
            );
            supported_apps.insert(
                "LiveContainer".to_string(),
                "SideStore/Documents/ALTPairingFile.mobiledevicepairing".to_string(),
            );
            supported_apps.insert("StosDebug".to_string(), "pairingFile.plist".to_string());
            supported_apps.insert("Protokolle".to_string(), "pairingFile.plist".to_string());
            supported_apps.insert("Antrag".to_string(), "pairingFile.plist".to_string());
            supported_apps.insert("Feather".to_string(), "pairingFile.plist".to_string());
        }
    }
    supported_apps
}

fn pairing_hostname() -> String {
    let suffix: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(6)
        .collect();
    format!("idevice_pair-{suffix}")
}

fn send_pairing_status(sender: &UnboundedSender<GuiCommands>, message: impl Into<String>) {
    let _ = sender.send(GuiCommands::PairingStatus(message.into()));
}

async fn generate_remote_pairing_file(
    provider: &dyn IdeviceProvider,
    hostname: &str,
    gui_sender: &UnboundedSender<GuiCommands>,
) -> Result<RpPairingFile, IdeviceError> {
    send_pairing_status(gui_sender, t!("connecting_coredevice"));
    let proxy = CoreDeviceProxy::connect(provider).await?;
    let rsd_port = proxy.tunnel_info().server_rsd_port;
    send_pairing_status(
        gui_sender,
        t!("cdtunnel_established", port = rsd_port.to_string()),
    );

    send_pairing_status(gui_sender, t!("starting_tcp"));
    let adapter = proxy.create_software_tunnel()?;
    let mut adapter = adapter.to_async_handle();

    send_pairing_status(gui_sender, t!("performing_rsd"));
    let rsd_stream = adapter.connect(rsd_port).await?;
    let handshake = RsdHandshake::new(rsd_stream).await?;
    send_pairing_status(
        gui_sender,
        t!("rsd_services", count = handshake.services.len().to_string()),
    );
    let tunnel_service = handshake
        .services
        .get("com.apple.internal.dt.coredevice.untrusted.tunnelservice")
        .ok_or_else(|| IdeviceError::InternalError("Untrusted tunnel service not found".into()))?;

    send_pairing_status(gui_sender, t!("connecting_untrusted"));
    let tunnel_service_stream = adapter.connect(tunnel_service.port).await?;
    let mut remote_xpc = RemoteXpcClient::new(tunnel_service_stream).await?;
    remote_xpc.do_handshake().await?;
    let _ = remote_xpc.recv_root().await;

    send_pairing_status(gui_sender, t!("starting_rp"));
    send_pairing_status(gui_sender, t!("trust_device"));
    let mut pairing_file = RpPairingFile::generate(hostname);
    let mut pairing_client = RemotePairingClient::new(remote_xpc, hostname, &mut pairing_file);
    pairing_client
        .connect(async |_| "000000".to_string(), ())
        .await?;

    Ok(pairing_file)
}

fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Cross-platform font search paths for CJK (Chinese) support
    let font_paths = [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/System/Library/Fonts/Supplemental/Songti.ttc",
        "/Library/Fonts/Arial Unicode.ttf",
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\msyh.ttf",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/wenquanyi/wqy-zenhei.ttc",
    ];

    let mut found_path = None;
    for path in font_paths {
        if std::path::Path::new(path).exists() {
            if let Ok(font_data) = std::fs::read(path) {
                fonts.font_data.insert(
                    "cjk_font".to_owned(),
                    egui::FontData::from_owned(font_data).into(),
                );
                found_path = Some(path);
                break;
            }
        }
    }

    if let Some(path) = found_path {
        println!("Loading font from: {}", path);
        fonts
            .families
            .get_mut(&egui::FontFamily::Proportional)
            .unwrap()
            .insert(0, "cjk_font".to_owned());
        fonts
            .families
            .get_mut(&egui::FontFamily::Monospace)
            .unwrap()
            .insert(0, "cjk_font".to_owned());
        ctx.set_fonts(fonts);
    } else {
        eprintln!("Warning: No CJK font found on this system. Chinese characters might not display correctly.");
    }
}

fn main() {
    println!("Startup");
    egui_logger::builder().init().unwrap();
    let (gui_sender, gui_recv) = unbounded_channel();
    let (idevice_sender, mut idevice_receiver) = unbounded_channel();
    idevice_sender.send(IdeviceCommands::GetDevices).unwrap();

    let app = MyApp {
        devices: None,
        devices_placeholder: t!("loading").to_string(),
        selected_device: "".to_string(),
        device_info: None,
        wireless_enabled: None,
        dev_mode_enabled: None,
        ddi_mounted: None,
        pairing_file: None,
        pairing_file_message: None,
        pairing_file_string: None,
        save_error: None,
        installed_apps: None,
        install_res: HashMap::new(),
        pairing_mode: PairingMode::RemotePairing,
        lockdown_supported_apps: supported_apps_for_mode(PairingMode::Lockdown),
        remote_supported_apps: supported_apps_for_mode(PairingMode::RemotePairing),
        validate_res: None,
        validating: false,
        validation_ip_input: "".to_string(),
        gui_recv,
        idevice_sender: idevice_sender.clone(),
        show_logs: false,
    };

    let mut options = eframe::NativeOptions::default();
    // Smoother drag/resize on Windows/Linux
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        options.vsync = false;
        options.run_and_return = false;
        options.wgpu_options.present_mode = wgpu::PresentMode::AutoNoVsync;
    }

    // Prefer GL only on macOS Intel
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        options.renderer = eframe::Renderer::Glow;
    }

    // Use default icon on macOS; use bundled PNG elsewhere
    #[cfg(target_os = "macos")]
    {
        options.viewport.icon = Some(std::sync::Arc::new(egui::IconData::default()));
    }

    #[cfg(not(target_os = "macos"))]
    {
        let icon_bytes: &[u8] = include_bytes!("../icon.png");
        let d = eframe::icon_data::from_png_bytes(icon_bytes).expect("The icon data must be valid");
        options.viewport.icon = Some(std::sync::Arc::new(d));
    }

    // rt must be kept in scope for channel lifetimes, so we define and then spawn.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let discover_sender = idevice_sender.clone();
    rt.spawn(async move {
        discover::start_discover(discover_sender).await;
    });

    let idevice_sender_listen = idevice_sender.clone();
    thread::spawn(move || {
        let rt_local = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt_local.block_on(async move {
            loop {
                match UsbmuxdConnection::default().await {
                    Ok(mut uc) => match uc.listen().await {
                        Ok(mut stream) => {
                            while let Some(evt) = stream.next().await {
                                match evt {
                                    Ok(UsbmuxdListenEvent::Connected(_))
                                    | Ok(UsbmuxdListenEvent::Disconnected(_)) => {
                                        let _ =
                                            idevice_sender_listen.send(IdeviceCommands::GetDevices);
                                    }
                                    Err(e) => {
                                        log::warn!("usbmuxd listen error: {e:?}");
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to start usbmuxd listen: {e:?}");
                        }
                    },
                    Err(e) => {
                        log::warn!("Failed to connect to usbmuxd for listening: {e:?}");
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });
    });

    rt.spawn(async move {
        let gui_sender = gui_sender.clone();
        let mut discovered_devices: HashMap<String, IpAddr> = HashMap::new(); // mac, IP
        'main: while let Some(command) = idevice_receiver.recv().await {
            match command {
                IdeviceCommands::GetDevices => {
                    // Connect to usbmuxd
                    let mut uc = match UsbmuxdConnection::default().await {
                        Ok(u) => u,
                        Err(e) => {
                            gui_sender.send(GuiCommands::NoUsbmuxd(e)).unwrap();
                            continue;
                        }
                    };

                    match uc.get_devices().await {
                        Ok(devs) => {
                            let devs: Vec<UsbmuxdDevice> = devs
                                .into_iter()
                                .filter(|x| x.connection_type == Connection::Usb)
                                .collect();

                            // We have to manually iterate to use async
                            let mut selections = HashMap::new();
                            for dev in devs {
                                let p = dev.to_provider(UsbmuxdAddr::default(), "idevice_pair");
                                let mut lc = match LockdownClient::connect(&p).await {
                                    Ok(l) => l,
                                    Err(e) => {
                                        error!("Failed to connect to lockdown: {e:?}");
                                        continue;
                                    }
                                };
                                let values = match lc.get_value(None, None).await {
                                    Ok(v) => v,
                                    Err(e) => {
                                        error!("Failed to get lockdown values: {e:?}");
                                        continue;
                                    }
                                };

                                // Get device name for selection
                                let device_name = match values
                                    .as_dictionary()
                                    .and_then(|x| x.get("DeviceName"))
                                    .and_then(|x| x.as_string())
                                {
                                    Some(n) => n.to_string(),
                                    _ => {
                                        continue;
                                    }
                                };
                                selections.insert(device_name, dev);
                            }

                            gui_sender.send(GuiCommands::Devices(selections)).unwrap();
                        }
                        Err(e) => {
                            gui_sender.send(GuiCommands::GetDevicesFailure(e)).unwrap();
                        }
                    }
                }
                IdeviceCommands::EnableWireless(dev) => {
                    // Connect to usbmuxd
                    let mut uc = match UsbmuxdConnection::default().await {
                        Ok(u) => u,
                        Err(e) => {
                            gui_sender.send(GuiCommands::NoUsbmuxd(e)).unwrap();
                            continue;
                        }
                    };

                    let p = dev.to_provider(UsbmuxdAddr::default(), "idevice_pair");
                    let mut lc = match LockdownClient::connect(&p).await {
                        Ok(l) => l,
                        Err(e) => {
                            gui_sender
                                .send(GuiCommands::EnableWirelessFailure(e))
                                .unwrap();
                            continue;
                        }
                    };

                    let pairing_file = match uc.get_pair_record(&p.udid).await {
                        Ok(p) => p,
                        Err(e) => {
                            gui_sender
                                .send(GuiCommands::EnableWirelessFailure(e))
                                .unwrap();
                            continue;
                        }
                    };

                    if let Err(e) = lc.start_session(&pairing_file).await {
                        gui_sender
                            .send(GuiCommands::EnableWirelessFailure(e))
                            .unwrap();
                        continue;
                    }

                    // Set the value
                    if let Err(e) = lc
                        .set_value(
                            "EnableWifiDebugging",
                            true.into(),
                            Some("com.apple.mobile.wireless_lockdown"),
                        )
                        .await
                    {
                        gui_sender
                            .send(GuiCommands::EnableWirelessFailure(e))
                            .unwrap();
                    } else {
                        gui_sender.send(GuiCommands::EnabledWireless).unwrap();
                    }
                }
                IdeviceCommands::CheckDevMode(dev) => {
                    // Connect to usbmuxd
                    let mut uc = match UsbmuxdConnection::default().await {
                        Ok(u) => u,
                        Err(e) => {
                            gui_sender.send(GuiCommands::NoUsbmuxd(e)).unwrap();
                            continue;
                        }
                    };

                    let p = dev.to_provider(UsbmuxdAddr::default(), "idevice_pair");
                    let pairing_file = match uc.get_pair_record(&p.udid).await {
                        Ok(p) => p,
                        Err(e) => {
                            gui_sender.send(GuiCommands::DevMode(Err(e))).unwrap();
                            continue;
                        }
                    };

                    let mut lc = match LockdownClient::connect(&p).await {
                        Ok(l) => l,
                        Err(e) => {
                            gui_sender.send(GuiCommands::DevMode(Err(e))).unwrap();
                            continue;
                        }
                    };

                    if let Err(e) = lc.start_session(&pairing_file).await {
                        gui_sender.send(GuiCommands::DevMode(Err(e))).unwrap();
                        continue;
                    }

                    let v = match lc
                        .get_value(
                            Some("DeveloperModeStatus"),
                            Some("com.apple.security.mac.amfi"),
                        )
                        .await
                    {
                        Ok(v) => v,
                        Err(e) => {
                            gui_sender.send(GuiCommands::DevMode(Err(e))).unwrap();
                            continue;
                        }
                    };

                    match v.as_boolean() {
                        Some(b) => {
                            gui_sender.send(GuiCommands::DevMode(Ok(b))).unwrap();
                            continue;
                        }
                        None => {
                            gui_sender
                                .send(GuiCommands::DevMode(Err(IdeviceError::UnexpectedResponse)))
                                .unwrap();
                            continue;
                        }
                    }
                }
                IdeviceCommands::AutoMount(dev) => match mount::auto_mount(dev).await {
                    Ok(_) => gui_sender.send(GuiCommands::MountRes(Ok(()))).unwrap(),
                    Err(e) => gui_sender.send(GuiCommands::MountRes(Err(e))).unwrap(),
                },
                IdeviceCommands::LoadPairingFile(dev) => {
                    // Connect to usbmuxd
                    let mut uc = match UsbmuxdConnection::default().await {
                        Ok(u) => u,
                        Err(e) => {
                            gui_sender.send(GuiCommands::NoUsbmuxd(e)).unwrap();
                            continue;
                        }
                    };

                    let mut pairing_file = match uc.get_pair_record(&dev.udid).await {
                        Ok(p) => p,
                        Err(e) => {
                            gui_sender.send(GuiCommands::PairingFile(Err(e))).unwrap();
                            continue;
                        }
                    };
                    pairing_file.udid = Some(dev.udid);

                    gui_sender
                        .send(GuiCommands::PairingFile(Ok(PairingPayload::Lockdown(
                            pairing_file,
                        ))))
                        .unwrap();
                }
                IdeviceCommands::GeneratePairingFile((dev, pairing_mode)) => {
                    match pairing_mode {
                        PairingMode::Lockdown => {
                            // Connect to usbmuxd
                            let mut uc = match UsbmuxdConnection::default().await {
                                Ok(u) => u,
                                Err(e) => {
                                    gui_sender.send(GuiCommands::NoUsbmuxd(e)).unwrap();
                                    continue;
                                }
                            };

                            let p = dev.to_provider(UsbmuxdAddr::default(), "idevice_pair");

                            let mut lc = match LockdownClient::connect(&p).await {
                                Ok(l) => l,
                                Err(e) => {
                                    gui_sender.send(GuiCommands::PairingFile(Err(e))).unwrap();
                                    continue;
                                }
                            };

                            let buid = match uc.get_buid().await {
                                Ok(b) => b,
                                Err(e) => {
                                    gui_sender.send(GuiCommands::PairingFile(Err(e))).unwrap();
                                    continue;
                                }
                            };

                            // Modify it slightly so iOS doesn't invalidate the one connected right now.
                            let mut buid: Vec<char> = buid.chars().collect();
                            buid[0] = if buid[0] == 'F' { 'A' } else { 'F' };
                            let buid: String = buid.into_iter().collect();

                            let id = uuid::Uuid::new_v4().to_string().to_uppercase();
                            let mut pairing_file = match lc.pair(id, buid, None).await {
                                Ok(p) => p,
                                Err(e) => {
                                    gui_sender.send(GuiCommands::PairingFile(Err(e))).unwrap();
                                    continue;
                                }
                            };

                            pairing_file.udid = Some(dev.udid.clone());

                            gui_sender
                                .send(GuiCommands::PairingFile(Ok(PairingPayload::Lockdown(
                                    pairing_file,
                                ))))
                                .unwrap();
                        }
                        PairingMode::RemotePairing => {
                            let provider = dev.to_provider(UsbmuxdAddr::default(), "idevice_pair");
                            let hostname = pairing_hostname();
                            let res = std::panic::AssertUnwindSafe(generate_remote_pairing_file(
                                &provider,
                                &hostname,
                                &gui_sender,
                            ))
                            .catch_unwind()
                            .await;

                            match res {
                                Ok(Ok(pairing_file)) => {
                                    gui_sender
                                        .send(GuiCommands::PairingFile(Ok(PairingPayload::Remote(
                                            pairing_file,
                                        ))))
                                        .unwrap();
                                }
                                Ok(Err(e)) => {
                                    gui_sender.send(GuiCommands::PairingFile(Err(e))).unwrap();
                                }
                                Err(_) => {
                                    gui_sender
                                        .send(GuiCommands::PairingFile(Err(
                                            IdeviceError::InternalError(
                                                "RPPairing generation failed unexpectedly"
                                                    .to_string(),
                                            ),
                                        )))
                                        .unwrap();
                                }
                            }
                        }
                    }
                }
                IdeviceCommands::Validate((ip, pairing_file)) => {
                    let ip: IpAddr = match ip {
                        Some(i) => i,
                        None => {
                            if let Some(ip) = discovered_devices.get(&pairing_file.wifi_mac_address)
                            {
                                *ip
                            } else {
                                gui_sender
                                    .send(GuiCommands::Validated(Err(IdeviceError::DeviceNotFound)))
                                    .unwrap();
                                continue;
                            }
                        }
                    };

                    let stream =
                        match tokio::net::TcpStream::connect(SocketAddr::new(ip, 62078)).await {
                            Ok(s) => s,
                            Err(e) => {
                                gui_sender
                                    .send(GuiCommands::Validated(Err(IdeviceError::Socket(e))))
                                    .unwrap();
                                continue;
                            }
                        };

                    let mut lc =
                        LockdownClient::new(Idevice::new(Box::new(stream), "idevice_pair"));
                    match lc.start_session(&pairing_file).await {
                        Ok(_) => gui_sender.send(GuiCommands::Validated(Ok(()))).unwrap(),
                        Err(e) => gui_sender.send(GuiCommands::Validated(Err(e))).unwrap(),
                    }
                }
                IdeviceCommands::ValidateRemote((dev, mut pairing_file)) => {
                    let provider = dev.to_provider(UsbmuxdAddr::default(), "idevice_pair");

                    let res = std::panic::AssertUnwindSafe(async {
                        let proxy = CoreDeviceProxy::connect(&provider).await?;
                        let rsd_port = proxy.tunnel_info().server_rsd_port;
                        let adapter = proxy.create_software_tunnel()?;
                        let mut adapter = adapter.to_async_handle();

                        let rsd_stream = adapter.connect(rsd_port).await?;
                        let handshake = RsdHandshake::new(rsd_stream).await?;
                        let tunnel_service = handshake
                            .services
                            .get("com.apple.internal.dt.coredevice.untrusted.tunnelservice")
                            .ok_or_else(|| {
                                IdeviceError::InternalError(
                                    "Untrusted tunnel service not found".into(),
                                )
                            })?;

                        let ts_stream = adapter.connect(tunnel_service.port).await?;
                        let mut conn = RemoteXpcClient::new(ts_stream).await?;
                        conn.do_handshake().await?;
                        let _ = conn.recv_root().await;

                        let hostname = pairing_hostname();
                        let mut rpc = RemotePairingClient::new(conn, &hostname, &mut pairing_file);
                        let _ = rpc.attempt_pair_verify().await?;
                        rpc.validate_pairing().await
                    })
                    .catch_unwind()
                    .await;

                    match res {
                        Ok(Ok(())) => gui_sender.send(GuiCommands::Validated(Ok(()))).unwrap(),
                        Ok(Err(e)) => gui_sender.send(GuiCommands::Validated(Err(e))).unwrap(),
                        Err(_) => gui_sender
                            .send(GuiCommands::Validated(Err(IdeviceError::InternalError(
                                "RPPairing validation failed unexpectedly".to_string(),
                            ))))
                            .unwrap(),
                    }
                }
                IdeviceCommands::InstalledApps((dev, desired_apps)) => {
                    let p = dev.to_provider(UsbmuxdAddr::default(), "idevice_pair");
                    let mut ic = match InstallationProxyClient::connect(&p).await {
                        Ok(i) => i,
                        Err(e) => {
                            gui_sender.send(GuiCommands::InstalledApps(Err(e))).unwrap();
                            continue;
                        }
                    };
                    let installed_apps = match ic.get_apps(Some("User"), None).await {
                        Ok(a) => a,
                        Err(e) => {
                            gui_sender.send(GuiCommands::InstalledApps(Err(e))).unwrap();
                            continue;
                        }
                    };

                    let mut installed = HashMap::new();
                    for (bundle_id, app) in installed_apps {
                        match app
                            .as_dictionary()
                            .and_then(|x| x.get("CFBundleDisplayName").and_then(|x| x.as_string()))
                        {
                            Some(n) => {
                                let app_name = if n == "StikDebug"
                                    && bundle_id != STIKDEBUG_APPSTORE_BUNDLE_ID
                                {
                                    "StikDebug (Sideloaded)"
                                } else {
                                    n
                                };

                                if desired_apps.iter().any(|app| app == app_name) {
                                    installed.insert(app_name.to_string(), bundle_id);
                                }
                            }
                            None => {
                                gui_sender
                                    .send(GuiCommands::InstalledApps(Err(
                                        IdeviceError::UnexpectedResponse,
                                    )))
                                    .unwrap();
                                continue 'main;
                            }
                        };
                    }
                    gui_sender
                        .send(GuiCommands::InstalledApps(Ok(installed)))
                        .unwrap();
                }
                IdeviceCommands::InstallPairingFile((dev, name, bundle_id, path, pairing_file)) => {
                    let p = dev.to_provider(UsbmuxdAddr::default(), "idevice_pair");
                    let hc = match HouseArrestClient::connect(&p).await {
                        Ok(h) => h,
                        Err(e) => {
                            gui_sender
                                .send(GuiCommands::InstallPairingFile((name, Err(e))))
                                .unwrap();
                            continue;
                        }
                    };

                    let mut ac = match hc.vend_documents(bundle_id).await {
                        Ok(a) => a,
                        Err(e) => {
                            gui_sender
                                .send(GuiCommands::InstallPairingFile((name, Err(e))))
                                .unwrap();
                            continue;
                        }
                    };

                    let mut f = match ac
                        .open(
                            format!("/Documents/{path}"),
                            idevice::afc::opcode::AfcFopenMode::Wr,
                        )
                        .await
                    {
                        Ok(f) => f,
                        Err(e) => {
                            gui_sender
                                .send(GuiCommands::InstallPairingFile((name, Err(e))))
                                .unwrap();
                            continue;
                        }
                    };

                    match f.write(&pairing_file).await {
                        Ok(_) => {
                            gui_sender
                                .send(GuiCommands::InstallPairingFile((name, Ok(()))))
                                .unwrap();
                            continue;
                        }
                        Err(e) => {
                            gui_sender
                                .send(GuiCommands::InstallPairingFile((
                                    name,
                                    Err(IdeviceError::Socket(e)),
                                )))
                                .unwrap();
                            continue;
                        }
                    }
                }
                IdeviceCommands::DiscoveredDevice((ip, mac)) => {
                    discovered_devices.insert(mac, ip);
                }
                IdeviceCommands::GetDeviceInfo(dev) => {
                    let p = dev.to_provider(UsbmuxdAddr::default(), "idevice_pair");
                    let mut lc = match LockdownClient::connect(&p).await {
                        Ok(l) => l,
                        Err(e) => {
                            error!("Failed to connect to lockdown: {e:?}");
                            continue;
                        }
                    };

                    let values = match lc.get_value(None, None).await {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Failed to get lockdown values: {e:?}");
                            continue;
                        }
                    };

                    let values = match values.as_dictionary() {
                        Some(v) => v,
                        None => {
                            error!("Values was not a dictionary");
                            continue;
                        }
                    };

                    let mut device_info: Vec<(String, String)> = Vec::with_capacity(5);

                    // Fixed order of fields in reverse order
                    let fields = [
                        ("device_name", "DeviceName"),
                        ("model", "ProductType"),
                        ("ios_version", "ProductVersion"),
                        ("build_number", "BuildVersion"),
                        ("udid", "UniqueDeviceID"),
                    ];

                    for (key_id, lockdown_key) in fields.iter() {
                        if let Some(plist::Value::String(value)) = values.get(*lockdown_key) {
                            device_info.push((key_id.to_string(), value.clone()));
                        }
                    }

                    gui_sender
                        .send(GuiCommands::DeviceInfo(device_info))
                        .unwrap();
                }
            };
        }
        eprintln!("Exited idevice loop!!");
    });

    eframe::run_native(
        &format!("idevice pair v{}", env!("CARGO_PKG_VERSION")),
        options,
        Box::new(|cc| {
            setup_custom_fonts(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    )
    .unwrap();
}

enum GuiCommands {
    NoUsbmuxd(IdeviceError),
    GetDevicesFailure(IdeviceError),
    Devices(HashMap<String, UsbmuxdDevice>),
    DeviceInfo(Vec<(String, String)>),
    EnabledWireless,
    EnableWirelessFailure(IdeviceError),
    DevMode(Result<bool, IdeviceError>),
    MountRes(Result<(), IdeviceError>),
    PairingStatus(String),
    PairingFile(Result<PairingPayload, IdeviceError>),
    Validated(Result<(), IdeviceError>),
    InstalledApps(Result<HashMap<String, String>, IdeviceError>),
    InstallPairingFile((String, Result<(), IdeviceError>)), // name
}

enum IdeviceCommands {
    GetDevices,
    EnableWireless(UsbmuxdDevice),
    CheckDevMode(UsbmuxdDevice),
    AutoMount(UsbmuxdDevice),
    LoadPairingFile(UsbmuxdDevice),
    GeneratePairingFile((UsbmuxdDevice, PairingMode)),
    GetDeviceInfo(UsbmuxdDevice),
    Validate((Option<IpAddr>, PairingFile)),
    ValidateRemote((UsbmuxdDevice, RpPairingFile)),
    InstalledApps((UsbmuxdDevice, Vec<String>)),
    InstallPairingFile((UsbmuxdDevice, String, String, String, Vec<u8>)), // dev, name, b_id, install path, bytes
    DiscoveredDevice((IpAddr, String)),                                   // ip, mac
}

struct MyApp {
    // Selector
    devices: Option<HashMap<String, UsbmuxdDevice>>,
    devices_placeholder: String,
    selected_device: String,
    pairing_mode: PairingMode,
    // Device details
    device_info: Option<Vec<(String, String)>>,

    // Device info
    wireless_enabled: Option<Result<(), IdeviceError>>,
    dev_mode_enabled: Option<Result<bool, IdeviceError>>,
    ddi_mounted: Option<Result<(), IdeviceError>>,

    // Pairing info
    pairing_file: Option<PairingPayload>,
    pairing_file_string: Option<String>,
    pairing_file_message: Option<String>,

    // Save
    save_error: Option<String>,
    installed_apps: Option<Result<HashMap<String, String>, IdeviceError>>,
    lockdown_supported_apps: HashMap<String, String>, // name, path to save pairing file to
    remote_supported_apps: HashMap<String, String>,   // name, path to save pairing file to
    install_res: HashMap<String, Option<Result<(), IdeviceError>>>,

    // Validation
    validate_res: Option<Result<(), String>>,
    validating: bool,
    validation_ip_input: String,

    // Channel
    gui_recv: UnboundedReceiver<GuiCommands>,
    idevice_sender: UnboundedSender<IdeviceCommands>,

    show_logs: bool,
}

impl MyApp {
    fn supported_apps(&self) -> &HashMap<String, String> {
        match self.pairing_mode {
            PairingMode::Lockdown => &self.lockdown_supported_apps,
            PairingMode::RemotePairing => &self.remote_supported_apps,
        }
    }

    fn supported_app_names(&self) -> Vec<String> {
        self.supported_apps().keys().cloned().collect()
    }

    fn reset_pairing_state(&mut self) {
        self.pairing_file = None;
        self.pairing_file_message = None;
        self.pairing_file_string = None;
        self.save_error = None;
        self.installed_apps = None;
        self.install_res.clear();
        self.validating = false;
        self.validate_res = None;
        self.validation_ip_input.clear();
    }

    fn save_pairing_file(&mut self, default_name: &str) {
        if let Some(path) = FileDialog::new()
            .set_can_create_directories(true)
            .set_title(t!("save_to_file"))
            .set_file_name(default_name)
            .save_file()
        {
            self.save_error = None;
            match self.pairing_file.as_ref() {
                Some(pairing_file) => match pairing_file.bytes() {
                    Ok(bytes) => {
                        if let Err(e) = std::fs::write(path, bytes) {
                            self.save_error = Some(e.to_string());
                        }
                    }
                    Err(e) => self.save_error = Some(e.to_string()),
                },
                None => self.save_error = Some("No pairing file loaded".to_string()),
            }
        }
    }

    fn refresh_device_state(&mut self, dev: UsbmuxdDevice) {
        self.wireless_enabled = None;
        self.dev_mode_enabled = None;
        self.ddi_mounted = None;
        self.device_info = None;

        let dev_clone = dev.clone();
        self.idevice_sender
            .send(IdeviceCommands::EnableWireless(dev_clone.clone()))
            .unwrap();
        self.idevice_sender
            .send(IdeviceCommands::CheckDevMode(dev_clone.clone()))
            .unwrap();
        self.idevice_sender
            .send(IdeviceCommands::AutoMount(dev_clone.clone()))
            .unwrap();
        self.idevice_sender
            .send(IdeviceCommands::GetDeviceInfo(dev_clone))
            .unwrap();

        self.reset_pairing_state();
        self.idevice_sender
            .send(IdeviceCommands::InstalledApps((
                dev,
                self.supported_app_names(),
            )))
            .unwrap();
    }

    fn select_device(&mut self, device_name: String, dev: UsbmuxdDevice) {
        self.selected_device = device_name;
        self.refresh_device_state(dev);
    }

    fn push_pairing_status(&mut self, status: String) {
        self.pairing_file_message = Some(status);
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Get updates from the idevice thread
        match self.gui_recv.try_recv() {
            Ok(msg) => match msg {
                GuiCommands::NoUsbmuxd(idevice_error) => {
                    let install_msg = if cfg!(windows) {
                        t!("itunes_help")
                    } else if cfg!(target_os = "macos") {
                        t!("macos_usbmuxd_help")
                    } else {
                        t!("linux_usbmuxd_help")
                    };

                    self.devices_placeholder = format!(
                        "{} {install_msg}\n\n{idevice_error:#?}",
                        t!("no_usbmuxd")
                    );
                }
                GuiCommands::Devices(vec) => {
                    self.devices = Some(vec);
                    if self.selected_device.is_empty()
                        || (self
                            .devices
                            .as_ref()
                            .is_none_or(|devs| !devs.contains_key(&self.selected_device)))
                    {
                        if let Some(devs) = self.devices.as_ref()
                            && devs.len() == 1
                        {
                            let (dev_name, dev) = devs.iter().next().unwrap();
                            self.select_device(dev_name.clone(), dev.clone());
                        }
                    }
                }
                GuiCommands::DeviceInfo(info) => self.device_info = Some(info),
                GuiCommands::GetDevicesFailure(idevice_error) => {
                    self.devices_placeholder = t!("get_devices_failure", error = format!("{idevice_error:?}")).to_string();
                }
                GuiCommands::EnabledWireless => self.wireless_enabled = Some(Ok(())),
                GuiCommands::EnableWirelessFailure(idevice_error) => {
                    self.wireless_enabled = Some(Err(idevice_error))
                }
                GuiCommands::DevMode(res) => {
                    self.dev_mode_enabled = Some(res);
                }
                GuiCommands::MountRes(res) => {
                    self.ddi_mounted = Some(res);
                }
                GuiCommands::PairingStatus(status) => {
                    self.push_pairing_status(status);
                }
                GuiCommands::PairingFile(pairing_file) => match pairing_file {
                    Ok(p) => {
                        self.pairing_file = Some(p.clone());
                        self.pairing_file_message = None;
                        self.pairing_file_string = match p.display_string() {
                            Ok(serialized) => Some(serialized),
                            Err(e) => {
                                self.pairing_file_message = Some(e.to_string());
                                None
                            }
                        };
                    }
                    Err(e) => {
                        self.pairing_file = None;
                        self.pairing_file_string = None;
                        self.pairing_file_message = Some(e.to_string());
                    }
                },
                GuiCommands::Validated(res) => match res {
                    Ok(()) => self.validate_res = Some(Ok(())),
                    Err(e) => self.validate_res = Some(Err(e.to_string())),
                },
                GuiCommands::InstalledApps(apps) => self.installed_apps = Some(apps),
                GuiCommands::InstallPairingFile((name, res)) => {
                    let pairing_file_message = match &res {
                        Ok(()) => t!("install_success", name = name.clone()).to_string(),
                        Err(e) => t!("install_failed", name = name.clone(), error = e.to_string()).to_string(),
                    };
                    if let Some(v) = self.install_res.get_mut(&name) {
                        *v = Some(res);
                    }
                    self.pairing_file_message = Some(pairing_file_message);
                }
            },
            Err(e) => match e {
                tokio::sync::mpsc::error::TryRecvError::Empty => {}
                tokio::sync::mpsc::error::TryRecvError::Disconnected => {
                    self.devices_placeholder = t!("backend_disconnected").to_string();
                    if self.pairing_file_message.is_none() {
                        self.pairing_file_message =
                            Some(t!("backend_disconnected").to_string());
                    }
                }
            },
        }
        if self.show_logs {
            egui::Window::new(t!("logs"))
                .open(&mut self.show_logs)
                .show(ctx, |ui| {
                    egui_logger::logger_ui()
                        .warn_color(Color32::BLACK) // the yellow is too bright in dark mode
                        .log_levels([true, true, true, true, false])
                        .enable_category("idevice".to_string(), true)
                        // there should be a way to set default false...
                        .enable_category("mdns::mdns".to_string(), false)
                        .enable_category("eframe".to_string(), false)
                        .enable_category("eframe::native::glow_integration".to_string(), false)
                        .enable_category("egui_glow::shader_version".to_string(), false)
                        .enable_category("egui_glow::vao".to_string(), false)
                        .enable_category("egui_glow::painter".to_string(), false)
                        .enable_category("rustls::client::hs".to_string(), false)
                        .enable_category("rustls::client::tls12".to_string(), false)
                        .enable_category("rustls::client::common".to_string(), false)
                        .enable_category("idevice_pair::discover".to_string(), false)
                        .enable_category("reqwest::connect".to_string(), false)
                        .show(ui);
                });
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(t!("app_title"));
                    ui.separator();
                    let p_background_color = match ctx.theme() {
                        egui::Theme::Dark => Color32::BLACK,
                        egui::Theme::Light => Color32::LIGHT_GRAY,
                    };
                    egui::frame::Frame::new().corner_radius(3).inner_margin(3).fill(p_background_color).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.toggle_value(&mut self.show_logs, t!("logs"));
                            ui.separator();
                            let current_locale = rust_i18n::locale();
                            ComboBox::from_id_salt("lang_selector")
                                .selected_text(t!("_language_name"))
                                .show_ui(ui, |ui| {
                                    for locale in rust_i18n::available_locales!() {
                                        let label = t!("_language_name", locale = locale);
                                        if ui.selectable_label(&*current_locale == locale, label).clicked() {
                                            rust_i18n::set_locale(locale);
                                        }
                                    }
                                });
                        });
                    });
                });
                let mut pending_selection: Option<(String, UsbmuxdDevice)> = None;
                match self.devices.as_ref() {
                    Some(devs) => {
                        if devs.is_empty() {
                            ui.label(t!("no_devices"));
                        } else {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(t!("choose_device"));
                                    ComboBox::from_label("")
                                        .selected_text(&self.selected_device)
                                        .show_ui(ui, |ui| {
                                            for (dev_name, dev) in devs {
                                                if ui
                                                    .selectable_value(
                                                        &mut self.selected_device,
                                                        dev_name.clone(),
                                                        dev_name.clone(),
                                                    )
                                                    .clicked()
                                                {
                                                    pending_selection =
                                                        Some((dev_name.clone(), dev.clone()));
                                                };
                                            }
                                        });
                                });

                                ui.separator();

                                // Show device info to the right if available
                                if let Some(info) = &self.device_info {
                                    ui.vertical(|ui| {
                                        for (key, value) in info {
                                            ui.horizontal(|ui| {
                                                ui.label(format!("{}:", t!(key.as_str())));
                                                ui.label(value);
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    }
                    None => {
                        ui.label(&self.devices_placeholder);
                    }
                }
                if let Some((dev_name, dev)) = pending_selection {
                    self.select_device(dev_name, dev);
                }

                ui.separator();

                let selected_device = self
                    .devices
                    .as_ref()
                    .and_then(|x| x.get(&self.selected_device))
                    .cloned();
                if let Some(dev) = selected_device {
                    let mut pairing_mode_changed = false;
                    ui.horizontal(|ui| {
                        ui.label(t!("pairing_type"));
                        pairing_mode_changed |= ui
                            .radio_value(
                                &mut self.pairing_mode,
                                PairingMode::Lockdown,
                                t!("lockdown"),
                            )
                            .changed();
                        pairing_mode_changed |= ui
                            .radio_value(
                                &mut self.pairing_mode,
                                PairingMode::RemotePairing,
                                t!("rp_pairing"),
                            )
                            .changed();
                    });
                    if pairing_mode_changed {
                        self.reset_pairing_state();
                        self.idevice_sender
                            .send(IdeviceCommands::InstalledApps((
                                dev.clone(),
                                self.supported_app_names(),
                            )))
                            .unwrap();
                    }

                    ui.horizontal(|ui| {
                        ui.label(t!("wireless_debugging"));
                        match &self.wireless_enabled {
                            Some(Ok(_)) => ui.label(RichText::new(t!("enabled")).color(Color32::GREEN)),
                            Some(Err(e)) => ui
                                .label(RichText::new(format!("{}: {e:?}", t!("failed"))).color(Color32::RED)),
                            None => ui.label(t!("loading")),
                        };
                    });
                    ui.horizontal(|ui| {
                        ui.label(t!("developer_mode"));
                        match &self.dev_mode_enabled {
                            Some(Ok(true)) => {
                                ui.label(RichText::new(t!("enabled")).color(Color32::GREEN))
                            }
                            Some(Ok(false)) => {
                                ui.label(RichText::new(t!("disabled")).color(Color32::RED))
                            }
                            Some(Err(e)) => ui
                                .label(RichText::new(format!("{}: {e:?}", t!("failed"))).color(Color32::RED)),
                            None => ui.label(t!("loading")),
                        };
                    });
                    ui.horizontal(|ui| {
                        ui.label(t!("ddi_image"));
                        match &self.ddi_mounted {
                            Some(Ok(_)) => {
                                ui.label(RichText::new(t!("mounted")).color(Color32::GREEN))
                            }
                            Some(Err(e)) => ui
                                .label(RichText::new(format!("{}: {e:?}", t!("failed"))).color(Color32::RED)),
                            None => ui.label(t!("loading")),
                        };
                    });

                    // How to load a file
                    ui.separator();
                    ui.horizontal(|ui| {
                        if self.pairing_mode == PairingMode::Lockdown {
                            ui.vertical(|ui| {
                                ui.heading(t!("load"));
                                ui.label(t!("load_help"));
                                if ui.button(t!("load")).clicked() {
                                    #[cfg(not(feature = "generate"))]
                                    {
                                        let shift_down = ui.input(|i| i.modifiers.shift);
                                        if shift_down && self.pairing_file.is_some() {
                                            let file_name =
                                                self.pairing_mode.default_file_name(&dev.udid);
                                            self.save_pairing_file(&file_name);
                                        } else {
                                            self.pairing_file = None;
                                            self.pairing_file_message =
                                                Some(t!("loading").to_string());
                                            self.pairing_file_string = None;
                                            self.save_error = None;
                                            self.idevice_sender
                                                .send(IdeviceCommands::LoadPairingFile(
                                                    dev.clone(),
                                                ))
                                                .unwrap();
                                        }
                                    }
                                    #[cfg(feature = "generate")]
                                    {
                                        self.pairing_file_message = Some(t!("loading").to_string());
                                        self.pairing_file_string = None;
                                        self.idevice_sender
                                            .send(IdeviceCommands::LoadPairingFile(dev.clone()))
                                            .unwrap();
                                    }
                                }
                            });
                            ui.separator();
                        }
                        let show_generate = match self.pairing_mode {
                            PairingMode::RemotePairing => true,
                            PairingMode::Lockdown => cfg!(feature = "generate"),
                        };
                        if show_generate {
                            ui.vertical(|ui| {
                                ui.heading(t!("generate"));
                                match self.pairing_mode {
                                    PairingMode::Lockdown => {
                                        ui.label(t!("generate_lockdown_help"));
                                    }
                                    PairingMode::RemotePairing => {
                                        ui.label(t!("generate_rp_help"));
                                    }
                                }
                                if ui.button(t!("generate")).clicked() {
                                    self.pairing_file = None;
                                    self.pairing_file_message = Some(t!("loading").to_string());
                                    self.pairing_file_string = None;
                                    self.save_error = None;
                                    self.idevice_sender
                                        .send(IdeviceCommands::GeneratePairingFile((
                                            dev.clone(),
                                            self.pairing_mode,
                                        )))
                                        .unwrap();
                                }
                            });
                        }
                    });
                    if let Some(msg) = &self.pairing_file_message {
                        ui.label(msg);
                    }

                    ui.separator();

                    let pairing_file_text = self.pairing_file_string.clone();
                    let supported_apps = self.supported_apps().clone();
                    let installed_apps = self
                        .installed_apps
                        .as_ref()
                        .and_then(|apps| apps.as_ref().ok())
                        .map(|apps| {
                            apps.iter()
                                .map(|(name, bundle_id)| (name.clone(), bundle_id.clone()))
                                .collect::<Vec<_>>()
                        });
                    let installed_apps_error = self
                        .installed_apps
                        .as_ref()
                        .and_then(|apps| apps.as_ref().err())
                        .map(|e| e.to_string());

                    if let Some(pairing_file) = pairing_file_text {
                        egui::Grid::new("reee").min_col_width(200.0).show(ui, |ui| {
                            ui.vertical(|ui| {
                                #[cfg(feature = "generate")]
                                {
                                    ui.heading(t!("save_to_file"));
                                    if let Some(msg) = &self.save_error {
                                        ui.label(RichText::new(msg).color(Color32::RED));
                                    }
                                    ui.label(t!("save_to_file_help"));
                                    if ui.button(t!("save_to_file")).clicked() {
                                        let file_name =
                                            self.pairing_mode.default_file_name(&dev.udid);
                                        self.save_pairing_file(&file_name);
                                    }

                                    ui.separator();
                                }
                                if self.pairing_mode == PairingMode::Lockdown {
                                    ui.heading(t!("validation"));
                                    ui.label(t!("validate_lan_help"));
                                    ui.add(egui::TextEdit::singleline(&mut self.validation_ip_input).hint_text(t!("validate_ip_hint")));
                                    if ui.button(t!("validate")).clicked() {
                                        self.validating = true;
                                        self.validate_res = None;
                                        if let Some(pairing_file) = self
                                            .pairing_file
                                            .as_ref()
                                            .and_then(PairingPayload::as_lockdown)
                                        {
                                            if self.validation_ip_input.is_empty() {
                                                self.idevice_sender
                                                    .send(IdeviceCommands::Validate((
                                                        None,
                                                        pairing_file,
                                                    )))
                                                    .unwrap()
                                            } else {
                                                match IpAddr::from_str(
                                                    self.validation_ip_input.as_str(),
                                                ) {
                                                    Ok(i) => {
                                                        self.idevice_sender
                                                            .send(IdeviceCommands::Validate((
                                                                Some(i),
                                                                pairing_file,
                                                            )))
                                                            .unwrap()
                                                    }
                                                    Err(_) => {
                                                        self.validate_res =
                                                            Some(Err(t!("invalid_ip").to_string()))
                                                    }
                                                };
                                            }
                                        } else {
                                            self.validate_res = Some(Err(
                                                t!("validate_only_lockdown").to_string(),
                                            ));
                                        }
                                    }
                                    if self.validating {
                                        match &self.validate_res {
                                            Some(Ok(_)) => ui.label(
                                                RichText::new(t!("validation_success")).color(Color32::GREEN),
                                            ),
                                            Some(Err(e)) => {
                                                ui.label(RichText::new(e).color(Color32::RED))
                                            }
                                            None => ui.label(t!("loading")),
                                        };
                                    }
                                } else {
                                    ui.heading(t!("validation"));
                                    ui.label(t!("validate_usb_help"));
                                    if ui.button(t!("validate")).clicked() {
                                        #[cfg(not(feature = "generate"))]
                                        if ui.input(|i| i.modifiers.shift)
                                            && self.pairing_file.is_some()
                                        {
                                            let file_name =
                                                self.pairing_mode.default_file_name(&dev.udid);
                                            self.save_pairing_file(&file_name);
                                        } else {
                                            self.validating = true;
                                            self.validate_res = None;
                                            if let Some(PairingPayload::Remote(pairing_file)) =
                                                self.pairing_file.as_ref()
                                            {
                                                self.idevice_sender
                                                    .send(IdeviceCommands::ValidateRemote((
                                                        dev.clone(),
                                                        pairing_file.clone(),
                                                    )))
                                                    .unwrap();
                                            } else {
                                                self.validate_res = Some(Err(
                                                    t!("validate_requires_rp").to_string(),
                                                ));
                                            }
                                        }
                                        #[cfg(feature = "generate")]
                                        {
                                            self.validating = true;
                                            self.validate_res = None;
                                            if let Some(PairingPayload::Remote(pairing_file)) =
                                                self.pairing_file.as_ref()
                                            {
                                                self.idevice_sender
                                                    .send(IdeviceCommands::ValidateRemote((
                                                        dev.clone(),
                                                        pairing_file.clone(),
                                                    )))
                                                    .unwrap();
                                            } else {
                                                self.validate_res = Some(Err(
                                                    t!("validate_requires_rp").to_string(),
                                                ));
                                            }
                                        }
                                    }
                                    if self.validating {
                                        match &self.validate_res {
                                            Some(Ok(_)) => ui.label(
                                                RichText::new(t!("validation_success")).color(Color32::GREEN),
                                            ),
                                            Some(Err(e)) => {
                                                ui.label(RichText::new(e).color(Color32::RED))
                                            }
                                            None => ui.label(t!("loading")),
                                        };
                                    }
                                }

                                match &installed_apps {
                                    Some(apps) => {
                                        for (name, bundle_id) in apps {
                                            ui.separator();
                                            ui.heading(name);
                                            ui.label(RichText::new(bundle_id).italics().weak());
                                            ui.label(t!("app_install_help", name = name.clone()));
                                            if ui.button(t!("install")).clicked() {
                                                if let Some(pairing_file) = &self.pairing_file {
                                                    match pairing_file.bytes() {
                                                        Ok(bytes) => {
                                                            self.idevice_sender
                                                                .send(IdeviceCommands::InstallPairingFile((
                                                                    dev.clone(),
                                                                    name.clone(),
                                                                    bundle_id.clone(),
                                                                    supported_apps
                                                                        .get(name)
                                                                        .unwrap()
                                                                        .to_owned(),
                                                                    bytes,
                                                                )))
                                                                .unwrap();
                                                            self.install_res
                                                                .insert(name.to_owned(), None);
                                                            self.pairing_file_message = Some(
                                                                t!("install_sending", name = name.clone()).to_string(),
                                                            );
                                                        }
                                                        Err(e) => {
                                                            self.install_res.insert(
                                                                name.to_owned(),
                                                                Some(Err(e)),
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            if let Some(v) = self.install_res.get(name) {
                                                match v {
                                                    Some(Ok(_)) => ui
                                                        .label(RichText::new(t!("validation_success")).color(Color32::GREEN)),
                                                    Some(Err(e)) => ui
                                                        .label(RichText::new(e.to_string()).color(Color32::RED)),
                                                    None => ui.label(t!("installing")),
                                                };
                                            }
                                        }
                                    }
                                    None if installed_apps_error.is_some() => {
                                        if let Some(error) = &installed_apps_error {
                                            ui.label(
                                                RichText::new(t!("failed_getting_apps", error = error.clone()))
                                                .color(Color32::RED),
                                            );
                                        }
                                    }
                                    None => {
                                        ui.label(t!("getting_apps"));
                                    }
                                }
                            });
                            let p_background_color = match ctx.theme() {
                                egui::Theme::Dark => Color32::BLACK,
                                egui::Theme::Light => Color32::LIGHT_GRAY,
                            };
                            egui::frame::Frame::new().corner_radius(10).inner_margin(10).fill(p_background_color).show(ui, |ui| {
                                ui.label(RichText::new(&pairing_file).monospace());
                            });
                        });
                    }
                }
            });
        });
    }
}
