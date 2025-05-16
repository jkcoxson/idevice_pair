// Jackson Coxson
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use egui::{Color32, ComboBox, RichText};
use log::error;
use tokio::sync::mpsc::unbounded_channel;

use idevice::{
    Idevice, IdeviceError, IdeviceService,
    house_arrest::HouseArrestClient,
    installation_proxy::InstallationProxyClient,
    lockdown::LockdownClient,
    pairing_file::PairingFile,
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection, UsbmuxdDevice},
};
use rfd::FileDialog;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

mod discover;
mod mount;

fn main() {
    println!("Startup");
    egui_logger::builder().init().unwrap();
    let (gui_sender, gui_recv) = unbounded_channel();
    let (idevice_sender, mut idevice_receiver) = unbounded_channel();
    idevice_sender.send(IdeviceCommands::GetDevices).unwrap();

    let mut supported_apps = HashMap::new();
    supported_apps.insert(
        "SideStore".to_string(),
        "ALTPairingFile.mobiledevicepairing".to_string(),
    );
    supported_apps.insert("Feather".to_string(), "pairingFile.plist".to_string());
    supported_apps.insert("StikDebug".to_string(), "pairingFile.plist".to_string());

    let app = MyApp {
        devices: None,
        devices_placeholder: "Loading...".to_string(),
        selected_device: "".to_string(),
        wireless_enabled: None,
        dev_mode_enabled: None,
        ddi_mounted: None,
        pairing_file: None,
        pairing_file_message: None,
        pairing_file_string: None,
        save_error: None,
        installed_apps: None,
        install_res: HashMap::new(),
        supported_apps,
        validate_res: None,
        validating: false,
        validation_ip_input: "".to_string(),
        gui_recv,
        idevice_sender: idevice_sender.clone(),
        show_logs: false,
    };

    let d = eframe::icon_data::from_png_bytes(include_bytes!("../icon.png"))
        .expect("The icon data must be valid");
    let mut options = eframe::NativeOptions::default();
    options.viewport.icon = Some(std::sync::Arc::new(d));

    // rt must be kept in scope for channel lifetimes, so we define and then spawn.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.spawn(async move {
        discover::start_discover(idevice_sender).await;
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
                                let mut values = match lc.get_all_values().await {
                                    Ok(v) => v,
                                    Err(e) => {
                                        error!("Failed to get lockdown values: {e:?}");
                                        continue;
                                    }
                                };
                                let device_name = match values.remove("DeviceName") {
                                    Some(plist::Value::String(n)) => n,
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
                            Some("com.apple.mobile.wireless_lockdown".into()),
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
                            "DeveloperModeStatus",
                            Some("com.apple.security.mac.amfi".to_string()),
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

                    let pairing_file = match uc.get_pair_record(&dev.udid).await {
                        Ok(p) => p,
                        Err(e) => {
                            gui_sender.send(GuiCommands::PairingFile(Err(e))).unwrap();
                            continue;
                        }
                    };
                    gui_sender
                        .send(GuiCommands::PairingFile(Ok(pairing_file)))
                        .unwrap();
                }
                IdeviceCommands::GeneratePairingFile(dev) => {
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
                    let mut pairing_file = match lc.pair(id, buid).await {
                        Ok(p) => p,
                        Err(e) => {
                            gui_sender.send(GuiCommands::PairingFile(Err(e))).unwrap();
                            continue;
                        }
                    };

                    pairing_file.udid = Some(dev.udid.clone());

                    gui_sender
                        .send(GuiCommands::PairingFile(Ok(pairing_file)))
                        .unwrap();
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
                IdeviceCommands::InstalledApps((dev, desired_apps)) => {
                    let p = dev.to_provider(UsbmuxdAddr::default(), "idevice_pair");
                    let mut ic = match InstallationProxyClient::connect(&p).await {
                        Ok(i) => i,
                        Err(e) => {
                            gui_sender.send(GuiCommands::InstalledApps(Err(e))).unwrap();
                            continue;
                        }
                    };
                    let installed_apps = match ic.get_apps(Some("User".to_string()), None).await {
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
                                if desired_apps.contains(&n.to_string()) {
                                    installed.insert(n.to_string(), bundle_id);
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

                    match f.write(&pairing_file.serialize().unwrap()).await {
                        Ok(_) => {
                            gui_sender
                                .send(GuiCommands::InstallPairingFile((name, Ok(()))))
                                .unwrap();
                            continue;
                        }
                        Err(e) => {
                            gui_sender
                                .send(GuiCommands::InstallPairingFile((name, Err(e))))
                                .unwrap();
                            continue;
                        }
                    }
                }
                IdeviceCommands::DiscoveredDevice((ip, mac)) => {
                    discovered_devices.insert(mac, ip);
                }
            };
        }
        eprintln!("Exited idevice loop!!");
    });

    eframe::run_native("idevice pair", options, Box::new(|_| Ok(Box::new(app)))).unwrap();
}

enum GuiCommands {
    NoUsbmuxd(IdeviceError),
    GetDevicesFailure(IdeviceError),
    Devices(HashMap<String, UsbmuxdDevice>),
    EnabledWireless,
    EnableWirelessFailure(IdeviceError),
    DevMode(Result<bool, IdeviceError>),
    MountRes(Result<(), IdeviceError>),
    PairingFile(Result<PairingFile, IdeviceError>),
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
    GeneratePairingFile(UsbmuxdDevice),
    Validate((Option<IpAddr>, PairingFile)),
    InstalledApps((UsbmuxdDevice, Vec<String>)),
    InstallPairingFile((UsbmuxdDevice, String, String, String, PairingFile)), // dev, name, b_id, install path, pf
    DiscoveredDevice((IpAddr, String)),                                       // ip, mac
}

struct MyApp {
    // Selector
    devices: Option<HashMap<String, UsbmuxdDevice>>,
    devices_placeholder: String,
    selected_device: String,

    // Device info
    wireless_enabled: Option<Result<(), IdeviceError>>,
    dev_mode_enabled: Option<Result<bool, IdeviceError>>,
    ddi_mounted: Option<Result<(), IdeviceError>>,

    // Pairing info
    pairing_file: Option<PairingFile>,
    pairing_file_string: Option<String>,
    pairing_file_message: Option<String>,

    // Save
    save_error: Option<String>,
    installed_apps: Option<Result<HashMap<String, String>, IdeviceError>>,
    supported_apps: HashMap<String, String>, // name, path to save pairing file to
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

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Get updates from the idevice thread
        match self.gui_recv.try_recv() {
            Ok(msg) => match msg {
                GuiCommands::NoUsbmuxd(idevice_error) => {
                    let install_msg = if cfg!(windows) {
                        "Make sure you have iTunes installed from Apple's website, and that it's running."
                    } else if cfg!(target_os = "macos") {
                        "usbmuxd should be running by default on MacOS. Please raise an issue on GitHub."
                    } else {
                        "Make sure usbmuxd is installed and running."
                    };

                    self.devices_placeholder = format!(
                        "Failed to connect to usbmuxd! {install_msg}\n\n{idevice_error:#?}"
                    );
                }
                GuiCommands::Devices(vec) => self.devices = Some(vec),
                GuiCommands::GetDevicesFailure(idevice_error) => {
                    self.devices_placeholder = format!(
                        "Failed to get list of connected devices from usbmuxd! {idevice_error:?}"
                    );
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
                GuiCommands::PairingFile(pairing_file) => match pairing_file {
                    Ok(p) => {
                        self.pairing_file = Some(p.clone());
                        self.pairing_file_message = None;
                        self.pairing_file_string =
                            Some(String::from_utf8_lossy(&p.serialize().unwrap()).to_string())
                    }
                    Err(e) => self.pairing_file_message = Some(e.to_string()),
                },
                GuiCommands::Validated(res) => match res {
                    Ok(()) => self.validate_res = Some(Ok(())),
                    Err(e) => self.validate_res = Some(Err(e.to_string())),
                },
                GuiCommands::InstalledApps(apps) => self.installed_apps = Some(apps),
                GuiCommands::InstallPairingFile((name, res)) => {
                    if let Some(v) = self.install_res.get_mut(&name) {
                        *v = Some(res)
                    }
                }
            },
            Err(e) => match e {
                tokio::sync::mpsc::error::TryRecvError::Empty => {}
                tokio::sync::mpsc::error::TryRecvError::Disconnected => {
                    panic!("idevice crashed");
                }
            },
        }
        if self.show_logs {
            egui::Window::new("logs").show(ctx, |ui| {
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
                    ui.heading("idevice pair");
                    ui.separator();
                    let p_background_color = match ctx.theme() {
                        egui::Theme::Dark => Color32::BLACK,
                        egui::Theme::Light => Color32::LIGHT_GRAY,
                    };
                    egui::frame::Frame::new().corner_radius(3).inner_margin(3).fill(p_background_color).show(ui, |ui| {
                        ui.toggle_value(&mut self.show_logs, "logs");
                    });
                });
                match &self.devices {
                    Some(devs) => {
                        if devs.is_empty() {
                            ui.label("No devices connected! Plug one in via USB.");
                        } else {
                            ui.label("Choose a device");
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
                                            // reset values
                                            self.wireless_enabled = None;
                                            self.idevice_sender
                                                .send(IdeviceCommands::EnableWireless(dev.clone()))
                                                .unwrap();
                                            self.dev_mode_enabled = None;
                                            self.idevice_sender
                                                .send(IdeviceCommands::CheckDevMode(dev.clone()))
                                                .unwrap();
                                            self.ddi_mounted = None;
                                            self.idevice_sender
                                                .send(IdeviceCommands::AutoMount(dev.clone()))
                                                .unwrap();
                                            self.pairing_file = None;
                                            self.pairing_file_message = None;
                                            self.pairing_file_string = None;
                                            self.installed_apps = None;
                                            self.idevice_sender.send(IdeviceCommands::InstalledApps((dev.clone(), self.supported_apps.keys().map(|x| x.to_owned()).collect()))).unwrap();
                                            self.validating = false;
                                            self.validate_res = None;
                                        };
                                    }
                                });
                        }
                    }
                    None => {
                        ui.label(&self.devices_placeholder);
                    }
                }
                if ui.button("Refresh...").clicked() {
                    self.idevice_sender
                        .send(IdeviceCommands::GetDevices)
                        .unwrap();
                }

                ui.separator();
                if let Some(dev) = self
                    .devices
                    .as_ref()
                    .and_then(|x| x.get(&self.selected_device))
                {
                    ui.horizontal(|ui| {
                        ui.label("Wireless Debugging:");
                        match &self.wireless_enabled {
                            Some(Ok(_)) => ui.label(RichText::new("Enabled").color(Color32::GREEN)),
                            Some(Err(e)) => ui
                                .label(RichText::new(format!("Failed: {e:?}")).color(Color32::RED)),
                            None => ui.label("Loading..."),
                        };
                    });
                    ui.horizontal(|ui| {
                        ui.label("Developer Mode:");
                        match &self.dev_mode_enabled {
                            Some(Ok(true)) => {
                                ui.label(RichText::new("Enabled").color(Color32::GREEN))
                            }
                            Some(Ok(false)) => {
                                ui.label(RichText::new("Disabled!").color(Color32::RED))
                            }
                            Some(Err(e)) => ui
                                .label(RichText::new(format!("Failed: {e:?}")).color(Color32::RED)),
                            None => ui.label("Loading..."),
                        };
                    });
                    ui.horizontal(|ui| {
                        ui.label("Developer Disk Image (iOS 17+):");
                        match &self.ddi_mounted {
                            Some(Ok(_)) => {
                                ui.label(RichText::new("Mounted").color(Color32::GREEN))
                            }
                            Some(Err(e)) => ui
                                .label(RichText::new(format!("Failed: {e:?}")).color(Color32::RED)),
                            None => ui.label("Loading..."),
                        };
                    });

                    // How to load a file
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.heading("Load");
                            ui.label("Load the pairing file from the system.");
                            if ui.button("Load").clicked() {
                                self.pairing_file_message = Some("Loading...".to_string());
                                self.pairing_file_string = None;
                                self.idevice_sender
                                    .send(IdeviceCommands::LoadPairingFile(dev.clone()))
                                    .unwrap();
                            }
                        });
                        ui.separator();
                        ui.vertical(|ui| {
                            ui.heading("Generate");
                            ui.label("Generate a new pairing file. This may invalidate old ones.");
                            if ui.button("Generate").clicked() {
                                self.pairing_file_message = Some("Loading...".to_string());
                                self.pairing_file_string = None;
                                self.idevice_sender
                                    .send(IdeviceCommands::GeneratePairingFile(dev.clone()))
                                    .unwrap();
                            }
                        });
                    });
                    if let Some(msg) = &self.pairing_file_message {
                        ui.label(msg);
                    }

                    ui.separator();

                    if let Some(pairing_file) = &self.pairing_file_string {
                        egui::Grid::new("reee").min_col_width(200.0).show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.heading("Save to File");
                                if let Some(msg) = &self.save_error {
                                    ui.label(RichText::new(msg).color(Color32::RED));
                                }
                                ui.label("Save this file to your computer, and then transfer it to your device manually.");
                                if ui.button("Save to File").clicked() {
                                    if let Some(p) = FileDialog::new()
                                        .set_can_create_directories(true)
                                        .set_title("Save Pairing File")
                                        .set_file_name(format!("{}.plist", &dev.udid))
                                        .save_file()
                                    {
                                        self.save_error = None;
                                        if let Err(e) = std::fs::write(
                                            p,
                                            self.pairing_file
                                                .as_ref()
                                                .unwrap()
                                                .clone()
                                                .serialize()
                                                .unwrap(),
                                        ) {
                                            self.save_error = Some(e.to_string());
                                        }
                                    }
                                }

                                ui.separator();
                                ui.heading("Validation");
                                ui.label("Verify that your pairing file works over LAN. Your device will be searched for over your network.");
                                ui.add(egui::TextEdit::singleline(&mut self.validation_ip_input).hint_text("OR enter your device's IP..."));
                                if ui.button("Validate").clicked() {
                                    self.validating = true;
                                    self.validate_res = None;
                                    if self.validation_ip_input.is_empty() {
                                        self.idevice_sender.send(IdeviceCommands::Validate((None, self.pairing_file.clone().unwrap()))).unwrap()
                                    } else {
                                        match IpAddr::from_str(self.validation_ip_input.as_str()) {
                                            Ok(i) => {
                                                self.idevice_sender.send(IdeviceCommands::Validate((Some(i), self.pairing_file.clone().unwrap()))).unwrap()
                                            },
                                            Err(_) => self.validate_res = Some(Err("Invalid IP".to_string()))
                                        };
                                    }
                                }
                                if self.validating {
                                    match &self.validate_res {
                                        Some(Ok(_)) => ui.label(RichText::new("Success").color(Color32::GREEN)),
                                        Some(Err(e)) =>ui.label(RichText::new(e).color(Color32::RED)),
                                        None => ui.label("Loading..."),
                                    };
                                }

                                match &self.installed_apps {
                                    Some(Ok(apps)) => {
                                        for (name, bundle_id) in apps {
                                            ui.separator();
                                            ui.heading(name);
                                            ui.label(RichText::new(bundle_id).italics().weak());
                                            ui.label(format!("{name} is installed on your device. You can automatically install the pairing file into the app."));
                                            if ui.button("Install").clicked() {
                                                self.idevice_sender.send(IdeviceCommands::InstallPairingFile((dev.clone(), name.clone(), bundle_id.clone(), self.supported_apps.get(name).unwrap().to_owned(), self.pairing_file.clone().unwrap()))).unwrap();
                                                self.install_res.insert(name.to_owned(), None);
                                            }
                                            if let Some(v) = self.install_res.get(name) {
                                                match v {
                                                    Some(Ok(_)) => ui.label(RichText::new("Success").color(Color32::GREEN)),
                                                    Some(Err(e)) => ui.label(RichText::new(e.to_string()).color(Color32::RED)),
                                                    None => ui.label("Installing..."),
                                                };
                                            }
                                        }
                                    }
                                    Some(Err(e)) => {
                                        ui.label(RichText::new(format!("Failed getting installed apps: {:?}", e.to_string())).color(Color32::RED));
                                    }
                                    None => {
                                        ui.label("Getting installed apps...");
                                    }
                                }
                            });
                            let p_background_color = match ctx.theme() {
                                egui::Theme::Dark => Color32::BLACK,
                                egui::Theme::Light => Color32::LIGHT_GRAY,
                            };
                            egui::frame::Frame::new().corner_radius(10).inner_margin(10).fill(p_background_color).show(ui, |ui| {
                                ui.label(RichText::new(pairing_file).monospace());
                            });
                        });
                    }
                }
            });
        });
    }
}
