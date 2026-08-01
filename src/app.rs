use std::collections::HashMap;

use eframe::egui;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{
    backend::{
        self, AppleTv, Backend, Check, Command, DeviceInfo, DeviceKey, DeviceSummary, Event,
        InstalledApp, PairingKind, PairingResult, WirelessStatus,
    },
    logging::Logs,
    ui,
};

pub struct App {
    pub logs: Logs,
    pub show_logs: bool,
    pub devices: Vec<DeviceSummary>,
    pub apple_tvs: Vec<AppleTv>,
    pub usbmuxd_failure: Option<String>,
    pub selected: Option<DeviceKey>,
    pub pages: HashMap<DeviceKey, Page>,
    pub wireless: Option<Wireless>,
    backend: Backend,
    events: UnboundedReceiver<Event>,
}

#[derive(Default)]
pub enum Task<T> {
    #[default]
    Idle,
    Busy,
    Done(Result<T, String>),
}

impl<T> Task<T> {
    pub fn busy(&self) -> bool {
        matches!(self, Self::Busy)
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Done(Ok(value)) => Some(value),
            _ => None,
        }
    }
}

#[derive(Default)]
pub struct Page {
    pub info: Task<DeviceInfo>,
    pub wireless_debugging: Task<bool>,
    pub developer_mode: Task<bool>,
    pub developer_image: Task<bool>,
    pub kind: PairingKind,
    pub stored_record: bool,
    pub pairing: Task<PairingResult>,
    pub progress: Option<String>,
    pub apps: Task<Vec<InstalledApp>>,
    pub installs: HashMap<String, Task<()>>,
    pub validation: Task<()>,
    pub ip: String,
    pub save_error: Option<String>,
}

impl Page {
    fn reset_pairing(&mut self) {
        self.pairing = Task::Idle;
        self.validation = Task::Idle;
        self.progress = None;
        self.save_error = None;
        self.installs.clear();
    }
}

pub enum Wireless {
    Advertising(String),
    ConnectingAppleTv(String),
    Connected,
    EnterPin { host: String, pin: String },
    PairingAppleTv,
    Pin(String),
    Failed(String),
}

pub enum Action {
    Kind(PairingKind),
    Create,
    Validate,
    Install(InstalledApp),
}

impl App {
    pub fn new(ctx: &egui::Context, logs: Logs) -> Self {
        let (backend, events) = backend::spawn(ctx.clone());
        Self {
            logs,
            show_logs: false,
            devices: Vec::new(),
            apple_tvs: Vec::new(),
            usbmuxd_failure: None,
            selected: None,
            pages: HashMap::new(),
            wireless: None,
            backend,
            events,
        }
    }

    pub fn select(&mut self, key: DeviceKey) {
        if self.selected.as_ref() == Some(&key) {
            return;
        }
        self.selected = Some(key.clone());
        let transport = self
            .devices
            .iter()
            .find(|device| device.key == key)
            .map(|device| device.transport);

        let page = self.pages.entry(key.clone()).or_default();
        if transport == Some(backend::Transport::Remote) {
            page.kind = PairingKind::Remote;
        }

        self.backend.send(Command::Inspect(key));
    }

    pub fn start_wireless_pairing(&self) {
        self.backend.send(Command::StartWirelessPairing);
    }

    pub fn stop_wireless_pairing(&mut self) {
        self.wireless = None;
        self.backend.send(Command::StopWirelessPairing);
    }

    pub fn submit_wireless_pin(&mut self, pin: String) {
        self.wireless = Some(Wireless::PairingAppleTv);
        self.backend.send(Command::SubmitWirelessPin(pin));
    }

    pub fn pair_apple_tv(&mut self, device: AppleTv) {
        self.wireless = Some(Wireless::ConnectingAppleTv(device.name.clone()));
        self.backend.send(Command::PairAppleTv(device));
    }

    pub fn act(&mut self, key: &DeviceKey, action: Action) {
        let page = self.pages.entry(key.clone()).or_default();

        match action {
            Action::Kind(kind) => {
                page.kind = kind;
                page.reset_pairing();
                page.apps = Task::Idle;
            }
            Action::Create => {
                let kind = page.kind;
                page.reset_pairing();
                page.pairing = Task::Busy;
                self.backend.send(Command::CreatePairing {
                    key: key.clone(),
                    kind,
                });
            }
            Action::Validate => {
                let ip = page.ip.trim();
                let ip = if ip.is_empty() {
                    None
                } else {
                    let Ok(ip) = ip.parse() else {
                        page.validation = Task::Done(Err("Not an IP address".to_string()));
                        return;
                    };
                    Some(ip)
                };
                page.validation = Task::Busy;
                self.backend.send(Command::Validate {
                    key: key.clone(),
                    ip,
                });
            }
            Action::Install(app) => {
                page.installs.insert(app.name.clone(), Task::Busy);
                self.backend.send(Command::Install {
                    key: key.clone(),
                    app,
                });
            }
        }
    }

    fn handle(&mut self, event: Event) {
        match event {
            Event::Devices(devices) => {
                self.usbmuxd_failure = None;
                self.devices = devices;
                if self
                    .selected
                    .as_ref()
                    .is_some_and(|key| !self.devices.iter().any(|device| &device.key == key))
                {
                    self.selected = None;
                }
                if self.selected.is_none() && self.devices.len() == 1 {
                    self.select(self.devices[0].key.clone());
                }
            }
            Event::AppleTvs(devices) => self.apple_tvs = devices,
            Event::UsbmuxdFailure(message) => self.usbmuxd_failure = Some(message),
            Event::Info { key, result } => self.page(key).info = Task::Done(result),
            Event::Check { key, check, result } => {
                let page = self.page(key);
                let task = match check {
                    Check::WirelessDebugging => &mut page.wireless_debugging,
                    Check::DeveloperMode => &mut page.developer_mode,
                    Check::DeveloperImage => &mut page.developer_image,
                };
                *task = Task::Done(result);
            }
            Event::PairRecord { key, stored } => self.page(key).stored_record = stored,
            Event::Apps { key, result } => self.page(key).apps = Task::Done(result),
            Event::Progress { key, message } => self.page(key).progress = Some(message),
            Event::Pairing { key, result } => {
                let paired = result.is_ok();
                let page = self.page(key.clone());
                page.progress = None;
                page.pairing = Task::Done(result);
                if paired {
                    page.apps = Task::Busy;
                    let kind = page.kind;
                    self.backend.send(Command::ListApps { key, kind });
                }
            }
            Event::Validation { key, result } => self.page(key).validation = Task::Done(result),
            Event::Install { key, app, result } => {
                self.page(key).installs.insert(app, Task::Done(result));
            }
            Event::Wireless(status) => match status {
                WirelessStatus::Advertising(name) => {
                    self.wireless = Some(Wireless::Advertising(name))
                }
                WirelessStatus::Connected => self.wireless = Some(Wireless::Connected),
                WirelessStatus::EnterPin(host) => {
                    self.wireless = Some(Wireless::EnterPin {
                        host,
                        pin: String::new(),
                    })
                }
                WirelessStatus::Pin(pin) => self.wireless = Some(Wireless::Pin(pin)),
                WirelessStatus::Failed(message) => self.wireless = Some(Wireless::Failed(message)),
                WirelessStatus::Paired(key) => {
                    self.wireless = None;
                    self.select(key);
                }
            },
        }
    }

    fn page(&mut self, key: DeviceKey) -> &mut Page {
        self.pages.entry(key).or_default()
    }
}

impl eframe::App for App {
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.events.try_recv() {
            self.handle(event);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        ui::top_bar(self, ui);
        ui::logs(self, ui);
        ui::device_page(self, ui);
        ui::wireless_modal(self, &ctx);
    }
}
