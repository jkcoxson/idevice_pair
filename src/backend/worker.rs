use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

use eframe::egui;
use idevice::{
    IdeviceError,
    remote_pairing::RpPairingFile,
    usbmuxd::{Connection, UsbmuxdDevice},
};
use tokio::sync::{
    Mutex, OwnedMutexGuard,
    mpsc::{UnboundedReceiver, unbounded_channel},
};
use tracing::debug;

use super::{
    Backend, Check, Command, DeviceKey, DeviceSummary, Event, Events, InstalledApp, PairingKind,
    Transport, WirelessStatus, ddi, install,
    link::Link,
    pairing::{self, Payload},
    usb, validate,
    wireless::{self, HostIdentity, WirelessDevice},
};

const WORKER_STACK_SIZE: usize = 8 * 1024 * 1024;

pub fn spawn(ctx: egui::Context) -> (Backend, UnboundedReceiver<Event>) {
    let (command_sender, mut commands) = unbounded_channel();
    let (event_sender, events) = unbounded_channel();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_stack_size(WORKER_STACK_SIZE)
            .build()
            .expect("failed to build the tokio runtime");

        runtime.block_on(async move {
            let worker = Arc::new(Worker::new(Events {
                sender: event_sender,
                ctx,
            }));
            worker.clone().watch_usb();

            while let Some(command) = commands.recv().await {
                let worker = worker.clone();
                tokio::spawn(worker.handle(command));
            }
        });
    });

    (
        Backend {
            commands: command_sender,
        },
        events,
    )
}

struct Worker {
    events: Events,
    identity: HostIdentity,
    devices: Mutex<HashMap<DeviceKey, Device>>,
    pairing_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

struct Device {
    summary: DeviceSummary,
    state: Arc<Mutex<State>>,
}

struct State {
    source: Source,
    link: Option<Link>,
    pairing: Option<Payload>,
}

enum Source {
    Usbmuxd(UsbmuxdDevice),
    Remote(Box<RpPairingFile>),
}

impl Source {
    fn transport(&self) -> Transport {
        match self {
            Self::Usbmuxd(device) if device.connection_type == Connection::Usb => Transport::Usb,
            Self::Usbmuxd(_) => Transport::Network,
            Self::Remote(_) => Transport::Remote,
        }
    }
}

impl State {
    async fn link(&mut self) -> Result<Link, IdeviceError> {
        if let Some(link) = &self.link {
            return Ok(link.clone());
        }

        let link = match &mut self.source {
            Source::Usbmuxd(device) => Link::usbmuxd(device),
            Source::Remote(pairing_file) => wireless::open_link(pairing_file).await?,
        };
        self.link = Some(link.clone());
        Ok(link)
    }

    async fn tunnel(&mut self, events: &Events, key: &DeviceKey) -> Result<Link, IdeviceError> {
        match self.link().await? {
            link @ Link::Rsd { .. } => Ok(link),
            Link::Usbmuxd { provider, .. } => {
                events.progress(key, "Opening a tunnel to the device");
                Link::over_core_device(&provider).await
            }
        }
    }
}

impl Worker {
    fn new(events: Events) -> Self {
        Self {
            events,
            identity: HostIdentity::generate(),
            devices: Mutex::new(HashMap::new()),
            pairing_task: Mutex::new(None),
        }
    }

    async fn handle(self: Arc<Self>, command: Command) {
        match command {
            Command::Inspect(key) => self.inspect(key).await,
            Command::ListApps { key, kind } => self.list_apps(key, kind).await,
            Command::CreatePairing { key, kind } => self.create_pairing(key, kind).await,
            Command::Validate { key, ip } => self.validate(key, ip).await,
            Command::Install { key, app } => self.install(key, app).await,
            Command::StartWirelessPairing => self.start_wireless_pairing().await,
            Command::StopWirelessPairing => self.stop_wireless_pairing().await,
        }
    }

    async fn refresh_devices(&self) {
        let attached = match usb::list().await {
            Ok(attached) => attached,
            Err(e) => {
                self.events.send(Event::UsbmuxdFailure(text(e)));
                return;
            }
        };

        {
            let mut devices = self.devices.lock().await;
            let keys: HashSet<DeviceKey> = attached
                .iter()
                .map(|device| muxer_key(&device.device))
                .collect();
            devices.retain(|key, device| {
                device.summary.transport == Transport::Remote || keys.contains(key)
            });
            for device in &attached {
                devices
                    .entry(muxer_key(&device.device))
                    .or_insert_with(|| Device::usbmuxd(device.name.clone(), device.device.clone()));
            }
        }

        for device in attached {
            let key = muxer_key(&device.device);
            let stored = usb::pair_record(&device.device.udid).await.is_ok();
            self.events.send(Event::Info {
                key: key.clone(),
                result: Ok(device.info),
            });
            self.events.send(Event::PairRecord { key, stored });
        }

        let devices = self.devices.lock().await;
        send_devices(&self.events, &devices);
    }

    async fn inspect(&self, key: DeviceKey) {
        let Some(mut state) = self.state(&key).await else {
            return;
        };
        let transport = state.source.transport();
        let mut link = match state.link().await {
            Ok(link) => link,
            Err(e) => return self.check(&key, Check::DeveloperMode, Err(e)),
        };
        drop(state);

        if transport == Transport::Remote {
            self.events.send(Event::Info {
                key: key.clone(),
                result: link.info().await.map_err(text),
            });
        }
        let result = link.developer_mode().await;
        self.check(&key, Check::DeveloperMode, result);
        let mount = match ddi::mounted(&mut link).await {
            Ok(false) => {
                self.check(&key, Check::DeveloperImage, Ok(false));
                true
            }
            result => {
                self.check(&key, Check::DeveloperImage, result);
                false
            }
        };
        if transport == Transport::Usb {
            let result = link.enable_wireless_debugging().await.map(|()| true);
            self.check(&key, Check::WirelessDebugging, result);
        }
        if mount {
            let result = ddi::mount(&mut link).await.map(|()| true);
            self.check(&key, Check::DeveloperImage, result);
        }
    }

    async fn list_apps(&self, key: DeviceKey, kind: PairingKind) {
        let Some(mut state) = self.state(&key).await else {
            return;
        };

        let link = state.link().await;
        drop(state);
        let result = match link {
            Ok(mut link) => install::list(&mut link, kind).await,
            Err(e) => Err(e),
        };
        self.events.send(Event::Apps {
            key,
            result: result.map_err(text),
        });
    }

    async fn create_pairing(&self, key: DeviceKey, kind: PairingKind) {
        let Some(mut state) = self.state(&key).await else {
            return;
        };

        let result = match self.build_pairing(&mut state, &key, kind).await {
            Ok(payload) => {
                let result = payload.result(udid(&key));
                state.pairing = Some(payload);
                result
            }
            Err(e) => Err(e),
        };

        self.events.send(Event::Pairing {
            key,
            result: result.map_err(text),
        });
    }

    async fn build_pairing(
        &self,
        state: &mut State,
        key: &DeviceKey,
        kind: PairingKind,
    ) -> Result<Payload, IdeviceError> {
        match kind {
            PairingKind::Lockdown => match pairing::stored_lockdown_file(udid(key)).await {
                Ok(file) => Ok(Payload::Lockdown(Box::new(file))),
                Err(e) => {
                    debug!("no stored pair record: {}", super::message(&e));
                    let mut link = state.link().await?;
                    pairing::lockdown_file(&mut link, udid(key), &self.events, key)
                        .await
                        .map(|file| Payload::Lockdown(Box::new(file)))
                }
            },
            PairingKind::Remote => {
                if let Source::Remote(pairing_file) = &state.source {
                    Ok(Payload::Remote(pairing_file.clone()))
                } else {
                    let mut tunnel = state.tunnel(&self.events, key).await?;
                    pairing::remote_file(&mut tunnel, &self.events, key)
                        .await
                        .map(|file| Payload::Remote(Box::new(file)))
                }
            }
        }
    }

    async fn validate(&self, key: DeviceKey, ip: Option<IpAddr>) {
        let Some(mut state) = self.state(&key).await else {
            return;
        };

        let result = match state.pairing.clone() {
            Some(Payload::Lockdown(file)) => validate::lockdown_over_lan(&file, ip).await,
            Some(Payload::Remote(mut file)) => match state.tunnel(&self.events, &key).await {
                Ok(mut tunnel) => pairing::verify_remote(&mut tunnel, &mut file).await,
                Err(e) => Err(e),
            },
            None => Err(IdeviceError::InternalError(
                "create a pairing file first".into(),
            )),
        };

        self.events.send(Event::Validation {
            key,
            result: result.map_err(text),
        });
    }

    async fn install(&self, key: DeviceKey, app: InstalledApp) {
        let Some(mut state) = self.state(&key).await else {
            return;
        };

        let Some(payload) = state.pairing.clone() else {
            return self.installed(
                &key,
                &app.name,
                Err(IdeviceError::InternalError(
                    "create a pairing file first".into(),
                )),
            );
        };

        let result = async {
            let bytes = payload.bytes()?;
            let mut link = state.link().await?;
            install::write(&mut link, &app, &bytes).await
        }
        .await;

        self.installed(&key, &app.name, result);
    }

    async fn start_wireless_pairing(self: &Arc<Self>) {
        let mut task = self.pairing_task.lock().await;
        if task.is_some() {
            return;
        }

        let worker = self.clone();
        *task = Some(tokio::spawn(worker.run_wireless_pairing()));
    }

    async fn run_wireless_pairing(self: Arc<Self>) {
        match wireless::accept_pairing(&self.identity, &self.events).await {
            Ok(device) => {
                let key = self.add_wireless(device).await;
                self.events
                    .send(Event::Wireless(WirelessStatus::Paired(key)));
            }
            Err(e) => self
                .events
                .send(Event::Wireless(WirelessStatus::Failed(text(e)))),
        }

        *self.pairing_task.lock().await = None;
    }

    async fn stop_wireless_pairing(&self) {
        let task = self.pairing_task.lock().await.take();
        if let Some(task) = task {
            task.abort();
        }
    }

    async fn add_wireless(&self, device: WirelessDevice) -> DeviceKey {
        let initial_pairing = Payload::Remote(Box::new(device.pairing_file.clone()));
        let result = initial_pairing.result(&device.udid).map_err(text);
        let device = Device::remote(device, initial_pairing);
        let key = device.summary.key.clone();

        {
            let mut devices = self.devices.lock().await;
            devices.insert(key.clone(), device);
            send_devices(&self.events, &devices);
        }
        self.events.send(Event::Pairing {
            key: key.clone(),
            result,
        });

        key
    }

    fn watch_usb(self: Arc<Self>) {
        let (change_sender, mut changes) = unbounded_channel();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build the usbmuxd runtime")
                .block_on(usb::watch(change_sender));
        });
        tokio::spawn(async move {
            while changes.recv().await.is_some() {
                self.refresh_devices().await;
            }
        });
    }

    async fn state(&self, key: &DeviceKey) -> Option<OwnedMutexGuard<State>> {
        let state = self.devices.lock().await.get(key)?.state.clone();
        Some(state.lock_owned().await)
    }

    fn check(&self, key: &DeviceKey, check: Check, result: Result<bool, IdeviceError>) {
        self.events.send(Event::Check {
            key: key.clone(),
            check,
            result: result.map_err(text),
        });
    }

    fn installed(&self, key: &DeviceKey, app: &str, result: Result<(), IdeviceError>) {
        self.events.send(Event::Install {
            key: key.clone(),
            app: app.to_string(),
            result: result.map_err(text),
        });
    }
}

impl Device {
    fn usbmuxd(name: String, device: UsbmuxdDevice) -> Self {
        let key = muxer_key(&device);
        let source = Source::Usbmuxd(device);
        Self::new(
            DeviceSummary {
                key,
                name,
                transport: source.transport(),
            },
            source,
            None,
        )
    }

    fn remote(device: WirelessDevice, pairing: Payload) -> Self {
        let WirelessDevice {
            udid,
            name,
            pairing_file,
        } = device;
        Self::new(
            DeviceSummary {
                key: format!("rp:{udid}"),
                name,
                transport: Transport::Remote,
            },
            Source::Remote(Box::new(pairing_file)),
            Some(pairing),
        )
    }

    fn new(summary: DeviceSummary, source: Source, pairing: Option<Payload>) -> Self {
        Self {
            summary,
            state: Arc::new(Mutex::new(State {
                source,
                link: None,
                pairing,
            })),
        }
    }
}

fn send_devices(events: &Events, devices: &HashMap<DeviceKey, Device>) {
    let mut summaries: Vec<DeviceSummary> = devices
        .values()
        .map(|device| device.summary.clone())
        .collect();
    summaries.sort_by_key(|device| (device.transport, device.name.to_lowercase()));

    debug!(
        "devices: {:?}",
        summaries.iter().map(|d| &d.key).collect::<Vec<_>>()
    );
    events.send(Event::Devices(summaries));
}

fn muxer_key(device: &UsbmuxdDevice) -> DeviceKey {
    match device.connection_type {
        Connection::Usb => format!("usb:{}", device.udid),
        _ => format!("net:{}", device.udid),
    }
}

fn udid(key: &DeviceKey) -> &str {
    key.split_once(':').expect("device key has a prefix").1
}

fn text(e: IdeviceError) -> String {
    super::message(&e)
}
