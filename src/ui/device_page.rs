use eframe::egui::{self, RichText, Ui};

use super::widgets;
use crate::{
    app::{Action, App, Page, Task},
    backend::{PairingKind, PairingResult, Transport},
};

pub fn device_page(app: &mut App, ui: &mut egui::Ui) {
    egui::CentralPanel::default().show(ui, |ui| {
        let selected = app.selected.clone().and_then(|key| {
            app.devices
                .iter()
                .find(|device| device.key == key)
                .map(|device| (key, device.transport, device.name.clone()))
        });

        let Some((key, transport, name)) = selected else {
            empty(app, ui);
            return;
        };

        let mut action = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let page = app.pages.entry(key.clone()).or_default();
                ui.add_space(4.0);
                header(&name, page, ui);
                checks(page, transport, ui);
                ui.add_space(10.0);
                ui.separator();
                pairing(page, transport, ui, &mut action);
            });

        if let Some(action) = action {
            app.act(&key, action);
        }
    });
}

fn empty(app: &App, ui: &mut Ui) {
    ui.centered_and_justified(|ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            widgets::label(ui, "No device");
            if let Some(message) = &app.usbmuxd_failure {
                ui.add_space(6.0);
                widgets::error(ui, message);
                widgets::label(ui, "Make sure usbmuxd is installed and running.");
            }
        });
    });
}

fn header(name: &str, page: &Page, ui: &mut Ui) {
    ui.heading(name);
    if let Task::Done(Err(message)) = &page.info {
        widgets::error(ui, message);
    }

    if let Some(info) = page.info.value() {
        ui.add_space(4.0);
        widgets::fields(
            ui,
            "device_info",
            &[
                ("Model", &info.model),
                ("iOS", &info.version),
                ("UDID", &info.udid),
            ],
        );
    }
}

fn checks(page: &Page, transport: Transport, ui: &mut Ui) {
    ui.add_space(10.0);
    if transport == Transport::Usb {
        widgets::status(
            ui,
            "Wireless debugging",
            &page.wireless_debugging,
            "Enabled",
            "Off",
        );
    }
    widgets::status(
        ui,
        "Developer mode",
        &page.developer_mode,
        "Enabled",
        "Disabled",
    );
    widgets::status(
        ui,
        "Developer image",
        &page.developer_image,
        "Mounted",
        "Not mounted",
    );
}

fn pairing(page: &mut Page, transport: Transport, ui: &mut Ui, action: &mut Option<Action>) {
    ui.add_space(8.0);
    ui.label(RichText::new("Pairing file").strong());
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        for kind in [PairingKind::Remote, PairingKind::Lockdown] {
            let enabled = transport != Transport::Remote || kind == PairingKind::Remote;
            let response = ui.add_enabled(
                enabled,
                egui::Button::selectable(page.kind == kind, kind.label()),
            );
            if response.clicked() && page.kind != kind {
                *action = Some(Action::Kind(kind));
            }
            if !enabled {
                response.on_disabled_hover_text(
                    "Lockdown pairing requires a USB or usbmuxd connection",
                );
            }
        }
    });

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        let stored = match page.kind {
            PairingKind::Lockdown => page.stored_record,
            PairingKind::Remote => transport == Transport::Remote,
        };
        let label = if stored { "Load" } else { "Create" };
        if ui
            .add_enabled(!page.pairing.busy(), egui::Button::new(label))
            .clicked()
        {
            *action = Some(Action::Create);
        }
        if page.pairing.busy() {
            widgets::spinner(ui);
        }
        if let Some(progress) = &page.progress {
            widgets::label(ui, progress);
        }
    });

    if let Task::Done(Err(message)) = &page.pairing {
        ui.add_space(4.0);
        widgets::error(ui, message);
    }
    destinations(page, ui, action);
}

fn destinations(page: &mut Page, ui: &mut Ui, action: &mut Option<Action>) {
    let Page {
        kind,
        pairing,
        validation,
        apps,
        installs,
        ip,
        save_error,
        ..
    } = page;
    let Some(pairing) = pairing.value() else {
        return;
    };

    ui.add_space(12.0);
    ui.horizontal(|ui| {
        if ui.button("Save to file…").clicked() {
            save(pairing, save_error);
        }
        if ui
            .add_enabled(!validation.busy(), egui::Button::new("Validate"))
            .clicked()
        {
            *action = Some(Action::Validate);
        }
        if *kind == PairingKind::Lockdown {
            ui.add(
                egui::TextEdit::singleline(ip)
                    .desired_width(130.0)
                    .hint_text("device IP"),
            );
        }
        widgets::outcome(ui, validation, "Works");
    });
    if let Some(message) = save_error {
        widgets::error(ui, message);
    }

    ui.add_space(12.0);
    widgets::label(ui, "Send to an app");
    ui.add_space(2.0);
    match apps {
        Task::Done(Ok(apps)) if apps.is_empty() => {
            widgets::label(ui, "No supported apps installed")
        }
        Task::Done(Ok(apps)) => {
            for app in apps.iter() {
                ui.horizontal(|ui| {
                    if ui.button(&app.name).clicked() {
                        *action = Some(Action::Install(app.clone()));
                    }
                    widgets::label(ui, app.path);
                    if let Some(install) = installs.get(&app.name) {
                        widgets::outcome(ui, install, "Sent");
                    }
                });
            }
        }
        Task::Done(Err(message)) => widgets::error(ui, message),
        _ => widgets::spinner(ui),
    }

    ui.add_space(12.0);
    ui.collapsing("Contents", |ui| widgets::plist(ui, &pairing.text));
}

fn save(pairing: &PairingResult, error: &mut Option<String>) {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Save pairing file")
        .set_file_name(&pairing.file_name)
        .set_can_create_directories(true)
        .save_file()
    else {
        return;
    };

    *error = std::fs::write(path, &pairing.bytes)
        .err()
        .map(|e| e.to_string());
}
