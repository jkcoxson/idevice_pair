use eframe::egui::{self, Ui};

use crate::{
    app::App,
    backend::{DeviceSummary, Transport},
};

pub fn picker(app: &mut App, ui: &mut Ui) {
    let selected_text = app
        .selected
        .as_ref()
        .and_then(|key| app.devices.iter().find(|device| &device.key == key))
        .map_or_else(|| "No device".into(), label);

    let mut pick = None;
    let mut pair = None;

    egui::ComboBox::from_id_salt("devices")
        .selected_text(selected_text)
        .width(280.0)
        .show_ui(ui, |ui| {
            for device in &app.devices {
                if ui
                    .selectable_label(app.selected.as_ref() == Some(&device.key), label(device))
                    .clicked()
                {
                    pick = Some(device.key.clone());
                }
            }
            for device in &app.apple_tvs {
                if ui
                    .selectable_label(false, format!("{} · available to pair", device.name))
                    .clicked()
                {
                    pair = Some(device.clone());
                }
            }
        });

    if let Some(device) = pair {
        app.pair_apple_tv(device);
    } else if let Some(key) = pick {
        app.select(key);
    }
    if ui.button("Pair over Wi-Fi").clicked() {
        app.start_wireless_pairing();
    }
}

fn label(device: &DeviceSummary) -> String {
    let transport = match device.transport {
        Transport::Usb => "USB",
        Transport::Network => "Wi-Fi",
        Transport::Remote => "paired over Wi-Fi",
    };
    format!("{} · {transport}", device.name)
}
