mod device_page;
mod devices;
mod widgets;

pub use device_page::device_page;

use eframe::egui::{self, FontFamily, RichText};

use crate::app::{App, Wireless};

pub fn setup(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let proportional = fonts.families.entry(FontFamily::Proportional).or_default();
    proportional.retain(|name| name != "Hack");
    proportional.insert(1.min(proportional.len()), "Hack".to_owned());
    ctx.set_fonts(fonts);

    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
    });
}

pub fn top_bar(app: &mut App, ui: &mut egui::Ui) {
    egui::Panel::top("top_bar").show(ui, |ui| {
        ui.add_space(5.0);
        ui.horizontal(|ui| {
            devices::picker(app, ui);

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.toggle_value(&mut app.show_logs, "Logs");
            });
        });
        ui.add_space(5.0);
    });
}

pub fn logs(app: &mut App, ui: &mut egui::Ui) {
    egui::Panel::bottom("logs")
        .resizable(true)
        .default_size(180.0)
        .show_collapsible(ui, &mut app.show_logs, |ui| {
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    app.logs.read(|lines| {
                        for line in lines {
                            ui.horizontal_wrapped(|ui| {
                                ui.spacing_mut().item_spacing.x = 5.0;
                                ui.label(
                                    RichText::new(line.level.as_str())
                                        .monospace()
                                        .color(level_color(ui, line.level)),
                                );
                                ui.label(RichText::new(&line.target).monospace().weak());
                                ui.label(RichText::new(&line.message).monospace());
                            });
                        }
                    });
                });
        });
}

pub fn wireless_modal(app: &mut App, ctx: &egui::Context) {
    let Some(state) = &app.wireless else {
        return;
    };

    let mut close = false;
    egui::Modal::new(egui::Id::new("wireless")).show(ctx, |ui| {
        ui.set_width(360.0);
        ui.heading("Pair over Wi-Fi");
        widgets::label(
            ui,
            "Wireless pairing is only available on iOS 27 and later. On your device, go to Settings → Privacy & Security → Developer Mode.",
        );
        ui.add_space(10.0);

        match state {
            Wireless::Advertising(name) => {
                ui.label(format!("This computer is offering to pair as “{name}”."));
                widgets::label(ui, "Pick it on your device to start pairing.");
                ui.add_space(6.0);
                widgets::spinner(ui);
            }
            Wireless::Connected => {
                ui.label("A device connected. Waiting for a code…");
                ui.add_space(6.0);
                widgets::spinner(ui);
            }
            Wireless::Pin(pin) => {
                ui.label("Enter this code on your device:");
                ui.add_space(6.0);
                ui.label(RichText::new(pin).monospace().size(30.0).strong());
            }
            Wireless::Failed(message) => widgets::error(ui, message),
        }

        ui.add_space(14.0);
        let button = if matches!(state, Wireless::Failed(_)) {
            "Close"
        } else {
            "Cancel"
        };
        if ui.button(button).clicked() {
            close = true;
        }
    });

    if close {
        app.stop_wireless_pairing();
    }
}

fn level_color(ui: &egui::Ui, level: tracing::Level) -> egui::Color32 {
    match level {
        tracing::Level::ERROR => ui.visuals().error_fg_color,
        tracing::Level::WARN => ui.visuals().warn_fg_color,
        _ => ui.visuals().weak_text_color(),
    }
}
