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
    let Some(state) = &mut app.wireless else {
        return;
    };

    let mut close = false;
    let mut submitted_pin = None;
    egui::Modal::new(egui::Id::new("wireless")).show(ctx, |ui| {
        ui.set_width(360.0);
        ui.heading("Pair over Wi-Fi");
        match state {
            Wireless::Advertising(host) => {
                widgets::label(
                    ui,
                    "On your iPhone/iPad, enable Developer Mode in Settings → Privacy & Security.",
                );
                ui.add_space(10.0);
                ui.label(format!("This computer is offering to pair as “{host}”."));
                widgets::label(ui, "Pick it on your iPhone/iPad to start pairing.");
                ui.add_space(6.0);
                widgets::spinner(ui);
            }
            Wireless::ConnectingAppleTv(name) => {
                ui.label(format!("Connecting to “{name}”…"));
                ui.add_space(6.0);
                widgets::spinner(ui);
            }
            Wireless::Connected => {
                ui.label("A device connected. Waiting for pairing…");
                ui.add_space(6.0);
                widgets::spinner(ui);
            }
            Wireless::EnterPin { host, pin } => {
                ui.label(format!("This computer is pairing as “{host}”."));
                ui.add_space(6.0);
                ui.label("Enter the code shown on your Apple TV:");
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::singleline(pin)
                        .char_limit(6)
                        .desired_width(120.0),
                );
                pin.retain(|character| character.is_ascii_digit());
                let valid = pin.len() == 6;
                let enter = valid && ui.input(|input| input.key_pressed(egui::Key::Enter));
                let clicked = ui.add_enabled(valid, egui::Button::new("Pair")).clicked();
                if enter || clicked {
                    submitted_pin = Some(pin.clone());
                }
            }
            Wireless::Pin(pin) => {
                ui.label("Enter this code on your device:");
                ui.add_space(6.0);
                ui.label(RichText::new(pin.as_str()).monospace().size(30.0).strong());
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

    if let Some(pin) = submitted_pin {
        app.submit_wireless_pin(pin);
    } else if close {
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
