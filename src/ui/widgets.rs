use eframe::egui::{self, Color32, RichText, Ui};

use crate::app::Task;

const GOOD: Color32 = Color32::from_rgb(0x4c, 0xaf, 0x50);

pub fn label(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).weak());
}

pub fn error(ui: &mut Ui, message: &str) {
    ui.label(RichText::new(message).color(ui.visuals().error_fg_color));
}

pub fn fields(ui: &mut Ui, id: &str, rows: &[(&str, &str)]) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            for (name, value) in rows {
                label(ui, name);
                ui.add(egui::Label::new(*value).selectable(true));
                ui.end_row();
            }
        });
}

pub fn status(ui: &mut Ui, name: &str, task: &Task<bool>, yes: &str, no: &str) {
    ui.horizontal(|ui| {
        ui.set_min_width(150.0);
        label(ui, name);
        match task {
            Task::Idle => label(ui, "-"),
            Task::Busy => spinner(ui),
            Task::Done(Ok(true)) => {
                ui.label(RichText::new(yes).color(GOOD));
            }
            Task::Done(Ok(false)) => {
                ui.label(RichText::new(no).color(ui.visuals().warn_fg_color));
            }
            Task::Done(Err(message)) => {
                ui.label(RichText::new(first_line(message)).color(ui.visuals().error_fg_color))
                    .on_hover_text(message);
            }
        }
    });
}

pub fn outcome(ui: &mut Ui, task: &Task<()>, done: &str) {
    match task {
        Task::Idle => {}
        Task::Busy => spinner(ui),
        Task::Done(Ok(())) => {
            ui.label(RichText::new(done).color(GOOD));
        }
        Task::Done(Err(message)) => {
            ui.label(RichText::new(first_line(message)).color(ui.visuals().error_fg_color))
                .on_hover_text(message);
        }
    }
}

pub fn spinner(ui: &mut Ui) {
    ui.add(egui::Spinner::new().size(14.0));
}

pub fn plist(ui: &mut Ui, text: &str) {
    egui::ScrollArea::vertical()
        .max_height(260.0)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.add(egui::Label::new(RichText::new(text).monospace()).selectable(true));
        });
}

fn first_line(message: &str) -> &str {
    message.lines().next().unwrap_or_default()
}
