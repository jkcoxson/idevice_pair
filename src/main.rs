#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod backend;
mod known_apps;
mod logging;
mod ui;

use eframe::egui;

fn main() -> eframe::Result {
    let logs = logging::init();

    eframe::run_native(
        &format!("idevice pair v{}", env!("CARGO_PKG_VERSION")),
        native_options(),
        Box::new(|cc| {
            ui::setup(&cc.egui_ctx);
            Ok(Box::new(app::App::new(&cc.egui_ctx, logs)))
        }),
    )
}

fn native_options() -> eframe::NativeOptions {
    let viewport = egui::ViewportBuilder::default().with_inner_size([760.0, 620.0]);

    #[cfg(not(target_os = "macos"))]
    let viewport = {
        let icon = eframe::icon_data::from_png_bytes(include_bytes!("../icon.png"))
            .expect("bad icon data");
        viewport.with_icon(std::sync::Arc::new(icon))
    };

    eframe::NativeOptions {
        viewport,
        ..Default::default()
    }
}
