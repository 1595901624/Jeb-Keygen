#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use slint::{PhysicalPosition, WindowPosition};
mod kengen;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    ui.window()
        .set_position(WindowPosition::Physical(PhysicalPosition::new(400, 400)));

    let ui_handle = ui.as_weak();
    ui.on_generate_license_key_click(move || {
        let ui = ui_handle.unwrap();
        if ui.get_license_data().is_empty() {
            ui.set_license_key("License Data is empty!".into());
            return;
        }
        let license_key = kengen::calculate(&ui.get_license_data());
        if let Ok(key) = license_key {
            ui.set_license_key(key.into());
        } else {
            ui.set_license_key("Generate Error!".into());
        }
    });
    ui.run()
}
