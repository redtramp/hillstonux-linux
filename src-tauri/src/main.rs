//! Hillstonux GUI binary entry point.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    hillstonux_gui_lib::build_app()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
