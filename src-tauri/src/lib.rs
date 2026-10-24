//! Hillstonux GUI library — exposes tray setup, profile/secret helpers, and
//! a Tauri builder function used by the `hillstonux-gui` binary.

pub mod commands;
pub mod config;
pub mod ipc_client;
pub mod profile;
pub mod secret;

use std::path::PathBuf;

use tauri::{Emitter, Listener, Manager};

use crate::ipc_client::{IpcClient, IpcRequestParams};
use hillstonux_daemon::ipc::{IpcResponse, VpnEvent, VpnStateDto};

/// Build the Tauri application. Called once from `main.rs`.
pub fn build_app() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .setup(|app| {
            install_tray(app.handle())?;
            install_daemon_bridge(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // Close button → hide to tray instead of quit.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::daemon_socket_path,
            commands::app_version,
            commands::load_profiles,
            commands::save_profiles,
            commands::save_password,
            commands::delete_password,
            commands::get_password,
            commands::load_config,
            commands::save_config,
            commands::vpn_connect,
            commands::vpn_disconnect,
            commands::vpn_state,
        ])
}

/// Create the shared `IpcClient`, register it in Tauri state, and spawn an
/// event-pump task that re-emits every daemon `VpnEvent` as a Tauri
/// `vpn-event` event.
///
/// The client is *lazily* connected (see `ipc_client::IpcClient`), so it is
/// always registered here at startup even when the daemon's socket does not
/// exist yet. Commands like `vpn_connect` therefore never hit "state not
/// managed"; the connection is established on first use / by the pump.
fn install_daemon_bridge(app: &tauri::AppHandle) -> tauri::Result<()> {
    let socket = PathBuf::from(daemon_socket_path_inner());

    // The client forwards every VpnEvent it receives from the daemon to this
    // channel; we re-emit each as a Tauri `vpn-event` for the Svelte side.
    let (evt_tx, mut evt_rx) =
        tokio::sync::mpsc::unbounded_channel::<hillstonux_daemon::ipc::VpnEvent>();
    let ipc = IpcClient::new(socket, evt_tx);

    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(evt) = evt_rx.recv().await {
            if let Err(e) = app_handle.emit("vpn-event", &evt) {
                tracing::warn!(?e, "failed to emit vpn-event");
            }
        }
        tracing::info!("vpn-event pump exited");
    });

    app.manage(ipc);
    Ok(())
}

fn daemon_socket_path_inner() -> String {
    if let Some(p) = std::env::var_os("HILLSTONUX_SOCKET") {
        return p.to_string_lossy().into_owned();
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let mut p = std::path::PathBuf::from(dir);
        p.push("hillstonux");
        p.push("hillstonux.sock");
        return p.to_string_lossy().into_owned();
    }
    "/tmp/hillstonux.sock".to_string()
}

/// Build and install the system tray icon. Called once at startup.
pub fn install_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::image::Image;
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    let show_item = MenuItem::with_id(app, "show", "显示窗口", true, None::<&str>)?;
    let toggle_item = MenuItem::with_id(app, "toggle", "连接", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show_item, &toggle_item, &quit_item])?;

    let icon_bytes = include_bytes!("../icons/icon.png");
    let img = Image::new_owned(icon_bytes.to_vec(), 32, 32);

    let tray = TrayIconBuilder::with_id("hillstonux-tray")
        .icon(img)
        .tooltip("Hillstonux VPN")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "toggle" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = tray_toggle(app).await {
                        tracing::warn!(?e, "tray toggle failed");
                    }
                });
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                if let Some(w) = tray.app_handle().get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
        })
        .build(app)?;

    // Reflect the VPN phase in the toggle menu label. The daemon pushes
    // StateChanged events on the `vpn-event` bus; rebuild the menu so the item
    // reads "Disconnect" while connected and "Connect" otherwise.
    let app_listen = app.clone();
    let tray_clone = tray.clone();
    let app_in_closure = app_listen.clone();
    app_listen.listen("vpn-event", move |event| {
        let Ok(VpnEvent::StateChanged { state }) =
            serde_json::from_str::<VpnEvent>(event.payload())
        else {
            return;
        };
        let label = match state {
            VpnStateDto::Connected { .. } => "断开",
            _ => "连接",
        };
        let Ok(show) = MenuItem::with_id(&app_in_closure, "show", "显示窗口", true, None::<&str>)
        else {
            return;
        };
        let Ok(toggle) = MenuItem::with_id(&app_in_closure, "toggle", label, true, None::<&str>)
        else {
            return;
        };
        let Ok(quit) = MenuItem::with_id(&app_in_closure, "quit", "退出", true, None::<&str>)
        else {
            return;
        };
        if let Ok(m) = Menu::with_items(&app_in_closure, &[&show, &toggle, &quit]) {
            let _ = tray_clone.set_menu(Some(m));
        }
    });

    Ok(())
}

/// Toggle the VPN connection from the tray menu. Connects using the persisted
/// login config when not already connected; disconnects when connected.
async fn tray_toggle(app: tauri::AppHandle) -> Result<(), String> {
    let ipc = app.state::<IpcClient>();
    let connected = match ipc.request(IpcRequestParams::State).await {
        Ok(IpcResponse::Ok { data: Some(v), .. }) => serde_json::from_value::<VpnStateDto>(v)
            .map(|d| matches!(d, VpnStateDto::Connected { .. }))
            .unwrap_or(false),
        _ => false,
    };
    if connected {
        ipc.request(IpcRequestParams::Disconnect)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        let cfg = crate::config::load().map_err(|e| e.to_string())?;
        ipc.request(IpcRequestParams::Connect {
            server: &cfg.server,
            port: cfg.port,
            user: &cfg.username,
            password: &cfg.password,
            password_ref: "",
            // 托盘菜单没有策略开关：用与 GUI 一致的分流默认值（外网保活）。
            full_tunnel: false,
        })
        .await
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}
