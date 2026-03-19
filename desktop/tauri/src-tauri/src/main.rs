#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::menu::{MenuBuilder, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent, Wry};

const WINDOW_LABEL: &str = "main";
const TRAY_SHOW_ID: &str = "tray.show";
const TRAY_OPEN_TOP_ID: &str = "tray.open-top";
const TRAY_REFRESH_ID: &str = "tray.refresh";
const TRAY_STOP_AGENT_ID: &str = "tray.stop-agent";
const TRAY_QUIT_ID: &str = "tray.quit";

#[derive(Default)]
struct CompanionState {
    service: Mutex<Option<ManagedService>>,
    snapshot: Mutex<TraySnapshot>,
    tray: Mutex<Option<TrayState>>,
}

struct ManagedService {
    child: Child,
    url: String,
    token: String,
}

struct TrayState {
    headline_item: MenuItem<Wry>,
    counts_item: MenuItem<Wry>,
    top_action_item: MenuItem<Wry>,
    stop_item: MenuItem<Wry>,
}

impl Drop for CompanionState {
    fn drop(&mut self) {
        if let Ok(Some(service)) = self.service.get_mut() {
            let _ = service.child.kill();
            let _ = service.child.wait();
        }
    }
}

#[derive(Serialize)]
struct ServiceStatus {
    running: bool,
    url: Option<String>,
    token: Option<String>,
}

#[derive(Serialize)]
struct StopResult {
    stopped: bool,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TraySnapshot {
    headline: Option<String>,
    subtitle: Option<String>,
    active_count: Option<usize>,
    new_count: Option<usize>,
    changed_count: Option<usize>,
    triaged_count: Option<usize>,
    top_action_title: Option<String>,
    top_action_path: Option<String>,
    top_action_line: Option<u32>,
}

#[tauri::command]
fn start_agent_service(
    repo_path: String,
    binary: String,
    host: String,
    port: u16,
    token: String,
    limit: u16,
    refresh_on_start: bool,
    app: AppHandle,
    state: State<'_, CompanionState>,
) -> Result<ServiceStatus, String> {
    if repo_path.trim().is_empty() {
        return Err("repo_path is required".into());
    }

    let mut guard = state
        .service
        .lock()
        .map_err(|_| String::from("failed to acquire service state"))?;

    if let Some(service) = guard.as_mut() {
        if service
            .child
            .try_wait()
            .map_err(|err| err.to_string())?
            .is_none()
        {
            sync_tray(&app, &state)?;
            return Ok(ServiceStatus {
                running: true,
                url: Some(service.url.clone()),
                token: Some(service.token.clone()),
            });
        }
    }

    let url = format!("http://{}:{}", host, port);
    let executable = if binary.trim().is_empty() {
        String::from("skylos")
    } else {
        binary
    };

    let mut command = Command::new(executable);
    command
        .arg("agent")
        .arg("serve")
        .arg(repo_path)
        .arg("--host")
        .arg(host)
        .arg("--port")
        .arg(port.to_string())
        .arg("--token")
        .arg(token.clone())
        .arg("--limit")
        .arg(limit.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if refresh_on_start {
        command.arg("--refresh-on-start");
    }

    let child = command.spawn().map_err(|err| err.to_string())?;
    *guard = Some(ManagedService {
        child,
        url: url.clone(),
        token: token.clone(),
    });
    drop(guard);
    sync_tray(&app, &state)?;

    Ok(ServiceStatus {
        running: true,
        url: Some(url),
        token: Some(token),
    })
}

#[tauri::command]
fn service_status(
    app: AppHandle,
    state: State<'_, CompanionState>,
) -> Result<ServiceStatus, String> {
    let mut guard = state
        .service
        .lock()
        .map_err(|_| String::from("failed to acquire service state"))?;

    if let Some(service) = guard.as_mut() {
        if service
            .child
            .try_wait()
            .map_err(|err| err.to_string())?
            .is_none()
        {
            return Ok(ServiceStatus {
                running: true,
                url: Some(service.url.clone()),
                token: Some(service.token.clone()),
            });
        }
        *guard = None;
    }
    drop(guard);
    sync_tray(&app, &state)?;

    Ok(ServiceStatus {
        running: false,
        url: None,
        token: None,
    })
}

#[tauri::command]
fn stop_agent_service(
    app: AppHandle,
    state: State<'_, CompanionState>,
) -> Result<StopResult, String> {
    let result = stop_managed_service(&state)?;
    sync_tray(&app, &state)?;
    Ok(result)
}

#[tauri::command]
fn open_in_editor(file_path: String, line: u32) -> Result<bool, String> {
    if file_path.trim().is_empty() {
        return Err("file_path is required".into());
    }

    Ok(open_in_editor_internal(&file_path, line.max(1)))
}

#[tauri::command]
fn update_tray_snapshot(
    snapshot: TraySnapshot,
    app: AppHandle,
    state: State<'_, CompanionState>,
) -> Result<(), String> {
    let mut guard = state
        .snapshot
        .lock()
        .map_err(|_| String::from("failed to acquire tray snapshot state"))?;
    *guard = snapshot;
    drop(guard);
    sync_tray(&app, &state)
}

fn stop_managed_service(state: &CompanionState) -> Result<StopResult, String> {
    let mut guard = state
        .service
        .lock()
        .map_err(|_| String::from("failed to acquire service state"))?;

    let Some(mut service) = guard.take() else {
        return Ok(StopResult { stopped: false });
    };

    service.child.kill().map_err(|err| err.to_string())?;
    let _ = service.child.wait();

    Ok(StopResult { stopped: true })
}

fn sync_tray(app: &AppHandle, state: &CompanionState) -> Result<(), String> {
    let snapshot = state
        .snapshot
        .lock()
        .map_err(|_| String::from("failed to acquire tray snapshot state"))?
        .clone();
    let running = managed_service_running(state)?;

    let tray_guard = state
        .tray
        .lock()
        .map_err(|_| String::from("failed to acquire tray state"))?;
    let Some(tray) = tray_guard.as_ref() else {
        return Ok(());
    };

    let headline = snapshot
        .headline
        .as_deref()
        .unwrap_or("Skylos Command Center");
    let counts = format!(
        "{} active • {} new • {} changed • {} triaged",
        snapshot.active_count.unwrap_or(0),
        snapshot.new_count.unwrap_or(0),
        snapshot.changed_count.unwrap_or(0),
        snapshot.triaged_count.unwrap_or(0),
    );
    let top_action_label = snapshot
        .top_action_title
        .as_deref()
        .map(|title| format!("Open top action: {}", truncate_label(title, 56)))
        .unwrap_or_else(|| String::from("Open top action"));

    tray.headline_item
        .set_text(headline)
        .map_err(|err| err.to_string())?;
    tray.counts_item
        .set_text(&counts)
        .map_err(|err| err.to_string())?;
    tray.top_action_item
        .set_text(&top_action_label)
        .map_err(|err| err.to_string())?;
    tray.top_action_item
        .set_enabled(snapshot.top_action_path.is_some())
        .map_err(|err| err.to_string())?;
    tray.stop_item
        .set_enabled(running)
        .map_err(|err| err.to_string())?;

    if let Some(tray_icon) = app.tray_by_id("main") {
        let tooltip = snapshot
            .subtitle
            .as_deref()
            .map(|subtitle| truncate_label(subtitle, 90))
            .unwrap_or_else(|| counts.clone());
        let _ = tray_icon.set_tooltip(Some(tooltip));
    }

    Ok(())
}

fn managed_service_running(state: &CompanionState) -> Result<bool, String> {
    let mut guard = state
        .service
        .lock()
        .map_err(|_| String::from("failed to acquire service state"))?;

    let Some(service) = guard.as_mut() else {
        return Ok(false);
    };

    if service
        .child
        .try_wait()
        .map_err(|err| err.to_string())?
        .is_some()
    {
        *guard = None;
        return Ok(false);
    }

    Ok(true)
}

fn install_tray(app: &mut tauri::App<Wry>) -> tauri::Result<()> {
    let headline_item = MenuItem::with_id(
        app,
        "tray.headline",
        "Skylos Command Center",
        false,
        None::<&str>,
    )?;
    let counts_item = MenuItem::with_id(
        app,
        "tray.counts",
        "0 active • 0 new • 0 changed • 0 triaged",
        false,
        None::<&str>,
    )?;
    let top_action_item = MenuItem::with_id(
        app,
        TRAY_OPEN_TOP_ID,
        "Open top action",
        false,
        None::<&str>,
    )?;
    let stop_item = MenuItem::with_id(
        app,
        TRAY_STOP_AGENT_ID,
        "Stop managed agent",
        false,
        None::<&str>,
    )?;

    let menu = MenuBuilder::new(app)
        .item(&headline_item)
        .item(&counts_item)
        .separator()
        .item(&top_action_item)
        .separator()
        .text(TRAY_SHOW_ID, "Show Companion")
        .text(TRAY_REFRESH_ID, "Refresh Queue")
        .item(&stop_item)
        .separator()
        .text(TRAY_QUIT_ID, "Quit")
        .build()?;

    let mut tray_builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .menu_on_left_click(false)
        .tooltip("Skylos Command Center")
        .on_menu_event(|app, event| {
            if let Err(error) = handle_tray_menu_event(app, event) {
                eprintln!("tray action failed: {error}");
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let _ = toggle_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon().cloned() {
        tray_builder = tray_builder.icon(icon);
    }

    tray_builder.build(app)?;

    let state = app.state::<CompanionState>();
    let mut tray_guard = state
        .tray
        .lock()
        .map_err(|_| tauri::Error::AssetNotFound(String::from("failed to acquire tray state")))?;
    *tray_guard = Some(TrayState {
        headline_item,
        counts_item,
        top_action_item,
        stop_item,
    });
    drop(tray_guard);

    sync_tray(&app.handle(), &state).map_err(tauri::Error::AssetNotFound)
}

fn handle_tray_menu_event(app: &AppHandle, event: tauri::menu::MenuEvent) -> Result<(), String> {
    match event.id().as_ref() {
        TRAY_SHOW_ID => reveal_main_window(app),
        TRAY_OPEN_TOP_ID => open_top_action(app),
        TRAY_REFRESH_ID => {
            app.emit("skylos://refresh", ())
                .map_err(|err| err.to_string())?;
            reveal_main_window(app)
        }
        TRAY_STOP_AGENT_ID => {
            let state = app.state::<CompanionState>();
            let _ = stop_managed_service(&state)?;
            sync_tray(app, &state)?;
            app.emit("skylos://refresh", ())
                .map_err(|err| err.to_string())
        }
        TRAY_QUIT_ID => {
            app.exit(0);
            Ok(())
        }
        _ => Ok(()),
    }
}

fn open_top_action(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<CompanionState>();
    let snapshot = state
        .snapshot
        .lock()
        .map_err(|_| String::from("failed to acquire tray snapshot state"))?
        .clone();

    let Some(path) = snapshot.top_action_path else {
        return reveal_main_window(app);
    };

    if open_in_editor_internal(&path, snapshot.top_action_line.unwrap_or(1)) {
        return Ok(());
    }

    reveal_main_window(app)
}

fn reveal_main_window(app: &AppHandle) -> Result<(), String> {
    let Some(window) = app.get_webview_window(WINDOW_LABEL) else {
        return Err(String::from("main window is not available"));
    };

    if window.is_minimized().map_err(|err| err.to_string())? {
        window.unminimize().map_err(|err| err.to_string())?;
    }
    window.show().map_err(|err| err.to_string())?;
    window.set_focus().map_err(|err| err.to_string())
}

fn toggle_main_window(app: &AppHandle) -> Result<(), String> {
    let Some(window) = app.get_webview_window(WINDOW_LABEL) else {
        return Err(String::from("main window is not available"));
    };

    if window.is_visible().map_err(|err| err.to_string())? {
        return window.hide().map_err(|err| err.to_string());
    }

    reveal_main_window(app)
}

fn handle_window_event(window: &tauri::Window<Wry>, event: &WindowEvent) {
    if window.label() != WINDOW_LABEL {
        return;
    }

    if let WindowEvent::CloseRequested { api, .. } = event {
        api.prevent_close();
        let _ = window.hide();
    }
}

fn truncate_label(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }

    let truncated: String = value.chars().take(limit.saturating_sub(1)).collect();
    format!("{truncated}…")
}

fn open_in_editor_internal(file_path: &str, line: u32) -> bool {
    let target = format!("{}:{}", file_path, line.max(1));
    let editor_commands = [
        ("code", vec![String::from("--goto"), target.clone()]),
        ("cursor", vec![String::from("--goto"), target.clone()]),
        ("codium", vec![String::from("--goto"), target.clone()]),
        ("windsurf", vec![String::from("--goto"), target.clone()]),
    ];

    for (binary, args) in editor_commands {
        if command_succeeds(binary, &args) {
            return true;
        }
    }

    let file_only = vec![file_path.to_string()];
    #[cfg(target_os = "macos")]
    if command_succeeds("open", &file_only) {
        return true;
    }
    #[cfg(target_os = "linux")]
    if command_succeeds("xdg-open", &file_only) {
        return true;
    }
    #[cfg(target_os = "windows")]
    if command_succeeds(
        "cmd",
        &vec![String::from("/C"), String::from("start"), target],
    ) {
        return true;
    }

    false
}

fn command_succeeds(binary: &str, args: &[String]) -> bool {
    Command::new(binary)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn main() {
    tauri::Builder::default()
        .manage(CompanionState::default())
        .setup(|app| Ok(install_tray(app)?))
        .on_window_event(handle_window_event)
        .invoke_handler(tauri::generate_handler![
            start_agent_service,
            service_status,
            stop_agent_service,
            open_in_editor,
            update_tray_snapshot,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
