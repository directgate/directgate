/*
 * @file directgate-manager/src-tauri/src/lib.rs
 * @brief DirectGate Manager backend: Tauri commands for device pairing and service control.
 *
 *  Copyright (c) 2025-2026 DirectGate. All rights reserved.
 *  Author: Sandro Kalatozishvili (sandro@directgate.io)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! DirectGate Manager backend.
//!
//! Exposes these Tauri commands to the frontend:
//!   - `pair_device`        -> runs the DirectGate agent to enroll a device
//!   - `get_pairing_status` -> reports Paired / Unpaired / Unknown (from config)
//!   - `get_service_status` -> reports Running / Stopped / NotInstalled / Unknown
//!   - `start_service`      -> starts the existing service (elevated if needed)
//!   - `stop_service`       -> stops the existing service (elevated if needed)
//!   - `restart_service`    -> restarts the existing service (elevated if needed)
//!
//! The app never installs the service and never requests admin privileges for
//! pairing; elevation is requested only for service start/stop/restart.

mod service;

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

// The pseudo-terminal path is only used off Windows: on Linux/macOS the agent
// reads the password via `tcgetattr`, which requires a real TTY. On Windows it
// reads stdin with plain `fgets`, so a normal pipe works (see `run_pairing`).
#[cfg(not(windows))]
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
#[cfg(not(windows))]
use std::io::Read;

/// Builds a `Command` that does not pop a console window on Windows. On other
/// platforms this is just `Command::new`.
pub(crate) fn hidden_command<S: AsRef<OsStr>>(program: S) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Executable name of the DirectGate agent for the current platform.
fn agent_exe_name() -> &'static str {
    if cfg!(windows) {
        "directgate.exe"
    } else {
        "directgate"
    }
}

/// Platform default install locations checked when the agent is not on PATH.
fn agent_default_paths() -> &'static [&'static str] {
    #[cfg(target_os = "windows")]
    return &[r"C:\Program Files\DirectGate\directgate.exe"];
    #[cfg(target_os = "macos")]
    return &["/usr/local/bin/directgate", "/opt/homebrew/bin/directgate"];
    #[cfg(target_os = "linux")]
    return &["/usr/bin/directgate", "/usr/local/bin/directgate"];
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    return &[];
}

/// Locates the DirectGate agent binary: first on `PATH`, then platform defaults.
fn find_agent() -> Option<PathBuf> {
    let exe = agent_exe_name();

    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(exe);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    for path in agent_default_paths() {
        let candidate = Path::new(path);
        if candidate.is_file() {
            return Some(candidate.to_path_buf());
        }
    }

    None
}

/// Pairs (enrolls) this device by invoking:
///   `directgate -sed <deviceId> -t <pairingToken>`
///
/// The `-s` flag makes the agent set up an SRP auth password, which it reads
/// only from a real terminal (`tcgetattr`). The agent is therefore driven
/// through a pseudo-terminal and the password is fed to its two prompts.
///
/// The token and password are passed straight to the agent and are never logged
/// or persisted by this app.
///
/// Declared `async` so Tauri runs it on a worker thread: the body blocks on PTY
/// I/O and `child.wait()`, and a plain sync command would block the main thread
/// and freeze the window ("Not responding" on Windows).
#[tauri::command(async)]
fn pair_device(
    device_id: String,
    pairing_token: String,
    auth_password: String,
) -> Result<String, String> {
    let device_id = device_id.trim();
    let pairing_token = pairing_token.trim();

    if device_id.is_empty() {
        return Err("Device ID is required.".into());
    }
    if pairing_token.is_empty() {
        return Err("Pairing token is required.".into());
    }
    // The password is preserved exactly as typed (it is being set here).
    if auth_password.trim().is_empty() {
        return Err("Auth password is required.".into());
    }

    let agent = find_agent().ok_or_else(|| {
        "DirectGate agent binary was not found. Install the DirectGate Agent or \
         add 'directgate' to your PATH."
            .to_string()
    })?;

    run_pairing(&agent, device_id, pairing_token, &auth_password)
}

/// Runs the agent inside a pseudo-terminal and answers its SRP password prompts.
///
/// Used on Linux/macOS, where the agent reads the password through `tcgetattr`
/// and therefore requires a real terminal. Windows uses a plain-pipe variant.
#[cfg(not(windows))]
fn run_pairing(
    agent: &Path,
    device_id: &str,
    pairing_token: &str,
    auth_password: &str,
) -> Result<String, String> {
    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("Failed to allocate a pseudo-terminal: {e}"))?;

    // Argument array (no shell): -sed bundles -s -e -d <id>, then -t <token>.
    // CommandBuilder inherits this process's environment (HOME, etc.) so the
    // agent resolves its config path correctly.
    let mut cmd = CommandBuilder::new(agent);
    cmd.arg("-sed");
    cmd.arg(device_id);
    cmd.arg("-t");
    cmd.arg(pairing_token);

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| format!("Failed to run the DirectGate agent: {e}"))?;

    // Close our handle to the slave so the master reaches EOF once the child
    // exits.
    drop(pair.slave);

    // Answer both prompts ("Set new auth password:" then "Repeat password:").
    {
        let mut writer = pair
            .master
            .take_writer()
            .map_err(|e| format!("Failed to access the pseudo-terminal: {e}"))?;
        let line = format!("{auth_password}\n{auth_password}\n");
        writer
            .write_all(line.as_bytes())
            .map_err(|e| format!("Failed to send the auth password: {e}"))?;
        writer.flush().ok();
    }

    // Drain the PTY output in a separate thread. On Windows, ConPTY does not
    // signal EOF when the child exits — the read pipe stays open until the
    // master handle is closed. We therefore wait for the child first, then
    // drop the master to unblock the reader thread.
    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("Failed to read from the pseudo-terminal: {e}"))?;
    let reader_thread = std::thread::spawn(move || {
        let mut raw = Vec::new();
        reader.read_to_end(&mut raw).ok();
        raw
    });

    let status = child
        .wait()
        .map_err(|e| format!("Failed to wait for the DirectGate agent: {e}"))?;

    // Closing the master forces ConPTY (Windows) to flush and close the pipe,
    // which unblocks the reader thread above.
    drop(pair.master);

    let raw = reader_thread.join().unwrap_or_default();

    if status.success() {
        // The agent's transcript can contain the password echoed back by the
        // pty before echo was disabled, so never surface it on success.
        Ok("Device paired successfully.".to_string())
    } else {
        // On failure the transcript is useful for diagnosis, but redact the
        // password in case the terminal echoed it.
        let text = redact(&sanitize_output(&String::from_utf8_lossy(&raw)), auth_password);
        Err(if text.is_empty() {
            format!("Pairing failed (exit {}).", status.exit_code())
        } else {
            format!("Pairing failed: {text}")
        })
    }
}

/// Windows variant: drives the agent through plain pipes instead of a ConPTY.
///
/// On Windows the agent reads the password with `fgets(stdin)` — no terminal is
/// required — so a normal stdin pipe is both sufficient and far more reliable
/// than a pseudo-console (ConPTY's terminal emulation can hang the read).
#[cfg(windows)]
fn run_pairing(
    agent: &Path,
    device_id: &str,
    pairing_token: &str,
    auth_password: &str,
) -> Result<String, String> {
    use std::process::Stdio;

    // Pair into the machine-wide config the service reads (see
    // `agent_config_path`). Without `-c`, the agent would write to the
    // per-user %APPDATA%, which the service account cannot read.
    let config_path = agent_config_path()
        .ok_or_else(|| "Could not determine the agent config path.".to_string())?;

    // -sed bundles -s -e -d <id>, then -t <token>. `hidden_command` sets
    // CREATE_NO_WINDOW so no console window flashes. Stdio is piped so we can
    // feed the password and capture the transcript.
    let mut child = hidden_command(agent)
        .arg("-c")
        .arg(&config_path)
        .arg("-sed")
        .arg(device_id)
        .arg("-t")
        .arg(pairing_token)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run the DirectGate agent: {e}"))?;

    // Answer both prompts ("Set new auth password:" then "Repeat password:"),
    // then drop stdin so any further read sees EOF instead of blocking.
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "Failed to access the agent's stdin.".to_string())?;
        let line = format!("{auth_password}\n{auth_password}\n");
        stdin
            .write_all(line.as_bytes())
            .map_err(|e| format!("Failed to send the auth password: {e}"))?;
        stdin.flush().ok();
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for the DirectGate agent: {e}"))?;

    if output.status.success() {
        Ok("Device paired successfully.".to_string())
    } else {
        // Combine stdout+stderr for diagnostics, then redact the password in
        // case it was echoed anywhere.
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        let text = redact(&sanitize_output(&combined), auth_password);
        Err(if text.is_empty() {
            match output.status.code() {
                Some(code) => format!("Pairing failed (exit {code})."),
                None => "Pairing failed.".to_string(),
            }
        } else {
            format!("Pairing failed: {text}")
        })
    }
}

/// Replaces every occurrence of `secret` in `text` so a password never leaks
/// into a message or log, even if a terminal echoed it.
fn redact(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "***")
}

/// Strips ANSI escape sequences and carriage returns from terminal output so it
/// reads cleanly in the UI.
fn sanitize_output(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip a CSI sequence: ESC '[' ... <final byte in @..~>
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if ('@'..='~').contains(&n) {
                        break;
                    }
                }
            }
            continue;
        }
        if c != '\r' {
            out.push(c);
        }
    }
    out.trim().to_string()
}

// `status` shells out to `sc.exe`/`systemctl`; start/stop/restart block on an
// elevation (UAC) prompt. All run off the main thread (`async`) so the window
// stays responsive while they wait.
#[tauri::command(async)]
fn get_service_status() -> Result<String, String> {
    Ok(service::status().label().to_string())
}

#[tauri::command(async)]
fn start_service() -> Result<String, String> {
    service::start()
}

#[tauri::command(async)]
fn stop_service() -> Result<String, String> {
    service::stop()
}

#[tauri::command(async)]
fn restart_service() -> Result<String, String> {
    service::restart()
}

/// Opens an external URL in the user's default browser. Used by the "add a
/// device" link in the pairing form so the in-app webview never navigates away
/// from the manager UI.
///
/// Restricted to `https://` URLs so the command can never be coerced into
/// launching a local program or an arbitrary protocol handler.
#[tauri::command(async)]
fn open_url(url: String) -> Result<(), String> {
    let url = url.trim();
    if !url.starts_with("https://") {
        return Err("Only https URLs can be opened.".into());
    }

    // rundll32's FileProtocolHandler opens the URL in the default browser
    // without going through cmd.exe (no shell metacharacter parsing).
    #[cfg(target_os = "windows")]
    let result = hidden_command("rundll32.exe")
        .arg("url.dll,FileProtocolHandler")
        .arg(url)
        .spawn();
    #[cfg(target_os = "macos")]
    let result = Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let result = Command::new("xdg-open").arg(url).spawn();

    result
        .map(|_| ())
        .map_err(|e| format!("Failed to open the browser: {e}"))
}

/// Reports whether this device is already enrolled, by reading the agent's
/// config file (the same default path the agent uses). Returns "Paired",
/// "Unpaired", or "Unknown".
#[tauri::command]
fn get_pairing_status() -> Result<String, String> {
    let path = match agent_config_path() {
        Some(p) => p,
        None => return Ok("Unknown".into()),
    };

    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        // No config yet -> the device has never been paired.
        Err(_) => return Ok("Unpaired".into()),
    };

    let json: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(_) => return Ok("Unknown".into()),
    };

    let enrolled = json
        .get("enrollment")
        .and_then(|e| e.get("enrolled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(if enrolled {
        "Paired".into()
    } else {
        "Unpaired".into()
    })
}

/// Canonical agent config path this app pairs into and reads status from.
///
/// On Windows this is the **machine-wide** location under `%PROGRAMDATA%`
/// (`C:\ProgramData\directgate\agent.json`), matching the service install in
/// docs/windows.md (`sc.exe create ... -c C:\ProgramData\directgate\agent.json`).
/// The agent's own default is the per-user `%APPDATA%`, but a service account
/// cannot read the interactive user's roaming profile — so pairing and the
/// service must agree on the all-users path, not the per-user default.
#[cfg(windows)]
fn agent_config_path() -> Option<PathBuf> {
    let base = std::env::var_os("PROGRAMDATA")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    Some(base.join("directgate").join("agent.json"))
}

#[cfg(not(windows))]
fn agent_config_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|s| !s.is_empty())?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("directgate")
            .join("agent.json"),
    )
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // On some Linux GPU/driver combinations (and many VMs) WebKitGTK's DMABUF
    // renderer fails to allocate a GBM buffer — the window opens blank/gray and
    // the log shows "Failed to create GBM buffer ... Invalid argument".
    // Disabling the DMABUF renderer falls back to a path that renders fine.
    // Set it before GTK/WebKit initializes, and only if the user has not
    // already chosen a value so they can still override the workaround.
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
    }

    // One-time startup hook. On Linux bare window managers this pre-launches a
    // PolicyKit agent so it has registered before the user clicks Start/Stop.
    service::prepare();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            pair_device,
            get_pairing_status,
            get_service_status,
            start_service,
            stop_service,
            restart_service,
            open_url
        ])
        .run(tauri::generate_context!())
        .expect("error while running DirectGate Manager");
}
