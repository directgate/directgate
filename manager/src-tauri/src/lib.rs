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
//!   - `get_agent_version`  -> the installed agent's release, from `directgate -v`
//!   - `check_for_update`   -> compares that release against the published one
//!
//! The app never installs the service and never requests admin privileges for
//! pairing; elevation is requested only for service start/stop/restart.

mod service;

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

// The pseudo-terminal path is only used off Windows: on Linux/macOS the agent
// reads the password via `tcgetattr`, which requires a real TTY. On Windows it
// reads stdin with plain `fgets`, so a normal pipe works (see
// `run_agent_with_password`).
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

    run_agent_with_password(
        &agent,
        &["-sed", device_id, "-t", pairing_token],
        &auth_password,
        "Pairing",
    )?;
    Ok("Device paired successfully.".to_string())
}

/// Changes the SRP auth password on an already-paired device by invoking
/// `directgate -s` (plus `-c <config>` on Windows). The agent prompts for the
/// new password twice; both prompts are answered with `auth_password`. The
/// device must already be paired - the agent reads its existing config.
///
/// `async` for the same reason as `pair_device` (blocking child I/O off the
/// main thread).
#[tauri::command(async)]
fn change_srp_password(auth_password: String) -> Result<String, String> {
    if auth_password.trim().is_empty() {
        return Err("Auth password is required.".into());
    }

    let agent = find_agent().ok_or_else(|| {
        "DirectGate agent binary was not found. Install the DirectGate Agent or \
         add 'directgate' to your PATH."
            .to_string()
    })?;

    run_agent_with_password(&agent, &["-s"], &auth_password, "Password change")?;
    Ok("Auth password changed.".to_string())
}

/// Runs the agent with `args` inside a pseudo-terminal and answers its two SRP
/// password prompts ("Set new auth password:" / "Repeat password:"), feeding
/// `auth_password` to both. Used by pairing and by the password change.
///
/// Used on Linux/macOS, where the agent reads the password through `tcgetattr`
/// and therefore requires a real terminal. Windows uses a plain-pipe variant.
/// `op_label` names the operation in error messages (e.g. "Pairing").
#[cfg(not(windows))]
fn run_agent_with_password(
    agent: &Path,
    args: &[&str],
    auth_password: &str,
    op_label: &str,
) -> Result<(), String> {
    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("Failed to allocate a pseudo-terminal: {e}"))?;

    // No shell: arguments are passed verbatim. CommandBuilder inherits this
    // process's environment (HOME, etc.) so the agent resolves its config path.
    let mut cmd = CommandBuilder::new(agent);
    for arg in args {
        cmd.arg(arg);
    }

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
    // signal EOF when the child exits - the read pipe stays open until the
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
        // pty before echo was disabled, so never surface it.
        Ok(())
    } else {
        // On failure the transcript is useful for diagnosis, but redact the
        // password in case the terminal echoed it.
        let text = redact(
            &sanitize_output(&String::from_utf8_lossy(&raw)),
            auth_password,
        );
        Err(if text.is_empty() {
            format!("{op_label} failed (exit {}).", status.exit_code())
        } else {
            format!("{op_label} failed: {text}")
        })
    }
}

/// Windows variant: drives the agent through plain pipes instead of a ConPTY.
///
/// On Windows the agent reads the password with `fgets(stdin)` - no terminal is
/// required - so a normal stdin pipe is both sufficient and far more reliable
/// than a pseudo-console (ConPTY's terminal emulation can hang the read).
///
/// `-c <config>` is prepended so the agent reads/writes the machine-wide config
/// the service uses; the per-user `%APPDATA%` is invisible to the service account.
#[cfg(windows)]
fn run_agent_with_password(
    agent: &Path,
    args: &[&str],
    auth_password: &str,
    op_label: &str,
) -> Result<(), String> {
    use std::process::Stdio;

    let config_path = agent_config_path()
        .ok_or_else(|| "Could not determine the agent config path.".to_string())?;

    // `hidden_command` sets CREATE_NO_WINDOW so no console window flashes; stdio
    // is piped so we can feed the password and capture the transcript.
    let mut command = hidden_command(agent);
    command.arg("-c").arg(&config_path);
    for arg in args {
        command.arg(arg);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
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
        Ok(())
    } else {
        // Combine stdout+stderr for diagnostics, then redact the password in
        // case it was echoed anywhere.
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        let text = redact(&sanitize_output(&combined), auth_password);
        Err(if text.is_empty() {
            match output.status.code() {
                Some(code) => format!("{op_label} failed (exit {code})."),
                None => format!("{op_label} failed."),
            }
        } else {
            format!("{op_label} failed: {text}")
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

// Service checks and control may block on system APIs or an elevation prompt.
// All run off the main thread (`async`) so the window stays responsive.
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

/*
 * Update checking.
 *
 * Windows has no package manager to notice a new release, so the manager has
 * to ask. It reads a small manifest published next to the installer by
 * pkg/release.sh, compares it with the agent actually installed here, and - at
 * most - offers a download link. It never downloads or installs anything on
 * its own: replacing the agent stops the service, which drops whatever remote
 * session the user is sitting in, so that has to stay their decision.
 *
 * Linux and macOS deliberately do not check. There the agent came from apt,
 * dnf or brew, and those know about updates already; a second opinion here
 * could only ever contradict the package manager or nag about an update the
 * user cannot apply from this window.
 */

/// Where the published manifest and the installer live.
#[cfg(windows)]
const UPDATE_MANIFEST_URL: &str = "https://pkg.directgate.io/win/latest-version";
#[cfg(windows)]
const UPDATE_DOWNLOAD_URL: &str = "https://pkg.directgate.io/win/directgate-latest-x64.msi";

/// A release, ordered the way releases are: numerically, field by field.
///
/// The build-channel tag (`-x64_msi`, `-amd64_deb`, `-brew_silicon`) is not
/// part of the ordering. It records where a build came from, not how new it
/// is, and comparing it as text would make `1.0.21-3-x64_msi` and the plain
/// `1.0.21-3` in the manifest look like different releases.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ReleaseVersion {
    major: u32,
    minor: u32,
    build: u32,
    pkg: u32,
}

/// Parses `MAJOR.MINOR.BUILD[-PKG][-tag]`, e.g. `1.0.21-3-x64_msi`.
///
/// A missing package revision reads as 0, which orders a bare `1.0.21` before
/// `1.0.21-1` - the same order the packaging uses.
fn parse_release_version(text: &str) -> Option<ReleaseVersion> {
    let text = text.trim().trim_start_matches('v');

    // Split the numeric head off any build tag: the revision is numeric, the
    // tag never is, so a field that does not parse simply leaves pkg at 0.
    let mut fields = text.split('-');
    let mut dotted = fields.next()?.split('.');

    let major = dotted.next()?.trim().parse().ok()?;
    let minor = dotted.next()?.trim().parse().ok()?;
    let build = dotted.next()?.trim().parse().ok()?;
    let pkg = fields
        .next()
        .and_then(|f| f.trim().parse().ok())
        .unwrap_or(0);

    Some(ReleaseVersion {
        major,
        minor,
        build,
        pkg,
    })
}

/// What the version line in the footer should say.
#[derive(serde::Serialize)]
struct UpdateInfo {
    /// Release of the agent installed here, `None` when it could not be read.
    installed: Option<String>,
    /// Release currently published, `None` when the check did not get that far.
    latest: Option<String>,
    /// `current` | `outdated` | `ahead` | `unknown` | `unsupported`
    state: String,
    /// Download link, only set when there is something newer to download.
    url: Option<String>,
    /// MD5 of the published installer, for a user who wants to verify it.
    md5: Option<String>,
    /// Whether checking is possible at all on this platform.
    supported: bool,
    /// Why a check could not be completed; shown as-is when state is `unknown`.
    detail: Option<String>,
}

/// Reads the installed agent's release string by running `directgate -v`,
/// whose output is `DirectGate agent: v<release>`.
fn installed_release() -> Result<String, String> {
    use std::process::Stdio;

    let agent = find_agent().ok_or_else(|| "DirectGate agent binary was not found.".to_string())?;

    let output = hidden_command(&agent)
        .arg("-v")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to run the DirectGate agent: {e}"))?;

    let text = String::from_utf8_lossy(&output.stdout);

    // Take the last whitespace-separated token of the first non-empty line and
    // drop its leading "v", rather than matching the whole sentence - the
    // banner's wording is not something this has to stay in step with.
    let token = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .and_then(|line| line.split_whitespace().last())
        .map(|token| token.trim_start_matches('v').to_string())
        .filter(|token| !token.is_empty())
        .ok_or_else(|| "The DirectGate agent did not report a version.".to_string())?;

    if parse_release_version(&token).is_none() {
        return Err(format!("Unrecognised agent version: {token}"));
    }

    Ok(token)
}

/// The installed agent's release, for the version line in the footer.
#[tauri::command(async)]
fn get_agent_version() -> Result<String, String> {
    installed_release()
}

/// Fetches a small text document over HTTPS.
///
/// Shells out to the system `curl` rather than linking an HTTP stack: this is
/// one plain GET of a few dozen bytes on a user-initiated action, and curl has
/// shipped in Windows since 1803 - well below anything the agent itself runs
/// on. It buys no TLS library, no async runtime, and nothing new to keep
/// patched in a program whose whole job is remote access.
///
/// The path is absolute on purpose. CreateProcess searches the calling
/// program's own directory before the system one, so a bare "curl" would let
/// anything that can drop a file next to the manager decide what runs here.
#[cfg(windows)]
fn http_get_text(url: &str) -> Result<String, String> {
    use std::process::Stdio;

    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let curl = PathBuf::from(system_root).join(r"System32\curl.exe");

    if !curl.is_file() {
        return Err("curl.exe was not found in System32.".to_string());
    }

    let output = hidden_command(&curl)
        .arg("--fail")
        .arg("--silent")
        .arg("--show-error")
        .arg("--location")
        .arg("--max-time")
        .arg("10")
        .arg("--")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Could not run curl: {e}"))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if err.is_empty() {
            "Could not reach the update server.".to_string()
        } else {
            err
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Reads one key from the flat `key=value` manifest. Unknown keys and blank or
/// commented lines are ignored, so the manifest can gain fields without
/// breaking managers already installed.
#[cfg(windows)]
fn manifest_value(manifest: &str, key: &str) -> Option<String> {
    for line in manifest.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((name, value)) = line.split_once('=') {
            if name.trim() == key {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }

    None
}

/// A result that says "could not tell", which is a normal outcome for a check
/// that runs unprompted on every launch.
#[cfg(windows)]
fn update_unknown(installed: Option<String>, detail: &str) -> UpdateInfo {
    UpdateInfo {
        installed,
        latest: None,
        state: "unknown".into(),
        url: None,
        md5: None,
        supported: true,
        detail: Some(detail.to_string()),
    }
}

/// Compares the installed agent against the published manifest.
///
/// Never returns Err: this runs on every launch, and a version footer that
/// could not reach the network is a footer that says so, not an error the user
/// has to dismiss before using the rest of the window.
#[cfg(windows)]
#[tauri::command(async)]
fn check_for_update() -> Result<UpdateInfo, String> {
    let installed = installed_release().ok();

    let manifest = match http_get_text(UPDATE_MANIFEST_URL) {
        Ok(text) => text,
        Err(err) => return Ok(update_unknown(installed, &err)),
    };

    let latest_text = match manifest_value(&manifest, "version") {
        Some(value) => value,
        None => {
            return Ok(update_unknown(
                installed,
                "The update server returned an unreadable manifest.",
            ))
        }
    };

    let latest_version = match parse_release_version(&latest_text) {
        Some(value) => value,
        None => {
            return Ok(update_unknown(
                installed,
                "The update server returned an unreadable version.",
            ))
        }
    };

    let installed_version = match installed.as_deref().and_then(parse_release_version) {
        Some(value) => value,
        None => {
            return Ok(update_unknown(
                installed,
                "Could not read the installed agent version.",
            ))
        }
    };

    // Only ever hand the frontend a link to our own package host. The manifest
    // arrives over the network and its url is the one field in it that turns
    // into something the user is invited to click.
    let url = match manifest_value(&manifest, "url") {
        Some(value) if value.starts_with("https://pkg.directgate.io/") => value,
        _ => UPDATE_DOWNLOAD_URL.to_string(),
    };

    // "ahead" is a normal state on a development machine, and saying so is more
    // use than claiming a local build is out of date.
    let outdated = installed_version < latest_version;
    let state = if outdated {
        "outdated"
    } else if installed_version > latest_version {
        "ahead"
    } else {
        "current"
    };

    Ok(UpdateInfo {
        installed,
        latest: Some(latest_text),
        state: state.into(),
        url: if outdated { Some(url) } else { None },
        md5: if outdated {
            manifest_value(&manifest, "md5")
        } else {
            None
        },
        supported: true,
        detail: None,
    })
}

/// Nothing to check where a package manager owns the agent; the footer shows
/// the installed version and no update controls.
#[cfg(not(windows))]
#[tauri::command(async)]
fn check_for_update() -> Result<UpdateInfo, String> {
    Ok(UpdateInfo {
        installed: installed_release().ok(),
        latest: None,
        state: "unsupported".into(),
        url: None,
        md5: None,
        supported: false,
        detail: None,
    })
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

    open_browser_url(url)
}

#[cfg(windows)]
fn open_browser_url(url: &str) -> Result<(), String> {
    const SW_SHOWNORMAL: i32 = 1;

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteW(
            hwnd: *mut c_void,
            operation: *const u16,
            file: *const u16,
            parameters: *const u16,
            directory: *const u16,
            show_cmd: i32,
        ) -> *mut c_void;
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    let operation = wide("open");
    let file = wide(url);
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    } as isize;

    if result <= 32 {
        return Err(format!(
            "Failed to open the browser (ShellExecuteW error {result})."
        ));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn open_browser_url(url: &str) -> Result<(), String> {
    Command::new("open")
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Failed to open the browser: {e}"))
}

#[cfg(target_os = "linux")]
fn open_browser_url(url: &str) -> Result<(), String> {
    Command::new("xdg-open")
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Failed to open the browser: {e}"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn open_browser_url(_url: &str) -> Result<(), String> {
    Err("Opening a browser is not supported on this platform.".into())
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
/// cannot read the interactive user's roaming profile - so pairing and the
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
    if let Some(code) = service::run_elevated_action_if_requested() {
        std::process::exit(code);
    }

    // On some Linux GPU/driver combinations (and many VMs) WebKitGTK's DMABUF
    // renderer fails to allocate a GBM buffer - the window opens blank/gray and
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
            change_srp_password,
            get_pairing_status,
            get_service_status,
            start_service,
            stop_service,
            restart_service,
            get_agent_version,
            check_for_update,
            open_url
        ])
        .run(tauri::generate_context!())
        .expect("error while running DirectGate Manager");
}
