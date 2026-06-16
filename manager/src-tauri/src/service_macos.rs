/*
 * @file directgate-manager/src-tauri/src/service_macos.rs
 * @brief macOS service control via launchd (osascript elevation).
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

//! macOS service control via launchd.
//!
//! A per-user LaunchAgent is preferred; if a system LaunchDaemon is detected
//! instead, privileged actions are wrapped in `osascript ... with
//! administrator privileges` so macOS shows the standard auth dialog.
//!
//!   LaunchAgent (gui/<uid>/io.directgate.agent):
//!     status: launchctl print gui/<uid>/io.directgate.agent
//!     start:  launchctl kickstart -k gui/<uid>/io.directgate.agent
//!     stop:   launchctl bootout   gui/<uid>/io.directgate.agent
//!
//!   LaunchDaemon (system/io.directgate.agent):
//!     status: launchctl print system/io.directgate.agent
//!     start:  osascript -e 'do shell script "launchctl kickstart -k system/io.directgate.agent" with administrator privileges'
//!     stop:   osascript -e 'do shell script "launchctl bootout   system/io.directgate.agent" with administrator privileges'

use super::ServiceStatus;
use crate::hidden_command;
use std::process::Output;

const LABEL: &str = "io.directgate.agent";

fn current_uid() -> String {
    hidden_command("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn agent_target() -> String {
    format!("gui/{}/{}", current_uid(), LABEL)
}

fn system_target() -> String {
    format!("system/{LABEL}")
}

fn launchctl_print(target: &str) -> Option<Output> {
    hidden_command("launchctl")
        .args(["print", target])
        .output()
        .ok()
}

/// Returns the loaded service's launchd target and its `print` output, trying
/// the per-user agent domain first, then the system daemon domain.
fn detect() -> Option<(String, Output)> {
    let agent = agent_target();
    if let Some(out) = launchctl_print(&agent) {
        if out.status.success() {
            return Some((agent, out));
        }
    }

    let system = system_target();
    if let Some(out) = launchctl_print(&system) {
        if out.status.success() {
            return Some((system, out));
        }
    }

    None
}

fn is_running(print_output: &Output) -> bool {
    let text = String::from_utf8_lossy(&print_output.stdout);
    if text.contains("state = running") {
        return true;
    }
    // A live job always reports a pid; "not running" jobs do not.
    text.lines()
        .any(|line| line.trim_start().starts_with("pid = "))
}

/// No startup preparation needed on macOS (launchd is always present).
pub fn prepare() {}

pub fn status() -> ServiceStatus {
    match detect() {
        None => ServiceStatus::NotInstalled,
        Some((_, out)) => {
            if is_running(&out) {
                ServiceStatus::Running
            } else {
                ServiceStatus::Stopped
            }
        }
    }
}

pub fn start() -> Result<String, String> {
    let (target, _) = detect().ok_or_else(|| super::NOT_INSTALLED_MSG.to_string())?;
    run_launchctl(&target, &["kickstart", "-k", target.as_str()])?;
    Ok("DirectGate service started.".into())
}

pub fn stop() -> Result<String, String> {
    let (target, _) = detect().ok_or_else(|| super::NOT_INSTALLED_MSG.to_string())?;
    run_launchctl(&target, &["bootout", target.as_str()])?;
    Ok("DirectGate service stopped.".into())
}

pub fn restart() -> Result<String, String> {
    // `kickstart -k` kills the running instance and starts it again.
    let (target, _) = detect().ok_or_else(|| super::NOT_INSTALLED_MSG.to_string())?;
    run_launchctl(&target, &["kickstart", "-k", target.as_str()])?;
    Ok("DirectGate service restarted.".into())
}

/// Runs a launchctl subcommand. System-domain targets are elevated through
/// `osascript`; user-domain (gui) targets run directly without elevation.
fn run_launchctl(target: &str, args: &[&str]) -> Result<(), String> {
    if target.starts_with("system/") {
        // Re-join the launchctl invocation as a single shell string for
        // osascript. All components are app-controlled constants (no user
        // input), so there is nothing to inject here.
        let shell_cmd = format!("launchctl {}", args.join(" "));
        run_osascript_admin(&shell_cmd)
    } else {
        let output = hidden_command("launchctl")
            .args(args)
            .output()
            .map_err(|e| format!("Failed to launch launchctl: {e}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let code = output.status.code().unwrap_or(-1);
        Err(if stderr.is_empty() {
            format!("launchctl failed (exit {code}).")
        } else {
            stderr
        })
    }
}

fn run_osascript_admin(shell_cmd: &str) -> Result<(), String> {
    let script = format!("do shell script \"{shell_cmd}\" with administrator privileges");
    let output = hidden_command("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("Failed to launch osascript: {e}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    // AppleScript reports a user-cancelled auth dialog as error -128.
    if stderr.contains("-128") || stderr.to_lowercase().contains("cancel") {
        return Err("Authorization was cancelled.".into());
    }
    Err(if stderr.is_empty() {
        "Operation failed.".into()
    } else {
        stderr
    })
}
