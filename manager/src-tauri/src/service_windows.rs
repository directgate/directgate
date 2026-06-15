/*
 * @file directgate-manager/src-tauri/src/service_windows.rs
 * @brief Windows service control via the Service Control Manager (sc.exe, UAC elevation).
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

//! Windows service control via the Service Control Manager (`sc.exe`).
//!
//!   status: `sc.exe query directgate-agent`        (no elevation needed)
//!   start:  `sc.exe start directgate-agent`        (elevated via UAC)
//!   stop:   `sc.exe stop  directgate-agent`        (elevated via UAC)
//!
//! Start/stop are launched through the `runas` crate, which uses
//! `ShellExecuteW` with the "runas" verb to trigger the UAC consent prompt.

use super::ServiceStatus;
use crate::hidden_command;

const SERVICE: &str = "directgate-agent";

// Win32 error: the specified service does not exist as an installed service.
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
// Win32 error: access is denied.
const ERROR_ACCESS_DENIED: i32 = 5;

/// No startup preparation needed on Windows (UAC handles elevation directly).
pub fn prepare() {}

pub fn status() -> ServiceStatus {
    let output = match hidden_command("sc.exe").args(["query", SERVICE]).output() {
        Ok(out) => out,
        Err(_) => return ServiceStatus::Unknown,
    };

    if !output.status.success() {
        return match output.status.code() {
            Some(ERROR_SERVICE_DOES_NOT_EXIST) => ServiceStatus::NotInstalled,
            _ => ServiceStatus::Unknown,
        };
    }

    let text = String::from_utf8_lossy(&output.stdout);
    if text.contains("RUNNING") || text.contains("START_PENDING") {
        ServiceStatus::Running
    } else if text.contains("STOPPED")
        || text.contains("STOP_PENDING")
        || text.contains("PAUSED")
    {
        ServiceStatus::Stopped
    } else {
        ServiceStatus::Unknown
    }
}

pub fn start() -> Result<String, String> {
    elevate_sc(&["start", SERVICE])?;
    Ok("DirectGate service start requested.".into())
}

pub fn stop() -> Result<String, String> {
    elevate_sc(&["stop", SERVICE])?;
    Ok("DirectGate service stop requested.".into())
}

pub fn restart() -> Result<String, String> {
    // sc.exe has no atomic restart, so use PowerShell's Restart-Service in a
    // single elevated invocation (one UAC prompt). The service name is a fixed
    // constant, so there is nothing to inject.
    let script = format!(
        "try {{ Restart-Service -Name '{SERVICE}' -Force -ErrorAction Stop }} catch {{ exit 1 }}"
    );
    let status = runas::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", script.as_str()])
        .gui(true)
        .status()
        .map_err(|e| {
            format!("Could not obtain administrator privileges (the UAC prompt may have been cancelled): {e}")
        })?;

    if status.success() {
        return Ok("DirectGate service restarted.".into());
    }
    match status.code() {
        Some(code) => Err(format!("Service restart failed (exit {code}).")),
        None => Err("PowerShell terminated unexpectedly.".into()),
    }
}

/// Runs `sc.exe <args>` elevated. The elevated process runs in its own context
/// so only its exit code is available (stdout cannot be captured across the
/// privilege boundary).
fn elevate_sc(args: &[&str]) -> Result<(), String> {
    let status = runas::Command::new("sc.exe")
        .args(args)
        .gui(true) // no flashing console window
        .status()
        .map_err(|e| {
            format!("Could not obtain administrator privileges (the UAC prompt may have been cancelled): {e}")
        })?;

    if status.success() {
        return Ok(());
    }

    match status.code() {
        Some(ERROR_SERVICE_DOES_NOT_EXIST) => Err(super::NOT_INSTALLED_MSG.into()),
        Some(ERROR_ACCESS_DENIED) => Err("Access denied.".into()),
        Some(code) => Err(format!("sc.exe failed (exit {code}).")),
        None => Err("sc.exe terminated unexpectedly.".into()),
    }
}
