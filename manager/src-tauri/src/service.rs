/*
 * @file directgate-manager/src-tauri/src/service.rs
 * @brief Cross-platform service-control dispatch for the DirectGate agent.
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

//! Cross-platform service control for the DirectGate agent.
//!
//! Each OS has its own implementation selected via `cfg(target_os = ...)`.
//! The expected service identifiers are:
//!   - Linux:   systemd unit `directgate`
//!   - Windows: service `directgate-agent`
//!   - macOS:   launchd label `io.directgate.agent`
//!
//! This module only *checks*, *starts*, and *stops* an already-installed
//! service. It never installs one.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    Running,
    Stopped,
    NotInstalled,
    Unknown,
}

impl ServiceStatus {
    /// Stable string sent to the frontend.
    pub fn label(self) -> &'static str {
        match self {
            ServiceStatus::Running => "Running",
            ServiceStatus::Stopped => "Stopped",
            ServiceStatus::NotInstalled => "NotInstalled",
            ServiceStatus::Unknown => "Unknown",
        }
    }
}

/// Shown when the user tries to control a service that is not installed.
pub const NOT_INSTALLED_MSG: &str =
    "DirectGate service is not installed. Please install DirectGate Agent first.";

#[cfg(target_os = "linux")]
#[path = "service_linux.rs"]
mod platform;

#[cfg(target_os = "macos")]
#[path = "service_macos.rs"]
mod platform;

#[cfg(target_os = "windows")]
#[path = "service_windows.rs"]
mod platform;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::ServiceStatus;
    pub fn prepare() {}
    pub fn run_elevated_action_if_requested() -> Option<i32> {
        None
    }
    pub fn status() -> ServiceStatus {
        ServiceStatus::Unknown
    }
    pub fn start() -> Result<String, String> {
        Err("Service control is not supported on this platform.".into())
    }
    pub fn stop() -> Result<String, String> {
        Err("Service control is not supported on this platform.".into())
    }
    pub fn restart() -> Result<String, String> {
        Err("Service control is not supported on this platform.".into())
    }
}

/// One-time startup hook. Currently only Linux uses it (to pre-launch a
/// PolicyKit agent on bare window managers); other platforms are a no-op.
pub fn prepare() {
    platform::prepare();
}

pub fn run_elevated_action_if_requested() -> Option<i32> {
    platform::run_elevated_action_if_requested()
}

pub fn status() -> ServiceStatus {
    platform::status()
}

pub fn start() -> Result<String, String> {
    if status() == ServiceStatus::NotInstalled {
        return Err(NOT_INSTALLED_MSG.to_string());
    }
    platform::start()
}

pub fn stop() -> Result<String, String> {
    if status() == ServiceStatus::NotInstalled {
        return Err(NOT_INSTALLED_MSG.to_string());
    }
    platform::stop()
}

pub fn restart() -> Result<String, String> {
    if status() == ServiceStatus::NotInstalled {
        return Err(NOT_INSTALLED_MSG.to_string());
    }
    platform::restart()
}
