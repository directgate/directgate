/*
 * @file directgate-manager/src-tauri/src/service_windows.rs
 * @brief Windows service control via the Service Control Manager (UAC elevation).
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

//! Windows service control via the Service Control Manager APIs.
//!
//!   status: OpenSCManagerW + QueryServiceStatus   (no elevation needed)
//!   start:  elevated helper mode + StartServiceW
//!   stop:   elevated helper mode + ControlService
//!
//! Privileged actions relaunch this same executable in a tiny helper mode
//! through the `runas` crate, which uses `ShellExecuteW` with the "runas" verb
//! to trigger the UAC consent prompt. The helper exits before Tauri starts.

use super::ServiceStatus;
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};

const SERVICE: &str = "directgate-agent";
const HELPER_ARG: &str = "--directgate-service-action";

// Win32 error: the specified service does not exist as an installed service.
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
// Win32 error: access is denied.
const ERROR_ACCESS_DENIED: i32 = 5;
// Win32 error: the service did not respond in time.
const ERROR_SERVICE_REQUEST_TIMEOUT: i32 = 1053;
// Win32 error: the service has already been started.
const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
// Win32 error: the service has not been started.
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;

const SC_MANAGER_CONNECT: u32 = 0x0001;
const SERVICE_QUERY_STATUS: u32 = 0x0004;
const SERVICE_START: u32 = 0x0010;
const SERVICE_STOP: u32 = 0x0020;
const SERVICE_CONTROL_STOP: u32 = 0x0001;

const SERVICE_STOPPED: u32 = 0x00000001;
const SERVICE_START_PENDING: u32 = 0x00000002;
const SERVICE_STOP_PENDING: u32 = 0x00000003;
const SERVICE_RUNNING: u32 = 0x00000004;
const SERVICE_CONTINUE_PENDING: u32 = 0x00000005;
const SERVICE_PAUSE_PENDING: u32 = 0x00000006;
const SERVICE_PAUSED: u32 = 0x00000007;

#[repr(C)]
#[derive(Default)]
struct SERVICE_STATUS {
    dw_service_type: u32,
    dw_current_state: u32,
    dw_controls_accepted: u32,
    dw_win32_exit_code: u32,
    dw_service_specific_exit_code: u32,
    dw_check_point: u32,
    dw_wait_hint: u32,
}

struct ScHandle(*mut c_void);

impl ScHandle {
    fn new(raw: *mut c_void) -> Option<Self> {
        if raw.is_null() {
            None
        } else {
            Some(Self(raw))
        }
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenSCManagerW(
        machine: *const u16,
        database: *const u16,
        desired_access: u32,
    ) -> *mut c_void;
    fn OpenServiceW(
        manager: *mut c_void,
        service_name: *const u16,
        desired_access: u32,
    ) -> *mut c_void;
    fn CloseServiceHandle(handle: *mut c_void) -> i32;
    fn QueryServiceStatus(service: *mut c_void, status: *mut SERVICE_STATUS) -> i32;
    fn StartServiceW(service: *mut c_void, argc: u32, argv: *const *const u16) -> i32;
    fn ControlService(service: *mut c_void, control: u32, status: *mut SERVICE_STATUS) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
}

#[derive(Clone, Copy)]
enum ServiceAction {
    Start,
    Stop,
    Restart,
}

impl ServiceAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            "restart" => Some(Self::Restart),
            _ => None,
        }
    }
}

/// No startup preparation needed on Windows (UAC handles elevation directly).
pub fn prepare() {}

pub fn run_elevated_action_if_requested() -> Option<i32> {
    let mut args = std::env::args();
    let _exe = args.next();

    if args.next().as_deref() != Some(HELPER_ARG) {
        return None;
    }

    let code = match args.next().as_deref().and_then(ServiceAction::from_str) {
        Some(action) => perform_action(action)
            .map(|_| 0)
            .unwrap_or_else(|err| err as i32),
        None => 87, // ERROR_INVALID_PARAMETER
    };

    Some(code)
}

pub fn status() -> ServiceStatus {
    let service = match open_service(SERVICE_QUERY_STATUS) {
        Ok(handle) => handle,
        Err(err) if err == ERROR_SERVICE_DOES_NOT_EXIST as u32 => {
            return ServiceStatus::NotInstalled
        }
        Err(_) => return ServiceStatus::Unknown,
    };

    match query_state(&service) {
        Ok(SERVICE_RUNNING | SERVICE_START_PENDING | SERVICE_CONTINUE_PENDING) => {
            ServiceStatus::Running
        }
        Ok(SERVICE_STOPPED | SERVICE_STOP_PENDING | SERVICE_PAUSED | SERVICE_PAUSE_PENDING) => {
            ServiceStatus::Stopped
        }
        Ok(_) => ServiceStatus::Unknown,
        Err(_) => ServiceStatus::Unknown,
    }
}

pub fn start() -> Result<String, String> {
    elevate_self(ServiceAction::Start)?;
    Ok("DirectGate service start requested.".into())
}

pub fn stop() -> Result<String, String> {
    elevate_self(ServiceAction::Stop)?;
    Ok("DirectGate service stop requested.".into())
}

pub fn restart() -> Result<String, String> {
    elevate_self(ServiceAction::Restart)?;
    Ok("DirectGate service restarted.".into())
}

fn elevate_self(action: ServiceAction) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("Could not locate DirectGate Manager executable: {e}"))?;

    let status = runas::Command::new(&exe)
        .args(&[HELPER_ARG, action.as_str()])
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
        Some(ERROR_SERVICE_REQUEST_TIMEOUT) => Err("Service control timed out.".into()),
        Some(code) => Err(format!("Service {} failed (exit {code}).", action.as_str())),
        None => Err("Elevated service helper terminated unexpectedly.".into()),
    }
}

fn perform_action(action: ServiceAction) -> Result<(), u32> {
    let desired_access = SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP;
    let service = open_service(desired_access)?;

    match action {
        ServiceAction::Start => start_service(&service),
        ServiceAction::Stop => stop_service(&service),
        ServiceAction::Restart => {
            stop_service(&service)?;
            start_service(&service)
        }
    }
}

fn open_service(desired_access: u32) -> Result<ScHandle, u32> {
    let manager = unsafe {
        ScHandle::new(OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CONNECT,
        ))
    }
    .ok_or_else(last_error)?;

    let name = wide(SERVICE);
    unsafe { ScHandle::new(OpenServiceW(manager.0, name.as_ptr(), desired_access)) }
        .ok_or_else(last_error)
}

fn query_state(service: &ScHandle) -> Result<u32, u32> {
    let mut status = SERVICE_STATUS::default();
    let ok = unsafe { QueryServiceStatus(service.0, &mut status) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(status.dw_current_state)
}

fn start_service(service: &ScHandle) -> Result<(), u32> {
    match query_state(service)? {
        SERVICE_RUNNING => return Ok(()),
        SERVICE_START_PENDING => return wait_for_state(service, SERVICE_RUNNING),
        _ => {}
    }

    let ok = unsafe { StartServiceW(service.0, 0, std::ptr::null()) };
    if ok == 0 {
        let err = last_error();
        if err != ERROR_SERVICE_ALREADY_RUNNING {
            return Err(err);
        }
    }

    wait_for_state(service, SERVICE_RUNNING)
}

fn stop_service(service: &ScHandle) -> Result<(), u32> {
    match query_state(service)? {
        SERVICE_STOPPED => return Ok(()),
        SERVICE_STOP_PENDING => return wait_for_state(service, SERVICE_STOPPED),
        _ => {}
    }

    let mut status = SERVICE_STATUS::default();
    let ok = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };
    if ok == 0 {
        let err = last_error();
        if err != ERROR_SERVICE_NOT_ACTIVE {
            return Err(err);
        }
    }

    wait_for_state(service, SERVICE_STOPPED)
}

fn wait_for_state(service: &ScHandle, wanted: u32) -> Result<(), u32> {
    let started = Instant::now();
    let timeout = Duration::from_secs(30);

    while started.elapsed() < timeout {
        if query_state(service)? == wanted {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(400));
    }

    Err(ERROR_SERVICE_REQUEST_TIMEOUT as u32)
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}
