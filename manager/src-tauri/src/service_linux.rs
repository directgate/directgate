/*
 * @file directgate-manager/src-tauri/src/service_linux.rs
 * @brief Linux service control via systemd (pkexec elevation).
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

//! Linux service control via systemd.
//!
//!   status: `systemctl is-active directgate-agent`
//!   start:  `pkexec systemctl start directgate-agent`
//!   stop:   `pkexec systemctl stop directgate-agent`
//!
//! Privileged start/stop are escalated in three layers so the app works across
//! full desktops *and* bare window managers (i3, sway, ...) that do not run a
//! PolicyKit agent by default:
//!
//!   1. `pkexec` - works out of the box on any desktop with a polkit agent.
//!   2. If pkexec has no agent to prompt with, try to launch a known polkit
//!      authentication agent ourselves, then retry pkexec once.
//!   3. If still no agent can be found, fall back to graphical `sudo -A` using
//!      an installed SSH askpass program (no polkit agent required).

use super::ServiceStatus;
use crate::hidden_command;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const SERVICE: &str = "directgate-agent";

/// Ensures we only ever spawn a polkit agent once per app run.
static AGENT_LAUNCH_TRIED: AtomicBool = AtomicBool::new(false);

/// Known PolicyKit authentication agent binaries, across desktops and distros.
/// The first one that exists is launched as a fallback when none is running.
const POLKIT_AGENTS: &[&str] = &[
    // GNOME
    "/usr/libexec/polkit-gnome-authentication-agent-1",
    "/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1",
    "/usr/lib/x86_64-linux-gnu/polkit-gnome-authentication-agent-1",
    // KDE
    "/usr/libexec/polkit-kde-authentication-agent-1",
    "/usr/lib/x86_64-linux-gnu/libexec/polkit-kde-authentication-agent-1",
    "/usr/lib/polkit-kde-authentication-agent-1",
    // MATE
    "/usr/libexec/polkit-mate-authentication-agent-1",
    "/usr/lib/mate-polkit/polkit-mate-authentication-agent-1",
    "/usr/lib/x86_64-linux-gnu/mate-polkit/polkit-mate-authentication-agent-1",
    // XFCE
    "/usr/libexec/xfce-polkit/xfce-polkit",
    "/usr/lib/xfce-polkit/xfce-polkit",
    // LXQt / LXDE
    "/usr/bin/lxqt-policykit-agent",
    "/usr/libexec/lxqt-policykit-agent",
    "/usr/bin/lxpolkit",
    // elementary / Deepin
    "/usr/libexec/policykit-1-pantheon/io.elementary.desktop.agent-polkit",
    "/usr/lib/polkit-1-dde/dde-polkit-agent",
    "/usr/lib/x86_64-linux-gnu/polkit-1-dde/dde-polkit-agent",
];

/// Graphical askpass programs used for the final `sudo -A` fallback.
const ASKPASS_BINS: &[&str] = &[
    "/usr/bin/ssh-askpass",
    "/usr/libexec/openssh/gnome-ssh-askpass",
    "/usr/lib/openssh/gnome-ssh-askpass",
    "/usr/libexec/openssh/ssh-askpass",
    "/usr/bin/ssh-askpass-fullscreen",
    "/usr/bin/x11-ssh-askpass",
    "/usr/bin/lxqt-openssh-askpass",
    "/usr/bin/ksshaskpass",
    "/usr/bin/qt4-ssh-askpass",
];

const NO_AUTH_MSG: &str = "Could not obtain administrator authorization. No PolicyKit \
authentication agent is running (and none could be started), and no graphical sudo \
askpass program (e.g. ssh-askpass) is installed. Start a PolicyKit agent in your session \
or install ssh-askpass, then try again.";

pub fn status() -> ServiceStatus {
    let output = match hidden_command("systemctl")
        .args(["is-active", SERVICE])
        .output()
    {
        Ok(out) => out,
        // systemctl missing / not spawnable: we cannot tell.
        Err(_) => return ServiceStatus::Unknown,
    };

    let state = String::from_utf8_lossy(&output.stdout);
    match state.trim() {
        "active" | "activating" | "reloading" => ServiceStatus::Running,
        _ => {
            if is_installed() {
                ServiceStatus::Stopped
            } else {
                ServiceStatus::NotInstalled
            }
        }
    }
}

/// `systemctl status <unit>` exits with code 4 when the unit does not exist.
fn is_installed() -> bool {
    match hidden_command("systemctl")
        .args(["status", SERVICE])
        .output()
    {
        Ok(out) => out.status.code() != Some(4),
        // Could not run the probe; assume installed rather than mislead the user.
        Err(_) => true,
    }
}

/// Called once at app startup. Bare window managers (i3, sway, …) usually run
/// no PolicyKit agent; launch one early so it has time to register with polkitd
/// before the user clicks Start/Stop. No-op when an agent is already running
/// (the case on every full desktop), so it never spawns a duplicate.
pub fn prepare() {
    if is_agent_running() {
        return;
    }
    if try_launch_agent() {
        AGENT_LAUNCH_TRIED.store(true, Ordering::SeqCst);
    }
}

pub fn run_elevated_action_if_requested() -> Option<i32> {
    None
}

pub fn start() -> Result<String, String> {
    elevate_systemctl("start")?;
    Ok("DirectGate service started.".into())
}

pub fn stop() -> Result<String, String> {
    elevate_systemctl("stop")?;
    Ok("DirectGate service stopped.".into())
}

pub fn restart() -> Result<String, String> {
    elevate_systemctl("restart")?;
    Ok("DirectGate service restarted.".into())
}

/// Outcome of a single `pkexec systemctl ...` attempt.
enum Pkexec {
    /// The privileged command ran and succeeded.
    Ok,
    /// The user dismissed/denied the authentication prompt (pkexec exit 126).
    Denied,
    /// pkexec could not authenticate us, typically because no agent is present
    /// (exit 127), or pkexec itself is missing -> try the fallbacks.
    NeedFallback,
    /// systemctl ran under pkexec but failed on its own; not an auth problem.
    CmdFailed(String),
}

fn elevate_systemctl(verb: &str) -> Result<(), String> {
    match run_pkexec(verb) {
        Pkexec::Ok => return Ok(()),
        Pkexec::Denied => return Err("Authorization was dismissed or denied.".into()),
        Pkexec::CmdFailed(e) => return Err(e),
        Pkexec::NeedFallback => {}
    }

    // No agent answered pkexec. Try to start one ourselves (once), then retry.
    if !AGENT_LAUNCH_TRIED.swap(true, Ordering::SeqCst) && !is_agent_running() && try_launch_agent()
    {
        // Give the freshly launched agent time to register with polkitd. A cold
        // GTK agent can take over a second before it can answer pkexec.
        std::thread::sleep(Duration::from_millis(1500));
        match run_pkexec(verb) {
            Pkexec::Ok => return Ok(()),
            Pkexec::Denied => return Err("Authorization was dismissed or denied.".into()),
            Pkexec::CmdFailed(e) => return Err(e),
            Pkexec::NeedFallback => {}
        }
    }

    // Last resort: graphical sudo via an askpass helper (no polkit needed).
    run_sudo_askpass(verb)
}

fn run_pkexec(verb: &str) -> Pkexec {
    let output = match hidden_command("pkexec")
        .args(["systemctl", verb, SERVICE])
        .output()
    {
        Ok(out) => out,
        // pkexec not installed / not spawnable -> let the fallbacks try.
        Err(_) => return Pkexec::NeedFallback,
    };

    if output.status.success() {
        return Pkexec::Ok;
    }

    let code = output.status.code().unwrap_or(-1);
    match code {
        126 => Pkexec::Denied,
        127 => Pkexec::NeedFallback,
        _ => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Pkexec::CmdFailed(if stderr.is_empty() {
                format!("systemctl {verb} failed (exit {code}).")
            } else {
                stderr
            })
        }
    }
}

/// Scans `/proc` for an already-running polkit authentication agent (not the
/// `polkitd` daemon, which is always present and cannot prompt by itself).
fn is_agent_running() -> bool {
    let known: Vec<&str> = POLKIT_AGENTS
        .iter()
        .map(|p| p.rsplit('/').next().unwrap_or(p))
        .collect();

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(cmdline) = std::fs::read(format!("/proc/{name}/cmdline")) else {
            continue;
        };
        // cmdline arguments are NUL-separated; the first is the program path.
        let prog = cmdline.split(|&b| b == 0).next().unwrap_or(&[]);
        let prog = String::from_utf8_lossy(prog);
        let base = prog.rsplit('/').next().unwrap_or(&prog);
        if known.contains(&base)
            || prog.contains("authentication-agent")
            || prog.contains("policykit-agent")
        {
            return true;
        }
    }
    false
}

/// Launches the first installed polkit agent it finds, detached. Returns true
/// if one was spawned.
fn try_launch_agent() -> bool {
    for path in POLKIT_AGENTS {
        if !Path::new(path).is_file() {
            continue;
        }
        let spawned = hidden_command(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if spawned.is_ok() {
            return true;
        }
    }
    false
}

/// Graphical `sudo -A` fallback driven by an SSH askpass dialog. Used only when
/// no PolicyKit agent is available at all.
fn run_sudo_askpass(verb: &str) -> Result<(), String> {
    let askpass = match ASKPASS_BINS.iter().find(|p| Path::new(p).is_file()) {
        Some(p) => *p,
        None => return Err(NO_AUTH_MSG.into()),
    };

    let output = hidden_command("sudo")
        .arg("-A")
        .arg("--")
        .args(["systemctl", verb, SERVICE])
        .env("SUDO_ASKPASS", askpass)
        .output()
        .map_err(|e| format!("Failed to run sudo: {e}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let code = output.status.code().unwrap_or(-1);
    Err(if stderr.is_empty() {
        format!("Authorization failed (sudo exit {code}).")
    } else {
        stderr
    })
}
