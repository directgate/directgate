# DirectGate Manager

A tiny [Tauri v2](https://tauri.app) desktop app that does exactly two things:

1. **Pair a device** with the DirectGate backend.
2. **Check / start / stop / restart** the locally installed DirectGate agent
   service.

It is intentionally a single page with no extra features. It does **not**
install the service and does **not** require admin privileges for pairing.

If the device is already enrolled (per the agent config), the pairing form is
replaced by a **"Device is already paired"** notice with a **Re-Pair** button.
The service action button is **Start Service** when stopped and **Restart
Service** when running. Pairing also restarts the service automatically so it
picks up the new enrollment.

```
┌────────────────────────────────┐       ┌────────────────────────────────┐
│        DirectGate Manager      │       │        DirectGate Manager      │
│                                │       │                                │
│  Pair Device                   │       │  Pair Device                   │
│   Device ID:     [___________] │       │   Device is paired.            │
│   Pairing Token: [___________] │       │   [ Re-Pair ]                  │
│   Auth Password: [___________] │       │                                │
│   Confirm Pass:  [___________] │       │  Service                       │
│   [ Pair Device ]              │       │   Status: Running              │
│                                │       │   [ Restart Service ] [ Stop ] │
│  Service                       │       │                                │
│   Status: Stopped              │       │                                │
│   [ Start Service ] [ Stop ...]│       │                                │
└────────────────────────────────┘       └────────────────────────────────┘
```

## Project layout

```
manager/
├── build.sh              # cross-build script (POSIX sh)
├── index.html            # single page
├── package.json
├── src/
│   ├── main.ts           # UI logic + Tauri command wrappers
│   └── styles.css
└── src-tauri/
    ├── Cargo.toml
    ├── tauri.conf.json
    ├── capabilities/default.json
    ├── icons/            # app icons (regenerate with icons/gen_icons.py)
    └── src/
        ├── main.rs
        ├── lib.rs              # Tauri commands + agent binary lookup
        ├── service.rs          # status/start/stop/restart dispatch
        ├── service_linux.rs    # systemd + pkexec
        ├── service_macos.rs    # launchd + osascript
        └── service_windows.rs  # sc.exe + UAC (runas)
```

## Prerequisites

- **Node.js 20.19+** and **npm** (required by Vite 7)
- **Rust toolchain** (`cargo`, install via <https://rustup.rs>)
- Platform Tauri dependencies:
  - **Linux:** WebKitGTK 4.1 + GTK 3 dev packages and `pkg-config`
    (`apt install libwebkit2gtk-4.1-dev libgtk-3-dev pkg-config build-essential`).
  - **Windows:** the MSVC build tools and WebView2 runtime (preinstalled on
    Windows 11).
  - **macOS:** the Xcode command line tools (`xcode-select --install`).

## Run locally (development)

```sh
cd manager
npm install
npm run tauri dev
```

This launches Vite (frontend) and the Tauri shell with hot reload.

## Build release binaries

`build.sh` builds standalone executables and copies them into `manager/dist`:

```sh
cd manager
./build.sh --linux              # one target
./build.sh --win --mac --linux  # several targets at once
```

| Argument  | Output                                   |
| --------- | ---------------------------------------- |
| `--win`   | `dist/directgate-manager-windows-x64.exe` |
| `--mac`   | `dist/directgate-manager-macos-x64`       |
| `--linux` | `dist/directgate-manager-linux-x64`       |

Each requested target is built independently. **Cross-OS compilation is
limited:** macOS can only be built on a Mac, Linux only on Linux, and Windows
natively on Windows (a best-effort MinGW cross-build from Linux/macOS is
attempted if `x86_64-w64-mingw32-gcc` is present). When a target cannot be
built on the current host, the script stops with a clear message describing
what is missing - it never silently skips a target.

The web assets are emitted to `manager/dist-web` so they never collide with the
final executables in `manager/dist`.

## Expected service names

The app controls an **already-installed** service. It looks for:

| Platform | Identifier                                   | Tooling               |
| -------- | -------------------------------------------- | --------------------- |
| Linux    | systemd unit `directgate-agent`              | `systemctl`, `pkexec` |
| Windows  | service `directgate-agent`                   | SCM APIs + UAC        |
| macOS    | launchd label `io.directgate.agent`          | `launchctl`           |

On macOS a per-user **LaunchAgent** (`gui/<uid>/io.directgate.agent`) is
preferred; if a system **LaunchDaemon** (`system/io.directgate.agent`) is
detected instead, privileged actions are elevated via `osascript`.

If the service is not present, the UI shows:

> DirectGate service is not installed. Please install DirectGate Agent first.

## How pairing works

When you click **Pair Device**, the app:

1. Decodes the single **Pairing Code** into a device ID and a one-time pairing
   token (see [Pairing code format](#pairing-code-format)), and validates that
   the code and **Auth Password** are non-empty and that **Auth Password**
   matches **Confirm Password**.
2. Locates the `directgate` agent binary - first on `PATH`, then platform
   defaults:
   - Windows: `C:\Program Files\DirectGate\directgate.exe`
   - macOS: `/usr/local/bin/directgate`, `/opt/homebrew/bin/directgate`
   - Linux: `/usr/bin/directgate`, `/usr/local/bin/directgate`
3. Runs the agent with an argument array (never a shell string):

   ```
   directgate -sed <deviceId> -t <pairingToken>
   ```

   (`-sed` expands to `-s -e -d <deviceId>`: init SRP, enroll, set device id.)
4. The `-s` step makes the agent set up an SRP auth password, which it reads
   only from a real terminal (`tcgetattr`). So the agent is run inside a
   **pseudo-terminal** and the **Auth Password** is written to its two prompts
   (`Set new auth password:` / `Repeat password:`). This is why the GUI needs an
   Auth Password field - first-time pairing always sets the SRP password.
5. Shows the agent's output, or its error on failure.
6. On success, switches to the "already paired" view and **restarts the
   service** so it picks up the new enrollment (this restart needs admin
   privileges; pairing itself does not).

The already-paired state is detected by reading `enrollment.enrolled` from the
agent's config file. On Windows this is the machine-wide
`%PROGRAMDATA%/directgate/agent.json` (`C:\ProgramData\directgate\agent.json`),
matching the service install in [docs/windows.md](../docs/windows.md); a service
account cannot read the interactive user's per-user `%APPDATA%`, so pairing
writes the same machine-wide path via `-c`. Elsewhere it is
`$HOME/.config/directgate/agent.json` - the same default path the agent uses.

## Pairing code format

directgate.io shows a single **Pairing Code** that bundles the device ID and the
one-time pairing token, so you copy one value instead of two:

```
dg1_<base64url( deviceId + "\n" + pairingToken )>
```

- `dg1_` is a version prefix (v1); it is accepted but optional on input.
- The payload is base64url (RFC 4648 §5), padding optional.
- The device ID and token are split on the **first** newline, so the token may
  contain any character (`:`, `.`, `/`, …) without escaping.

Example: device `desk-01` with token `f3a9c1b8e7d6` encodes to
`dg1_ZGVzay0wMQpmM2E5YzFiOGU3ZDY`. The manager decodes it and runs the agent
with `-d desk-01 -t f3a9c1b8e7d6`.

The pairing token and auth password are **never stored, written to disk by this
app, or logged**. They are held only transiently to drive the agent (the
password is sent through the pseudo-terminal, never as a CLI argument or
environment variable), both inputs are cleared after each attempt, and pairing
never requests admin privileges.

## Why admin privileges are requested for start/stop/restart

Starting, stopping and restarting a system service is a privileged operation,
so the OS must authorize it. Pairing and status checks need no elevation; only
start/stop/restart do:

- **Windows:** status is read with Service Control Manager APIs. Start, stop and
  restart relaunch this same manager executable in a tiny elevated helper mode
  using `ShellExecuteW` + the `runas` verb (via the `runas` crate), which
  triggers the standard **UAC** consent prompt. The helper calls
  `StartServiceW` / `ControlService` directly and exits before the Tauri UI
  starts.
- **Linux:** `pkexec systemctl start|stop|restart directgate-agent` triggers the
  PolicyKit authentication dialog. Status (`systemctl is-active`) runs
  unelevated. Because bare window managers (i3, sway, …) often run no PolicyKit
  agent, start/stop escalate in three layers: (1) `pkexec`; (2) if no agent is
  running, the app launches a known polkit agent itself - once at startup so it
  has time to register, and again (with a retry) on demand; (3) as a last resort
  it uses graphical `sudo -A` with an installed SSH askpass program. On full
  desktops (GNOME/KDE/XFCE/MATE/…) an agent already runs, so step 1 just works.
- **macOS:** a user LaunchAgent needs no elevation; a system LaunchDaemon is
  controlled through `osascript ... with administrator privileges`, which
  shows the macOS authentication dialog.

## Version and updates (footer)

The line under the two cards answers one question - "am I running the current
version?" - and stays out of the way otherwise. It shows the release reported
by the installed agent (`directgate -v`), a dot for the state, and, only when
there is somewhere to go, a link to the newer installer.

**Windows only.** Nothing else has a package manager problem to solve here: on
Linux and macOS the agent came from apt, dnf or brew, those already know about
updates, and a second opinion in this window could only contradict them or nag
about something the user cannot apply from here. On those platforms the footer
shows the version and nothing more.

How the check works:

1. `get_agent_version` runs `directgate -v` and reads the release out of it.
2. `check_for_update` fetches `https://pkg.directgate.io/win/latest-version`, a
   flat `key=value` manifest published by `pkg/release.sh` alongside the
   installer:

   ```
   version=1.0.21-3
   md5=<md5 of the installer>
   sha256=<sha256 of the installer>
   file=directgate-latest-x64.msi
   url=https://pkg.directgate.io/win/directgate-latest-x64.msi
   ```

   Unknown keys are ignored, so the manifest can gain fields without breaking
   managers already installed.
3. Both releases are compared **numerically** on `MAJOR.MINOR.BUILD-PKG`. The
   build-channel tag (`-x64_msi`, `-amd64_deb`, …) records where a build came
   from, not how new it is, and is left out of the comparison.

Three things it deliberately does not do:

- **It never downloads or installs.** Replacing the agent stops the service,
  which drops whatever remote session the user is sitting in. The link opens
  the system browser and the rest is their decision.
- **It never fails loudly.** A check that cannot reach the network paints
  "Update check unavailable" and puts the reason in the tooltip. This runs on
  every launch; it is not something to make anyone dismiss.
- **It adds no HTTP stack.** The fetch shells out to `%SystemRoot%\System32\curl.exe`,
  which has shipped in Windows since 1803. One plain GET of a few dozen bytes
  does not justify a TLS library and an async runtime inside a remote-access
  program. The path is absolute because `CreateProcess` searches the calling
  program's own directory first, and only our own package host is ever accepted
  as a download link.

## Troubleshooting

**Blank/gray window on Linux, log shows `Failed to create GBM buffer ...
Invalid argument`.** WebKitGTK's DMABUF renderer cannot allocate a GPU buffer
on some drivers/VMs. The app disables that renderer automatically on Linux, but
you can also set it yourself:

```sh
WEBKIT_DISABLE_DMABUF_RENDERER=1 ./dist/directgate-manager-linux-x64
```

If a window still fails to paint, try also `WEBKIT_DISABLE_COMPOSITING_MODE=1`.

**Start/Stop does nothing on a bare window manager (i3, sway, …).** These WMs
don't run a PolicyKit agent, so `pkexec` has nothing to prompt with. The app
will try to launch a polkit agent for you and fall back to graphical `sudo -A`,
but the most reliable fix is to autostart an agent in your session, e.g. in
`~/.config/i3/config`:

```
exec --no-startup-id /usr/libexec/polkit-mate-authentication-agent-1
```

(Use whichever agent is installed: `polkit-gnome`, `polkit-kde`, `lxqt-policykit-agent`, ….)
