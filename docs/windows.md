# Building for Windows

The Windows port targets **Windows 10 1809+ / Windows 11 x64** and the **MinGW-w64** toolchain family. Everything is CLI-driven: CMake + Ninja, no Visual Studio required.

Two supported ways to produce `directgate.exe` and `dgcli.exe`:

1. **Cross-compile from Linux/macOS** with [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) - what the maintainers use; you never need a Windows machine to build.
2. **Native build on Windows** with [MSYS2](https://www.msys2.org/) - a pacman-based POSIX-like shell, familiar if you come from Linux.

Both are exercised by CI (`.github/workflows/windows.yml`).

---

## 1. Cross-compiling from Linux

### Toolchain

Any MinGW-w64 toolchain works (`x86_64-w64-mingw32-gcc` from your distro is fine, e.g. Fedora `mingw64-gcc` or Debian `gcc-mingw-w64-x86-64`). llvm-mingw is recommended because it ships modern clang with current Windows headers and needs no root to install:

```sh
curl -sLO https://github.com/mstorsjo/llvm-mingw/releases/download/20260602/llvm-mingw-20260602-ucrt-ubuntu-22.04-x86_64.tar.xz
tar xf llvm-mingw-20260602-ucrt-ubuntu-22.04-x86_64.tar.xz
mv llvm-mingw-20260602-ucrt-ubuntu-22.04-x86_64 ~/llvm-mingw
export PATH="$HOME/llvm-mingw/bin:$PATH"
```

### OpenSSL for Windows (one-time)

The agent links OpenSSL statically; cross-build it once into a prefix:

```sh
curl -sLO https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz
tar xzf openssl-3.5.7.tar.gz && cd openssl-3.5.7
./Configure mingw64 no-shared no-tests no-apps no-docs \
    --prefix="$HOME/win64-prefix" \
    --cross-compile-prefix=x86_64-w64-mingw32-
make -j"$(nproc)" && make install_sw
```

Stay on the OpenSSL 3.x LTS line: the SRP authentication layer uses `openssl/srp.h`, which OpenSSL 4.x removed.

### Opus for Windows (one-time)

Desktop system audio encodes with libopus. Linux/macOS dlopen it at runtime, but Windows has no package manager, so the agent links it **statically** (like OpenSSL) into the self-contained exe. Cross-build it once into the same prefix:

```sh
git clone --depth 1 --branch v1.5.2 https://github.com/xiph/opus.git && cd opus
cmake -B build-win64 -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=/path/to/agent/cmake/toolchain-mingw-w64.cmake \
    -DCMAKE_INSTALL_PREFIX="$HOME/win64-prefix" \
    -DOPUS_BUILD_SHARED_LIBRARY=OFF -DOPUS_BUILD_TESTING=OFF -DBUILD_TESTING=OFF
cmake --build build-win64 -j"$(nproc)" && cmake --install build-win64
```

The agent's CMake finds `libopus.a` in the prefix, defines `DIRECTGATE_OPUS_STATIC`, and calls libopus directly (no runtime `opus.dll`). Without it the WIN32 `find_library(... REQUIRED)` fails at configure time.

### Build directgate

```sh
git submodule update --init --recursive
cmake -B build-win64 -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw-w64.cmake \
    -DCMAKE_PREFIX_PATH="$HOME/win64-prefix"
cmake --build build-win64 -j"$(nproc)"
```

Result: `build-win64/directgate.exe` and `build-win64/dgcli.exe` - self-contained binaries you can copy to any Windows x64 machine (or VM).

If the toolchain is not in `PATH`, point the toolchain file at it with `-DMINGW_TOOLCHAIN_ROOT=$HOME/llvm-mingw`.

---

## 2. Native build on Windows (MSYS2)

Install [MSYS2](https://www.msys2.org/), open the **UCRT64** shell and run:

```sh
pacman -S --needed \
    mingw-w64-ucrt-x86_64-gcc \
    mingw-w64-ucrt-x86_64-cmake \
    mingw-w64-ucrt-x86_64-ninja \
    mingw-w64-ucrt-x86_64-openssl \
    git

git clone --recursive https://github.com/directgate/directgate
cd directgate
cmake -B build -G Ninja -DOPENSSL_USE_STATIC_LIBS=TRUE
cmake --build build -j4
```

The binaries land in `build/`. The MinGW runtime is linked statically and `OPENSSL_USE_STATIC_LIBS` folds OpenSSL in as well, so the executables depend only on DLLs that ship with Windows - copy them anywhere, no MSYS2 needed at runtime. Verify with `objdump -p build/directgate.exe | grep "DLL Name"`: nothing outside the system /  api-ms-win-crt-*` set should appear. A `libstdc++` / `libwinpthread` / `libc++` / `libssl` import means the binary will silently fail to start on machines without those DLLs - the loader kills the process before `main()` with `STATUS_DLL_NOT_FOUND` (exit code `-1073741515`) and prints nothing.

> MSVC (Visual Studio) builds are not supported yet. The code uses MinGW's
> POSIX shims (`getopt`, `ssize_t`, etc.) on Windows.

---

## Installer (MSI)

The project's Windows CI builds a Windows x64 MSI with the [WiX Toolset](https://wixtoolset.org/) - the `build-msi` job in `.github/workflows/windows.yml`. WiX runs only on Windows, so the installer is produced in CI rather than the Linux release pipeline. The rest of this section covers installing and configuring that MSI.

Installing `directgate-<release>_x64.msi` (double-click, or `msiexec /i directgate-<release>_x64.msi`, add `/qn` for silent):

- requests elevation once for the per-machine installation;
- installs the `DirectGate P2P UDP` inbound Windows Firewall rule for `directgate.exe` on every profile, with edge traversal enabled;
- removes that firewall rule automatically when DirectGate is uninstalled;
- installs `directgate.exe` and `dgcli.exe` into `C:\Program Files\DirectGate\` and adds that directory to the system `PATH`;
- creates `C:\ProgramData\directgate\`, the machine-wide config home and the default log directory (`log.path` in `agent.json` overrides it);
- registers one Windows service, `directgate-agent`, running as **LocalSystem**
  and configured to start automatically at boot with the command line
  `directgate.exe --win-service --win-launcher -c "C:\ProgramData\directgate\agent.json"`;
- **starts that service before the installer finishes** - on every install, repair and upgrade, not only at the next boot.

Nothing here needs a reboot, and the installer does not ask for one. It stops the agent's processes itself before replacing their files - without that, Windows Installer checks for files in use *before* it stops the service, always finds `directgate.exe` held open by the service and by the processes it spawned, and reports a restart as necessary even though the files are free again by the time it writes them.

An interactive install shows the normal Windows UAC prompt. A silent `/qn` install cannot display UAC, so it must be launched from an already elevated process or deployment service.

**Operational disclosure.** The service runs only the privilege-separation *launcher* (see [As a Windows service](#as-a-windows-service)): a tiny LocalSystem supervisor that acquires `shell.user`'s logon token and runs the actual agent as `shell.user`. Terminal sessions, file-manager operations, protocol parsing and network session handling run as `shell.user`, not as LocalSystem. The one exception is the logon screen, where no user exists to be: see [Reaching a machine before anyone logs on](#reaching-a-machine-before-anyone-logs-on). Remote access is unavailable until the device is explicitly paired and the client authenticates; the installed service does not grant anonymous remote access. No Windows password is ever stored or prompted.

Finish setup after installing:

1. Configure/pair the machine-wide config. Do this **as `shell.user`** so that account owns its config (the agent writes `agent.json` with a `0600`-equivalent DACL limited to `SYSTEM`, `Administrators`, and the owner):

   ```bat
   directgate.exe -c C:\ProgramData\directgate\agent.json -sed <device_id> -t <token>
   ```

2. Set `shell.user` in that config to the account whose sessions the agent should own (the logged-on user).

There is no third step: the service is already running and picks the configuration up on its own within a couple of seconds. It does not need to be started by hand and the machine does not need a reboot. Until a config with a `shell.user` exists the launcher simply waits, which is also why a fresh install never reports a failed service start.

The launcher serves full sessions only while `shell.user` is logged on (console/RDP). When nobody is logged on at all it keeps the device reachable on the logon screen instead of going dark - see [Reaching a machine before anyone logs on](#reaching-a-machine-before-anyone-logs-on). When somebody *else* is logged on it waits, and starts the agent on the next `shell.user` logon.

Uninstalling stops and removes the service, deletes the files, and removes the `PATH` entry.

### Upgrading a machine you can only reach remotely

Replacing `directgate.exe` means stopping the service, which drops your own session. That is unavoidable. What must not happen is the service staying down afterwards, so the installer starts it again itself and the agent reconnects on its own - no console access needed at the far end.

One thing still to get right: **do not launch the installer from a DirectGate terminal session.** That console belongs to the agent, and when the installer stops the service the agent - and everything running under its pseudo-console, including `msiexec` - goes with it. Windows Installer would then roll the transaction back mid-upgrade, which is exactly the state you cannot recover from remotely.

Safe ways to start it:

- From the **remote desktop** session, by double-clicking the MSI or running it from an ordinary `cmd`/PowerShell window opened inside that desktop. Those belong to Explorer, not to the agent, and survive the restart.
- Detached from the session entirely, which is the option to prefer for a scripted or unattended upgrade:

  ```bat
  schtasks /create /tn DirectGateUpgrade /ru SYSTEM /sc once /st 00:00 /f ^
      /tr "msiexec /i C:\path\directgate-<release>_x64.msi /qn /norestart"
  schtasks /run /tn DirectGateUpgrade
  ```

  `msiexec` then runs under the Task Scheduler and is unaffected by the agent restarting underneath it. Delete the task afterwards with `schtasks /delete /tn DirectGateUpgrade /f`.

### Config path: console vs service

- **Console / interactive:** the default is the per-user   `%APPDATA%\directgate\agent.json`.
- **Service (launcher):** the launcher (LocalSystem) reads `shell.user` from the   machine-wide `C:\ProgramData\directgate\agent.json` (passed with `-c`), and the agent it spawns reads the same file. Pair into that path (step 1) so the agent loads the config you paired.

---

## Running the agent on Windows

### Console (foreground)

```bat
directgate.exe -c C:\path\to\agent.json
```

The default config path is `%APPDATA%\directgate\agent.json`. Pairing
(`-sed <device_id> -t <token>`) works exactly as on Linux.

### Windows paths inside the config

The config is JSON, and in JSON a raw backslash starts an escape sequence - `"C:\Users\Kala"` is **invalid** (`\U` is not a JSON escape) and the parser will reject the file. Write Windows paths in one of the two valid forms:

```json
{
  "shell": {
    "user": "Kala",
    "home": "C:/Users/Kala"
  }
}
```

or `"C:\\Users\\Kala"`. Forward slashes are the recommended form: every Windows API accepts them, and the agent itself always generates paths with forward slashes for exactly this reason.

### As a Windows service

The [MSI installer](#installer-msi) registers this service for you; the manual
`sc.exe` route below is for source builds and custom setups.

DirectGate uses **privilege separation** on Windows. A single service runs a small **launcher** as LocalSystem; the launcher acquires `shell.user`'s logon token (passwordless, via `WTSQueryUserToken`) and spawns the agent inside that user's session, so the agent - including all protocol parsing, the PTY and the file manager - runs as `shell.user`, never as SYSTEM. This mirrors the POSIX model where the agent `setuid`s to `shell.user`: the untrusted parser is never SYSTEM. The single, bounded exception is the pre-logon agent described [below](#reaching-a-machine-before-anyone-logs-on), which exists only while nobody is logged on and serves nothing but a desktop session. Remote access is available only after explicit pairing and client authentication; installing or starting the service alone does not expose an anonymous remote shell or file manager.

**`agent.json` is untrusted input to the privileged side.** The agent has to be able to rewrite that file - it persists refreshed enrolment tokens into it - so it is owned by `shell.user`, which means every path in it is chosen by the account the untrusted half runs as. The launcher still has to read it (that is where `shell.user` and the desktop policy come from), but no privileged process acts on a *path* it names: `log.path` and `log.ident` are ignored by the LocalSystem launcher and by the pre-logon agent, which log to `%ProgramData%\directgate` under their own names instead. The desktop helper does not open the file at all - it is handed its verbosity as a number on its command line, so nothing a SYSTEM process does depends on parsing it. Honouring those fields would have let an unprivileged account pick where a SYSTEM process creates directories and opens files, which is a privilege-escalation primitive rather than a logging preference.
From an **administrator** prompt:

```bat
sc.exe create directgate-agent ^
    binPath= "C:\Program Files\DirectGate\directgate.exe --win-service --win-launcher -c C:\ProgramData\directgate\agent.json" ^
    start= auto ^
    obj= LocalSystem ^
    DisplayName= "DirectGate Agent"

sc.exe start directgate-agent
```

Notes:

- **No password.** The service is LocalSystem; only the launcher (which holds   `SeTcbPrivilege`) can mint `shell.user`'s token. `shell.user` must be set in the config and **logged on** for terminal and file-manager sessions to run - the launcher waits for both rather than exiting, so it can be installed and started before the machine has ever been paired. The identity is still pinned once: the first configuration carrying a `shell.user` is the one it commits to, and nothing re-reads it afterwards.
- The launcher pins the spawn identity to the configured `shell.user` and never takes it from anything else, so terminal and file-manager sessions can never run under an unexpected identity - the Windows counterpart of the POSIX privilege-drop policy.
- A service stop (`sc.exe stop directgate-agent`) stops the launcher, which terminates the supervised agent.
- Logs go to the file configured under `log` in `agent.json`; there is no Windows Event Log integration.

### Reaching a machine before anyone logs on

A Windows machine that reboots with nobody at the keyboard used to be unreachable until somebody walked up to it: there is no logon session, so there is no `shell.user` token, so the launcher had nothing to start the agent with. That is precisely the situation remote access exists for - a power cut on a machine three time zones away - so the launcher covers it with an agent run under the one identity that exists before any user does: its own.

When `shell.user` is not logged on **and nobody else is either**, the launcher duplicates its own LocalSystem token, retargets it at the console session with `SetTokenInformation(TokenSessionId)` - the same mint the [desktop helper](#elevated-ui-and-the-secure-desktop) uses - and starts the agent there with `--win-prelogon`. The result is a device that stays online at the logon screen: connect a desktop session, drive `LogonUI` through the helper, sign in normally.

What that agent may do is deliberately narrow, because it is SYSTEM:

- **Desktop sessions only.** `DirectGate_Session_StartMode` refuses `terminal`
  and `file-manager` outright, so the pre-logon window never yields a SYSTEM
  shell or a SYSTEM file manager. Clients are told before they pick a mode: the
  auth result carries `preLogon: true`.
- **A session that is being torn down is not spawned into twice.** For a second
  or two after a sign-out, the dying session still answers `WTSQueryUserToken`,
  so the supervisor would start an agent straight back into it and watch that
  one die within milliseconds. An agent that exits in under three seconds is
  taken as evidence about its session rather than about itself: that session is
  then left alone for six seconds, which also caps what used to be an unbounded
  two-second retry loop against a session that keeps killing whatever starts in
  it.
- **Signing out brings it back.** The supervisor re-checks a running agent on
  every tick, not only when its process exits, because a Windows session can be
  destroyed out from under a process that keeps running: an agent left in a
  session that no longer exists holds its relay connection open and looks
  perfectly healthy while every session it could serve is already impossible.
  The question it asks is deliberately narrow - *is the agent's own session
  still `shell.user`'s?* - resolved against the session the OS says the process
  is in (`ProcessIdToSessionId` at spawn). Asking the broad "is `shell.user`
  logged on anywhere" instead cannot settle it: the agent is itself a process
  in the session being torn down, so the broad answer can stay "yes" for as
  long as the stale agent lives. After six seconds of the narrow answer being
  "no", the agent is stopped and the logon screen is back on the air.
- **It ends at the first logon.** The launcher retires it the moment the console
  session gains a user. If that user is `shell.user`, the normal unprivileged
  agent replaces it and everything works as documented above; if it is anyone
  else, no agent runs at all - a SYSTEM capture left running in a session that
  now belongs to somebody else would be streaming their desktop.
- **The flag is not a switch a user can flip.** `--win-prelogon` is refused by
  any agent that is not actually running as LocalSystem, so passing it by hand
  cannot turn the `shell.user` identity check into an opt-out.
- **It hands its files back.** Private files (`agent.json` above all) normally
  carry a protected DACL naming SYSTEM, Administrators and the owner - which is
  right when the writer is `shell.user`, and wrong when it is SYSTEM. A
  pre-logon agent adds `shell.user` to that DACL explicitly, so a token refresh
  it performs cannot lock the real agent out of its own configuration. This is
  the Windows counterpart of the POSIX `chown` to `shell.user`, and it heals on
  the next normal write.

It is on by default (`desktop.preLogon`) and needs `desktop.elevatedInput`, since the logon screen lives on `winsta0\Winlogon` and only the helper can reach it; with elevated input off, the launcher logs why and disables pre-logon rather than serving a connected session that shows nothing. Deployments that would rather stay dark than run a restricted SYSTEM agent set:

```json
"desktop": { "preLogon": false }
```

and get exactly the previous behaviour - the launcher waits for a logon, and a machine that reboots unattended waits for someone to walk up to it.

### Terminal sessions

Terminals use **ConPTY** (`CreatePseudoConsole`), so you get a real interactive shell with colors, resizing, and arrow keys. The shell is `%COMSPEC%` when set, otherwise `cmd.exe`; users can launch PowerShell from that shell if they need it.

### File manager

The virtual root `/` lists the mounted drives (`C:/`, `D:/`, ...); paths travel with forward slashes. Owner/group columns show the agent account - Windows keeps ownership in ACLs, which do not map onto the POSIX `user:group` model.

### Desktop streaming

Remote desktop uses only components that ship with Windows - there is nothing
extra to install:

- **Capture:** [DXGI Desktop Duplication](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api) on a dedicated thread. Duplication delivers a frame only when pixels actually changed, so an idle desktop costs no CPU. When duplication is unavailable - the "All displays" capture spanning several monitors, rotated outputs, or another application already duplicating the screen - the pipeline falls back to paced GDI `BitBlt` capture with the same encoder behind it.
- **Encoding:** the H.264 encoder is picked through Media Foundation, hardware first (Quick Sync / NVENC / AMF - whichever MFT the GPU driver registered), with the Microsoft software encoder as the fallback. Low-latency mode, CBR and zero B-frames are requested for interactive latency; bitrate adapts live from RTCP receiver reports like on the other platforms.
- **Input:** pointer and keyboard injection via `SendInput` over the virtual desktop, so multi-monitor setups and negative coordinates work. Privileged UI is handled separately - see [Elevated UI and the secure desktop](#elevated-ui-and-the-secure-desktop).

`mfplat.dll` is loaded at runtime rather than linked, so the agent still starts on **Windows N editions** that ship without Media Foundation - desktop sessions there run the raw-RGBA fallback pipeline and report the reason in the desktop status, or you can install the [Media Feature Pack](https://support.microsoft.com/en-us/topic/media-feature-pack-for-windows-10-n-may-2020-ebbdf559-b84c-0fc2-bd51-e23c9f6a4439) to get H.264 back. The agent marks itself per-monitor-DPI-aware at desktop session start so capture geometry and input coordinates always work in physical pixels on scaled displays.

Desktop streaming requires the interactive session the launcher starts the agent in (see [As a Windows service](#as-a-windows-service)).

### Elevated UI and the secure desktop

Windows walls a medium-integrity process off from privileged UI in two different ways, and both used to end a remote session in a frozen picture that nobody could click out of:

- **The secure desktop.** A UAC consent prompt, the lock screen and the Ctrl+Alt+Del security screen all run on `winsta0\Winlogon`. Duplication dies with `DXGI_ERROR_ACCESS_LOST`, `OpenInputDesktop` is refused, and no injected input arrives.
- **Elevated windows on the normal desktop.** Task Manager and any elevated application stay on `winsta0\Default`, so the picture keeps updating, but UIPI silently drops every `SendInput` from the agent while one of them has focus - which reads as a frozen screen even though it is not.

Neither can be lifted from inside the agent. Instead the LocalSystem launcher spawns a small **desktop helper** - the same `directgate.exe` under `--win-desktop-helper` - as SYSTEM inside the interactive session. SYSTEM is not subject to UIPI and may attach to the Winlogon desktop, so one mechanism covers all of it. The helper is started with the desktop session and exits with it.

This is a fallback, never the normal path. The agent keeps its own duplication and its own `SendInput`, and the helper is engaged only for the events Windows will not take. The two refusals are detected differently, and the difference matters:

- **Secure desktop.** `SendInput` returns zero, because the calling thread's desktop is not the one receiving input. The direct call therefore goes first exactly as before and only what it rejected is re-sent through the helper - which costs nothing but reading a return value the call already produced.
- **Elevated window.** UIPI drops the event and reports nothing: MSDN states plainly that `SendInput` "fails when it is blocked by UIPI" and that "neither `GetLastError` nor the return value will indicate the failure". This one has to be decided *before* the call, so the agent checks whether the foreground window outranks its own integrity level and, if so, skips the direct `SendInput` entirely - sending both would double every event on windows that do accept input. The check is one `GetForegroundWindow` per event; the token lookup behind it is cached against that window and only redone when focus moves.
- **Capture:** a lost duplication that `OpenInputDesktop` confirms is the secure desktop hands capture to the helper, which delivers BGRA at the pipeline's own encode size through a shared section. The same encoder, the same stream - only a keyframe is forced on each transition, which the screen change warrants anyway.
- **Capture that was never there.** A pipeline can also *start* on the secure desktop - the logon screen, or a lock screen that was already up - and then there is no duplication to lose: it will not initialise, and the GDI probe reads a desktop this process does not own. That is not a broken pipeline, it is the case the helper exists for, so the pipeline starts bridged instead of failing. Treating it as fatal is what once made a device on the logon screen useless: the H.264 pipeline refused to start, the caller fell back to raw RGBA, the fallback released the helper, and the raw path has no bridge - so the operator got a display list, no picture and no error. A pipeline that started this way never leaves the bridge either; there is nothing to go back to, and the helper serves an ordinary desktop just as well.

The helper never encodes. It is a capture and injection surface only, and the frames it hands over go through the agent's existing Media Foundation encoder - the same hardware MFT instance, chosen once at pipeline start and never rebuilt - so a UAC prompt or the lock screen is encoded on the GPU exactly like the rest of the session. Giving the helper its own encoder would mean two MFTs, two bitstreams and a discontinuity for the viewer at every transition, which is why the split is where it is.

The agent log names which path took over, once per transition: `Elevated window has focus, routing input through the elevated helper` or `Secure desktop is up, routing input through the elevated helper`. Neither line appearing while privileged UI is unresponsive means the helper never started - check the `directgate-launcher` and `directgate-helper` logs in the same directory.

#### Lifetime, and what it costs when nothing privileged is on screen

The helper **process** exists for exactly as long as a desktop session does: the launcher spawns it when the pipeline starts and it exits when the agent releases it or the agent itself goes away. In between it is blocked on a pipe read - no capture, no injection, no GPU objects, normal priority, and the frame section it shares is committed but untouched, so only its first page is ever resident.

The helper **path** is entered and left independently of that, and separately for the two halves:

| | engaged when | back to the agent's own path when |
|---|---|---|
| Capture | duplication is lost *and* `OpenInputDesktop` confirms the secure desktop | the next pass sees the desktop is `Default` again - checked every pass while bridged, so within one frame |
| Input | the foreground window's process outranks the agent's integrity level, or a direct `SendInput` was refused | the next event, as soon as the foreground window is an ordinary one again |

Both are edge-triggered off state the loop already has, so an ordinary session pays essentially nothing for the feature being present:

- **Capture.** While DXGI duplication is delivering frames the desktop probe is skipped outright - a duplication that is still producing pixels cannot be looking at a secure desktop. It only runs after the picture has been unchanged for 250 ms, or on the GDI fallback where duplication cannot report anything. A game at 60 fps therefore issues **zero** extra calls.
- **Input.** One `GetForegroundWindow` per injected event while the helper is attached (sub-microsecond); the token lookup behind it is cached against that window, so a fullscreen game recomputes nothing after the first event.

Leaving the bridge restores the original pipeline exactly: the same Media Foundation encoder instance is used throughout - it is never destroyed or reconfigured - and the only visible effect is one forced keyframe, which the wholesale screen change warrants anyway. Bitrate, ABR state and the hardware encoder selection all carry across untouched.

`Ctrl+Alt+Del` is a separate case: the secure attention sequence cannot be synthesized at all, by design. The viewer's request reaches the launcher, which calls `SendSAS` - permitted only to a LocalSystem service, which is exactly what it is.

`desktop-status` reports `elevatedInput` (the helper is available), `secureDesktop` (frames are coming from it right now), `secureAttention` (Ctrl+Alt+Del can be delivered) and `elevatedReason` when it is unavailable, so the viewer can say why a prompt cannot be answered instead of just appearing to hang.

**This is a real privilege boundary, and it is on by default.** An operator who can approve a UAC prompt on your machine is, in practice, an administrator on it; one who can drive the lock screen can log in. That is the inherent price of the feature, not an implementation flaw. See [What a desktop session can do](security.md#what-a-desktop-session-can-do) for what the design does and does not bound, and set `"desktop": { "elevatedInput": false }` to keep the previous behaviour - privileged UI visible but frozen. `"lockScreen": false` keeps UAC prompts working while refusing the lock screen.

The helper is unavailable when the agent runs from a console rather than the service (there is no launcher to mint it). Everything degrades to the previous behaviour and the reason is reported in `desktop-status`.

**System audio** (opt-in) is captured with WASAPI loopback on the default render endpoint. The encode worker drains the endpoint directly (no separate capture thread or ring buffer, so audio stays tight to video), resamples the shared mix to 48 kHz stereo, and pads silent stretches on a high-resolution wall clock (loopback delivers nothing during silence). libopus is linked **statically** into the exe (see [Opus for Windows](#opus-for-windows-one-time)), so no runtime DLL is needed and audio always works when an output device is present. See [Desktop audio track](webrtc.md#desktop-audio-track).

---

## Security notes specific to Windows

- Private files (config, enrollment keys) are written with a **protected DACL** restricted to `SYSTEM`,  `Administrators`, and the file owner - the ACL equivalent of `0600`, with no inheritance from the parent directory.
- The **desktop helper** ([above](#elevated-ui-and-the-secure-desktop)) is the only SYSTEM code besides the launcher. Every channel it uses - the command pipe, the frame section and the two hand-off events - is an **unnamed** kernel object minted by the launcher and duplicated straight into the two intended processes, so there is no object-namespace entry to squat and no DACL to get wrong. It accepts only fixed-size binary records whose length is checked against the exact size for their type: the untrusted protocol parser stays in the agent, never in a SYSTEM process. It injects only when the input desktop is not `Default` or the foreground window outranks the agent's integrity level, so on the ordinary desktop it grants nothing `shell.user` did not already have. It is spawned only by the launcher, waits on the agent's process handle and exits with it.
- Internal IPC (the ConPTY terminal bridge, search and WebRTC notification channels) uses **AF_UNIX socket pairs** (Windows 10 1803+), which are not addressable from the network stack at all; the accepted endpoint is verified by **peer PID** before use. On systems without AF_UNIX support the implementation falls back to a loopback TCP pair hardened against connect-race hijacking.
- Atomic config updates use `MoveFileEx(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`; targets that are reparse points (symlinks / junctions) are refused, mirroring the `O_NOFOLLOW` checks on POSIX.
- Binaries are linked with DEP (`--nxcompat`), ASLR (`--dynamicbase`) and high-entropy 64-bit ASLR (`--high-entropy-va`).
- All files open in binary mode; an embedded manifest sets the **UTF-8 active code page**, so non-ASCII file names work end to end.
