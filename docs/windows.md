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

Installing `directgate-<version>-x64.msi` (double-click, or `msiexec /i directgate-<version>-x64.msi`, add `/qn` for silent):

- installs `directgate.exe` and `dgcli.exe` into `C:\Program Files\DirectGate\` and adds that directory to the system `PATH`;
- creates `C:\ProgramData\directgate\`, the machine-wide config home;
- registers one Windows service, `directgate-agent`, running as **LocalSystem**   and configured to start automatically at boot with the command line `directgate.exe --win-service --win-launcher -c "C:\ProgramData\directgate\agent.json"`.

**Operational disclosure.** The service runs only the privilege-separation *launcher* (see [As a Windows service](#as-a-windows-service)): a tiny LocalSystem supervisor that acquires `shell.user`'s logon token and runs the actual agent as `shell.user`. Terminal sessions, file-manager operations, protocol parsing and network session handling run as `shell.user`, not as LocalSystem. Remote access is unavailable until the device is explicitly paired and the client authenticates; the installed service does not grant anonymous remote access. No Windows password is ever stored or prompted.

Finish setup after installing:

1. Configure/pair the machine-wide config. Do this **as `shell.user`** so that account owns its config (the agent writes `agent.json` with a `0600`-equivalent DACL limited to `SYSTEM`, `Administrators`, and the owner):

   ```bat
   directgate.exe -c C:\ProgramData\directgate\agent.json -sed <device_id> -t <token>
   ```

2. Set `shell.user` in that config to the account whose sessions the agent should own (the logged-on user).
3. Start it: `sc.exe start directgate-agent` (or `Start-Service directgate-agent`).

The launcher serves sessions only while `shell.user` is logged on (console/RDP); when they are not it waits and starts the agent on the next logon. There is no headless mode - that is the deliberate cost of never storing a password.

Uninstalling stops and removes the service, deletes the files, and removes the `PATH` entry.

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

DirectGate uses **privilege separation** on Windows. A single service runs a small **launcher** as LocalSystem; the launcher acquires `shell.user`'s logon token (passwordless, via `WTSQueryUserToken`) and spawns the agent inside that user's session, so the agent - including all protocol parsing, the PTY and the file manager - runs as `shell.user`, never as SYSTEM. This mirrors the POSIX model where the agent `setuid`s to `shell.user`: the untrusted parser is never SYSTEM. Remote access is available only after explicit pairing and client authentication; installing or starting the service alone does not expose an anonymous remote shell or file manager.
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

- **No password.** The service is LocalSystem; only the launcher (which holds   `SeTcbPrivilege`) can mint `shell.user`'s token. `shell.user` must be set in the config and **logged on** for sessions to run: the launcher refuses to start when `shell.user` is unset, and waits for a logon when it is set but not present.
- The launcher pins the spawn identity to the configured `shell.user` and never takes it from anything else, so terminal and file-manager sessions can never run under an unexpected identity - the Windows counterpart of the POSIX privilege-drop policy.
- A service stop (`sc.exe stop directgate-agent`) stops the launcher, which terminates the supervised agent.
- Logs go to the file configured under `log` in `agent.json`; there is no Windows Event Log integration.

### Terminal sessions

Terminals use **ConPTY** (`CreatePseudoConsole`), so you get a real interactive shell with colors, resizing, and arrow keys. The shell is `%COMSPEC%` when set, otherwise `cmd.exe`; users can launch PowerShell from that shell if they need it.

### File manager

The virtual root `/` lists the mounted drives (`C:/`, `D:/`, ...); paths travel with forward slashes. Owner/group columns show the agent account - Windows keeps ownership in ACLs, which do not map onto the POSIX `user:group` model.

### Desktop streaming

Remote desktop uses only components that ship with Windows - there is nothing
extra to install:

- **Capture:** [DXGI Desktop Duplication](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api) on a dedicated thread. Duplication delivers a frame only when pixels actually changed, so an idle desktop costs no CPU. When duplication is unavailable - the "All displays" capture spanning several monitors, rotated outputs, or another application already duplicating the screen - the pipeline falls back to paced GDI `BitBlt` capture with the same encoder behind it.
- **Encoding:** the H.264 encoder is picked through Media Foundation, hardware first (Quick Sync / NVENC / AMF - whichever MFT the GPU driver registered), with the Microsoft software encoder as the fallback. Low-latency mode, CBR and zero B-frames are requested for interactive latency; bitrate adapts live from RTCP receiver reports like on the other platforms.
- **Input:** pointer and keyboard injection via `SendInput` over the virtual desktop, so multi-monitor setups and negative coordinates work.

`mfplat.dll` is loaded at runtime rather than linked, so the agent still starts on **Windows N editions** that ship without Media Foundation - desktop sessions there run the raw-RGBA fallback pipeline and report the reason in the desktop status, or you can install the [Media Feature Pack](https://support.microsoft.com/en-us/topic/media-feature-pack-for-windows-10-n-may-2020-ebbdf559-b84c-0fc2-bd51-e23c9f6a4439) to get H.264 back. The agent marks itself per-monitor-DPI-aware at desktop session start so capture geometry and input coordinates always work in physical pixels on scaled displays.

Desktop streaming requires the interactive session the launcher starts the agent in (see [As a Windows service](#as-a-windows-service)); a UAC secure-desktop prompt pauses duplication until it is dismissed, and the lock screen cannot be captured by design.

---

## Security notes specific to Windows

- Private files (config, enrollment keys) are written with a **protected DACL** restricted to `SYSTEM`,  `Administrators`, and the file owner - the ACL equivalent of `0600`, with no inheritance from the parent directory.
- Internal IPC (the ConPTY terminal bridge, search and WebRTC notification channels) uses **AF_UNIX socket pairs** (Windows 10 1803+), which are not addressable from the network stack at all; the accepted endpoint is verified by **peer PID** before use. On systems without AF_UNIX support the implementation falls back to a loopback TCP pair hardened against connect-race hijacking.
- Atomic config updates use `MoveFileEx(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`; targets that are reparse points (symlinks / junctions) are refused, mirroring the `O_NOFOLLOW` checks on POSIX.
- Binaries are linked with DEP (`--nxcompat`), ASLR (`--dynamicbase`) and high-entropy 64-bit ASLR (`--high-entropy-va`).
- All files open in binary mode; an embedded manifest sets the **UTF-8 active code page**, so non-ASCII file names work end to end.
