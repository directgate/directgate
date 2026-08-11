[Back to README](../README.md)

# Building from source

If your platform is not covered by the [package repositories](../README.md#installation), or you want to audit and build the agent yourself, build it from source. The dependency set is small and the project builds on most Unix-like systems.

> **Windows:** see [Building for Windows](windows.md) - MinGW-w64 cross-compilation from Linux/macOS or a native MSYS2 build, plus service installation and Windows-specific notes.

## Requirements

- Linux or macOS
- A C/C++ toolchain (GCC or Clang)
- CMake ≥ 3.16
- OpenSSL development headers (`libssl-dev` / `openssl-devel`, or `brew install openssl`)
- On Linux: X11 development headers for desktop streaming - `libx11-dev`, `libxrandr-dev`, `libxext-dev` (Debian/Ubuntu) or `libX11-devel`, `libXrandr-devel`, `libXext-devel` (Fedora/RHEL)
- `git` (the build pulls two submodules)

For H.264 desktop streaming on Linux the agent loads `libopenh264.so` at runtime (it is not a build dependency - only the vendored API headers are compiled in). Install the [Cisco OpenH264](https://github.com/cisco/openh264) binary through your distribution (`openh264` on Fedora via the `fedora-cisco-openh264` repository) or point `DIRECTGATE_OPENH264_LIB` at the library path. Without it, desktop sessions fall back to the raw RGBA pipeline.

Linux desktop sessions prefer the **GPU** encoder when one is usable (NVENC, VAAPI, QSV, AMF or V4L2 M2M), reached through libavcodec. If the `libavcodec`/`libavutil` development headers are present at configure time - `ffmpeg-devel` on Fedora, `libavcodec-dev libavutil-dev` on Debian/Ubuntu - CMake reports `GPU desktop encoding: enabled` and compiles the support in; the libraries themselves are dlopen'd at runtime and never linked, so they stay optional and add no package dependency. Building without those headers, or running on a host with no libavcodec, no GPU or no usable encoder, simply keeps the OpenH264 software path. Set `DIRECTGATE_HWENC=0` to force software encoding, or `DIRECTGATE_HWENC_ENCODER=h264_vaapi` to pin one.

### Talking to more than one libavcodec

The struct layouts come from the build-time headers, so one compiled encoder only accepts a runtime libavcodec with the *same major soname* - a mismatch is treated like "not installed" and falls back to software, silently. A single build would therefore reach the GPU only on hosts running the same FFmpeg generation as the machine that built it.

A binary meant to run on machines other than the one that built it can carry several instead. [`misc/ffmpeg-headers.sh`](../misc/ffmpeg-headers.sh) populates a directory with one FFmpeg public-header tree per major, and `DIRECTGATE_HWENC_HEADERS` points CMake at it:

```
<dir>/58/libavcodec/*.h   <dir>/58/libavutil/*.h
<dir>/59/...              <dir>/60/...   <dir>/61/...   <dir>/62/...
```

`desktop/hwenc.c` is then compiled once against each tree and `desktop/hwenc_abi.c` selects the variant matching whatever the host has, newest first. Nothing is linked or redistributed - the host's own FFmpeg is still what gets loaded, so VAAPI and QSV keep using the drivers that distribution configured, and the binary grows by a few tens of kilobytes per major.

| libavcodec | libavutil | FFmpeg | Covers                               |
|------------|-----------|--------|--------------------------------------|
| 58         | 56        | 4.4    | Debian 11, Ubuntu 20.04 / 22.04, EL8 |
| 59         | 57        | 5.1    | Debian 12, EL9                       |
| 60         | 58        | 6.1    | Ubuntu 24.04                         |
| 61         | 59        | 7.1    | Debian 13, current Fedora            |
| 62         | 60        | 8.0    | rolling releases moving to FFmpeg 8  |

```sh
./misc/ffmpeg-headers.sh /tmp/ffmpeg-headers
cmake -B build -DDIRECTGATE_HWENC_HEADERS=/tmp/ffmpeg-headers
```

The trees are ordinary `libavcodec/` and `libavutil/` directories from an FFmpeg release tarball, plus a `libavutil/avconfig.h` (two macros, which FFmpeg's `configure` normally generates) - so a distribution's own `-dev` package works just as well if you symlink it in. CMake takes whatever majors it finds, so adding one as distributions move on means another release line in that script plus the matching pair of `#if` blocks in `hwenc_abi.c`.

A plain `cmake -B build` passes no header trees and keeps the single-variant behaviour, compiled against whatever FFmpeg is installed - which is what you want on a machine that only has to run its own build.

Two switches guard this for release builds, and the `hwenc-abi` CI job exercises both on every push. `-DDIRECTGATE_REQUIRE_HWENC=ON` fails at configure time when no FFmpeg headers are found at all, instead of quietly producing a permanently software-only binary - the decision is baked in at compile time and no user can repair it afterwards. And the `hwenc_abi_smoke` test loads the build machine's own libavcodec through the dispatcher, so a variant that compiles but cannot be selected fails too.

On macOS and Windows desktop streaming uses only OS components (ScreenCaptureKit + VideoToolbox, and DXGI Desktop Duplication + Media Foundation respectively) - nothing extra to install; see [Building for Windows](windows.md#desktop-streaming) for the Windows specifics.

Desktop **system-audio** streaming encodes with `libopus`. On Linux and macOS it is loaded at runtime (`DIRECTGATE_OPUS_LIB` overrides the search; `libopus.so`/`libopus.dylib`) and is optional - a missing library just reports audio `unavailable`. On Windows there is no package manager, so libopus is **linked statically** into the exe (see [Building for Windows](windows.md#opus-for-windows-one-time)) and is always present. Capture uses the OS output loopback: `libpulse` for the PulseAudio / PipeWire default-sink monitor on Linux (`DIRECTGATE_AUDIO_SOURCE` overrides the source), WASAPI on Windows, and ScreenCaptureKit on macOS (13+, sharing the screen-recording permission the video path already needs) - nothing extra to install for the Windows or macOS capture side. When the capture source is missing the session still streams video and audio just reports `unavailable`. On a headless Linux host install your distribution's `libopus` and `pulseaudio-libs` / `libpulse` packages to enable it.

[libxutils](https://github.com/kala13x/libxutils) and [libdatachannel](https://github.com/paullouisageneau/libdatachannel) are included as git submodules and built automatically - there is no separate system-wide WebRTC dependency to install. libdatachannel is linked **statically**, so the resulting binaries are self-contained.

## Build

```bash
# Clone with submodules (or run the submodule command after a plain clone)
git clone --recurse-submodules https://github.com/directgate/directgate.git
cd directgate-agent
git submodule update --init --recursive   # only needed if you cloned without --recurse-submodules

# Configure and build
cmake -B build
cmake --build build -j
```

This produces:

| Binary | Path               | Description                      |
|--------|--------------------|----------------------------------|
| Agent  | `build/directgate` | PTY agent                        |
| Client | `build/dgcli`      | CLI terminal client              |

## Install from source

```bash
sudo make -C build install
```

This installs the `directgate` and `dgcli` binaries plus a system service that runs the agent **as the installing user** (not root). The user and home directory are detected at install time (`$SUDO_USER`, falling back to `$USER`) and substituted into the service template. On Linux, the installer also detects the active X11 authority file from the environment, GDM, LightDM, `~/.Xauthority`, or the user's graphical session, so the generated unit does not hardcode a display manager.

**Linux** - binaries to `/usr/bin`, and a systemd unit from [misc/directgate-agent.service](../misc/directgate-agent.service):

```
/usr/bin/directgate, /usr/bin/dgcli
/etc/systemd/system/directgate-agent.service
```

Once the agent is [paired](../README.md#pairing-with-your-account) and its config exists, enable and start it:

```bash
sudo systemctl enable directgate-agent
sudo systemctl restart directgate-agent
```

**macOS** - `/usr/bin` is read-only (SIP), so binaries go to `/usr/local/bin`, and a launchd daemon is installed from [misc/io.directgate.agent.plist](../misc/io.directgate.agent.plist):

```
/usr/local/bin/directgate, /usr/local/bin/dgcli
/Library/LaunchDaemons/io.directgate.agent.plist
```

Load it once the agent is paired:

```bash
sudo launchctl load -w /Library/LaunchDaemons/io.directgate.agent.plist
```

To install the binaries or the service unit elsewhere, override the paths at configure time:

```bash
# Linux
cmake -B build -DDIRECTGATE_INSTALL_BINDIR=/usr/local/bin -DDIRECTGATE_SYSTEMD_DIR=/etc/systemd/system
# macOS
cmake -B build -DDIRECTGATE_INSTALL_BINDIR=/opt/homebrew/bin -DDIRECTGATE_LAUNCHD_DIR=/Library/LaunchDaemons
```

> On macOS, installing via [Homebrew](../README.md#installation) is the recommended path - the formula sets up the same launchd service automatically (`brew services start directgate`).

## Tests

A set of smoke tests can be built and run with CTest:

```bash
./tests/run-smoke.sh
```

Valgrind can be used to run the tests under memory checking:

```bash
./tests/run-valgrind.sh
```

AddressSanitizer and UndefinedBehaviorSanitizer can be used to run the tests under memory checking:

```bash
./tests/run-sanitizers.sh
```

The script configures the build with `-DDIRECTGATE_BUILD_TESTS=ON`, builds the test executables, and runs them through `ctest`.

## Repository layout

```
directgate-agent/
├── src/
│   ├── common/          # Shared code (protocol, auth, e2e, hkdf, srp, webrtc, transfer)
│   ├── agent/           # Agent source (config, enroll, files, search, session, term, directgate)
│   └── client/          # CLI client source code
├── tests/               # Smoke tests + run-smoke.sh
├── docs/                # Detailed documentation
├── misc/                # Screenshots and helper snippets
├── libxutils/           # libxutils submodule (utility library)
├── libdatachannel/      # libdatachannel submodule (WebRTC)
├── build/               # Build output (created by CMake; git-ignored)
├── cmake/               # CMake helper scripts
├── CMakeLists.txt       # Single cross-platform build
├── LICENSE              # GNU GPL v3
└── README.md            # Project overview
```
