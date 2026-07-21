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

For H.264 desktop streaming on Linux the agent loads `libopenh264.so` at runtime (it is not a build dependency - only the vendored API headers are compiled in). Install the [Cisco OpenH264](https://github.com/cisco/openh264) binary through your distribution (`openh264` on Fedora via the `fedora-cisco-openh264` repository) or point `DIRECTGATE_OPENH264_LIB` at the library path. Without it, desktop sessions fall back to the raw RGBA pipeline. On macOS and Windows desktop streaming uses only OS components (ScreenCaptureKit + VideoToolbox, and DXGI Desktop Duplication + Media Foundation respectively) - nothing extra to install; see [Building for Windows](windows.md#desktop-streaming) for the Windows specifics.

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
| Client | `build/dgcli`      | Experimental CLI terminal client |

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
│   └── client/          # Experimental CLI client source
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
