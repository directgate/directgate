[Back to README](../README.md)

# Building from source

If your platform is not covered by the [package repositories](../README.md#installation), or you want to audit and build the agent yourself, build it from source. The dependency set is small and the project builds on most Unix-like systems.

> **Windows:** see [Building for Windows](windows.md) - MinGW-w64
> cross-compilation from Linux/macOS or a native MSYS2 build, plus service
> installation and Windows-specific notes.

## Requirements

- Linux or macOS
- A C/C++ toolchain (GCC or Clang)
- CMake ≥ 3.16
- OpenSSL development headers (`libssl-dev` / `openssl-devel`, or `brew install openssl`)
- `git` (the build pulls two submodules)

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

This installs the `directgate` and `dgcli` binaries plus a system service that runs the agent **as the installing user** (not root). The user and home directory are detected at install time (`$SUDO_USER`, falling back to `$USER`) and substituted into the service template, so you never edit it by hand.

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
