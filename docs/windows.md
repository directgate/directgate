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

The binaries land in `build/`. The MinGW runtime is linked statically and `OPENSSL_USE_STATIC_LIBS` folds OpenSSL in as well, so the executables depend only on DLLs that ship with Windows - copy them anywhere, no MSYS2 needed at runtime. Verify with `objdump -p build/directgate.exe | grep "DLL Name"`: nothing outside the system / `api-ms-win-crt-*` set should appear. A
`libstdc++` / `libwinpthread` / `libc++` / `libssl` import means the binary will silently fail to start on machines without those DLLs - the loader kills the process before `main()` with `STATUS_DLL_NOT_FOUND` (exit code `-1073741515`) and prints nothing.

> MSVC (Visual Studio) builds are not supported yet. The code uses MinGW's
> POSIX shims (`getopt`, `ssize_t`, etc.) on Windows.

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

The agent has native Service Control Manager support via the
`--win-service` flag. From an **administrator** prompt:

```bat
sc.exe create directgate-agent ^
    binPath= "C:\Program Files\directgate\directgate.exe --win-service -c C:\ProgramData\directgate\agent.json" ^
    start= auto ^
    obj= ".\YourUser" password= YourPassword ^
    DisplayName= "DirectGate Agent"

sc.exe start directgate-agent
```

Notes:

- `obj=` sets the account the service runs as. The agent **refuses to start** unless `shell.user` in the config matches that account - the Windows counterpart of the POSIX privilege-drop policy: terminal and file-manager sessions can never run under an unexpected identity.

- A service stop (`sc.exe stop directgate-agent`) triggers the same clean shutdown path as `SIGTERM` on Linux.
- Logs go to the file configured under `log` in `agent.json`; there is no Windows Event Log integration.

### Terminal sessions

Terminals use **ConPTY** (`CreatePseudoConsole`), so you get a real interactive shell with colors, resizing, and arrow keys. The shell is `powershell.exe` when available, otherwise `%COMSPEC%` (cmd.exe).

### File manager

The virtual root `/` lists the mounted drives (`C:/`, `D:/`, ...); paths travel with forward slashes. Owner/group columns show the agent account - Windows keeps ownership in ACLs, which do not map onto the POSIX `user:group` model.

---

## Security notes specific to Windows

- Private files (config, enrollment keys) are written with a **protected DACL** restricted to `SYSTEM`, `Administrators`, and the file owner - the ACL equivalent of `0600`, with no inheritance from the parent directory.
- Atomic config updates use `MoveFileEx(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`; targets that are reparse points (symlinks / junctions) are refused, mirroring the `O_NOFOLLOW` checks on POSIX.
- Binaries are linked with DEP (`--nxcompat`), ASLR (`--dynamicbase`) and high-entropy 64-bit ASLR (`--high-entropy-va`).
- All files open in binary mode; an embedded manifest sets the **UTF-8 active code page**, so non-ASCII file names work end to end.
