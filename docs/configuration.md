[Back to README](../README.md)

# Configuration & running

The agent uses a JSON configuration file. You can point to one with `-c <path>`, or create/update it interactively with `-i`. Most fields are populated for you during [pairing](../README.md#pairing-with-your-account) and interactive setup (`directgate -i`, `directgate -s`).

## Default configuration path

- Agent: `~/.config/directgate/agent.json` (falls back to `./agent.json` if `$HOME` is unset)

## Logging

```json
{
  "log": {
    "path": "/var/log/directgate",
    "toScreen": true,
    "toFile": false,
    "flush": true,
    "levels": ["panic", "error", "warn", "note", "info", "debug"]
  }
}
```

| Field          | Type    | Description              |
|----------------|---------|--------------------------|
| `log.toScreen` | boolean | Output logs to console   |
| `log.toFile`   | boolean | Write logs to file       |
| `log.path`     | string  | Log file directory       |

The default log directory is platform-specific: `/var/log/directgate` on Linux and macOS, and `%ProgramData%\directgate` (normally `C:\ProgramData\directgate`) on Windows, next to the machine-wide `agent.json`. Setting `log.path` overrides it everywhere; on Windows either separator may be used.

`log.path` and `log.ident` are honoured by the agent itself, which runs as `shell.user` - the same account that owns `agent.json`. They are **ignored** by any process that outranks that account: the Windows LocalSystem launcher, the SYSTEM desktop helper, the pre-logon agent, and a POSIX agent that has not dropped privileges yet all log to the platform default under their own names, and say so in the log when they do. Letting a file the unprivileged account can rewrite choose where a SYSTEM or root process creates directories would be a privilege-escalation path, not a setting. An explicit `-l <path>` still applies everywhere, because that comes from whoever started the process rather than from the file.

## Agent configuration

```json
{
  "signalingUrl": "wss://relay1.directgate.io/websock",
  "deviceId": "<unique_uuidv4>",
  "iceServers": [
    "stun:stun.cloudflare.com:3478",
    "stun:stun.l.google.com:19302"
  ],
  "shell": {
    "user": "username",
    "home": "/home/username"
  },
  "desktop": {
    "elevatedInput": true,
    "lockScreen": true,
    "preLogon": true
  },
  "auth": {
    "srp": {
      "verifier": "<srp_verifier_hex>",
      "salt": "<64_hex_chars>"
    },
    "key": {
      "agentIdentity": {
        "seed": "<base64_ed25519_seed>",
        "pub": "<base64_ed25519_public_key>"
      },
      "authorizedKeys": [
        "<base64_ed25519_client_public_key>"
      ],
      "managedOrganizationId": "<organization_uuid>"
    }
  }
}
```

| Field                         | Type     | Description                                |
|-------------------------------|----------|--------------------------------------------|
| `signalingUrl`                | string   | WebSocket relay endpoint URL               |
| `deviceId`                    | string   | Unique device identifier for pairing       |
| `iceServers`                  | string[] | Manual ICE/TURN override (optional; normally delivered by the API - see [WebRTC P2P](webrtc.md#iceturn-server-configuration)) |
| `shell.user`                  | string   | Unix user for the shell session            |
| `shell.home`                  | string   | Working directory for the shell            |
| `desktop.elevatedInput`       | bool     | **Windows only**, default `true`. Lets a desktop session drive privileged UI - UAC prompts, Task Manager, elevated windows - through the service's SYSTEM helper. Setting it to `false` leaves those visible but frozen. Read [Elevated UI and the secure desktop](windows.md#elevated-ui-and-the-secure-desktop) before changing it: with it on, a remote operator who approves a UAC prompt is effectively an administrator on the host |
| `desktop.lockScreen`          | bool     | **Windows only**, default `true`. Also allows the lock screen and the Ctrl+Alt+Del security screen. Ignored when `desktop.elevatedInput` is `false` |
| `desktop.preLogon`            | bool     | **Windows only**, default `true`. Keeps the device reachable while nobody is logged on, by running the agent as SYSTEM in the console session so the logon screen can be driven remotely - the only way back into a machine that rebooted unattended. Such an agent serves desktop sessions and nothing else, and is retired at the first logon. Ignored when `desktop.elevatedInput` is `false`. See [Reaching a machine before anyone logs on](windows.md#reaching-a-machine-before-anyone-logs-on) |
| `auth.srp.salt`               | string   | SRP salt in hex (32 bytes / 64 hex chars)  |
| `auth.srp.verifier`           | string   | SRP verifier in hex                        |
| `auth.srp.suite`              | number   | SRP credential suite advertised at auth (managed by the agent; older records are upgraded in place on load) |
| `auth.key.agentIdentity.seed` | string   | Agent Ed25519 identity seed for key auth   |
| `auth.key.agentIdentity.pub`  | string   | Agent Ed25519 public identity for key auth |
| `auth.key.authorizedKeys`     | string[] | Authorized client Ed25519 public keys      |
| `auth.key.managedOrganizationId` | string | The organization this device's operator allowed to authorize client keys through the managed-key lease, as given with `-m <org_id>`. Only `-m` changes it - not an API response, not a re-pairing without `-m`, not a revoked enrollment - and it applies only while the enrollment is in that same organization. Absent: managed keys are off; `-m ""` removes it. See [Security](security.md#organization-managed-keys) |

### Terminal sessions

The terminal runs `shell.user`'s login shell from the account database, unless that shell is `nologin`, `false` or missing, in which case the agent falls back to its own `$SHELL`, then `bash`, then `sh`. `HOME`, `USER`, `LOGNAME`, `SHELL` and `TERM` are set for that account rather than inherited from the agent, and the shell starts in `shell.home` when it is set, otherwise in the account's home directory.

Output is paced to the client: when more than 4 MB is waiting to be sent, the agent stops reading the terminal until the backlog drops below 1 MB, and the program writing to it simply blocks, the way it would on a slow terminal. Input that would push the backlog towards the shell past 8 MB is refused. Closing a session hangs the shell up and, if it has not exited half a second later, kills its process group - without the agent waiting for it.

### Commands (exec sessions)

A client can also run one command without a terminal - what `ssh host 'command'` does, and what `dgcli exec` and AI agents use. The command runs as the same account the terminal would, through that account's shell (`<shell> -c <command>`; `%COMSPEC% /d /s /c` on Windows), with the terminal's environment except `TERM=dumb`. stdout and stderr reach the client separately, and its exit code (or the signal that ended it) comes back last.

- It starts in the directory the client names, which has to be an absolute path (a relative one is refused before anything runs); one that cannot be entered fails the command (exit 127) instead of running it elsewhere. Without one it starts where a terminal would, falling back to `/`.
- It runs in a process group of its own, with every inherited descriptor beyond stdin, stdout and stderr closed and every signal at its default. A signal the client forwards, a timeout it asked for and a session that goes away all reach that whole group. It does not outlive the agent either: on Linux the shell is killed when the agent dies (and never starts if the agent is already gone), on Windows the whole job is.
- Output is paced exactly like a terminal's (4 MB / 1 MB), and at most 8 MB of input may wait for a command that is not reading it.
- Output takes the session's WebRTC data channel, direct or through TURN. The relay carries it only when WebRTC cannot be established - the client says so, or no channel opened within 15 s - and there it is kept below the limit the relay announces, so one busy command never holds up the device's other sessions on the relay link. A command does not start before its output has a route (`the data channel is not ready`); `dgcli` starts it once its channel is open, or after 10 s on the relay.
- A client may keep one session for many commands and file operations, one at a time (session mode `remote`, `dgcli session`): signalling and authentication happen once, not per command.
- A client may ask for no more than so much of each stream (`outputMax`, `dgcli exec -o`). The rest is read and dropped on the device rather than sent, so the command runs exactly as it would with all of its output read - it is never blocked or cut off by the limit - and the link carries only what the client will keep. A command that prints without end still runs until its timeout.
- The exit is reported the moment the command ends. On Linux 5.3 and later the agent waits for it as an event, so a command that has closed its output (`make > build.log 2>&1`) costs the agent nothing while it runs; elsewhere such an exit is polled for, from every 5 ms backing off to every 100 ms.
- The agent logs that a command ran - session, pid, exit code, duration - but never the command line, which can carry a password as easily as a path.

A pre-logon Windows agent and a temporary desktop share never run commands. The wire format is in [`exec`](../../docs/protocol.md#exec).

## Running the agent

The agent exits with an error at start-up when its configuration has not been paired, or has no usable SRP password record: pair it first (see [Command-line options](#command-line-options)).

Run the installed binary directly:

```bash
directgate -c ~/.config/directgate/agent.json
```

If built from source without installing, the binary is at `build/directgate`.

### Command-line options

```
Usage: directgate [options]
Options are:
  -d <id>       Device ID for this agent
  -u <url>      WebSocket relay URL
  -c <path>     Config JSON path
  -l <path>     Log directory path
  -t <token>    Pairing token for enrollment
  -v <number>   Set/override verbosity level (0-5)
  -g <path>     Generate a client key file and exit
  -a <path>     Authorize this agent against an existing key file and exit
  -m <org_id>   Enable organization-managed client keys for this organization (a UUID). With -e it is saved
                with the pairing; on its own it is saved into the existing config, then exit. "" disables
  -r            Rotate agent identity keypair, push new pub to API, and exit
  -w            Enable WebRTC verbose logging (works with -v)
  -i            Init config and exit
  -e            Enroll device and exit
  -s            Init SRP verifier and exit
  -h            Print version and usage
```

Common one-shot commands:

```bash
directgate -sed <id> -t <token>  # pair this device with your account and init config
directgate -sed <id> -t <token> -m <org_id>  # pair into an organization and let it manage client keys here
directgate -m <org_id>           # enable organization-managed keys on an already paired device
directgate -m ""                 # disable them again
directgate -i                    # create/update the agent config interactively
directgate -s                    # set/change the SRP password (regenerates the verifier)
directgate -r                    # rotate the agent identity keypair
```

## Systemd hardening

By default, DirectGate installs its systemd service with `PrivateTmp=true`, which gives the service isolated `/tmp` and `/var/tmp` directories. It also uses `NoNewPrivileges=false`, which is basically required to make `sudo` work correctly within remote terminal sessions (similar to how SSH works).

This default is a deliberate tradeoff between functionality and isolation. Although `NoNewPrivileges` is disabled, the agent does not execute user sessions with elevated privileges by default and drops privileges to the configured account before handling interactive workloads.

If you do not require `sudo` capabilities from remote sessions, you may set:

```ini
NoNewPrivileges=true
```

for additional hardening.

Administrators are also encouraged to apply further systemd sandboxing restrictions where appropriate, such as filesystem restrictions, capability filtering, address family restrictions, and other hardening directives based on their deployment requirements.

As with any remote access software, the appropriate hardening profile depends on the balance between functionality and security required by your environment.

## CLI client

`dgcli` signs in to your DirectGate account, lists the devices on it and connects
to the one you pick - the same path the workspace UI takes.

### Signing in

```sh
dgcli login
```

This runs an OAuth 2.0 authorization code flow with PKCE. The CLI opens a short-lived listener on `127.0.0.1` (ports 40777-40784), opens your browser, and exchanges the returned authorization code for a session. Tokens are written
to `~/.config/directgate/auth/auth.json` with `0600` permissions inside a `0700` directory, created on demand alongside the client key, and refreshed automatically as they expire - you only sign in again when the refresh token is gone. That includes a
sign-in ended from another device (Settings → Signed-in devices on the web): the API then refuses even an access token
that has not run out, the refresh is refused too, and `dgcli` forgets the dead session and starts a new sign-in - or,
without a terminal, exits telling you to run `dgcli login`.

The CLI holds no identity-provider configuration of its own. It knows exactly two hosts - the API and the web app - and the code exchange and refresh go through `POST /api/v1/auth/cli/token` and `/api/v1/auth/cli/refresh`, which the
API performs against the provider on its behalf. Swapping the provider therefore needs no new CLI release, and the repository carries no provider credentials.

The link it prints points at `https://directgate.io/cli-auth/start`, which forwards to the auth provider. The web app never shows this URL - `supabase-js` navigates to it from JavaScript - but the CLI has to print it, so it goes through our own domain rather than asking you to trust a raw project host. The page takes only a loopback port and a mode; it rebuilds the redirect target itself, so the link cannot be rewritten to send an authorization code elsewhere. Set `webUrl` to empty at build time and the CLI falls back to printing the provider URL directly.

On a machine with no browser (a box you reached over SSH, for example) the CLI detects the missing display - or you pass `-B` - and asks for the code to come back through `https://directgate.io/cli-auth` instead. That page hands the code to the listener when it can reach it and otherwise shows it for you to paste back into the terminal.

`dgcli logout` deletes the stored session; `dgcli whoami` prints the account it belongs to.

### Connecting

```sh
dgcli                # pick a device with the arrow keys, then connect
dgcli homelab        # connect by device name, exact or unique prefix
dgcli -d <device-id> # connect by device id
dgcli devices        # just list the account's devices (dgcli ls does the same)
```

The picker marks each device online (green), offline (yellow) or unavailable (red) and refuses to connect to devices the backend would reject anyway - unpaired, expired enrollment, or a share invitation you have not accepted. When stdin is not a terminal it falls back to a numbered prompt.

Once a device is chosen the CLI calls `POST /api/v1/sessions/connect`, which returns the relay URL, the short-lived browser JWT, the routing key and the ICE servers in one round trip. The routing key becomes the `?rk=` query parameter on the relay WebSocket handshake; without it the relay has no route to the agent and drops the connection.

The device password is prompted for after the device is chosen and is never written to disk.

A production build of `dgcli` connects only to a `wss://` relay, whether the URL came from the API or from its own configuration: the first relay message carries the access token, so a plaintext relay would hand it to the network. Debug builds also accept `ws://` for local development.

`dgcli` exits `0` when the session ran and ended: the host closed it, or `-A` authorized the key (or found it already authorized). Anything a script has to be able to tell apart from that exits non-zero: a configuration that does not load, a device that cannot be connected, a login that did not complete (a wrong password, a host that could not prove itself), a host with nobody logged on (it serves desktop sessions only, and `dgcli` has no desktop client), a session broken by a protocol violation after the login, and a key the device refused.

### Key authentication

`dgcli` can authenticate with an Ed25519 key instead of typing the device password every time. The key is always tried first; the password is only reached when there is no usable key or the host refuses the one offered.

```sh
dgcli -g                 # generate a key at ~/.config/directgate/auth/key.json
dgcli -k /path/to/key.json <device>
```

`-g` writes the key `0600` inside a `0700` directory and prints the public half. `-A` then hands that public half to a device over an authenticated session - the same `admin/add-key` the workspace UI uses - so a device can be authorized from anywhere the CLI already reaches it:

```sh
dgcli -A                 # pick a device, authorize the key, exit
dgcli -A -d homelab      # or name the device
dgcli -A -k /path/to/other-key.json
```

Without `-d` it shows the usual device picker, headed with what it is about to do so the operator can see this is not a connection attempt. The key it adds is the one `-k` names, or the default path; with neither present it prints where the key would live and how to get one.

Since a key file holds a single identity, the key being authorized is by definition not yet authorized, so `-A` authenticates with the device password the way `ssh-copy-id` does. After that the password is no longer needed for that device.

A device can also authorize a key locally, without the CLI:

```sh
directgate -a /path/to/key.json
```

Without `-k`, `~/.config/directgate/auth/key.json` is used when it exists; `-k` always wins over it. The distinction matters on failure: an unusable `-k` is an error, because the key was asked for by name, while the default path simply not existing is the ordinary password-only setup.

Two things have to line up for a key attempt to happen. The key file has to load, and the device has to have published an `agentPub` during enrollment - that value comes from the API over TLS and is what the host is pinned to. A
host presenting any other identity is refused outright rather than falling back, since it is not provably the device that was asked for. A host that proves its identity but has not authorized the key is a different case: that is what the password is for, so the CLI reconnects and runs SRP instead.

The file is the same `directgate-client-key-v2` identity the agent generates and the web client loads, so one key works across all three.

### Remote operations (scripts and AI agents)

The same connection can do one thing and exit, with no terminal, no prompt and nothing on stdout but the result - so a script, a CI job or an AI agent can use a device the way it uses `ssh` and `scp`:

```sh
dgcli exec homelab 'df -h /'                     # stdout/stderr kept apart, exit code is the command's
echo data | dgcli exec homelab 'cat > /tmp/x'    # piped stdin goes to the command
dgcli exec -t 30 -C /srv/app homelab -- make test   # timeout (seconds) and directory, before the device
dgcli exec -o 64K homelab 'journalctl -b'        # at most 64 KB of each stream; the rest is dropped on the device
dgcli cp homelab:/etc/hostname .                 # download; a directory keeps the remote name
dgcli cp homelab:/etc/hostname -                 # download to stdout
dgcli cp ./build.tar homelab:/tmp/               # upload; a remote path ending in / keeps the local name
tar c src | dgcli cp - homelab:/tmp/src.tar      # upload from stdin
dgcli cp -f notes.txt homelab:/tmp/notes.txt     # -f replaces an existing file, in either direction
dgcli ls homelab:/var/log                        # a listing; -j prints it as JSON
dgcli rm homelab:/tmp/old.log                    # a file or an empty directory
dgcli rm -r homelab:/tmp/old-build               # -r: a directory with everything in it
dgcli mkdir homelab:/tmp/new
dgcli mv homelab:/tmp/a /tmp/b                   # an existing target is refused, never replaced
dgcli ls -j                                      # the account's devices, as JSON (as does devices -j)
dgcli session -t 120 homelab                     # many of the above on one connection, requests on stdin
```

Each of these connects, authenticates and sets up its data channel for one operation. `dgcli session <device>` does
that once and then runs operations one after another for as long as its caller keeps it: it writes `{"ready":true}`
on its first line, then reads one JSON request per line - `{"argv":["exec","df -h /"]}`, with an optional `"stdin"`
(text for the command) and `"max"` (bytes kept of each stream, 16 MB at most) - and answers each with a JSON line,
`{"exitCode":0,"stdout":12,"stderr":0,"truncated":false}`, followed by exactly that many bytes of stdout and then of
stderr. `argv` is any of the operations above, without the device. The session ends at end of input, after 10 minutes
with no request (`-t` sets fewer seconds), and once it has lived 30 minutes - never in the middle of an operation - so
what the account may reach is checked again on the next connection. Errors that end it exit 255.

Data - file contents and command output - moves over WebRTC, direct or through TURN, like every other session's. When
no data channel opens within 10 s, or WebRTC fails outright, `dgcli` tells the device so and the relay carries it,
kept below the relay's per-session limit.

The operation comes first, then its options, then its operands. Each option belongs to the operations it means something to - `-f` to `cp`, `-r` to `rm`, `-j` to `ls`, `-t`, `-C` and `-o` to `exec` - and is refused anywhere else rather than ignored (`rm -rf` asks you to drop the `f`; nothing ever asks before removing). `exec` takes the device and then the command; whatever follows the device belongs to the command (`dgcli exec host ls -la` runs `ls -la`, and `--` may separate them). The file operations name the remote side the way `scp` does, as `<device>:<path>`: `cp` copies whichever way that points, so exactly one of its two arguments is remote, and `mv` moves within one device (its target may be written `/b` or `homelab:/b`). Anything with no `<device>:` in front is local; a single letter before the colon is a Windows drive (`C:\dir`), and `./name:with:colons` is how to name a local file whose name holds a colon. Remote paths must be absolute.

Nothing is replaced without `-f`: not an existing local file a download would land on, and not an existing remote file an upload would land on. The local check happens before anything is fetched and again when the finished download is moved into place, so a file that appears in the meantime is not replaced either - the download fails and leaves it alone.

Ctrl-C (or SIGTERM) is forwarded to a running command, whose exit is still waited for; a second one ends `dgcli`. A command still running when its session ends - `dgcli` gone, the connection lost - is hung up and then killed, with its process group. Should the agent itself die, Linux kills the command's shell with it and Windows its whole job; on macOS it runs on until it ends.

Exit codes: `exec` exits with the command's own status - 128 + the signal for one ended by a signal, 137 for one killed for its timeout. `dgcli` itself failing - bad arguments, signing in, connecting, a device that does not match, an agent too old to run commands (it says so) - exits 255, as ssh does. The file operations exit 0 on success and 1 when the device refuses or a local file is in the way (the reason is on stderr).

These never ask for a password without a terminal, so authenticate with a client key first (`dgcli -g`, then `dgcli -A -d <device>`, above). A download is written next to its destination, checked against its SHA-256 and only then moved into place; an upload is reserved on the device first and only replaces anything once it is verified there.

### MCP server

`dgcli mcp` serves the same operations to an AI agent as [Model Context Protocol](https://modelcontextprotocol.io) tools, over stdio: `list_devices`, `exec`, `list_directory`, `read_file`, `write_file`, `upload`, `download`, `remove`, `make_directory`, `move` and `disconnect`. A call runs `dgcli` again for that one operation - its own connection, authentication and end-to-end keys - unless it passes `keep_open: true`: then the connection (a `dgcli session`) stays open, and the device's next calls run on it without signalling or authenticating again, until `disconnect` closes it, the session's idle or lifetime limit ends it, or `dgcli mcp` exits. At most 8 are kept, the least recently used one closing first; a kept connection that turns out to be gone is opened again for the call, and an agent too old for sessions gets one connection per call as before. It runs on the machine the AI agent runs on - the keys never leave it - and takes the options its calls should use (`-c`, `-k`, `-a`, `-w`).

For Claude Code, for example:

```sh
claude mcp add directgate -- dgcli mcp
```

or in an MCP client's JSON configuration:

```json
{ "mcpServers": { "directgate": { "command": "dgcli", "args": ["mcp"] } } }
```

`exec` returns the exit code, stdout and stderr (each cut at 128 KB) both as text and as structured content, and is an error result when the command exits non-zero. The device is asked for no more than that (`-o`), so a command that prints megabytes does not send them over the link only for them to be thrown away; a cut is reported as `truncated`. `read_file` returns UTF-8 text up to 256 KB and refuses anything larger or binary, pointing at `download`. A command gets 600 s unless the call names a `timeout_seconds`.

### Client config

`dgcli` runs with no config at all. A `client.json` is only needed to override the built-in endpoints:

```json
{
  "apiUrl": "https://api.directgate.io",
  "webUrl": "https://directgate.io",
  "signalingUrl": "wss://relay1.directgate.io/websock",
  "iceServers": ["stun:stun.cloudflare.com:3478"]
}
```

| Field          | Type     | Description                                              |
|----------------|----------|----------------------------------------------------------|
| `apiUrl`       | string   | Control-plane API origin                                  |
| `webUrl`       | string   | Web app origin, hosts the `/cli-auth` sign-in page        |
| `signalingUrl` | string   | Relay endpoint; normally supplied by the session envelope |
| `apiToken`     | string   | Pre-issued bearer token; replaces the browser sign-in     |
| `keyPath`      | string   | Client key file tried before the password                 |
| `iceServers`   | string[] | ICE/TURN server URLs for WebRTC (optional)                |

`apiUrl` and `webUrl` may also be set per shell through `DIRECTGATE_API_URL` and `DIRECTGATE_WEB_URL`, which take precedence over the config file. Their compiled-in defaults come from the CMake cache variables of the same names, so a self-hosted build ships a binary that points at its own stack - and since those are the only endpoints it carries, that is all a fork has to change.

Setting `apiToken` skips the account sign-in entirely and is the path to use for automation, where no browser is available to authorize anything.
