[Back to README](../README.md)

# Linux desktop sessions

The agent streams an Xorg desktop with XShm capture and XTest input, and a
Wayland desktop through `xdg-desktop-portal` + PipeWire. Which one is used is
decided from the session type, not from what happens to be installed.

## Xorg

Nothing is required beyond the X11 libraries the agent already links. Capture
uses MIT-SHM where available and falls back to `XGetImage`; input goes through
the XTest extension, which is loaded at runtime.

## Building with Wayland support

Wayland streaming is compiled in only when the PipeWire and D-Bus **headers**
are present at configure time. Neither library is linked - both are loaded at
runtime - so these are build-time dependencies only, and their absence costs
nothing on an X11-only host:

```sh
sudo dnf install pipewire-devel dbus-devel        # Fedora / RHEL
sudo apt install libpipewire-0.3-dev libdbus-1-dev # Debian / Ubuntu
sudo pacman -S libpipewire dbus                    # Arch
```

Configure prints which one it took:

```
-- Wayland desktop streaming: enabled (PipeWire 1.4.11 headers, runtime dlopen)
```

If it says `disabled`, the agent reports *"This agent was built without
Wayland desktop streaming"* at run time. Install the packages and **re-run
cmake** - a plain `cmake --build` will not re-check. If configure still says
disabled afterwards, delete `CMakeCache.txt` and configure again.

## Wayland sessions

The agent streams a Wayland desktop through `xdg-desktop-portal`: the
compositor is asked for permission, the pixels then arrive over PipeWire, and
keyboard and pointer events go back through the portal's RemoteDesktop
interface. A Wayland client cannot read the screen or synthesise input on its
own, and DirectGate does not try to work around that.

Requirements on the streamed machine:

- `pipewire` and `dbus` runtime libraries (both already present on a normal
  desktop install). They are loaded at runtime, not linked, so an X11-only
  host without them runs the same binary unchanged.
- A desktop portal with a ScreenCast **and** RemoteDesktop backend -
  `xdg-desktop-portal-gnome` or `xdg-desktop-portal-kde`. A wlroots-only
  setup (`xdg-desktop-portal-wlr`) can capture but cannot inject input.

The first connection raises a permission prompt on the remote machine, which
someone has to be there to allow. Until they do, the session is refused with
*"Waiting for screen sharing to be allowed on the remote computer"* rather
than streaming a black screen. Once allowed, the grant is remembered in
`~/.config/directgate/wayland.token` (owner-only) and later connections start
without a prompt.

Two behaviours differ from X11 and are the compositor's rules, not choices
this agent makes:

- **The cursor is drawn into the frames.** A Wayland client is not told where
  the pointer is, so it cannot be composited separately the way the X11 path
  does it.
- **One screen at a time.** The portal grants a single stream, so the monitor
  list holds exactly that stream rather than every output.

Nothing about the X11 path changes. The session type is decided before the
display is opened, because XWayland sets `DISPLAY` on a Wayland session too
and capturing that would silently produce a black screen: a machine that
reports `XDG_SESSION_TYPE=x11` is always treated as X11.
