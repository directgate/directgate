[Back to README](../README.md)

# File transfer & remote file manager

The agent powers the browser file manager and code editor through two mechanisms, over either transport (WebRTC P2P or WebSocket relay).

## Remote file manager (`manager`)

The `manager` message type exposes filesystem operations to the client:

| Action   | Purpose                                       |
|----------|-----------------------------------------------|
| `list`   | List a directory                              |
| `open`   | Read a file (powers previews and the editor)  |
| `save`   | Write a file                                  |
| `mkdir`  | Create a directory                            |
| `rename` | Rename an entry                               |
| `copy`   | Copy a file or directory                      |
| `move`   | Move an entry                                 |
| `delete` | Delete a file or directory                    |
| `search` | File search - streamed and cancelable         |

Search is more than name matching: it supports **recursive** traversal and **advanced filters** - file name, text/content inside files, file type, size range, permissions, and link count, with case-insensitive matching. Results stream back incrementally, in batches, and a long-running search can be canceled mid-run.

Search, copy and delete all run off the agent's event loop, so a search over a whole disk or a copy of a large tree never freezes the session that asked for it - or the terminals and desktops other clients have open on the same device. One copy or delete runs per session at a time, and recursion stops at 256 directory levels. A second copy or delete sent before the first has answered fails at once with `another file operation is in progress`; see the [protocol specification](protocol.md).

Together with the [chunked file transfer](#chunked-file-transfer-file) below, these primitives deliver a full file-manager experience in the web and mobile clients:

- **Upload and download** files of any size - chunked and integrity-checked
- **Cut, copy, paste, rename, and delete** entries
- **Drag and drop between different devices** - drag a file out of one paired machine's file manager and drop it straight into another's
- **Search, recursive search, and advanced search** with all the filters above
- **Image and video playback** directly in the browser, streamed from the agent
- A built-in **code editor** for editing files in place

It works identically in the desktop web client and on mobile, and every request and response travels over the same authenticated, end-to-end-encrypted channel as the terminal.

## Chunked file transfer (`file`)

Bidirectional file transfer uses a dedicated `file` message type with the following actions:

| Action        | Direction          | Purpose                                     |
|---------------|--------------------|---------------------------------------------|
| `file/start`  | Sender → Receiver  | Begin transfer: filename, size, chunk count |
| `file/chunk`  | Sender → Receiver  | One 64 KB chunk of file data                |
| `file/end`    | Sender → Receiver  | Transfer complete, with SHA-256 hash        |
| `file/ack`    | Receiver → Sender  | Acknowledgement for a chunk (or final)      |
| `file/cancel` | Either → Either    | Abort an in-progress transfer               |

- **Chunk size:** fixed at **64 KB**, safe for both WebRTC data channels and WebSocket frames. Files of any size are supported; the chunk count is calculated and sent in `file/start`.
- **Integrity:** a running **SHA-256** hash is accumulated over all chunks. The sender includes the final digest in `file/end`; the receiver verifies it before accepting the file. On mismatch, the partial file is discarded.
- **Transfer ID:** each transfer has a unique string ID (timestamp + random component).
- **Async sending:** chunk sending is driven by the event-loop interrupt handler (one chunk per tick), keeping the event loop responsive and avoiding frame-size or buffer overflow on either transport.

## See also

- [Protocol specification](protocol.md) - header fields for the `manager` and `file` message types
