# Binary HTTP: Network Architecture Project

A small HTTP-like protocol that runs over TCP using **binary frames** instead of text. The project has two programs that talk only through the protocol spec:

| Program | Source | Role |
|---|---|---|
| `bserve` | `server.cpp` | Serves files from a root directory |
| `bcurl` | `bcurl.cpp` | Fetches one file and prints the body to stdout |

## Project layout

```
.
├── server.cpp      # Track 1: the server (bserve)
├── bcurl.cpp       # Track 2: the client (bcurl)
├── www/
│   └── index.html  # sample file to serve
└── README.md
```

## Build

Requires a C++17 compiler on Linux or macOS.

```bash
g++ -std=c++17 -Wall -Wextra -o bserve server.cpp
g++ -std=c++17 -Wall -Wextra -o bcurl  bcurl.cpp
```

## Run

Start the server in one terminal:

```bash
./bserve ./www 9000
```

Fetch a file from another:

```bash
./bcurl localhost:9000/index.html          # body to stdout
./bcurl -v localhost:9000/index.html       # also hexdump every frame to stderr
./bcurl localhost:9000/index.html > out.html   # save the body only
```

### Server

```
./bserve ROOT PORT
```

- Listens on all IPv4 interfaces.
- Serves files only from under `ROOT`. Requests that escape it (for example `/../server.cpp`) get a 400.
- Keeps each connection open and handles any number of requests on it.
- Handles one connection at a time.

### Client

```
./bcurl [-v] host:port/path
```

- `http://` before the host is accepted and ignored. If the port is omitted it defaults to 80.
- Builds one request frame, reads the response on the same connection, and never opens a second connection.
- The body goes to **stdout**. Everything else (`-v` output, errors) goes to **stderr**, so redirecting stdout always gives a clean copy of the file.
- `-v` hexdumps every frame sent and received, with a one-line decoded summary for each.

| Exit code | Meaning |
|---|---|
| `0` | Success (status below 400) |
| `1` | Server replied 4xx or 5xx |
| `2` | Usage, network or protocol error |

## Protocol summary

All multi-byte integers are **big-endian**. The full specification is in the separate spec document. This is the short version.

### Frame

Every frame is a fixed 9-byte header followed by a payload.

| Field | Size | Notes |
|---|---|---|
| Length | 3 bytes | Payload size only, at most 16,777,215 |
| Type | 1 byte | See below |
| Flags | 1 byte | Reserved, sent as `0x00` |
| Stream ID | 4 bytes | Top bit reserved and must be 0, leaving 31 bits |

| Type | Name | Direction |
|---|---|---|
| `0x01` | REQUEST | client to server |
| `0x02` | RESPONSE_HEADERS | server to client |
| `0x03` | RESPONSE_BODY | server to client |
| `0x04` | END | server to client |

**Unknown frame types must be skipped.** The length comes first, so a receiver that meets a type it does not know reads and discards exactly `Length` payload bytes and carries on. This is what leaves room for a version 2.

The server echoes the request's stream ID on every response frame. The client uses stream `1` and ignores frames for any other stream.

### REQUEST payload

```
method (1) | path length (2) | path | header count (1) | headers...
```

Only `GET` (`0x01`) exists. A request for a missing file gets 404. A malformed request, an unknown method, or a path that escapes the root gets 400.

### RESPONSE_HEADERS payload

```
status (2) | header count (1) | headers...
```

### Response sequence

```
RESPONSE_HEADERS  ->  RESPONSE_BODY (zero or more)  ->  END
```

Files are sent in chunks of up to 1 MiB, one BODY frame per chunk. Error responses have no body: HEADERS (with `content-length: 0`), then END.

### Headers

The ten names below are sent as a single index byte. Any other name is sent as a literal.

| Index | Name | Index | Name |
|---|---|---|---|
| 0 | `host` | 5 | `accept` |
| 1 | `content-type` | 6 | `date` |
| 2 | `content-length` | 7 | `server` |
| 3 | `connection` | 8 | `cache-control` |
| 4 | `user-agent` | 9 | `content-encoding` |

```
known header:    index (1) | value length (2) | value
literal header:  0xFF (1)  | name length (2)  | name | value length (2) | value
```

Index bytes `10` to `254` are invalid.

## Testing

Run the server, then try each case:

```bash
./bcurl localhost:9000/index.html;  echo "exit=$?"     # 200 -> exit 0
./bcurl localhost:9000/missing.html; echo "exit=$?"    # 404 -> exit 1
./bcurl -v localhost:9000/index.html 2>&1 >/dev/null   # frame hexdump only
./bcurl localhost:9999/index.html;  echo "exit=$?"     # no server -> exit 2
```

Cross-testing: because only the spec is shared, the best check is to run your `bserve` against a partner's `bcurl`, and your `bcurl` against their `bserve`. A client that only works against its own server is an implementation, not a protocol.

## Scope and design notes

- **GET only.** The problem statement asks for a file server and a client that fetches a file, so `GET` is all that is needed. The method is a byte in the request, so other methods can be added later without changing the frame format.
- **Sequential connections.** The server handles one connection at a time and keeps it open for any number of requests. Handling several clients at once would be an extension, not part of the stated requirements.
- **Flags are reserved.** The Flags byte is always sent as `0x00` and ignored on receipt, leaving room for a future version.
- **Forward compatibility.** Receivers skip frame types they do not know, so a version 2 can add new frame types without breaking a version 1 peer.