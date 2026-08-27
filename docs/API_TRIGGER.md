# Netping: Trigger Mode API Architecture & Specification

This document specifies the architecture, CLI commands, security model, and REST API specification for Netping's **TRIGGER Mode**.

---

## 1. Executive Summary & Operating Modes

Netping operates in two distinct modes:

```
                      +-------------------------------------------------------------+
                      |                   NETPING HTTP SERVER                       |
                      |                                                             |
                      |  [ Public / SUBSCRIBER Mode ]    [ Authenticated / TRIGGER ]|
                      |  - GET /api/v1/stream (SSE)      - POST /api/v1/trigger     |
                      |  - GET /api/v1/metrics           - POST /api/v1/targets     |
                      |  - GET /api/v1/targets           - DELETE /api/v1/targets/:id|
                      |  - GET /api/v1/probes            - POST /api/v1/reset       |
                      |  - Web UI Dashboard / Docs                                  |
                      +------------------+-----------------------------+------------+
                                         |                             |
                                         |                             | [X-API-Key / Bearer]
                                         |                             v
                                         |               +-----------------------------+
                                         |               |    Argon2id Auth Engine     |
                                         |               | - ConstantTimeCompare       |
                                         |               | - Memory Zeroing (RAM)      |
                                         |               +-------------+---------------+
                                         |                             | (Authorized)
                                         |                             v
                      +------------------v---------+     +-----------------------------+
                      |     Event Broadcaster      |<----+   Dynamic Probing Engine    |
                      | (SSE Channels & History)   |     | - On-demand Single/Batch    |
                      +----------------------------+     | - Dynamic Fleet Workers     |
                                                         +-----------------------------+
```

| Dimension | Subscriber Mode (CLI-driven) | Trigger Mode (API-driven) |
| :--- | :--- | :--- |
| **Startup Command** | `netping --host <target> --port <port> [flags] --web` | `netping --trigger-mode --api-key-store <path>` |
| **CLI Target Args** | **Required** (`--host`, `--port`, or `--uri`) | **None** (Starts idle listener daemon) |
| **Probe Execution** | Fixed targets probed continuously from CLI | Dynamic on-demand or fleet probes via REST API |
| **Telemetry / Web UI**| **Public** (`/api/v1/stream`, `/api/v1/metrics`, etc.) | **Public** for web dashboard and subscribers |
| **Trigger Endpoints** | Disabled / Not registered | **Protected** via Argon2id API Keys |
| **Key Storage** | N/A | Keystore file with irreversible Argon2id hashes |

---

## 2. API Key Management & Keystore

### 2.1 Generating API Keys
Generate a high-entropy 256-bit API key and automatically record its Argon2id hash into the keystore.

**Linux / macOS**:
```bash
netping --generate-api-key /etc/netping/keystore.json
```

**Windows (Supports drive letters, forward slashes, and backslashes)**:
```powershell
netping --generate-api-key E:/data/netping/keystore.json
# or
netping.exe --generate-api-key C:\Users\app\AppData\Roaming\netping\keystore.json
```

**Console Output**:
```text
✔ Generated new strong API key!
  Keystore: E:/data/netping/keystore.json (Argon2id hash recorded)
  API Key:  np_live_4f9a8b1c7d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a

⚠️  Store this API key securely. It cannot be recovered from the keystore!
```

---

### 2.2 Keystore Storage & Cross-Platform Path Handling
The keystore file (`keystore.json` or `.keys`) contains only non-reversible Argon2id hashes.

#### Cross-Platform Path & File Normalization:
- **Windows Support**: Fully handles drive letter paths (`E:/path/to/keystore.json`, `E:\path\to\keystore.json`), UNC paths, and relative paths (`.\keystore.json`) using `filepath.Clean` and `filepath.Abs`.
- **Directory Creation**: Automatically creates any missing parent directories (`os.MkdirAll(filepath.Dir(path), 0755)`).
- **Permissions**:
  - **Linux / Unix**: Enforces strict `0600` owner-only read/write permissions.
  - **Windows**: Uses standard secure file ACLs without POSIX mode bit failure.

```json
{
  "version": "1.0",
  "keys": [
    {
      "id": "key_1",
      "created_at": "2026-08-24T12:00:00Z",
      "hash": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQxMjM0NTY3OA$9xY2v7P8..."
    }
  ]
}
```

> [!NOTE]
> The server **never** stores the plaintext API key. Because Argon2id is a one-way memory-hard hash function, stealing the keystore does not grant an attacker access.

---

### 2.3 Key Verification & In-Memory RAM Hygiene

```
[ Incoming HTTP Request ]  --->  Header: "X-API-Key: np_live_..." (Byte buffer)
                                                      |
                                                      v
                                        +---------------------------+
                                        | Argon2id Hash Calculation |
                                        | (Memory: 64MB, Iter: 3)   |
                                        +-------------+-------------+
                                                      |
                                                      v
[ Keystore Argon2 Hash ] --------------> [ ConstantTimeCompare ] ---> [ Zero RAM Buffer ]
                                                      |
                                             +--------+--------+
                                             |                 |
                                      (Valid / Match)  (Invalid / Mismatch)
                                             |                 |
                                        [ Execute ]      [ 401 Reject ]
```

- **Argon2id Parameters (OWASP Compliant)**:
  - Memory: `64 MB` (`65536 KiB`)
  - Iterations / Time Cost: `3`
  - Parallelism: `4` threads
  - Salt Length: `16 bytes` (CSPRNG)
- **Constant-Time Verification**: Uses `crypto/subtle.ConstantTimeCompare` to eliminate timing side-channel attacks.
- **Memory Hygiene**: Incoming key bytes in RAM are immediately wiped (`zeroBytes`) in a `defer` block after verification.

---

## 3. Starting the Netping Trigger Listener

### 3.1 CLI Startup Command
To start the daemon in Trigger Mode:

**Linux / macOS**:
```bash
netping --trigger-mode --listen 127.0.0.1:3000 --api-key-store /etc/netping/keystore.json
```

**Windows (PowerShell / Command Prompt)**:
```powershell
netping.exe --trigger-mode --listen 127.0.0.1:3000 --api-key-store E:/data/netping/keystore.json
# or with backslashes
netping.exe --trigger-mode --listen :3000 --api-key-store C:\netping\keystore.json
```

### 3.2 Environment Variable Support
Ideal for Docker / Kubernetes container environments:
```bash
export NETPING_API_KEY_STORE="/etc/netping/keystore.json"
# Or direct inline hash:
export NETPING_API_KEY_HASH='$argon2id$v=19$m=65536,t=3,p=4$...'

netping --trigger-mode --listen :3000
```

### 3.3 Startup Banner
```text
● Netping Trigger Daemon live at: http://127.0.0.1:3000
● REST Trigger API: Protected (Argon2id Keystore: /etc/netping/keystore.json)
● Subscriber API & Dashboard: Public at http://127.0.0.1:3000
● Ready to accept REST trigger calls...
```

---

## 4. Trigger Mode API Specification

### 4.1 Authentication Headers
Requests to protected endpoints must supply the API key in either header:
- `X-API-Key: np_live_...`
- `Authorization: Bearer np_live_...`

### 4.2 API Endpoints Matrix

| Endpoint | Method | Authentication | Description |
| :--- | :--- | :--- | :--- |
| `/api/v1/trigger` | `POST` | **Argon2id Protected** | Executes an on-demand synchronous probe (single or batch). |
| `/api/v1/targets` | `POST` | **Argon2id Protected** | Dynamically registers a background monitored target into fleet. |
| `/api/v1/targets/{id}` | `DELETE` | **Argon2id Protected** | Deregisters and stops an active fleet target. |
| `/api/v1/reset` | `POST` | **Argon2id Protected** | Resets telemetry metrics, history ring buffer, and counters. |
| `/api/v1/trigger/status` | `GET` | **Argon2id Protected** | Returns trigger engine status, active workers, and queue capacity. |
| `/api/v1/stream` | `GET` | **Public** | Real-time Server-Sent Events (SSE) telemetry stream. |
| `/api/v1/metrics` | `GET` | **Public** | Aggregate fleet and per-target metrics. |
| `/api/v1/targets` | `GET` | **Public** | List all monitored targets and current statistics. |
| `/api/v1/probes` | `GET` | **Public** | Paginated historical probe events query. |
| `/api/v1/health` | `GET` | **Public** | Server health, uptime, and target count. |
| `/api/docs` | `GET` | **Public** | Interactive Swagger UI / OpenAPI 3.0 documentation. |

---

### 4.3 Probe Execution Schema (`POST /api/v1/trigger`)

All CLI probe execution controls are mapped 1-to-1 to the JSON request payload:

**Request Body (`application/json`)**:
```json
{
  "target": "db.corp.internal",
  "port": 5432,
  "protocol": "postgres",
  "timeout": "2.5s",
  "count": 1,
  "interval": "1s",
  "retries": 2,
  "retry_backoff": "50ms",
  "max_latency_ms": 150.0,
  "use_ipv4": true,
  "send_data": "",
  "expect_data": "",
  "service_name": "",
  "traceroute": false,
  "show_diags": true,
  "broadcast": true
}
```

**Success Response (`200 OK`)**:
```json
{
  "success": true,
  "target": "db.corp.internal:5432",
  "protocol": "POSTGRES",
  "ip": "10.0.4.12",
  "port": 5432,
  "rtt_ms": 12.45,
  "dns_time_ms": 1.20,
  "tcp_time_ms": 3.80,
  "tls_time_ms": 7.45,
  "ttfb_ms": 11.90,
  "diagnostics": "TLS 1.3 / TLS_AES_128_GCM_SHA256",
  "timestamp": "2026-08-24T15:30:00.123Z"
}
```

**Failure Response (`200 OK` with failure details)**:
```json
{
  "success": false,
  "target": "db.corp.internal:5432",
  "protocol": "POSTGRES",
  "ip": "10.0.4.12",
  "port": 5432,
  "rtt_ms": 0,
  "error": "dial tcp 10.0.4.12:5432: connect: connection refused",
  "error_code": "CONNECTION_REFUSED",
  "timestamp": "2026-08-24T15:30:00.123Z"
}
```

*(When `broadcast: true` (default), the event is dispatched in real time to SSE subscribers on `/api/v1/stream` and added to queryable history).*

---

### 4.4 CORS & Preflight Handling
The HTTP server and auth middleware implement full Cross-Origin Resource Sharing (CORS):
- Handles HTTP `OPTIONS` preflight requests unauthenticated (returning `204 No Content`).
- Sends headers:
  - `Access-Control-Allow-Origin: *`
  - `Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS`
  - `Access-Control-Allow-Headers: Authorization, X-API-Key, Content-Type`

---

## 5. REST Client Invocations & Workflow Models

### Workflow 1: Direct Synchronous Trigger (No Subscription Needed)
**Target**: CI/CD pipelines, automations, ad-hoc probe scripts.

```
REST Client                                          Netping Listener (Trigger Mode)
    |                                                               |
    |  POST /api/v1/trigger                                         |
    |  Header: X-API-Key: np_live_...                               |
    |  Body: {"target": "db.corp:5432", "protocol": "postgres"}     |
    |-------------------------------------------------------------->|
    |                                                               |  [Executes Probe]
    |  HTTP 200 OK (JSON with RTT, TLS, Diags, Success/Fail)        |
    |<--------------------------------------------------------------|
```

```bash
curl -s -X POST http://127.0.0.1:3000/api/v1/trigger \
  -H "X-API-Key: np_live_4f9a8b1c7d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a" \
  -H "Content-Type: application/json" \
  -d '{"target": "db.corp.internal", "port": 5432, "protocol": "postgres", "timeout": "2s"}'
```

---

### Workflow 2: Interactive Real-Time UI (**Subscribe First, Then Trigger**)
**Target**: Web UIs, SPAs, multi-service dashboards.

> [!IMPORTANT]
> **Best Practice**: Always **Subscribe FIRST, then Trigger** to ensure fast probe events aren't missed during the SSE connection handshake.

```
Web Dashboard (Public / Subscriber)      REST Controller (Auth)         Netping Daemon
        |                                       |                              |
[1. Connect SSE]                                |                              |
        |  GET /api/v1/stream                   |                              |
        |--------------------------------------------------------------------->| (Public SSE Pipe Established)
        |  HTTP 200 (text/event-stream)         |                              |
        |<---------------------------------------------------------------------|
        |                                       |                              |
        |                               [2. Trigger Probe]                     |
        |                                       |  POST /api/v1/trigger        |
        |                                       |  Header: X-API-Key: <key>    |
        |                                       |----------------------------->| (Auth Verified)
        |                                       |  HTTP 200 OK (Probe Result)  |
        |                                       |<-----------------------------|
        |                                       |                              |
[3. Live Stream Event Received]                 |                              |
        |  event: data: {"target":"...", ...}   |                              |
        |<---------------------------------------------------------------------|
```

1. **Frontend opens public SSE pipe**:
   ```javascript
   const events = new EventSource('/api/v1/stream');
   events.onmessage = (e) => console.log('Live probe:', JSON.parse(e.data));
   ```
2. **Controller initiates probe** via `POST /api/v1/trigger` with `X-API-Key`.
3. **Frontend receives broadcast event** automatically over SSE.

---

## 6. Architecture & Implementation Blueprint

```
[ CLI Flags / Env ] ---> [ ProcessUserInput ]
                                 |
              +------------------+------------------+
              |                                     |
    (Subscriber Mode)                         (Trigger Mode)
              |                                     |
[ Resolve CLI Targets ]                    [ Load Keystore Hashes ]
              |                                     |
[ Start Web Server ]                       [ Start Listener Server ]
              |                                     |
[ Run CLI Probers Loop ]                   [ Await HTTP Triggers ]
```

### Module Structure:
1. **`pkg/auth` (Authentication & Keystore)**:
   - `keystore.go`: Loads and appends Argon2id hashes from/to keystore file.
   - `keygen.go`: Generates strong 256-bit keys and computes Argon2id hashes (`--generate-api-key`).
   - `middleware.go`: HTTP interceptor enforcing constant-time Argon2id verification on protected routes.
   - `memory.go`: RAM buffer zeroing utilities.
2. **`pkg/engine` (Dynamic Prober)**:
   - Synchronous probe execution wrapper reusing `buildPingerForTarget` for all 25+ protocols.
   - Worker pool concurrency limiter.
   - Dynamic target fleet manager.
3. **`pkg/web` (HTTP Server & OpenAPI)**:
   - Registers `/api/v1/trigger` and dynamic target routes with auth middleware.
   - Preserves public unauthenticated access for `/api/v1/stream`, `/api/v1/metrics`, `/api/v1/targets`, `/api/v1/probes`, `/api/v1/health`, and `dashboard.html`.
   - Updates OpenAPI 3.0 definition in `/api/openapi.json`.
4. **`internal/config` & `cmd/netping.go`**:
   - Flags: `--trigger-mode` / `--listen`, `--generate-api-key`, `--api-key-store`, `--api-key-hash`.
   - Starts daemon without CLI targets when `--trigger-mode` or `--generate-api-key` is supplied.

---

## 7. Implementation Roadmap

1. **Dependency Verification**:
   - Add `golang.org/x/crypto/argon2` to `go.mod`.
2. **Authentication & Keystore Package (`pkg/auth`)**:
   - Implement `keygen.go`, `keystore.go`, `middleware.go`, and comprehensive unit tests.
3. **Dynamic Prober Engine (`pkg/engine`)**:
   - Implement dynamic single-shot and continuous probe executors.
4. **Web Server & OpenAPI (`pkg/web`)**:
   - Add trigger routes with auth middleware; update OpenAPI spec.
5. **CLI & Startup Lifecycle (`internal/config`, `cmd/netping.go`)**:
   - Integrate `--generate-api-key`, `--api-key-store`, and `--trigger-mode`.
6. **Integration & Regression Testing**:
   - Validate key generation, keystore loading, authenticated triggers, unauthorized rejections (`401`), SSE broadcasting, and verify that existing CLI subscriber mode and dashboard are 100% unaffected.

---

## 8. Operational, Performance & Security Considerations

### 8.1 Authentication DoS & Resource Protection
- **Argon2id Compute Profile**: Argon2id with 64 MB RAM and 3 iterations is intentionally compute/memory-heavy to prevent brute-force attacks.
- **Mitigation**: An unauthenticated attacker could attempt to exhaust server CPU by flooding invalid `X-API-Key` requests. To protect the listener:
  - Enforce max concurrent authentication calculations (e.g. capped worker semaphore).
  - Return `401 Unauthorized` with immediate cooldown for repeat failures from the same IP.

### 8.2 In-Transit Security (TLS Recommendation)
- The raw API key (`np_live_...`) is sent in plaintext HTTP headers (`X-API-Key` or `Authorization: Bearer`).
- **Production Deployment**: When running over public or untrusted networks, the Netping listener should either:
  - Terminate TLS directly (via HTTPS flags or reverse proxy like Nginx, Traefik, Caddy, or Cloudflare Tunnel).
  - Bind strictly to `127.0.0.1` or internal private VPC subnets.

### 8.3 Socket & Concurrency Resource Management
- **High-Throughput Triggering**: Rapid ad-hoc trigger execution can generate thousands of short-lived TCP sockets.
- **TIME_WAIT Mitigation**: Enable `"fast_close": true` (sets `SO_LINGER=0`) in high-frequency trigger payloads to force immediate TCP RST on close and prevent ephemeral socket exhaustion.
- **Worker Pool Limits**: Dynamic probe executions are bounded by a configurable concurrency semaphore (`--trigger-concurrency`, default: 100) returning `429 Too Many Requests` if the pool is fully saturated.

### 8.4 Network Perimeter & SSRF Isolation
- Because the Trigger API allows probing arbitrary network destinations (IPs, hostnames, ports), the server effectively acts as a network client.
- **Recommendation**: Deploy Netping within a dedicated management or monitoring network boundary, ensuring it cannot be leveraged as an open egress proxy into sensitive unroutable subnets.

### 8.5 Zero-Downtime Key Rotation
- The keystore supports multiple active keys in its JSON array.
- **Hot Reload**: The listener checks the keystore file modification timestamp (`ModTime`) on each authenticated request or periodic ticker, automatically loading newly added keys without requiring a daemon restart or dropping active SSE subscriber connections.

### 8.6 Telemetry Retention & Slow Client Isolation
- **Ring Buffer Capping**: Triggered probe events with `"broadcast": true` enter the in-memory history buffer (default: 1,000,000 events, max: 5,000,000). Excess events are pruned in $O(1)$ time without memory leaks.
- **Non-Blocking SSE**: The broadcaster uses non-blocking channel select (`select { case ch <- ev: default: }`) to guarantee that slow or lagging browser clients never block or delay real-time trigger probe execution.
