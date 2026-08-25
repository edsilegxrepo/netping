# `netping` — Modern Multi-Protocol Network Prober & Telemetry Diagnostics Suite

`netping` is an enterprise-grade, multi-protocol network latency prober, active telemetry collector, and diagnostics suite written in Go. Designed as the modern evolution of TCP socket ping utilities, `netping` spans Layer 3 through Layer 7, providing deep protocol negotiation analysis, visual interactive terminal and web dashboards, continuous SLA monitoring, and structured log streaming.

For complete architectural specifications, concurrency mechanics, and dependency models, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## 1. Application Overview & Objectives

Traditional ping utilities are typically restricted to Layer 3 ICMP or simple Layer 4 TCP handshakes. Modern distributed systems, cloud infrastructures, and microservice meshes require granular application-layer latency analysis, TLS certificate verification, database responsiveness checks, and real-time observability.

### Core Objectives
- **Layer 3 to Layer 7 Unified Probing**: Measure handshake, TTFB, and protocol responsiveness across 49 network and application protocols (HTTP/S, gRPC/S, WebSocket/S, DNS/DoH/DoT, Redis/S, DBs, Mail, Queues, Storage, Directory, SMB, Rsync, FTP/S, SSH, O365).
- **Deep Protocol Diagnostics (`--diags`)**: Extract TLS cipher suites, certificate expiration, HTTP headers, database banners, message queue metadata, and DNS RCODEs.
- **Real-Time Visual Telemetry**:
  - **120-Column Interactive TUI Dashboard (`--dashboard`)** with a 106-point latency waveform chart.
  - **Zero-Dependency Web Dashboard (`--web`)** with Server-Sent Events (SSE) and Canvas 2D timeline graphs.
- **REST Trigger Listener & Fleet Orchestration (`--trigger-mode`)**: Dynamic probe execution via authenticated `POST /api/v1/trigger` with OWASP-compliant Argon2id key validation.
- **Enterprise Resilience & Socket Controls**: Prevent socket exhaustion under high frequencies via `SO_LINGER=0` fast teardown (`--fast-close`), and recover from transient drops with randomized exponential jitter backoff (`--retry`).
- **Flexible Data Pipelines**: Stream data natively into SIEM and monitoring pipelines using structured output formats via `--output-format` (`json`, `pretty_json`, `ndjson`, `jsonl`, `csv`, `tsv`, `sqlite`, `txt`) with optional `--output-file`, or Prometheus metrics (`--metrics-addr`).

---

## 2. Security Assessment & Hardening Posture

`netping` implements a comprehensive security baseline across transport encryption, local persistence, execution privileges, and memory isolation.

### 2.1. Encryption in Transit
- **TLS 1.2 / 1.3 Native Verification**: All secure application drivers (`HTTPS`, `TLS`, `DoT`, `DoH`, `Redis-TLS`, `SMTPS`, `IMAPS`, `POP3S`, `LDAPS`, `Kafka-TLS`, `AMQPS`, `O365`) utilize Go's cryptographic stack (`crypto/tls`), enforcing full certificate chain verification and modern cipher suite negotiation.
- **Certificate Expiration Auditing**: Active inspection alerts on expiring or expired X.509 certificates and computes remaining validity days without decrypting payload traffic.

### 2.2. Secret Management & Authentication Policy
- **Zero Ingestion of Sensitive Credentials**: `netping` probes endpoint reachability and wire protocol health via standard unauthenticated handshakes (e.g. Postgres `SSLRequest`, MySQL `HandshakeV10`, MongoDB `isMaster`, Kafka `ApiVersions`, RabbitMQ `0-9-1 Connection.Start`).
- **Argon2id REST API Authentication**: Trigger listener endpoints enforce RFC 9106 Argon2id cryptographic key hashing with 30s TTL in-memory verification caching and memory-scrubbing primitives (`ZeroBytes`).

### 2.3. Privilege Separation & Execution Context
- **Unprivileged Execution Context**: `netping` operates strictly as a standard, unprivileged non-root user.
- **Unprivileged ICMP Fallback**: Layer 3 ICMP probes utilize unprivileged datagram sockets (`net.ipv4.ping_group_range` on Linux) or unprivileged UDP fallbacks, completely eliminating the need for `CAP_NET_RAW`, `setuid root`, or `sudo`.
- **Loopback-Only Telemetry Binding**: The embedded Web Dashboard server (`--web`) defaults to `127.0.0.1:3000`, preventing unintended exposure to external network interfaces.

### 2.4. Library & Dependency Vulnerability Profile
- **Pure-Go CGo-Free Footprint**: Embedded SQLite persistence utilizes `modernc.org/sqlite` transpiled C runtime, avoiding native CGo toolchain requirements.
- **SQL Injection Prevention**: Database table names generated from target hostnames are validated against an alphanumeric regex allowlist (`^[a-zA-Z0-9_]+$`) prior to executing DDL statements.

---

## 3. Code Quality & Engineering Best Practices

`netping` adheres to strict Go idioms and architectural principles:

- **Strict Directed Acyclic Graph (DAG)**: Zero circular dependencies. Leaf packages contain zero domain-logic coupling.
- **Thread-Safe Snapshotting**: Statistics accumulators are protected by `sync.RWMutex` and exposed to output formatters via immutable `stats.Snapshot` value copies (copy-on-read).
- **Graceful Lifecycle Management**: Standard `context.Context` cancellation and signal interception (`os.Interrupt`, `syscall.SIGTERM`) guarantee that all network sockets, CSV/TSV writers, and SQLite transactions are cleanly flushed to disk via `defer printer.Done()`.
- **Standardized Diagnostic Exit Codes**:
  - `0`: Success (0% packet loss).
  - `1`: General runtime error or panic recovery.
  - `2`: CLI argument or usage syntax error.
  - `3`: DNS resolution failure.
  - `4`: Network interface or routing error.
  - `5`: Target unreachable (100% packet loss).
  - `6`: Partial packet loss (>0% and <100%).
  - `7`: Local storage or write failure (CSV/TSV/SQLite).
  - `130`: Terminated by user via `Ctrl+C` (SIGINT).

---

## 4. Command-Line Arguments Reference

```bash
netping --host <hostname|IP> --port <port> [options]
netping --uri <scheme://host:port> [options]
netping --host <host1,host2> --port <port1,port2> [options]
```

### 4.1. Target & Protocol Configuration
| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--host` | `string` | `""` | Comma-separated target hostnames or IP addresses. |
| `--port` | `string` | `""` | Comma-separated target port numbers. |
| `--uri` | `string` | `""` | Comma-separated target URIs (e.g. `https://host:443,postgres://db:5432`). |
| `--protocol` | `string` | `tcp` | Target protocol: `tcp`, `http`, `https`, `tls`, `udp`, `icmp`, `ws`, `wss`, `grpc`, `grpcs`, `dns`, `dot`, `doh`, `redis`, `rediss`, `memcached`, `smtp`, `smtps`, `imap`, `imaps`, `pop3`, `pop3s`, `ldap`, `ldaps`, `postgres`, `mysql`, `mssql`, `oracle`, `mongodb`, `cassandra`, `saphana`, `s3`, `blob`, `gcs`, `kafka`, `kafkas`, `rabbitmq`, `amqps`, `smb`, `rsync`, `ftp`, `ftps`, `ssh`, `o365`. |
| `--service`, `--oracle-service` | `string` | `""` | Database service/SID name (Oracle) or domain realm. |
| `--send` | `string` | `""` | Payload to transmit on connection (raw string for TCP/UDP; automatically switches HTTP/S prober to `POST` with request body). |
| `--expect` | `string` | `""` | Expected response substring for validation (checks raw socket replies; automatically switches HTTP/S prober to `GET` to validate response body). |
| `--starttls` | `bool` | `false` | Explicitly initiate protocol-level STARTTLS negotiation (SMTP/IMAP/POP3/LDAP). |

### 4.2. Timing, Limits & SLA Thresholds
| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--count` | `uint` | `0` (infinite) | Total number of probes to transmit before stopping. |
| `--interval` | `duration` | `1s` | Interval between probes (e.g. `1s`, `500ms`, `0.002`). |
| `--timeout` | `duration` | `1s` | Per-probe network timeout threshold. |
| `--max-latency` | `float` | `0` | Threshold latency in milliseconds; breaches count as SLA failures. |
| `--max-consecutive-fails`| `uint` | `0` | Automatically terminate probing after $N$ consecutive failures. |

### 4.3. Resilience, Retries & Socket Performance
| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--retry` | `uint` | `0` | Number of transient retry attempts per probe before recording a failure. |
| `--retry-backoff` | `float` | `0.05` | Initial retry backoff delay in seconds. |
| `--retry-max-backoff` | `float` | `2.0` | Maximum retry backoff delay cap in seconds. |
| `--retry-jitter` | `bool` | `true` | Apply randomized full jitter to exponential retry backoffs. |
| `--fast-close` | `bool` | `false` | Enable `SO_LINGER=0` (TCP RST) to bypass `TIME_WAIT` socket accumulation. |
| `--concurrency` | `int` | `0` (unlimited) | Maximum concurrent target workers during multi-target fleet probing. |

### 4.4. Network Interfaces, DNS & Routing
| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--interface` | `string` | `""` | Bind outbound traffic to a specific network interface or source IP. |
| `--dns-server` | `string` | `""` | Use custom DNS server IP or IP:port for hostname resolution. |
| `--dns-host` | `string` | `""` | Specific hostname to resolve when testing DNS probers. |
| `--retry-resolve` | `uint` | `0` | Retry DNS resolution after $N$ consecutive probe failures. |
| `--resolve-every-probe`| `bool` | `false` | Re-resolve target DNS on every probe cycle to detect Anycast/CDN rotations. |
| `--ipv4` | `bool` | `false` | Force IPv4 address resolution only. |
| `--ipv6` | `bool` | `false` | Force IPv6 address resolution only. |
| `--traceroute` | `bool` | `false` | Execute hop-by-hop Layer-4 TCP route discovery to target port. |

### 4.5. Output Formatting, Exporters & Logging
| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--diags`, `--diagnostics` | `bool` | `false` | Enable deep protocol negotiation metadata and handshake breakdown. |
| `--output-format` | `string` | `plain` | Structured output format: `plain`, `json`, `pretty_json`, `csv`, `tsv`, `sqlite`, `ndjson`, `jsonl`, `txt`. |
| `--output-file` | `string` | `""` | Destination file path for structured output exporter. |
| `--no-color` | `bool` | `false` | Disable ANSI color escapes for plain text output. |
| `--quiet` | `bool` | `false` | Quiet mode: suppress per-probe lines, output only final summary. |
| `--show-source-address`| `bool` | `false` | Display local IP address and dynamic ephemeral port for each connection. |
| `--timestamp` | `bool` | `false` | Print local timestamp prefix before every probe. |
| `--show-failures-only` | `bool` | `false` | Suppress successful replies, displaying only failed probes. |
| `--metrics-addr` | `string` | `""` | Expose Prometheus/OpenMetrics telemetry server on given address (e.g. `:9100`). |

### 4.6. Visual Dashboards (Interactive TUI & Web)
| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--dashboard` | `bool` | `false` | Launch full-screen interactive 120-column TUI dashboard with waveform history. |
| `--legacy-console` | `bool` | `false` | Use CP437/ASCII compatibility glyphs and square borders for legacy terminals (PuTTY, cmd.exe). |
| `--web` | `bool` | `false` | Launch embedded real-time web dashboard with SSE event streaming. |
| `--web-addr` | `string` | `127.0.0.1:3000` | Listening address and port for the embedded web dashboard. |
| `--url-prefix`, `--base-path` | `string` | `""` | Base URL subpath when running behind reverse proxies (e.g. `/probe`). |

### 4.7. REST API Trigger Daemon & Authentication
| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--trigger-mode` | `bool` | `false` | Start as an idle daemon accepting dynamic on-demand probe triggers via REST API. |
| `--listen` | `string` | `""` | Address to listen on for trigger mode (e.g. `127.0.0.1:3000` or `:3000`). |
| `--generate-api-key` | `string` | `""` | Generate a high-entropy API key and persist its Argon2id hash to specified store path. |
| `--api-key-store` | `string` | `""` | Path to JSON keystore containing valid Argon2id hashed API keys. |
| `--api-key-hash` | `string` | `""` | Single raw Argon2id hash string for direct authentication without a keystore file. |
| `--trigger-concurrency` | `int` | `100` | Maximum parallel worker threads for dynamic on-demand trigger executions. |
| `--history-limit` | `uint` | `1000000` | In-memory ring buffer event capacity for SSE broadcaster and REST history APIs. |

### 4.8. General & Informational
| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--version` | `bool` | `false` | Display version and exit. |
| `--help` | `bool` | `false` | Display help and usage instructions. |
| `--check-updates` | `bool` | `false` | Check for updates and exit. |

---

## 5. Usage & Deployment Examples

### 5.1. Basic & Protocol Handshake Probing

#### Standard TCP Probing with Source Address
```bash
netping --host 1.1.1.1 --port 443 --show-source-address
```
```text
Probing 1.1.1.1 on port 443
● Reply from 1.1.1.1 on port 443 using 192.168.1.100:54321: TCP_conn=1 time=14.230 ms
● Reply from 1.1.1.1 on port 443 using 192.168.1.100:54322: TCP_conn=2 time=13.890 ms
```

#### HTTPS Probing with Deep Protocol Diagnostics (`--diags`)
```bash
netping --host 1.1.1.1 --port 443 --protocol https --diags --count 2
```
```text
Probing 1.1.1.1 on port 443
● Reply from 1.1.1.1 on port 443: TCP_conn=1 time=48.210 ms
  └─ [DIAG] Status: 301 Moved Permanently │ Server: cloudflare │ Proto: HTTP/1.1 │ CertValid: 2026-12-21 (122d left) │ TTFB: 48.21ms [DNS: 0.00ms TCP: 14.10ms TLS: 22.40ms]
● Reply from 1.1.1.1 on port 443: TCP_conn=2 time=44.150 ms
  └─ [DIAG] Status: 301 Moved Permanently │ Server: cloudflare │ Proto: HTTP/1.1 │ CertValid: 2026-12-21 (122d left) │ TTFB: 44.15ms [DNS: 0.00ms TCP: 13.80ms TLS: 21.10ms]

--- 1.1.1.1 TCPing statistics ---
2 probes transmitted on port 443 │ 2 received, 0.00% packet loss
successful probes:   2
unsuccessful probes: 0
total uptime:   1 second
total downtime: 0 second
rtt min/avg/max: 44.150/46.180/48.210 ms │ jitter: 2.030 ms │ p95: 48.007 ms
```

#### HTTP/HTTPS Probing with Payload Dispatching (`--send` / `--expect`)

The HTTP/HTTPS prober dynamically adapts its request method based on configured options while retaining lightweight `HEAD` by default:

```bash
# 1. Default Lightweight HEAD Reachability & Timing Probe
netping --host api.example.com --port 443 --protocol https --diags

# 2. HTTP POST with Custom Request Payload (--send)
netping --host api.example.com --port 443 --protocol https --send '{"action":"health"}' --diags

# 3. HTTP GET with Response Body Assertion (--expect)
netping --host api.example.com --port 443 --protocol https --expect "healthy" --diags
```
```text
Probing api.example.com on port 443
● Reply from api.example.com on port 443: TCP_conn=1 time=38.450 ms
  └─ [DIAG] Status: 200 OK │ Sent: 19B │ Matched: "healthy" │ Server: envoy │ Proto: HTTP/2 (h2) │ CertValid: 2026-11-15 (83d left) │ TTFB: 38.45ms [DNS: 1.20ms TCP: 12.10ms TLS: 18.20ms]
```

---

### 5.2. Visual Dashboards

#### 120-Column Interactive Terminal TUI Dashboard
```bash
netping --host 1.1.1.1 --port 443 --dashboard --protocol https --diags
```
```text
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ NETPING DASHBOARD   Target: 1.1.1.1:443   Proto: HTTPS   Elapsed: 12s                                                │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Probes:  12           │ Success: 12           │ Failed:  0            │ Loss:    0.0%         │ Jit:    1.12 ms      │
│ Min:   13.89 ms       │ Avg:   14.45 ms       │ Max:   16.12 ms       │ P95:   15.98 ms       │ P99:   16.10 ms      │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ DIAGNOSTICS: Status: 301 Moved Permanently │ Server: cloudflare │ Proto: HTTP/1.1 │ CertValid: 2026-12-21 (122d left) │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ REAL-TIME LATENCY WAVEFORM (Last 106 probes)                                                                         │
│   20.0ms ┤                                                                                                           │
│   16.0ms ┤                                                                                                 █         │
│   12.0ms ┤                                                                                                ███        │
│    8.0ms ┤                                                                                                ████       │
│    4.0ms ┤                                                                                                ████       │
│    0.0ms ┴────────────────────────────────────────────────────────────────────────────────────────────────────────── │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ RECENT PROBE EVENT LOG                                                                                               │
│ ● [23:45:10] #11    14.21 ms │ Status: 301 Moved Permanently │ Server: cloudflare │ Proto: HTTP/1.1 │ CertValid: 122d   │
│ ● [23:45:11] #12    13.95 ms │ Status: 301 Moved Permanently │ Server: cloudflare │ Proto: HTTP/1.1 │ CertValid: 122d   │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
Press Ctrl+C to stop probing and view final report.
```

#### Terminal Compatibility & Legacy Console Mode (PuTTY, cmd.exe)
For terminal emulators or fonts lacking Unicode fractional block elements (`U+2581`–`U+2587`) or rounded box corners (such as PuTTY using *Lucida Console* or *Consolas*, or classic Windows `cmd.exe`), use `--legacy-console` or export `NETPING_LEGACY_CONSOLE=1`:

```bash
# Via CLI flag
netping --host 1.1.1.1 --port 443 --dashboard --legacy-console

# Via Environment Variable
export NETPING_LEGACY_CONSOLE=1
netping --host 1.1.1.1 --port 443 --dashboard
```
This forces compatibility mode:
- **Sparklines & Waveform**: Uses CP437/VGA-safe block characters (`_`, `▄`, `█`), avoiding missing-glyph `[?]` replacement boxes.
- **Card & Modal Borders**: Replaces Unicode rounded corners (`╭`, `╮`, `╰`, `╯`) with crisp square corners (`┌`, `┐`, `└`, `┘`).

#### Zero-Dependency Embedded Web Dashboard
```bash
netping --host 1.1.1.1 --port 443 --web --web-addr 127.0.0.1:3000
```
- Opens native HTTP server at `http://127.0.0.1:3000`.
- Connects via Server-Sent Events (SSE) for 0ms telemetry streaming and Canvas 2D latency timelines.

#### Reverse Proxy Subpath Deployment (Nginx / Caddy / Traefik)
To host the Web Dashboard and REST API behind an arbitrary subpath (e.g. `http://example.com/probe/`), pass `--url-prefix` (or set `NETPING_URL_PREFIX`):

```bash
netping --host 1.1.1.1 --port 443 --web --web-addr 127.0.0.1:8080 --url-prefix /probe
```

**Nginx Configuration:**
```nginx
location /probe {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # SSE Real-Time Stream options
    proxy_set_header Connection '';
    proxy_buffering off;
    proxy_cache off;
    chunked_transfer_encoding off;
    proxy_read_timeout 86400s;
}
```
*See [docs/REVERSE_PROXY.md](docs/REVERSE_PROXY.md) for full configuration recipes including Caddy, Traefik, and HAProxy.*

---

### 5.3. Log Streaming & Data Pipeline Ingestion

#### NDJSON Stream for Vector / FluentBit / Elasticsearch
```bash
netping --host 1.1.1.1 --port 443 --output-format ndjson | jq -c '.'
```
```json
{"type":"probe","success":true,"message":"Reply from 1.1.1.1 on port 443 TCP_conn=1 time=14.230 ms","ipAddress":"1.1.1.1","port":443,"destinationIsIP":true,"time":"14.230","ongoingSuccessfulProbes":1}
{"type":"probe","success":true,"message":"Reply from 1.1.1.1 on port 443 TCP_conn=2 time=13.890 ms","ipAddress":"1.1.1.1","port":443,"destinationIsIP":true,"time":"13.890","ongoingSuccessfulProbes":2}
```

#### Tab-Separated Values (TSV) Export
```bash
netping --host 1.1.1.1 --port 443 --output-format tsv --output-file results.tsv --count 5
```
Generates `results.tsv` (probe events) and `results_stats.tsv` (SLA summary).

#### Standing Prometheus Metrics Exporter
```bash
netping --host 1.1.1.1 --port 443 --metrics-addr :9100
```
Scrape metrics on `http://localhost:9100/metrics`:
```text
# HELP tcping_probe_duration_seconds Latency of the latest probe in seconds.
# TYPE tcping_probe_duration_seconds gauge
tcping_probe_duration_seconds 0.014230
# HELP tcping_jitter_seconds Interarrival jitter in seconds.
# TYPE tcping_jitter_seconds gauge
tcping_jitter_seconds 0.001120
# HELP tcping_packet_loss_ratio Ratio of failed probes.
# TYPE tcping_packet_loss_ratio gauge
tcping_packet_loss_ratio 0.000000
```

---

### 5.4. Enterprise Resilience & High-Speed Controls

#### High-Frequency Probing with Fast-Close (Bypass Socket Exhaustion)
```bash
netping --host 1.1.1.1 --port 443 --interval 0.002 --fast-close
```

#### Transient Failure Recovery with Exponential Jitter Backoff
```bash
netping --host 1.1.1.1 --port 443 --retry 3 --retry-backoff 0.1 --retry-max-backoff 1.0 --retry-jitter
```

#### Multi-Target Concurrent Comparison
```bash
netping --host 1.1.1.1,8.8.8.8,9.9.9.9 --port 53 --protocol dns
```
```text
========================= MULTI-TARGET SUMMARY =========================
TARGET                       SENT       RECV       LOSS %     AVG (ms)   MAX (ms)  
------------------------------------------------------------------------
1.1.1.1:53                   10         10         0.0      % 14.12      15.80     
8.8.8.8:53                   10         10         0.0      % 18.45      21.10     
9.9.9.9:53                   10         10         0.0      % 16.20      17.90     
========================================================================
```

---

### 5.5. Dynamic REST Trigger Daemon & API Key Authentication

`netping` can run as a long-lived, headless daemon accepting dynamic, authenticated probe triggers from CI/CD pipelines, orchestrators, and monitoring systems.

#### 1. Generate an Argon2id API Key
```bash
netping --generate-api-key ./keystore.json
```
```text
✓ API Key generated successfully!

  API Key (Save now - cannot be recovered):
  np_live_018f9e6b4a2c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c

  Argon2id Hash saved to: ./keystore.json
```

#### 2. Start the Trigger Listener Daemon
```bash
netping --trigger-mode --api-key-store ./keystore.json --web-addr :3000 --trigger-concurrency 50
```

#### 3. Execute Dynamic On-Demand Probes (`POST /api/v1/trigger`)
```bash
curl -X POST http://localhost:3000/api/v1/trigger \
  -H "Authorization: Bearer np_live_018f9e6b4a2c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com:443",
    "protocol": "https",
    "count": 3,
    "interval": "200ms",
    "timeout": "2s",
    "show_diags": true,
    "sla_max_latency": 150.0,
    "broadcast": true
  }'
```

#### 4. REST API Endpoint Reference
| Endpoint | Method | Auth | Description |
| :--- | :---: | :---: | :--- |
| `/api/v1/trigger` | `POST` | Bearer Token | Execute synchronous or count-limited dynamic probe runs. |
| `/api/v1/targets` | `GET` | Public / Key | List all actively monitored targets and current metrics. |
| `/api/v1/metrics` | `GET` | Public / Key | Retrieve target-level SLA metrics, loss %, and jitter. |
| `/api/v1/probes` | `GET` | Public / Key | Paginated historical probe events with filtering. |
| `/api/v1/events` | `GET` | Public / Key | Real-time Server-Sent Events (SSE) stream. |
| `/api/v1/export/csv` | `GET` | Public / Key | Export current fleet telemetry as an RFC 4180 CSV file. |
| `/api/v1/export/json`| `GET` | Public / Key | Export current fleet telemetry as structured JSON. |
| `/api/v1/openapi.json` | `GET` | Public | OpenAPI 3.0 specification for automated SDK generation. |

---

## 6. Architecture & System Design

For deep architectural reviews, sequence diagrams, concurrency models, dependency DAGs, testing strategies, and security specifications, refer to:
- **[`ARCHITECTURE.md`](ARCHITECTURE.md)**: System architecture, data flow sequences, concurrency model, and threat matrix.
- **[`TESTING.md`](TESTING.md)**: Test suite architecture, wire-level mock fixtures, and race detection guide.
- **[`docs/API_TRIGGER.md`](docs/API_TRIGGER.md)**: Exhaustive API Trigger daemon specification and OpenAPI models.
- **[`docs/MODERNIZATION.md`](docs/MODERNIZATION.md)**: Master modernization roadmap, protocol capabilities, and feature validation.
- **[`docs/CONCURRENCY.md`](docs/CONCURRENCY.md)**: Concurrency and thread safety audit.
