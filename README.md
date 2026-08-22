# `netping` — Modern Multi-Protocol Network Prober & Telemetry Diagnostics Suite

`netping` is an enterprise-grade, multi-protocol network latency prober, active telemetry collector, and diagnostics suite written in Go. Designed as the modern evolution of TCP socket ping utilities, `netping` spans Layer 3 through Layer 7, providing deep protocol negotiation analysis, visual interactive terminal and web dashboards, continuous SLA monitoring, and structured log streaming.

For complete architectural specifications, concurrency mechanics, and dependency models, see [`ARCHITECTURE.md`](ARCHITECTURE.md) and [`MODERNIZATION.md`](MODERNIZATION.md).

---

## 1. Application Overview & Objectives

Traditional ping utilities are typically restricted to Layer 3 ICMP or simple Layer 4 TCP handshakes. Modern distributed systems, cloud infrastructures, and microservice meshes require granular application-layer latency analysis, TLS certificate verification, database responsiveness checks, and real-time observability.

### Core Objectives
- **Layer 3 to Layer 7 Unified Probing**: Measure handshake, TTFB, and protocol responsiveness across 15+ network and application protocols.
- **Deep Protocol Diagnostics (`--diags`)**: Extract TLS cipher suites, certificate expiration, HTTP headers, database banners, message queue metadata, and DNS RCODEs.
- **Real-Time Visual Telemetry**:
  - **120-Column Interactive TUI Dashboard (`--dashboard`)** with a 106-point latency waveform chart.
  - **Zero-Dependency Web Dashboard (`--web`)** with Server-Sent Events (SSE) and Canvas 2D timeline graphs.
- **Enterprise Resilience & Socket Controls**: Prevent socket exhaustion under high frequencies via `SO_LINGER=0` fast teardown (`--fast-close`), and recover from transient drops with randomized exponential jitter backoff (`--retry`).
- **Flexible Data Pipelines**: Stream data natively into SIEM and monitoring pipelines using JSON (`--json`), NDJSON (`--ndjson`), JSON Lines (`--jsonl`), CSV (`--csv`), TSV (`--tsv`), SQLite3 (`--db`), or Prometheus metrics (`--metrics-addr`).

---

## 2. Security Assessment & Hardening Posture

`netping` implements a comprehensive security baseline across transport encryption, local persistence, execution privileges, and memory isolation.

### 2.1. Encryption in Transit
- **TLS 1.2 / 1.3 Native Verification**: All secure application drivers (`HTTPS`, `TLS`, `DoT`, `DoH`, `Redis-TLS`, `SMTPS`, `IMAPS`, `POP3S`, `LDAPS`, `Kafka-TLS`, `AMQPS`, `O365`) utilize Go's cryptographic stack (`crypto/tls`), enforcing full certificate chain verification and modern cipher suite negotiation.
- **Certificate Expiration Auditing**: Active inspection alerts on expiring or expired X.509 certificates and computes remaining validity days without decrypting payload traffic.

### 2.2. Secret Management & Authentication Policy
- **Zero Ingestion of Sensitive Credentials**: `netping` probes endpoint reachability and wire protocol health via standard unauthenticated handshakes (e.g. Postgres `SSLRequest`, MySQL `HandshakeV10`, MongoDB `isMaster`, Kafka `ApiVersions`, RabbitMQ `0-9-1 Connection.Start`).
- **No Secret Storage**: The tool never accepts, logs, caches, or writes passwords, API tokens, or private keys to disk or terminal streams.

### 2.3. Privilege Separation & Execution Context
- **Unprivileged Execution Context**: `netping` operates strictly as a standard, unprivileged non-root user.
- **Unprivileged ICMP Fallback**: Layer 3 ICMP probes utilize unprivileged datagram sockets (`net.ipv4.ping_group_range` on Linux) or unprivileged UDP fallbacks, completely eliminating the need for `CAP_NET_RAW`, `setuid root`, or `sudo`.
- **Loopback-Only Telemetry Binding**: The embedded Web Dashboard server (`--web`) defaults to `127.0.0.1:3000`, preventing unintended exposure to external network interfaces.

### 2.4. Library & Dependency Vulnerability Profile
- **Minimal Third-Party Footprint**: Leaf packages utilize standard Go library primitives. External dependencies are strictly constrained:
  - `mattn/go-sqlite3`: Embedded SQLite3 driver.
  - `golang.org/x/net`: Supplementary low-level socket controls.
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

```
netping [options] <hostname|IP> <port>
netping [options] <hostname:port>
netping [options] <target1:port> <target2:port> ...
```

| Flag | Short | Type | Default | Description |
| :--- | :---: | :---: | :---: | :--- |
| `--protocol` | — | `string` | `tcp` | Target protocol: `tcp`, `http`, `https`, `tls`, `udp`, `icmp`, `ws`, `wss`, `grpc`, `grpcs`, `dns`, `dot`, `doh`, `redis`, `rediss`, `memcached`, `smtp`, `smtps`, `imap`, `imaps`, `pop3`, `pop3s`, `ldap`, `ldaps`, `postgres`, `mysql`, `mssql`, `oracle`, `mongodb`, `cassandra`, `saphana`, `s3`, `blob`, `gcs`, `kafka`, `kafkas`, `rabbitmq`, `amqps`, `o365`. |
| `--count` | `-c` | `uint` | `0` (infinite) | Total number of probes to transmit before stopping. |
| `--interval` | `-i` | `duration` | `1s` | Interval between probes (e.g. `1s`, `500ms`, `0.002`). |
| `--timeout` | `-t` | `duration` | `1s` | Per-probe network timeout threshold. |
| `--diags`, `--diagnostics` | — | `bool` | `false` | Enable deep protocol negotiation metadata and handshake breakdown. |
| `--dashboard`, `-ui` | — | `bool` | `false` | Launch full-screen interactive 120-column TUI dashboard with waveform history. |
| `--web` | — | `bool` | `false` | Launch embedded real-time web dashboard with SSE event streaming. |
| `--web-addr` | — | `string` | `127.0.0.1:3000` | Listening address and port for the embedded web dashboard. |
| `--metrics-addr` | — | `string` | `""` | Expose Prometheus/OpenMetrics telemetry server on given address (e.g. `:9100`). |
| `--json` | `-j` | `bool` | `false` | Output results as JSON documents. |
| `--pretty` | — | `bool` | `false` | Indent/prettify JSON output (requires `--json`). |
| `--ndjson` | — | `bool` | `false` | Output real-time Newline-Delimited JSON stream. |
| `--jsonl` | — | `bool` | `false` | Output real-time JSON Lines stream. |
| `--csv` | — | `string` | `""` | File path to export probe events and stats summary to CSV. |
| `--tsv` | — | `string` | `""` | File path to export probe events and stats summary to TSV. |
| `--db` | — | `string` | `""` | File path to persist probe events and statistics into a SQLite3 database. |
| `--no-color` | `-n` | `bool` | `false` | Disable ANSI color escapes for plain text output. |
| `--quiet` | `-q` | `bool` | `false` | Quiet mode: suppress per-probe lines, output only final summary. |
| `--show-source-address`| `-S` | `bool` | `false` | Display local IP address and dynamic ephemeral port for each connection. |
| `--timestamp` | `-ts` | `bool` | `false` | Print local timestamp prefix before every probe. |
| `--show-failures-only` | `-f` | `bool` | `false` | Suppress successful replies, displaying only failed probes. |
| `--retry` | — | `uint` | `0` | Number of transient retry attempts per probe before recording a failure. |
| `--retry-backoff` | — | `float` | `0.05` | Initial retry backoff delay in seconds. |
| `--retry-max-backoff` | — | `float` | `2.0` | Maximum retry backoff delay cap in seconds. |
| `--retry-jitter` | — | `bool` | `true` | Apply randomized full jitter to exponential retry backoffs. |
| `--fast-close` | — | `bool` | `false` | Enable `SO_LINGER=0` (TCP RST) to bypass `TIME_WAIT` socket accumulation. |
| `--resolve-every-probe`| — | `bool` | `false` | Re-resolve target DNS on every probe cycle to detect Anycast/CDN rotations. |
| `--max-latency` | — | `float` | `0` | Threshold latency in milliseconds; breaches count as SLA failures. |
| `--max-consecutive-fails`| — | `uint` | `0` | Automatically terminate probing after $N$ consecutive failures. |
| `--traceroute` | — | `bool` | `false` | Execute hop-by-hop Layer-4 TCP route discovery to target port. |
| `--interface` | `-I` | `string` | `""` | Bind outbound traffic to a specific network interface. |
| `--dns-server` | `-d` | `string` | `""` | Use custom DNS server IP or IP:port for hostname resolution. |
| `--version` | `-v` | `bool` | `false` | Display version and exit. |
| `--help` | `-h` | `bool` | `false` | Display help and usage instructions. |

---

## 5. Usage & Deployment Examples

### 5.1. Basic & Protocol Handshake Probing

#### Standard TCP Probing with Source Address
```bash
netping -S 1.1.1.1 443
```
```text
Probing 1.1.1.1 on port 443
● Reply from 1.1.1.1 on port 443 using 192.168.1.100:54321: TCP_conn=1 time=14.230 ms
● Reply from 1.1.1.1 on port 443 using 192.168.1.100:54322: TCP_conn=2 time=13.890 ms
```

#### HTTPS Probing with Deep Protocol Diagnostics (`--diags`)
```bash
netping --protocol https --diags -c 2 1.1.1.1 443
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

---

### 5.2. Visual Dashboards

#### 120-Column Interactive Terminal TUI Dashboard
```bash
netping --dashboard --protocol https --diags 1.1.1.1 443
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

#### Zero-Dependency Embedded Web Dashboard
```bash
netping --web --web-addr 127.0.0.1:3000 1.1.1.1 443
```
- Opens native HTTP server at `http://127.0.0.1:3000`.
- Connects via Server-Sent Events (SSE) for 0ms telemetry streaming and Canvas 2D latency timelines.

---

### 5.3. Log Streaming & Data Pipeline Ingestion

#### NDJSON Stream for Vector / FluentBit / Elasticsearch
```bash
netping --ndjson 1.1.1.1 443 | jq -c '.'
```
```json
{"type":"probe","success":true,"message":"Reply from 1.1.1.1 on port 443 TCP_conn=1 time=14.230 ms","ipAddress":"1.1.1.1","port":443,"destinationIsIP":true,"time":"14.230","ongoingSuccessfulProbes":1}
{"type":"probe","success":true,"message":"Reply from 1.1.1.1 on port 443 TCP_conn=2 time=13.890 ms","ipAddress":"1.1.1.1","port":443,"destinationIsIP":true,"time":"13.890","ongoingSuccessfulProbes":2}
```

#### Tab-Separated Values (TSV) Export
```bash
netping --tsv results.tsv -c 5 1.1.1.1 443
```
Generates `results.tsv` (probe events) and `results_stats.tsv` (SLA summary).

#### Standing Prometheus Metrics Exporter
```bash
netping --metrics-addr :9100 1.1.1.1 443
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
netping -i 0.002 --fast-close 1.1.1.1 443
```

#### Transient Failure Recovery with Exponential Jitter Backoff
```bash
netping --retry 3 --retry-backoff 0.1 --retry-max-backoff 1.0 --retry-jitter 1.1.1.1 443
```

#### Multi-Target Concurrent Comparison
```bash
netping 1.1.1.1:53 8.8.8.8:53 9.9.9.9:53
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

## 6. Architecture & System Design

For deep architectural reviews, sequence diagrams, concurrency models, dependency DAGs, and security specifications, refer to:
- **[`ARCHITECTURE.md`](ARCHITECTURE.md)**: System architecture, data flow sequences, concurrency model, and threat matrix.
- **[`MODERNIZATION.md`](MODERNIZATION.md)**: Master modernization roadmap, protocol capabilities, and feature validation.
