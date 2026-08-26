# `netping` — System Architecture & Engineering Specification

This document provides a comprehensive technical breakdown of the **`netping`** architecture, design rationale, concurrency mechanics, data flow pipelines, dependency graphs, performance optimizations, edge case mitigations, and security controls.

---

## 1. Architecture and Design Choices

`netping` is engineered as a zero-dependency, high-throughput network diagnostics and latency measurement engine written in Go. Its core purpose is to provide Layer 3 to Layer 7 latency probing, active protocol diagnostics, and real-time observability while guaranteeing low memory overhead, lock-free telemetry reads, and resilience against transient network failures.

```mermaid
flowchart TD
    %% TIER 1: INGESTION & CONTROL
    subgraph Tier1 ["Tier 1: Entrypoint, Configuration & Trigger Daemon"]
        direction TB
        CLI["cmd/netping.go<br/>(Composition Root)"]
        
        subgraph T1_Helpers [" "]
            direction LR
            Config["internal/config<br/>(Flag Parsing & Pool Matrix)"]
            App["internal/app<br/>(Signal Trapping & Lifecycle)"]
            
            subgraph TriggerDaemon ["Dynamic REST Trigger Daemon"]
                direction TB
                Engine["pkg/engine<br/>(DynamicEngine Semaphore)"] <--> Auth["pkg/auth<br/>(Argon2id Keystore)"]
            end
        end

        CLI --> Config
        CLI --> App
        CLI --> Engine
    end

    %% TIER 2: ORCHESTRATION & FACTORY
    subgraph Tier2 ["Tier 2: Probing Orchestrators & Factory"]
        direction TB
        subgraph T2_Probers [" "]
            direction LR
            Prober["pkg/probers.Prober<br/>(Single-Target Loop)"]
            MultiProber["pkg/probers.MultiProber<br/>(Concurrent Fleet Pool)"]
        end

        Factory["pkg/probers.BuildPinger<br/>(Central Driver Factory)"]
        PingerContract["«interface» probers.Pinger<br/>Ping(ctx context.Context) ProbeResult"]

        Prober --> Factory
        MultiProber --> Factory
        Factory --> PingerContract
    end

    %% TIER 3: PROTOCOL CLUSTERS (2x2 Stacked Grid)
    subgraph Tier3 ["Tier 3: Protocol Drivers & Deep Diagnostics (55 Protocols)"]
        direction TB
        
        subgraph T3_Row1 ["Transport & Web Protocols"]
            direction LR
            P_Net["<b>Network & Transport (L3–L4)</b><br/>• TCP, UDP, ICMP Ping<br/>• Raw TLS Handshake<br/>• Layer-4 Traceroute Engine"]
            P_Web["<b>Web, DNS & APIs (L7)</b><br/>• HTTP / HTTPS (HEAD, POST, GET)<br/>• WebSocket / WSS Handshake<br/>• gRPC / GRPCS Health & ALPN<br/>• DNS, DoH & DoT Wire Queries"]
        end

        subgraph T3_Row2 ["Databases, Queues & Identity"]
            direction LR
            P_Data["<b>Databases & Message Queues</b><br/>• Postgres, MySQL, MSSQL, Oracle, SAP HANA, Mongo<br/>• Redis & Memcached Wire Handshakes<br/>• Kafka (ApiVersions) & RabbitMQ / AMQP"]
            P_Auth["<b>Identity, SSO, Directory & Storage</b><br/>• SSO: OIDC Discovery, SAML 2.0 XML & OAuth 2.0 PKCE<br/>• Kerberos v5: KDC TCP/UDP AS-REQ Handshakes<br/>• LDAP / LDAPS Anonymous Bind & Root DSE<br/>• Cloud Storage (S3, Azure Blob, GCS) & Mail"]
        end

        PingerContract --> T3_Row1
        PingerContract --> T3_Row2
    end

    %% TIER 4: TELEMETRY STATE MACHINE
    subgraph Tier4 ["Tier 4: Telemetry State Machine & Snapshots"]
        direction TB
        Stats["pkg/stats.Statistics<br/>(RWMutex Thread-Safe State Accumulator)"]
        Snapshot["pkg/stats.Snapshot<br/>(Immutable Copy-on-Read Metric Struct)"]
        Stats -.->|Copy-on-Read| Snapshot
    end

    %% TIER 5: OUTPUT SURFACES & OBSERVABILITY
    subgraph Tier5 ["Tier 5: Output & Observability Surfaces"]
        direction LR
        
        subgraph TerminalUI ["Terminal & Storage"]
            direction TB
            TUIDash["120-Column TUI Dashboard<br/>(internal/printers/dashboard.go)"]
            Printers["CLI & File Exporters<br/>(Color, JSON, NDJSON, CSV, TSV, SQLite3)"]
        end

        subgraph NetworkExporters ["Web & Monitoring"]
            direction TB
            WebUI["Embedded Web Server & SSE Broadcaster<br/>(pkg/web)"]
            PromExporter["Prometheus Metrics Exporter<br/>(pkg/metrics)"]
        end

        Snapshot --> TerminalUI
        Snapshot --> NetworkExporters
    end

    %% VERTICAL TIER FLOW
    Tier1 ==>|Configures & Spawns| Tier2
    Tier2 -->|Executes Handshakes| Tier3
    Tier3 -->|Updates Counters & Timings| Stats
    Tier2 -.->|Updates Ongoing Probes| Stats
    Tier4 ==>|Pipes Snapshots| Tier5
```

### 1.1. Core Design Patterns

1. **Decoupled Application Orchestration**:
   - `internal/config` is a leaf package dedicated strictly to argument parsing and primitive configuration structures.
   - `cmd/netping.go` acts as the composition root, wiring together DNS resolvers, network interfaces, stats accumulators, output formatters, and prober implementations.
2. **Interface Minimization & Pluggable Probers**:
   - All protocol drivers implement the minimalist `probers.Pinger` interface:
     ```go
     type Pinger interface {
         Ping(ctx context.Context) ProbeResult
     }
     ```
   - Returning `ProbeResult` isolates latency, DNS resolution timing, network interfaces, error categories, and protocol diagnostics from the main timing loop.
3. **Thread-Safe Snapshotting (Copy-on-Read)**:
   - `stats.Statistics` encapsulates all real-time and cumulative counters behind a `sync.RWMutex`.
   - Telemetry consumers (Prometheus scraper, Web UI SSE broadcaster, interactive `Enter` summary keystrokes) read immutable copies generated via `stats.Snapshot()`, eliminating lock contention and blocking delays.

### 1.2. Assumptions

- **Direct Socket Access**: The host OS permits creating Layer 4 TCP/UDP sockets without administrative elevation.
- **ICMP Privilege Fallback**: For Layer 3 ICMP pinging, `netping` assumes unprivileged UDP-based ICMP datagrams on Linux (`net.ipv4.ping_group_range`) or falls back gracefully if raw socket creation (`CAP_NET_RAW` / `Administrator`) is denied.
- **Clock Monotonicity**: Latency timings utilize Go's runtime monotonic clock (`time.Now()` / `time.Since()`), ensuring immunity to OS NTP step adjustments during probe calculations.

### 1.3. Edge Cases & Mitigations

| Edge Case | Failure Mode | Mitigation Strategy | Reference |
| :--- | :--- | :--- | :--- |
| **High-Frequency Socket Exhaustion** | Probing at sub-millisecond intervals (`--interval 0.002`) exhausts ephemeral ports, filling OS socket table with `TIME_WAIT`. | Added `--fast-close` (`SO_LINGER=0`), forcing immediate `TCP RST` packets on socket teardown to bypass `TIME_WAIT`. | [`pkg/probers/tcp.go`](pkg/probers/tcp.go) |
| **Anycast / CDN DNS Flapping** | Target IP rotates dynamically under Anycast routing or multi-record DNS configurations. | Added `--resolve-every-probe` to re-query upstream DNS on each cycle and track hostname-to-IP transitions. | [`pkg/probers/probers.go`](pkg/probers/probers.go) |
| **Transient Network Drops** | Brief packet loss or gateway flaps cause false-positive alert cascades. | Exponential backoff engine with randomized full jitter (`--retry`, `--retry-backoff`, `--retry-jitter`) to absorb network burps. | [`pkg/utils/backoff.go`](pkg/utils/backoff.go) |
| **Terminal Width Misalignment** | ANSI escape codes disrupt character counts in variable-width terminal emulators. | Built ANSI-safe width calculation (`padRightVisible`) with automatic ellipsis truncation (`…\033[0m`) guaranteeing strict 120-column table alignment. | [`internal/printers/dashboard.go`](internal/printers/dashboard.go) |
| **Silent Storage Corruption** | Unexpected process exit (SIGINT/SIGTERM) leaves SQLite or CSV write buffers uncommitted. | Enforced `io.Closer` / `Done()` lifecycle with `defer printer.Done()` ensuring all open buffers are synced to disk before termination. | [`internal/printers/csv.go`](internal/printers/csv.go), [`internal/printers/sqlite3.go`](internal/printers/sqlite3.go) |

### 1.4. Performance & Efficiency

- **Zero Allocations in Hot Dial Paths**: Connection buffers and byte arrays for protocol handshakes are preallocated or reused.
- **Bounded Telemetry History**: Historical latency arrays in the TUI dashboard and Web SSE broadcaster are capped (106 samples in terminal, 120 in browser) to prevent memory growth during long-running sessions.
- **SSE Non-Blocking Push**: SSE channels drop slow client connections rather than blocking the real-time probe engine.

---

## 2. Data Flow and Control Logic

### 2.1. Operational Control Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as Operator / API Client
    participant Engine as Engine (cmd & pkg/probers)
    participant Driver as Protocol Driver (L3–L7)
    participant Target as Remote Target
    participant Output as Telemetry & Exporters

    Note over User,Output: Phase 1: Initialization & Target Matrix Expansion
    User->>Engine: Dispatch Probe Request (CLI / REST Trigger)
    Engine->>Engine: Parse options, resolve target pool & bind socket

    Note over User,Output: Phase 2: High-Precision Probing Loop
    loop Every Probe Interval (default 1s)
        Engine->>Driver: Ping(ctx)
        Driver->>Driver: Resolve DNS & measure DNSTime
        Driver->>Target: Transmit Protocol Handshake / Payload
        Target-->>Driver: Reply (SYN-ACK / Cert / Banner / JSON)
        Driver-->>Engine: Return ProbeResult (RTT, TTFB, Diags, Err)
        Engine->>Output: Ingest metrics & stream updates (TUI / SSE / SQLite)
    end

    Note over User,Output: Phase 3: Teardown & SLA Reporting
    User->>Engine: Termination Signal (SIGINT / --count limit)
    Engine->>Output: Flush buffers & compute final SLA percentiles
    Output-->>User: Render statistics table & return exit code
```

### 2.2. Code Relations & Data Sequences

1. **Resolution Stage**: Hostname resolution queries the OS resolver or configured custom DNS server ([`internal/dns/dns.go`](internal/dns/dns.go)). DNS lookup duration is recorded separately as `DNSTime`.
2. **Handshake Stage**: The selected `Pinger` initiates connection with per-probe context timeouts.
   - For **HTTP/HTTPS**: Uses `net/http/httptrace` to isolate DNS, TCP connect, TLS handshake, and Time-To-First-Byte (TTFB).
   - For **Databases & Queues**: Sends native binary greetings (Postgres `SSLRequest`, MySQL `HandshakeV10`, Kafka `ApiVersions`, AMQP `Connection.Start`).
3. **Ingestion & Metric Processing**:
   - Computes RFC 3550 interarrival jitter: $J = J + \frac{(|D| - J)}{16}$.
   - Performs linear percentile interpolation for P50, P90, P95, and P99 SLAs.
   - Categorizes failures (`Connection Refused`, `Connection Timeout`, `Host Unreachable`, `DNS Failed`).
4. **Broadcasting & Output Dispatch**:
   - `PrinterConfig` routes the update to active outputs (Color, Plain, JSON, NDJSON, CSV, TSV, SQLite3, 120-Col Dashboard).
   - If enabled, SSE broadcaster sends real-time JSON payloads to browser clients.

---

## 3. Performance, Scalability & Concurrency Model

```mermaid
graph TD
    subgraph MultiTargetConcurrency ["Multi-Target Concurrent Architecture"]
        Target1["Worker 1 (1.1.1.1:53)"]
        Target2["Worker 2 (8.8.8.8:53)"]
        TargetN["Worker N (9.9.9.9:53)"]
    end

    subgraph SyncChannel ["Synchronized Coordination Pipeline"]
        Queue["sync.WaitGroup + Buffered Channels"]
        Collector["Unified Event Multiplexer"]
    end

    subgraph TelemetryStore ["Thread-Safe Storage & Handlers"]
        Stats1["Stats Map (Target 1)"]
        Stats2["Stats Map (Target 2)"]
        StatsN["Stats Map (Target N)"]
    end

    Target1 -->|ProbeResult| Queue
    Target2 -->|ProbeResult| Queue
    TargetN -->|ProbeResult| Queue

    Queue --> Collector
    Collector --> Stats1
    Collector --> Stats2
    Collector --> StatsN
```

### 3.1. Concurrency Mechanics

- **Goroutine per Target Worker**: When executing multi-target probing (`MultiProber`), each target endpoint executes in an isolated worker goroutine with its own ticker and state accumulator.
- **Mutex-Free Broadcast Channel**: The web SSE broadcaster uses buffered event channels per client (`chan ProbeEvent`, buffer size 64). Slow browser clients are non-blockingly dropped if their buffer overflows.
- **Asynchronous User Keyboard Monitor**: An independent goroutine monitors `os.Stdin` for `Enter` key presses to output instant interim statistics snapshots without interrupting the ongoing probe loop.

---

## 4. Package Dependencies & Module Flow

The codebase strictly adheres to a **Directed Acyclic Graph (DAG)**. Leaf packages contain zero domain-logic coupling, and configuration parsing is decoupled from subsystem constructors.

```mermaid
graph TD
    cmd[cmd/netping] --> app[internal/app]
    cmd --> config[internal/config]
    cmd --> probers[pkg/probers]
    cmd --> printers[internal/printers]
    cmd --> dns[internal/dns]
    cmd --> nic[internal/nic]
    cmd --> stats[pkg/stats]
    cmd --> metrics[pkg/metrics]
    cmd --> web[pkg/web]
    cmd --> auth[pkg/auth]
    cmd --> engine[pkg/engine]

    probers --> stats
    probers --> utils[pkg/utils]
    probers --> consts[pkg/consts]

    printers --> stats
    printers --> utils
    printers --> consts

    web --> stats
    web --> utils

    engine --> probers
    engine --> stats
    engine --> web
    engine --> consts

    auth --> consts
    dns --> consts
    nic --> consts
    stats --> consts
    utils --> consts

    classDef core fill:#1e293b,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef leaf fill:#0f172a,stroke:#334155,stroke-width:1px,color:#cbd5e1;
    class cmd,app core;
    class config,probers,printers,dns,nic,stats,utils,consts,metrics,web,auth,engine leaf;
```

### Dependency Breakdown

| Package | Purpose | Dependencies |
| :--- | :--- | :--- |
| **`cmd/`** | Main entrypoint and composition orchestrator. | `internal/*`, `pkg/*` |
| **`internal/config`** | Pure CLI argument parser and flag validator. | `pkg/consts` |
| **`internal/app`** | OS signal interception (`SIGINT`/`SIGTERM`) and graceful context shutdown. | Standard Library only |
| **`internal/dns`** | Custom upstream DNS client and resolver caching bypass. | `pkg/consts` |
| **`internal/nic`** | Network interface selector and local IP binding dialer. | `pkg/consts` |
| **`internal/printers`** | Terminal formatting (Color, Plain, JSON, NDJSON, CSV, TSV, SQLite3, Dashboard). | `pkg/stats`, `pkg/utils`, `pkg/consts`, `modernc.org/sqlite` |
| **`pkg/probers`** | Layer 3 to Layer 7 prober drivers, traceroute, centralized factory (`BuildPinger`), and multi-target orchestrator. | `pkg/stats`, `pkg/utils`, `pkg/consts`, `golang.org/x/net` |
| **`pkg/stats`** | Thread-safe metric accumulators, SLA calculations, and snapshot generator. | `pkg/consts` |
| **`pkg/metrics`** | Zero-dependency Prometheus/OpenMetrics HTTP exporter. | Standard Library only |
| **`pkg/web`** | Zero-dependency embedded web server, SSE broadcaster, and Canvas 2D UI. | `pkg/stats`, `pkg/utils`, `internal/printers` |
| **`pkg/auth`** | Argon2id token generation, keystore persistence, fast-path verification cache, and memory zeroing (`ZeroBytes`). | `golang.org/x/crypto/argon2`, `pkg/consts` |
| **`pkg/engine`** | Dynamic on-demand trigger orchestration, concurrency limiting, and fleet registry. | `pkg/probers`, `pkg/stats`, `pkg/web`, `pkg/consts` |
| **`pkg/utils`** | Mathematical jitter, percentiles, sparklines, and backoff helpers. | `pkg/consts` |
| **`pkg/consts`** | Immutable protocol constants, canonical protocol matrix, ANSI escape definitions, and exit codes. | Standard Library only |

---

## 5. Security Architecture

`netping` enforces a **defense-in-depth security model** across socket communications, memory management, protocol negotiation, and export boundaries.

```mermaid
flowchart TD
    subgraph Row1 ["Transport, Socket & Cryptographic Authentication"]
        direction LR
        
        subgraph SocketSecurity ["Socket & Transport Security"]
            direction TB
            TLSVal["TLS 1.2 / 1.3 Strict Verification"] --> CertChecks["X.509 Certificate Chain & Validity Checks"]
            RawSocketDrop["Unprivileged ICMP Fallback<br/>(Drop CAP_NET_RAW)"]
        end

        subgraph AuthSecurity ["Authentication & Memory Security"]
            direction TB
            ArgonHash["Argon2id Hashed Keystores<br/>(OWASP m=65536, t=3, p=4)"]
            ArgonHash --> MemScrub["RAM Scrubbing on API Tokens<br/>(auth.ZeroBytes)"]
            ArgonHash --> TimeConstant["Constant-Time Token Comparison<br/>(subtle.ConstantTimeCompare)"]
        end
    end

    subgraph Row2 ["Data Integrity, Network Exposure & Surface Isolation"]
        direction LR
        
        subgraph NetworkSurface ["Network Exposure Surface"]
            direction TB
            LoopbackOnly["Web Dashboard Defaults to 127.0.0.1<br/>(Localhost Only)"] --> ReadHeaders["Safe Header Parsing & 1MB Body Limit<br/>(Prevents DoS)"]
            NoAuthData["Zero Ingestion of Sensitive Passwords/Payloads"]
        end

        subgraph DataIntegrity ["Data Storage & Export Integrity"]
            direction TB
            SQLSanitize["SQLite Table Name Sanitization<br/>(Regex Enforced)"] --> BufferSync["Guaranteed io.Closer Sync<br/>on SIGINT / SIGTERM"]
            MemoryIsolation["Private Mutex Enclosed Statistics<br/>(No Data Races)"]
        end
    end

    Row1 --> Row2
```

### 5.1. Authentication & Protocol Security Layers

- **Argon2id REST API Key Verification**:
  - Validates API tokens using RFC 9106 Argon2id cryptographic parameters (`memory=64MB`, `iterations=3`, `parallelism=4`).
  - Sensitive plaintext byte buffers are overwritten in RAM using [`auth.ZeroBytes`](pkg/auth/keygen.go) immediately after hashing.
  - Constant-time verification comparisons prevent side-channel timing attacks.
  - Accelerated by a thread-safe 30-second TTL in-memory LRU cache.
- **HTTP/HTTPS Prober Method Routing**:
  - Defaults to RFC 7231 `HEAD` method for zero body download overhead and minimal resource consumption.
  - Automatically switches to `POST` when custom `--send` payload is provided.
  - Automatically switches to `GET` when `--expect` substring validation is specified, with responses bounded to 64KB (`io.LimitReader`) to prevent memory exhaustion attacks.
- **TLS / SSL Probing**:
  - Validates full X.509 certificate chains, alerting on expired certificates, invalid hostnames, or weak ciphers.
  - Supports testing direct ALPN negotiation (`h2`, `http/1.1`) and extracts certificate expiration dates (`NotAfter`).
- **Database & Application Wire Security**:
  - Probes database ports using safe, unauthenticated protocol handshakes (e.g. Postgres `SSLRequest`, MySQL `HandshakeV10` greeting parsing, MongoDB `isMaster` command).
  - No database credentials, usernames, or sensitive application keys are required or transmitted.
- **Cloud Object Storage (S3 / Azure Blob / GCS)**:
  - Validates storage endpoint availability and measures TTFB using unauthenticated HTTP head/get options without requiring AWS/Azure/GCP secret keys.

### 5.2. Access Control & System Permissions

- **Privilege Separation**:
  - `netping` runs entirely as an **unprivileged user**.
  - For Layer 3 ICMP pinging, it utilizes Linux unprivileged ping sockets (`IPPROTO_ICMP`) or unprivileged UDP sockets, eliminating the need for `setuid root` or `sudo`.
- **Localhost-Bound Telemetry Servers**:
  - The embedded web dashboard (`--web`) defaults strictly to `127.0.0.1:3000` (loopback only) to prevent unauthorized external network access unless explicitly bound to `--web-addr 0.0.0.0:<port>`.
- **SQL Injection Prevention**:
  - SQLite database table names derived from target hostnames are strictly validated against an alphanumeric allowlist regex `^[a-zA-Z0-9_]+$` before execution in DDL statements. Parameterized queries are used for all probe record insertions.

---

## 6. Companion Architectural Specifications & Guides

For deep protocol wire mechanics, deployment blueprints, and specialized subsystems, refer to the companion specifications:

- **[Single Sign-On (SSO) & Identity Federation](docs/SSO.md)** (`docs/SSO.md`): Protocol specifications for OpenID Connect (OIDC 1.0) discovery + JWKS `x5c` cert expiry parsing, SAML 2.0 XML `EntityDescriptor` + X.509 verification, and OAuth 2.0 (RFC 8414) PKCE AS metadata audits.
- **[Kerberos v5 Probing & KDC Diagnostics](docs/KERBEROS.md)** (`docs/KERBEROS.md`): Wire framing specifications for dual-transport TCP and UDP RFC 4120 `AS-REQ` DER generation, microsecond clock skew tracking, and diagnostic error codes.
- **[Reverse Proxy & Subpath Mounting](docs/REVERSE_PROXY.md)** (`docs/REVERSE_PROXY.md`): Production deployment architectures for Nginx, Apache, Caddy, HAProxy, and Traefik with `--url-prefix` dynamic base-path resolution and SSE buffer controls.
- **[Dynamic REST Trigger API & Daemon](docs/API_TRIGGER.md)** (`docs/API_TRIGGER.md`): Full REST API endpoint contracts, Argon2id authentication mechanics, and keystore management.
- **[Parallel Multi-Target & Concurrency Architecture](docs/CONCURRENCY.md)** (`docs/CONCURRENCY.md`): Worker goroutine isolation, target expansion matrix, and single-writer telemetry synchronization.
- **[Modernization & Protocol Engine Architecture](docs/MODERNIZATION.md)** (`docs/MODERNIZATION.md`): Complete multi-protocol prober design rationale, performance metrics, and zero-allocation hot paths.
