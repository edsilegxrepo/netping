# Changelog

## v0.6.3 - 2026-08-28

- **WAF-Resilient Probing & Detection Engine (`--waf`)**:
  - Added dedicated `--waf` preset mode designed for origins protected by Web Application Firewalls (Cloudflare, Imperva/Incapsula, Akamai, AWS CloudFront / AWS WAF, Fastly, F5 BIG-IP / ASM, Sucuri, Azure Front Door).
  - Emulates modern browser headers (`User-Agent: Chrome/128`, `Sec-Ch-Ua`, `Sec-Fetch-*`, `Accept: text/html,...`, `Accept-Language: en-US,en;q=0.9`, `Upgrade-Insecure-Requests: 1`), defaults HTTP verb to `GET` (bypassing WAF `HEAD` blackholing), and adjusts default timeout to 5.0s to absorb anti-bot JavaScript challenge evaluation delays.
  - Deep diagnostics (`--diags`) actively inspects response headers, cookies, TLS certificates, and HTML markers to identify and report detected WAF / CDN vendors.
- **Granular HTTP Method & User-Agent Controls**:
  - Added `--method <verb>` (alias `--http-method`) allowing explicit selection of HTTP verbs (`GET`, `HEAD`, `POST`, `OPTIONS`, `PUT`, `DELETE`, etc.) for HTTP/HTTPS probes.
  - Added `--user-agent <string>` (alias `--ua`) for injecting custom User-Agent headers.
- **RFC-Compliant HTTP/2 `:authority` Port Handling**:
  - Standardized URL formatting to omit default ports (`:80` for HTTP, `:443` for HTTPS), preventing strict HTTP/2 reverse proxies from dropping streams with explicit standard port suffixes.
- **MongoDB Atlas & SRV Auto-Discovery (`mongodb+srv`)**:
  - Added native `mongodb+srv://` URI schema and `--protocol mongodb+srv` (aliases: `mongo+srv`, `mongosrv`, `atlas`) support.
  - Automatically executes `_mongodb._tcp.<cluster>` DNS SRV queries on Atlas and replica set parent hostnames, resolving all underlying shard member endpoints and probing each node with mandatory TLS (`MONGODBS`).
- **Web Dashboard Latency Comparison (TTFB Waterfall)**:
  - Added multi-phase latency breakdown visualization for single-target web monitoring, supporting **Curves**, **Grouped Bars**, and **Stacked 100%** contribution modes for DNS, TCP, TLS, and Server Wait stages.

## v0.6.2 - 2026-08-27

- **Windows Remote Management (WinRM / WinRMS)**: Added native WS-Management SOAP prober (`--protocol winrm` / `winrms` on Ports 5985/5986) with deep inspection (`--diags`) of OS product versions, authentication schemes (`Negotiate, Kerberos, NTLM, CredSSP`), and TLS ciphers.
- **Microsoft Entra ID (Azure Active Directory)**: Added native Entra ID tenant discovery and health prober (`--protocol entra` on Port 443) with cloud environment detection, token endpoints, and active JWKS X.509 signing key expiration audits.
- **KMS & Secrets Vaults**: Added unified multi-vault probing engine (`--protocol kms` / `vault`) supporting HashiCorp Vault (health & seal alerts), Azure Key Vault (tenant ID extraction), CyberArk EPV/Conjur, AWS KMS, and GCP Cloud KMS. See [docs/KMS.md](docs/KMS.md).

## v0.6.1 - 2026-08-25

- **Single Sign-On (SSO) & Federation Probing Engine**:
  - **OpenID Connect (OIDC 1.0)**: Added native latency and discovery probing (`--protocol oidc`) on Port 443 with deep inspection (`--diags`) extracting issuer, endpoints, token signing algorithms, scopes, and active JWKS X.509 signing key expiration audits.
  - **SAML 2.0 Identity Federation**: Added SAML metadata prober (`--protocol saml`) parsing XML `EntityDescriptor`, SSO/SLO bindings (`HTTP-Redirect`, `HTTP-POST`), NameID formats, and `<ds:X509Certificate>` validity with $<30\text{d}$ expiration warnings and expired alerts.
  - **OAuth 2.0 Authorization Server (RFC 8414)**: Added OAuth 2.0 metadata prober (`--protocol oauth2`) dissecting token endpoints, grant types, client authentication methods, and PKCE (`S256`) security verification.
  - **Unified SSO Auto-Discovery**: Added `--protocol sso` for automatic endpoint type inference from target URIs.
  - **Documentation**: See [docs/SSO.md](docs/SSO.md) for full protocol specifications, XML/JSON schemas, and architecture details.
- **Kerberos v5 Protocol Probing Engine (RFC 4120)**:
  - **Dual-Transport Probing**: Added native Kerberos KDC latency probing on Port 88 over both **TCP** (`--protocol kerberos`) and **UDP** (`--protocol kerberos-udp`) via RFC 4120 ASN.1 DER `AS-REQ` generation.
  - **Deep Protocol Inspection (`--diags`)**: Extracts message types (`KRB-ERROR`/`AS-REP`), symbolic error codes (0–76+), authoritative Realm/SPN identities, microsecond clock skew ($\ge 300\text{s}$ critical alerts), supported cipher suites (AES-256, AES-128, RC4), and pre-authentication mechanisms.
  - **Documentation**: See [docs/KERBEROS.md](docs/KERBEROS.md) for full protocol specifications, wire framing, and architecture details.

## v0.6.0 - 2026-08-24

- **REST Trigger API & Daemon Operating Mode**:
  - **On-Demand Dynamic Probe Triggering**: Added `POST /api/v1/trigger` enabling remote systems to execute network diagnostic probes on demand across all 49 supported application layer protocols.
  - **Rich Trigger Payload Options**: Complete support for count-limited iterations (`count`), interval pacing (`interval`), custom payload send/expect matching (`send_data`/`expect_data`), fast teardown (`fast_close`), SLA latency thresholds (`max_latency_ms`), retry backoff loops, and Layer-4 traceroute discovery (`traceroute`).
  - **Dual Operating Modes**: Added idle trigger listener daemon (`--trigger-mode`, `--listen <addr>`, `--trigger-concurrency <n>`) alongside existing CLI subscriber mode (`--web`), starting cleanly with zero initial targets.
  - **Dynamic Fleet Registry Synchronization**: Real-time integration of dynamically triggered probe targets into the Web UI dashboard, historical event queries (`/api/v1/probes`), and standing metrics (`/api/v1/metrics`, `/api/v1/targets`).
- **Argon2id Authentication & Keystore Management**:
  - **CLI Key Generation**: Added `--generate-api-key <path>` to generate high-entropy 256-bit API keys (`np_live_...`) with OWASP-standard Argon2id hashing (`m=65536, t=3, p=4`).
  - **Zero-Downtime Hot-Reloading Keystore**: Added JSON keystore persistence with file permission hardening (`0600`) and live modification detection without daemon restarts.
  - **Dual-Header Authentication Middleware**: Full support for `X-API-Key` and `Authorization: Bearer <key>` authentication schemes, structured 401 JSON error responses, and CORS preflight (`OPTIONS`) handling.
  - **In-Memory Security Hygiene**: Cryptographic memory wiping via `auth.ZeroBytes` and constant-time key validation (`subtle.ConstantTimeCompare`) against timing attacks.
- **HTTP Probe Method Dispatching**:
  - **Dynamic Method Routing**: Supports payload transmission (`--send` / `send_data` via HTTP `POST`) and response body assertion (`--expect` / `expect_data` via HTTP `GET`) across CLI and trigger API, while preserving standard lightweight `HEAD` requests by default.
- **Terminal Compatibility & Legacy Console Mode**:
  - Added `--legacy-console` CLI flag and `NETPING_LEGACY_CONSOLE=1` support to force CP437/VGA-safe block characters (`_`, `▄`, `█`) on terminal clients lacking Unicode fractional block glyphs (e.g. PuTTY with Lucida Console / Consolas).
- **Reverse Proxy & Subpath Mounting**:
  - Added `--url-prefix` (and `--base-path`) CLI flag and `NETPING_URL_PREFIX` environment variable to host the Web Dashboard and REST API at arbitrary subpaths (e.g. `/probe`).
  - Added dynamic base-path and API resolvers in the frontend SPA to resolve all telemetry metrics, exports, and SSE streams relative to the mounting subpath.
  - Added `X-Accel-Buffering: no` header on `/api/v1/stream` to prevent Nginx/proxy buffer stalls on live event streams.
  - Added automated 301 trailing-slash redirects for clean browser relative asset resolution.
- **Testing & Verification**:
  - Comprehensive unit test suites across `pkg/auth`, `pkg/engine`, `pkg/web`, `internal/config`, and `cmd`.
  - 8-stage end-to-end lifecycle testing covering key generation, idle daemon startup, REST authentication, probe triggering, SSE streaming, and dashboard visualization.
  - 100% data-race free under `go test -race ./...`.

## v0.5.2 - 2026-08-23

- **Interactive Web Dashboard**:
  - **Enhanced Latency Waveform**: Real-time hover tooltips, drag/wheel zoom with reset, and X-axis timestamp scale.
  - **Enterprise Controls & View Menu**: Maximize Waveform or Event Stream views (window-bounded), toggle Line vs Bar chart mode, and context-aware action states.
  - **Live Event Stream Filter**: Universal search bar filtering incoming probe events across all fields.
  - **API Specs Popup Modal**: Embedded Swagger UI/OpenAPI viewer with dedicated tab option.
  - **Composite PNG Snapshot**: Telemetry export combining target fleet metrics and waveform chart.
  - **Sticky Header**: Pinned header with solid background mask.
- **Engine Precision & Performance**:
  - **Wire-Level HTTP Timing**: Measures true network RTT from TCP connection start to first byte response (`TTFB`).
  - **Detached Async Saves**: Zero-latency-spike background export process on Windows and POSIX.
  - **Dynamic History Buffer**: Expandable in-memory retention buffer up to 5M events (`--history-limit`) with REST API controls (`/api/v1/config/history`).

## v0.5.1 - 2026-08-21

- **Features & Protocol Diagnostics**:
  - **Oracle Database (`--protocol oracle`)**: Added `TNS RESEND` (0x0B) automatic frame negotiation, 16-bit TNS protocol version mapping (TNS v316 -> Oracle 19c/21c/23c), and dynamic database service routing via `--service` / `--oracle-service`.
  - **SAP HANA (`--protocol hana`)**: Upgraded to native 14-byte SQLDBC protocol v4.20 handshake, automated instance number and role deduction (`SystemDB SQL` on port 39013 vs Tenant DB), and Authenticate part framing.
  - **LDAP / LDAPS (`--protocol ldap` / `ldaps`)**: Added RFC 4512 RootDSE search to extract domain `BaseDN` (`defaultNamingContext`), Domain Controller hostname (`dnsHostName`), and ASN.1 BER ResultCode name mapping.
  - **Microsoft 365 (`--protocol o365`)**: Added rich diagnostics displaying HTTP status, TLS cipher, Front-End server routing tags (`X-FEServer`, `request-id`), and certificate validity.
  - **gRPC (`--protocol grpc` / `grpcs`)**: Added canonical gRPC status code name mapping (e.g. `0 OK`, `12 UNIMPLEMENTED`, `16 UNAUTHENTICATED`), server headers, and TLS handshake metrics.
  - **Message Brokers (`--protocol rabbitmq` / `kafka`)**: Added AMQP 0-9-1 `Connection.Start` server properties/cluster/auth extraction and Kafka `ApiVersions` supported API count decoding.
  - **WebSocket (`--protocol ws` / `wss`)**: Added HTTP 101 upgrade status, Pong frame (`0xA`), and server header diagnostics.
- **Refactoring & Architecture (DRY)**:
  - **Database Engine Modularization**: Decomposed monolithic `db.go` `Ping()` into isolated protocol methods (`probePostgres`, `probeMySQL`, `probeMSSQL`, `probeOracle`, `probeMongoDB`, `probeCassandra`, `probeSAPHANA`).
  - **Unified Structs & Helpers**: Embedded `DBOptions` directly into `DBing`, unified network dialing and TLS inspection in `(d *DBing) dial(ctx)`, and introduced reusable BSON/TNS/ASN.1 extraction helpers.
- **Testing & Verification**:
  - Expanded unit test coverage across database, queue, directory, and WebSocket packages; verified end-to-end against live production endpoints (Gmail/Outlook IMAPS, Google Cloud gRPC, Forumsys LDAP, Echo WebSocket, SAP HANA).

## v0.5.0 - 2026-08-20

Modernization and evolution into **`netping`** — an enterprise-grade multi-protocol network diagnostics and latency measurement suite. For the complete engineering architecture and design specification, see [`docs/MODERNIZATION.md`](docs/MODERNIZATION.md).

- **Multi-Protocol Engine (15+ Protocols)**: Added Layer 3 to Layer 7 probers for HTTP/HTTPS (TTFB breakdown), TLS/SSL, UDP, ICMP Ping, WebSocket RFC 6455, gRPC Health, DNS/DoT/DoH, Redis, Memcached, Mail (SMTP/IMAP/POP3), Directory Services (LDAP/LDAPS), Databases (Postgres, MySQL, MSSQL, Oracle, MongoDB, Cassandra, SAP HANA), Cloud Buckets (S3, Blob, GCS), Message Queues (Kafka, RabbitMQ), and Microsoft 365 / Graph.
- **Protocol Handshake Diagnostics Engine (`--diags` / `--diagnostics`)**: Real-time extraction of TLS cipher/version, certificate expiration, HTTP headers, database banners, cloud request IDs, and DNS RCODEs across CLI, TUI, and Web UI.
- **Interactive 120-Column TUI Dashboard (`--dashboard` / `-ui`)**: Live terminal dashboard with a 106-point latency waveform chart, 5-column SLA/jitter KPI cards, scrolling event log, and underlying output format delegation upon exit.
- **Zero-Dependency Web Dashboard (`--web` / `--web-addr`)**: Embedded real-time web server with Server-Sent Events (SSE) streaming and dynamic HTML5 Canvas 2D latency timeline charts.
- **Resilience & Socket Controls**: Exponential backoff retry engine with jitter (`--retry`), `SO_LINGER=0` fast teardown (`--fast-close`), continuous dynamic DNS re-resolution (`--resolve-every-probe`), SLA latency threshold limits (`--max-latency`), and hop-by-hop traceroute discovery (`--traceroute`).
- **Concurrent Multi-Target Probing**: Simultaneous parallel probing of multiple target endpoints with aggregated summary matrix comparison.
- **Comprehensive Data Ingestion & Exports**: Native support for JSON (`-j` / `--json`), Pretty JSON (`--pretty`), Newline-Delimited JSON (`--ndjson`), JSON Lines (`--jsonl`), CSV (`--csv`), TSV (`--tsv`), SQLite3 database (`--db`), and standing Prometheus metrics endpoint (`--metrics-addr`).
- **Thread-Safe Architecture & Exit Codes**: Implemented immutable `stats.Snapshot` copy-on-read model, strict DAG package dependency hierarchy, and standardized diagnostic exit codes (`0`, `1`, `2`, `3`, `4`, `5`, `6`, `7`, `130`).

## v0.0.0 - Baseline

Used `wip/v3` branch from https://github.com/pouriyajamshidi/tcping for MVP functional specs.