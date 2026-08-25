# Changelog

## v3.6.0 - 2026-08-24

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
- **Testing & Verification**:
  - Comprehensive unit test suites across `pkg/auth`, `pkg/engine`, `pkg/web`, `internal/config`, and `cmd`.
  - 8-stage end-to-end lifecycle testing covering key generation, idle daemon startup, REST authentication, probe triggering, SSE streaming, and dashboard visualization.
  - 100% data-race free under `go test -race ./...`.

## v3.5.2 - 2026-08-23

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

## v3.5.1 - 2026-08-21

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

## v3.5.0 - 2026-08-20

Modernization and evolution into **`netping`** — an enterprise-grade multi-protocol network diagnostics and latency measurement suite. For the complete engineering architecture and design specification, see [`docs/MODERNIZATION.md`](docs/MODERNIZATION.md).

- **Multi-Protocol Engine (15+ Protocols)**: Added Layer 3 to Layer 7 probers for HTTP/HTTPS (TTFB breakdown), TLS/SSL, UDP, ICMP Ping, WebSocket RFC 6455, gRPC Health, DNS/DoT/DoH, Redis, Memcached, Mail (SMTP/IMAP/POP3), Directory Services (LDAP/LDAPS), Databases (Postgres, MySQL, MSSQL, Oracle, MongoDB, Cassandra, SAP HANA), Cloud Buckets (S3, Blob, GCS), Message Queues (Kafka, RabbitMQ), and Microsoft 365 / Graph.
- **Protocol Handshake Diagnostics Engine (`--diags` / `--diagnostics`)**: Real-time extraction of TLS cipher/version, certificate expiration, HTTP headers, database banners, cloud request IDs, and DNS RCODEs across CLI, TUI, and Web UI.
- **Interactive 120-Column TUI Dashboard (`--dashboard` / `-ui`)**: Live terminal dashboard with a 106-point latency waveform chart, 5-column SLA/jitter KPI cards, scrolling event log, and underlying output format delegation upon exit.
- **Zero-Dependency Web Dashboard (`--web` / `--web-addr`)**: Embedded real-time web server with Server-Sent Events (SSE) streaming and dynamic HTML5 Canvas 2D latency timeline charts.
- **Resilience & Socket Controls**: Exponential backoff retry engine with jitter (`--retry`), `SO_LINGER=0` fast teardown (`--fast-close`), continuous dynamic DNS re-resolution (`--resolve-every-probe`), SLA latency threshold limits (`--max-latency`), and hop-by-hop traceroute discovery (`--traceroute`).
- **Concurrent Multi-Target Probing**: Simultaneous parallel probing of multiple target endpoints with aggregated summary matrix comparison.
- **Comprehensive Data Ingestion & Exports**: Native support for JSON (`-j` / `--json`), Pretty JSON (`--pretty`), Newline-Delimited JSON (`--ndjson`), JSON Lines (`--jsonl`), CSV (`--csv`), TSV (`--tsv`), SQLite3 database (`--db`), and standing Prometheus metrics endpoint (`--metrics-addr`).
- **Thread-Safe Architecture & Exit Codes**: Implemented immutable `stats.Snapshot` copy-on-read model, strict DAG package dependency hierarchy, and standardized diagnostic exit codes (`0`, `1`, `2`, `3`, `4`, `5`, `6`, `7`, `130`).

## v3.0.0 - Unreleased

- build: bump stale days before close from 7 to 14
- build: ensure to fail on any linting issues
- build: simplify container publish workflow
- build: general cleanups
- build: support more container architectures
- improvement: make print statistics (when the **Enter** key is pressed) snappy. No more waiting when using high probe intervals
- refactor: drop `TimeFormat` constants in favor of stdlib's `time.DateTime`
- refactor: drop `HourFormat` constants in favor of stdlib's `time.TimeOnly`
- templates: improve pull and bug report templates
- docs: we have a new logo thanks to Gemini!
- refactor: modernize with `go fix`
- dependencies: replace `github.com/google/go-github` with Go's built-in HTTP library
- docs: grammar fix in the README.md thanks to @taiman724
- project structure: move Artwork and Images folders to the docs folder

## v2.8.0 - 2026-05-11

- feat: add a _non-interactive_ mode through `--non-interactive` flag so that tcping can run in the background using `nohup` or `disown`
- feat: add support for `host:port` format in command arguments in [362](https://github.com/pouriyajamshidi/tcping/pull/362) thanks to @bingoohuang
- fix: omit printing the IP address twice when the given target is an IP address itself
- fix: add missing comma separator in no-color statistics output in [376](https://github.com/pouriyajamshidi/tcping/issues/376) thanks to @clarabennettdev
- fix: version typo resulting in erroneous update message raised in [313](https://github.com/pouriyajamshidi/tcping/issues/313)
- build: bump Golang base image to `1.26.3-alpine3.23`
- documents: fix typo in the Chinese README in [386](https://github.com/pouriyajamshidi/tcping/pull/386) thanks to @peeweep
- documents: clarify the difference between static and dynamic binaries in README raised in [357](https://github.com/pouriyajamshidi/tcping/issues/357)

## v2.7.1 - 2025-01-26

- release: add tcping to [WinGet](https://learn.microsoft.com/en-us/windows/package-manager/winget) [#113](https://github.com/pouriyajamshidi/tcping/issues/113)
- bug: fix name resolution in static builds with `-4` flag causing name resolution failures due to _IPv4-mapped IPv6 addresses_
- CI: apply **Revive** suggestions
- CI: add **Revive** to CI
- CI: add **Revive** config
- documents: revamp and simplify the README file
- documents: update the Chinese translation thanks to @edwinjhlee

## v2.7.0 - 2025-01-18

- new feature: implement **csv** output through `--csv <filename>` flag [#254](https://github.com/pouriyajamshidi/tcping/pull/254) thanks to @Ilhan-Personal
- new feature: implement plain (color-less) output through `--no-color` flag [#253](https://github.com/pouriyajamshidi/tcping/issues/253)
- new feature: implement display of source IP address and port used to create TCP connections through `--show-source-address` flag [#249](https://github.com/pouriyajamshidi/tcping/issues/249)
- refactor: rename `planePrinter` to `colorPrinter` to match the actual functionality of the function
- refactor: rename `localAddr` to `sourceAddr` throughout the code-base for better clarity
- refactor: complete rewrite of the **Makefile** thanks to @cyqsimon
- refactor: add containerization section in the **Makefile** thanks to @cyqsimon
- fix: crash on database writes when hostname includes a hyphen thanks to @pro0o
- documents: add Chinese translation thanks to @edwinjhlee
- documents: add link to [X CMD](https://x-cmd.com/pkg/tcping) thanks to @edwinjhlee
- tests: add new tests for `printProbeSuccess` and `printProbeFail` thanks to @basil-gray
- tests: add tests for `show-local-address` flag
- dependencies:
  - crypto v0.28.0 => v0.32.0
  - exp v0.0.0-20241004190924-225e2abe05e6 => v0.0.0-20250106191152-7588d65b2ba8
  - sys v0.26.0 => v0.29.0
  - modernc.org/libc v1.61.6 => v1.61.8
  - modernc.org/memory v1.8.0 => v1.8.2
  - modernc.org/sqlite v1.34.4 => v1.34.5

## v2.6.0 - 2024-10-05

- new feature: add `-D` flag to display date and time in probe output by @SYSHIL
- new feature: add `-h` flag to show available flags by @karimalzalek
- fix: display `second` instead of `seconds` on probe failures that convert to a value more than 1 and less than 1.1 second
- refactor: Makefile: Split build section into smaller, distinct targets by @iskiy

## v2.5.0 - 2024-01-13

- new feature: add `-show-failures-only` flag to omit printing successful probes
- new feature: re-add **static** Linux binary. Thanks to @daniql
- new feature: add support for Linux `arm64` in Makefile. Thanks to @ChrisClarke246
- fix: extra precision for seconds calculation when the value is under a second. Thanks to @daniql
- refactor: migrate to a pure-Go `sqlite` package. Thanks to @wizsk
- refactor: user flag handlers
- cleanup: user input functions. Thanks to @friday963
- chore: fix typos

## v2.4.0 - 2023-09-10

- new feature: add `-i` to specify the interval between sending probes. Thanks to @luca-patrignani
- new feature: add `-I` to specify the source interface to use for sending probes. Thanks to @wizsk
- new feature: add `-t` to specify a custom timeout for probes. Thanks to @luca-patrignani
- new feature: add `--db` to specify the path and file name to store tcping output to sqlite database. e.g. `--db /tmp/tcping.db`. Thanks to @wizsk
- fix: add `rtt` to JSON output
- fix: CI warning thanks to @wizsk
- refactor: remove unnecessary custom types
- refactor: memory align `structs`
- refactor: Debian packaging instructions

## v2.0.0 - 2023-08-05

- new feature: add `-c` or count flag to exit **TCPING** after a certain amount of probes specified by user thanks to @ravsii
- new feature: add **BSD** support
- new feature: add **Debian** package to make **TCPING** `apt installable`
- fix: packet loss `NaN` when program terminated too quickly thanks to @ravsii
- fix: random IP address selector index out of range bug
- fix: display format of IPv4 embedded in IPv6 addresses
- fix: time report bug. Everything is now accurate
- fix: Enter key detection for Windows machines
- refactor: complete overhaul of time calculation. **TCPING** now is hack-free when it comes to time handling thanks to @ravsii
- refactor: memory align `structs`
- refactor: improve code readability
- refactor: refactor `stats struct` and extract user input to a separate `struct`
- refactor: Enter key detection logic
- refactor: name resolution handling. The maximum allowed time to wait for DNS response is now 2 seconds
- refactor: and unify exit points thanks to @ravsii
- tests: add more test special thanks to @ravsii
- enhancement: add dependabot
- docs: improve documentation

## v1.22.1 - 2023-5-14

- new feature: implement JSON output thanks to @ravsii
- new feature: implement JSON output [prettifier](https://github.com/pouriyajamshidi/tcping/raw/master/Images/gifs/tcping_json_pretty.gif) thanks to @ravsii
- fix IP version selection bug when `-4` or `-6` flags are passed

## v1.21.2 - 2023-5-8

- make `stats` struct fields' names uniform
- add `|` separator to summary report for better visibility

## v1.21.1 - 2023-5-8

- fix retry resolve logic

## v1.21.0 - 2023-5-7

- add option to enforce the use of IPv4 `-4` or IPv6 `-6` addresses only
- instead of always picking the first, randomly pick an address from the list of resolved IP addresses

## v1.20.0 - 2023-4-22

- add hostname, IP and port number to summary output

## v1.19.2 - 2023-4-7

- display stats even if all the probes had failed update version
- update version
- incorporate sha256sum into Makefile

## v1.19.1 - 2023-3-4

- close `TCP` connections faster to lessen the resource utilization on target

## v1.19.0 - 2023-2-26

- implement sub-millisecond timing report to make it suitable for Data center and Cloud environments
- refactor `tcping` function and simplify it
- fix downtime report miscalculation
- fix picking of go version
- improve build process
- changed `ipAddress` type from string to `netip.Addr` thanks @segfault99
- fix `statsprinter` formats thanks @segfault99
- upgrade actions thanks @wutingfeng
- fix undeclared `statsPrinter` warning
- fix code scanning alert - Incorrect conversion between integer types #43
- add `stale` workflow
- add new logo
- add Linux brew section
- add docker demo recording
- restructure README file
- update dependencies and bump Go version
- improve Makefile
- fix tag detection on Actions workflow
- add `Go` version to `CodeQL`
- add `downloads` badge
- improve checkUpdate message
- fix go install guide
- fix bug report template
- create SECURITY.md
- improve pull request template
- improve stale workflow

## v1.12.0 - 2022-7-10

- add preliminary JSON output support thanks @icemint0828 for collaboration
- add Docker container images on Docker Hub and GitHub container registry
- add and optimize GitHub workflows
- small refactoring and cleanups
- add -v flag to show version
- improve code readability
- add logo thanks @code-hyker

## v1.9.0 - 2022-5-29

- Add `-r` flag to retry resolving the hostname after a certain amount of probe failures (thanks to @icemint0828)
- Show statistics if the RTT is less than 1ms (thanks to @icemint0828)
- Show longest uptime similar to longest downtime (thanks to @icemint0828)
- Improve time calculation and display time in reports (thanks to @icemint0828)
- Add initial test cases (thanks to @icemint0828)
- General refactoring, fixes and decrease of resource utilization
- Update dependencies
- Update `Makefile` to include `go fmt` command in `build`
- Update `Makefile` to include `go test` command in `build`

## v1.4.4 - 2022-2-26

- Improve time constants for better readability

## v1.4.3 - 2022-2-21

- Revert successful reply text color

## v1.4.2 - 2022-2-20

- Memory alignment for rttResults struct

## v1.4.1 - 2022-2-20

- Make hour format a constant

## v1.4.0 - 2022-2-19

- Remove sort function to increase performance
- General refactoring to make the code more readable

## v1.3.0 - 2022-2-9

- Fix longest downtime bug

## v1.2.0 - 2022-2-6

- Improve memory alignment
- Add display of longest downtime
- Add display of runtime duration
- Add display of last successful and unsuccessful probes
- General improvements and cleanup
