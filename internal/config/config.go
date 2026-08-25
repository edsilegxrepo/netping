// Package config handles CLI flag registration, argument permutation, multi-target parsing,
// operational mode resolution, and configuration defaults for netping.
//
// Objectives:
//   - Parse POSIX and GNU-style command-line arguments and positional target endpoints.
//   - Validate conflicting CLI flags and resolve default ports, timeouts, and intervals.
//   - Initialize storage, printer, web server, and daemon operational configs.
//
// Core Components:
//   - Config: Top-level runtime configuration struct.
//   - TargetConfig: Individual target configuration (host, IP, port, protocol, service).
//   - ProcessUserInput / ParseConfig: CLI flag parsing and configuration validation pipeline.
//
// Data Flow:
//
//	os.Args -> permuteArgs -> FlagSet.Parse -> parseConfigFromParsed -> Config.
package config

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/edsilegx/netping/internal/dns"
	"github.com/edsilegx/netping/internal/nic"
	"github.com/edsilegx/netping/internal/printers"
	"github.com/edsilegx/netping/pkg/consts"
	"github.com/edsilegx/netping/pkg/utils"
)

const minProbeInterval = 2 * time.Millisecond

// flagsRequiringValue inspects every flag registered on flag.CommandLine and
// returns the set of flag names that expect a value on the command line
// (i.e. anything that isn't a bool flag). Derived directly from the flag
// definitions, so it can never drift out of sync when a flag is added,
// renamed, or removed.
func flagsRequiringValue(fs *flag.FlagSet) map[string]bool {
	if fs == nil {
		fs = flag.CommandLine
	}
	flagsWithValues := make(map[string]bool)

	fs.VisitAll(func(f *flag.Flag) {
		// Flags created via flag.Bool implement this interface, it's the
		// same check the flag package uses internally to decide whether a
		// flag needs a following argument.
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			return
		}

		flagsWithValues[f.Name] = true
	})

	return flagsWithValues
}

// permuteArgs rearranges user provided args for flag parsing.
// Go's standard flag package stops parsing flags as soon as it encounters the first non-flag argument,
// causing us to lose our flags, so we need to override that behavior.
// Given [tcping.go example.com 443 -4 -r 1 -c 2] or [tcping.go -4 -r 1 -c 2 example.com 443]
// returns [tcping.go -4 -r 1 -c 2 example.com 443]
// nonFlagArgs are ["example.com", "443"]
// flagArgs are ["-4", "-c 2"]
//
// Without permutation, `tcping example.com 443 -4 -c 5` becomes:
// flags:
//
//	none
//
// args:
//
//	example.com
//	443
//	-4
//	-c
//	5
//
// With permutation:
// flags:
//
//	-4
//	-c 5
//
// args:
//
//	example.com
//	443
//
// In memory of Takaya, you will be missed my friend.
func permuteArgs(fs *flag.FlagSet, args []string) {
	flagsWithValues := flagsRequiringValue(fs)

	flagArgs := make([]string, 0, len(args))
	nonFlagArgs := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if !strings.HasPrefix(arg, "-") {
			nonFlagArgs = append(nonFlagArgs, arg)
			continue
		}

		option := strings.TrimLeft(arg, "-")

		if flagsWithValues[option] {
			if i+1 >= len(args) {
				fmt.Printf("-%s option requires a value\n", option)
				usage()
			}

			if strings.HasPrefix(args[i+1], "-") {
				fmt.Printf("-%s option requires a value\n", option)
				usage()
			}

			flagArgs = append(flagArgs, arg, args[i+1])

			i++
			continue
		}

		// bool flags
		flagArgs = append(flagArgs, arg)
	}

	copy(args, append(flagArgs, nonFlagArgs...))
}

// TargetConfig represents an individual resolved probe target.
type TargetConfig struct {
	Host                    string
	IP                      netip.Addr
	Port                    uint16
	Protocol                consts.Protocol
	TargetIsIP              bool
	ServiceName             string
	ShouldRetryResolve      bool
	RetryResolveAfterNFails uint
}

// Config holds all user provided settings
type Config struct {
	Hostname                   string
	IP                         netip.Addr
	Port                       uint16
	Protocol                   consts.Protocol
	TargetConfigs              []TargetConfig
	Targets                    []string
	Concurrency                uint
	UseIPv4                    bool
	UseIPv6                    bool
	ShowSourceAddress          bool
	RetryResolveAfterNFailures uint
	ProbesBeforeQuit           uint
	IfaceNameOrIPAddress       string
	Timeout                    time.Duration
	IntervalBetweenProbes      time.Duration
	PrinterConfig              printers.PrinterConfig
	NetworkInterface           nic.NetworkInterface
	RetryHostnameLookupAfter   uint // Number of failed requests before retrying to resolve the hostname.
	TargetIsIP                 bool // Flag indicating whether the destination is an IP address (not a hostname).
	ShouldRetryResolve         bool
	ShowFailuresOnly           bool
	Resolver                   *dns.Resolver
	SendData                   string
	ExpectData                 string
	FastClose                  bool
	ResolveEveryProbe          bool
	MaxConsecutiveFails        uint
	MaxLatency                 float64
	MetricsAddr                string
	QuietMode                  bool
	ShowSparkline              bool
	ShowDashboard              bool
	TracerouteMode             bool
	Retries                    uint
	InitialRetryBackoff        time.Duration
	MaxRetryBackoff            time.Duration
	RetryJitter                bool
	EnableWeb                  bool
	WebAddr                    string
	ShowDiags                  bool
	StartTLS                   bool
	DNSHosts                   []string
	ServiceName                string
	HistoryLimit               uint
	GenerateAPIKeyPath         string
	APIKeyStore                string
	APIKeyHash                 string
	TriggerMode                bool
	TriggerConcurrency         int
	LegacyConsole              bool
	URLPrefix                  string
}

func (c Config) GetHostname() string {
	return c.Hostname
}

func (c Config) GetIP() netip.Addr {
	return c.IP
}

func (c Config) GetPort() uint16 {
	return c.Port
}

func (c Config) GetProtocol() consts.Protocol {
	return c.Protocol
}

func (c Config) GetUseIPv4() bool {
	return c.UseIPv4
}

func (c Config) GetUseIPv6() bool {
	return c.UseIPv6
}

func (c Config) GetTimeout() string {
	return c.Timeout.String()
}

func (c Config) GetProbesBeforeQuit() uint {
	return c.ProbesBeforeQuit
}

func (c Config) GetTargetIsIP() bool {
	return c.TargetIsIP
}

func (c Config) GetIntervalBetweenProbes() string {
	return c.IntervalBetweenProbes.String()
}

func (c Config) GetShowFailuresOnly() bool {
	return c.ShowFailuresOnly
}

func (c Config) GetShouldRetryResolve() bool {
	return c.ShouldRetryResolve
}

func (c Config) GetRetryResolveAfterNFailures() uint {
	return c.RetryHostnameLookupAfter
}

func (c Config) GetNetworkInterface() nic.NetworkInterface {
	return c.NetworkInterface
}

func (c Config) GetPrinterConfig() printers.PrinterConfig {
	return c.PrinterConfig
}

func (c Config) GetWithTimestamp() bool {
	return c.PrinterConfig.WithTimestamp
}

func (c Config) GetWithSourceAddress() bool {
	return c.PrinterConfig.WithSourceAddress
}

type flagOptions struct {
	useIPv4                            *bool
	useIPv6                            *bool
	probesBeforeQuit                   *uint
	intervalBetweenProbes              *float64
	timeout                            *float64
	showTimestamp                      *bool
	retryHostnameResolveAfterNFailures *uint
	customDNSServer                    *string
	interfaceName                      *string
	showSourceAddress                  *bool
	showFailuresOnly                   *bool
	noColor                            *bool
	outputFormat                       *string
	outputFile                         *string
	showVer                            *bool
	checkUpdates                       *bool
	showHelp                           *bool
	sendData                           *string
	expectData                         *string
	fastClose                          *bool
	resolveEveryProbe                  *bool
	maxConsecutiveFails                *uint
	maxLatency                         *float64
	metricsAddr                        *string
	protocol                           *string
	quietMode                          *bool
	showSparkline                      *bool
	showDashboard                      *bool
	tracerouteMode                     *bool
	retries                            *uint
	retryBackoff                       *float64
	retryMaxBackoff                    *float64
	retryJitter                        *bool
	enableWeb                          *bool
	webAddr                            *string
	showDiags                          *bool
	showDiagnostics                    *bool
	startTLS                           *bool
	dnsHost                            *string
	serviceName                        *string
	oracleService                      *string
	host                               *string
	port                               *string
	uri                                *string
	concurrency                        *uint
	historyLimit                       *uint
	generateAPIKey                     *string
	apiKeyStore                        *string
	apiKeyHash                         *string
	triggerMode                        *bool
	listen                             *string
	triggerConcurrency                 *int
	legacyConsole                      *bool
	urlPrefix                          *string
	basePath                           *string
}

func registerFlags(fs *flag.FlagSet) flagOptions {
	return flagOptions{
		host:        fs.String("host", "", "Target host(s), comma-separated for multi-target."),
		port:        fs.String("port", "", "Target port(s), comma-separated for multi-port."),
		uri:         fs.String("uri", "", "Target URI(s) in host:port or scheme://host:port format, comma-separated."),
		concurrency: fs.Uint("concurrency", 0, "Max parallel prober workers (0 = unconstrained)."),
		useIPv4:     fs.Bool("ipv4", false, "Only use IPv4 to initiate probes."),
		useIPv6:     fs.Bool("ipv6", false, "Only use IPv6 to initiate probes."),
		probesBeforeQuit: fs.Uint(
			"count",
			0,
			`Stop after <n> probes, regardless of the result.
		By default, no limit will be applied.`,
		),
		intervalBetweenProbes: fs.Float64(
			"interval",
			1,
			`Interval between probes.
		Real number allowed with dot as a decimal separator.
		The default value is one second`,
		),
		timeout: fs.Float64(
			"timeout",
			1,
			`Time to wait for a response in seconds.
		Real number allowed.
		0 means infinite timeout.`,
		),
		showTimestamp: fs.Bool(
			"timestamp",
			false,
			"Show a timestamp for each probe in the output.",
		),
		retryHostnameResolveAfterNFailures: fs.Uint(
			"retry-resolve",
			0,
			`Retry resolving target's hostname after <n> number of failed probes.
		e.g. --retry-resolve 10 to retry after 10 failed probes.`,
		),
		customDNSServer: fs.String(
			"dns-server",
			"",
			`Custom DNS server IP to use. Defaults to the system-wide server.
		IP and port combination is allowed: 1.1.1.1:53`,
		),
		interfaceName: fs.String(
			"interface",
			"",
			"Use a specific interface name or IP address to initiate the probes.",
		),
		showSourceAddress: fs.Bool(
			"show-source-address",
			false,
			"Show source address and port used for probes.",
		),
		showFailuresOnly: fs.Bool(
			"show-failures-only",
			false,
			"Show only the failed probes.",
		),
		noColor: fs.Bool("no-color", false, "Do not colorize output."),
		outputFormat: fs.String(
			"output-format",
			"",
			"Output format: json, pretty_json, csv, tsv, sqlite, txt.",
		),
		outputFile: fs.String(
			"output-file",
			"",
			"Path to destination output file.",
		),
		showVer:             fs.Bool("version", false, "Show version and exit."),
		checkUpdates:        fs.Bool("check-updates", false, "Check for updates and exit."),
		showHelp:            fs.Bool("help", false, "Show help message and exit."),
		sendData:            fs.String("send", "", "Send specific payload upon connection."),
		expectData:          fs.String("expect", "", "Expect specific string in response banner."),
		fastClose:           fs.Bool("fast-close", false, "Use SO_LINGER=0 to avoid TIME_WAIT socket accumulation."),
		resolveEveryProbe:   fs.Bool("resolve-every-probe", false, "Re-resolve target DNS on every probe cycle."),
		maxConsecutiveFails: fs.Uint("max-consecutive-fails", 0, "Stop probing after N consecutive failed probes."),
		maxLatency:          fs.Float64("max-latency", 0, "Fail probe if latency exceeds threshold in ms."),
		metricsAddr:         fs.String("metrics-addr", "", "Enable Prometheus metrics exporter on given address (e.g. :9100)."),
		protocol:            fs.String("protocol", "tcp", "Probe protocol: tcp, http, https."),
		quietMode:           fs.Bool("quiet", false, "Quiet mode: suppress per-probe lines, show only final summary."),
		showSparkline:       fs.Bool("sparkline", false, "Render live terminal latency sparklines."),
		showDashboard:       fs.Bool("dashboard", false, "Open interactive live TUI dashboard."),
		tracerouteMode:      fs.Bool("traceroute", false, "Perform hop-by-hop Layer-4 route discovery."),
		retries:             fs.Uint("retry", 0, "Number of transient retry attempts per probe before failing."),
		retryBackoff:        fs.Float64("retry-backoff", 0.05, "Initial retry backoff delay in seconds."),
		retryMaxBackoff:     fs.Float64("retry-max-backoff", 2.0, "Maximum retry backoff delay in seconds."),
		retryJitter:         fs.Bool("retry-jitter", true, "Apply randomized jitter to exponential retry backoff."),
		enableWeb:           fs.Bool("web", false, "Start embedded real-time web dashboard (default 127.0.0.1:3000)."),
		webAddr:             fs.String("web-addr", "", "Listen address for web dashboard (e.g. 127.0.0.1:3000 or :3000)."),
		showDiags:           fs.Bool("diags", false, "Show detailed protocol negotiation diagnostics."),
		showDiagnostics:     fs.Bool("diagnostics", false, "Show detailed protocol negotiation diagnostics."),
		startTLS:            fs.Bool("starttls", false, "Upgrade connection via STARTTLS (SMTP/IMAP/POP3)."),
		dnsHost:             fs.String("dns-host", "", "Host(s) to query in DNS mode (comma-separated, e.g. google.com,cloudflare.com)."),
		serviceName:         fs.String("service", "", "Service name / SID for Oracle database connections (e.g. ORCL, FREE, XE, ORCLPDB1)."),
		oracleService:       fs.String("oracle-service", "", "Oracle database service name (e.g. ORCL, FREE, XE, ORCLPDB1)."),
		historyLimit:        fs.Uint("history-limit", 1000000, "Maximum in-memory historical probe events retained (default: 1000000, max: 5000000)."),
		generateAPIKey:      fs.String("generate-api-key", "", "Generate a 256-bit API key, compute Argon2id hash, and save to keystore file path."),
		apiKeyStore:         fs.String("api-key-store", "", "Path to API key keystore file for Trigger mode authentication."),
		apiKeyHash:          fs.String("api-key-hash", "", "Inline Argon2id hash string for Trigger mode authentication."),
		triggerMode:         fs.Bool("trigger-mode", false, "Start in trigger-only mode without initial targets."),
		listen:              fs.String("listen", "", "Start trigger listener on specified address (e.g. :3000 or 127.0.0.1:3000)."),
		triggerConcurrency:  fs.Int("trigger-concurrency", 100, "Maximum concurrent dynamic probe workers."),
		legacyConsole:       fs.Bool("legacy-console", false, "Use CP437/ASCII fallback glyphs and square borders for legacy terminals (PuTTY, cmd.exe)."),
		urlPrefix:           fs.String("url-prefix", "", "URL subpath prefix when running behind a reverse proxy (e.g. /probe)."),
		basePath:            fs.String("base-path", "", "Alias for --url-prefix."),
	}
}

// ProcessUserInput gets and validate user input
func ProcessUserInput() Config {
	flag.CommandLine.Usage = usage
	opts := registerFlags(flag.CommandLine)
	args := make([]string, len(os.Args[1:]))
	copy(args, os.Args[1:])
	permuteArgs(flag.CommandLine, args)
	if err := flag.CommandLine.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		usage()
	}

	if *opts.showHelp {
		usage()
	}
	if *opts.showVer {
		showVersion()
	}
	if *opts.checkUpdates {
		checkForUpdates()
	}

	cfg, err := parseConfigFromParsed(flag.CommandLine, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(consts.ExitUsageError)
	}
	return *cfg
}

// ParseConfig parses command line flags and positional arguments into a Config instance.
func ParseConfig(fs *flag.FlagSet, args []string) (*Config, error) {
	opts := registerFlags(fs)
	argsCopy := make([]string, len(args))
	copy(argsCopy, args)
	permuteArgs(fs, argsCopy)
	if err := fs.Parse(argsCopy); err != nil {
		return nil, err
	}

	return parseConfigFromParsed(fs, opts)
}

func parseConfigFromParsed(fs *flag.FlagSet, opts flagOptions) (*Config, error) {
	if *opts.useIPv4 && *opts.useIPv6 {
		return nil, fmt.Errorf("only one IP version can be specified")
	}

	if *opts.generateAPIKey != "" {
		return &Config{
			GenerateAPIKeyPath: *opts.generateAPIKey,
		}, nil
	}

	isTriggerMode := *opts.triggerMode || *opts.listen != "" || (*opts.apiKeyStore != "" && *opts.host == "" && *opts.uri == "" && *opts.port == "")

	serviceName := *opts.serviceName
	if serviceName == "" && *opts.oracleService != "" {
		serviceName = *opts.oracleService
	}

	var targetPool []TargetDef
	if *opts.host != "" || *opts.port != "" || *opts.uri != "" {
		var err error
		targetPool, err = ResolveTargetPool(*opts.host, *opts.port, *opts.uri, *opts.protocol, serviceName)
		if err != nil {
			return nil, err
		}
	} else if !isTriggerMode {
		return nil, fmt.Errorf("target host, port, or URI must be specified using --host, --port, or --uri")
	}

	intervalBetweenProbesDuration := utils.SecondsToDuration(*opts.intervalBetweenProbes)
	if intervalBetweenProbesDuration < minProbeInterval {
		return nil, fmt.Errorf("wait interval should be more than 2 ms")
	}

	resolver := dns.NewResolver(
		*opts.customDNSServer,
		2*time.Second,
		*opts.useIPv4,
		*opts.useIPv6,
	)

	var targetConfigs []TargetConfig
	var targetStrings []string

	for _, tDef := range targetPool {
		var targetIsAlreadyIP bool
		resolvedIP, _ := resolver.ResolveHostname(tDef.Host)
		if resolvedIP.IsValid() && resolvedIP.String() == tDef.Host {
			targetIsAlreadyIP = true
		}

		var shouldRetryResolve bool
		if (!resolvedIP.IsValid() || *opts.retryHostnameResolveAfterNFailures > 0) && !targetIsAlreadyIP {
			shouldRetryResolve = true
		}

		tCfg := TargetConfig{
			Host:                    tDef.Host,
			IP:                      resolvedIP,
			Port:                    tDef.Port,
			Protocol:                tDef.Protocol,
			TargetIsIP:              targetIsAlreadyIP,
			ServiceName:             tDef.ServiceName,
			ShouldRetryResolve:      shouldRetryResolve,
			RetryResolveAfterNFails: *opts.retryHostnameResolveAfterNFailures,
		}
		targetConfigs = append(targetConfigs, tCfg)
		targetStrings = append(targetStrings, fmt.Sprintf("%s:%d", tDef.Host, tDef.Port))
	}

	var primaryTarget TargetConfig
	if len(targetConfigs) > 0 {
		primaryTarget = targetConfigs[0]
	}
	timeoutInDuration := utils.SecondsToDuration(*opts.timeout)

	var networkInterface nic.NetworkInterface
	if *opts.interfaceName != "" {
		var err error
		networkInterface, err = nic.NewNetworkInterface(
			*opts.interfaceName,
			primaryTarget.IP,
			primaryTarget.Port,
			*opts.useIPv4,
			*opts.useIPv6,
			timeoutInDuration,
		)
		if err != nil {
			return nil, err
		}
	}

	format := strings.ToLower(strings.TrimSpace(*opts.outputFormat))
	filePath := strings.TrimSpace(*opts.outputFile)

	if format == "" && filePath != "" {
		ext := strings.ToLower(filepath.Ext(filePath))
		switch ext {
		case ".json":
			format = "json"
		case ".csv":
			format = "csv"
		case ".tsv":
			format = "tsv"
		case ".db", ".sqlite", ".sqlite3":
			format = "sqlite"
		case ".txt":
			format = "txt"
		}
	}

	var isJSON, isPretty bool
	var csvPath, tsvPath, dbPath string

	switch format {
	case "json":
		isJSON = true
	case "pretty_json", "pretty-json", "prettyjson":
		isJSON = true
		isPretty = true
	case "csv":
		csvPath = filePath
		if csvPath == "" {
			csvPath = printers.GenerateDefaultExportPath(len(targetPool) > 1, printers.FormatCSV)
		}
	case "tsv":
		tsvPath = filePath
		if tsvPath == "" {
			tsvPath = printers.GenerateDefaultExportPath(len(targetPool) > 1, printers.FormatTSV)
		}
	case "sqlite", "sqlite3", "db":
		dbPath = filePath
		if dbPath == "" {
			dbPath = printers.GenerateDefaultExportPath(len(targetPool) > 1, printers.FormatSQLite3)
		}
	case "txt", "text", "plain":
		// text export format
	case "":
		// standard console output
	default:
		return nil, fmt.Errorf("unsupported output format %q (supported: json, pretty_json, csv, tsv, sqlite, txt)", format)
	}

	printerConfig := printers.PrinterConfig{
		Target:            primaryTarget.Host,
		Port:              primaryTarget.Port,
		OutputFormat:      format,
		OutputFile:        filePath,
		OutputJSON:        isJSON,
		PrettyJSON:        isPretty,
		NoColor:           *opts.noColor,
		WithTimestamp:     *opts.showTimestamp,
		WithSourceAddress: *opts.showSourceAddress,
		WithDiags:         *opts.showDiags || *opts.showDiagnostics,
		OutputDBPath:      dbPath,
		OutputCSVPath:     csvPath,
		OutputTSVPath:     tsvPath,
	}

	var dnsHosts []string
	if *opts.dnsHost != "" {
		for _, h := range strings.Split(*opts.dnsHost, ",") {
			trimmed := strings.TrimSpace(h)
			if trimmed != "" {
				dnsHosts = append(dnsHosts, trimmed)
			}
		}
	}

	webAddr := *opts.webAddr
	if *opts.listen != "" {
		webAddr = *opts.listen
	}
	if webAddr == "" && isTriggerMode {
		webAddr = ":3000"
	}

	isLegacyConsole := *opts.legacyConsole
	if isLegacyConsole {
		_ = os.Setenv("NETPING_LEGACY_CONSOLE", "1")
	}

	rawPrefix := *opts.urlPrefix
	if rawPrefix == "" && *opts.basePath != "" {
		rawPrefix = *opts.basePath
	}
	if rawPrefix == "" {
		rawPrefix = os.Getenv("NETPING_URL_PREFIX")
	}
	urlPrefix := normalizeURLPrefix(rawPrefix)

	cfg := &Config{
		Hostname:                   primaryTarget.Host,
		IP:                         primaryTarget.IP,
		Port:                       primaryTarget.Port,
		Protocol:                   primaryTarget.Protocol,
		TargetConfigs:              targetConfigs,
		Targets:                    targetStrings,
		Concurrency:                *opts.concurrency,
		UseIPv4:                    *opts.useIPv4,
		UseIPv6:                    *opts.useIPv6,
		ShowSourceAddress:          *opts.showSourceAddress,
		ProbesBeforeQuit:           *opts.probesBeforeQuit,
		Timeout:                    timeoutInDuration,
		IntervalBetweenProbes:      intervalBetweenProbesDuration,
		PrinterConfig:              printerConfig,
		NetworkInterface:           networkInterface,
		RetryResolveAfterNFailures: *opts.retryHostnameResolveAfterNFailures,
		RetryHostnameLookupAfter:   *opts.retryHostnameResolveAfterNFailures,
		TargetIsIP:                 primaryTarget.TargetIsIP,
		ShouldRetryResolve:         primaryTarget.ShouldRetryResolve,
		ShowFailuresOnly:           *opts.showFailuresOnly,
		Resolver:                   resolver,
		SendData:                   *opts.sendData,
		ExpectData:                 *opts.expectData,
		FastClose:                  *opts.fastClose,
		ResolveEveryProbe:          *opts.resolveEveryProbe,
		MaxConsecutiveFails:        *opts.maxConsecutiveFails,
		MaxLatency:                 *opts.maxLatency,
		MetricsAddr:                *opts.metricsAddr,
		QuietMode:                  *opts.quietMode,
		ShowSparkline:              *opts.showSparkline,
		ShowDashboard:              *opts.showDashboard,
		TracerouteMode:             *opts.tracerouteMode,
		Retries:                    *opts.retries,
		InitialRetryBackoff:        utils.SecondsToDuration(*opts.retryBackoff),
		MaxRetryBackoff:            utils.SecondsToDuration(*opts.retryMaxBackoff),
		RetryJitter:                *opts.retryJitter,
		EnableWeb:                  *opts.enableWeb || isTriggerMode,
		WebAddr:                    webAddr,
		ShowDiags:                  *opts.showDiags || *opts.showDiagnostics,
		StartTLS:                   *opts.startTLS,
		DNSHosts:                   dnsHosts,
		ServiceName:                serviceName,
		HistoryLimit:               *opts.historyLimit,
		GenerateAPIKeyPath:         *opts.generateAPIKey,
		APIKeyStore:                *opts.apiKeyStore,
		APIKeyHash:                 *opts.apiKeyHash,
		TriggerMode:                isTriggerMode,
		TriggerConcurrency:         *opts.triggerConcurrency,
		LegacyConsole:              isLegacyConsole,
		URLPrefix:                  urlPrefix,
	}

	return cfg, nil
}

func normalizeURLPrefix(raw string) string {
	clean := strings.TrimSpace(raw)
	if clean == "" || clean == "/" {
		return ""
	}
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}
	return strings.TrimRight(clean, "/")
}
