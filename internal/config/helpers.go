package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
)

// version is set at compile time via the Makefile
var version = "dev"

// Used when checking for updates
const (
	owner = "edsilegx"
	repo  = "netping"
)

// convertAndValidatePort validates and returns the TCP/UDP port
func convertAndValidatePort(port string) (uint16, error) {
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port number %q", port)
	}

	if parsedPort == 0 {
		return 0, fmt.Errorf("port should be in 1..65535 range")
	}

	return uint16(parsedPort), nil
}

// ParseHostPort parses a target string into host and port, falling back to defaultPort if unassigned.
func ParseHostPort(target string, defaultPort uint16) (string, uint16) {
	if h, p, err := net.SplitHostPort(target); err == nil {
		if parsed, err := strconv.ParseUint(p, 10, 16); err == nil && parsed > 0 {
			return h, uint16(parsed)
		}
		return h, defaultPort
	}
	return target, defaultPort
}

// ParseHostPortArgs handles both "host port" and "host:port" formats
func ParseHostPortArgs(args []string) (host, port string) {
	if len(args) == 0 {
		return "", ""
	}

	// If the first argument is already in host:port format, extract it
	if h, p, err := net.SplitHostPort(args[0]); err == nil {
		return h, p
	}

	// If provided as separate arguments [host, port, ...]
	if len(args) >= 2 {
		return args[0], args[1]
	}

	return args[0], ""
}

// ResolveProtocolAndPort parses protocol strings and provides default ports and cloud target hostnames.
func ResolveProtocolAndPort(protocolStr, port, target string) (consts.Protocol, string, string) {
	proto, defaultPort, ok := consts.NormalizeProtocol(protocolStr)
	if !ok {
		proto = consts.TCP
	}

	if port == "" && strings.ToLower(strings.TrimSpace(protocolStr)) != "udp" {
		if ok {
			port = strconv.Itoa(int(defaultPort))
		}
	}

	// Default target endpoints for specialized cloud protocols if none provided
	if target == "" {
		switch proto {
		case consts.O365:
			target = "outlook.office365.com"
		case consts.S3:
			target = "s3.amazonaws.com"
		case consts.AZUREBLOB:
			target = "blob.core.windows.net"
		case consts.GCS:
			target = "storage.googleapis.com"
		case consts.ENTRA:
			target = "login.microsoftonline.com"
		}
	}

	return proto, port, target
}

// TargetDef represents a parsed and normalized target destination.
type TargetDef struct {
	Host        string
	Port        uint16
	Protocol    consts.Protocol
	ServiceName string
	URI         string
}

// splitAndTrimComma splits a comma-delimited string, trimming whitespace and filtering empty elements.
func splitAndTrimComma(s string) []string {
	var res []string
	for _, item := range strings.Split(s, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

// ResolveTargetPool parses --host, --port, --uri, and --protocol inputs into a slice of TargetDefs.
func ResolveTargetPool(hostStr, portStr, uriStr, protoStr, serviceName string) ([]TargetDef, error) {
	var targets []TargetDef

	// 1. If --uri is provided, split by comma and parse each URI
	if strings.TrimSpace(uriStr) != "" {
		for _, raw := range splitAndTrimComma(uriStr) {
			proto := consts.TCP
			targetPart := raw
			if protoStr != "" {
				proto, _, _ = ResolveProtocolAndPort(protoStr, "", "")
			} else if idx := strings.Index(raw, "://"); idx != -1 {
				scheme := raw[:idx]
				proto, _, _ = ResolveProtocolAndPort(scheme, "", "")
			}

			rawURL := raw
			if !strings.Contains(raw, "://") {
				rawURL = "https://" + raw
			}
			var h string
			var p uint16
			if parsedU, err := url.Parse(rawURL); err == nil && parsedU.Hostname() != "" {
				h = parsedU.Hostname()
				if parsedU.Port() != "" {
					if parsedPort, err := strconv.ParseUint(parsedU.Port(), 10, 16); err == nil && parsedPort > 0 {
						p = uint16(parsedPort)
					}
				}
			} else {
				h, p = ParseHostPort(targetPart, 0)
			}

			if p == 0 {
				_, defPortStr, _ := ResolveProtocolAndPort(string(proto), "", "")
				if parsedPort, err := strconv.ParseUint(defPortStr, 10, 16); err == nil && parsedPort > 0 {
					p = uint16(parsedPort)
				} else {
					p = 443
				}
			}
			if h == "" {
				return nil, fmt.Errorf("invalid URI %q: missing host", raw)
			}
			targets = append(targets, TargetDef{
				Host:        h,
				Port:        p,
				Protocol:    proto,
				ServiceName: serviceName,
				URI:         raw,
			})
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("no valid targets found in --uri")
		}
		return targets, nil
	}

	// 2. If --host or --port or --protocol is provided
	hostStr = strings.TrimSpace(hostStr)
	portStr = strings.TrimSpace(portStr)
	protoStr = strings.TrimSpace(protoStr)

	if hostStr == "" && portStr == "" {
		if protoStr != "" {
			_, _, defTarget := ResolveProtocolAndPort(protoStr, "", "")
			if defTarget != "" {
				hostStr = defTarget
			} else {
				return nil, fmt.Errorf("target host, port, or URI must be specified using --host, --port, or --uri")
			}
		} else {
			return nil, fmt.Errorf("target host, port, or URI must be specified using --host, --port, or --uri")
		}
	}

	hosts := splitAndTrimComma(hostStr)
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1"}
	}

	var protocols []consts.Protocol
	for _, pr := range splitAndTrimComma(protoStr) {
		p, _, _ := ResolveProtocolAndPort(pr, "", "")
		protocols = append(protocols, p)
	}
	if len(protocols) == 0 {
		protocols = []consts.Protocol{consts.TCP}
	}

	var ports []uint16
	for _, ps := range splitAndTrimComma(portStr) {
		val, err := convertAndValidatePort(ps)
		if err != nil {
			return nil, err
		}
		ports = append(ports, val)
	}

	// Combinatorial Expansion
	if len(ports) == 0 {
		// Multi-protocol / default protocol auto-port
		for _, host := range hosts {
			for _, proto := range protocols {
				_, defPortStr, _ := ResolveProtocolAndPort(string(proto), "", "")
				defPort, _ := strconv.Atoi(defPortStr)
				if defPort == 0 {
					defPort = 443
				}
				targets = append(targets, TargetDef{
					Host:        host,
					Port:        uint16(defPort),
					Protocol:    proto,
					ServiceName: serviceName,
				})
			}
		}
	} else if len(protocols) > 1 && len(ports) == len(protocols) {
		// Paired protocol and ports (1-to-1)
		for _, host := range hosts {
			for i, proto := range protocols {
				targets = append(targets, TargetDef{
					Host:        host,
					Port:        ports[i],
					Protocol:    proto,
					ServiceName: serviceName,
				})
			}
		}
	} else {
		// Cartesian Product across hosts x ports x protocols
		for _, host := range hosts {
			for _, port := range ports {
				for _, proto := range protocols {
					targets = append(targets, TargetDef{
						Host:        host,
						Port:        port,
						Protocol:    proto,
						ServiceName: serviceName,
					})
				}
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets resolved")
	}
	return targets, nil
}

// PrintUsage prints how netping should be run with clean categorized sections to the given writer
func PrintUsage(w io.Writer) {
	usageText := fmt.Sprintf(`
netping version %s - Multi-Protocol Latency & Diagnostics Prober

USAGE:
  netping --host <hosts> --port <ports> [options]
  netping --uri <uri1,uri2,...> [options]

EXAMPLES:
  netping --host example.com --port 443
  netping --host web1,web2 --port 80,443 --protocol https
  netping --host db-server --port 5432 --protocol postgresql --diags
  netping --host kdc.corp.local --protocol kerberos --diags
  netping --host accounts.google.com --protocol oidc --diags
  netping --host login.microsoftonline.com --protocol saml --diags
  netping --uri cloudflare.com:443 --dashboard
  netping --host 1.1.1.1,8.8.8.8 --port 53 --output-format csv --output-file ./dns.csv

TARGET CONFIGURATION:
  --host <hosts>             Target hostname(s) or IP(s), comma-separated for multi-target.
  --port <ports>             Target port(s), comma-separated for multi-port.
  --uri <uris>               Target URI(s) in host:port or scheme://host:port format.
  --protocol <proto>         Probe protocol (tcp, http, https, grpc, dns, redis, postgresql, kerberos, oidc, saml, oauth2, sso, ...).
  --service <name>           Service name / SID for Oracle database connections.
  --oracle-service <name>    Alias for --service.
  --dns-host <domains>       Domain(s) to resolve in DNS query mode (comma-separated).

PROBE EXECUTION & TIMING:
  --count <n>                Stop after <n> probes (default: unlimited).
  --interval <sec>           Interval between probes in seconds (default: 1.0).
  --timeout <sec>            Response timeout in seconds (default: 1.0).
  --concurrency <n>          Maximum parallel prober workers (0 = unconstrained).
  --ipv4                     Force IPv4 address resolution.
  --ipv6                     Force IPv6 address resolution.
  --interface <iface>        Bind to a specific network interface name or source IP.
  --dns-server <ip:port>     Custom DNS server to use for resolution.
  --resolve-every-probe      Re-resolve target DNS on every probe cycle.
  --retry-resolve <n>        Retry resolving target hostname after <n> consecutive failures.

SLA & ERROR HANDLING:
  --max-latency <ms>         Fail probe if latency exceeds threshold in milliseconds.
  --max-consecutive-fails <n> Stop probing after <n> consecutive failed probes.
  --retry <n>                Number of transient retry attempts per probe before failing.
  --retry-backoff <sec>      Initial retry backoff delay in seconds (default: 0.05).
  --retry-max-backoff <sec>  Maximum retry backoff delay in seconds (default: 2.0).
  --retry-jitter             Apply randomized jitter to exponential retry backoff.

PROTOCOL & PAYLOAD OPTIONS:
  --send <data>              Send specific payload string upon connection.
  --expect <data>            Expect specific response string in banner.
  --starttls                 Upgrade connection via STARTTLS (SMTP, IMAP, POP3).
  --fast-close               Use SO_LINGER=0 to avoid TIME_WAIT socket accumulation.
  --traceroute               Perform hop-by-hop Layer-4 route discovery.

DASHBOARD & WEB MONITORING:
  --dashboard                Open interactive live terminal TUI dashboard.
  --web                      Start embedded real-time web dashboard (default 127.0.0.1:3000).
  --web-addr <addr>          Custom listen address for web dashboard (e.g. :3000).
  --metrics-addr <addr>      Enable Prometheus metrics exporter on given address (e.g. :9100).
  --history-limit <n>        Maximum in-memory historical probe events retained (default: 1000000, max: 5000000).
  --sparkline                Render live terminal latency sparklines.

OUTPUT & REPORTING:
  --output-format <format>   Export format: json, pretty_json, csv, tsv, sqlite, txt.
  --output-file <path>       Destination file path to save output report.
  --quiet                    Quiet mode: suppress per-probe lines, show only final summary.
  --show-failures-only       Show only failed probes in live output.
  --show-source-address      Show source IP and port used for probes.
  --timestamp                Show timestamp for each probe in output.
  --diags, --diagnostics     Show detailed protocol negotiation diagnostics.
  --no-color                 Do not colorize terminal output.

GENERAL:
  --help                     Show this help message and exit.
  --version                  Show version and exit.
  --check-updates            Check for newer releases on GitHub and exit.
`, version)
	_, _ = fmt.Fprint(w, usageText)
}

func usage() {
	PrintUsage(os.Stdout)
	os.Exit(consts.ExitUsageError)
}

// PrintVersion displays the version to the given writer
func PrintVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "netping version %s\n", version)
}

// showVersion displays the version and exits
func showVersion() {
	PrintVersion(os.Stdout)
	os.Exit(consts.ExitSuccess)
}

// compareVersions is used to compare tcping versions
func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		p1, err1 := strconv.Atoi(parts1[i])
		p2, err2 := strconv.Atoi(parts2[i])

		if err1 != nil || err2 != nil {
			return 0
		}

		if p1 < p2 {
			return -1
		} else if p1 > p2 {
			return 1
		}
	}

	if len(parts1) < len(parts2) {
		return -1
	} else if len(parts1) > len(parts2) {
		return 1
	}

	return 0
}

// CheckForUpdatesURL checks for newer versions of netping against a custom URL (for testing)
func CheckForUpdatesURL(url string, client *http.Client, w io.Writer) error {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	resp, err := client.Get(url)
	if err != nil {
		_, _ = fmt.Fprintf(w, "Check for updates failed: %s\n", err)
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		_, _ = fmt.Fprintf(w, "Check for updates failed: %s\n", err)
		return err
	}

	var data struct {
		TagName string `json:"tag_name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		_, _ = fmt.Fprintf(w, "Failed to decode update response: %s\n", err)
		return err
	}

	latestTagName := data.TagName
	latestVer := strings.TrimPrefix(latestTagName, "v")

	comparison := compareVersions(version, latestVer)
	if comparison < 0 {
		_, _ = fmt.Fprintf(w, "Found newer version: %s\n", latestVer)
		_, _ = fmt.Fprintf(w, "Please update netping from the URL below:\n")
		_, _ = fmt.Fprintf(w, "https://github.com/%s/%s/releases/tag/%s\n", owner, repo, latestTagName)
	} else if comparison > 0 {
		_, _ = fmt.Fprintf(w, "Current version %s is newer than the latest release %s\n", version, latestVer)
	} else {
		_, _ = fmt.Fprintf(w, "You have the latest version: %s\n", version)
	}
	return nil
}

// checkForUpdates checks for newer versions of netping
func checkForUpdates() {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	err := CheckForUpdatesURL(url, nil, os.Stdout)
	if err != nil {
		os.Exit(consts.ExitGeneralError)
	}
	os.Exit(consts.ExitSuccess)
}
