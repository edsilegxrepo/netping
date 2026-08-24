package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
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
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 && parsed <= 65535 {
			return h, uint16(parsed)
		}
		return h, defaultPort
	}
	return target, defaultPort
}

// parseHostPortArgs handles both "host port" and "host:port" formats
func parseHostPortArgs(args []string) (host string, port string) {
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

// ResolveProtocolAndPort resolves the target protocol and its standard default port.
func ResolveProtocolAndPort(protocolStr string, port string, target string) (consts.Protocol, string, string) {
	proto := consts.TCP
	switch strings.ToLower(protocolStr) {
	case "http":
		proto = consts.HTTP
		if port == "" {
			port = "80"
		}
	case "https":
		proto = consts.HTTPS
		if port == "" {
			port = "443"
		}
	case "grpc":
		proto = consts.GRPC
		if port == "" {
			port = "50051"
		}
	case "icmp", "ping":
		proto = consts.ICMP
		if port == "" {
			port = "0"
		}
	case "tls", "tcps", "ssl":
		proto = consts.TLS
		if port == "" {
			port = "443"
		}
	case "grpcs":
		proto = consts.GRPCS
		if port == "" {
			port = "443"
		}
	case "ws":
		proto = consts.WS
		if port == "" {
			port = "80"
		}
	case "wss":
		proto = consts.WSS
		if port == "" {
			port = "443"
		}
	case "dns":
		proto = consts.DNS
		if port == "" {
			port = "53"
		}
	case "dot":
		proto = consts.DOT
		if port == "" {
			port = "853"
		}
	case "doh":
		proto = consts.DOH
		if port == "" {
			port = "443"
		}
	case "redis":
		proto = consts.REDIS
		if port == "" {
			port = "6379"
		}
	case "rediss":
		proto = consts.REDISS
		if port == "" {
			port = "6380"
		}
	case "ssh", "sftp":
		proto = consts.SSH
		if port == "" {
			port = "22"
		}
	case "postgres", "postgresql":
		proto = consts.POSTGRES
		if port == "" {
			port = "5432"
		}
	case "mysql", "mariadb":
		proto = consts.MYSQL
		if port == "" {
			port = "3306"
		}
	case "mssql", "sqlserver":
		proto = consts.MSSQL
		if port == "" {
			port = "1433"
		}
	case "oracle", "tns":
		proto = consts.ORACLE
		if port == "" {
			port = "1521"
		}
	case "mongodb", "mongo":
		proto = consts.MONGODB
		if port == "" {
			port = "27017"
		}
	case "mongodbs", "mongodb+ssl", "mongo+ssl":
		proto = consts.MONGODBS
		if port == "" {
			port = "27017"
		}
	case "cassandra", "scylla", "cql":
		proto = consts.CASSANDRA
		if port == "" {
			port = "9042"
		}
	case "cassandras", "cqls":
		proto = consts.CASSANDRAS
		if port == "" {
			port = "9042"
		}
	case "saphana", "hana":
		proto = consts.SAPHANA
		if port == "" {
			port = "30015"
		}
	case "memcached", "memcache":
		proto = consts.MEMCACHED
		if port == "" {
			port = "11211"
		}
	case "memcacheds", "memcaches":
		proto = consts.MEMCACHEDS
		if port == "" {
			port = "11211"
		}
	case "smtp":
		proto = consts.SMTP
		if port == "" {
			port = "25"
		}
	case "smtps":
		proto = consts.SMTPS
		if port == "" {
			port = "465"
		}
	case "imap":
		proto = consts.IMAP
		if port == "" {
			port = "143"
		}
	case "imaps":
		proto = consts.IMAPS
		if port == "" {
			port = "993"
		}
	case "pop3":
		proto = consts.POP3
		if port == "" {
			port = "110"
		}
	case "pop3s":
		proto = consts.POP3S
		if port == "" {
			port = "995"
		}
	case "ldap":
		proto = consts.LDAP
		if port == "" {
			port = "389"
		}
	case "ldaps":
		proto = consts.LDAPS
		if port == "" {
			port = "636"
		}
	case "o365", "o365mbx", "graph":
		proto = consts.O365
		if port == "" {
			port = "443"
		}
		if target == "" {
			target = "outlook.office365.com"
		}
	case "s3", "awss3":
		proto = consts.S3
		if port == "" {
			port = "443"
		}
		if target == "" {
			target = "s3.amazonaws.com"
		}
	case "blob", "azureblob", "adls":
		proto = consts.AZUREBLOB
		if port == "" {
			port = "443"
		}
		if target == "" {
			target = "blob.core.windows.net"
		}
	case "gcs", "gcpbucket", "gcpstorage":
		proto = consts.GCS
		if port == "" {
			port = "443"
		}
		if target == "" {
			target = "storage.googleapis.com"
		}
	case "kafka":
		proto = consts.KAFKA
		if port == "" {
			port = "9092"
		}
	case "kafkas":
		proto = consts.KAFKAS
		if port == "" {
			port = "9093"
		}
	case "rabbitmq", "amqp":
		proto = consts.RABBITMQ
		if port == "" {
			port = "5672"
		}
	case "amqps":
		proto = consts.AMQPS
		if port == "" {
			port = "5671"
		}
	case "smb", "cifs":
		proto = consts.SMB
		if port == "" {
			port = "445"
		}
	case "rsync":
		proto = consts.RSYNC
		if port == "" {
			port = "873"
		}
	case "ftp":
		proto = consts.FTP
		if port == "" {
			port = "21"
		}
	case "ftps":
		proto = consts.FTPS
		if port == "" {
			port = "990"
		}
	case "udp":
		proto = consts.UDP
	default:
		proto = consts.TCP
	}
	return proto, port, target
}

// TargetDef represents a parsed and normalized target destination.
type TargetDef struct {
	Host        string
	Port        uint16
	Protocol    consts.Protocol
	ServiceName string
}

// ResolveTargetPool parses --host, --port, --uri, and --protocol inputs into a slice of TargetDefs.
func ResolveTargetPool(hostStr, portStr, uriStr, protoStr, serviceName string) ([]TargetDef, error) {
	var targets []TargetDef

	// 1. If --uri is provided, split by comma and parse each URI
	if strings.TrimSpace(uriStr) != "" {
		rawURIs := strings.Split(uriStr, ",")
		for _, raw := range rawURIs {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			var proto consts.Protocol = consts.TCP
			targetPart := raw
			if idx := strings.Index(raw, "://"); idx != -1 {
				scheme := raw[:idx]
				targetPart = raw[idx+3:]
				proto, _, _ = ResolveProtocolAndPort(scheme, "", "")
			} else if protoStr != "" {
				proto, _, _ = ResolveProtocolAndPort(protoStr, "", "")
			}

			h, p := ParseHostPort(targetPart, 0)
			if p == 0 {
				_, defPortStr, _ := ResolveProtocolAndPort(string(proto), "", "")
				if parsedPort, err := strconv.Atoi(defPortStr); err == nil && parsedPort > 0 {
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
		return nil, fmt.Errorf("target host, port, or URI must be specified using --host, --port, or --uri")
	}

	var hosts []string
	if hostStr != "" {
		for _, h := range strings.Split(hostStr, ",") {
			if trimmed := strings.TrimSpace(h); trimmed != "" {
				hosts = append(hosts, trimmed)
			}
		}
	} else {
		hosts = []string{"127.0.0.1"}
	}

	var protocols []consts.Protocol
	if protoStr != "" {
		for _, pr := range strings.Split(protoStr, ",") {
			if trimmed := strings.TrimSpace(pr); trimmed != "" {
				p, _, _ := ResolveProtocolAndPort(trimmed, "", "")
				protocols = append(protocols, p)
			}
		}
	}
	if len(protocols) == 0 {
		protocols = []consts.Protocol{consts.TCP}
	}

	var ports []uint16
	if portStr != "" {
		for _, ps := range strings.Split(portStr, ",") {
			if trimmed := strings.TrimSpace(ps); trimmed != "" {
				val, err := convertAndValidatePort(trimmed)
				if err != nil {
					return nil, err
				}
				ports = append(ports, val)
			}
		}
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

// usage prints how netping should be run with clean categorized sections
func usage() {
	fmt.Printf("\nnetping version %s - Multi-Protocol Latency & Diagnostics Prober\n\n", version)
	fmt.Println("USAGE:")
	fmt.Println("  netping <host> <port> [options]")
	fmt.Println("  netping --host <hosts> --port <ports> [options]")
	fmt.Println("  netping --uri <uri1,uri2,...> [options]")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  netping example.com 443")
	fmt.Println("  netping --host web1,web2 --port 80,443 --protocol https")
	fmt.Println("  netping --host db-server --protocol postgresql --diags")
	fmt.Println("  netping --uri cloudflare.com:443 --dashboard")
	fmt.Println("  netping --host 1.1.1.1,8.8.8.8 --port 53 --output-format csv --output-file ./dns.csv")
	fmt.Println()
	fmt.Println("TARGET CONFIGURATION:")
	fmt.Println("  --host <hosts>             Target hostname(s) or IP(s), comma-separated for multi-target.")
	fmt.Println("  --port <ports>             Target port(s), comma-separated for multi-port.")
	fmt.Println("  --uri <uris>               Target URI(s) in host:port or scheme://host:port format.")
	fmt.Println("  --protocol <proto>         Probe protocol (tcp, http, https, grpc, dns, redis, postgresql, ...).")
	fmt.Println("  --service <name>           Service name / SID for Oracle database connections.")
	fmt.Println("  --oracle-service <name>    Alias for --service.")
	fmt.Println("  --dns-host <domains>       Domain(s) to resolve in DNS query mode (comma-separated).")
	fmt.Println()
	fmt.Println("PROBE EXECUTION & TIMING:")
	fmt.Println("  --count <n>                Stop after <n> probes (default: unlimited).")
	fmt.Println("  --interval <sec>           Interval between probes in seconds (default: 1.0).")
	fmt.Println("  --timeout <sec>            Response timeout in seconds (default: 1.0).")
	fmt.Println("  --concurrency <n>          Maximum parallel prober workers (0 = unconstrained).")
	fmt.Println("  --ipv4                     Force IPv4 address resolution.")
	fmt.Println("  --ipv6                     Force IPv6 address resolution.")
	fmt.Println("  --interface <iface>        Bind to a specific network interface name or source IP.")
	fmt.Println("  --dns-server <ip:port>     Custom DNS server to use for resolution.")
	fmt.Println("  --resolve-every-probe      Re-resolve target DNS on every probe cycle.")
	fmt.Println("  --retry-resolve <n>        Retry resolving target hostname after <n> consecutive failures.")
	fmt.Println()
	fmt.Println("SLA & ERROR HANDLING:")
	fmt.Println("  --max-latency <ms>         Fail probe if latency exceeds threshold in milliseconds.")
	fmt.Println("  --max-consecutive-fails <n> Stop probing after <n> consecutive failed probes.")
	fmt.Println("  --retry <n>                Number of transient retry attempts per probe before failing.")
	fmt.Println("  --retry-backoff <sec>      Initial retry backoff delay in seconds (default: 0.05).")
	fmt.Println("  --retry-max-backoff <sec>  Maximum retry backoff delay in seconds (default: 2.0).")
	fmt.Println("  --retry-jitter             Apply randomized jitter to exponential retry backoff.")
	fmt.Println()
	fmt.Println("PROTOCOL & PAYLOAD OPTIONS:")
	fmt.Println("  --send <data>              Send specific payload string upon connection.")
	fmt.Println("  --expect <data>            Expect specific response string in banner.")
	fmt.Println("  --starttls                 Upgrade connection via STARTTLS (SMTP, IMAP, POP3).")
	fmt.Println("  --fast-close               Use SO_LINGER=0 to avoid TIME_WAIT socket accumulation.")
	fmt.Println("  --traceroute               Perform hop-by-hop Layer-4 route discovery.")
	fmt.Println()
	fmt.Println("DASHBOARD & WEB MONITORING:")
	fmt.Println("  --dashboard                Open interactive live terminal TUI dashboard.")
	fmt.Println("  --web                      Start embedded real-time web dashboard (default 127.0.0.1:3000).")
	fmt.Println("  --web-addr <addr>          Custom listen address for web dashboard (e.g. :3000).")
	fmt.Println("  --metrics-addr <addr>      Enable Prometheus metrics exporter on given address (e.g. :9100).")
	fmt.Println("  --history-limit <n>        Maximum in-memory historical probe events retained (default: 1000000, max: 5000000).")
	fmt.Println("  --sparkline                Render live terminal latency sparklines.")
	fmt.Println()
	fmt.Println("OUTPUT & REPORTING:")
	fmt.Println("  --output-format <format>   Export format: json, pretty_json, csv, tsv, sqlite, txt.")
	fmt.Println("  --output-file <path>       Destination file path to save output report.")
	fmt.Println("  --quiet                    Quiet mode: suppress per-probe lines, show only final summary.")
	fmt.Println("  --show-failures-only       Show only failed probes in live output.")
	fmt.Println("  --show-source-address      Show source IP and port used for probes.")
	fmt.Println("  --timestamp                Show timestamp for each probe in output.")
	fmt.Println("  --diags, --diagnostics     Show detailed protocol negotiation diagnostics.")
	fmt.Println("  --no-color                 Do not colorize terminal output.")
	fmt.Println()
	fmt.Println("GENERAL:")
	fmt.Println("  --help                     Show this help message and exit.")
	fmt.Println("  --version                  Show version and exit.")
	fmt.Println("  --check-updates            Check for newer releases on GitHub and exit.")
	fmt.Println()

	os.Exit(1)
}

// showVersion displays the version and exits
func showVersion() {
	fmt.Printf("netping version %s\n", version)
	os.Exit(0)
}

// compareVersions is used to compare tcping versions
func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		n1, _ := strconv.Atoi(parts1[i])
		n2, _ := strconv.Atoi(parts2[i])

		if n1 < n2 {
			return -1
		}

		if n1 > n2 {
			return 1
		}
	}

	// for cases in which version numbers differ in length
	if len(parts1) < len(parts2) {
		return -1
	}

	if len(parts1) > len(parts2) {
		return 1
	}

	return 0
}

// checkForUpdates checks for newer versions of tcping
func checkForUpdates() {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Could not create request: %s", err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// optional (GitHub recommends)
	req.Header.Set("User-Agent", "edsilegx-netping-update-check")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to check for updates %s\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed to check for updates: HTTP %d\n", resp.StatusCode)
		os.Exit(1)
	}

	release := struct {
		TagName string `json:"tag_name"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		fmt.Printf("Failed to parse release info: %s\n", err)
		os.Exit(1)
	}

	reg := `^v?(\d+\.\d+\.\d+)$`
	latestTagName := release.TagName
	re := regexp.MustCompile(reg)
	m := re.FindStringSubmatch(latestTagName)
	if len(m) == 0 {
		fmt.Printf("Failed to check for updates. The version name does not match the rule: %s\n", latestTagName)
		os.Exit(1)
	}

	latestVer := m[1]

	comparison := compareVersions(version, latestVer)

	if comparison < 0 {
		fmt.Printf("Found newer version: %s\n", latestVer)
		fmt.Printf("Please update netping from the URL below:\n")
		fmt.Printf("https://github.com/%s/%s/releases/tag/%s\n",
			owner, repo, latestTagName)
	} else if comparison > 0 {
		fmt.Printf("Current version %s is newer than the latest release %s\n",
			version, latestVer)
	} else {
		fmt.Printf("You have the latest version: %s\n", version)
	}

	os.Exit(0)
}
