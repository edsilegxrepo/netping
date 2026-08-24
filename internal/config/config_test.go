package config

import (
	"flag"
	"net/netip"
	"testing"
	"time"

	"github.com/edsilegx/netping/internal/printers"
	"github.com/edsilegx/netping/pkg/consts"
	"github.com/stretchr/testify/assert"
)

func TestFlagsRequiringValue(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	registerFlags(fs)
	fv := flagsRequiringValue(fs)

	wantValue := []string{"host", "port", "uri", "concurrency", "count", "interval", "timeout", "retry-resolve", "dns-server", "dns-host", "interface", "output-format", "output-file", "send", "expect", "max-consecutive-fails", "max-latency", "metrics-addr", "protocol", "retry", "retry-backoff", "retry-max-backoff", "web-addr", "service", "oracle-service", "history-limit"}
	for _, name := range wantValue {
		assert.True(t, fv[name], "expected %q to require a value", name)
	}

	wantBool := []string{"ipv4", "ipv6", "timestamp", "show-source-address", "show-failures-only", "no-color", "version", "check-updates", "help", "fast-close", "resolve-every-probe", "quiet", "sparkline", "dashboard", "traceroute", "retry-jitter", "web", "diags", "diagnostics", "starttls"}
	for _, name := range wantBool {
		assert.False(t, fv[name], "expected %q to be a bool flag", name)
	}
}

func TestConfig_Getters(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	cfg := Config{
		Hostname:                   "example.com",
		IP:                         ip,
		Port:                       8080,
		Protocol:                   consts.HTTP,
		UseIPv4:                    true,
		UseIPv6:                    false,
		Timeout:                    2 * time.Second,
		IntervalBetweenProbes:      500 * time.Millisecond,
		ProbesBeforeQuit:           5,
		TargetIsIP:                 false,
		ShowFailuresOnly:           true,
		ShouldRetryResolve:         true,
		RetryHostnameLookupAfter:   3,
		PrinterConfig: printers.PrinterConfig{
			WithTimestamp:     true,
			WithSourceAddress: true,
		},
	}

	assert.Equal(t, "example.com", cfg.GetHostname())
	assert.Equal(t, ip, cfg.GetIP())
	assert.Equal(t, uint16(8080), cfg.GetPort())
	assert.Equal(t, consts.HTTP, cfg.GetProtocol())
	assert.True(t, cfg.GetUseIPv4())
	assert.False(t, cfg.GetUseIPv6())
	assert.Equal(t, "2s", cfg.GetTimeout())
	assert.Equal(t, "500ms", cfg.GetIntervalBetweenProbes())
	assert.Equal(t, uint(5), cfg.GetProbesBeforeQuit())
	assert.False(t, cfg.GetTargetIsIP())
	assert.True(t, cfg.GetShowFailuresOnly())
	assert.True(t, cfg.GetShouldRetryResolve())
	assert.Equal(t, uint(3), cfg.GetRetryResolveAfterNFailures())
	assert.True(t, cfg.GetWithTimestamp())
	assert.True(t, cfg.GetWithSourceAddress())
	assert.NotNil(t, cfg.GetPrinterConfig())
	assert.NotNil(t, cfg.GetNetworkInterface())
}

func TestPermuteArgs(t *testing.T) {
	registerFlags(flag.CommandLine)

	// Reorder positional args after flags
	args := []string{"example.com", "443", "--count", "2", "--ipv4"}
	permuteArgs(flag.CommandLine, args)

	assert.Equal(t, "--count", args[0])
	assert.Equal(t, "2", args[1])
	assert.Equal(t, "--ipv4", args[2])
	assert.Equal(t, "example.com", args[3])
	assert.Equal(t, "443", args[4])
}

func TestPermuteArgs_OnlyFlags(t *testing.T) {
	args := []string{"--output-format", "json", "--no-color"}
	permuteArgs(flag.CommandLine, args)
	assert.Equal(t, "--output-format", args[0])
	assert.Equal(t, "json", args[1])
	assert.Equal(t, "--no-color", args[2])
}

func TestPermuteArgs_OnlyPositional(t *testing.T) {
	args := []string{"example.com", "80"}
	permuteArgs(flag.CommandLine, args)
	assert.Equal(t, "example.com", args[0])
	assert.Equal(t, "80", args[1])
}

func TestResolveProtocolAndPort_AllProtocols(t *testing.T) {
	testCases := []struct {
		protoStr    string
		portIn      string
		targetIn    string
		wantProto   consts.Protocol
		wantPort    string
		wantTarget  string
	}{
		{"http", "", "", consts.HTTP, "80", ""},
		{"https", "", "", consts.HTTPS, "443", ""},
		{"grpc", "", "", consts.GRPC, "50051", ""},
		{"grpcs", "", "", consts.GRPCS, "443", ""},
		{"icmp", "", "", consts.ICMP, "0", ""},
		{"ping", "", "", consts.ICMP, "0", ""},
		{"tls", "", "", consts.TLS, "443", ""},
		{"tcps", "", "", consts.TLS, "443", ""},
		{"ssl", "", "", consts.TLS, "443", ""},
		{"ws", "", "", consts.WS, "80", ""},
		{"wss", "", "", consts.WSS, "443", ""},
		{"dns", "", "", consts.DNS, "53", ""},
		{"dot", "", "", consts.DOT, "853", ""},
		{"doh", "", "", consts.DOH, "443", ""},
		{"redis", "", "", consts.REDIS, "6379", ""},
		{"rediss", "", "", consts.REDISS, "6380", ""},
		{"ssh", "", "", consts.SSH, "22", ""},
		{"sftp", "", "", consts.SSH, "22", ""},
		{"postgres", "", "", consts.POSTGRES, "5432", ""},
		{"postgresql", "", "", consts.POSTGRES, "5432", ""},
		{"mysql", "", "", consts.MYSQL, "3306", ""},
		{"mariadb", "", "", consts.MYSQL, "3306", ""},
		{"mssql", "", "", consts.MSSQL, "1433", ""},
		{"sqlserver", "", "", consts.MSSQL, "1433", ""},
		{"oracle", "", "", consts.ORACLE, "1521", ""},
		{"tns", "", "", consts.ORACLE, "1521", ""},
		{"mongodb", "", "", consts.MONGODB, "27017", ""},
		{"mongo", "", "", consts.MONGODB, "27017", ""},
		{"mongodbs", "", "", consts.MONGODBS, "27017", ""},
		{"cassandra", "", "", consts.CASSANDRA, "9042", ""},
		{"scylla", "", "", consts.CASSANDRA, "9042", ""},
		{"saphana", "", "", consts.SAPHANA, "30015", ""},
		{"hana", "", "", consts.SAPHANA, "30015", ""},
		{"memcached", "", "", consts.MEMCACHED, "11211", ""},
		{"smtp", "", "", consts.SMTP, "25", ""},
		{"smtps", "", "", consts.SMTPS, "465", ""},
		{"imap", "", "", consts.IMAP, "143", ""},
		{"imaps", "", "", consts.IMAPS, "993", ""},
		{"pop3", "", "", consts.POP3, "110", ""},
		{"pop3s", "", "", consts.POP3S, "995", ""},
		{"ldap", "", "", consts.LDAP, "389", ""},
		{"ldaps", "", "", consts.LDAPS, "636", ""},
		{"o365", "", "", consts.O365, "443", "outlook.office365.com"},
		{"graph", "", "", consts.O365, "443", "outlook.office365.com"},
		{"s3", "", "", consts.S3, "443", "s3.amazonaws.com"},
		{"blob", "", "", consts.AZUREBLOB, "443", "blob.core.windows.net"},
		{"gcs", "", "", consts.GCS, "443", "storage.googleapis.com"},
		{"kafka", "", "", consts.KAFKA, "9092", ""},
		{"kafkas", "", "", consts.KAFKAS, "9093", ""},
		{"rabbitmq", "", "", consts.RABBITMQ, "5672", ""},
		{"amqp", "", "", consts.RABBITMQ, "5672", ""},
		{"amqps", "", "", consts.AMQPS, "5671", ""},
		{"smb", "", "", consts.SMB, "445", ""},
		{"cifs", "", "", consts.SMB, "445", ""},
		{"rsync", "", "", consts.RSYNC, "873", ""},
		{"ftp", "", "", consts.FTP, "21", ""},
		{"ftps", "", "", consts.FTPS, "990", ""},
		{"udp", "5000", "", consts.UDP, "5000", ""},
		{"unknown", "8080", "custom.host", consts.TCP, "8080", "custom.host"},
	}

	for _, tc := range testCases {
		p, port, target := ResolveProtocolAndPort(tc.protoStr, tc.portIn, tc.targetIn)
		assert.Equal(t, tc.wantProto, p, "protocol mismatch for %s", tc.protoStr)
		assert.Equal(t, tc.wantPort, port, "port mismatch for %s", tc.protoStr)
		assert.Equal(t, tc.wantTarget, target, "target mismatch for %s", tc.protoStr)
	}
}

func TestParseHostPortAndArgs(t *testing.T) {
	h, p := ParseHostPort("example.com:8443", 443)
	assert.Equal(t, "example.com", h)
	assert.Equal(t, uint16(8443), p)

	h, p = ParseHostPort("example.com", 443)
	assert.Equal(t, "example.com", h)
	assert.Equal(t, uint16(443), p)

	// parseHostPortArgs
	h, pStr := parseHostPortArgs([]string{"example.com:9000"})
	assert.Equal(t, "example.com", h)
	assert.Equal(t, "9000", pStr)

	h, pStr = parseHostPortArgs([]string{"example.com", "9000"})
	assert.Equal(t, "example.com", h)
	assert.Equal(t, "9000", pStr)

	h, pStr = parseHostPortArgs([]string{})
	assert.Empty(t, h)
	assert.Empty(t, pStr)
}

func TestPortValidation(t *testing.T) {
	p, err := convertAndValidatePort("80")
	assert.NoError(t, err)
	assert.Equal(t, uint16(80), p)

	p, err = convertAndValidatePort("65535")
	assert.NoError(t, err)
	assert.Equal(t, uint16(65535), p)

	_, err = convertAndValidatePort("0")
	assert.Error(t, err)

	_, err = convertAndValidatePort("70000")
	assert.Error(t, err)

	_, err = convertAndValidatePort("invalid")
	assert.Error(t, err)
}

func TestConfig_AllGetters(t *testing.T) {
	cfg := Config{
		ShowFailuresOnly: true,
		ShowDashboard:    true,
		QuietMode:        true,
		ShowSparkline:    true,
		Retries:          3,
		InitialRetryBackoff: 10 * time.Millisecond,
		MaxRetryBackoff:     50 * time.Millisecond,
		RetryJitter:         true,
		EnableWeb:           true,
		WebAddr:             ":8080",
		ShowDiags:           true,
		StartTLS:            true,
		ServiceName:         "testsvc",
		PrinterConfig: printers.PrinterConfig{
			NoColor:           true,
			OutputDBPath:      "test.db",
			OutputJSON:        true,
			PrettyJSON:        true,
			OutputCSVPath:     "test.csv",
			OutputTSVPath:     "test.tsv",
			WithTimestamp:     true,
			WithSourceAddress: true,
			WithDiags:         true,
			Target:            "127.0.0.1",
			Port:              8080,
		},
	}

	assert.True(t, cfg.ShowFailuresOnly)
	assert.True(t, cfg.ShowDashboard)
	assert.True(t, cfg.QuietMode)
	assert.True(t, cfg.ShowSparkline)
	assert.Equal(t, uint(3), cfg.Retries)
	assert.True(t, cfg.RetryJitter)
	assert.True(t, cfg.EnableWeb)
	assert.Equal(t, ":8080", cfg.WebAddr)
	assert.True(t, cfg.ShowDiags)
	assert.True(t, cfg.StartTLS)
	assert.Equal(t, "testsvc", cfg.ServiceName)
	assert.True(t, cfg.PrinterConfig.NoColor)
	assert.Equal(t, "test.db", cfg.PrinterConfig.OutputDBPath)
	assert.True(t, cfg.PrinterConfig.OutputJSON)
	assert.True(t, cfg.PrinterConfig.PrettyJSON)
	assert.Equal(t, "test.csv", cfg.PrinterConfig.OutputCSVPath)
	assert.Equal(t, "test.tsv", cfg.PrinterConfig.OutputTSVPath)
	assert.True(t, cfg.PrinterConfig.GetWithTimestamp())
	assert.True(t, cfg.PrinterConfig.GetWithSourceAddress())
	assert.True(t, cfg.PrinterConfig.GetWithDiags())
}

func TestParseConfig_SuccessScenarios(t *testing.T) {
	// Standard TCP probe with --host and --port
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg, err := ParseConfig(fs, []string{"--host", "127.0.0.1", "--port", "8080", "--count", "5", "--interval", "0.5", "--timeout", "2.0"})
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "127.0.0.1", cfg.Hostname)
	assert.Equal(t, uint16(8080), cfg.Port)
	assert.Equal(t, uint(5), cfg.ProbesBeforeQuit)
	assert.Equal(t, consts.TCP, cfg.Protocol)

	// HTTPS probe with output-format and output-file
	fs2 := flag.NewFlagSet("test2", flag.ContinueOnError)
	cfg2, err := ParseConfig(fs2, []string{"--host", "127.0.0.1", "--port", "443", "--protocol", "https", "--output-format", "pretty_json", "--output-file", "test.json"})
	assert.NoError(t, err)
	assert.NotNil(t, cfg2)
	assert.Equal(t, consts.HTTPS, cfg2.Protocol)
	assert.True(t, cfg2.PrinterConfig.OutputJSON)
	assert.True(t, cfg2.PrinterConfig.PrettyJSON)
	assert.Equal(t, "test.json", cfg2.PrinterConfig.OutputFile)
	assert.Equal(t, "pretty_json", cfg2.PrinterConfig.OutputFormat)

	// Multi-target probe with --uri
	fs3 := flag.NewFlagSet("test3", flag.ContinueOnError)
	cfg3, err := ParseConfig(fs3, []string{"--uri", "127.0.0.1:8080,127.0.0.1:8443"})
	assert.NoError(t, err)
	assert.NotNil(t, cfg3)
	assert.Equal(t, 2, len(cfg3.Targets))

	// DNS hosts flag
	fs4 := flag.NewFlagSet("test4", flag.ContinueOnError)
	cfg4, err := ParseConfig(fs4, []string{"--host", "127.0.0.1", "--port", "53", "--protocol", "dns", "--dns-host", "example.com, test.local"})
	assert.NoError(t, err)
	assert.NotNil(t, cfg4)
	assert.Equal(t, 2, len(cfg4.DNSHosts))
	assert.Equal(t, "example.com", cfg4.DNSHosts[0])
	assert.Equal(t, "test.local", cfg4.DNSHosts[1])

	// Advanced enterprise flags: send/expect, web, metrics, SLA latency, retries, jitter
	fs5 := flag.NewFlagSet("test5", flag.ContinueOnError)
	cfg5, err := ParseConfig(fs5, []string{
		"--host", "localhost",
		"--port", "8080",
		"--send", "PING",
		"--expect", "PONG",
		"--fast-close",
		"--resolve-every-probe",
		"--max-consecutive-fails", "3",
		"--max-latency", "150.5",
		"--metrics-addr", ":9090",
		"--quiet",
		"--sparkline",
		"--dashboard",
		"--traceroute",
		"--retry", "4",
		"--retry-backoff", "0.1",
		"--retry-max-backoff", "1.0",
		"--retry-jitter",
		"--web",
		"--web-addr", ":8081",
		"--diags",
		"--starttls",
		"--service", "XE",
		"--retry-resolve", "2",
		"--ipv4",
		"--no-color",
		"--timestamp",
		"--show-source-address",
		"--show-failures-only",
	})
	assert.NoError(t, err)
	assert.NotNil(t, cfg5)
	assert.Equal(t, "PING", cfg5.SendData)
	assert.Equal(t, "PONG", cfg5.ExpectData)
	assert.True(t, cfg5.FastClose)
	assert.True(t, cfg5.ResolveEveryProbe)
	assert.Equal(t, uint(3), cfg5.MaxConsecutiveFails)
	assert.Equal(t, 150.5, cfg5.MaxLatency)
	assert.Equal(t, ":9090", cfg5.MetricsAddr)
	assert.True(t, cfg5.QuietMode)
	assert.True(t, cfg5.ShowSparkline)
	assert.True(t, cfg5.ShowDashboard)
	assert.True(t, cfg5.TracerouteMode)
	assert.Equal(t, uint(4), cfg5.Retries)
	assert.True(t, cfg5.RetryJitter)
	assert.True(t, cfg5.EnableWeb)
	assert.Equal(t, ":8081", cfg5.WebAddr)
	assert.True(t, cfg5.ShowDiags)
	assert.True(t, cfg5.StartTLS)
	assert.Equal(t, "XE", cfg5.ServiceName)
	assert.True(t, cfg5.ShouldRetryResolve)
	assert.Equal(t, uint(2), cfg5.RetryResolveAfterNFailures)
	assert.True(t, cfg5.UseIPv4)
	assert.True(t, cfg5.ShowFailuresOnly)
	assert.True(t, cfg5.PrinterConfig.NoColor)
	assert.True(t, cfg5.PrinterConfig.WithTimestamp)
	assert.True(t, cfg5.PrinterConfig.WithSourceAddress)
}

func TestParseConfig_FailureScenarios(t *testing.T) {
	// IPv4 and IPv6 conflict
	fs1 := flag.NewFlagSet("err1", flag.ContinueOnError)
	_, err := ParseConfig(fs1, []string{"--ipv4", "--ipv6", "--host", "127.0.0.1", "--port", "80"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only one IP version")

	// Missing target host/port/uri
	fs2 := flag.NewFlagSet("err2", flag.ContinueOnError)
	_, err = ParseConfig(fs2, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--host, --port, or --uri")

	// Invalid port
	fs3 := flag.NewFlagSet("err3", flag.ContinueOnError)
	_, err = ParseConfig(fs3, []string{"--host", "127.0.0.1", "--port", "99999"})
	assert.Error(t, err)

	// Interval < 2ms
	fs4 := flag.NewFlagSet("err4", flag.ContinueOnError)
	_, err = ParseConfig(fs4, []string{"--host", "127.0.0.1", "--port", "80", "--interval", "0.0001"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "more than 2 ms")
}

func TestConfig_FullFieldGetters(t *testing.T) {
	fs := flag.NewFlagSet("getters", flag.ContinueOnError)
	cfg, err := ParseConfig(fs, []string{
		"--host", "example.com",
		"--port", "443",
		"--protocol", "https",
		"--count", "10",
		"--timeout", "2.0",
		"--interval", "0.5",
		"--timestamp",
		"--show-source-address",
		"--retry-resolve", "3",
		"--show-failures-only",
		"--ipv4",
	})
	assert.NoError(t, err)

	assert.Equal(t, "example.com", cfg.GetHostname())
	assert.Equal(t, uint16(443), cfg.GetPort())
	assert.Equal(t, consts.HTTPS, cfg.GetProtocol())
	assert.True(t, cfg.GetUseIPv4())
	assert.False(t, cfg.GetUseIPv6())
	assert.Equal(t, "2s", cfg.GetTimeout())
	assert.Equal(t, uint(10), cfg.GetProbesBeforeQuit())
	assert.Equal(t, "500ms", cfg.GetIntervalBetweenProbes())
	assert.True(t, cfg.GetShowFailuresOnly())
	assert.True(t, cfg.GetShouldRetryResolve())
	assert.Equal(t, uint(3), cfg.GetRetryResolveAfterNFailures())
	assert.True(t, cfg.GetWithTimestamp())
	assert.True(t, cfg.GetWithSourceAddress())
	assert.NotNil(t, cfg.GetNetworkInterface())
	assert.Equal(t, cfg.PrinterConfig, cfg.GetPrinterConfig())
}

func TestParseConfig_MultiTarget_URIs(t *testing.T) {
	fs := flag.NewFlagSet("uris", flag.ContinueOnError)
	cfg, err := ParseConfig(fs, []string{
		"--uri", "https://1.1.1.1:443,dns://8.8.8.8:53,9.9.9.9:53",
		"--concurrency", "8",
		"--history-limit", "500000",
		"--diagnostics",
	})
	assert.NoError(t, err)

	assert.Equal(t, 3, len(cfg.Targets))
	assert.Equal(t, uint(8), cfg.Concurrency)
	assert.Equal(t, uint(500000), cfg.HistoryLimit)
	assert.True(t, cfg.ShowDiags)
}

func TestParseConfig_GenerateAPIKeyFlag(t *testing.T) {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	cfg, err := ParseConfig(fs, []string{
		"--generate-api-key", "/tmp/keys.json",
	})
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/keys.json", cfg.GenerateAPIKeyPath)
}

func TestParseConfig_TriggerModeFlags(t *testing.T) {
	fs := flag.NewFlagSet("trigger", flag.ContinueOnError)
	cfg, err := ParseConfig(fs, []string{
		"--trigger-mode",
		"--listen", ":3000",
		"--api-key-store", "C:/keys/keystore.json",
		"--trigger-concurrency", "250",
	})
	assert.NoError(t, err)
	assert.True(t, cfg.TriggerMode)
	assert.Equal(t, ":3000", cfg.WebAddr)
	assert.Equal(t, "C:/keys/keystore.json", cfg.APIKeyStore)
	assert.Equal(t, 250, cfg.TriggerConcurrency)
	assert.Empty(t, cfg.Targets)
}
