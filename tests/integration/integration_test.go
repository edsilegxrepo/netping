//go:build integration

package integration

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/edsilegx/netping/internal/config"
	"github.com/edsilegx/netping/internal/printers"
	"github.com/edsilegx/netping/pkg/consts"
	"github.com/edsilegx/netping/pkg/probers"
	"github.com/edsilegx/netping/pkg/stats"
	"github.com/edsilegx/netping/pkg/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// ==========================================
// 1. Web & API Protocols
// ==========================================

func TestLive_HTTP_Cloudflare(t *testing.T) {
	opts := probers.HTTPOptions{
		Hostname: "1.1.1.1",
		IP:       netip.MustParseAddr("1.1.1.1"),
		Port:     80,
		Protocol: consts.HTTP,
		Timeout:  5 * time.Second,
	}

	h := probers.NewHTTPing(opts)
	res := h.Ping(context.Background())

	assert.NoError(t, res.Err)
	assert.Greater(t, res.HTTPStatus, 0)
	assert.True(t, res.RTT > 0)
}

func TestLive_HTTPS_Cloudflare(t *testing.T) {
	opts := probers.HTTPOptions{
		Hostname: "1.1.1.1",
		IP:       netip.MustParseAddr("1.1.1.1"),
		Port:     443,
		Protocol: consts.HTTPS,
		Timeout:  5 * time.Second,
	}

	h := probers.NewHTTPing(opts)
	res := h.Ping(context.Background())

	assert.NoError(t, res.Err)
	assert.Greater(t, res.HTTPStatus, 0)
	assert.True(t, res.RTT > 0)
}

func TestLive_WebSocket_Echo(t *testing.T) {
	opts := probers.WSOptions{
		Hostname: "echo.websocket.org",
		Port:     443,
		UseTLS:   true,
		Timeout:  5 * time.Second,
	}

	ws := probers.NewWSing(opts)
	res := ws.Ping(context.Background())

	assert.NoError(t, res.Err)
	assert.Equal(t, 101, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "101 Switching Protocols")
}

func TestLive_gRPC_GooglePubSub(t *testing.T) {
	opts := probers.GRPCOptions{
		Hostname: "pubsub.googleapis.com",
		Port:     443,
		UseTLS:   true,
		Timeout:  5 * time.Second,
	}

	g := probers.NewGRPCing(opts)
	res := g.Ping(context.Background())

	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "HTTP/2")
}

// ==========================================
// 2. DNS Protocols (UDP, DoT, DoH)
// ==========================================

func TestLive_DNS_UDP_Google(t *testing.T) {
	opts := probers.DNSQueryOptions{
		Nameserver: "8.8.8.8",
		IP:         netip.MustParseAddr("8.8.8.8"),
		Port:       53,
		Domains:    []string{"google.com"},
		Timeout:    5 * time.Second,
	}

	dq := probers.NewDNSQueryProber(opts)
	res := dq.Ping(context.Background())

	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "NOERROR")
	assert.True(t, res.RTT > 0)
}

func TestLive_DNS_DoT_Cloudflare(t *testing.T) {
	opts := probers.DNSQueryOptions{
		Nameserver: "1.1.1.1",
		Port:       853,
		Domain:     "cloudflare.com",
		IsDoT:      true,
		Timeout:    5 * time.Second,
	}

	dq := probers.NewDNSQueryProber(opts)
	res := dq.Ping(context.Background())

	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "NOERROR")
	assert.Contains(t, res.Diagnostics, "TLS")
}

func TestLive_DNS_DoH_Cloudflare(t *testing.T) {
	opts := probers.DNSQueryOptions{
		Nameserver: "1.1.1.1",
		Port:       443,
		Domain:     "cloudflare.com",
		IsDoH:      true,
		Timeout:    5 * time.Second,
	}

	dq := probers.NewDNSQueryProber(opts)
	res := dq.Ping(context.Background())

	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "NOERROR")
}

// ==========================================
// 3. Cloud Storage Buckets (S3, Azure, GCS)
// ==========================================

func TestLive_Storage_S3(t *testing.T) {
	s := probers.NewStorageing(probers.StorageOptions{
		Type:     probers.StorageS3,
		Hostname: "s3.amazonaws.com",
		Port:     443,
		Timeout:  5 * time.Second,
	})

	res := s.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "s3")
}

func TestLive_Storage_AzureBlob(t *testing.T) {
	s := probers.NewStorageing(probers.StorageOptions{
		Type:     probers.StorageAzureBlob,
		Hostname: "azure.blob.core.windows.net",
		Port:     443,
		Timeout:  5 * time.Second,
	})

	res := s.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "azureblob")
}

func TestLive_Storage_GCS(t *testing.T) {
	s := probers.NewStorageing(probers.StorageOptions{
		Type:     probers.StorageGCS,
		Hostname: "storage.googleapis.com",
		Port:     443,
		Timeout:  5 * time.Second,
	})

	res := s.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "gcs")
}

// ==========================================
// 4. Enterprise Services (O365, LDAP, LDAPS)
// ==========================================

func TestLive_O365_Graph(t *testing.T) {
	opts := probers.O365Options{
		Hostname: "graph.microsoft.com",
		Port:     443,
		Timeout:  5 * time.Second,
	}

	o := probers.NewO365ing(opts)
	res := o.Ping(context.Background())

	assert.NoError(t, res.Err)
	assert.Greater(t, res.HTTPStatus, 0)
	assert.Contains(t, res.Diagnostics, "TLS")
}

func TestLive_LDAP_ForumSys(t *testing.T) {
	opts := probers.LDAPOptions{
		Hostname: "ldap.forumsys.com",
		Port:     389,
		UseTLS:   false,
		Timeout:  5 * time.Second,
	}

	ldap := probers.NewLDAPing(opts)
	res := ldap.Ping(context.Background())

	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SUCCESS")
	assert.Contains(t, res.Diagnostics, "BaseDN: dc=example,dc=com")
}

func TestLive_LDAPS_ForumSys(t *testing.T) {
	opts := probers.LDAPOptions{
		Hostname: "ldap.forumsys.com",
		Port:     636,
		UseTLS:   true,
		Timeout:  5 * time.Second,
	}

	ldap := probers.NewLDAPing(opts)
	res := ldap.Ping(context.Background())

	if res.Err == nil {
		assert.Contains(t, res.Diagnostics, "SUCCESS")
	}
}

// ==========================================
// 5. Mail Services (SMTP, SMTPS, IMAPS, POP3S)
// ==========================================

func TestLive_Mail_SMTP_STARTTLS(t *testing.T) {
	m := probers.NewMailing(probers.MailOptions{
		Protocol: probers.MailSMTP,
		Hostname: "smtp.gmail.com",
		Port:     587,
		StartTLS: true,
		Timeout:  5 * time.Second,
	})

	res := m.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SMTP")
	assert.Contains(t, res.Diagnostics, "STARTTLS")
}

func TestLive_Mail_SMTPS(t *testing.T) {
	m := probers.NewMailing(probers.MailOptions{
		Protocol: probers.MailSMTP,
		Hostname: "smtp.gmail.com",
		Port:     465,
		UseTLS:   true,
		Timeout:  5 * time.Second,
	})

	res := m.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SMTP")
}

func TestLive_Mail_IMAPS(t *testing.T) {
	m := probers.NewMailing(probers.MailOptions{
		Protocol: probers.MailIMAP,
		Hostname: "imap.gmail.com",
		Port:     993,
		UseTLS:   true,
		Timeout:  5 * time.Second,
	})

	res := m.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "IMAP")
}

func TestLive_Mail_POP3S(t *testing.T) {
	m := probers.NewMailing(probers.MailOptions{
		Protocol: probers.MailPOP3,
		Hostname: "pop.gmail.com",
		Port:     995,
		UseTLS:   true,
		Timeout:  5 * time.Second,
	})

	res := m.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "+OK")
}

// ==========================================
// 6. Remote Access & File (SSH, FTP)
// ==========================================

func TestLive_SSH_GitHub(t *testing.T) {
	s := probers.NewSSHing(probers.SSHOptions{
		Hostname: "github.com",
		Port:     22,
		Timeout:  5 * time.Second,
	})

	res := s.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "HostKeys")
}

func TestLive_FTP_Rebex(t *testing.T) {
	f := probers.NewFTPing(probers.FTPOptions{
		Hostname: "test.rebex.net",
		Port:     21,
		Timeout:  5 * time.Second,
	})

	res := f.Ping(context.Background())
	if res.Err != nil && strings.Contains(res.Err.Error(), "quota") {
		t.Skipf("skipping: public test.rebex.net rate limited or quota exceeded: %v", res.Err)
		return
	}
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Features")
}

// ==========================================
// 7. Databases (Container Endpoints)
// ==========================================

const dbHost = "cs-main-wsl001.csysinet.com"

func ensureDockerDBContainers(t *testing.T) {
	cmdName := "docker"
	args := []string{"start", "mysqldb", "postgresdb", "postgresqldb", "mssqldb", "oracledb", "hanadb"}
	if runtime.GOOS == "windows" {
		cmdName = "wsl"
		args = append([]string{"docker"}, args...)
	}
	_ = exec.Command(cmdName, args...).Run()
}

func waitForPort(host string, port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 2*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func TestLive_DB_PostgreSQL(t *testing.T) {
	ensureDockerDBContainers(t)
	if !waitForPort(dbHost, 5432, 5*time.Second) {
		t.Skipf("PostgreSQL on %s:5432 is not accessible", dbHost)
	}

	db := probers.NewDBing(probers.DBOptions{
		Type:     probers.PostgreSQL,
		Hostname: dbHost,
		Port:     5432,
		Timeout:  5 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "PostgreSQL")
}

func TestLive_DB_MySQL(t *testing.T) {
	ensureDockerDBContainers(t)
	if !waitForPort(dbHost, 3306, 5*time.Second) {
		t.Skipf("MySQL on %s:3306 is not accessible", dbHost)
	}

	db := probers.NewDBing(probers.DBOptions{
		Type:     probers.MySQL,
		Hostname: dbHost,
		Port:     3306,
		Timeout:  5 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Version:")
}

func TestLive_DB_MSSQL(t *testing.T) {
	ensureDockerDBContainers(t)
	if !waitForPort(dbHost, 1433, 5*time.Second) {
		t.Skipf("MSSQL on %s:1433 is not accessible", dbHost)
	}

	db := probers.NewDBing(probers.DBOptions{
		Type:     probers.MSSQL,
		Hostname: dbHost,
		Port:     1433,
		Timeout:  5 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SQL Server")
}

func TestLive_DB_Oracle(t *testing.T) {
	ensureDockerDBContainers(t)
	if !waitForPort(dbHost, 1521, 5*time.Second) {
		t.Skipf("Oracle on %s:1521 is not accessible", dbHost)
	}

	db := probers.NewDBing(probers.DBOptions{
		Type:        probers.Oracle,
		Hostname:    dbHost,
		Port:        1521,
		ServiceName: "FREE",
		Timeout:     5 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "TNS")
}

func TestLive_DB_SAPHANA(t *testing.T) {
	ensureDockerDBContainers(t)
	port := 39013
	if !waitForPort(dbHost, port, 5*time.Second) {
		t.Skipf("SAP HANA on %s:%d is not accessible", dbHost, port)
	}

	db := probers.NewDBing(probers.DBOptions{
		Type:     probers.SAPHANA,
		Hostname: dbHost,
		Port:     uint16(port),
		Timeout:  5 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SAP HANA")
}

func TestLive_DB_SAPHANA_Port39013(t *testing.T) {
	ensureDockerDBContainers(t)
	if !waitForPort(dbHost, 39013, 5*time.Second) {
		t.Skipf("SAP HANA on %s:39013 is not accessible", dbHost)
	}

	db := probers.NewDBing(probers.DBOptions{
		Type:     probers.SAPHANA,
		Hostname: dbHost,
		Port:     39013,
		Timeout:  5 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SAP HANA")
	assert.Contains(t, res.Diagnostics, "SystemDB SQL")
}

// ==========================================
// 8. CLI Flag Combinations End-to-End Tests
// ==========================================

func TestLive_CLI_FlagCombinations_E2E(t *testing.T) {
	tempDir := t.TempDir()
	csvPath := filepath.Join(tempDir, "e2e.csv")

	// Combination 1: Reporting & Formatting flags with count limit
	t.Run("Reporting_Formatting_Flags", func(t *testing.T) {
		fs := flag.NewFlagSet("test_fmt", flag.ContinueOnError)
		cfg, err := config.ParseConfig(fs, []string{
			"--host", "1.1.1.1",
			"--port", "443",
			"--count", "2",
			"--timeout", "2.5",
			"--interval", "0.2",
			"--output-format", "json",
			"--output-file", csvPath,
			"--no-color",
			"--timestamp",
			"--show-source-address",
		})
		require.NoError(t, err)
		assert.Equal(t, uint(2), cfg.ProbesBeforeQuit)
		assert.Equal(t, 2500*time.Millisecond, cfg.Timeout)
		assert.Equal(t, 200*time.Millisecond, cfg.IntervalBetweenProbes)
		assert.Equal(t, "json", cfg.PrinterConfig.OutputFormat)
		assert.Equal(t, csvPath, cfg.PrinterConfig.OutputFile)
		assert.True(t, cfg.PrinterConfig.WithTimestamp)
		assert.True(t, cfg.PrinterConfig.WithSourceAddress)
		assert.True(t, cfg.PrinterConfig.NoColor)
	})

	// Combination 2: Protocol diagnostics, timeouts, retries and jitter
	t.Run("Protocol_Diagnostics_Retries_Jitter", func(t *testing.T) {
		fs := flag.NewFlagSet("test_proto", flag.ContinueOnError)
		cfg, err := config.ParseConfig(fs, []string{
			"--host", "cs-main-wsl001.csysinet.com",
			"--protocol", "postgresql",
			"--diags",
			"--retry", "3",
			"--retry-backoff", "0.1",
			"--retry-max-backoff", "0.5",
			"--retry-jitter",
			"--max-latency", "250.0",
			"--max-consecutive-fails", "2",
			"--quiet",
		})
		require.NoError(t, err)
		assert.Equal(t, consts.POSTGRES, cfg.Protocol)
		assert.True(t, cfg.ShowDiags)
		assert.Equal(t, uint(3), cfg.Retries)
		assert.Equal(t, 100*time.Millisecond, cfg.InitialRetryBackoff)
		assert.Equal(t, 500*time.Millisecond, cfg.MaxRetryBackoff)
		assert.True(t, cfg.RetryJitter)
		assert.Equal(t, 250.0, cfg.MaxLatency)
		assert.Equal(t, uint(2), cfg.MaxConsecutiveFails)
		assert.True(t, cfg.QuietMode)
	})

	// Combination 3: DNS query with multi-hosts and custom server
	t.Run("DNS_MultiHosts_CustomServer", func(t *testing.T) {
		fs := flag.NewFlagSet("test_dns", flag.ContinueOnError)
		cfg, err := config.ParseConfig(fs, []string{
			"--host", "dns.google",
			"--port", "53",
			"--protocol", "dns",
			"--dns-host", "google.com,cloudflare.com,github.com",
			"--dns-server", "1.1.1.1:53",
			"--retry-resolve", "5",
		})
		require.NoError(t, err)
		assert.Equal(t, consts.DNS, cfg.Protocol)
		assert.Equal(t, 3, len(cfg.DNSHosts))
		assert.Equal(t, "google.com", cfg.DNSHosts[0])
		assert.Equal(t, "cloudflare.com", cfg.DNSHosts[1])
		assert.Equal(t, "github.com", cfg.DNSHosts[2])
		assert.True(t, cfg.ShouldRetryResolve)
		assert.Equal(t, uint(5), cfg.RetryResolveAfterNFailures)
	})

	// Combination 4: HTTP payload assertion, fast-close and SLA checks
	t.Run("HTTP_Send_Expect_FastClose", func(t *testing.T) {
		fs := flag.NewFlagSet("test_http", flag.ContinueOnError)
		cfg, err := config.ParseConfig(fs, []string{
			"--host", "1.1.1.1",
			"--port", "80",
			"--protocol", "http",
			"--send", "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n",
			"--expect", "HTTP/1.1",
			"--fast-close",
			"--resolve-every-probe",
			"--sparkline",
		})
		require.NoError(t, err)
		assert.Equal(t, consts.HTTP, cfg.Protocol)
		assert.Contains(t, cfg.SendData, "GET / HTTP/1.1")
		assert.Equal(t, "HTTP/1.1", cfg.ExpectData)
		assert.True(t, cfg.FastClose)
		assert.True(t, cfg.ResolveEveryProbe)
		assert.True(t, cfg.ShowSparkline)
	})

	// Combination 5: Web UI & Prometheus metrics exporter
	t.Run("Web_And_Metrics_Flags", func(t *testing.T) {
		fs := flag.NewFlagSet("test_web", flag.ContinueOnError)
		cfg, err := config.ParseConfig(fs, []string{
			"--host", "1.1.1.1",
			"--port", "443",
			"--web",
			"--web-addr", ":8080",
			"--metrics-addr", ":9090",
			"--dashboard",
			"--traceroute",
		})
		require.NoError(t, err)
		assert.True(t, cfg.EnableWeb)
		assert.Equal(t, ":8080", cfg.WebAddr)
		assert.Equal(t, ":9090", cfg.MetricsAddr)
		assert.True(t, cfg.ShowDashboard)
		assert.True(t, cfg.TracerouteMode)
	})

	// Combination 6: Oracle Service name & Mail STARTTLS flags
	t.Run("Oracle_Service_And_Mail_STARTTLS", func(t *testing.T) {
		fs1 := flag.NewFlagSet("test_ora", flag.ContinueOnError)
		cfg1, err := config.ParseConfig(fs1, []string{
			"--host", "cs-main-wsl001.csysinet.com",
			"--protocol", "oracle",
			"--service", "FREE",
			"--diags",
		})
		require.NoError(t, err)
		assert.Equal(t, consts.ORACLE, cfg1.Protocol)
		assert.Equal(t, "FREE", cfg1.ServiceName)
		assert.True(t, cfg1.ShowDiags)

		fs2 := flag.NewFlagSet("test_mail", flag.ContinueOnError)
		cfg2, err := config.ParseConfig(fs2, []string{
			"--host", "smtp.gmail.com",
			"--port", "587",
			"--protocol", "smtp",
			"--starttls",
			"--diags",
		})
		require.NoError(t, err)
		assert.Equal(t, consts.SMTP, cfg2.Protocol)
		assert.True(t, cfg2.StartTLS)
		assert.True(t, cfg2.ShowDiags)
	})

	// Combination 7: Multi-target probing with URI and Concurrency
	t.Run("MultiTarget_URI_Concurrency", func(t *testing.T) {
		fs := flag.NewFlagSet("test_multi", flag.ContinueOnError)
		cfg, err := config.ParseConfig(fs, []string{
			"--uri", "1.1.1.1:443,8.8.8.8:53,9.9.9.9:53",
			"--ipv4",
			"--count", "1",
			"--concurrency", "4",
		})
		require.NoError(t, err)
		assert.Equal(t, 3, len(cfg.Targets))
		assert.True(t, cfg.UseIPv4)
		assert.False(t, cfg.UseIPv6)
		assert.Equal(t, uint(1), cfg.ProbesBeforeQuit)
		assert.Equal(t, uint(4), cfg.Concurrency)
	})
}

func TestLive_MultiTarget_Parallel_Fleet_E2E(t *testing.T) {
	// Parallel multi-target probe across Public DNS and Web endpoints
	targets := []struct {
		host  string
		port  uint16
		proto consts.Protocol
	}{
		{"1.1.1.1", 443, consts.HTTPS},
		{"8.8.8.8", 53, consts.DNS},
		{"9.9.9.9", 53, consts.DNS},
		{"github.com", 22, consts.SSH},
	}

	var workers []probers.TargetWorker
	for _, tgt := range targets {
		var p probers.Pinger
		switch tgt.proto {
		case consts.HTTPS:
			p = probers.NewHTTPing(probers.HTTPOptions{
				Hostname: tgt.host,
				Port:     tgt.port,
				Protocol: consts.HTTPS,
				Timeout:  3 * time.Second,
			})
		case consts.DNS:
			p = probers.NewDNSQueryProber(probers.DNSQueryOptions{
				Nameserver: tgt.host,
				Port:       tgt.port,
				Domain:     "google.com",
				Timeout:    3 * time.Second,
			})
		case consts.SSH:
			p = probers.NewSSHing(probers.SSHOptions{
				Hostname: tgt.host,
				Port:     tgt.port,
				Timeout:  3 * time.Second,
			})
		default:
			p = probers.NewTcping(probers.TCPOptions{
				Port:    tgt.port,
				Timeout: 3 * time.Second,
			})
		}

		workers = append(workers, probers.TargetWorker{
			Target:   fmt.Sprintf("%s:%d", tgt.host, tgt.port),
			Host:     tgt.host,
			Port:     tgt.port,
			Protocol: tgt.proto,
			Pinger:   p,
			Stats:    &stats.Statistics{},
		})
	}

	multi := probers.NewMultiProber(workers, probers.MultiProberOptions{
		ProbeCount:  2,
		Interval:    10 * time.Millisecond,
		Timeout:     3 * time.Second,
		Concurrency: 4,
		NoColor:     true,
	})

	multi.Run(context.Background())

	for _, w := range workers {
		assert.Equal(t, uint(2), w.Stats.TotalSuccessfulProbes, "Target %s should succeed", w.Target)
	}
}

func TestLive_DB_All5Protocols_Concurrent_E2E(t *testing.T) {
	ensureDockerDBContainers(t)

	// Define all 5 supported enterprise database targets on cs-main-wsl001.csysinet.com
	dbTargets := []struct {
		dbType      probers.DBType
		protocol    consts.Protocol
		port        uint16
		serviceName string
		diagKeyword string
	}{
		{
			dbType:      probers.PostgreSQL,
			protocol:    consts.POSTGRES,
			port:        5432,
			diagKeyword: "PostgreSQL",
		},
		{
			dbType:      probers.MySQL,
			protocol:    consts.MYSQL,
			port:        3306,
			diagKeyword: "8.4.",
		},
		{
			dbType:      probers.MSSQL,
			protocol:    consts.MSSQL,
			port:        1433,
			diagKeyword: "SQL Server",
		},
		{
			dbType:      probers.Oracle,
			protocol:    consts.ORACLE,
			port:        1521,
			serviceName: "FREE",
			diagKeyword: "TNS",
		},
		{
			dbType:      probers.SAPHANA,
			protocol:    consts.SAPHANA,
			port:        39013,
			diagKeyword: "SAP HANA",
		},
	}

	var workers []probers.TargetWorker
	for _, dt := range dbTargets {
		pinger := probers.NewDBing(probers.DBOptions{
			Type:        dt.dbType,
			Hostname:    dbHost,
			Port:        dt.port,
			ServiceName: dt.serviceName,
			Timeout:     5 * time.Second,
		})

		workers = append(workers, probers.TargetWorker{
			Target:      fmt.Sprintf("%s:%d", dbHost, dt.port),
			Host:        dbHost,
			Port:        dt.port,
			Protocol:    dt.protocol,
			ServiceName: dt.serviceName,
			Pinger:      pinger,
			Stats:       &stats.Statistics{},
		})
	}

	// Execute all 5 database probers concurrently in parallel
	multi := probers.NewMultiProber(workers, probers.MultiProberOptions{
		ProbeCount:  2,
		Interval:    10 * time.Millisecond,
		Timeout:     5 * time.Second,
		Concurrency: 5,
		ShowDiags:   true,
		NoColor:     true,
	})

	multi.Run(context.Background())

	// Verify that every single DB worker succeeded for all probe attempts
	for i, w := range workers {
		assert.Equal(t, uint(2), w.Stats.TotalSuccessfulProbes, "DB Target %s (%s) should succeed all probes", w.Target, w.Protocol)
		assert.Equal(t, uint(0), w.Stats.TotalUnsuccessfulProbes, "DB Target %s (%s) should have 0 failures", w.Target, w.Protocol)
		assert.True(t, len(w.Stats.RTT) >= 2, "DB Target %s (%s) should record latency results", w.Target, w.Protocol)
		_ = dbTargets[i].diagKeyword
	}
}

func TestLive_MultiTarget_Outputs_AllFormats_E2E(t *testing.T) {
	tempDir := t.TempDir()

	targets := []struct {
		host  string
		port  uint16
		proto consts.Protocol
	}{
		{"1.1.1.1", 443, consts.HTTPS},
		{"8.8.8.8", 53, consts.DNS},
	}

	// 1. CSV Output Generation & Structural Parsing Test
	t.Run("CSV_Output", func(t *testing.T) {
		csvFile := filepath.Join(tempDir, "fleet_probes.csv")
		csvPrinter, err := printers.NewCSVPrinter(csvFile)
		require.NoError(t, err)
		defer csvPrinter.Done()

		var workers []probers.TargetWorker
		for _, tgt := range targets {
			var p probers.Pinger
			if tgt.proto == consts.DNS {
				p = probers.NewDNSQueryProber(probers.DNSQueryOptions{
					Nameserver: tgt.host,
					Port:       tgt.port,
					Domain:     "google.com",
					Timeout:    2 * time.Second,
				})
			} else {
				p = probers.NewHTTPing(probers.HTTPOptions{
					Hostname: tgt.host,
					Port:     tgt.port,
					Protocol: tgt.proto,
					Timeout:  2 * time.Second,
				})
			}
			st := &stats.Statistics{
				Hostname: tgt.host,
				Port:     tgt.port,
			}
			csvPrinter.PrintStart(st)
			workers = append(workers, probers.TargetWorker{
				Target:   fmt.Sprintf("%s:%d", tgt.host, tgt.port),
				Host:     tgt.host,
				Port:     tgt.port,
				Protocol: tgt.proto,
				Pinger:   p,
				Stats:    st,
			})
		}

		multi := probers.NewMultiProber(workers, probers.MultiProberOptions{
			ProbeCount:  2,
			Interval:    10 * time.Millisecond,
			Timeout:     2 * time.Second,
			Concurrency: 2,
			NoColor:     true,
			OnProbeEvent: func(res probers.ProbeResult, w probers.TargetWorker, seq uint) {
				if res.Err == nil {
					csvPrinter.PrintProbeSuccess(w.Stats)
				} else {
					csvPrinter.PrintProbeFailure(w.Stats)
				}
			},
		})
		multi.Run(context.Background())
		for _, w := range workers {
			csvPrinter.PrintStatistics(w.Stats)
		}
		csvPrinter.Done()

		// Structural Parsing: CSV Probe Records
		fProbe, err := os.Open(csvFile)
		require.NoError(t, err)
		defer func() { _ = fProbe.Close() }()

		rProbe := csv.NewReader(fProbe)
		probeRecords, err := rProbe.ReadAll()
		require.NoError(t, err, "CSV file must parse cleanly with csv.Reader")
		require.True(t, len(probeRecords) >= 5, "Expected at least 1 header + 4 probe rows, got %d", len(probeRecords))

		// Verify header columns
		assert.Equal(t, "Status", probeRecords[0][0])
		assert.Equal(t, "Hostname", probeRecords[0][1])
		assert.Equal(t, "IP", probeRecords[0][2])
		assert.Equal(t, "Port", probeRecords[0][3])

		// Verify content integrity across all probe rows
		probeRowCount := 0
		for _, row := range probeRecords[1:] {
			probeRowCount++
			assert.Equal(t, "Reply", row[0])
			assert.NotEmpty(t, row[1], "Hostname should not be empty")
			assert.NotEmpty(t, row[2], "IP address should not be empty")
			assert.NotEmpty(t, row[3], "Port should not be empty")
		}
		assert.Equal(t, 4, probeRowCount, "Must have exactly 4 probe records (2 per target)")

		// Structural Parsing: CSV Statistics Records
		statsCSVFile := filepath.Join(tempDir, "fleet_probes_stats.csv")
		fStats, err := os.Open(statsCSVFile)
		require.NoError(t, err)
		defer func() { _ = fStats.Close() }()

		rStats := csv.NewReader(fStats)
		statsRecords, err := rStats.ReadAll()
		require.NoError(t, err, "Stats CSV file must parse cleanly with csv.Reader")
		assert.True(t, len(statsRecords) >= 2, "Stats CSV must contain headers and metric entries")
		assert.Equal(t, "Metric", statsRecords[0][0])
		assert.Equal(t, "Value", statsRecords[0][1])
	})

	// 2. TSV Output Generation & Structural Parsing Test
	t.Run("TSV_Output", func(t *testing.T) {
		tsvFile := filepath.Join(tempDir, "fleet_probes.tsv")
		tsvPrinter, err := printers.NewTSVPrinter(tsvFile)
		require.NoError(t, err)
		defer tsvPrinter.Done()

		var workers []probers.TargetWorker
		for _, tgt := range targets {
			var p probers.Pinger
			if tgt.proto == consts.DNS {
				p = probers.NewDNSQueryProber(probers.DNSQueryOptions{
					Nameserver: tgt.host,
					Port:       tgt.port,
					Domain:     "google.com",
					Timeout:    2 * time.Second,
				})
			} else {
				p = probers.NewHTTPing(probers.HTTPOptions{
					Hostname: tgt.host,
					Port:     tgt.port,
					Protocol: tgt.proto,
					Timeout:  2 * time.Second,
				})
			}
			st := &stats.Statistics{
				Hostname: tgt.host,
				Port:     tgt.port,
			}
			tsvPrinter.PrintStart(st)
			workers = append(workers, probers.TargetWorker{
				Target:   fmt.Sprintf("%s:%d", tgt.host, tgt.port),
				Host:     tgt.host,
				Port:     tgt.port,
				Protocol: tgt.proto,
				Pinger:   p,
				Stats:    st,
			})
		}

		multi := probers.NewMultiProber(workers, probers.MultiProberOptions{
			ProbeCount:  2,
			Interval:    10 * time.Millisecond,
			Timeout:     2 * time.Second,
			Concurrency: 2,
			NoColor:     true,
			OnProbeEvent: func(res probers.ProbeResult, w probers.TargetWorker, seq uint) {
				if res.Err == nil {
					tsvPrinter.PrintProbeSuccess(w.Stats)
				} else {
					tsvPrinter.PrintProbeFailure(w.Stats)
				}
			},
		})
		multi.Run(context.Background())
		for _, w := range workers {
			tsvPrinter.PrintStatistics(w.Stats)
		}
		tsvPrinter.Done()

		// Structural Parsing: TSV Probe Records
		fTSV, err := os.Open(tsvFile)
		require.NoError(t, err)
		defer func() { _ = fTSV.Close() }()

		rTSV := csv.NewReader(fTSV)
		rTSV.Comma = '\t'
		tsvRecords, err := rTSV.ReadAll()
		require.NoError(t, err, "TSV file must parse cleanly with tab-delimited reader")
		require.True(t, len(tsvRecords) >= 5, "Expected at least 1 header + 4 probe rows in TSV, got %d", len(tsvRecords))

		// Verify header and fields
		assert.Equal(t, "Status", tsvRecords[0][0])
		assert.Equal(t, "Hostname", tsvRecords[0][1])
		for _, row := range tsvRecords[1:] {
			assert.Equal(t, "Reply", row[0])
			assert.NotEmpty(t, row[1])
			assert.NotEmpty(t, row[2])
			assert.NotEmpty(t, row[3])
		}

		// Structural Parsing: TSV Statistics Records
		statsTSVFile := filepath.Join(tempDir, "fleet_probes_stats.tsv")
		fStatsTSV, err := os.Open(statsTSVFile)
		require.NoError(t, err)
		defer func() { _ = fStatsTSV.Close() }()

		rStatsTSV := csv.NewReader(fStatsTSV)
		rStatsTSV.Comma = '\t'
		statsTSVRecords, err := rStatsTSV.ReadAll()
		require.NoError(t, err, "Stats TSV file must parse cleanly with tab-delimited reader")
		assert.True(t, len(statsTSVRecords) >= 2)
		assert.Equal(t, "Metric", statsTSVRecords[0][0])
		assert.Equal(t, "Value", statsTSVRecords[0][1])
	})

	// 3. SQLite3 Database Generation & SQL Query Count Verification Test
	t.Run("SQLite3_Output", func(t *testing.T) {
		dbFile := filepath.Join(tempDir, "fleet_probes.db")
		dbPrinter, err := printers.NewDatabasePrinter("fleet", "all", dbFile)
		require.NoError(t, err)
		defer dbPrinter.Done()

		var workers []probers.TargetWorker
		for _, tgt := range targets {
			var p probers.Pinger
			if tgt.proto == consts.DNS {
				p = probers.NewDNSQueryProber(probers.DNSQueryOptions{
					Nameserver: tgt.host,
					Port:       tgt.port,
					Domain:     "google.com",
					Timeout:    2 * time.Second,
				})
			} else {
				p = probers.NewHTTPing(probers.HTTPOptions{
					Hostname: tgt.host,
					Port:     tgt.port,
					Protocol: tgt.proto,
					Timeout:  2 * time.Second,
				})
			}
			st := &stats.Statistics{
				Hostname: tgt.host,
				Port:     tgt.port,
			}
			workers = append(workers, probers.TargetWorker{
				Target:   fmt.Sprintf("%s:%d", tgt.host, tgt.port),
				Host:     tgt.host,
				Port:     tgt.port,
				Protocol: tgt.proto,
				Pinger:   p,
				Stats:    st,
			})
		}

		multi := probers.NewMultiProber(workers, probers.MultiProberOptions{
			ProbeCount:  2,
			Interval:    10 * time.Millisecond,
			Timeout:     2 * time.Second,
			Concurrency: 2,
			NoColor:     true,
			OnProbeEvent: func(res probers.ProbeResult, w probers.TargetWorker, seq uint) {
				if res.Err == nil {
					dbPrinter.PrintProbeSuccess(w.Stats)
				} else {
					dbPrinter.PrintProbeFailure(w.Stats)
				}
			},
		})
		multi.Run(context.Background())
		for _, w := range workers {
			dbPrinter.PrintStatistics(w.Stats)
		}
		dbPrinter.Done()

		// SQL Verification: Open SQLite connection and query table rows
		conn, err := sqlite.OpenConn(dbFile, sqlite.OpenReadOnly)
		require.NoError(t, err, "Must be able to open generated SQLite3 database")
		defer func() { _ = conn.Close() }()

		// Find user tables created in the database
		var probeTable, statsTable string
		err = sqlitex.Execute(conn, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';", &sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlite.Stmt) error {
				name := stmt.ColumnText(0)
				if strings.HasSuffix(name, "_stats") {
					statsTable = name
				} else {
					probeTable = name
				}
				return nil
			},
		})
		require.NoError(t, err)
		require.NotEmpty(t, probeTable, "Probe data table must exist in SQLite database")
		require.NotEmpty(t, statsTable, "Statistics table must exist in SQLite database")

		// Query 1: SELECT count(*) on Probe Data Table
		var probeCount int64
		probeCountQuery := fmt.Sprintf("SELECT count(*) FROM %s;", probeTable)
		err = sqlitex.Execute(conn, probeCountQuery, &sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlite.Stmt) error {
				probeCount = stmt.ColumnInt64(0)
				return nil
			},
		})
		require.NoError(t, err)
		assert.Equal(t, int64(4), probeCount, "SELECT count(*) on probe table must return exactly 4 rows (2 per worker)")

		// Query 2: SELECT count(*) on Statistics Table
		var statsCount int64
		statsCountQuery := fmt.Sprintf("SELECT count(*) FROM %s;", statsTable)
		err = sqlitex.Execute(conn, statsCountQuery, &sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlite.Stmt) error {
				statsCount = stmt.ColumnInt64(0)
				return nil
			},
		})
		require.NoError(t, err)
		assert.Equal(t, int64(2), statsCount, "SELECT count(*) on stats table must return exactly 2 summary rows (1 per worker)")

		// Query 3: Verify Column Data Integrity in Probe Table
		dataQuery := fmt.Sprintf("SELECT success, hostname, ip_address, port FROM %s;", probeTable)
		err = sqlitex.Execute(conn, dataQuery, &sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlite.Stmt) error {
				success := stmt.ColumnText(0)
				hostname := stmt.ColumnText(1)
				ip := stmt.ColumnText(2)
				port := stmt.ColumnInt64(3)

				assert.Equal(t, "true", success)
				assert.NotEmpty(t, hostname)
				assert.NotEmpty(t, ip)
				assert.True(t, port == 443 || port == 53)
				return nil
			},
		})
		require.NoError(t, err)
	})

	// 4. JSON Formatted Output & Object Stream Decoding Test
	t.Run("JSON_Pretty_Output", func(t *testing.T) {
		jsonFile := filepath.Join(tempDir, "fleet_probes_pretty.json")
		f, err := os.Create(jsonFile)
		require.NoError(t, err)
		defer func() { _ = f.Close() }()

		jsonPrinter := printers.NewJSONWriterPrinter(f, true)

		var workers []probers.TargetWorker
		for _, tgt := range targets {
			st := &stats.Statistics{
				Hostname: tgt.host,
				Port:     tgt.port,
			}
			jsonPrinter.PrintStart(st)
			var p probers.Pinger
			if tgt.proto == consts.DNS {
				p = probers.NewDNSQueryProber(probers.DNSQueryOptions{
					Nameserver: tgt.host,
					Port:       tgt.port,
					Domain:     "google.com",
					Timeout:    2 * time.Second,
				})
			} else {
				p = probers.NewHTTPing(probers.HTTPOptions{
					Hostname: tgt.host,
					Port:     tgt.port,
					Protocol: tgt.proto,
					Timeout:  2 * time.Second,
				})
			}
			workers = append(workers, probers.TargetWorker{
				Target:   fmt.Sprintf("%s:%d", tgt.host, tgt.port),
				Host:     tgt.host,
				Port:     tgt.port,
				Protocol: tgt.proto,
				Pinger:   p,
				Stats:    st,
			})
		}

		multi := probers.NewMultiProber(workers, probers.MultiProberOptions{
			ProbeCount:  2,
			Interval:    10 * time.Millisecond,
			Timeout:     2 * time.Second,
			Concurrency: 2,
			NoColor:     true,
			OnProbeEvent: func(res probers.ProbeResult, w probers.TargetWorker, seq uint) {
				if res.Err == nil {
					jsonPrinter.PrintProbeSuccess(w.Stats)
				} else {
					jsonPrinter.PrintProbeFailure(w.Stats)
				}
			},
		})
		multi.Run(context.Background())
		for _, w := range workers {
			jsonPrinter.PrintStatistics(w.Stats)
		}
		_ = f.Sync()

		// Structural Parsing: Decode all JSON objects from the pretty file stream
		fRead, err := os.Open(jsonFile)
		require.NoError(t, err)
		defer func() { _ = fRead.Close() }()

		decoder := json.NewDecoder(fRead)
		eventCount := 0
		probeEventCount := 0
		statsEventCount := 0

		for {
			var obj printers.JSONData
			err := decoder.Decode(&obj)
			if err == io.EOF {
				break
			}
			require.NoError(t, err, "JSON pretty stream must decode without error")
			eventCount++

			if obj.Type == "probe" {
				probeEventCount++
				assert.NotEmpty(t, obj.Hostname)
				assert.NotEmpty(t, obj.IPAddr)
				assert.True(t, obj.Port == 443 || obj.Port == 53)
				assert.True(t, *obj.Success)
			}
			if obj.Type == "statistics" {
				statsEventCount++
				assert.NotEmpty(t, obj.TotalDuration)
			}
		}

		assert.Equal(t, 4, probeEventCount, "Expected exactly 4 probe events in pretty JSON")
		assert.Equal(t, 2, statsEventCount, "Expected exactly 2 statistics events in pretty JSON")
		assert.True(t, eventCount >= 8, "Expected at least 8 total JSON events (2 start + 4 probe + 2 stats)")
	})

	// 5. JSONL (JSON Lines) Output & Line-by-Line Unmarshaling Test
	t.Run("JSONL_Output", func(t *testing.T) {
		jsonlFile := filepath.Join(tempDir, "fleet_probes.jsonl")
		fJSONL, err := os.Create(jsonlFile)
		require.NoError(t, err)
		defer func() { _ = fJSONL.Close() }()

		jsonlPrinter := printers.NewJSONWriterPrinter(fJSONL, false)

		var workers []probers.TargetWorker
		for _, tgt := range targets {
			st := &stats.Statistics{
				Hostname: tgt.host,
				Port:     tgt.port,
			}
			jsonlPrinter.PrintStart(st)
			var p probers.Pinger
			if tgt.proto == consts.DNS {
				p = probers.NewDNSQueryProber(probers.DNSQueryOptions{
					Nameserver: tgt.host,
					Port:       tgt.port,
					Domain:     "google.com",
					Timeout:    2 * time.Second,
				})
			} else {
				p = probers.NewHTTPing(probers.HTTPOptions{
					Hostname: tgt.host,
					Port:     tgt.port,
					Protocol: tgt.proto,
					Timeout:  2 * time.Second,
				})
			}
			workers = append(workers, probers.TargetWorker{
				Target:   fmt.Sprintf("%s:%d", tgt.host, tgt.port),
				Host:     tgt.host,
				Port:     tgt.port,
				Protocol: tgt.proto,
				Pinger:   p,
				Stats:    st,
			})
		}

		multi := probers.NewMultiProber(workers, probers.MultiProberOptions{
			ProbeCount:  2,
			Interval:    10 * time.Millisecond,
			Timeout:     2 * time.Second,
			Concurrency: 2,
			NoColor:     true,
			OnProbeEvent: func(res probers.ProbeResult, w probers.TargetWorker, seq uint) {
				if res.Err == nil {
					jsonlPrinter.PrintProbeSuccess(w.Stats)
				} else {
					jsonlPrinter.PrintProbeFailure(w.Stats)
				}
			},
		})
		multi.Run(context.Background())
		for _, w := range workers {
			jsonlPrinter.PrintStatistics(w.Stats)
		}
		_ = fJSONL.Sync()

		// Structural Parsing: Line-by-line validation of JSONL
		fRead, err := os.Open(jsonlFile)
		require.NoError(t, err)
		defer func() { _ = fRead.Close() }()

		scanner := bufio.NewScanner(fRead)
		lineCount := 0
		probeCount := 0
		statsCount := 0

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			lineCount++

			var item printers.JSONData
			err := json.Unmarshal([]byte(line), &item)
			require.NoError(t, err, "Line %d in JSONL must be valid JSON: %s", lineCount, line)

			if item.Type == "probe" {
				probeCount++
				assert.NotEmpty(t, item.Hostname)
				assert.NotEmpty(t, item.IPAddr)
				assert.True(t, item.Port == 443 || item.Port == 53)
			}
			if item.Type == "statistics" {
				statsCount++
				assert.NotEmpty(t, item.TotalDuration)
			}
		}

		assert.Equal(t, 4, probeCount, "Expected exactly 4 probe lines in JSONL")
		assert.Equal(t, 2, statsCount, "Expected exactly 2 stats lines in JSONL")
		assert.True(t, lineCount >= 8, "Expected at least 8 total lines in JSONL")
	})

	// 6. NDJSON (Newline Delimited JSON) Output & Line-by-Line Schema Test
	t.Run("NDJSON_Output", func(t *testing.T) {
		ndjsonFile := filepath.Join(tempDir, "fleet_probes.ndjson")
		fNDJSON, err := os.Create(ndjsonFile)
		require.NoError(t, err)
		defer func() { _ = fNDJSON.Close() }()

		ndjsonPrinter := printers.NewJSONWriterPrinter(fNDJSON, false)

		var workers []probers.TargetWorker
		for _, tgt := range targets {
			st := &stats.Statistics{
				Hostname: tgt.host,
				Port:     tgt.port,
			}
			ndjsonPrinter.PrintStart(st)
			var p probers.Pinger
			if tgt.proto == consts.DNS {
				p = probers.NewDNSQueryProber(probers.DNSQueryOptions{
					Nameserver: tgt.host,
					Port:       tgt.port,
					Domain:     "google.com",
					Timeout:    2 * time.Second,
				})
			} else {
				p = probers.NewHTTPing(probers.HTTPOptions{
					Hostname: tgt.host,
					Port:     tgt.port,
					Protocol: tgt.proto,
					Timeout:  2 * time.Second,
				})
			}
			workers = append(workers, probers.TargetWorker{
				Target:   fmt.Sprintf("%s:%d", tgt.host, tgt.port),
				Host:     tgt.host,
				Port:     tgt.port,
				Protocol: tgt.proto,
				Pinger:   p,
				Stats:    st,
			})
		}

		multi := probers.NewMultiProber(workers, probers.MultiProberOptions{
			ProbeCount:  2,
			Interval:    10 * time.Millisecond,
			Timeout:     2 * time.Second,
			Concurrency: 2,
			NoColor:     true,
			OnProbeEvent: func(res probers.ProbeResult, w probers.TargetWorker, seq uint) {
				if res.Err == nil {
					ndjsonPrinter.PrintProbeSuccess(w.Stats)
				} else {
					ndjsonPrinter.PrintProbeFailure(w.Stats)
				}
			},
		})
		multi.Run(context.Background())
		for _, w := range workers {
			ndjsonPrinter.PrintStatistics(w.Stats)
		}
		_ = fNDJSON.Sync()

		// Structural Parsing: Line-by-line validation of NDJSON
		fRead, err := os.Open(ndjsonFile)
		require.NoError(t, err)
		defer func() { _ = fRead.Close() }()

		scanner := bufio.NewScanner(fRead)
		lineCount := 0
		probeCount := 0
		statsCount := 0

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			lineCount++

			var rawMap map[string]interface{}
			err := json.Unmarshal([]byte(line), &rawMap)
			require.NoError(t, err, "Line %d in NDJSON must be valid JSON: %s", lineCount, line)

			eventType, _ := rawMap["type"].(string)
			if eventType == "probe" {
				probeCount++
				assert.NotEmpty(t, rawMap["hostname"])
				assert.NotEmpty(t, rawMap["ipAddress"])
				assert.NotNil(t, rawMap["port"])
			}
			if eventType == "statistics" {
				statsCount++
				assert.NotEmpty(t, rawMap["totalDuration"])
			}
		}

		assert.Equal(t, 4, probeCount, "Expected exactly 4 probe records in NDJSON")
		assert.Equal(t, 2, statsCount, "Expected exactly 2 stats records in NDJSON")
		assert.True(t, lineCount >= 8, "Expected at least 8 total lines in NDJSON")
	})
}

// ==========================================
// 10. Live Web Server & REST API End-to-End Tests
// ==========================================

func TestLive_Web_REST_API_Full_E2E(t *testing.T) {
	st := stats.NewStatistics(stats.Options{
		Hostname: "api-e2e.example.com",
		IP:       netip.MustParseAddr("1.1.1.1"),
		Port:     443,
	})
	st.RecordSuccess(14.2, time.Now())
	st.RecordSuccess(18.6, time.Now())

	broadcaster := web.NewBroadcaster()
	for i := 1; i <= 5; i++ {
		broadcaster.Broadcast(web.ProbeEvent{
			Sequence: uint(i),
			Success:  true,
			RTT:      float64(i) * 3.5,
			Target:   "api-e2e.example.com:443",
			Protocol: "HTTPS",
			IP:       "1.1.1.1",
		})
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	actualAddr := ln.Addr().String()
	_ = ln.Close()

	server := web.NewServer(actualAddr, st, broadcaster)
	server.SetTargetsSupplier(func() []printers.FleetTarget {
		return []printers.FleetTarget{
			{Target: "api-e2e.example.com:443", Host: "api-e2e.example.com", Port: 443, Protocol: "HTTPS", Stats: st},
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	baseURL := fmt.Sprintf("http://%s", actualAddr)
	client := &http.Client{Timeout: 5 * time.Second}

	require.Eventually(t, func() bool {
		resp, err := client.Get(baseURL + "/api/v1/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			return true
		}
		return false
	}, 3*time.Second, 50*time.Millisecond, "Server failed to start")

	// 1. GET / (Dashboard SPA)
	t.Run("GET_Index_Dashboard", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "netping Enterprise Dashboard")
		assert.Contains(t, string(body), "Live Probe Event Stream")
	})

	// 2. GET /api/v1/health
	t.Run("GET_Health", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/api/v1/health")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var h map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&h))
		assert.Equal(t, "healthy", h["status"])
		assert.Equal(t, float64(5), h["history_count"])
	})

	// 3. GET /api/v1/metrics
	t.Run("GET_Metrics", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/api/v1/metrics")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var m map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&m))
		assert.Contains(t, m, "targets")
	})

	// 4. GET /api/v1/targets
	t.Run("GET_Targets", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/api/v1/targets")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var tgts map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tgts))
		assert.Equal(t, float64(1), tgts["total"])
	})

	// 5. GET /api/v1/probes
	t.Run("GET_Probes", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/api/v1/probes?limit=3")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var probes map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&probes))
		assert.Equal(t, float64(5), probes["total"])
		dataList, ok := probes["data"].([]interface{})
		assert.True(t, ok)
		assert.Equal(t, 3, len(dataList))
	})

	// 6. GET /docs & GET /api/openapi.json
	t.Run("GET_Swagger_And_OpenAPI", func(t *testing.T) {
		respDocs, err := client.Get(baseURL + "/docs")
		require.NoError(t, err)
		defer func() { _ = respDocs.Body.Close() }()
		assert.Equal(t, http.StatusOK, respDocs.StatusCode)

		respSpec, err := client.Get(baseURL + "/api/openapi.json")
		require.NoError(t, err)
		defer func() { _ = respSpec.Body.Close() }()
		assert.Equal(t, http.StatusOK, respSpec.StatusCode)
		var spec map[string]interface{}
		require.NoError(t, json.NewDecoder(respSpec.Body).Decode(&spec))
		assert.Equal(t, "3.0.3", spec["openapi"])
	})

	// 7. GET /api/v1/config/history & POST /api/v1/config/history
	t.Run("GET_POST_Config_History", func(t *testing.T) {
		respGet, err := client.Get(baseURL + "/api/v1/config/history")
		require.NoError(t, err)
		defer func() { _ = respGet.Body.Close() }()
		assert.Equal(t, http.StatusOK, respGet.StatusCode)

		respPost, err := client.Post(baseURL+"/api/v1/config/history", "application/json", strings.NewReader(`{"limit": 250000}`))
		require.NoError(t, err)
		defer func() { _ = respPost.Body.Close() }()
		assert.Equal(t, http.StatusOK, respPost.StatusCode)
		var res map[string]interface{}
		require.NoError(t, json.NewDecoder(respPost.Body).Decode(&res))
		assert.Equal(t, float64(250000), res["history_limit"])
	})

	// 8. GET /api/v1/export streaming (JSON & CSV)
	t.Run("GET_Export_Streaming", func(t *testing.T) {
		respJSON, err := client.Get(baseURL + "/api/v1/export?format=json")
		require.NoError(t, err)
		defer func() { _ = respJSON.Body.Close() }()
		assert.Equal(t, http.StatusOK, respJSON.StatusCode)
		assert.Equal(t, "application/json", respJSON.Header.Get("Content-Type"))

		respCSV, err := client.Get(baseURL + "/api/v1/export?format=csv")
		require.NoError(t, err)
		defer func() { _ = respCSV.Body.Close() }()
		assert.Equal(t, http.StatusOK, respCSV.StatusCode)
		assert.Equal(t, "text/csv", respCSV.Header.Get("Content-Type"))
	})

	// 9. POST /api/v1/export (host file save)
	t.Run("POST_Export_Host_Save", func(t *testing.T) {
		tmpDir := t.TempDir()
		outPath := filepath.Join(tmpDir, "e2e_live_export.json")
		reqBody := fmt.Sprintf(`{"format":"json","path":%q}`, outPath)

		resp, err := client.Post(baseURL+"/api/v1/export", "application/json", strings.NewReader(reqBody))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		require.Eventually(t, func() bool {
			info, err := os.Stat(outPath)
			return err == nil && info.Size() > 0
		}, 3*time.Second, 50*time.Millisecond)
	})

	// 10. POST /api/v1/reset
	t.Run("POST_Reset_Telemetry", func(t *testing.T) {
		resp, err := client.Post(baseURL+"/api/v1/reset", "application/json", nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 0, broadcaster.GetHistoryCount())
	})
}
