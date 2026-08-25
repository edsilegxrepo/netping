package probers

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type MemcachedOptions struct {
	Hostname string
	IP       netip.Addr
	Port     uint16
	UseTLS   bool
	Timeout  time.Duration
	Dialer   *net.Dialer
}

// Memcacheding implements Pinger for Memcached protocol health checks with version & STATS harvesting.
type Memcacheding struct {
	hostname string
	ip       netip.Addr
	port     uint16
	useTLS   bool
	timeout  time.Duration
	dialer   *net.Dialer
}

// NewMemcacheding constructs a new Memcached prober.
func NewMemcacheding(opts MemcachedOptions) *Memcacheding {
	port := opts.Port
	if port == 0 {
		port = 11211
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return &Memcacheding{
		hostname: opts.Hostname,
		ip:       opts.IP,
		port:     port,
		useTLS:   opts.UseTLS,
		timeout:  opts.Timeout,
		dialer:   d,
	}
}

// formatBytes formats byte counts into human-readable strings (e.g. 12.5M, 64M).
func formatBytes(bytes int64) string {
	if bytes >= 1024*1024*1024 {
		return fmt.Sprintf("%.1fG", float64(bytes)/(1024*1024*1024))
	}
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.1fM", float64(bytes)/(1024*1024))
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%dK", bytes/1024)
	}
	return fmt.Sprintf("%dB", bytes)
}

// Ping connects to Memcached, retrieves version and stats, and extracts server telemetry.
func (m *Memcacheding) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	targetHost := m.hostname
	if targetHost == "" {
		targetHost = m.ip.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(m.port)))

	var conn net.Conn
	var err error

	var tlsDetails string
	if m.useTLS {
		// #nosec G402 -- diagnostic Memcached TLS prober measuring latency
		// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification -- diagnostic prober measuring latency
		tlsConfig := &tls.Config{
			ServerName:         targetHost,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
		tlsDialer := &tls.Dialer{NetDialer: m.dialer, Config: tlsConfig}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			if tc, ok := conn.(*tls.Conn); ok {
				state := tc.ConnectionState()
				tlsDetails = fmt.Sprintf("TLS: %s (%s)", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))
			}
		}
	} else {
		conn, err = m.dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(m.timeout))

	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("memcached write failed: %w", err),
		}
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	rtt := time.Since(start)
	if err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       rtt,
			Err:       fmt.Errorf("memcached read failed: %w", err),
		}
	}

	cleanLine := strings.TrimSpace(line)
	if !strings.HasPrefix(cleanLine, "VERSION") {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       rtt,
			Err:       fmt.Errorf("unexpected memcached response: %q", cleanLine),
		}
	}

	var diagParts []string
	if tlsDetails != "" {
		diagParts = append(diagParts, tlsDetails)
	}

	ver := strings.TrimSpace(strings.TrimPrefix(cleanLine, "VERSION"))
	if ver != "" {
		diagParts = append(diagParts, fmt.Sprintf("Version: %s", ver))
	}

	// Send `stats\r\n` to harvest server telemetry
	_ = conn.SetDeadline(time.Now().Add(m.timeout / 2))
	if _, err := conn.Write([]byte("stats\r\n")); err == nil {
		statsMap := make(map[string]string)
		for {
			sLine, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			sTrim := strings.TrimSpace(sLine)
			if sTrim == "END" || sTrim == "ERROR" {
				break
			}
			if strings.HasPrefix(sTrim, "STAT ") {
				fields := strings.Fields(sTrim)
				if len(fields) >= 3 {
					statsMap[fields[1]] = fields[2]
				}
			}
		}

		if conns := statsMap["curr_connections"]; conns != "" {
			diagParts = append(diagParts, fmt.Sprintf("Conns: %s", conns))
		}
		if items := statsMap["curr_items"]; items != "" {
			diagParts = append(diagParts, fmt.Sprintf("Items: %s", items))
		}

		curBytes, _ := strconv.ParseInt(statsMap["bytes"], 10, 64)
		maxBytes, _ := strconv.ParseInt(statsMap["limit_maxbytes"], 10, 64)
		if maxBytes > 0 {
			diagParts = append(diagParts, fmt.Sprintf("Mem: %s/%s", formatBytes(curBytes), formatBytes(maxBytes)))
		} else if curBytes > 0 {
			diagParts = append(diagParts, fmt.Sprintf("Mem: %s", formatBytes(curBytes)))
		}

		getHits, _ := strconv.ParseInt(statsMap["get_hits"], 10, 64)
		getMisses, _ := strconv.ParseInt(statsMap["get_misses"], 10, 64)
		totalGets := getHits + getMisses
		if totalGets > 0 {
			hitRatio := (float64(getHits) / float64(totalGets)) * 100.0
			diagParts = append(diagParts, fmt.Sprintf("HitRatio: %.1f%%", hitRatio))
		}

		if uptimeSec, err := strconv.ParseInt(statsMap["uptime"], 10, 64); err == nil && uptimeSec > 0 {
			days := uptimeSec / 86400
			if days > 0 {
				diagParts = append(diagParts, fmt.Sprintf("Uptime: %dd", days))
			} else {
				hours := uptimeSec / 3600
				diagParts = append(diagParts, fmt.Sprintf("Uptime: %dh", hours))
			}
		}
	}

	if len(diagParts) == 0 {
		diagParts = append(diagParts, cleanLine)
	}

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: strings.Join(diagParts, ", "),
		Err:         nil,
	}
}
