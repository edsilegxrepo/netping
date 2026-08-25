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

// FTPOptions holds configuration for the FTP/FTPS prober.
type FTPOptions struct {
	Hostname string
	IP       netip.Addr
	Port     uint16
	UseTLS   bool // Implicit FTPS (port 990)
	StartTLS bool // Explicit FTPS via AUTH TLS (port 21)
	Timeout  time.Duration
	Dialer   *net.Dialer
}

// FTPing implements Pinger for FTP and FTPS protocols with FEAT harvesting and TLS dissection.
type FTPing struct {
	hostname string
	ip       netip.Addr
	port     uint16
	useTLS   bool
	startTLS bool
	timeout  time.Duration
	dialer   *net.Dialer
}

// NewFTPing constructs a new FTP/FTPS prober.
func NewFTPing(opts FTPOptions) *FTPing {
	port := opts.Port
	if port == 0 {
		if opts.UseTLS {
			port = 990
		} else {
			port = 21
		}
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return &FTPing{
		hostname: opts.Hostname,
		ip:       opts.IP,
		port:     port,
		useTLS:   opts.UseTLS,
		startTLS: opts.StartTLS,
		timeout:  opts.Timeout,
		dialer:   d,
	}
}

// readFTPResponse reads a standard FTP single-line or multi-line response (e.g. "220-..." followed by "220 ...").
func readFTPResponse(reader *bufio.Reader) (string, []string, error) {
	var lines []string
	var lastLine string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return lastLine, lines, err
		}
		trimmed := strings.TrimSpace(line)
		lines = append(lines, trimmed)
		lastLine = trimmed

		if len(trimmed) >= 4 && trimmed[3] == ' ' && (trimmed[0] >= '1' && trimmed[0] <= '5') {
			break
		}
		if len(trimmed) == 3 && (trimmed[0] >= '1' && trimmed[0] <= '5') {
			break
		}
	}

	return lastLine, lines, nil
}

// Ping connects to the FTP server, harvests the 220 banner, negotiates TLS/STARTTLS, queries FEAT capabilities, and measures RTT.
func (f *FTPing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	targetHost := f.hostname
	if targetHost == "" {
		targetHost = f.ip.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(f.port)))

	var conn net.Conn
	var err error

	if f.useTLS {
		// #nosec G402 -- diagnostic FTPS prober measuring connection latency
		// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification -- diagnostic prober measuring latency
		tlsConfig := &tls.Config{
			ServerName:         targetHost,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
		tlsDialer := &tls.Dialer{
			NetDialer: f.dialer,
			Config:    tlsConfig,
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = f.dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(f.timeout))
	reader := bufio.NewReader(conn)

	var diagParts []string

	if f.useTLS {
		if tc, ok := conn.(*tls.Conn); ok {
			state := tc.ConnectionState()
			tlsVerName := tls.VersionName(state.Version)
			cipherName := tls.CipherSuiteName(state.CipherSuite)
			diagParts = append(diagParts, fmt.Sprintf("TLS: %s (%s)", tlsVerName, cipherName))
		}
	}

	// Read 220 Greeting Banner
	lastLine, _, err := readFTPResponse(reader)
	if err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("failed to read ftp banner: %w", err),
		}
	}
	if !strings.HasPrefix(lastLine, "220") {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("unexpected ftp banner: %q", lastLine),
		}
	}

	bannerText := strings.TrimSpace(strings.TrimPrefix(lastLine, "220"))
	if bannerText != "" {
		diagParts = append(diagParts, fmt.Sprintf("Banner: %s", bannerText))
	}

	// Explicit FTPS: send AUTH TLS if requested
	if f.startTLS && !f.useTLS {
		if _, err := conn.Write([]byte("AUTH TLS\r\n")); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("failed to send AUTH TLS: %w", err),
			}
		}

		resp, _, err := readFTPResponse(reader)
		if err != nil || !strings.HasPrefix(resp, "234") {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("AUTH TLS rejected by server: %q", resp),
			}
		}

		// #nosec G402 -- diagnostic AUTH TLS prober measuring handshake latency
		// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification -- diagnostic prober measuring latency
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         targetHost,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("AUTH TLS handshake failed: %w", err),
			}
		}
		tlsState := tlsConn.ConnectionState()
		tlsName := tls.VersionName(tlsState.Version)
		cipherName := tls.CipherSuiteName(tlsState.CipherSuite)
		diagParts = append(diagParts, fmt.Sprintf("AUTH TLS: %s (%s)", tlsName, cipherName))

		reader = bufio.NewReader(tlsConn)
		conn = tlsConn
	}

	// Send FEAT command to harvest server feature extensions (RFC 2389)
	_ = conn.SetDeadline(time.Now().Add(f.timeout / 2))
	if _, err := conn.Write([]byte("FEAT\r\n")); err == nil {
		lastFeat, featLines, err := readFTPResponse(reader)
		if err == nil && strings.HasPrefix(lastFeat, "211") {
			var feats []string
			for _, fl := range featLines {
				flTrim := strings.TrimSpace(fl)
				if strings.HasPrefix(flTrim, "211") {
					continue
				}
				if flTrim != "" {
					feats = append(feats, flTrim)
				}
			}
			if len(feats) > 0 {
				if len(feats) > 5 {
					diagParts = append(diagParts, fmt.Sprintf("Features: %s (+%d more)", strings.Join(feats[:5], "|"), len(feats)-5))
				} else {
					diagParts = append(diagParts, fmt.Sprintf("Features: %s", strings.Join(feats, "|")))
				}
			}
		}
	}

	// Send QUIT to close cleanly
	_, _ = conn.Write([]byte("QUIT\r\n"))

	rtt := time.Since(start)

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: strings.Join(diagParts, ", "),
		Err:         nil,
	}
}
