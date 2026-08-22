package probers

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// RsyncOptions holds configuration for the Rsync prober.
type RsyncOptions struct {
	Hostname string
	IP       netip.Addr
	Port     uint16
	Timeout  time.Duration
	Dialer   *net.Dialer
}

// Rsyncing implements Pinger for the Rsync daemon protocol (port 873).
type Rsyncing struct {
	hostname string
	ip       netip.Addr
	port     uint16
	timeout  time.Duration
	dialer   *net.Dialer
}

// NewRsyncing constructs a new Rsync daemon prober.
func NewRsyncing(opts RsyncOptions) *Rsyncing {
	port := opts.Port
	if port == 0 {
		port = 873
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return &Rsyncing{
		hostname: opts.Hostname,
		ip:       opts.IP,
		port:     port,
		timeout:  opts.Timeout,
		dialer:   d,
	}
}

// Ping connects to the target Rsync daemon, exchanges protocol greeting, queries available modules, and extracts diagnostics.
func (r *Rsyncing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	targetHost := r.hostname
	if targetHost == "" {
		targetHost = r.ip.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(r.port)))

	conn, err := r.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(r.timeout))
	reader := bufio.NewReader(conn)

	// Read server greeting: @RSYNCD: <version> [digest=...]
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("failed to read rsyncd greeting: %w", err),
		}
	}

	cleanGreeting := strings.TrimSpace(greeting)
	if !strings.HasPrefix(cleanGreeting, "@RSYNCD:") {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("unexpected rsyncd greeting: %q", cleanGreeting),
		}
	}

	// Send client protocol announcement (using protocol 31 for universal daemon listing compatibility)
	clientGreeting := "@RSYNCD: 31.0\n"
	if _, err := conn.Write([]byte(clientGreeting)); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("failed to send rsyncd client greeting: %w", err),
		}
	}

	rtt := time.Since(start)

	// Parse server greeting banner & capabilities
	greetingBody := strings.TrimSpace(strings.TrimPrefix(cleanGreeting, "@RSYNCD:"))
	var parts []string
	var protoVer string = "31.0"
	var digests string

	fields := strings.Fields(greetingBody)
	if len(fields) > 0 {
		protoVer = fields[0]
		parts = append(parts, fmt.Sprintf("Protocol: RSYNCD %s", protoVer))
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "digest=") {
				digests = strings.ReplaceAll(strings.TrimPrefix(f, "digest="), ",", "|")
			} else if strings.HasPrefix(f, "checksum=") {
				digests = strings.ReplaceAll(strings.TrimPrefix(f, "checksum="), ",", "|")
			}
		}
	} else {
		parts = append(parts, fmt.Sprintf("Banner: %s", cleanGreeting))
	}

	if digests != "" {
		parts = append(parts, fmt.Sprintf("Checksums: %s", digests))
	} else {
		verFloat, _ := strconv.ParseFloat(protoVer, 64)
		if verFloat >= 32.0 {
			parts = append(parts, "Checksums: xxh128|xxh3|xxh64|md5|md4|sha1")
		} else if verFloat >= 30.0 {
			parts = append(parts, "Checksums: MD5|MD4")
		} else {
			parts = append(parts, "Checksums: MD4")
		}
	}

	// Query available modules using #list command
	_ = conn.SetDeadline(time.Now().Add(r.timeout / 2))
	if _, err := conn.Write([]byte("#list\n")); err == nil {
		var modules []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "@RSYNCD: EXIT") || strings.HasPrefix(trimmed, "@RSYNCD: AUTHREQD") || strings.HasPrefix(trimmed, "@ERROR:") {
				break
			}
			if trimmed != "" && !strings.HasPrefix(trimmed, "@RSYNCD:") && !strings.HasPrefix(trimmed, "@ERROR:") {
				modFields := strings.Fields(trimmed)
				if len(modFields) > 0 {
					modules = append(modules, modFields[0])
				}
			}
		}
		if len(modules) > 0 {
			if len(modules) > 4 {
				parts = append(parts, fmt.Sprintf("Modules: [%s, +%d more]", strings.Join(modules[:4], ", "), len(modules)-4))
			} else {
				parts = append(parts, fmt.Sprintf("Modules: [%s]", strings.Join(modules, ", ")))
			}
		}
	}

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: strings.Join(parts, ", "),
		Err:         nil,
	}
}
