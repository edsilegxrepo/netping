package probers

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type RedisOptions struct {
	Hostname string
	IP       netip.Addr
	Port     uint16
	UseTLS   bool
	Password string
	Timeout  time.Duration
	Dialer   *net.Dialer
}

// Redising implements Pinger for Redis RESP protocol health checks with deep INFO metadata extraction.
type Redising struct {
	hostname string
	ip       netip.Addr
	port     uint16
	useTLS   bool
	password string
	timeout  time.Duration
	dialer   *net.Dialer
}

// NewRedising constructs a new Redis prober.
func NewRedising(opts RedisOptions) *Redising {
	port := opts.Port
	if port == 0 {
		if opts.UseTLS {
			port = 6380
		} else {
			port = 6379
		}
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return &Redising{
		hostname: opts.Hostname,
		ip:       opts.IP,
		port:     port,
		useTLS:   opts.UseTLS,
		password: opts.Password,
		timeout:  opts.Timeout,
		dialer:   d,
	}
}

// readRESPBulkString reads a RESP bulk string ($<length>\r\n<data>\r\n).
func readRESPBulkString(reader *bufio.Reader, firstLine string) (string, error) {
	lenStr := strings.TrimSpace(strings.TrimPrefix(firstLine, "$"))
	length, err := strconv.Atoi(lenStr)
	if err != nil {
		return "", err
	}
	if length < 0 {
		return "", nil // Nil bulk string
	}

	buf := make([]byte, length+2) // data + \r\n
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", err
	}
	return string(buf[:length]), nil
}

// parseRedisInfo parses the key-value pairs from Redis INFO command output.
func parseRedisInfo(infoStr string) map[string]string {
	info := make(map[string]string)
	lines := strings.Split(infoStr, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) == 2 {
			info[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return info
}

// Ping connects to Redis, optionally authenticates, sends RESP PING & INFO, and extracts rich server diagnostics.
func (r *Redising) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	targetHost := r.hostname
	if targetHost == "" {
		targetHost = r.ip.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(r.port)))

	var conn net.Conn
	var err error

	var tlsDetails string
	if r.useTLS {
		tlsConfig := &tls.Config{
			ServerName:         targetHost,
			InsecureSkipVerify: true,
		}
		tlsDialer := &tls.Dialer{NetDialer: r.dialer, Config: tlsConfig}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			if tc, ok := conn.(*tls.Conn); ok {
				state := tc.ConnectionState()
				tlsDetails = fmt.Sprintf("TLS: %s (%s)", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))
			}
		}
	} else {
		conn, err = r.dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(r.timeout))
	reader := bufio.NewReader(conn)

	// If password provided, send AUTH command
	if r.password != "" {
		authCmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(r.password), r.password)
		if _, err := conn.Write([]byte(authCmd)); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("redis auth write failed: %w", err),
			}
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("redis auth read failed: %w", err),
			}
		}
		if !strings.HasPrefix(line, "+OK") {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("redis auth error: %s", strings.TrimSpace(line)),
			}
		}
	}

	// Send RESP PING
	pingCmd := "*1\r\n$4\r\nPING\r\n"
	if _, err := conn.Write([]byte(pingCmd)); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("redis ping write failed: %w", err),
		}
	}

	line, err := reader.ReadString('\n')
	rtt := time.Since(start)
	if err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       rtt,
			Err:       fmt.Errorf("redis ping read failed: %w", err),
		}
	}

	cleanLine := strings.TrimSpace(line)
	if cleanLine != "+PONG" && !strings.Contains(cleanLine, "PONG") && !strings.HasPrefix(cleanLine, "-NOAUTH") {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       rtt,
			Err:       fmt.Errorf("unexpected redis response: %q", cleanLine),
		}
	}

	var diagParts []string
	if tlsDetails != "" {
		diagParts = append(diagParts, tlsDetails)
	}

	// Send INFO command to harvest server version, role, memory, and client count
	_ = conn.SetDeadline(time.Now().Add(r.timeout / 2))
	infoCmd := "*1\r\n$4\r\nINFO\r\n"
	if _, err := conn.Write([]byte(infoCmd)); err == nil {
		infoRespLine, err := reader.ReadString('\n')
		if err == nil {
			infoRespTrim := strings.TrimSpace(infoRespLine)
			if strings.HasPrefix(infoRespTrim, "$") {
				bulkData, err := readRESPBulkString(reader, infoRespTrim)
				if err == nil && bulkData != "" {
					infoMap := parseRedisInfo(bulkData)

					ver := infoMap["redis_version"]
					if ver == "" {
						ver = infoMap["valkey_version"]
					}
					if ver != "" {
						mode := infoMap["redis_mode"]
						if mode == "" {
							mode = "standalone"
						}
						diagParts = append(diagParts, fmt.Sprintf("Version: %s (%s)", ver, mode))
					}

					if role := infoMap["role"]; role != "" {
						diagParts = append(diagParts, fmt.Sprintf("Role: %s", role))
					}
					if clients := infoMap["connected_clients"]; clients != "" {
						diagParts = append(diagParts, fmt.Sprintf("Clients: %s", clients))
					}
					if mem := infoMap["used_memory_human"]; mem != "" {
						diagParts = append(diagParts, fmt.Sprintf("Mem: %s", mem))
					}
					if uptime := infoMap["uptime_in_days"]; uptime != "" && uptime != "0" {
						diagParts = append(diagParts, fmt.Sprintf("Uptime: %sd", uptime))
					}
				}
			} else if strings.HasPrefix(infoRespTrim, "-NOAUTH") {
				diagParts = append(diagParts, "Response: +PONG", "Auth: Required (Protected)")
			}
		}
	}

	if len(diagParts) == 0 {
		diagParts = append(diagParts, fmt.Sprintf("Response: %s", cleanLine))
	}

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: strings.Join(diagParts, ", "),
		Err:         nil,
	}
}
