package probers

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type WSOptions struct {
	Hostname string
	IP       netip.Addr
	Port     uint16
	UseTLS   bool
	Timeout  time.Duration
	Dialer   *net.Dialer
}

// WSing implements Pinger for WebSocket (RFC 6455) upgrade and Ping/Pong frame validation.
type WSing struct {
	hostname string
	ip       netip.Addr
	port     uint16
	useTLS   bool
	timeout  time.Duration
	dialer   *net.Dialer
}

// NewWSing constructs a new WebSocket prober.
func NewWSing(opts WSOptions) *WSing {
	port := opts.Port
	if port == 0 {
		if opts.UseTLS {
			port = 443
		} else {
			port = 80
		}
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return &WSing{
		hostname: opts.Hostname,
		ip:       opts.IP,
		port:     port,
		useTLS:   opts.UseTLS,
		timeout:  opts.Timeout,
		dialer:   d,
	}
}

// Ping connects, completes the RFC 6455 WebSocket upgrade, sends a Ping frame, and waits for a Pong frame.
func (w *WSing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	targetHost := w.hostname
	if targetHost == "" {
		targetHost = w.ip.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(w.port)))

	var conn net.Conn
	var err error

	if w.useTLS {
		tlsConfig := &tls.Config{
			ServerName: targetHost,
		}
		tlsDialer := &tls.Dialer{
			NetDialer: w.dialer,
			Config:    tlsConfig,
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = w.dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(w.timeout))

	// Generate random 16-byte Sec-WebSocket-Key
	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	// Send HTTP 1.1 WebSocket Upgrade request
	req := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n",
		addr, wsKey,
	)

	if _, err := conn.Write([]byte(req)); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("websocket upgrade write failed: %w", err),
		}
	}

	// Read HTTP 101 Switching Protocols response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("websocket upgrade response failed: %w", err),
		}
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return ProbeResult{
			LocalAddr:  conn.LocalAddr(),
			RTT:        time.Since(start),
			HTTPStatus: resp.StatusCode,
			Err:        fmt.Errorf("websocket upgrade rejected with status %d %s", resp.StatusCode, resp.Status),
		}
	}

	// Send RFC 6455 Masked Ping Frame (Opcode 0x9)
	// Byte 0: 0x89 (FIN + Ping)
	// Byte 1: 0x84 (Masked + Payload Length 4)
	// Bytes 2-5: Masking Key
	// Bytes 6-9: Masked Payload ("PING")
	maskKey := []byte{0x1a, 0x2b, 0x3c, 0x4d}
	pingPayload := []byte("PING")
	maskedPayload := make([]byte, 4)
	for i := 0; i < 4; i++ {
		maskedPayload[i] = pingPayload[i] ^ maskKey[i%4]
	}

	frame := []byte{0x89, 0x84}
	frame = append(frame, maskKey...)
	frame = append(frame, maskedPayload...)

	if _, err := conn.Write(frame); err != nil {
		return ProbeResult{
			LocalAddr:  conn.LocalAddr(),
			RTT:        time.Since(start),
			HTTPStatus: resp.StatusCode,
			Err:        fmt.Errorf("failed to send websocket ping frame: %w", err),
		}
	}

	// Read Pong frame (Opcode 0xA)
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return ProbeResult{
			LocalAddr:  conn.LocalAddr(),
			RTT:        time.Since(start),
			HTTPStatus: resp.StatusCode,
			Err:        fmt.Errorf("failed to read websocket pong frame: %w", err),
		}
	}

	opcode := header[0] & 0x0f

	var diags []string
	diags = append(diags, fmt.Sprintf("Upgrade: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode)))
	if opcode == 0x0a {
		diags = append(diags, "Frame: Pong (0xA)")
	} else {
		diags = append(diags, fmt.Sprintf("Frame: Opcode 0x%x", opcode))
	}
	if w.useTLS {
		if tlsConn, ok := conn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()
			diags = append(diags, fmt.Sprintf("TLS: %s (%s)", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite)))
		}
	}
	if srv := resp.Header.Get("Server"); srv != "" {
		diags = append(diags, fmt.Sprintf("Server: %s", srv))
	}

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         time.Since(start),
		HTTPStatus:  resp.StatusCode,
		Diagnostics: strings.Join(diags, ", "),
		Err:         nil,
	}
}
