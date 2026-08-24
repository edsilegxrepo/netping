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

type MailProtocol string

const (
	MailSMTP MailProtocol = "smtp"
	MailIMAP MailProtocol = "imap"
	MailPOP3 MailProtocol = "pop3"
)

type MailOptions struct {
	Protocol MailProtocol
	Hostname string
	IP       netip.Addr
	Port     uint16
	UseTLS   bool
	StartTLS bool
	Timeout  time.Duration
	Dialer   *net.Dialer
}

// Mailing implements Pinger for SMTP, IMAP, and POP3 protocols with deep capability and banner harvesting.
type Mailing struct {
	protocol MailProtocol
	hostname string
	ip       netip.Addr
	port     uint16
	useTLS   bool
	startTLS bool
	timeout  time.Duration
	dialer   *net.Dialer
}

// NewMailing constructs a new Mail prober.
func NewMailing(opts MailOptions) *Mailing {
	port := opts.Port
	if port == 0 {
		switch opts.Protocol {
		case MailIMAP:
			if opts.UseTLS {
				port = 993
			} else {
				port = 143
			}
		case MailPOP3:
			if opts.UseTLS {
				port = 995
			} else {
				port = 110
			}
		case MailSMTP:
			fallthrough
		default:
			if opts.UseTLS {
				port = 465
			} else if opts.StartTLS {
				port = 587
			} else {
				port = 25
			}
		}
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return &Mailing{
		protocol: opts.Protocol,
		hostname: opts.Hostname,
		ip:       opts.IP,
		port:     port,
		useTLS:   opts.UseTLS,
		startTLS: opts.StartTLS,
		timeout:  opts.Timeout,
		dialer:   d,
	}
}

// formatBytesSize formats byte size into human readable string (e.g. 52428800 -> 50MB)
func formatBytesSize(sizeStr string) string {
	bytes, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil || bytes <= 0 {
		return sizeStr
	}
	if bytes >= 1024*1024*1024 {
		return fmt.Sprintf("%.1fGB", float64(bytes)/(1024*1024*1024))
	}
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%dMB", bytes/(1024*1024))
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%dKB", bytes/1024)
	}
	return fmt.Sprintf("%dB", bytes)
}

// Ping connects to the mail server, completes the handshake, harvests capabilities, and measures RTT.
func (m *Mailing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	targetHost := m.hostname
	if targetHost == "" {
		targetHost = m.ip.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(m.port)))

	var conn net.Conn
	var err error

	if m.useTLS {
		tlsConfig := &tls.Config{
			ServerName: targetHost,
			// #nosec G402 -- diagnostic mail TLS prober measuring latency
			InsecureSkipVerify: true,
		}
		tlsDialer := &tls.Dialer{
			NetDialer: m.dialer,
			Config:    tlsConfig,
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = m.dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(m.timeout))
	reader := bufio.NewReader(conn)

	var diagParts []string

	if m.useTLS {
		if tc, ok := conn.(*tls.Conn); ok {
			state := tc.ConnectionState()
			tlsVerName := tls.VersionName(state.Version)
			cipherName := tls.CipherSuiteName(state.CipherSuite)
			diagParts = append(diagParts, fmt.Sprintf("TLS: %s (%s)", tlsVerName, cipherName))
		}
	}

	if m.protocol == MailSMTP {
		// Read 220 greeting banner
		banner, err := reader.ReadString('\n')
		if err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("failed to read smtp banner: %w", err),
			}
		}
		cleanBanner := strings.TrimSpace(banner)
		if !strings.HasPrefix(cleanBanner, "220") {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("unexpected smtp banner: %q", cleanBanner),
			}
		}

		// Clean banner string (strip leading "220 " or "220-")
		bannerText := strings.TrimSpace(cleanBanner[3:])
		diagParts = append(diagParts, fmt.Sprintf("Banner: %s", bannerText))

		// Send EHLO netping
		if _, err := conn.Write([]byte("EHLO netping\r\n")); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("failed to send smtp ehlo: %w", err),
			}
		}

		// Read multiline 250 response to harvest ESMTP capabilities
		var caps []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return ProbeResult{
					LocalAddr: conn.LocalAddr(),
					RTT:       time.Since(start),
					Err:       fmt.Errorf("failed to read smtp ehlo response: %w", err),
				}
			}
			trimmed := strings.TrimSpace(line)
			if len(trimmed) >= 4 && trimmed[:3] == "250" {
				capLine := strings.TrimSpace(trimmed[4:])
				if capLine != "" && !strings.HasPrefix(strings.ToLower(capLine), "hello ") {
					// Format capabilities nicely
					if strings.HasPrefix(strings.ToUpper(capLine), "SIZE ") {
						sizeVal := strings.TrimSpace(capLine[5:])
						caps = append(caps, fmt.Sprintf("SIZE(%s)", formatBytesSize(sizeVal)))
					} else if strings.HasPrefix(strings.ToUpper(capLine), "AUTH ") {
						caps = append(caps, fmt.Sprintf("AUTH(%s)", strings.TrimSpace(capLine[5:])))
					} else {
						caps = append(caps, capLine)
					}
				}
				if trimmed[3] == ' ' {
					break
				}
			}
		}

		if len(caps) > 0 {
			diagParts = append(diagParts, fmt.Sprintf("Caps: %s", strings.Join(caps, "|")))
		}

		// Optional STARTTLS negotiation
		if m.startTLS && !m.useTLS {
			if _, err := conn.Write([]byte("STARTTLS\r\n")); err != nil {
				return ProbeResult{
					LocalAddr: conn.LocalAddr(),
					RTT:       time.Since(start),
					Err:       fmt.Errorf("failed to send starttls command: %w", err),
				}
			}

			line, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "220") {
				return ProbeResult{
					LocalAddr: conn.LocalAddr(),
					RTT:       time.Since(start),
					Err:       fmt.Errorf("starttls negotiation rejected: %q", strings.TrimSpace(line)),
				}
			}

			tlsConn := tls.Client(conn, &tls.Config{
				ServerName: targetHost,
				// #nosec G402 -- diagnostic STARTTLS prober measuring handshake latency
				InsecureSkipVerify: true,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return ProbeResult{
					LocalAddr: conn.LocalAddr(),
					RTT:       time.Since(start),
					Err:       fmt.Errorf("starttls handshake failed: %w", err),
				}
			}
			tlsState := tlsConn.ConnectionState()
			tlsName := tls.VersionName(tlsState.Version)
			cipherName := tls.CipherSuiteName(tlsState.CipherSuite)
			diagParts = append(diagParts, fmt.Sprintf("STARTTLS: %s (%s)", tlsName, cipherName))
		}

	} else if m.protocol == MailIMAP {
		// Read * OK greeting
		greeting, err := reader.ReadString('\n')
		if err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("failed to read imap greeting: %w", err),
			}
		}
		cleanGreeting := strings.TrimSpace(greeting)
		if !strings.HasPrefix(cleanGreeting, "* OK") && !strings.HasPrefix(cleanGreeting, "* PREAUTH") {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("unexpected imap greeting: %q", cleanGreeting),
			}
		}
		diagParts = append(diagParts, fmt.Sprintf("Banner: %s", cleanGreeting))

		// Send A001 CAPABILITY
		if _, err := conn.Write([]byte("A001 CAPABILITY\r\n")); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("failed to send imap capability: %w", err),
			}
		}

		var imapCaps string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return ProbeResult{
					LocalAddr: conn.LocalAddr(),
					RTT:       time.Since(start),
					Err:       fmt.Errorf("failed to read imap capability response: %w", err),
				}
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToUpper(trimmed), "* CAPABILITY ") {
				imapCaps = strings.ReplaceAll(strings.TrimSpace(trimmed[13:]), " ", "|")
			}
			if strings.HasPrefix(trimmed, "A001 OK") {
				break
			}
		}

		if imapCaps != "" {
			diagParts = append(diagParts, fmt.Sprintf("Caps: %s", imapCaps))
		}

	} else if m.protocol == MailPOP3 {
		// Read +OK greeting
		greeting, err := reader.ReadString('\n')
		if err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("failed to read pop3 greeting: %w", err),
			}
		}
		cleanGreeting := strings.TrimSpace(greeting)
		if !strings.HasPrefix(cleanGreeting, "+OK") {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("unexpected pop3 greeting: %q", cleanGreeting),
			}
		}
		diagParts = append(diagParts, fmt.Sprintf("Banner: %s", cleanGreeting))

		// Send CAPA
		if _, err := conn.Write([]byte("CAPA\r\n")); err == nil {
			resp, err := reader.ReadString('\n')
			if err == nil && strings.HasPrefix(resp, "+OK") {
				var popCaps []string
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						break
					}
					trimmed := strings.TrimSpace(line)
					if trimmed == "." {
						break
					}
					popCaps = append(popCaps, trimmed)
				}
				if len(popCaps) > 0 {
					diagParts = append(diagParts, fmt.Sprintf("Caps: %s", strings.Join(popCaps, "|")))
				}
			}
		}
	}

	rtt := time.Since(start)

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: strings.Join(diagParts, ", "),
		Err:         nil,
	}
}
