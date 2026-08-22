package probers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type SSHOptions struct {
	Hostname string
	IP       netip.Addr
	Port     uint16
	Timeout  time.Duration
	Dialer   *net.Dialer
}

// SSHing implements Pinger for SSH RFC 4253 daemon protocol handshake and KEXINIT dissection.
type SSHing struct {
	hostname string
	ip       netip.Addr
	port     uint16
	timeout  time.Duration
	dialer   *net.Dialer
}

// NewSSHing constructs a new SSH prober.
func NewSSHing(opts SSHOptions) *SSHing {
	port := opts.Port
	if port == 0 {
		port = 22
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return &SSHing{
		hostname: opts.Hostname,
		ip:       opts.IP,
		port:     port,
		timeout:  opts.Timeout,
		dialer:   d,
	}
}

func readSSHNameList(r io.Reader) (string, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}
	if length > 65536 {
		return "", fmt.Errorf("name-list too large: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// formatTopItems takes a comma-separated name-list and returns the first N items joined with |.
func formatTopItems(nameList string, maxItems int) string {
	if nameList == "" {
		return "none"
	}
	parts := strings.Split(nameList, ",")
	if len(parts) > maxItems {
		parts = parts[:maxItems]
	}
	return strings.Join(parts, "|")
}

// Ping connects, exchanges SSH identification strings, and dissects the server's SSH_MSG_KEXINIT packet.
func (s *SSHing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	targetHost := s.hostname
	if targetHost == "" {
		targetHost = s.ip.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(s.port)))

	conn, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	reader := bufio.NewReader(conn)

	// Read server identification banner (RFC 4253 Section 4.2 allows preliminary comment lines)
	var serverBanner string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("failed to read SSH server banner: %w", err),
			}
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SSH-") {
			serverBanner = trimmed
			break
		}
	}

	// Send client identification banner
	clientBanner := "SSH-2.0-Netping_1.0\r\n"
	if _, err := conn.Write([]byte(clientBanner)); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("failed to write SSH client banner: %w", err),
		}
	}

	rtt := time.Since(start)

	// Dissect SSH_MSG_KEXINIT (RFC 4253 Section 7.1)
	var packetLen uint32
	if err := binary.Read(reader, binary.BigEndian, &packetLen); err != nil {
		// Fall back to banner diagnostics if server doesn't immediately send KEXINIT
		return ProbeResult{
			LocalAddr:   conn.LocalAddr(),
			RTT:         rtt,
			Diagnostics: fmt.Sprintf("Banner: %s", serverBanner),
			Err:         nil,
		}
	}

	if packetLen > 65536 || packetLen < 20 {
		return ProbeResult{
			LocalAddr:   conn.LocalAddr(),
			RTT:         rtt,
			Diagnostics: fmt.Sprintf("Banner: %s", serverBanner),
			Err:         nil,
		}
	}

	packetBytes := make([]byte, packetLen)
	if _, err := io.ReadFull(reader, packetBytes); err != nil {
		return ProbeResult{
			LocalAddr:   conn.LocalAddr(),
			RTT:         rtt,
			Diagnostics: fmt.Sprintf("Banner: %s", serverBanner),
			Err:         nil,
		}
	}

	paddingLen := int(packetBytes[0])
	payloadLen := int(packetLen) - paddingLen - 1
	if payloadLen <= 17 {
		return ProbeResult{
			LocalAddr:   conn.LocalAddr(),
			RTT:         rtt,
			Diagnostics: fmt.Sprintf("Banner: %s", serverBanner),
			Err:         nil,
		}
	}

	msgType := packetBytes[1]
	if msgType != 20 { // SSH_MSG_KEXINIT is 20 (0x14)
		return ProbeResult{
			LocalAddr:   conn.LocalAddr(),
			RTT:         rtt,
			Diagnostics: fmt.Sprintf("Banner: %s", serverBanner),
			Err:         nil,
		}
	}

	payloadReader := bytes.NewReader(packetBytes[2 : 1+payloadLen])
	// Skip 16-byte cookie
	if _, err := payloadReader.Seek(16, io.SeekStart); err != nil {
		return ProbeResult{
			LocalAddr:   conn.LocalAddr(),
			RTT:         rtt,
			Diagnostics: fmt.Sprintf("Banner: %s", serverBanner),
			Err:         nil,
		}
	}

	kexAlgs, _ := readSSHNameList(payloadReader)
	hostKeyAlgs, _ := readSSHNameList(payloadReader)
	encC2S, _ := readSSHNameList(payloadReader)
	_ = encC2S
	encS2C, _ := readSSHNameList(payloadReader)
	macC2S, _ := readSSHNameList(payloadReader)
	_ = macC2S
	macS2C, _ := readSSHNameList(payloadReader)
	compC2S, _ := readSSHNameList(payloadReader)

	// Construct rich diagnostics summary
	sw := strings.TrimPrefix(serverBanner, "SSH-2.0-")
	sw = strings.TrimPrefix(sw, "SSH-1.99-")

	var parts []string
	parts = append(parts, fmt.Sprintf("Software: %s", sw))

	if hostKeyAlgs != "" {
		parts = append(parts, fmt.Sprintf("HostKeys: %s", formatTopItems(hostKeyAlgs, 3)))
	}
	if kexAlgs != "" {
		parts = append(parts, fmt.Sprintf("KEX: %s", formatTopItems(kexAlgs, 2)))
	}
	if encS2C != "" {
		parts = append(parts, fmt.Sprintf("Ciphers: %s", formatTopItems(encS2C, 2)))
	}
	if macS2C != "" {
		parts = append(parts, fmt.Sprintf("MAC: %s", formatTopItems(macS2C, 2)))
	}
	if compC2S != "" && compC2S != "none" {
		parts = append(parts, fmt.Sprintf("Compress: %s", formatTopItems(compC2S, 2)))
	}

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: strings.Join(parts, ", "),
		Err:         nil,
	}
}
