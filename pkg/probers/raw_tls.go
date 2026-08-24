package probers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type TLSOptions struct {
	Hostname   string
	IP         netip.Addr
	Port       uint16
	Timeout    time.Duration
	Dialer     *net.Dialer
	FastClose  bool
	SkipVerify bool
}

// TLSing implements Pinger for raw TLS 1.2/1.3 handshakes on any port.
type TLSing struct {
	hostname   string
	ip         netip.Addr
	port       uint16
	timeout    time.Duration
	dialer     *net.Dialer
	fastClose  bool
	skipVerify bool
}

// NewTLSing constructs a new TLS handshake prober.
func NewTLSing(opts TLSOptions) *TLSing {
	port := opts.Port
	if port == 0 {
		port = 443
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return &TLSing{
		hostname:   opts.Hostname,
		ip:         opts.IP,
		port:       port,
		timeout:    opts.Timeout,
		dialer:     d,
		fastClose:  opts.FastClose,
		skipVerify: opts.SkipVerify,
	}
}

// Ping connects to the target port, completes TLS 1.2/1.3 handshake, records cert expiry, and measures RTT.
func (t *TLSing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	targetHost := t.hostname
	if targetHost == "" {
		targetHost = t.ip.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(t.port)))

	// First establish raw TCP connection
	tcpConn, err := t.dialer.DialContext(ctx, "tcp", addr)
	tcpRTT := time.Since(start)
	if err != nil {
		return ProbeResult{
			RTT: tcpRTT,
			Err: err,
		}
	}
	defer tcpConn.Close()

	if realTCP, ok := tcpConn.(*net.TCPConn); ok && t.fastClose {
		_ = realTCP.SetLinger(0)
	}

	_ = tcpConn.SetDeadline(time.Now().Add(t.timeout))

	tlsConfig := &tls.Config{
		ServerName: targetHost,
		// #nosec G402 -- user-configurable TLS certificate verification for latency probing
		InsecureSkipVerify: t.skipVerify,
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	tlsStart := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return ProbeResult{
			LocalAddr: tcpConn.LocalAddr(),
			RTT:       time.Since(start),
			TCPTime:   tcpRTT,
			Err:       err,
		}
	}
	tlsRTT := time.Since(tlsStart)
	totalRTT := time.Since(start)

	var certExpiry time.Time
	var diagParts []string
	state := tlsConn.ConnectionState()
	tlsVer := tls.VersionName(state.Version)
	diagParts = append(diagParts, fmt.Sprintf("Version: %s", tlsVer))
	if cipherName := tls.CipherSuiteName(state.CipherSuite); cipherName != "" {
		diagParts = append(diagParts, fmt.Sprintf("Cipher: %s", cipherName))
	}
	if state.NegotiatedProtocol != "" {
		diagParts = append(diagParts, fmt.Sprintf("ALPN: %s", state.NegotiatedProtocol))
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		certExpiry = leaf.NotAfter
		subj := leaf.Subject.CommonName
		if subj == "" && len(leaf.DNSNames) > 0 {
			subj = leaf.DNSNames[0]
		}
		issuer := leaf.Issuer.CommonName
		if issuer == "" && len(leaf.Issuer.Organization) > 0 {
			issuer = leaf.Issuer.Organization[0]
		}
		daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
		diagParts = append(diagParts, fmt.Sprintf("Cert: %s (Issuer: %s, Valid: %s, %dd left)", subj, issuer, leaf.NotAfter.Format("2006-01-02"), daysLeft))
	}
	diagParts = append(diagParts, fmt.Sprintf("Timing: [TCP:%.1fms TLS:%.1fms]", tcpRTT.Seconds()*1000, tlsRTT.Seconds()*1000))

	return ProbeResult{
		LocalAddr:   tcpConn.LocalAddr(),
		RTT:         totalRTT,
		TCPTime:     tcpRTT,
		TLSTime:     tlsRTT,
		CertExpiry:  certExpiry,
		Diagnostics: strings.Join(diagParts, " │ "),
		Err:         nil,
	}
}
