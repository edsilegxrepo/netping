package probers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type DNSQueryOptions struct {
	Nameserver string
	IP         netip.Addr
	Port       uint16
	Domains    []string
	Domain     string
	IsDoH      bool
	IsDoT      bool
	Timeout    time.Duration
	Dialer     *net.Dialer
}

// DNSQueryProber probes standard DNS (UDP 53), DoT (RFC 7858, TLS 853), or DoH (RFC 8484, HTTPS 443).
type DNSQueryProber struct {
	nameserver string
	ip         netip.Addr
	port       uint16
	domains    []string
	queryIdx   uint64
	isDoH      bool
	isDoT      bool
	timeout    time.Duration
	dialer     *net.Dialer
	httpClient *http.Client
}

// NewDNSQueryProber creates a new DNS / DoT / DoH prober with multi-host support.
func NewDNSQueryProber(opts DNSQueryOptions) *DNSQueryProber {
	var domains []string
	for _, d := range opts.Domains {
		trimmed := strings.TrimSpace(d)
		if trimmed != "" {
			domains = append(domains, trimmed)
		}
	}
	if len(domains) == 0 {
		if opts.Domain != "" {
			domains = []string{strings.TrimSpace(opts.Domain)}
		} else {
			domains = []string{"google.com"}
		}
	}

	port := opts.Port
	if port == 0 {
		if opts.IsDoH {
			port = 443
		} else if opts.IsDoT {
			port = 853
		} else {
			port = 53
		}
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	var client *http.Client
	if opts.IsDoH {
		tr := &http.Transport{
			DisableKeepAlives: true,
			// #nosec G402 -- diagnostic DoH prober measuring endpoint latency
			// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification -- diagnostic prober measuring latency
			TLSClientConfig: &tls.Config{
				ServerName:         opts.Nameserver,
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
			DialContext: d.DialContext,
		}
		client = &http.Client{
			Transport: tr,
			Timeout:   opts.Timeout,
		}
	}

	return &DNSQueryProber{
		nameserver: opts.Nameserver,
		ip:         opts.IP,
		port:       port,
		domains:    domains,
		isDoH:      opts.IsDoH,
		isDoT:      opts.IsDoT,
		timeout:    opts.Timeout,
		dialer:     d,
		httpClient: client,
	}
}

// buildDNSQuery builds a standard wire-format DNS query packet for A record lookup.
func buildDNSQuery(domain string) []byte {
	var buf bytes.Buffer
	// Transaction ID (2 bytes)
	buf.Write([]byte{0xab, 0xcd})
	// Flags: Standard query, Recursion Desired (0x0100)
	buf.Write([]byte{0x01, 0x00})
	// Questions: 1 (0x0001)
	buf.Write([]byte{0x00, 0x01})
	// Answer RRs: 0
	buf.Write([]byte{0x00, 0x00})
	// Authority RRs: 0
	buf.Write([]byte{0x00, 0x00})
	// Additional RRs: 0
	buf.Write([]byte{0x00, 0x00})

	// Domain labels (e.g. google.com -> 6google3com0)
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			continue
		}
		// #nosec G115 -- DNS label length strictly bounded to <= 63 bytes
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0x00) // End of domain labels

	// Type A (0x0001)
	buf.Write([]byte{0x00, 0x01})
	// Class IN (0x0001)
	buf.Write([]byte{0x00, 0x01})

	return buf.Bytes()
}

// parseDNSName reads a domain name from the DNS packet supporting compression pointers (0xc0).
func parseDNSName(msg []byte, offset int) (string, int, error) {
	if offset >= len(msg) {
		return "", offset, fmt.Errorf("offset out of bounds")
	}

	var labels []string
	cur := offset
	jumped := false
	nextOffset := offset

	for {
		if cur >= len(msg) {
			return "", nextOffset, fmt.Errorf("malformed dns name")
		}
		length := int(msg[cur])
		if length == 0 {
			if !jumped {
				nextOffset = cur + 1
			}
			break
		}

		// Pointer check (top 2 bits set)
		if (length & 0xc0) == 0xc0 {
			if cur+1 >= len(msg) {
				return "", nextOffset, fmt.Errorf("malformed pointer")
			}
			ptr := int(binary.BigEndian.Uint16(msg[cur:cur+2]) & 0x3fff)
			if !jumped {
				nextOffset = cur + 2
				jumped = true
			}
			cur = ptr
			continue
		}

		cur++
		if cur+length > len(msg) {
			return "", nextOffset, fmt.Errorf("label exceeds packet")
		}
		labels = append(labels, string(msg[cur:cur+length]))
		cur += length
	}

	return strings.Join(labels, "."), nextOffset, nil
}

type parsedDNSReply struct {
	RcodeStr     string
	Flags        []string
	Answers      []string
	MinTTL       uint32
	QuestionsCnt uint16
	AnswersCnt   uint16
}

// dissectDNSResponse parses the full DNS response packet and extracts RCODE, Flags, Answers, and TTL.
func dissectDNSResponse(msg []byte) (*parsedDNSReply, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("dns response packet too short (%d bytes)", len(msg))
	}

	flags := binary.BigEndian.Uint16(msg[2:4])
	qdCount := binary.BigEndian.Uint16(msg[4:6])
	anCount := binary.BigEndian.Uint16(msg[6:8])

	rcode := flags & 0x0f
	var rcodeStr string
	switch rcode {
	case 0:
		rcodeStr = "NOERROR"
	case 1:
		rcodeStr = "FORMERR"
	case 2:
		rcodeStr = "SERVFAIL"
	case 3:
		rcodeStr = "NXDOMAIN"
	case 5:
		rcodeStr = "REFUSED"
	default:
		rcodeStr = fmt.Sprintf("RCODE_%d", rcode)
	}

	var flagList []string
	if (flags & 0x0400) != 0 {
		flagList = append(flagList, "AA")
	}
	if (flags & 0x0200) != 0 {
		flagList = append(flagList, "TC")
	}
	if (flags & 0x0100) != 0 {
		flagList = append(flagList, "RD")
	}
	if (flags & 0x0080) != 0 {
		flagList = append(flagList, "RA")
	}

	offset := 12
	// Skip Question section
	for i := 0; i < int(qdCount); i++ {
		_, newOffset, err := parseDNSName(msg, offset)
		if err != nil {
			break
		}
		offset = newOffset + 4 // Skip Type (2) + Class (2)
		if offset > len(msg) {
			break
		}
	}

	var answers []string
	var minTTL uint32 = 0

	// Parse Answer section
	for i := 0; i < int(anCount); i++ {
		if offset >= len(msg) {
			break
		}
		_, newOffset, err := parseDNSName(msg, offset)
		if err != nil {
			break
		}
		offset = newOffset
		if offset+10 > len(msg) {
			break
		}

		rrType := binary.BigEndian.Uint16(msg[offset : offset+2])
		ttl := binary.BigEndian.Uint32(msg[offset+4 : offset+8])
		rdLength := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
		offset += 10

		if minTTL == 0 || (ttl > 0 && ttl < minTTL) {
			minTTL = ttl
		}

		if offset+rdLength > len(msg) {
			break
		}

		rdata := msg[offset : offset+rdLength]
		if rrType == 1 && rdLength == 4 { // Type A (IPv4)
			answers = append(answers, net.IP(rdata).String())
		} else if rrType == 28 && rdLength == 16 { // Type AAAA (IPv6)
			answers = append(answers, net.IP(rdata).String())
		} else if rrType == 5 { // CNAME
			cname, _, err := parseDNSName(msg, offset)
			if err == nil && cname != "" {
				answers = append(answers, fmt.Sprintf("CNAME->%s", cname))
			}
		}

		offset += rdLength
	}

	return &parsedDNSReply{
		RcodeStr:     rcodeStr,
		Flags:        flagList,
		Answers:      answers,
		MinTTL:       minTTL,
		QuestionsCnt: qdCount,
		AnswersCnt:   anCount,
	}, nil
}

// Ping sends a DNS query over UDP, DoT (TLS 853), or DoH (HTTPS 443) and extracts deep diagnostics.
func (d *DNSQueryProber) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	// Select current target domain from domain list
	idx := atomic.AddUint64(&d.queryIdx, 1) - 1
	currentDomain := d.domains[idx%uint64(len(d.domains))]
	queryBytes := buildDNSQuery(currentDomain)

	if d.isDoH {
		// DoH (RFC 8484)
		target := d.nameserver
		if target == "" {
			target = d.ip.String()
		}
		url := fmt.Sprintf("https://%s:%d/dns-query", target, d.port)
		if d.port == 443 {
			url = fmt.Sprintf("https://%s/dns-query", target)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(queryBytes))
		if err != nil {
			return ProbeResult{Err: err}
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")

		resp, err := d.httpClient.Do(req)
		rtt := time.Since(start)
		if err != nil {
			return ProbeResult{
				RTT: rtt,
				Err: err,
			}
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			return ProbeResult{
				RTT:        rtt,
				HTTPStatus: resp.StatusCode,
				Err:        fmt.Errorf("doh query failed with status %d %s", resp.StatusCode, resp.Status),
			}
		}

		respBody, err := io.ReadAll(resp.Body)
		if err != nil || len(respBody) < 12 {
			return ProbeResult{
				RTT:        rtt,
				HTTPStatus: resp.StatusCode,
				Err:        fmt.Errorf("invalid doh dns response payload"),
			}
		}

		parsed, err := dissectDNSResponse(respBody)
		if err != nil {
			return ProbeResult{
				RTT:        rtt,
				HTTPStatus: resp.StatusCode,
				Err:        err,
			}
		}

		var diagParts []string
		diagParts = append(diagParts, fmt.Sprintf("Query: %s (A)", currentDomain))
		diagParts = append(diagParts, fmt.Sprintf("RCODE: %s", parsed.RcodeStr))
		if len(parsed.Flags) > 0 {
			diagParts = append(diagParts, fmt.Sprintf("Flags: %s", strings.Join(parsed.Flags, "|")))
		}
		if len(parsed.Answers) > 0 {
			diagParts = append(diagParts, fmt.Sprintf("Answers: [%s]", strings.Join(parsed.Answers, ", ")))
			if parsed.MinTTL > 0 {
				diagParts = append(diagParts, fmt.Sprintf("TTL: %ds", parsed.MinTTL))
			}
		}

		return ProbeResult{
			RTT:         rtt,
			HTTPStatus:  resp.StatusCode,
			Diagnostics: strings.Join(diagParts, " │ "),
			Err:         nil,
		}
	}

	target := d.nameserver
	if target == "" {
		target = d.ip.String()
	}
	addr := net.JoinHostPort(target, strconv.Itoa(int(d.port)))

	if d.isDoT {
		// DoT (RFC 7858 - DNS over TLS)
		// #nosec G402 -- diagnostic DoT prober measuring endpoint latency
		// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification -- diagnostic prober measuring latency
		tlsConfig := &tls.Config{
			ServerName:         target,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
		tlsDialer := &tls.Dialer{
			NetDialer: d.dialer,
			Config:    tlsConfig,
		}
		conn, err := tlsDialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return ProbeResult{
				RTT: time.Since(start),
				Err: err,
			}
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(d.timeout))

		var tlsDetails string
		if tc, ok := conn.(*tls.Conn); ok {
			state := tc.ConnectionState()
			tlsDetails = fmt.Sprintf("TLS: %s (%s)", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))
		}

		// 2-byte length prefix for TCP/DoT
		lenBuf := make([]byte, 2)
		// #nosec G115 -- DNS wire query size bounded to standard UDP/TCP buffer
		binary.BigEndian.PutUint16(lenBuf, uint16(len(queryBytes)))

		if _, err := conn.Write(append(lenBuf, queryBytes...)); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("dot query write failed: %w", err),
			}
		}

		respLenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, respLenBuf); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("dot length read failed: %w", err),
			}
		}

		respLen := binary.BigEndian.Uint16(respLenBuf)
		reply := make([]byte, respLen)
		if _, err := io.ReadFull(conn, reply); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("dot response read failed: %w", err),
			}
		}
		rtt := time.Since(start)

		parsed, err := dissectDNSResponse(reply)
		if err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       rtt,
				Err:       err,
			}
		}

		var diagParts []string
		if tlsDetails != "" {
			diagParts = append(diagParts, tlsDetails)
		}
		diagParts = append(diagParts, fmt.Sprintf("Query: %s (A)", currentDomain))
		diagParts = append(diagParts, fmt.Sprintf("RCODE: %s", parsed.RcodeStr))
		if len(parsed.Flags) > 0 {
			diagParts = append(diagParts, fmt.Sprintf("Flags: %s", strings.Join(parsed.Flags, "|")))
		}
		if len(parsed.Answers) > 0 {
			diagParts = append(diagParts, fmt.Sprintf("Answers: [%s]", strings.Join(parsed.Answers, ", ")))
			if parsed.MinTTL > 0 {
				diagParts = append(diagParts, fmt.Sprintf("TTL: %ds", parsed.MinTTL))
			}
		}

		return ProbeResult{
			LocalAddr:   conn.LocalAddr(),
			RTT:         rtt,
			Diagnostics: strings.Join(diagParts, " │ "),
			Err:         nil,
		}
	}

	// Standard DNS over UDP 53
	conn, err := d.dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(d.timeout))

	if _, err := conn.Write(queryBytes); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("dns query send failed: %w", err),
		}
	}

	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	rtt := time.Since(start)
	if err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       rtt,
			Err:       err,
		}
	}

	parsed, err := dissectDNSResponse(reply[:n])
	if err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       rtt,
			Err:       err,
		}
	}

	var diagParts []string
	diagParts = append(diagParts, fmt.Sprintf("Query: %s (A)", currentDomain))
	diagParts = append(diagParts, fmt.Sprintf("RCODE: %s", parsed.RcodeStr))
	if len(parsed.Flags) > 0 {
		diagParts = append(diagParts, fmt.Sprintf("Flags: %s", strings.Join(parsed.Flags, "|")))
	}
	if len(parsed.Answers) > 0 {
		diagParts = append(diagParts, fmt.Sprintf("Answers: [%s]", strings.Join(parsed.Answers, ", ")))
		if parsed.MinTTL > 0 {
			diagParts = append(diagParts, fmt.Sprintf("TTL: %ds", parsed.MinTTL))
		}
	}

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: strings.Join(diagParts, " │ "),
		Err:         nil,
	}
}
