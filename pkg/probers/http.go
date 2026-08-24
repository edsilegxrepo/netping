package probers

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
)

type HTTPOptions struct {
	Hostname   string
	IP         netip.Addr
	Port       uint16
	Protocol   consts.Protocol
	Timeout    time.Duration
	Dialer     *net.Dialer
	SendData   string
	ExpectData string
}

// HTTPing implements Pinger for HTTP and HTTPS protocols with full timing breakdown.
type HTTPing struct {
	client     *http.Client
	url        string
	hostname   string
	ip         netip.Addr
	port       uint16
	protocol   consts.Protocol
	timeout    time.Duration
	sendData   string
	expectData string
}

// NewHTTPing constructs a new HTTP/HTTPS prober.
func NewHTTPing(opts HTTPOptions) *HTTPing {
	port := opts.Port
	if port == 0 {
		if opts.Protocol == consts.HTTPS {
			port = 443
		} else {
			port = 80
		}
	}

	scheme := "http"
	if opts.Protocol == consts.HTTPS {
		scheme = "https"
	}

	target := opts.Hostname
	if target == "" {
		target = opts.IP.String()
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, target, port)

	dialer := opts.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: opts.Timeout}
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if opts.IP.IsValid() {
			addr = net.JoinHostPort(opts.IP.String(), fmt.Sprintf("%d", port))
		}
		return dialer.DialContext(ctx, network, addr)
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         opts.Hostname,
		},
		DialContext: dialContext,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &HTTPing{
		client:     client,
		url:        url,
		hostname:   opts.Hostname,
		ip:         opts.IP,
		port:       port,
		protocol:   opts.Protocol,
		timeout:    opts.Timeout,
		sendData:   opts.SendData,
		expectData: opts.ExpectData,
	}
}

// Ping executes an HTTP/HTTPS probe with httptrace timing collection.
func (h *HTTPing) Ping(ctx context.Context) ProbeResult {
	method := http.MethodHead
	var reqBody io.Reader
	if h.sendData != "" {
		method = http.MethodPost
		reqBody = strings.NewReader(h.sendData)
	} else if h.expectData != "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, h.url, reqBody)
	if err != nil {
		return ProbeResult{Err: err}
	}
	req.Header.Set("User-Agent", "netping/1.0")
	req.Header.Set("Accept", "*/*")
	if h.sendData != "" {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	var (
		start          = time.Now()
		dnsStart       time.Time
		dnsDone        time.Time
		connStart      time.Time
		connDone       time.Time
		tlsStart       time.Time
		tlsDone        time.Time
		firstByte      time.Time
		localAddr      net.Addr
		certExpiry     time.Time
		tlsVersion     uint16
		tlsCipherSuite uint16
		alpnProto      string
	)

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			dnsDone = time.Now()
		},
		ConnectStart: func(_, _ string) {
			connStart = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) {
			connDone = time.Now()
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, _ error) {
			tlsDone = time.Now()
			tlsVersion = state.Version
			tlsCipherSuite = state.CipherSuite
			alpnProto = state.NegotiatedProtocol
			if len(state.PeerCertificates) > 0 {
				certExpiry = state.PeerCertificates[0].NotAfter
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				localAddr = info.Conn.LocalAddr()
			}
		},
		GotFirstResponseByte: func() {
			firstByte = time.Now()
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := h.client.Do(req)
	totalRTT := time.Since(start)
	if !firstByte.IsZero() {
		if !dnsStart.IsZero() {
			totalRTT = firstByte.Sub(dnsStart)
		} else if !connStart.IsZero() {
			totalRTT = firstByte.Sub(connStart)
		}
	} else if !connDone.IsZero() && !connStart.IsZero() {
		totalRTT = connDone.Sub(connStart)
	}

	if err != nil {
		return ProbeResult{
			LocalAddr: localAddr,
			RTT:       totalRTT,
			Err:       err,
		}
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	respBodyStr := string(bodyBytes)

	if resp.TLS != nil {
		if tlsVersion == 0 {
			tlsVersion = resp.TLS.Version
		}
		if tlsCipherSuite == 0 {
			tlsCipherSuite = resp.TLS.CipherSuite
		}
		if alpnProto == "" {
			alpnProto = resp.TLS.NegotiatedProtocol
		}
	}

	var dnsTime, tcpTime, tlsTime, ttfb time.Duration
	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		dnsTime = dnsDone.Sub(dnsStart)
	}
	if !connStart.IsZero() && !connDone.IsZero() {
		tcpTime = connDone.Sub(connStart)
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		tlsTime = tlsDone.Sub(tlsStart)
	}
	if !firstByte.IsZero() {
		ttfb = firstByte.Sub(start)
	}

	if h.expectData != "" && !strings.Contains(respBodyStr, h.expectData) {
		snippet := strings.TrimSpace(respBodyStr)
		if len(snippet) > 64 {
			snippet = snippet[:64] + "..."
		}
		return ProbeResult{
			LocalAddr:  localAddr,
			RTT:        totalRTT,
			DNSTime:    dnsTime,
			TCPTime:    tcpTime,
			TLSTime:    tlsTime,
			TTFB:       ttfb,
			HTTPStatus: resp.StatusCode,
			CertExpiry: certExpiry,
			Err:        fmt.Errorf("expected %q in response, received %q", h.expectData, snippet),
		}
	}

	var diagParts []string
	diagParts = append(diagParts, fmt.Sprintf("Status: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode)))
	if h.sendData != "" {
		diagParts = append(diagParts, fmt.Sprintf("Sent: %dB", len(h.sendData)))
	}
	if h.expectData != "" {
		diagParts = append(diagParts, fmt.Sprintf("Matched: %q", h.expectData))
	}
	if srv := resp.Header.Get("Server"); srv != "" {
		diagParts = append(diagParts, fmt.Sprintf("Server: %s", srv))
	}
	if proto := resp.Proto; proto != "" {
		if alpnProto != "" && alpnProto != strings.ToLower(proto) {
			diagParts = append(diagParts, fmt.Sprintf("Proto: %s (%s)", proto, alpnProto))
		} else {
			diagParts = append(diagParts, fmt.Sprintf("Proto: %s", proto))
		}
	}
	if tlsVersion != 0 {
		tlsVerName := tls.VersionName(tlsVersion)
		cipherName := tls.CipherSuiteName(tlsCipherSuite)
		if cipherName != "" && cipherName != "0x0000" {
			diagParts = append(diagParts, fmt.Sprintf("TLS: %s, Cipher: %s", tlsVerName, cipherName))
		} else if tlsVerName != "" {
			diagParts = append(diagParts, fmt.Sprintf("TLS: %s", tlsVerName))
		}
	}
	if !certExpiry.IsZero() {
		days := int(time.Until(certExpiry).Hours() / 24)
		diagParts = append(diagParts, fmt.Sprintf("CertValid: %s (%dd left)", certExpiry.Format("2006-01-02"), days))
	}
	if ttfb > 0 {
		diagParts = append(diagParts, fmt.Sprintf("TTFB: %.2fms [DNS:%.1fms TCP:%.1fms TLS:%.1fms]",
			ttfb.Seconds()*1000, dnsTime.Seconds()*1000, tcpTime.Seconds()*1000, tlsTime.Seconds()*1000))
	}

	return ProbeResult{
		LocalAddr:   localAddr,
		RTT:         totalRTT,
		DNSTime:     dnsTime,
		TCPTime:     tcpTime,
		TLSTime:     tlsTime,
		TTFB:        ttfb,
		HTTPStatus:  resp.StatusCode,
		CertExpiry:  certExpiry,
		Diagnostics: strings.Join(diagParts, " │ "),
		Err:         nil,
	}
}
