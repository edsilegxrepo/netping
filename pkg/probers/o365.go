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
)

type O365Options struct {
	Hostname   string
	IP         netip.Addr
	Port       uint16
	SkipVerify bool
	Timeout    time.Duration
	Dialer     *net.Dialer
}

// O365ing implements Pinger for Microsoft 365 / Exchange Online / Graph Front Door service health probing.
type O365ing struct {
	hostname   string
	ip         netip.Addr
	port       uint16
	timeout    time.Duration
	url        string
	httpClient *http.Client
}

// NewO365ing constructs a new Microsoft 365 service endpoint prober.
func NewO365ing(opts O365Options) *O365ing {
	port := opts.Port
	if port == 0 {
		port = 443
	}

	target := opts.Hostname
	if target == "" {
		if opts.IP.IsValid() {
			target = opts.IP.String()
		} else {
			target = "outlook.office365.com"
		}
	}

	var url string
	switch {
	case strings.Contains(target, "graph.microsoft.com"):
		url = fmt.Sprintf("https://%s:%d/v1.0/$metadata", target, port)
	case strings.Contains(target, "login.microsoftonline.com"):
		url = fmt.Sprintf("https://%s:%d/common/v2.0/.well-known/openid-configuration", target, port)
	case strings.Contains(target, "outlook.office365.com") || strings.Contains(target, "outlook.office.com"):
		url = fmt.Sprintf("https://%s:%d/autodiscover/autodiscover.json/v1.0", target, port)
	default:
		url = fmt.Sprintf("https://%s:%d/autodiscover/autodiscover.json/v1.0", target, port)
	}

	dialContext := (&net.Dialer{Timeout: opts.Timeout}).DialContext
	if opts.Dialer != nil {
		dialContext = opts.Dialer.DialContext
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			ServerName: opts.Hostname,
			// #nosec G402 -- user-configurable TLS verification flag for endpoint probing
			// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification -- user-configurable TLS verification flag
			InsecureSkipVerify: opts.SkipVerify,
			MinVersion:         tls.VersionTLS12,
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

	return &O365ing{
		hostname:   target,
		ip:         opts.IP,
		port:       port,
		timeout:    opts.Timeout,
		url:        url,
		httpClient: client,
	}
}

// Ping executes an unauthenticated HTTP GET request against Microsoft 365 Front Door and measures timing breakdown.
func (o *O365ing) Ping(ctx context.Context) ProbeResult {
	var (
		dnsStart, dnsEnd time.Time
		tcpStart, tcpEnd time.Time
		tlsStart, tlsEnd time.Time
		localAddr        net.Addr
	)

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { dnsEnd = time.Now() },
		ConnectStart: func(_, _ string) {
			if dnsStart.IsZero() {
				dnsStart = time.Now()
				dnsEnd = dnsStart
			}
			tcpStart = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) { tcpEnd = time.Now() },
		TLSHandshakeStart: func() {
			if tcpStart.IsZero() {
				tcpStart = time.Now()
				tcpEnd = tcpStart
			}
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) { tlsEnd = time.Now() },
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				localAddr = info.Conn.LocalAddr()
			}
		},
	}

	reqCtx := httptrace.WithClientTrace(ctx, trace)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, o.url, nil)
	if err != nil {
		return ProbeResult{Err: err}
	}
	req.Header.Set("User-Agent", "netping/o365-prober")
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := o.httpClient.Do(req)
	rtt := time.Since(start)
	if err != nil {
		return ProbeResult{
			LocalAddr: localAddr,
			RTT:       rtt,
			Err:       err,
		}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	var dnsTime, tcpTime, tlsTime time.Duration
	if !dnsStart.IsZero() && !dnsEnd.IsZero() {
		dnsTime = dnsEnd.Sub(dnsStart)
	}
	if !tcpStart.IsZero() && !tcpEnd.IsZero() {
		tcpTime = tcpEnd.Sub(tcpStart)
	}
	if !tlsStart.IsZero() && !tlsEnd.IsZero() {
		tlsTime = tlsEnd.Sub(tlsStart)
	}

	var certExpiry time.Time
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		certExpiry = resp.TLS.PeerCertificates[0].NotAfter
	}

	var diagParts []string
	diagParts = append(diagParts, fmt.Sprintf("HTTP: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode)))

	if resp.TLS != nil {
		diagParts = append(diagParts, fmt.Sprintf("TLS: %s (%s)", tls.VersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite)))
	}

	if srv := resp.Header.Get("Server"); srv != "" {
		diagParts = append(diagParts, fmt.Sprintf("Server: %s", srv))
	}
	if fe := resp.Header.Get("X-FEServer"); fe != "" {
		diagParts = append(diagParts, fmt.Sprintf("FE: %s", fe))
	} else if be := resp.Header.Get("X-CalculatedBETarget"); be != "" {
		diagParts = append(diagParts, fmt.Sprintf("BE: %s", be))
	} else if reqId := resp.Header.Get("request-id"); reqId != "" {
		diagParts = append(diagParts, fmt.Sprintf("ReqID: %s", reqId))
	}

	if !certExpiry.IsZero() {
		days := int(time.Until(certExpiry).Hours() / 24)
		if days > 0 {
			diagParts = append(diagParts, fmt.Sprintf("Cert: %dd left", days))
		}
	}

	return ProbeResult{
		LocalAddr:   localAddr,
		RTT:         rtt,
		DNSTime:     dnsTime,
		TCPTime:     tcpTime,
		TLSTime:     tlsTime,
		HTTPStatus:  resp.StatusCode,
		CertExpiry:  certExpiry,
		Diagnostics: strings.Join(diagParts, ", "),
		Err:         nil,
	}
}
