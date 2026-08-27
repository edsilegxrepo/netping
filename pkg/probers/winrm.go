// Package probers implements network and application-layer diagnostic probers for netping.
package probers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Standard WS-Management Identify SOAP request envelope
const wsmanIdentifyRequest = `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Header/>
  <s:Body>
    <wsmid:Identify/>
  </s:Body>
</s:Envelope>`

// WinRMOptions defines configuration parameters for the WinRM prober.
type WinRMOptions struct {
	Hostname  string
	IP        netip.Addr
	Port      uint16
	UseTLS    bool
	URI       string
	Timeout   time.Duration
	TLSConfig *tls.Config
	Dialer    *net.Dialer
	UseIPv4   bool
	UseIPv6   bool
}

// WinRMing implements probers.Pinger for Windows Remote Management (WS-Management).
type WinRMing struct {
	hostname  string
	ip        netip.Addr
	port      uint16
	useTLS    bool
	uri       string
	timeout   time.Duration
	tlsConfig *tls.Config
	dialer    *net.Dialer
}

// WSManIdentifyResponse captures the XML schema for WS-Management identify responses.
type WSManIdentifyResponse struct {
	XMLName          xml.Name `xml:"Envelope"`
	ProtocolVersion  string   `xml:"Body>IdentifyResponse>ProtocolVersion"`
	ProductVendor    string   `xml:"Body>IdentifyResponse>ProductVendor"`
	ProductVersion   string   `xml:"Body>IdentifyResponse>ProductVersion"`
	SecurityProfiles []string `xml:"Body>IdentifyResponse>SecurityProfiles>SecurityProfileName"`
}

// NewWinRMing constructs an initialized WinRMing prober.
func NewWinRMing(opts WinRMOptions) *WinRMing {
	port := opts.Port
	if port == 0 {
		if opts.UseTLS {
			port = 5986
		} else {
			port = 5985
		}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tlsConfig := opts.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		}
	}
	if tlsConfig.ServerName == "" && opts.Hostname != "" {
		tlsConfig.ServerName = opts.Hostname
	}
	dialer := opts.Dialer
	if dialer == nil {
		dialer = &net.Dialer{
			Timeout: timeout,
		}
	}

	return &WinRMing{
		hostname:  opts.Hostname,
		ip:        opts.IP,
		port:      port,
		useTLS:    opts.UseTLS,
		uri:       opts.URI,
		timeout:   timeout,
		tlsConfig: tlsConfig,
		dialer:    dialer,
	}
}

// Ping executes the WinRM WS-Management diagnostic probe.
func (w *WinRMing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	reqURL, err := w.buildTargetURL()
	if err != nil {
		return ProbeResult{RTT: time.Since(start), Err: fmt.Errorf("invalid winrm target url: %w", err)}
	}

	var dnsStart, dnsDone time.Time
	var tcpStart, tcpDone time.Time
	var tlsStart, tlsDone time.Time
	var firstByte time.Time
	var localAddr net.Addr
	var certExpiry time.Time
	var tlsState *tls.ConnectionState

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			dnsDone = time.Now()
		},
		ConnectStart: func(network, addr string) {
			tcpStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			tcpDone = time.Now()
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsDone = time.Now()
			tlsState = &state
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

	reqCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	bodyReader := bytes.NewReader([]byte(wsmanIdentifyRequest))
	httpReq, err := http.NewRequestWithContext(httptrace.WithClientTrace(reqCtx, trace), http.MethodPost, reqURL.String(), bodyReader)
	if err != nil {
		return ProbeResult{RTT: time.Since(start), Err: fmt.Errorf("failed to create winrm http request: %w", err)}
	}

	httpReq.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	httpReq.Header.Set("User-Agent", "netping-winrm/0.6.2")

	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       w.tlsConfig.Clone(),
		ResponseHeaderTimeout: w.timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialAddr := addr
			if w.ip.IsValid() {
				dialAddr = net.JoinHostPort(w.ip.String(), fmt.Sprintf("%d", w.port))
			}
			return w.dialer.DialContext(ctx, network, dialAddr)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("stopped after 3 redirects")
			}
			return nil
		},
	}

	resp, err := client.Do(httpReq)
	rtt := time.Since(start)

	if err != nil {
		return ProbeResult{
			LocalAddr:  localAddr,
			RTT:        rtt,
			DNSTime:    timeSubOrZero(dnsDone, dnsStart),
			TCPTime:    timeSubOrZero(tcpDone, tcpStart),
			TLSTime:    timeSubOrZero(tlsDone, tlsStart),
			TTFB:       timeSubOrZero(firstByte, start),
			CertExpiry: certExpiry,
			Err:        err,
		}
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil && err != io.EOF {
		return ProbeResult{
			LocalAddr:  localAddr,
			RTT:        rtt,
			HTTPStatus: resp.StatusCode,
			DNSTime:    timeSubOrZero(dnsDone, dnsStart),
			TCPTime:    timeSubOrZero(tcpDone, tcpStart),
			TLSTime:    timeSubOrZero(tlsDone, tlsStart),
			TTFB:       timeSubOrZero(firstByte, start),
			CertExpiry: certExpiry,
			Err:        fmt.Errorf("failed to read winrm response body: %w", err),
		}
	}

	// Status 200 OK or 401 Unauthorized (with WWW-Authenticate challenge) indicates a live, responding WinRM service
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		return ProbeResult{
			LocalAddr:  localAddr,
			RTT:        rtt,
			HTTPStatus: resp.StatusCode,
			DNSTime:    timeSubOrZero(dnsDone, dnsStart),
			TCPTime:    timeSubOrZero(tcpDone, tcpStart),
			TLSTime:    timeSubOrZero(tlsDone, tlsStart),
			TTFB:       timeSubOrZero(firstByte, start),
			CertExpiry: certExpiry,
			Err:        fmt.Errorf("winrm endpoint returned unexpected HTTP status %d %s", resp.StatusCode, resp.Status),
		}
	}

	diags := w.parseDiagnostics(resp, bodyBytes, tlsState)

	return ProbeResult{
		LocalAddr:   localAddr,
		RTT:         rtt,
		HTTPStatus:  resp.StatusCode,
		Diagnostics: diags,
		DNSTime:     timeSubOrZero(dnsDone, dnsStart),
		TCPTime:     timeSubOrZero(tcpDone, tcpStart),
		TLSTime:     timeSubOrZero(tlsDone, tlsStart),
		TTFB:        timeSubOrZero(firstByte, start),
		CertExpiry:  certExpiry,
		Err:         nil,
	}
}

// buildTargetURL constructs the canonical WinRM HTTP/HTTPS URL.
func (w *WinRMing) buildTargetURL() (*url.URL, error) {
	raw := w.uri
	if raw == "" {
		raw = w.hostname
	}
	if raw == "" && w.ip.IsValid() {
		raw = w.ip.String()
	}
	if raw == "" {
		return nil, fmt.Errorf("no target host or uri specified for winrm")
	}

	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		if w.useTLS {
			raw = "https://" + raw
		} else {
			raw = "http://" + raw
		}
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid host in winrm url: %s", raw)
	}

	if !strings.Contains(parsed.Host, ":") && w.port != 0 && w.port != 80 && w.port != 443 {
		parsed.Host = net.JoinHostPort(parsed.Host, fmt.Sprintf("%d", w.port))
	}

	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/wsman"
	}

	return parsed, nil
}

// parseDiagnostics parses WS-Management XML and HTTP headers into structured diagnostic lines.
func (w *WinRMing) parseDiagnostics(resp *http.Response, body []byte, tlsState *tls.ConnectionState) string {
	var lines []string

	// 1. Check for XML IdentifyResponse
	var identify WSManIdentifyResponse
	if err := xml.Unmarshal(body, &identify); err == nil && (identify.ProductVendor != "" || identify.ProductVersion != "") {
		if identify.ProductVendor != "" {
			lines = append(lines, fmt.Sprintf("Vendor: %s", identify.ProductVendor))
		}
		if identify.ProductVersion != "" {
			lines = append(lines, fmt.Sprintf("ProductVersion: %s", identify.ProductVersion))
		}
		if identify.ProtocolVersion != "" {
			lines = append(lines, fmt.Sprintf("ProtocolVersion: %s", identify.ProtocolVersion))
		}
		if len(identify.SecurityProfiles) > 0 {
			lines = append(lines, fmt.Sprintf("SecurityProfiles: %s", strings.Join(identify.SecurityProfiles, ", ")))
		}
	}

	// 2. Extract Auth Schemes from WWW-Authenticate headers
	authHeaders := resp.Header.Values("WWW-Authenticate")
	if len(authHeaders) > 0 {
		var schemes []string
		for _, hdr := range authHeaders {
			for _, part := range strings.Split(hdr, ",") {
				fields := strings.Fields(strings.TrimSpace(part))
				if len(fields) > 0 {
					scheme := fields[0]
					if !containsString(schemes, scheme) {
						schemes = append(schemes, scheme)
					}
				}
			}
		}
		if len(schemes) > 0 {
			lines = append(lines, fmt.Sprintf("AuthSchemes: %s", strings.Join(schemes, ", ")))
		}
	}

	// 3. Server Header
	if srv := resp.Header.Get("Server"); srv != "" {
		lines = append(lines, fmt.Sprintf("Server: %s", srv))
	}

	// 4. TLS Security Info
	if tlsState != nil {
		lines = append(lines, fmt.Sprintf("TLSVersion: %s", tlsVersionToString(tlsState.Version)))
		lines = append(lines, fmt.Sprintf("CipherSuite: %s", tls.CipherSuiteName(tlsState.CipherSuite)))
		if len(tlsState.PeerCertificates) > 0 {
			cert := tlsState.PeerCertificates[0]
			daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
			lines = append(lines, fmt.Sprintf("CertExpiry: %s (%dd remaining)", cert.NotAfter.Format("2006-01-02"), daysRemaining))
		}
	}

	return strings.Join(lines, " | ")
}

func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}
