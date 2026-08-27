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
	Method     string
	UserAgent  string
	WAFMode    bool
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
	method     string
	userAgent  string
	wafMode    bool
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

	var url string
	if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
		url = fmt.Sprintf("%s://%s/", scheme, target)
	} else {
		url = fmt.Sprintf("%s://%s:%d/", scheme, target, port)
	}

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

	method := strings.ToUpper(strings.TrimSpace(opts.Method))
	if method == "" {
		if opts.SendData != "" {
			method = http.MethodPost
		} else if opts.ExpectData != "" || opts.WAFMode {
			method = http.MethodGet
		} else {
			method = http.MethodHead
		}
	}

	ua := strings.TrimSpace(opts.UserAgent)
	if ua == "" {
		if opts.WAFMode {
			ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
		} else {
			ua = "netping/1.0"
		}
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
		method:     method,
		userAgent:  ua,
		wafMode:    opts.WAFMode,
	}
}

// Ping executes an HTTP/HTTPS probe with httptrace timing collection.
func (h *HTTPing) Ping(ctx context.Context) ProbeResult {
	var reqBody io.Reader
	if h.sendData != "" {
		reqBody = strings.NewReader(h.sendData)
	}

	req, err := http.NewRequestWithContext(ctx, h.method, h.url, reqBody)
	if err != nil {
		return ProbeResult{Err: err}
	}
	req.Header.Set("User-Agent", h.userAgent)
	if h.wafMode {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Sec-Ch-Ua", `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`)
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	} else {
		req.Header.Set("Accept", "*/*")
	}
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
		certSubject    string
		certIssuer     string
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
				certSubject = state.PeerCertificates[0].Subject.CommonName
				certIssuer = state.PeerCertificates[0].Issuer.CommonName
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
	defer func() { _ = resp.Body.Close() }()
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
	if wafVendor := detectWAF(resp, certSubject, certIssuer, respBodyStr); wafVendor != "" {
		diagParts = append(diagParts, fmt.Sprintf("WAF: %s", wafVendor))
	}
	if ttfb > 0 {
		diagParts = append(diagParts, fmt.Sprintf("TTFB: %.2fms [DNS:%.1fms TCP:%.1fms TLS:%.1fms]",
			ttfb.Seconds()*1000, dnsTime.Seconds()*1000, tcpTime.Seconds()*1000, tlsTime.Seconds()*1000))
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

func detectWAF(resp *http.Response, certSubject, certIssuer, bodySnippet string) string {
	if resp == nil {
		return ""
	}
	server := strings.ToLower(resp.Header.Get("Server"))
	via := strings.ToLower(resp.Header.Get("Via"))
	certAll := strings.ToLower(certSubject + " " + certIssuer)
	bodyLower := strings.ToLower(bodySnippet)

	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, strings.ToLower(c.Name))
	}
	cookieStr := strings.Join(cookies, " ")

	var detected []string

	if strings.Contains(server, "cloudflare") || resp.Header.Get("CF-RAY") != "" || resp.Header.Get("cf-ray") != "" || strings.Contains(cookieStr, "__cf") || strings.Contains(certAll, "cloudflare") {
		detected = append(detected, "Cloudflare")
	}
	if strings.Contains(server, "incapsula") || strings.Contains(server, "imperva") || strings.EqualFold(resp.Header.Get("X-CDN"), "Imperva") || strings.EqualFold(resp.Header.Get("X-CDN"), "Incapsula") || resp.Header.Get("X-Iinfo") != "" || resp.Header.Get("x-iinfo") != "" || strings.Contains(cookieStr, "incap_ses") || strings.Contains(cookieStr, "visid_incap") || strings.Contains(certAll, "imperva") || strings.Contains(certAll, "incapsula") || strings.Contains(bodyLower, "_incapsula_resource") || strings.Contains(bodyLower, "cking-with-mannot") {
		detected = append(detected, "Imperva")
	}
	if strings.Contains(server, "akamaighost") || resp.Header.Get("X-Akamai-Transformed") != "" || resp.Header.Get("Akamai-GRN") != "" || strings.Contains(cookieStr, "ak_bmsc") || strings.Contains(cookieStr, "bm_sz") {
		detected = append(detected, "Akamai")
	}
	if strings.Contains(server, "cloudfront") || strings.Contains(via, "cloudfront") || resp.Header.Get("X-Amz-Cf-Id") != "" || resp.Header.Get("X-Amzn-Waf-Action") != "" {
		detected = append(detected, "AWS CloudFront / AWS WAF")
	}
	if strings.Contains(server, "fastly") || resp.Header.Get("X-Fastly-Request-ID") != "" {
		detected = append(detected, "Fastly")
	}
	if strings.Contains(server, "bigip") || strings.Contains(cookieStr, "bigipserver") || strings.Contains(cookieStr, "ts01") {
		detected = append(detected, "F5 BIG-IP / ASM")
	}
	if strings.Contains(server, "sucuri") || resp.Header.Get("X-Sucuri-ID") != "" || resp.Header.Get("X-Sucuri-Cache") != "" {
		detected = append(detected, "Sucuri CloudProxy")
	}
	if resp.Header.Get("X-Azure-Ref") != "" || resp.Header.Get("X-FD-Ref") != "" {
		detected = append(detected, "Azure Front Door")
	}

	if len(detected) == 0 {
		return ""
	}
	return strings.Join(detected, " + ")
}
