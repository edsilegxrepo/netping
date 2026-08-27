// Package probers implements network and application-layer diagnostic probers for netping.
package probers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// EntraOptions defines configuration parameters for the Microsoft Entra ID prober.
type EntraOptions struct {
	Hostname  string
	TenantID  string
	IP        netip.Addr
	Port      uint16
	URI       string
	Timeout   time.Duration
	TLSConfig *tls.Config
	Dialer    *net.Dialer
	UseIPv4   bool
	UseIPv6   bool
}

// Entraing implements probers.Pinger for Microsoft Entra ID (Azure Active Directory) endpoints.
type Entraing struct {
	hostname   string
	tenantID   string
	ip         netip.Addr
	port       uint16
	uri        string
	timeout    time.Duration
	tlsConfig  *tls.Config
	dialer     *net.Dialer
	jwksCache  *jwksAuditCache
	cacheMutex sync.Mutex
}

type jwksAuditCache struct {
	cachedAt   time.Time
	keysCount  int
	minExpiry  time.Time
	nearestKey string
}

// entraOIDCConfig maps the Microsoft Entra ID OpenID Connect metadata document.
type entraOIDCConfig struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint      string   `json:"device_authorization_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseModesSupported           []string `json:"response_modes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	CloudInstanceName                string   `json:"cloud_instance_name"`
	TenantRegionScope                string   `json:"tenant_region_scope"`
}

type entraJWKSResponse struct {
	Keys []entraJWKKey `json:"keys"`
}

type entraJWKKey struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	X5c []string `json:"x5c"`
	Alg string   `json:"alg"`
}

// NewEntraing constructs an initialized Entraing prober.
func NewEntraing(opts EntraOptions) *Entraing {
	port := opts.Port
	if port == 0 {
		port = 443
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

	tenant := opts.TenantID
	if tenant == "" {
		tenant = "common"
	}

	host := opts.Hostname
	if host == "" {
		host = "login.microsoftonline.com"
	}

	return &Entraing{
		hostname:  host,
		tenantID:  tenant,
		ip:        opts.IP,
		port:      port,
		uri:       opts.URI,
		timeout:   timeout,
		tlsConfig: tlsConfig,
		dialer:    dialer,
	}
}

// Ping executes the Microsoft Entra ID diagnostic probe.
func (e *Entraing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	reqURL, err := e.buildTargetURL()
	if err != nil {
		return ProbeResult{RTT: time.Since(start), Err: fmt.Errorf("invalid entra target url: %w", err)}
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

	reqCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(httptrace.WithClientTrace(reqCtx, trace), http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return ProbeResult{RTT: time.Since(start), Err: fmt.Errorf("failed to create entra http request: %w", err)}
	}

	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "netping-entra/0.6.2")

	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       e.tlsConfig.Clone(),
		ResponseHeaderTimeout: e.timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialAddr := addr
			if e.ip.IsValid() {
				dialAddr = net.JoinHostPort(e.ip.String(), fmt.Sprintf("%d", e.port))
			}
			return e.dialer.DialContext(ctx, network, dialAddr)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
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
			Err:        fmt.Errorf("failed to read entra response body: %w", err),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return ProbeResult{
			LocalAddr:  localAddr,
			RTT:        rtt,
			HTTPStatus: resp.StatusCode,
			DNSTime:    timeSubOrZero(dnsDone, dnsStart),
			TCPTime:    timeSubOrZero(tcpDone, tcpStart),
			TLSTime:    timeSubOrZero(tlsDone, tlsStart),
			TTFB:       timeSubOrZero(firstByte, start),
			CertExpiry: certExpiry,
			Err:        fmt.Errorf("entra discovery returned non-success HTTP status %d %s", resp.StatusCode, resp.Status),
		}
	}

	diags := e.parseDiagnostics(bodyBytes, client, ctx, tlsState)

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

// buildTargetURL constructs the canonical Microsoft Entra ID OpenID discovery URL.
func (e *Entraing) buildTargetURL() (*url.URL, error) {
	raw := e.uri
	if raw == "" {
		raw = e.hostname
	}
	if raw == "" && e.ip.IsValid() {
		raw = e.ip.String()
	}
	if raw == "" {
		raw = "login.microsoftonline.com"
	}

	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		if e.port == 80 {
			raw = "http://" + raw
		} else {
			raw = "https://" + raw
		}
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid host in entra url: %s", raw)
	}

	if e.port != 0 && e.port != 443 && e.port != 80 && !strings.Contains(parsed.Host, ":") {
		parsed.Host = net.JoinHostPort(parsed.Host, fmt.Sprintf("%d", e.port))
	}

	// Auto-append discovery path if root
	if parsed.Path == "" || parsed.Path == "/" {
		tenant := e.tenantID
		if tenant == "" {
			tenant = "common"
		}
		parsed.Path = fmt.Sprintf("/%s/v2.0/.well-known/openid-configuration", tenant)
	}

	return parsed, nil
}

// parseDiagnostics extracts cloud environment, endpoints, JWKS certificate audits, and TLS metadata.
func (e *Entraing) parseDiagnostics(body []byte, client *http.Client, ctx context.Context, tlsState *tls.ConnectionState) string {
	var cfg entraOIDCConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return fmt.Sprintf("Protocol: Microsoft Entra ID │ Payload: %d bytes (JSON parse error)", len(body))
	}

	var parts []string

	// 1. Identify Cloud Environment
	cloudEnv := "Microsoft Entra ID (Azure Commercial)"
	if strings.Contains(cfg.Issuer, "login.microsoftonline.us") {
		cloudEnv = "Microsoft Entra ID (Azure US Government)"
	} else if strings.Contains(cfg.Issuer, "login.chinacloudapi.cn") {
		cloudEnv = "Microsoft Entra ID (Azure China 21Vianet)"
	}
	parts = append(parts, fmt.Sprintf("CloudEnv: %s", cloudEnv))

	// 2. Token & Auth Endpoints
	if cfg.TokenEndpoint != "" {
		if u, err := url.Parse(cfg.TokenEndpoint); err == nil {
			parts = append(parts, fmt.Sprintf("TokenPath: %s", u.Path))
		}
	}

	// 3. JWKS Certificate Audit
	if cfg.JWKSURI != "" {
		jwksInfo := e.auditJWKS(cfg.JWKSURI, client, ctx)
		if jwksInfo != "" {
			parts = append(parts, jwksInfo)
		}
	}

	// 4. Signing Algorithms & Scopes
	if len(cfg.IDTokenSigningAlgValuesSupported) > 0 {
		parts = append(parts, fmt.Sprintf("SigningAlgs: [%s]", strings.Join(cfg.IDTokenSigningAlgValuesSupported, ", ")))
	}
	if len(cfg.ScopesSupported) > 0 {
		limit := 4
		if len(cfg.ScopesSupported) < limit {
			limit = len(cfg.ScopesSupported)
		}
		parts = append(parts, fmt.Sprintf("Scopes: [%s]", strings.Join(cfg.ScopesSupported[:limit], ", ")))
	}

	// 5. TLS Security
	if tlsState != nil {
		parts = append(parts, fmt.Sprintf("TLSVersion: %s", tlsVersionToString(tlsState.Version)))
		parts = append(parts, fmt.Sprintf("CipherSuite: %s", tls.CipherSuiteName(tlsState.CipherSuite)))
		if len(tlsState.PeerCertificates) > 0 {
			cert := tlsState.PeerCertificates[0]
			daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
			parts = append(parts, fmt.Sprintf("CertExpiry: %s (%dd remaining)", cert.NotAfter.Format("2006-01-02"), daysRemaining))
		}
	}

	return strings.Join(parts, " │ ")
}

// auditJWKS downloads and audits active X.509 signing certificates from the JWKS URI.
func (e *Entraing) auditJWKS(jwksURI string, client *http.Client, ctx context.Context) string {
	e.cacheMutex.Lock()
	if e.jwksCache != nil && time.Since(e.jwksCache.cachedAt) < 10*time.Minute {
		cached := e.jwksCache
		e.cacheMutex.Unlock()
		daysRemaining := int(time.Until(cached.minExpiry).Hours() / 24)
		if daysRemaining <= 30 {
			return fmt.Sprintf("JWKS: %d keys [CRITICAL ALERT: Key %s expires in %dd on %s]",
				cached.keysCount, cached.nearestKey, daysRemaining, cached.minExpiry.Format("2006-01-02"))
		}
		return fmt.Sprintf("JWKS: %d keys (Nearest KeyExpiry: %s, %dd remaining)",
			cached.keysCount, cached.minExpiry.Format("2006-01-02"), daysRemaining)
	}
	e.cacheMutex.Unlock()

	jwksCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(jwksCtx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "netping-entra/0.6.1")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return ""
	}

	var jwks entraJWKSResponse
	if err := json.Unmarshal(body, &jwks); err != nil || len(jwks.Keys) == 0 {
		return ""
	}

	var minExpiry time.Time
	var nearestKid string
	var parsedCerts int

	for _, k := range jwks.Keys {
		if len(k.X5c) > 0 {
			certBytes, err := base64.StdEncoding.DecodeString(k.X5c[0])
			if err == nil {
				cert, err := x509.ParseCertificate(certBytes)
				if err == nil {
					parsedCerts++
					if minExpiry.IsZero() || cert.NotAfter.Before(minExpiry) {
						minExpiry = cert.NotAfter
						nearestKid = k.Kid
					}
				}
			}
		}
	}

	if parsedCerts > 0 && !minExpiry.IsZero() {
		e.cacheMutex.Lock()
		e.jwksCache = &jwksAuditCache{
			cachedAt:   time.Now(),
			keysCount:  len(jwks.Keys),
			minExpiry:  minExpiry,
			nearestKey: nearestKid,
		}
		e.cacheMutex.Unlock()

		daysRemaining := int(time.Until(minExpiry).Hours() / 24)
		if daysRemaining <= 30 {
			return fmt.Sprintf("JWKS: %d keys [CRITICAL ALERT: Key %s expires in %dd on %s]",
				len(jwks.Keys), nearestKid, daysRemaining, minExpiry.Format("2006-01-02"))
		}
		return fmt.Sprintf("JWKS: %d keys (Nearest KeyExpiry: %s, %dd remaining)",
			len(jwks.Keys), minExpiry.Format("2006-01-02"), daysRemaining)
	}

	return fmt.Sprintf("JWKS: %d active keys", len(jwks.Keys))
}
