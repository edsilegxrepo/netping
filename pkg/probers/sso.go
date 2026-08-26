// Package probers implements network and application-layer diagnostic probers for netping.
package probers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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

// SSOType specifies the sub-protocol for Single Sign-On probing.
type SSOType string

const (
	SSOTypeOIDC   SSOType = "OIDC"
	SSOTypeSAML   SSOType = "SAML"
	SSOTypeOAuth2 SSOType = "OAUTH2"
	SSOTypeAuto   SSOType = "SSO"
)

// SSOOptions defines configuration parameters for SSO probers.
type SSOOptions struct {
	Type      SSOType
	Hostname  string
	IP        netip.Addr
	Port      uint16
	URI       string
	Timeout   time.Duration
	TLSConfig *tls.Config
	Dialer    *net.Dialer
	UseIPv4   bool
	UseIPv6   bool
}

// SSOing implements probers.Pinger for OpenID Connect, SAML 2.0, and OAuth 2.0 IdP endpoints.
type SSOing struct {
	ssoType   SSOType
	hostname  string
	ip        netip.Addr
	port      uint16
	uri       string
	timeout   time.Duration
	tlsConfig *tls.Config
	dialer    *net.Dialer
}

// NewSSOing constructs an initialized SSOing prober.
func NewSSOing(opts SSOOptions) *SSOing {
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

	sType := opts.Type
	if sType == "" {
		sType = SSOTypeAuto
	}

	return &SSOing{
		ssoType:   sType,
		hostname:  opts.Hostname,
		ip:        opts.IP,
		port:      port,
		uri:       opts.URI,
		timeout:   timeout,
		tlsConfig: tlsConfig,
		dialer:    dialer,
	}
}

// Ping executes the SSO diagnostic probe.
func (s *SSOing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	reqURL, resolvedType, err := s.buildTargetURL()
	if err != nil {
		return ProbeResult{RTT: time.Since(start), Err: fmt.Errorf("invalid target url: %w", err)}
	}

	var dnsStart, dnsDone time.Time
	var tcpStart, tcpDone time.Time
	var tlsStart, tlsDone time.Time
	var firstByte time.Time
	var localAddr net.Addr
	var certExpiry time.Time

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

	reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(httptrace.WithClientTrace(reqCtx, trace), http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return ProbeResult{RTT: time.Since(start), Err: fmt.Errorf("failed to create http request: %w", err)}
	}

	// Set protocol-specific Accept header
	switch resolvedType {
	case SSOTypeOIDC, SSOTypeOAuth2:
		httpReq.Header.Set("Accept", "application/json")
	case SSOTypeSAML:
		httpReq.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml;q=0.9, */*;q=0.8")
	default:
		httpReq.Header.Set("Accept", "application/json, application/samlmetadata+xml, application/xml;q=0.9, */*;q=0.8")
	}
	httpReq.Header.Set("User-Agent", "netping-sso/3.7.0")

	// Custom Transport with dialed connection & TLS config
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       s.tlsConfig.Clone(),
		ResponseHeaderTimeout: s.timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// If IP override provided, dial resolved IP
			dialAddr := addr
			if s.ip.IsValid() {
				dialAddr = net.JoinHostPort(s.ip.String(), fmt.Sprintf("%d", s.port))
			}
			return s.dialer.DialContext(ctx, network, dialAddr)
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

	// Read body up to 512 KB to avoid unbounded buffering
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
			Err:        fmt.Errorf("failed to read response body: %w", err),
		}
	}

	// Validate status
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
			Err:        fmt.Errorf("received non-success HTTP status %d %s", resp.StatusCode, resp.Status),
		}
	}

	// Parse deep diagnostics
	diags := s.parseDiagnostics(resolvedType, bodyBytes, reqURL, client, ctx)

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

func timeSubOrZero(t2, t1 time.Time) time.Duration {
	if !t1.IsZero() && !t2.IsZero() && t2.After(t1) {
		return t2.Sub(t1)
	}
	return 0
}

// buildTargetURL parses the target hostname, port, and URI into a canonical URL.
func (s *SSOing) buildTargetURL() (*url.URL, SSOType, error) {
	raw := s.uri
	if raw == "" {
		raw = s.hostname
	}
	if raw == "" && s.ip.IsValid() {
		raw = s.ip.String()
	}
	if raw == "" {
		return nil, s.ssoType, fmt.Errorf("no target host or uri specified")
	}

	resolvedType := s.ssoType

	// Add default scheme if missing
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		if s.port == 80 {
			raw = "http://" + raw
		} else {
			raw = "https://" + raw
		}
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, resolvedType, err
	}

	if parsed.Host == "" {
		return nil, resolvedType, fmt.Errorf("invalid url host: %s", raw)
	}

	// Ensure port if non-standard
	if s.port != 0 && s.port != 443 && s.port != 80 && !strings.Contains(parsed.Host, ":") {
		parsed.Host = net.JoinHostPort(parsed.Host, fmt.Sprintf("%d", s.port))
	}

	// Deduce default path based on resolved type
	if parsed.Path == "" || parsed.Path == "/" {
		switch resolvedType {
		case SSOTypeOIDC:
			parsed.Path = "/.well-known/openid-configuration"
		case SSOTypeOAuth2:
			parsed.Path = "/.well-known/oauth-authorization-server"
		case SSOTypeSAML:
			parsed.Path = "/FederationMetadata/2007-06/FederationMetadata.xml"
		case SSOTypeAuto:
			// Default auto path is OIDC discovery
			parsed.Path = "/.well-known/openid-configuration"
			resolvedType = SSOTypeOIDC
		}
	} else if resolvedType == SSOTypeAuto {
		// Differentiate based on path
		lowPath := strings.ToLower(parsed.Path)
		if strings.Contains(lowPath, "openid") || strings.Contains(lowPath, "oidc") {
			resolvedType = SSOTypeOIDC
		} else if strings.Contains(lowPath, "metadata") || strings.HasSuffix(lowPath, ".xml") || strings.Contains(lowPath, "saml") {
			resolvedType = SSOTypeSAML
		} else if strings.Contains(lowPath, "oauth") {
			resolvedType = SSOTypeOAuth2
		} else {
			resolvedType = SSOTypeOIDC
		}
	}

	return parsed, resolvedType, nil
}

// parseDiagnostics orchestrates sub-protocol diagnostic dissection.
func (s *SSOing) parseDiagnostics(sType SSOType, body []byte, reqURL *url.URL, client *http.Client, ctx context.Context) string {
	switch sType {
	case SSOTypeOIDC:
		return s.parseOIDCDiagnostics(body, client, ctx)
	case SSOTypeSAML:
		return s.parseSAMLDiagnostics(body)
	case SSOTypeOAuth2:
		return s.parseOAuth2Diagnostics(body)
	default:
		// Attempt OIDC JSON first, then SAML XML
		if json.Valid(body) {
			return s.parseOIDCDiagnostics(body, client, ctx)
		}
		return s.parseSAMLDiagnostics(body)
	}
}

// oidcDiscoveryDoc maps RFC 8414 & OpenID Connect Discovery 1.0 JSON fields.
type oidcDiscoveryDoc struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JwksURI               string   `json:"jwks_uri"`
	SigningAlgs           []string `json:"id_token_signing_alg_values_supported"`
	Scopes                []string `json:"scopes_supported"`
	SubjectTypes          []string `json:"subject_types_supported"`
	ResponseTypes         []string `json:"response_types_supported"`
}

// jwksDoc maps RFC 7517 JWK Key Set structures.
type jwksDoc struct {
	Keys []struct {
		Kty string   `json:"kty"`
		Use string   `json:"use"`
		Kid string   `json:"kid"`
		Alg string   `json:"alg"`
		X5c []string `json:"x5c"`
	} `json:"keys"`
}

func (s *SSOing) parseOIDCDiagnostics(body []byte, client *http.Client, ctx context.Context) string {
	var doc oidcDiscoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Sprintf("Protocol: OIDC │ RawResponse: %d bytes (JSON parse error: %v)", len(body), err)
	}

	parts := []string{"Protocol: OIDC (OpenID Connect 1.0)"}

	if doc.Issuer != "" {
		parts = append(parts, fmt.Sprintf("Issuer: %s", doc.Issuer))
	}
	if doc.TokenEndpoint != "" {
		parts = append(parts, fmt.Sprintf("TokenEndpoint: %s", doc.TokenEndpoint))
	}
	if doc.AuthorizationEndpoint != "" {
		parts = append(parts, fmt.Sprintf("AuthEndpoint: %s", doc.AuthorizationEndpoint))
	}
	if len(doc.SigningAlgs) > 0 {
		limit := 4
		if len(doc.SigningAlgs) < limit {
			limit = len(doc.SigningAlgs)
		}
		parts = append(parts, fmt.Sprintf("SigningAlgs: [%s]", strings.Join(doc.SigningAlgs[:limit], ", ")))
	}
	if len(doc.Scopes) > 0 {
		limit := 4
		if len(doc.Scopes) < limit {
			limit = len(doc.Scopes)
		}
		parts = append(parts, fmt.Sprintf("Scopes: [%s]", strings.Join(doc.Scopes[:limit], ", ")))
	}

	// Check JWKS if available
	if doc.JwksURI != "" && client != nil {
		jwksInfo := s.inspectJWKS(doc.JwksURI, client, ctx)
		if jwksInfo != "" {
			parts = append(parts, jwksInfo)
		}
	}

	return strings.Join(parts, " │ ")
}

func (s *SSOing) inspectJWKS(jwksURI string, client *http.Client, ctx context.Context) string {
	jwksCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	jwksReq, err := http.NewRequestWithContext(jwksCtx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return ""
	}
	jwksReq.Header.Set("Accept", "application/json")
	jwksReq.Header.Set("User-Agent", "netping-sso/3.7.0")

	resp, err := client.Do(jwksReq)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	jwksBytes, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return ""
	}

	var jwks jwksDoc
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		return ""
	}

	keyCount := len(jwks.Keys)
	if keyCount == 0 {
		return "JWKS: 0 keys"
	}

	var nearestExpiry *time.Time
	for _, key := range jwks.Keys {
		for _, rawCert := range key.X5c {
			certBytes, err := base64.StdEncoding.DecodeString(rawCert)
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				continue
			}
			if nearestExpiry == nil || cert.NotAfter.Before(*nearestExpiry) {
				exp := cert.NotAfter
				nearestExpiry = &exp
			}
		}
	}

	if nearestExpiry != nil {
		daysLeft := int(time.Until(*nearestExpiry).Hours() / 24)
		if daysLeft < 0 {
			return fmt.Sprintf("JWKS: %d keys [CRITICAL: Cert Expired %d days ago]", keyCount, -daysLeft)
		}
		if daysLeft < 30 {
			return fmt.Sprintf("JWKS: %d keys [WARNING: Nearest Cert Expires in %d days]", keyCount, daysLeft)
		}
		return fmt.Sprintf("JWKS: %d active keys (nearest cert expires in %d days)", keyCount, daysLeft)
	}

	return fmt.Sprintf("JWKS: %d active keys", keyCount)
}

// samlEntityDescriptor maps OASIS SAML 2.0 XML metadata structures.
type samlEntityDescriptor struct {
	XMLName          xml.Name `xml:"EntityDescriptor"`
	EntityID         string   `xml:"entityID,attr"`
	ValidUntil       string   `xml:"validUntil,attr"`
	IDPSSODescriptor struct {
		SingleSignOnService []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleSignOnService"`
		SingleLogoutService []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleLogoutService"`
		NameIDFormat  []string `xml:"NameIDFormat"`
		KeyDescriptor []struct {
			Use             string `xml:"use,attr"`
			X509Certificate string `xml:"KeyInfo>X509Data>X509Certificate"`
		} `xml:"KeyDescriptor"`
	} `xml:"IDPSSODescriptor"`
	SPSSODescriptor struct {
		SingleLogoutService []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleLogoutService"`
		KeyDescriptor []struct {
			Use             string `xml:"use,attr"`
			X509Certificate string `xml:"KeyInfo>X509Data>X509Certificate"`
		} `xml:"KeyDescriptor"`
	} `xml:"SPSSODescriptor"`
}

func (s *SSOing) parseSAMLDiagnostics(body []byte) string {
	var doc samlEntityDescriptor
	if err := xml.Unmarshal(body, &doc); err != nil {
		return fmt.Sprintf("Protocol: SAML 2.0 │ RawResponse: %d bytes (XML parse notice)", len(body))
	}

	parts := []string{"Protocol: SAML 2.0 Metadata"}

	if doc.EntityID != "" {
		parts = append(parts, fmt.Sprintf("EntityID: %s", doc.EntityID))
	}

	// Bindings
	bindings := make([]string, 0, len(doc.IDPSSODescriptor.SingleSignOnService))
	for _, ssoSvc := range doc.IDPSSODescriptor.SingleSignOnService {
		bName := ssoSvc.Binding
		if idx := strings.LastIndex(bName, ":"); idx != -1 {
			bName = bName[idx+1:]
		}
		bindings = append(bindings, bName)
	}
	if len(bindings) > 0 {
		parts = append(parts, fmt.Sprintf("Bindings: [%s]", strings.Join(bindings, ", ")))
	}

	// NameID formats
	if len(doc.IDPSSODescriptor.NameIDFormat) > 0 {
		formats := make([]string, 0, len(doc.IDPSSODescriptor.NameIDFormat))
		for _, f := range doc.IDPSSODescriptor.NameIDFormat {
			fName := f
			if idx := strings.LastIndex(fName, ":"); idx != -1 {
				fName = fName[idx+1:]
			}
			formats = append(formats, fName)
		}
		parts = append(parts, fmt.Sprintf("NameID: [%s]", strings.Join(formats, ", ")))
	}

	// Certificate Audit
	keyDescriptors := doc.IDPSSODescriptor.KeyDescriptor
	if len(keyDescriptors) == 0 {
		keyDescriptors = doc.SPSSODescriptor.KeyDescriptor
	}

	hasEnc := false
	for _, kd := range keyDescriptors {
		rawCert := strings.TrimSpace(kd.X509Certificate)
		rawCert = strings.ReplaceAll(rawCert, "\n", "")
		rawCert = strings.ReplaceAll(rawCert, "\r", "")
		rawCert = strings.ReplaceAll(rawCert, " ", "")

		if kd.Use == "encryption" {
			hasEnc = true
		}

		if rawCert != "" && (kd.Use == "signing" || kd.Use == "") {
			certBytes, err := base64.StdEncoding.DecodeString(rawCert)
			if err == nil {
				cert, err := x509.ParseCertificate(certBytes)
				if err == nil {
					daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
					subjectCN := cert.Subject.CommonName
					if subjectCN == "" && len(cert.Subject.Organization) > 0 {
						subjectCN = cert.Subject.Organization[0]
					}
					if subjectCN == "" {
						subjectCN = "SAML Signing"
					}

					if daysLeft < 0 {
						parts = append(parts, fmt.Sprintf("SigningCert: CN=%s [CRITICAL: EXPIRED on %s]", subjectCN, cert.NotAfter.Format("2006-01-02")))
					} else if daysLeft < 30 {
						parts = append(parts, fmt.Sprintf("SigningCert: CN=%s, Expires: %s [WARNING: %d days left]", subjectCN, cert.NotAfter.Format("2006-01-02"), daysLeft))
					} else {
						parts = append(parts, fmt.Sprintf("SigningCert: CN=%s, Expires: %s (%d days left)", subjectCN, cert.NotAfter.Format("2006-01-02"), daysLeft))
					}
				}
			}
		}
	}

	if hasEnc {
		parts = append(parts, "EncryptionCert: Present")
	}

	return strings.Join(parts, " │ ")
}

// oauth2MetadataDoc maps RFC 8414 OAuth 2.0 Authorization Server metadata.
type oauth2MetadataDoc struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	GrantTypes            []string `json:"grant_types_supported"`
	AuthMethods           []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

func (s *SSOing) parseOAuth2Diagnostics(body []byte) string {
	var doc oauth2MetadataDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Sprintf("Protocol: OAuth 2.0 │ RawResponse: %d bytes", len(body))
	}

	parts := []string{"Protocol: OAuth 2.0 (RFC 8414)"}

	if doc.Issuer != "" {
		parts = append(parts, fmt.Sprintf("Issuer: %s", doc.Issuer))
	}
	if doc.TokenEndpoint != "" {
		parts = append(parts, fmt.Sprintf("TokenEndpoint: %s", doc.TokenEndpoint))
	}
	if len(doc.GrantTypes) > 0 {
		limit := 4
		if len(doc.GrantTypes) < limit {
			limit = len(doc.GrantTypes)
		}
		parts = append(parts, fmt.Sprintf("Grants: [%s]", strings.Join(doc.GrantTypes[:limit], ", ")))
	}
	if len(doc.AuthMethods) > 0 {
		limit := 3
		if len(doc.AuthMethods) < limit {
			limit = len(doc.AuthMethods)
		}
		parts = append(parts, fmt.Sprintf("AuthMethods: [%s]", strings.Join(doc.AuthMethods[:limit], ", ")))
	}

	// PKCE check
	if len(doc.CodeChallengeMethods) > 0 {
		hasS256 := false
		for _, m := range doc.CodeChallengeMethods {
			if strings.EqualFold(m, "S256") {
				hasS256 = true
				break
			}
		}
		if hasS256 {
			parts = append(parts, "PKCE: [S256]")
		} else {
			parts = append(parts, "PKCE: [plain only - S256 missing]")
		}
	}

	if doc.IntrospectionEndpoint != "" {
		parts = append(parts, "Introspection: Enabled")
	}

	return strings.Join(parts, " │ ")
}
