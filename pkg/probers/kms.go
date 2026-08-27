// Package probers implements network and application-layer diagnostic probers for netping.
package probers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// KMSType identifies the specific KMS or Secrets Vault provider.
type KMSType string

const (
	KMSTypeAuto      KMSType = "AUTO"
	KMSTypeHashiCorp KMSType = "HASHICORP"
	KMSTypeAzure     KMSType = "AZURE"
	KMSTypeCyberArk  KMSType = "CYBERARK"
	KMSTypeAWS       KMSType = "AWS"
	KMSTypeGCP       KMSType = "GCP"
)

// KMSOptions defines configuration parameters for KMS and Secrets Vault probers.
type KMSOptions struct {
	Type      KMSType
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

// KMSing implements probers.Pinger for Key Management Services and Secrets Vaults.
type KMSing struct {
	kmsType   KMSType
	hostname  string
	ip        netip.Addr
	port      uint16
	uri       string
	timeout   time.Duration
	tlsConfig *tls.Config
	dialer    *net.Dialer
}

// hashicorpVaultHealth maps the response from HashiCorp Vault /v1/sys/health.
type hashicorpVaultHealth struct {
	Initialized                bool   `json:"initialized"`
	Sealed                     bool   `json:"sealed"`
	Standby                    bool   `json:"standby"`
	PerformanceStandby         bool   `json:"performance_standby"`
	ReplicationPerformanceMode string `json:"replication_performance_mode"`
	ReplicationDRMode          string `json:"replication_dr_mode"`
	ServerTimeUTC              int64  `json:"server_time_utc"`
	Version                    string `json:"version"`
	ClusterName                string `json:"cluster_name"`
	ClusterID                  string `json:"cluster_id"`
}

// cyberarkHealthDoc maps CyberArk PVWA /PasswordVault/api/Health and Conjur /health.
type cyberarkHealthDoc struct {
	ComponentHealth  string `json:"ComponentHealth"`
	ComponentState   string `json:"ComponentState"`
	ComponentVersion string `json:"ComponentVersion"`
	IsVaultConnected bool   `json:"IsVaultConnected"`
	Status           string `json:"status"`
	Version          string `json:"version"`
}

var bearerAuthTenantRegex = regexp.MustCompile(`authorization="https://login\.(?:microsoftonline\.com|windows\.net)/([a-f0-9\-]+)"`)

// NewKMSing constructs an initialized KMSing prober.
func NewKMSing(opts KMSOptions) *KMSing {
	port := opts.Port
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

	kType := opts.Type
	if kType == "" {
		kType = KMSTypeAuto
	}

	return &KMSing{
		kmsType:   kType,
		hostname:  opts.Hostname,
		ip:        opts.IP,
		port:      port,
		uri:       opts.URI,
		timeout:   timeout,
		tlsConfig: tlsConfig,
		dialer:    dialer,
	}
}

// Ping executes the KMS / Secrets Vault diagnostic probe.
func (k *KMSing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	reqURL, detectedType, err := k.buildTargetURL()
	if err != nil {
		return ProbeResult{RTT: time.Since(start), Err: fmt.Errorf("invalid kms target url: %w", err)}
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

	reqCtx, cancel := context.WithTimeout(ctx, k.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(httptrace.WithClientTrace(reqCtx, trace), http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return ProbeResult{RTT: time.Since(start), Err: fmt.Errorf("failed to create kms http request: %w", err)}
	}

	httpReq.Header.Set("Accept", "application/json, */*")
	httpReq.Header.Set("User-Agent", "netping-kms/0.6.2")

	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       k.tlsConfig.Clone(),
		ResponseHeaderTimeout: k.timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialAddr := addr
			if k.ip.IsValid() {
				targetPort := k.port
				if targetPort == 0 {
					if strings.HasPrefix(reqURL.Scheme, "https") {
						targetPort = 443
					} else {
						targetPort = 80
					}
				}
				dialAddr = net.JoinHostPort(k.ip.String(), fmt.Sprintf("%d", targetPort))
			}
			return k.dialer.DialContext(ctx, network, dialAddr)
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
			Err:        fmt.Errorf("failed to read kms response body: %w", err),
		}
	}

	// Validate expected provider status codes:
	// - HashiCorp Vault: 200 (Active), 429/472/473 (Standby), 503 (Sealed - valid diagnostic response!)
	// - Azure Key Vault: 401 Unauthorized (Auth challenge)
	// - CyberArk: 200 OK
	// - AWS KMS: 400 Bad Request / 404 Not Found
	// - GCP KMS: 404 Not Found / 401 Unauthorized
	isAcceptedStatus := false
	switch detectedType {
	case KMSTypeHashiCorp:
		if resp.StatusCode == 200 || resp.StatusCode == 429 || resp.StatusCode == 472 || resp.StatusCode == 473 || resp.StatusCode == 501 || resp.StatusCode == 503 {
			isAcceptedStatus = true
		}
	case KMSTypeAzure:
		if resp.StatusCode == 401 || resp.StatusCode == 200 || resp.StatusCode == 403 {
			isAcceptedStatus = true
		}
	case KMSTypeAWS:
		if resp.StatusCode == 400 || resp.StatusCode == 404 || resp.StatusCode == 403 || resp.StatusCode == 200 {
			isAcceptedStatus = true
		}
	case KMSTypeGCP:
		if resp.StatusCode == 404 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 200 {
			isAcceptedStatus = true
		}
	default:
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			isAcceptedStatus = true
		}
	}

	if !isAcceptedStatus {
		return ProbeResult{
			LocalAddr:  localAddr,
			RTT:        rtt,
			HTTPStatus: resp.StatusCode,
			DNSTime:    timeSubOrZero(dnsDone, dnsStart),
			TCPTime:    timeSubOrZero(tcpDone, tcpStart),
			TLSTime:    timeSubOrZero(tlsDone, tlsStart),
			TTFB:       timeSubOrZero(firstByte, start),
			CertExpiry: certExpiry,
			Err:        fmt.Errorf("kms endpoint returned non-operational HTTP status %d %s", resp.StatusCode, resp.Status),
		}
	}

	diags := k.parseDiagnostics(detectedType, resp, bodyBytes, tlsState)

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

// buildTargetURL classifies the provider and formats the URL.
func (k *KMSing) buildTargetURL() (*url.URL, KMSType, error) {
	raw := k.uri
	if raw == "" {
		raw = k.hostname
	}
	if raw == "" && k.ip.IsValid() {
		raw = k.ip.String()
	}
	if raw == "" {
		raw = "127.0.0.1:8200"
	}

	detectedType := k.kmsType

	// Add default scheme if missing
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		if k.port == 8200 || strings.Contains(raw, ":8200") {
			raw = "http://" + raw
		} else {
			raw = "https://" + raw
		}
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, detectedType, err
	}

	if parsed.Host == "" {
		return nil, detectedType, fmt.Errorf("invalid host in kms url: %s", raw)
	}

	// Apply port if provided explicitly and not in host
	if k.port != 0 && !strings.Contains(parsed.Host, ":") {
		parsed.Host = net.JoinHostPort(parsed.Host, fmt.Sprintf("%d", k.port))
	}

	// Detect provider heuristics if AUTO
	if detectedType == KMSTypeAuto {
		hostLower := strings.ToLower(parsed.Hostname())
		switch {
		case strings.Contains(hostLower, ".vault.azure.net") || strings.Contains(hostLower, ".managedhsm.azure.net"):
			detectedType = KMSTypeAzure
		case strings.Contains(hostLower, "kms.") && strings.Contains(hostLower, ".amazonaws.com"):
			detectedType = KMSTypeAWS
		case strings.Contains(hostLower, "cloudkms.googleapis.com"):
			detectedType = KMSTypeGCP
		case strings.Contains(hostLower, "cyberark") || strings.Contains(hostLower, "conjur") || strings.Contains(parsed.Path, "/PasswordVault"):
			detectedType = KMSTypeCyberArk
		default:
			detectedType = KMSTypeHashiCorp
		}
	}

	// Set default path per detected provider if empty
	if parsed.Path == "" || parsed.Path == "/" {
		switch detectedType {
		case KMSTypeHashiCorp:
			parsed.Path = "/v1/sys/health"
		case KMSTypeCyberArk:
			parsed.Path = "/PasswordVault/api/Health"
		case KMSTypeAzure, KMSTypeAWS, KMSTypeGCP:
			parsed.Path = "/"
		}
	}

	return parsed, detectedType, nil
}

// parseDiagnostics dissects provider responses into rich diagnostic strings.
func (k *KMSing) parseDiagnostics(detectedType KMSType, resp *http.Response, body []byte, tlsState *tls.ConnectionState) string {
	var parts []string

	switch detectedType {
	case KMSTypeHashiCorp:
		var vh hashicorpVaultHealth
		if err := json.Unmarshal(body, &vh); err == nil {
			parts = append(parts, "Vault: HashiCorp Vault")
			if vh.Version != "" {
				parts = append(parts, fmt.Sprintf("Version: v%s", vh.Version))
			}
			if vh.ClusterName != "" {
				parts = append(parts, fmt.Sprintf("Cluster: %s", vh.ClusterName))
			}

			// Seal Check
			if vh.Sealed {
				parts = append(parts, "[CRITICAL ALERT: Vault is SEALED/Locked]")
			} else {
				parts = append(parts, "Sealed: false (Unsealed)")
			}

			// HA Role
			if vh.Standby {
				parts = append(parts, "Role: Standby Node")
			} else {
				parts = append(parts, "Role: Active Primary Leader")
			}

			// Server Time Skew
			if vh.ServerTimeUTC > 0 {
				serverTime := time.Unix(vh.ServerTimeUTC, 0)
				skew := time.Since(serverTime)
				if skew < 0 {
					skew = -skew
				}
				if skew > 2*time.Second {
					parts = append(parts, fmt.Sprintf("ClockSkew: %s", skew.Round(time.Millisecond)))
				}
			}
		} else {
			parts = append(parts, fmt.Sprintf("Vault: HashiCorp Vault (HTTP %d)", resp.StatusCode))
		}

	case KMSTypeAzure:
		parts = append(parts, "Vault: Azure Key Vault")
		// Extract Entra Tenant ID from WWW-Authenticate
		authHdr := resp.Header.Get("WWW-Authenticate")
		if authHdr != "" {
			if match := bearerAuthTenantRegex.FindStringSubmatch(authHdr); len(match) > 1 {
				parts = append(parts, fmt.Sprintf("TenantID: %s", match[1]))
			}
		}
		if region := resp.Header.Get("x-ms-keyvault-region"); region != "" {
			parts = append(parts, fmt.Sprintf("Region: %s", region))
		}
		if ver := resp.Header.Get("x-ms-keyvault-service-version"); ver != "" {
			parts = append(parts, fmt.Sprintf("ServiceVer: %s", ver))
		}
		if reqID := resp.Header.Get("x-ms-request-id"); reqID != "" {
			parts = append(parts, fmt.Sprintf("ReqID: %s", reqID))
		}

	case KMSTypeCyberArk:
		var cb cyberarkHealthDoc
		if err := json.Unmarshal(body, &cb); err == nil {
			parts = append(parts, "Vault: CyberArk")
			if cb.ComponentHealth != "" {
				parts = append(parts, fmt.Sprintf("Health: %s", cb.ComponentHealth))
			}
			if cb.ComponentVersion != "" {
				parts = append(parts, fmt.Sprintf("Version: %s", cb.ComponentVersion))
			}
			if cb.IsVaultConnected {
				parts = append(parts, "VaultLink: Connected")
			}
		} else {
			parts = append(parts, "Vault: CyberArk PAM")
		}

	case KMSTypeAWS:
		parts = append(parts, "Vault: AWS Key Management Service (AWS KMS)")
		if reqID := resp.Header.Get("x-amzn-RequestId"); reqID != "" {
			parts = append(parts, fmt.Sprintf("AmznReqID: %s", reqID))
		}

	case KMSTypeGCP:
		parts = append(parts, "Vault: Google Cloud Key Management Service (GCP KMS)")
		if reqID := resp.Header.Get("x-goog-request-id"); reqID != "" {
			parts = append(parts, fmt.Sprintf("GCPReqID: %s", reqID))
		}
	}

	// Append TLS details if available
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
