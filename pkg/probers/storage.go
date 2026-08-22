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

type StorageType string

const (
	StorageS3        StorageType = "s3"
	StorageAzureBlob StorageType = "azureblob"
	StorageGCS       StorageType = "gcs"
)

type StorageOptions struct {
	Type       StorageType
	Hostname   string
	IP         netip.Addr
	Port       uint16
	SkipVerify bool
	Timeout    time.Duration
	Dialer     *net.Dialer
}

// Storageing implements Pinger for Cloud Storage Buckets (AWS S3, Azure Blob/ADLS, GCP Cloud Storage).
type Storageing struct {
	storageType StorageType
	hostname    string
	ip          netip.Addr
	port        uint16
	timeout     time.Duration
	url         string
	httpClient  *http.Client
}

// NewStorageing constructs a new Cloud Storage prober.
func NewStorageing(opts StorageOptions) *Storageing {
	port := opts.Port
	if port == 0 {
		port = 443
	}

	target := opts.Hostname
	if target == "" {
		if opts.IP.IsValid() {
			target = opts.IP.String()
		} else {
			switch opts.Type {
			case StorageAzureBlob:
				target = "blob.core.windows.net"
			case StorageGCS:
				target = "storage.googleapis.com"
			case StorageS3:
				fallthrough
			default:
				target = "s3.amazonaws.com"
			}
		}
	}

	var url string
	switch opts.Type {
	case StorageAzureBlob:
		if strings.Contains(target, "blob.core.windows.net") || strings.Contains(target, "dfs.core.windows.net") {
			url = fmt.Sprintf("https://%s:%d/?comp=list", target, port)
		} else {
			url = fmt.Sprintf("https://%s:%d/", target, port)
		}
	case StorageGCS:
		url = fmt.Sprintf("https://%s:%d/", target, port)
	case StorageS3:
		fallthrough
	default:
		url = fmt.Sprintf("https://%s:%d/", target, port)
	}

	dialContext := (&net.Dialer{Timeout: opts.Timeout}).DialContext
	if opts.Dialer != nil {
		dialContext = opts.Dialer.DialContext
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			ServerName:         opts.Hostname,
			InsecureSkipVerify: opts.SkipVerify,
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

	return &Storageing{
		storageType: opts.Type,
		hostname:    target,
		ip:          opts.IP,
		port:        port,
		timeout:     opts.Timeout,
		url:         url,
		httpClient:  client,
	}
}

// Ping executes an unauthenticated request to the Cloud Storage endpoint and measures end-to-end timing.
func (s *Storageing) Ping(ctx context.Context) ProbeResult {
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
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, s.url, nil)
	if err != nil {
		return ProbeResult{Err: err}
	}
	req.Header.Set("User-Agent", "netping/cloud-storage-prober")
	if s.storageType == StorageAzureBlob {
		req.Header.Set("x-ms-version", "2023-08-03")
	}

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	rtt := time.Since(start)
	if err != nil {
		return ProbeResult{
			LocalAddr: localAddr,
			RTT:       rtt,
			Err:       err,
		}
	}
	defer resp.Body.Close()
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
	diagParts = append(diagParts, fmt.Sprintf("Storage: %s", string(s.storageType)))
	diagParts = append(diagParts, fmt.Sprintf("HTTP %d", resp.StatusCode))
	if reqID := resp.Header.Get("x-amz-request-id"); reqID != "" {
		diagParts = append(diagParts, fmt.Sprintf("RequestID: %s", reqID))
	} else if reqID := resp.Header.Get("x-ms-request-id"); reqID != "" {
		diagParts = append(diagParts, fmt.Sprintf("RequestID: %s", reqID))
	} else if reqID := resp.Header.Get("x-goog-request-id"); reqID != "" {
		diagParts = append(diagParts, fmt.Sprintf("RequestID: %s", reqID))
	}
	if region := resp.Header.Get("x-amz-bucket-region"); region != "" {
		diagParts = append(diagParts, fmt.Sprintf("Region: %s", region))
	}
	if srv := resp.Header.Get("Server"); srv != "" {
		diagParts = append(diagParts, fmt.Sprintf("Server: %s", srv))
	}

	return ProbeResult{
		LocalAddr:   localAddr,
		RTT:         rtt,
		DNSTime:     dnsTime,
		TCPTime:     tcpTime,
		TLSTime:     tlsTime,
		HTTPStatus:  resp.StatusCode,
		CertExpiry:  certExpiry,
		Diagnostics: strings.Join(diagParts, " │ "),
		Err:         nil,
	}
}
