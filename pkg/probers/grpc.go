package probers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type GRPCOptions struct {
	Hostname string
	IP       netip.Addr
	Port     uint16
	UseTLS   bool
	Timeout  time.Duration
	Dialer   *net.Dialer
}

// GRPCing implements Pinger for gRPC service health checks.
type GRPCing struct {
	client  *http.Client
	url     string
	timeout time.Duration
}

// NewGRPCing constructs a new gRPC health check prober.
func NewGRPCing(opts GRPCOptions) *GRPCing {
	port := opts.Port
	if port == 0 {
		if opts.UseTLS {
			port = 443
		} else {
			port = 50051
		}
	}

	target := opts.Hostname
	if target == "" {
		target = opts.IP.String()
	}

	scheme := "http"
	if opts.UseTLS || opts.Port == 443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/grpc.health.v1.Health/Check", scheme, target, port)

	dialContext := (&net.Dialer{Timeout: opts.Timeout}).DialContext
	if opts.Dialer != nil {
		dialContext = opts.Dialer.DialContext
	}

	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DisableKeepAlives: true,
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
	}

	return &GRPCing{
		client:  client,
		url:     url,
		timeout: opts.Timeout,
	}
}

// Ping sends a gRPC Health/Check request and measures latency.
func (g *GRPCing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.url, nil)
	if err != nil {
		return ProbeResult{Err: err}
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	resp, err := g.client.Do(req)
	rtt := time.Since(start)
	if err != nil {
		return ProbeResult{
			RTT: rtt,
			Err: err,
		}
	}
	defer func() { _ = resp.Body.Close() }()

	grpcStatus := resp.Header.Get("grpc-status")
	if grpcStatus == "" {
		grpcStatus = resp.Trailer.Get("grpc-status")
	}

	var diags []string
	if grpcStatus != "" {
		diags = append(diags, fmt.Sprintf("gRPC: %s (%s)", grpcStatus, grpcStatusName(grpcStatus)))
	} else {
		diags = append(diags, fmt.Sprintf("HTTP: %d %s", resp.StatusCode, resp.Proto))
	}

	if grpcMsg := resp.Header.Get("grpc-message"); grpcMsg != "" {
		diags = append(diags, fmt.Sprintf("Msg: %q", grpcMsg))
	}

	if resp.TLS != nil {
		diags = append(diags, fmt.Sprintf("TLS: %s (%s)", tls.VersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite)))
	}

	if srv := resp.Header.Get("Server"); srv != "" {
		diags = append(diags, fmt.Sprintf("Server: %s", srv))
	}

	var probeErr error
	if grpcStatus == "14" { // UNAVAILABLE
		probeErr = fmt.Errorf("grpc service unavailable: %s", grpcStatus)
	}

	return ProbeResult{
		RTT:         rtt,
		HTTPStatus:  resp.StatusCode,
		Diagnostics: strings.Join(diags, ", "),
		Err:         probeErr,
	}
}

func grpcStatusName(code string) string {
	switch code {
	case "0":
		return "OK"
	case "1":
		return "CANCELLED"
	case "2":
		return "UNKNOWN"
	case "3":
		return "INVALID_ARGUMENT"
	case "4":
		return "DEADLINE_EXCEEDED"
	case "5":
		return "NOT_FOUND"
	case "6":
		return "ALREADY_EXISTS"
	case "7":
		return "PERMISSION_DENIED"
	case "8":
		return "RESOURCE_EXHAUSTED"
	case "9":
		return "FAILED_PRECONDITION"
	case "10":
		return "ABORTED"
	case "11":
		return "OUT_OF_RANGE"
	case "12":
		return "UNIMPLEMENTED"
	case "13":
		return "INTERNAL"
	case "14":
		return "UNAVAILABLE"
	case "15":
		return "DATA_LOSS"
	case "16":
		return "UNAUTHENTICATED"
	default:
		return "CODE_" + code
	}
}
