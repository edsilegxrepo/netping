package web

import (
	"context"
)

// TriggerRequest defines the JSON payload received by POST /api/v1/trigger.
type TriggerRequest struct {
	Target              string   `json:"target"`
	Host                string   `json:"host"`
	Port                uint16   `json:"port"`
	Protocol            string   `json:"protocol"`
	URI                 string   `json:"uri"`
	Timeout             string   `json:"timeout"`
	Count               uint     `json:"count"`
	Interval            string   `json:"interval"`
	Retries             uint     `json:"retries"`
	RetryBackoff        string   `json:"retry_backoff"`
	MaxRetryBackoff     string   `json:"max_retry_backoff"`
	RetryJitter         *bool    `json:"retry_jitter"`
	MaxLatencyMS        float64  `json:"max_latency_ms"`
	UseIPv4             bool     `json:"use_ipv4"`
	UseIPv6             bool     `json:"use_ipv6"`
	SendData            string   `json:"send_data"`
	ExpectData          string   `json:"expect_data"`
	FastClose           bool     `json:"fast_close"`
	StartTLS            bool     `json:"starttls"`
	ServiceName         string   `json:"service_name"`
	DNSServer           string   `json:"dns_server"`
	DNSHosts            []string `json:"dns_hosts"`
	Traceroute          bool     `json:"traceroute"`
	ShowDiags           bool     `json:"show_diags"`
	Broadcast           *bool    `json:"broadcast"`
	ResolveEveryProbe   bool     `json:"resolve_every_probe"`
	RetryResolveAfter   uint     `json:"retry_resolve_after"`
	MaxConsecutiveFails uint     `json:"max_consecutive_fails"`
	Method              string   `json:"method,omitempty"`
	UserAgent           string   `json:"user_agent,omitempty"`
	WAF                 bool     `json:"waf,omitempty"`
}

// SingleProbeItem represents an individual measurement in a multi-probe execution.
type SingleProbeItem struct {
	Sequence    uint    `json:"sequence"`
	Success     bool    `json:"success"`
	RTTMs       float64 `json:"rtt_ms"`
	DNSTimeMs   float64 `json:"dns_time_ms,omitempty"`
	TCPTimeMs   float64 `json:"tcp_time_ms,omitempty"`
	TLSTimeMs   float64 `json:"tls_time_ms,omitempty"`
	TTFBMs      float64 `json:"ttfb_ms,omitempty"`
	HTTPStatus  int     `json:"http_status,omitempty"`
	Diagnostics string  `json:"diagnostics,omitempty"`
	Error       string  `json:"error,omitempty"`
	ErrorCode   string  `json:"error_code,omitempty"`
	Timestamp   string  `json:"timestamp"`
}

// HopItem represents a single hop in a traceroute trigger response.
type HopItem struct {
	Hop      int       `json:"hop"`
	Address  string    `json:"address"`
	Hostname string    `json:"hostname,omitempty"`
	RTTsMs   []float64 `json:"rtts_ms"`
	Timeout  bool      `json:"timeout"`
}

// TriggerResponse defines the JSON response returned by POST /api/v1/trigger.
type TriggerResponse struct {
	Success      bool              `json:"success"`
	Target       string            `json:"target"`
	Hostname     string            `json:"hostname"`
	IP           string            `json:"ip"`
	Port         uint16            `json:"port"`
	Protocol     string            `json:"protocol"`
	RTTMs        float64           `json:"rtt_ms"`
	DNSTimeMs    float64           `json:"dns_time_ms,omitempty"`
	TCPTimeMs    float64           `json:"tcp_time_ms,omitempty"`
	TLSTimeMs    float64           `json:"tls_time_ms,omitempty"`
	TTFBMs       float64           `json:"ttfb_ms,omitempty"`
	HTTPStatus   int               `json:"http_status,omitempty"`
	CertExpiry   string            `json:"cert_expiry,omitempty"`
	Diagnostics  string            `json:"diagnostics,omitempty"`
	Error        string            `json:"error,omitempty"`
	ErrorCode    string            `json:"error_code,omitempty"`
	Timestamp    string            `json:"timestamp"`
	TotalSent    uint              `json:"total_sent,omitempty"`
	TotalSuccess uint              `json:"total_success,omitempty"`
	TotalFailed  uint              `json:"total_failed,omitempty"`
	PacketLoss   float64           `json:"packet_loss,omitempty"`
	AvgRTTMs     float64           `json:"avg_rtt_ms,omitempty"`
	MinRTTMs     float64           `json:"min_rtt_ms,omitempty"`
	MaxRTTMs     float64           `json:"max_rtt_ms,omitempty"`
	Probes       []SingleProbeItem `json:"probes,omitempty"`
	Hops         []HopItem         `json:"hops,omitempty"`
}

// KeyValidator abstracts API key authentication verification.
type KeyValidator interface {
	ValidateKey(rawKey string) bool
}

// DynamicExecutor abstracts dynamic on-demand probe execution.
type DynamicExecutor interface {
	Execute(ctx context.Context, req TriggerRequest) (*TriggerResponse, error)
}

// DynamicFleetManager abstracts dynamic target fleet registration and deregistration.
type DynamicFleetManager interface {
	RemoveTarget(targetID string) bool
}
