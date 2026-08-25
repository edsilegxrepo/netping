// Package engine provides dynamic on-demand probe orchestration, concurrent worker pooling,
// real-time target registry management, and SLA threshold evaluation for netping.
//
// Objectives:
//   - Execute on-demand Layer 3-7 network diagnostic probes triggered via REST API.
//   - Enforce concurrency boundaries using buffered channel semaphores.
//   - Evaluate SLA latency thresholds and calculate packet loss, jitter, and response percentiles.
//   - Maintain synchronization with the dynamic fleet target registry and real-time SSE broadcaster.
//
// Core Components:
//   - DynamicEngine: Core orchestrator managing concurrent execution workers and probe lifecycles.
//   - DynamicTargetRegistry: Thread-safe target inventory tracking active endpoints and statistics.
//   - Execute: Primary dispatch handler for single probes, iterative runs, and traceroutes.
//
// Data Flow:
//
//	POST /api/v1/trigger -> resolveTriggerTarget -> DynamicTargetRegistry.GetOrCreateTarget
//	-> Semaphore Acquire -> probers.BuildPinger -> Pinger.Ping -> Stats Update -> SSE Broadcast -> JSON Response.
package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/edsilegx/netping/internal/dns"
	"github.com/edsilegx/netping/pkg/consts"
	"github.com/edsilegx/netping/pkg/probers"
	"github.com/edsilegx/netping/pkg/utils"
	"github.com/edsilegx/netping/pkg/web"
)

// Type aliases to pkg/web
type (
	TriggerRequest  = web.TriggerRequest
	SingleProbeItem = web.SingleProbeItem
	HopItem         = web.HopItem
	TriggerResponse = web.TriggerResponse
)

// DynamicEngine coordinates on-demand and dynamic fleet probe executions.
type DynamicEngine struct {
	broadcaster *web.Broadcaster
	registry    *DynamicTargetRegistry
	sem         chan struct{}
}

// NewDynamicEngine constructs a new DynamicEngine.
func NewDynamicEngine(broadcaster *web.Broadcaster, registry *DynamicTargetRegistry, maxConcurrency int) *DynamicEngine {
	if maxConcurrency <= 0 {
		maxConcurrency = 100
	}
	return &DynamicEngine{
		broadcaster: broadcaster,
		registry:    registry,
		sem:         make(chan struct{}, maxConcurrency),
	}
}

// Execute handles a single synchronous or count-limited trigger request.
func (e *DynamicEngine) Execute(ctx context.Context, req TriggerRequest) (*TriggerResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Acquire worker slot
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Parse and normalize target, host, port, protocol
	host, port, proto, svc, err := resolveTriggerTarget(req)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	timeout := 2 * time.Second
	if req.Timeout != "" {
		if d, err := time.ParseDuration(req.Timeout); err == nil && d > 0 {
			timeout = d
		} else if val, err := strconv.ParseFloat(req.Timeout, 64); err == nil && val > 0 {
			timeout = utils.SecondsToDuration(val)
		}
	}

	resolver := dns.NewResolver(req.DNSServer, 2*time.Second, req.UseIPv4, req.UseIPv6)
	var resolvedIP netip.Addr
	if host != "" {
		resolvedIP, _ = resolver.ResolveHostname(host)
	}

	shouldBroadcast := true
	if req.Broadcast != nil {
		shouldBroadcast = *req.Broadcast
	}

	targetDisplay := fmt.Sprintf("%s:%d", host, port)
	if host == "" && resolvedIP.IsValid() {
		targetDisplay = fmt.Sprintf("%s:%d", resolvedIP.String(), port)
	}

	// 1. Traceroute Trigger Mode
	if req.Traceroute {
		return e.executeTraceroute(ctx, host, resolvedIP, port, proto, timeout, targetDisplay)
	}

	pinger := buildPinger(host, resolvedIP, port, proto, svc, timeout, req)
	stat := e.registry.GetOrCreateStats(targetDisplay, host, resolvedIP, port, proto, svc)

	count := req.Count
	if count == 0 {
		count = 1
	}

	interval := 500 * time.Millisecond
	if req.Interval != "" {
		if d, err := time.ParseDuration(req.Interval); err == nil && d > 0 {
			interval = d
		} else if val, err := strconv.ParseFloat(req.Interval, 64); err == nil && val > 0 {
			interval = utils.SecondsToDuration(val)
		}
	}

	retries := req.Retries
	retryBackoff := 50 * time.Millisecond
	if req.RetryBackoff != "" {
		if d, err := time.ParseDuration(req.RetryBackoff); err == nil && d > 0 {
			retryBackoff = d
		}
	}
	maxRetryBackoff := 2 * time.Second
	if req.MaxRetryBackoff != "" {
		if d, err := time.ParseDuration(req.MaxRetryBackoff); err == nil && d > 0 {
			maxRetryBackoff = d
		}
	}
	retryJitter := true
	if req.RetryJitter != nil {
		retryJitter = *req.RetryJitter
	}

	probeItems := make([]SingleProbeItem, 0, count)
	var lastRes probers.ProbeResult
	var lastErrStr, lastErrCode string

	for i := uint(1); i <= count; i++ {
		if i > 1 {
			select {
			case <-ctx.Done():
				break
			case <-time.After(interval):
			}
		}

		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		res := pinger.Ping(probeCtx)
		cancel()

		rttMs := float64(res.RTT.Nanoseconds()) / 1e6
		isFailure := res.Err != nil

		if !isFailure && req.MaxLatencyMS > 0 && rttMs >= req.MaxLatencyMS {
			isFailure = true
			res.Err = fmt.Errorf("latency breached SLA threshold: %.4fms >= %.4fms", rttMs, req.MaxLatencyMS)
		}

		if isFailure && retries > 0 && res.Err != nil && !strings.Contains(res.Err.Error(), "SLA threshold") {
			for attempt := 1; attempt <= int(retries); attempt++ {
				delay := utils.CalculateBackoff(attempt-1, utils.BackoffConfig{
					InitialDelay: retryBackoff,
					MaxDelay:     maxRetryBackoff,
					Multiplier:   2.0,
					Jitter:       retryJitter,
				})
				if err := utils.SleepWithContext(ctx, delay); err != nil {
					break
				}
				retryCtx, retryCancel := context.WithTimeout(ctx, timeout)
				retryRes := pinger.Ping(retryCtx)
				retryCancel()

				retryRttMs := float64(retryRes.RTT.Nanoseconds()) / 1e6
				retryFail := retryRes.Err != nil
				if !retryFail && req.MaxLatencyMS > 0 && retryRttMs >= req.MaxLatencyMS {
					retryFail = true
					retryRes.Err = fmt.Errorf("latency breached SLA threshold: %.4fms >= %.4fms", retryRttMs, req.MaxLatencyMS)
				}
				if !retryFail {
					res = retryRes
					rttMs = retryRttMs
					isFailure = false
					break
				}
				res = retryRes
				rttMs = retryRttMs
			}
		}

		lastRes = res
		now := time.Now().UTC()

		if isFailure {
			lastErrStr = res.Err.Error()
			lastErrCode = utils.ClassifyError(res.Err)
			stat.Mu.Lock()
			stat.OngoingSuccessfulProbes = 0
			stat.OngoingUnsuccessfulProbes++
			stat.Failed++
			stat.TotalUnsuccessfulProbes++
			stat.LastUnsuccessfulProbe = now
			stat.LastFailureReason = lastErrCode
			stat.Mu.Unlock()
		} else {
			lastErrStr = ""
			lastErrCode = ""
			stat.RecordSuccess(float32(rttMs), now)
			stat.Mu.Lock()
			stat.LatestDiagnostics = res.Diagnostics
			stat.LatestDNSTime = res.DNSTime
			stat.LatestTCPTime = res.TCPTime
			stat.LatestTLSTime = res.TLSTime
			stat.LatestTTFB = res.TTFB
			stat.LatestHTTPStatus = res.HTTPStatus
			stat.LatestCertExpiry = res.CertExpiry
			stat.Mu.Unlock()
		}

		snap := stat.Snapshot()

		item := SingleProbeItem{
			Sequence:    i,
			Success:     !isFailure,
			RTTMs:       float64(rttMs),
			DNSTimeMs:   res.DNSTime.Seconds() * 1000,
			TCPTimeMs:   res.TCPTime.Seconds() * 1000,
			TLSTimeMs:   res.TLSTime.Seconds() * 1000,
			TTFBMs:      res.TTFB.Seconds() * 1000,
			HTTPStatus:  res.HTTPStatus,
			Diagnostics: res.Diagnostics,
			Error:       lastErrStr,
			ErrorCode:   lastErrCode,
			Timestamp:   now.Format(time.RFC3339),
		}
		probeItems = append(probeItems, item)

		if shouldBroadcast && e.broadcaster != nil {
			diagStr := ""
			if req.ShowDiags {
				diagStr = res.Diagnostics
			}
			ipStr := ""
			if resolvedIP.IsValid() {
				ipStr = resolvedIP.String()
			}

			e.broadcaster.Broadcast(web.ProbeEvent{
				RawTime:        now,
				Sequence:       snap.TotalSent,
				Success:        !isFailure,
				RTT:            float64(rttMs),
				Target:         targetDisplay,
				Hostname:       host,
				IP:             ipStr,
				Port:           port,
				Protocol:       strings.ToUpper(string(proto)),
				Diagnostics:    diagStr,
				Error:          lastErrCode,
				DNSTime:        res.DNSTime.Seconds() * 1000,
				TCPTime:        res.TCPTime.Seconds() * 1000,
				TLSTime:        res.TLSTime.Seconds() * 1000,
				HTTPStatus:     res.HTTPStatus,
				TotalSent:      snap.TotalSent,
				TotalSuccess:   snap.TotalSuccess,
				TotalFailed:    snap.TotalFailed,
				PacketLoss:     snap.PacketLoss,
				AvgRTT:         float64(snap.AvgRTT),
				MinRTT:         float64(snap.MinRTT),
				MaxRTT:         float64(snap.MaxRTT),
				Jitter:         float64(snap.Jitter),
				UptimeDuration: snap.UptimeDuration,
			})
		}
	}

	snap := stat.Snapshot()
	certExpStr := ""
	if !lastRes.CertExpiry.IsZero() {
		certExpStr = lastRes.CertExpiry.Format(time.RFC3339)
	}

	ipStr := ""
	if resolvedIP.IsValid() {
		ipStr = resolvedIP.String()
	}

	resp := &TriggerResponse{
		Success:      lastRes.Err == nil,
		Target:       targetDisplay,
		Hostname:     host,
		IP:           ipStr,
		Port:         port,
		Protocol:     strings.ToUpper(string(proto)),
		RTTMs:        float64(lastRes.RTT.Nanoseconds()) / 1e6,
		DNSTimeMs:    lastRes.DNSTime.Seconds() * 1000,
		TCPTimeMs:    lastRes.TCPTime.Seconds() * 1000,
		TLSTimeMs:    lastRes.TLSTime.Seconds() * 1000,
		TTFBMs:       lastRes.TTFB.Seconds() * 1000,
		HTTPStatus:   lastRes.HTTPStatus,
		CertExpiry:   certExpStr,
		Diagnostics:  lastRes.Diagnostics,
		Error:        lastErrStr,
		ErrorCode:    lastErrCode,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		TotalSent:    snap.TotalSent,
		TotalSuccess: snap.TotalSuccess,
		TotalFailed:  snap.TotalFailed,
		PacketLoss:   snap.PacketLoss,
		AvgRTTMs:     float64(snap.AvgRTT),
		MinRTTMs:     float64(snap.MinRTT),
		MaxRTTMs:     float64(snap.MaxRTT),
	}

	if len(probeItems) > 1 {
		resp.Probes = probeItems
	}

	return resp, nil
}

func (e *DynamicEngine) executeTraceroute(ctx context.Context, host string, ip netip.Addr, port uint16, proto consts.Protocol, timeout time.Duration, targetDisplay string) (*TriggerResponse, error) {
	var hops []HopItem
	var mu sync.Mutex

	traceRes, err := probers.RunTraceroute(ctx, probers.TracerouteOptions{
		Target:   host,
		IP:       ip,
		Port:     port,
		Protocol: proto,
		MaxHops:  30,
		Probes:   3,
		Timeout:  timeout,
	}, func(hop probers.TraceHop) {
		mu.Lock()
		defer mu.Unlock()

		addrStr := "*"
		if hop.Addr != nil {
			addrStr = hop.Addr.String()
		}
		rtts := make([]float64, len(hop.RTTs))
		for idx, r := range hop.RTTs {
			rtts[idx] = r.Seconds() * 1000
		}
		hops = append(hops, HopItem{
			Hop:      hop.Hop,
			Address:  addrStr,
			Hostname: hop.Hostname,
			RTTsMs:   rtts,
			Timeout:  hop.Timeout && len(hop.RTTs) == 0,
		})
	})

	ipStr := ""
	if ip.IsValid() {
		ipStr = ip.String()
	}

	resp := &TriggerResponse{
		Success:   err == nil,
		Target:    targetDisplay,
		Hostname:  host,
		IP:        ipStr,
		Port:      port,
		Protocol:  strings.ToUpper(string(proto)),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hops:      hops,
	}

	if err != nil {
		resp.Error = err.Error()
		resp.ErrorCode = "TRACEROUTE_ERROR"
	}
	_ = traceRes
	return resp, nil
}

func resolveTriggerTarget(req TriggerRequest) (string, uint16, consts.Protocol, string, error) {
	rawTarget := req.Target
	if rawTarget == "" {
		rawTarget = req.Host
	}
	if rawTarget == "" {
		rawTarget = req.URI
	}
	if rawTarget == "" {
		return "", 0, consts.TCP, "", fmt.Errorf("target, host, or uri must be specified")
	}

	protoStr := req.Protocol
	port := req.Port
	svc := req.ServiceName

	// If URI format provided (scheme://host:port or host:port)
	if strings.Contains(rawTarget, "://") {
		parts := strings.SplitN(rawTarget, "://", 2)
		if protoStr == "" {
			protoStr = parts[0]
		}
		rawTarget = parts[1]
	}

	host := rawTarget
	if h, p, err := net.SplitHostPort(rawTarget); err == nil {
		host = h
		if port == 0 {
			if parsed, err := strconv.ParseUint(p, 10, 16); err == nil && parsed > 0 {
				port = uint16(parsed)
			}
		}
	}

	proto, defPortStr, _ := resolveProtocolAndDefaultPort(protoStr)
	if port == 0 {
		if defP, err := strconv.ParseUint(defPortStr, 10, 16); err == nil && defP > 0 {
			port = uint16(defP)
		} else {
			port = 443
		}
	}

	return host, port, proto, svc, nil
}

func resolveProtocolAndDefaultPort(protocolStr string) (consts.Protocol, string, string) {
	proto, port, _ := consts.NormalizeProtocol(protocolStr)
	return proto, strconv.Itoa(int(port)), ""
}

func buildPinger(host string, ip netip.Addr, port uint16, proto consts.Protocol, svc string, timeout time.Duration, req TriggerRequest) probers.Pinger {
	return probers.BuildPinger(probers.FactoryOptions{
		Protocol:    proto,
		Hostname:    host,
		IP:          ip,
		Port:        port,
		Timeout:     timeout,
		UseIPv4:     req.UseIPv4,
		UseIPv6:     req.UseIPv6,
		SendData:    req.SendData,
		ExpectData:  req.ExpectData,
		ServiceName: svc,
		StartTLS:    req.StartTLS,
		FastClose:   req.FastClose,
	})
}
