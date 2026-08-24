// Package probers implements high-precision Layer 3 to Layer 7 network diagnostic probers,
// protocol handshakes, and wire-level timing measurements across 49 supported protocols.
//
// Objectives:
//   - Execute latency and connectivity checks with nanosecond clock precision.
//   - Extract detailed protocol-level metadata (TLS ciphers, cert expiry, HTTP TTFB, DB banners, DNS RCODEs).
//   - Provide a unified Pinger interface across all protocols and operational modes.
//
// Core Components:
//   - Pinger: Core interface defining Ping(context.Context) ProbeResult.
//   - ProbeResult: Standardized telemetry struct carrying latency breakdowns, status codes, and diagnostics.
//   - BuildPinger: Factory function constructing protocol-specific pingers from unified configuration options.
//
// Data Flow:
//
//	Context & Target -> probers.BuildPinger -> Pinger.Ping(ctx) -> Socket Dial / Protocol Handshake
//	-> Latency Breakdown (DNS, TCP, TLS, TTFB) -> Protocol Diagnostics -> ProbeResult.
package probers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/edsilegx/netping/pkg/utils"
)

var (
	ErrTimeout       = errors.New("timed out waiting for ping")
	ErrPingCompleted = errors.New("ping completed")
)

// ProbeResult contains the outcome and network details of a single probe.
type ProbeResult struct {
	LocalAddr     net.Addr
	RTT           time.Duration
	DNSTime       time.Duration
	TCPTime       time.Duration
	TLSTime       time.Duration
	TTFB          time.Duration
	HTTPStatus    int
	CertExpiry    time.Time
	Diagnostics   string
	FailureReason string
	Err           error
}

// Pinger defines the interface for all protocol probing engines.
type Pinger interface {
	Ping(ctx context.Context) ProbeResult
}

// Printer defines the output interface required by Prober.
type Printer interface {
	PrintProbeSuccess(s *stats.Statistics)
	PrintProbeFailure(s *stats.Statistics)
	PrintTotalDownTime(s *stats.Statistics)
	PrintRetryingToResolve(hostname string)
	PrintError(format string, args ...any)
}

// Resolver defines the hostname re-resolution interface.
type Resolver interface {
	RetryResolveHostname(s *stats.Statistics) error
}

// Options holds runtime parameters for the probing loop.
type Options struct {
	Timeout                    time.Duration
	IntervalBetweenProbes      time.Duration
	ProbesBeforeQuit           uint
	ShouldRetryResolve         bool
	RetryResolveAfterNFailures uint
	ResolveEveryProbe          bool
	MaxConsecutiveFails        uint
	MaxLatency                 float64
	QuietMode                  bool
	Retries                    uint
	InitialRetryBackoff        time.Duration
	MaxRetryBackoff            time.Duration
	RetryJitter                bool
	OnProbeResult              func(res ProbeResult, s *stats.Statistics)
	Resolver                   Resolver
}

// Prober coordinates scheduled probe execution and state updates.
type Prober struct {
	pinger     Pinger
	printer    Printer
	opts       Options
	Ticker     *time.Ticker
	Timeout    time.Duration
	Statistics *stats.Statistics
}

// NewProber constructs a new Prober.
func NewProber(pinger Pinger, printer Printer, stat *stats.Statistics, opts Options) *Prober {
	interval := opts.IntervalBetweenProbes
	if interval <= 0 {
		interval = time.Second
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}

	return &Prober{
		pinger:     pinger,
		printer:    printer,
		opts:       opts,
		Ticker:     time.NewTicker(interval),
		Timeout:    timeout,
		Statistics: stat,
	}
}

// Probe runs the continuous or count-limited probing loop.
func (p *Prober) Probe(ctx context.Context) (*stats.Statistics, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var probeCount uint

	defer p.Ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.finalizeStatistics()
			return p.Statistics, nil

		case <-p.Ticker.C:
			pingTime := time.Now()

			if p.opts.ResolveEveryProbe && !p.Statistics.DestIsIP && p.opts.Resolver != nil {
				_ = p.opts.Resolver.RetryResolveHostname(p.Statistics)
			}

			probeCtx, cancel := context.WithTimeout(ctx, p.Timeout)
			res := p.pinger.Ping(probeCtx)
			cancel()

			rttMs := utils.NanoToMillisecond(res.RTT.Nanoseconds())
			isFailure := res.Err != nil
			if !isFailure && p.opts.MaxLatency > 0 && float64(rttMs) > p.opts.MaxLatency {
				isFailure = true
				res.Err = fmt.Errorf("latency SLA breached: %.2fms > %.2fms", rttMs, p.opts.MaxLatency)
			}

			// If initial probe failed and retries are configured, perform exponential backoff retries
			if isFailure && p.opts.Retries > 0 {
				for attempt := 1; attempt <= int(p.opts.Retries); attempt++ {
					delay := utils.CalculateBackoff(attempt-1, utils.BackoffConfig{
						InitialDelay: p.opts.InitialRetryBackoff,
						MaxDelay:     p.opts.MaxRetryBackoff,
						Multiplier:   2.0,
						Jitter:       p.opts.RetryJitter,
					})

					if err := utils.SleepWithContext(ctx, delay); err != nil {
						break
					}

					retryCtx, retryCancel := context.WithTimeout(ctx, p.Timeout)
					retryRes := p.pinger.Ping(retryCtx)
					retryCancel()

					retryRttMs := utils.NanoToMillisecond(retryRes.RTT.Nanoseconds())
					retryFailure := retryRes.Err != nil
					if !retryFailure && p.opts.MaxLatency > 0 && float64(retryRttMs) > p.opts.MaxLatency {
						retryFailure = true
						retryRes.Err = fmt.Errorf("latency SLA breached: %.2fms > %.2fms", retryRttMs, p.opts.MaxLatency)
					}

					if !retryFailure {
						res = retryRes
						rttMs = retryRttMs
						isFailure = false
						break
					}
					res = retryRes
					rttMs = retryRttMs
				}
			}

			if isFailure {
				p.Statistics.Mu.Lock()
				p.Statistics.OngoingSuccessfulProbes = 0
				p.Statistics.OngoingUnsuccessfulProbes++
				p.Statistics.Failed++
				p.Statistics.TotalUnsuccessfulProbes++
				p.Statistics.LastUnsuccessfulProbe = pingTime
				p.Statistics.LastFailureReason = utils.ClassifyError(res.Err)

				if !p.Statistics.DestWasDown {
					p.Statistics.DestWasDown = true
					p.Statistics.StartOfDowntime = pingTime
				}
				p.Statistics.Mu.Unlock()

				if p.printer != nil && !p.opts.QuietMode {
					p.printer.PrintProbeFailure(p.Statistics)
				}

				if p.opts.ShouldRetryResolve && p.Statistics.OngoingUnsuccessfulProbes >= p.opts.RetryResolveAfterNFailures && p.opts.Resolver != nil {
					p.Statistics.RetriedHostnameLookups++
					if p.printer != nil && !p.opts.QuietMode {
						p.printer.PrintRetryingToResolve(p.Statistics.Hostname)
					}
					if err := p.opts.Resolver.RetryResolveHostname(p.Statistics); err != nil {
						if p.printer != nil {
							p.printer.PrintError("%s", err.Error())
						}
					}
				}

				if p.opts.MaxConsecutiveFails > 0 && p.Statistics.OngoingUnsuccessfulProbes >= p.opts.MaxConsecutiveFails {
					p.finalizeStatistics()
					return p.Statistics, nil
				}
			} else {
				p.Statistics.RecordSuccess(rttMs, pingTime)
				p.Statistics.Mu.Lock()
				if res.LocalAddr != nil {
					p.Statistics.LocalAddr = res.LocalAddr
				}
				p.Statistics.LatestDiagnostics = res.Diagnostics
				p.Statistics.LatestDNSTime = res.DNSTime
				p.Statistics.LatestTCPTime = res.TCPTime
				p.Statistics.LatestTLSTime = res.TLSTime
				p.Statistics.LatestTTFB = res.TTFB
				p.Statistics.LatestHTTPStatus = res.HTTPStatus
				p.Statistics.LatestCertExpiry = res.CertExpiry

				if p.Statistics.DestWasDown {
					p.Statistics.DestWasDown = false
					downDuration := pingTime.Sub(p.Statistics.StartOfDowntime)
					p.Statistics.TotalDowntime += downDuration
					p.Statistics.DownTime = downDuration
					utils.SetLongestDuration(p.Statistics.StartOfDowntime, downDuration, &p.Statistics.LongestDown)
					p.Statistics.StartOfUptime = pingTime
					if p.printer != nil && !p.opts.QuietMode {
						p.printer.PrintTotalDownTime(p.Statistics)
					}
				}

				if p.Statistics.StartOfUptime.IsZero() {
					p.Statistics.StartOfUptime = pingTime
				}
				p.Statistics.Mu.Unlock()

				if p.printer != nil && !p.opts.QuietMode {
					p.printer.PrintProbeSuccess(p.Statistics)
				}
			}

			if p.opts.OnProbeResult != nil {
				p.opts.OnProbeResult(res, p.Statistics)
			}

			if p.opts.ProbesBeforeQuit > 0 {
				probeCount++
				if probeCount >= p.opts.ProbesBeforeQuit {
					p.finalizeStatistics()
					return p.Statistics, nil
				}
			}
		}
	}
}

func (p *Prober) finalizeStatistics() {
	p.Statistics.Mu.Lock()
	defer p.Statistics.Mu.Unlock()

	p.Statistics.EndTime = time.Now()
	p.Statistics.UpTime = p.Statistics.EndTime.Sub(p.Statistics.StartTime)

	if p.Statistics.DestWasDown {
		downDuration := p.Statistics.EndTime.Sub(p.Statistics.StartOfDowntime)
		p.Statistics.TotalDowntime += downDuration
		p.Statistics.DownTime = downDuration
		utils.SetLongestDuration(p.Statistics.StartOfDowntime, downDuration, &p.Statistics.LongestDown)
	} else {
		upDuration := p.Statistics.EndTime.Sub(p.Statistics.StartOfUptime)
		p.Statistics.TotalUptime += upDuration
		utils.SetLongestDuration(p.Statistics.StartOfUptime, upDuration, &p.Statistics.LongestUp)
	}
}
