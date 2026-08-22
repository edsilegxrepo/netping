package probers

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
	"github.com/edsilegx/netping/pkg/stats"
	"github.com/edsilegx/netping/pkg/utils"
)

// TargetWorker represents an individual probe task for a specific target endpoint.
type TargetWorker struct {
	Target      string
	Host        string
	IP          netip.Addr
	Port        uint16
	Protocol    consts.Protocol
	ServiceName string
	Pinger      Pinger
	Stats       *stats.Statistics
}

// MultiProberOptions configures execution options for MultiProber.
type MultiProberOptions struct {
	ProbeCount   uint
	Interval     time.Duration
	Timeout      time.Duration
	Concurrency  uint
	ShowDiags    bool
	NoColor      bool
	HideLiveLogs bool
	OnProbeEvent func(res ProbeResult, w TargetWorker, seq uint)
}

// MultiProber coordinates concurrent probing against multiple targets in parallel.
type MultiProber struct {
	workers      []TargetWorker
	opts         MultiProberOptions
	printerMutex sync.Mutex
	stopSignal   chan struct{}
	startTime    time.Time
	endTime      time.Time
}

// NewMultiProber constructs a new multi-target probing coordinator.
func NewMultiProber(workers []TargetWorker, opts MultiProberOptions) *MultiProber {
	return &MultiProber{
		workers:    workers,
		opts:       opts,
		stopSignal: make(chan struct{}),
		startTime:  time.Now(),
	}
}

// Workers returns the list of target workers.
func (m *MultiProber) Workers() []TargetWorker {
	return m.workers
}

func formatTargetBadge(worker TargetWorker) string {
	protoDisplay := strings.ToUpper(string(worker.Protocol))
	if protoDisplay == "" {
		protoDisplay = "TCP"
	}

	host := worker.Host
	if host == "" && worker.Target != "" {
		host = worker.Target
	}

	if worker.IP.IsValid() {
		ipStr := worker.IP.String()
		if host == "" || host == ipStr {
			if worker.Port > 0 {
				return fmt.Sprintf("[%s:%d (%s)]", ipStr, worker.Port, protoDisplay)
			}
			return fmt.Sprintf("[%s (%s)]", ipStr, protoDisplay)
		}
		if worker.Port > 0 {
			return fmt.Sprintf("[%s:%d (%s,%s)]", host, worker.Port, ipStr, protoDisplay)
		}
		return fmt.Sprintf("[%s (%s,%s)]", host, ipStr, protoDisplay)
	}

	if worker.Port > 0 {
		return fmt.Sprintf("[%s:%d (%s)]", host, worker.Port, protoDisplay)
	}
	return fmt.Sprintf("[%s (%s)]", host, protoDisplay)
}

func formatTargetBadgeColored(worker TargetWorker) string {
	protoDisplay := strings.ToUpper(string(worker.Protocol))
	if protoDisplay == "" {
		protoDisplay = "TCP"
	}

	host := worker.Host
	if host == "" && worker.Target != "" {
		host = worker.Target
	}

	// Entire badge (Host, IP, brackets, commas) is \033[1;36m (cyan). Port and Protocol are \033[38;5;75m (sky blue).
	if worker.IP.IsValid() {
		ipStr := worker.IP.String()
		if host == "" || host == ipStr {
			if worker.Port > 0 {
				return fmt.Sprintf("\033[1;36m[%s:\033[38;5;75m%d\033[1;36m (\033[38;5;75m%s\033[1;36m)]\033[0m",
					ipStr, worker.Port, protoDisplay)
			}
			return fmt.Sprintf("\033[1;36m[%s (\033[38;5;75m%s\033[1;36m)]\033[0m",
				ipStr, protoDisplay)
		}
		if worker.Port > 0 {
			return fmt.Sprintf("\033[1;36m[%s:\033[38;5;75m%d\033[1;36m (%s,\033[38;5;75m%s\033[1;36m)]\033[0m",
				host, worker.Port, ipStr, protoDisplay)
		}
		return fmt.Sprintf("\033[1;36m[%s (%s,\033[38;5;75m%s\033[1;36m)]\033[0m",
			host, ipStr, protoDisplay)
	}

	if worker.Port > 0 {
		return fmt.Sprintf("\033[1;36m[%s:\033[38;5;75m%d\033[1;36m (\033[38;5;75m%s\033[1;36m)]\033[0m",
			host, worker.Port, protoDisplay)
	}
	return fmt.Sprintf("\033[1;36m[%s (\033[38;5;75m%s\033[1;36m)]\033[0m",
		host, protoDisplay)
}

// Run executes parallel probes across all target workers until cancelled or probe count reached.
func (m *MultiProber) Run(ctx context.Context) {
	var wg sync.WaitGroup

	maxBadgeLen := 0
	for _, w := range m.workers {
		b := formatTargetBadge(w)
		if len(b) > maxBadgeLen {
			maxBadgeLen = len(b)
		}
	}

	var sem chan struct{}
	if m.opts.Concurrency > 0 {
		sem = make(chan struct{}, m.opts.Concurrency)
	}

	for _, w := range m.workers {
		wg.Add(1)
		go func(worker TargetWorker) {
			defer wg.Done()
			var seq uint

			for {
				select {
				case <-ctx.Done():
					return
				case <-m.stopSignal:
					return
				default:
				}

				if sem != nil {
					sem <- struct{}{}
				}

				seq++
				res := worker.Pinger.Ping(ctx)

				if sem != nil {
					<-sem
				}

				now := time.Now()
				worker.Stats.Mu.Lock()
				if res.Err == nil {
					rttMs := float32(res.RTT.Seconds() * 1000)
					worker.Stats.TotalSuccessfulProbes++
					worker.Stats.OngoingSuccessfulProbes++
					worker.Stats.LatestRTT = rttMs
					worker.Stats.RTT = append(worker.Stats.RTT, rttMs)
					worker.Stats.LastSuccessfulProbe = now
				} else {
					worker.Stats.TotalUnsuccessfulProbes++
					worker.Stats.OngoingUnsuccessfulProbes++
					worker.Stats.LastUnsuccessfulProbe = now
				}
				worker.Stats.Mu.Unlock()

				plainBadge := formatTargetBadge(worker)
				pad := ""
				if padLen := maxBadgeLen - len(plainBadge); padLen > 0 {
					pad = strings.Repeat(" ", padLen)
				}

				if !m.opts.HideLiveLogs {
					m.printerMutex.Lock()
					if res.Err == nil {
						rttMs := res.RTT.Seconds() * 1000
						if m.opts.NoColor {
							fmt.Printf("● %s%s Reply_seq=%d time=%.2f ms\n", plainBadge, pad, seq, rttMs)
						} else {
							fmt.Printf("\033[38;5;71m●\033[0m %s%s Reply_seq=\033[38;5;248m%d\033[0m time=\033[1;37m%.2f ms\033[0m\n", formatTargetBadgeColored(worker), pad, seq, rttMs)
						}
						if m.opts.ShowDiags && res.Diagnostics != "" {
							if m.opts.NoColor {
								fmt.Printf("  └─ [DIAG] %s\n", res.Diagnostics)
							} else {
								fmt.Printf("  \033[38;5;240m└─\033[0m \033[38;5;244m[DIAG]\033[0m \033[38;5;75m%s\033[0m\n", res.Diagnostics)
							}
						}
					} else {
						errMsg := utils.ClassifyError(res.Err)
						if m.opts.NoColor {
							fmt.Printf("✖ %s%s No reply_seq=%d (%s)\n", plainBadge, pad, seq, errMsg)
						} else {
							fmt.Printf("\033[38;5;167m✖\033[0m %s%s \033[31mNo reply_seq=%d\033[0m (\033[38;5;167m%s\033[0m)\n", formatTargetBadgeColored(worker), pad, seq, errMsg)
						}
					}
					m.printerMutex.Unlock()
				}

				if m.opts.OnProbeEvent != nil {
					m.opts.OnProbeEvent(res, worker, seq)
				}

				if m.opts.ProbeCount > 0 && seq >= m.opts.ProbeCount {
					return
				}

				select {
				case <-ctx.Done():
					return
				case <-m.stopSignal:
					return
				case <-time.After(m.opts.Interval):
				}
			}
		}(w)
	}

	wg.Wait()
	m.endTime = time.Now()
	if !m.opts.HideLiveLogs {
		m.PrintSummaryTable()
	}
}

// PrintSummaryTable prints a comparative multi-target latency & packet loss summary table and aggregate recap.
func (m *MultiProber) PrintSummaryTable() {
	m.printerMutex.Lock()
	defer m.printerMutex.Unlock()

	targetColW := 23
	for _, w := range m.workers {
		if len(w.Target) > targetColW {
			targetColW = len(w.Target)
		}
	}
	if targetColW > 42 {
		targetColW = 42
	}

	topBorder := fmt.Sprintf("┌%s┬────────────┬────────┬────────┬────────┬────────┬────────┬──────────┐", strings.Repeat("─", targetColW+2))
	midBorder := fmt.Sprintf("├%s┼────────────┼────────┼────────┼────────┼────────┼────────┼──────────┤", strings.Repeat("─", targetColW+2))
	botBorder := fmt.Sprintf("└%s┴────────────┴────────┴────────┴────────┴────────┴────────┴──────────┘", strings.Repeat("─", targetColW+2))

	fmt.Println("\n" + topBorder)
	fmt.Printf("│ %-*s │ %-10s │ %-6s │ %-6s │ %-6s │ %-6s │ %-6s │ %-8s │\n", targetColW, "TARGET", "PROTOCOL", "SENT", "RECV", "LOSS %", "MIN ms", "AVG ms", "MAX ms")
	fmt.Println(midBorder)

	totalSuccess := uint(0)
	totalUnsuccess := uint(0)
	var lastSuccess time.Time
	var lastUnsuccess time.Time
	totalUptime := time.Duration(0)
	totalDowntime := time.Duration(0)
	var allRTTs []float32
	totalRetriedResolve := uint(0)
	var longestUp stats.LongestTime
	var longestDown stats.LongestTime

	for _, w := range m.workers {
		w.Stats.Mu.RLock()
		total := w.Stats.TotalSuccessfulProbes + w.Stats.TotalUnsuccessfulProbes
		succ := w.Stats.TotalSuccessfulProbes
		unsucc := w.Stats.TotalUnsuccessfulProbes
		totalSuccess += succ
		totalUnsuccess += unsucc
		if w.Stats.LastSuccessfulProbe.After(lastSuccess) {
			lastSuccess = w.Stats.LastSuccessfulProbe
		}
		if w.Stats.LastUnsuccessfulProbe.After(lastUnsuccess) {
			lastUnsuccess = w.Stats.LastUnsuccessfulProbe
		}
		totalUptime += w.Stats.TotalUptime
		totalDowntime += w.Stats.TotalDowntime
		totalRetriedResolve += w.Stats.RetriedHostnameLookups
		allRTTs = append(allRTTs, w.Stats.RTT...)
		if w.Stats.LongestUp.Duration > longestUp.Duration {
			longestUp = w.Stats.LongestUp
		}
		if w.Stats.LongestDown.Duration > longestDown.Duration {
			longestDown = w.Stats.LongestDown
		}

		loss := float64(0)
		if total > 0 {
			loss = float64(unsucc) / float64(total) * 100.0
		}

		min, avg, max := float32(0), float32(0), float32(0)
		if len(w.Stats.RTT) > 0 {
			var sum float32
			min = slices.Min(w.Stats.RTT)
			max = slices.Max(w.Stats.RTT)
			for _, r := range w.Stats.RTT {
				sum += r
			}
			avg = sum / float32(len(w.Stats.RTT))
		}
		w.Stats.Mu.RUnlock()

		protoDisplay := strings.ToUpper(string(w.Protocol))
		if protoDisplay == "" {
			protoDisplay = "TCP"
		}

		tgtDisplay := w.Target
		if len(tgtDisplay) > targetColW {
			tgtDisplay = tgtDisplay[:targetColW-3] + "..."
		}

		fmt.Printf("│ %-*s │ %-10s │ %-6d │ %-6d │ %5.1f%% │ %6.2f │ %6.2f │ %8.2f │\n",
			targetColW, tgtDisplay, protoDisplay, total, succ, loss, min, avg, max)
	}
	fmt.Println(botBorder)

	// Aggregate recap across ALL probes
	endTime := m.endTime
	if endTime.IsZero() {
		endTime = time.Now()
	}
	startTime := m.startTime
	if startTime.IsZero() {
		startTime = endTime.Add(-time.Second)
	}

	dur := endTime.Sub(startTime).Round(time.Second)
	if totalUptime == 0 && totalDowntime == 0 {
		if totalUnsuccess == 0 {
			totalUptime = dur
		} else if totalSuccess == 0 {
			totalDowntime = dur
		}
	}

	if m.opts.NoColor {
		fmt.Printf("successful probes:   %d\n", totalSuccess)
		fmt.Printf("unsuccessful probes: %d\n", totalUnsuccess)

		if lastSuccess.IsZero() {
			fmt.Printf("last successful probe:   Never succeeded\n")
		} else {
			fmt.Printf("last successful probe:   %v\n", lastSuccess.Format(time.DateTime))
		}

		if lastUnsuccess.IsZero() {
			fmt.Printf("last unsuccessful probe: Never failed\n")
		} else {
			fmt.Printf("last unsuccessful probe: %v\n", lastUnsuccess.Format(time.DateTime))
		}

		fmt.Printf("total uptime:   %s\n", utils.DurationToString(totalUptime))
		fmt.Printf("total downtime: %s\n", utils.DurationToString(totalDowntime))

		if longestUp.Duration != 0 {
			uptime := utils.DurationToString(longestUp.Duration)
			fmt.Printf("longest consecutive uptime:   %v from %v to %v\n",
				uptime, longestUp.Start.Format(time.DateTime), longestUp.End.Format(time.DateTime))
		}

		if longestDown.Duration != 0 {
			downtime := utils.DurationToString(longestDown.Duration)
			fmt.Printf("longest consecutive downtime: %v from %v to %v\n",
				downtime, longestDown.Start.Format(time.DateTime), longestDown.End.Format(time.DateTime))
		}

		if totalRetriedResolve > 0 {
			timeNoun := "time"
			if totalRetriedResolve > 1 {
				timeNoun = "times"
			}
			fmt.Printf("retried to resolve hostname:  %d %s\n", totalRetriedResolve, timeNoun)
		}

		if len(allRTTs) > 0 {
			var sum float32
			minRTT := slices.Min(allRTTs)
			maxRTT := slices.Max(allRTTs)
			for _, r := range allRTTs {
				sum += r
			}
			avgRTT := sum / float32(len(allRTTs))
			jitter := utils.CalculateJitter(allRTTs)
			p95 := utils.CalculatePercentile(allRTTs, 95)

			fmt.Printf("rtt min/avg/max: %.3f/%.3f/%.3f ms", minRTT, avgRTT, maxRTT)
			if jitter > 0 {
				fmt.Printf(" │ jitter: %.3f ms", jitter)
			}
			if p95 > 0 {
				fmt.Printf(" │ p95: %.3f ms", p95)
			}
			fmt.Print("\n")
		}

		fmt.Printf("--------------------------------------\n")
		fmt.Printf("TCPing started at:   %v\n", startTime.Format(time.DateTime))
		fmt.Printf("TCPing ended at:     %v\n", endTime.Format(time.DateTime))
		durationTime := time.Time{}.Add(dur)
		fmt.Printf("duration (HH:MM:SS): %v\n\n", durationTime.Format(time.TimeOnly))
	} else {
		fmt.Printf("\033[38;5;244msuccessful probes:\033[0m   \033[38;5;71m%d\033[0m\n", totalSuccess)
		fmt.Printf("\033[38;5;244munsuccessful probes:\033[0m \033[38;5;167m%d\033[0m\n", totalUnsuccess)

		if lastSuccess.IsZero() {
			fmt.Printf("\033[38;5;244mlast successful probe:\033[0m   \033[38;5;244mNever succeeded\033[0m\n")
		} else {
			fmt.Printf("\033[38;5;244mlast successful probe:\033[0m   \033[38;5;250m%v\033[0m\n", lastSuccess.Format(time.DateTime))
		}

		if lastUnsuccess.IsZero() {
			fmt.Printf("\033[38;5;244mlast unsuccessful probe:\033[0m \033[38;5;244mNever failed\033[0m\n")
		} else {
			fmt.Printf("\033[38;5;244mlast unsuccessful probe:\033[0m \033[38;5;167m%v\033[0m\n", lastUnsuccess.Format(time.DateTime))
		}

		fmt.Printf("\033[38;5;244mtotal uptime:\033[0m   \033[38;5;71m%s\033[0m\n", utils.DurationToString(totalUptime))
		fmt.Printf("\033[38;5;244mtotal downtime:\033[0m \033[38;5;167m%s\033[0m\n", utils.DurationToString(totalDowntime))

		if longestUp.Duration != 0 {
			uptime := utils.DurationToString(longestUp.Duration)
			fmt.Printf("\033[38;5;244mlongest consecutive uptime:\033[0m   \033[38;5;71m%v\033[0m \033[38;5;244mfrom\033[0m \033[38;5;250m%v\033[0m \033[38;5;244mto\033[0m \033[38;5;250m%v\033[0m\n",
				uptime, longestUp.Start.Format(time.DateTime), longestUp.End.Format(time.DateTime))
		}

		if longestDown.Duration != 0 {
			downtime := utils.DurationToString(longestDown.Duration)
			fmt.Printf("\033[38;5;244mlongest consecutive downtime:\033[0m \033[38;5;167m%v\033[0m \033[38;5;244mfrom\033[0m \033[38;5;250m%v\033[0m \033[38;5;244mto\033[0m \033[38;5;250m%v\033[0m\n",
				downtime, longestDown.Start.Format(time.DateTime), longestDown.End.Format(time.DateTime))
		}

		if totalRetriedResolve > 0 {
			timeNoun := "time"
			if totalRetriedResolve > 1 {
				timeNoun = "times"
			}
			fmt.Printf("\033[38;5;244mretried to resolve hostname:\033[0m  \033[1;37m%d\033[0m \033[38;5;244m%s\033[0m\n", totalRetriedResolve, timeNoun)
		}

		if len(allRTTs) > 0 {
			var sum float32
			minRTT := slices.Min(allRTTs)
			maxRTT := slices.Max(allRTTs)
			for _, r := range allRTTs {
				sum += r
			}
			avgRTT := sum / float32(len(allRTTs))
			jitter := utils.CalculateJitter(allRTTs)
			p95 := utils.CalculatePercentile(allRTTs, 95)

			fmt.Printf("\033[38;5;244mrtt min/avg/max:\033[0m \033[1;37m%.3f\033[0m/\033[1;37m%.3f\033[0m/\033[1;37m%.3f\033[0m \033[38;5;244mms\033[0m",
				minRTT, avgRTT, maxRTT)
			if jitter > 0 {
				fmt.Printf(" \033[38;5;240m│\033[0m \033[38;5;244mjitter:\033[0m \033[1;37m%.3f ms\033[0m", jitter)
			}
			if p95 > 0 {
				fmt.Printf(" \033[38;5;240m│\033[0m \033[38;5;244mp95:\033[0m \033[38;5;221m%.3f ms\033[0m", p95)
			}
			fmt.Print("\n")
		}

		fmt.Printf("\033[38;5;240m--------------------------------------\033[0m\n")
		fmt.Printf("\033[38;5;244mTCPing started at:\033[0m   \033[38;5;250m%v\033[0m\n", startTime.Format(time.DateTime))
		fmt.Printf("\033[38;5;244mTCPing ended at:\033[0m     \033[38;5;250m%v\033[0m\n", endTime.Format(time.DateTime))
		durationTime := time.Time{}.Add(dur)
		fmt.Printf("\033[38;5;244mduration (HH:MM:SS):\033[0m \033[1;37m%v\033[0m\n\n", durationTime.Format(time.TimeOnly))
	}
}

