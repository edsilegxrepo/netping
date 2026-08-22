package printers

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"golang.org/x/term"
)

// DashboardPrinter renders a high-performance, real-time terminal UI dashboard.
type DashboardPrinter struct {
	mu           sync.Mutex
	target       string
	port         uint16
	protocol     string
	stats        *stats.Statistics
	underlying   Printer
	recentRTTs   []float32
	recentProbes []string
	startTime    time.Time
	maxLogLines  int
	closed       bool
}

// NewDashboardPrinter constructs a new live terminal dashboard.
func NewDashboardPrinter(target string, port uint16, protocol string, stat *stats.Statistics, underlying ...Printer) *DashboardPrinter {
	// Enable alternate screen buffer
	fmt.Print("\033[?1049h\033[H\033[2J\033[?25l")

	var und Printer
	if len(underlying) > 0 {
		und = underlying[0]
	}

	return &DashboardPrinter{
		target:       target,
		port:         port,
		protocol:     protocol,
		stats:        stat,
		underlying:   und,
		recentRTTs:   make([]float32, 0, 110),
		recentProbes: make([]string, 0, 10),
		startTime:    time.Now(),
		maxLogLines:  8,
	}
}

// Close restores the normal terminal screen buffer and shows cursor.
func (d *DashboardPrinter) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		fmt.Print("\033[?25h\033[?1049l")
	}
}

// PrintStart displays initial startup info if needed.
func (d *DashboardPrinter) PrintStart(s *stats.Statistics) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.render()
}

// PrintProbeSuccess records a probe success and redraws the dashboard.
func (d *DashboardPrinter) PrintProbeSuccess(s *stats.Statistics) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rtt := s.LatestRTT
	d.recentRTTs = append(d.recentRTTs, rtt)
	if len(d.recentRTTs) > 105 {
		d.recentRTTs = d.recentRTTs[1:]
	}

	ipStr := s.IP.String()
	logLine := fmt.Sprintf("\033[38;5;71m●\033[0m \033[38;5;244m[%s]\033[0m \033[38;5;248mSeq=%-4d\033[0m \033[38;5;244mRTT=\033[0m\033[1;37m%7.2f ms\033[0m \033[38;5;244mIP=\033[0m\033[38;5;248m%s\033[0m", time.Now().Format("15:04:05"), s.OngoingSuccessfulProbes+s.OngoingUnsuccessfulProbes, rtt, ipStr)
	if s.WithDiags && s.LatestDiagnostics != "" {
		logLine = fmt.Sprintf("\033[38;5;71m●\033[0m \033[38;5;244m[%s]\033[0m \033[38;5;248m#%-4d\033[0m \033[1;37m%6.2f ms\033[0m \033[38;5;240m│\033[0m \033[38;5;75m%s\033[0m", time.Now().Format("15:04:05"), s.OngoingSuccessfulProbes+s.OngoingUnsuccessfulProbes, rtt, s.LatestDiagnostics)
	}
	d.addLog(logLine)
	d.render()
}

// PrintProbeFailure records a probe failure and redraws the dashboard.
func (d *DashboardPrinter) PrintProbeFailure(s *stats.Statistics) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.recentRTTs = append(d.recentRTTs, 0)
	if len(d.recentRTTs) > 105 {
		d.recentRTTs = d.recentRTTs[1:]
	}

	errMsg := s.LastFailureReason
	if errMsg == "" {
		errMsg = "Timeout"
	}
	logLine := fmt.Sprintf("\033[38;5;167m✖\033[0m \033[38;5;244m[%s]\033[0m \033[38;5;248mSeq=%-4d\033[0m \033[38;5;167mError: %s\033[0m", time.Now().Format("15:04:05"), s.OngoingSuccessfulProbes+s.OngoingUnsuccessfulProbes, errMsg)
	d.addLog(logLine)
	d.render()
}

func (d *DashboardPrinter) addLog(line string) {
	d.recentProbes = append(d.recentProbes, line)
	if len(d.recentProbes) > 100 {
		d.recentProbes = d.recentProbes[1:]
	}
}

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(str string) string {
	return ansiRegex.ReplaceAllString(str, "")
}

func visibleLen(str string) int {
	clean := stripANSI(str)
	return len([]rune(clean))
}

func padRightVisible(s string, targetWidth int) string {
	vlen := visibleLen(s)
	if vlen < targetWidth {
		return s + strings.Repeat(" ", targetWidth-vlen)
	}
	return s
}

func getTerminalDimensions() (int, int) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 80, 24
	}
	return w, h
}

func renderRow(content string, innerW int) string {
	return fmt.Sprintf("\033[38;5;60m│\033[0m %s \033[38;5;60m│\033[0m\n", padRightVisible(content, innerW))
}

func renderKPI(items []string, innerW int) string {
	n := len(items)
	if n == 0 {
		return ""
	}
	sep := "\033[38;5;239m│\033[0m"
	sepsLen := (n - 1) * 3 // " │ "
	avail := innerW - sepsLen
	colW := avail / n
	rem := avail % n

	var b strings.Builder
	for i, it := range items {
		w := colW
		if i < rem {
			w++
		}
		b.WriteString(padRightVisible(it, w))
		if i < n-1 {
			b.WriteString(" " + sep + " ")
		}
	}
	return b.String()
}

func renderMultiLineChart(rtts []float32, plotWidth int, height int) []string {
	var lines []string
	if height < 3 {
		height = 5
	}

	maxVal := float32(10.0)
	for _, v := range rtts {
		if v > maxVal {
			maxVal = v
		}
	}
	maxVal = maxVal * 1.15

	dataLen := len(rtts)
	samples := make([]float32, plotWidth)
	offset := plotWidth - dataLen
	for i := 0; i < plotWidth; i++ {
		srcIdx := i - offset
		if srcIdx >= 0 && srcIdx < dataLen {
			samples[i] = rtts[srcIdx]
		} else {
			samples[i] = -1 // No data
		}
	}

	for row := height - 1; row >= 0; row-- {
		rowVal := (float32(row+1) / float32(height)) * maxVal
		var line strings.Builder
		line.WriteString(fmt.Sprintf("\033[38;5;244m%6.1fms\033[0m \033[38;5;240m┤\033[0m\033[38;5;75m", rowVal))

		for col := 0; col < plotWidth; col++ {
			val := samples[col]
			if val < 0 {
				line.WriteString(" ")
				continue
			}
			if val == 0 {
				line.WriteString("\033[38;5;167m.\033[38;5;75m") // Failed probe dot
				continue
			}

			norm := (val / maxVal) * float32(height)
			if norm >= float32(row+1) {
				line.WriteString("█")
			} else if norm >= float32(row)+0.5 {
				line.WriteString("▄")
			} else if norm >= float32(row)+0.15 {
				line.WriteString(" ")
			} else {
				line.WriteString(" ")
			}
		}
		line.WriteString("\033[0m")
		lines = append(lines, line.String())
	}

	axisLine := fmt.Sprintf("\033[38;5;244m   0.0ms\033[0m \033[38;5;240m┴\033[38;5;239m%s\033[0m", strings.Repeat("─", plotWidth))
	lines = append(lines, axisLine)
	return lines
}

// render refreshes the full dashboard view.
func (d *DashboardPrinter) render() {
	termW, termH := getTerminalDimensions()
	boxWidth := termW
	if boxWidth < 70 {
		boxWidth = 70
	}
	innerW := boxWidth - 4
	plotWidth := innerW - 10
	if plotWidth < 20 {
		plotWidth = 20
	}

	var b strings.Builder
	b.WriteString("\033[H") // Move cursor to top-left

	elapsed := time.Since(d.startTime).Round(time.Second)

	total := d.stats.TotalSuccessfulProbes + d.stats.TotalUnsuccessfulProbes
	successful := d.stats.TotalSuccessfulProbes
	failed := d.stats.TotalUnsuccessfulProbes

	lossRatio := float64(0)
	if total > 0 {
		lossRatio = float64(failed) / float64(total) * 100.0
	}

	res := calcMinAvgMaxRttTime(d.stats.RTT)

	borderHoriz := strings.Repeat("─", boxWidth-2)
	topBorder := fmt.Sprintf("\033[38;5;60m┌%s┐\033[0m\n", borderHoriz)
	midDivider := fmt.Sprintf("\033[38;5;60m├%s┤\033[0m\n", borderHoriz)
	bottomBorder := fmt.Sprintf("\033[38;5;60m└%s┘\033[0m\n", borderHoriz)

	// Top Border
	b.WriteString(topBorder)

	// Header Row
	headerStr := fmt.Sprintf("\033[1;37mNETPING DASHBOARD\033[0m   \033[38;5;244mTarget:\033[0m \033[1;38;5;75m%s:%d\033[0m   \033[38;5;244mProto:\033[0m \033[38;5;73m%s\033[0m   \033[38;5;244mElapsed:\033[0m \033[38;5;250m%s\033[0m", d.target, d.port, d.protocol, elapsed)
	b.WriteString(renderRow(headerStr, innerW))

	// Divider
	b.WriteString(midDivider)

	// Stats Row 1 (Counters & Jitter)
	lossColor := "\033[38;5;71m"
	if failed > 0 {
		lossColor = "\033[38;5;167m"
	}
	r1_1 := fmt.Sprintf("\033[38;5;244mProbes:\033[0m \033[1;37m%d\033[0m", total)
	r1_2 := fmt.Sprintf("\033[38;5;244mSuccess:\033[0m \033[38;5;71m%d\033[0m", successful)
	r1_3 := fmt.Sprintf("\033[38;5;244mFailed:\033[0m \033[38;5;167m%d\033[0m", failed)
	r1_4 := fmt.Sprintf("\033[38;5;244mLoss:\033[0m %s%.1f%%\033[0m", lossColor, lossRatio)
	r1_5 := fmt.Sprintf("\033[38;5;244mJit:\033[0m \033[1;37m%.2fms\033[0m", res.Jitter)
	b.WriteString(renderRow(renderKPI([]string{r1_1, r1_2, r1_3, r1_4, r1_5}, innerW), innerW))

	// Stats Row 2 (Latency & SLA Percentiles)
	r2_1 := fmt.Sprintf("\033[38;5;244mMin:\033[0m \033[1;37m%.2fms\033[0m", res.Min)
	r2_2 := fmt.Sprintf("\033[38;5;244mAvg:\033[0m \033[1;37m%.2fms\033[0m", res.Average)
	r2_3 := fmt.Sprintf("\033[38;5;244mMax:\033[0m \033[1;37m%.2fms\033[0m", res.Max)
	r2_4 := fmt.Sprintf("\033[38;5;244mP95:\033[0m \033[38;5;221m%.2fms\033[0m", res.P95)
	r2_5 := fmt.Sprintf("\033[38;5;244mP99:\033[0m \033[38;5;221m%.2fms\033[0m", res.P99)
	b.WriteString(renderRow(renderKPI([]string{r2_1, r2_2, r2_3, r2_4, r2_5}, innerW), innerW))

	if d.stats.WithDiags && d.stats.LatestDiagnostics != "" {
		b.WriteString(midDivider)
		diagRow := fmt.Sprintf("\033[38;5;244mDIAGNOSTICS:\033[0m \033[38;5;75m%s\033[0m", d.stats.LatestDiagnostics)
		b.WriteString(renderRow(diagRow, innerW))
	}

	// Divider
	b.WriteString(midDivider)

	// Chart Title Row
	b.WriteString(renderRow(fmt.Sprintf("\033[1;37mREAL-TIME LATENCY WAVEFORM\033[0m \033[38;5;244m(Last %d probes)\033[0m", plotWidth), innerW))

	// Chart Rows (5-row tall graph + axis = 6 lines)
	chartLines := renderMultiLineChart(d.recentRTTs, plotWidth, 5)
	for _, cl := range chartLines {
		b.WriteString(renderRow(cl, innerW))
	}

	// Divider
	b.WriteString(midDivider)

	// Log Title Row
	b.WriteString(renderRow("\033[1;37mRECENT PROBE EVENT LOG\033[0m", innerW))

	overhead := 18
	if d.stats.WithDiags && d.stats.LatestDiagnostics != "" {
		overhead = 20
	}

	logCount := 5
	if termH > overhead {
		logCount = termH - overhead
	}
	if logCount < 3 {
		logCount = 3
	}

	probesToRender := d.recentProbes
	if len(probesToRender) > logCount {
		probesToRender = probesToRender[len(probesToRender)-logCount:]
	}

	for i := 0; i < logCount; i++ {
		line := ""
		if i < len(probesToRender) {
			line = probesToRender[i]
		}
		b.WriteString(renderRow(line, innerW))
	}

	// Bottom Border
	b.WriteString(bottomBorder)
	b.WriteString("\033[38;5;242mPress Ctrl+C to stop probing and view final report.\033[0m\033[K")

	os.Stdout.WriteString(b.String())
}

// PrintRetryingToResolve stub for interface compliance.
func (d *DashboardPrinter) PrintRetryingToResolve(hostname string) {}

// PrintTotalDownTime stub for interface compliance.
func (d *DashboardPrinter) PrintTotalDownTime(s *stats.Statistics) {}

// PrintStatistics stub for interface compliance.
func (d *DashboardPrinter) PrintStatistics(s *stats.Statistics) {}

// PrintError stub for interface compliance.
func (d *DashboardPrinter) PrintError(format string, args ...any) {}

// Shutdown gracefully ends the TUI dashboard session and restores normal screen.
func (d *DashboardPrinter) Shutdown(s *stats.Statistics) {
	d.Close()
	p := NewColorPrinter()
	PrintStats(p, s)
}

// FleetTarget represents an individual target endpoint monitored in a multi-target fleet session.
type FleetTarget struct {
	Target      string
	Host        string
	Port        uint16
	Protocol    string
	ServiceName string
	Stats       *stats.Statistics
}

// MultiDashboardPrinter implements a live, multi-target concurrent TUI matrix dashboard.
type MultiDashboardPrinter struct {
	mu          sync.Mutex
	targets     []FleetTarget
	targetRTTs  map[string][]float32
	underlying  Printer
	recentLogs  []string
	maxLogLines int
	startTime   time.Time
	closed      bool
}

// NewMultiDashboardPrinter constructs a new MultiDashboardPrinter for monitoring multiple probe workers.
func NewMultiDashboardPrinter(targets []FleetTarget, underlying ...Printer) *MultiDashboardPrinter {
	var und Printer
	if len(underlying) > 0 {
		und = underlying[0]
	}
	d := &MultiDashboardPrinter{
		targets:     targets,
		targetRTTs:  make(map[string][]float32),
		underlying:  und,
		maxLogLines: 8,
		startTime:   time.Now(),
	}

	fmt.Print("\033[?1049h\033[?25l\033[2J") // Alternate screen buffer, hide cursor, clear
	return d
}

// Close restores the normal terminal screen buffer and shows cursor.
func (d *MultiDashboardPrinter) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		fmt.Print("\033[?25h\033[?1049l")
	}
}

var sparkBlocks = []rune{' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// renderSparkline converts a slice of RTT floats into a compact, colorful Unicode sparkline.
func renderSparkline(rtts []float32, width int) string {
	if width <= 0 {
		return ""
	}
	dataLen := len(rtts)
	slice := rtts
	if dataLen > width {
		slice = rtts[dataLen-width:]
	}

	maxVal := float32(10.0)
	for _, v := range slice {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1.0
	}

	var b strings.Builder
	pad := width - len(slice)
	for i := 0; i < pad; i++ {
		b.WriteRune(' ')
	}

	for _, v := range slice {
		if v <= 0 {
			b.WriteString("\033[38;5;167m.\033[0m") // Failed probe dot
			continue
		}
		idx := int((v / maxVal) * float32(len(sparkBlocks)-1))
		if idx >= len(sparkBlocks) {
			idx = len(sparkBlocks) - 1
		}
		if idx < 0 {
			idx = 0
		}
		var color string
		if v < 50 {
			color = "\033[38;5;71m" // Soft green
		} else if v < 150 {
			color = "\033[38;5;221m" // Soft amber/yellow
		} else {
			color = "\033[38;5;203m" // Coral red
		}
		b.WriteString(color)
		b.WriteRune(sparkBlocks[idx])
		b.WriteString("\033[0m")
	}

	return b.String()
}

// OnProbe records a live probe event from any concurrent worker and refreshes the fleet dashboard.
func (d *MultiDashboardPrinter) OnProbe(target string, proto string, rtt time.Duration, diags string, err error, seq uint) {
	d.mu.Lock()
	defer d.mu.Unlock()

	protoDisplay := strings.ToUpper(proto)
	if protoDisplay == "" {
		protoDisplay = "TCP"
	}
	badge := fmt.Sprintf("[%s (%s)]", target, protoDisplay)

	var logLine string
	if err == nil {
		rttMs := float32(rtt.Seconds() * 1000)
		d.targetRTTs[target] = append(d.targetRTTs[target], rttMs)
		logLine = fmt.Sprintf("\033[38;5;71m●\033[0m \033[38;5;244m[%s]\033[0m \033[38;5;75m%-26s\033[0m \033[1;37m%6.2f ms\033[0m", time.Now().Format("15:04:05"), badge, rttMs)
		if diags != "" {
			logLine += fmt.Sprintf(" \033[38;5;240m│\033[0m \033[38;5;248m%s\033[0m", diags)
		}
	} else {
		d.targetRTTs[target] = append(d.targetRTTs[target], 0)
		errMsg := err.Error()
		if idx := strings.LastIndex(errMsg, ": "); idx != -1 {
			errMsg = errMsg[idx+2:]
		}
		logLine = fmt.Sprintf("\033[38;5;167m✖\033[0m \033[38;5;244m[%s]\033[0m \033[38;5;75m%-26s\033[0m \033[38;5;167m%s\033[0m", time.Now().Format("15:04:05"), badge, errMsg)
	}

	if len(d.targetRTTs[target]) > 100 {
		d.targetRTTs[target] = d.targetRTTs[target][1:]
	}

	d.recentLogs = append(d.recentLogs, logLine)
	if len(d.recentLogs) > 100 {
		d.recentLogs = d.recentLogs[1:]
	}

	d.render()
}

// render refreshes the entire multi-target fleet TUI view.
func (d *MultiDashboardPrinter) render() {
	termW, termH := getTerminalDimensions()
	boxWidth := termW
	if boxWidth < 80 {
		boxWidth = 80
	}
	innerW := boxWidth - 4

	var b strings.Builder
	b.WriteString("\033[H") // Cursor to top-left

	elapsed := time.Since(d.startTime).Round(time.Second)

	borderHoriz := strings.Repeat("─", boxWidth-2)
	topBorder := fmt.Sprintf("\033[38;5;60m┌%s┐\033[0m\n", borderHoriz)
	midDivider := fmt.Sprintf("\033[38;5;60m├%s┤\033[0m\n", borderHoriz)
	bottomBorder := fmt.Sprintf("\033[38;5;60m└%s┘\033[0m\n", borderHoriz)

	b.WriteString(topBorder)
	headerStr := fmt.Sprintf("\033[1;37mNETPING FLEET DASHBOARD\033[0m   \033[38;5;244mTargets:\033[0m \033[1;38;5;75m%d\033[0m   \033[38;5;244mElapsed:\033[0m \033[38;5;250m%s\033[0m", len(d.targets), elapsed)
	b.WriteString(renderRow(headerStr, innerW))
	b.WriteString(midDivider)

	// Dynamically compute column widths so table spans 100% of innerW
	maxTargetLen := 20
	for _, t := range d.targets {
		if len(t.Target) > maxTargetLen {
			maxTargetLen = len(t.Target)
		}
	}
	targetColW := maxTargetLen + 2
	if targetColW < 22 {
		targetColW = 22
	}
	if targetColW > 38 {
		targetColW = 38
	}

	fixedMetricsW := 10 + 6 + 6 + 7 + 9 + 9 + 9 + 7 // PROTOCOL, SENT, RECV, LOSS%, LAST, AVG, MAX + gaps = 63
	sparkColW := innerW - targetColW - fixedMetricsW
	if sparkColW < 10 {
		sparkColW = 10
		targetColW = innerW - fixedMetricsW - sparkColW
		if targetColW < 18 {
			targetColW = 18
		}
	}

	fleetHdr := fmt.Sprintf("\033[1;37m%-*s %-10s %-5s %-5s %-6s %-8s %-8s %-8s %-*s\033[0m",
		targetColW, "TARGET", "PROTOCOL", "SENT", "RECV", "LOSS%", "LAST ms", "AVG ms", "MAX ms", sparkColW, "SPARKLINE (RECENT)")
	b.WriteString(renderRow(fleetHdr, innerW))
	b.WriteString(midDivider)

	for _, t := range d.targets {
		t.Stats.Mu.RLock()
		total := t.Stats.TotalSuccessfulProbes + t.Stats.TotalUnsuccessfulProbes
		succ := t.Stats.TotalSuccessfulProbes
		loss := float64(0)
		if total > 0 {
			loss = float64(t.Stats.TotalUnsuccessfulProbes) / float64(total) * 100.0
		}
		latest := t.Stats.LatestRTT
		rttRes := calcMinAvgMaxRttTime(t.Stats.RTT)
		t.Stats.Mu.RUnlock()

		protoDisplay := strings.ToUpper(t.Protocol)
		if protoDisplay == "" {
			protoDisplay = "TCP"
		}

		lossColor := "\033[38;5;71m"
		if loss > 0 {
			lossColor = "\033[38;5;167m"
		}

		targetName := t.Target
		if len(targetName) > targetColW {
			targetName = targetName[:targetColW-3] + "..."
		}

		spark := renderSparkline(d.targetRTTs[t.Target], sparkColW)

		rowStr := fmt.Sprintf("%-*s \033[38;5;73m%-10s\033[0m %-5d \033[38;5;71m%-5d\033[0m %s%5.1f%%\033[0m \033[1;37m%7.2f\033[0m %7.2f %7.2f %s",
			targetColW, targetName, protoDisplay, total, succ, lossColor, loss, latest, rttRes.Average, rttRes.Max, spark)
		b.WriteString(renderRow(rowStr, innerW))
	}

	showWaveform := false
	waveformHeight := 0
	if termH >= 24 {
		showWaveform = true
		waveformHeight = 2 + len(d.targets) // divider + title + rows
	}

	// Fixed UI lines overhead:
	// topBorder (1) + header (1) + divider (1) + tableHdr (1) + divider (1) + tableRows (len(d.targets))
	// + [waveformHeight] + divider (1) + eventStreamTitle (1) + bottomBorder (1) + footerMsg (1)
	fixedOverhead := 9 + len(d.targets) + waveformHeight

	logCount := 4
	if termH > fixedOverhead {
		logCount = termH - fixedOverhead
	}
	if logCount < 3 {
		logCount = 3
	}

	// Fleet Latency Waveform section if terminal height permits
	if showWaveform {
		b.WriteString(midDivider)
		chartPlotW := innerW - (targetColW + 12)
		if chartPlotW < 20 {
			chartPlotW = 20
		}
		b.WriteString(renderRow(fmt.Sprintf("\033[1;37mREAL-TIME FLEET LATENCY WAVEFORMS\033[0m \033[38;5;244m(Last %d probes)\033[0m", chartPlotW), innerW))
		for _, t := range d.targets {
			rtts := d.targetRTTs[t.Target]
			spark := renderSparkline(rtts, chartPlotW)
			protoDisplay := strings.ToUpper(t.Protocol)
			if protoDisplay == "" {
				protoDisplay = "TCP"
			}
			targetName := t.Target
			if len(targetName) > targetColW {
				targetName = targetName[:targetColW-3] + "..."
			}
			targetLabel := fmt.Sprintf("\033[1;38;5;75m%-*s\033[0m \033[38;5;73m%-8s\033[0m", targetColW, targetName, protoDisplay)
			b.WriteString(renderRow(fmt.Sprintf("%s %s", targetLabel, spark), innerW))
		}
	}

	b.WriteString(midDivider)
	b.WriteString(renderRow("\033[1;37mRECENT PROBE EVENT STREAM\033[0m", innerW))

	logsToRender := d.recentLogs
	if len(logsToRender) > logCount {
		logsToRender = logsToRender[len(logsToRender)-logCount:]
	}

	for i := 0; i < logCount; i++ {
		line := ""
		if i < len(logsToRender) {
			line = logsToRender[i]
		}
		b.WriteString(renderRow(line, innerW))
	}

	b.WriteString(bottomBorder)
	b.WriteString("\033[38;5;242mPress Ctrl+C to stop probing and view comparative fleet summary.\033[0m\033[K")

	os.Stdout.WriteString(b.String())
}
