package printers

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/edsilegx/netping/pkg/stats"
	"golang.org/x/term"
)

// ---------------------------------------------------------------------
// STYLING & DESIGN SYSTEM (Lip Gloss)
// ---------------------------------------------------------------------

var (
	colorBorder   = lipgloss.Color("60")  // Slate blue
	colorHeader   = lipgloss.Color("255") // Bright white
	colorDim      = lipgloss.Color("244") // Muted gray
	colorCyan     = lipgloss.Color("75")  // Bright cyan
	colorTeal     = lipgloss.Color("73")  // Soft teal
	colorGreen    = lipgloss.Color("71")  // Muted green
	colorRed      = lipgloss.Color("167") // Soft coral red
	colorAmber    = lipgloss.Color("221") // Soft amber
	colorSubtleBg = lipgloss.Color("236") // Dark card bg
	colorDivider  = lipgloss.Color("239") // Inner divider line

	styleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorHeader)

	styleDim = lipgloss.NewStyle().
			Foreground(colorDim)

	styleValue = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorHeader)

	styleGreen = lipgloss.NewStyle().
			Foreground(colorGreen)

	styleRed = lipgloss.NewStyle().
			Foreground(colorRed)

	styleCyan = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyan)

	styleTeal = lipgloss.NewStyle().
			Foreground(colorTeal)

	styleAmber = lipgloss.NewStyle().
			Foreground(colorAmber)
)

// ---------------------------------------------------------------------
// MESSAGES FOR BUBBLE TEA
// ---------------------------------------------------------------------

type singleProbeMsg struct {
	stat        stats.Statistics
	isSuccess   bool
	failReason  string
	timestamp   time.Time
	seq         uint
	rtt         float32
	ip          string
	diagnostics string
}

type multiProbeMsg struct {
	target      string
	protocol    string
	ip          string
	rtt         time.Duration
	diagnostics string
	err         error
	seq         uint
	timestamp   time.Time
}

type tickMsg time.Time

type exportResultMsg struct {
	err  error
	path string
}

type modalState int

const (
	modalNone modalState = iota
	modalSelectFormat
	modalInputPath
)

func renderExportModal(state modalState, selectedFormat int, inputPath string, boxW int) string {
	modalInnerW := 52
	if modalInnerW > boxW-4 {
		modalInnerW = boxW - 4
	}

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(colorHeader).PaddingBottom(1)
	cardStyle := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(colorCyan).
		Padding(1, 2).
		Width(modalInnerW)

	var content string
	if state == modalSelectFormat {
		var sb strings.Builder
		sb.WriteString(titleStyle.Render("EXPORT DATA - CHOOSE FORMAT") + "\n\n")
		for i, name := range FormatNames {
			if i == selectedFormat {
				sb.WriteString(fmt.Sprintf("%s %s\n", styleCyan.Render("▶"), styleCyan.Bold(true).Render(fmt.Sprintf("[%d] %s", i+1, name))))
			} else {
				sb.WriteString(fmt.Sprintf("  %s\n", styleDim.Render(fmt.Sprintf("[%d] %s", i+1, name))))
			}
		}
		sb.WriteString("\n" + styleDim.Render("[↑/↓/1-6] Select  •  [Enter] Next  •  [Esc] Cancel"))
		content = sb.String()
	} else if state == modalInputPath {
		var sb strings.Builder
		sb.WriteString(titleStyle.Render("EXPORT DATA - DESTINATION FILE") + "\n\n")
		sb.WriteString(fmt.Sprintf("%s %s\n\n", styleDim.Render("Format:"), styleTeal.Render(FormatNames[selectedFormat])))
		sb.WriteString(styleDim.Render("Enter Destination File Path:") + "\n")
		sb.WriteString(styleCyan.Render("> ") + styleHeader.Render(inputPath) + styleCyan.Render("█") + "\n\n")
		sb.WriteString(styleDim.Render("[Enter] Confirm & Save  •  [Esc] Cancel"))
		content = sb.String()
	}

	return cardStyle.Render(content)
}

// ---------------------------------------------------------------------
// SINGLE-TARGET DASHBOARD MODEL
// ---------------------------------------------------------------------

type singleDashboardModel struct {
	target         string
	port           uint16
	protocol       string
	stats          stats.Statistics
	rawStats       *stats.Statistics
	recentRTTs     []float64
	recentProbes   []string
	probeHistory   []SingleProbeExportRecord
	startTime      time.Time
	width          int
	height         int
	quitting       bool
	modalState     modalState
	selectedFormat int
	inputPath      string
	flashMsg       string
	flashTime      time.Time
}

func newSingleDashboardModel(target string, port uint16, protocol string, initialStats *stats.Statistics) *singleDashboardModel {
	st := stats.Statistics{}
	if initialStats != nil {
		initialStats.Mu.RLock()
		st = *initialStats
		initialStats.Mu.RUnlock()
	}
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		w, h = 80, 24
	}

	return &singleDashboardModel{
		target:       target,
		port:         port,
		protocol:     protocol,
		rawStats:     initialStats,
		stats:        st,
		recentRTTs:   make([]float64, 0, 100),
		recentProbes: make([]string, 0, 100),
		probeHistory: make([]SingleProbeExportRecord, 0, 200),
		startTime:    time.Now(),
		width:        w,
		height:       h,
	}
}

func (m *singleDashboardModel) Init() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *singleDashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		if m.modalState == modalSelectFormat {
			switch msg.Type {
			case tea.KeyEsc, tea.KeyCtrlC:
				m.modalState = modalNone
				return m, nil
			case tea.KeyUp:
				m.selectedFormat = (m.selectedFormat + len(FormatNames) - 1) % len(FormatNames)
				return m, nil
			case tea.KeyDown:
				m.selectedFormat = (m.selectedFormat + 1) % len(FormatNames)
				return m, nil
			case tea.KeyEnter:
				m.modalState = modalInputPath
				m.inputPath = GenerateDefaultExportPath(false, ExportFormat(m.selectedFormat))
				return m, nil
			default:
				s := msg.String()
				switch s {
				case "k", "K":
					m.selectedFormat = (m.selectedFormat + len(FormatNames) - 1) % len(FormatNames)
					return m, nil
				case "j", "J":
					m.selectedFormat = (m.selectedFormat + 1) % len(FormatNames)
					return m, nil
				case "1", "2", "3", "4", "5", "6":
					idx := int(s[0] - '1')
					m.selectedFormat = idx
					m.modalState = modalInputPath
					m.inputPath = GenerateDefaultExportPath(false, ExportFormat(m.selectedFormat))
					return m, nil
				case "q", "Q", "esc":
					m.modalState = modalNone
					return m, nil
				}
			}
			return m, nil
		}

		if m.modalState == modalInputPath {
			switch msg.Type {
			case tea.KeyEsc, tea.KeyCtrlC:
				m.modalState = modalNone
				return m, nil
			case tea.KeyEnter:
				target := m.target
				port := m.port
				proto := m.protocol
				statCopy := m.stats
				historyCopy := slices.Clone(m.probeHistory)
				fmtIdx := ExportFormat(m.selectedFormat)
				destPath := m.inputPath
				m.modalState = modalNone
				m.flashMsg = styleDim.Render("Saving export...")
				m.flashTime = time.Now()
				return m, func() tea.Msg {
					err := ExportSingleTarget(target, port, proto, &statCopy, historyCopy, fmtIdx, destPath)
					return exportResultMsg{err: err, path: destPath}
				}
			case tea.KeyBackspace:
				if len(m.inputPath) > 0 {
					m.inputPath = m.inputPath[:len(m.inputPath)-1]
				}
				return m, nil
			default:
				if len(msg.Runes) > 0 {
					m.inputPath += string(msg.Runes)
				}
				return m, nil
			}
		}

		if msg.Type == tea.KeyCtrlC || msg.Type == tea.KeyEsc {
			m.quitting = true
			return m, tea.Quit
		}
		switch msg.String() {
		case "ctrl+c", "q", "Q", "esc":
			m.quitting = true
			return m, tea.Quit
		case "s", "S":
			m.modalState = modalSelectFormat
			m.selectedFormat = 0
			m.inputPath = GenerateDefaultExportPath(false, ExportFormat(0))
			return m, nil
		}

	case exportResultMsg:
		if msg.err != nil {
			m.flashMsg = styleRed.Render(fmt.Sprintf("✖ Export failed: %s", msg.err.Error()))
		} else {
			m.flashMsg = styleGreen.Render(fmt.Sprintf("✔ Saved to %s", msg.path))
		}
		m.flashTime = time.Now()
		return m, nil

	case tickMsg:
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})

	case singleProbeMsg:
		m.stats = msg.stat
		rttVal := float64(msg.rtt)
		if !msg.isSuccess {
			rttVal = 0
		}
		m.recentRTTs = append(m.recentRTTs, rttVal)
		if len(m.recentRTTs) > 120 {
			m.recentRTTs = m.recentRTTs[1:]
		}

		m.probeHistory = append(m.probeHistory, SingleProbeExportRecord{
			Timestamp:   msg.timestamp,
			Seq:         msg.seq,
			Target:      m.target,
			Protocol:    m.protocol,
			IP:          msg.ip,
			IsSuccess:   msg.isSuccess,
			RTTMs:       float64(msg.rtt),
			Diagnostics: msg.diagnostics,
			Error:       msg.failReason,
		})

		var line string
		if msg.isSuccess {
			line = fmt.Sprintf("%s %s %s %s%s %s%s",
				styleGreen.Render("●"),
				styleDim.Render(fmt.Sprintf("[%s]", msg.timestamp.Format("15:04:05"))),
				styleDim.Render(fmt.Sprintf("Seq=%-4d", msg.seq)),
				styleDim.Render("RTT="),
				styleValue.Render(fmt.Sprintf("%6.2f ms", msg.rtt)),
				styleDim.Render("IP="),
				styleDim.Render(msg.ip),
			)
			if msg.diagnostics != "" && msg.stat.WithDiags {
				line += fmt.Sprintf(" %s %s", styleDim.Render("│"), styleCyan.Render(msg.diagnostics))
			}
		} else {
			errMsg := msg.failReason
			if errMsg == "" {
				errMsg = "Timeout"
			}
			line = fmt.Sprintf("%s %s %s %s",
				styleRed.Render("×"),
				styleDim.Render(fmt.Sprintf("[%s]", msg.timestamp.Format("15:04:05"))),
				styleDim.Render(fmt.Sprintf("Seq=%-4d", msg.seq)),
				styleRed.Render(fmt.Sprintf("Error: %s", errMsg)),
			)
		}

		m.recentProbes = append(m.recentProbes, line)
		if len(m.recentProbes) > 100 {
			m.recentProbes = m.recentProbes[1:]
		}
		return m, nil
	}

	return m, nil
}

func (m *singleDashboardModel) View() string {
	if m.quitting {
		return ""
	}

	w := m.width
	h := m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}

	if w < 60 || h < 12 {
		warnStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorRed).
			Padding(0, 1).
			Width(min(w-2, 50))
		content := fmt.Sprintf("%s\n%s",
			styleRed.Render(fmt.Sprintf("⚠ Window too small (%dx%d)", w, h)),
			styleDim.Render("Resize terminal to >= 60x12"),
		)
		return warnStyle.Render(content)
	}

	boxW := w - 2
	innerW := boxW - 2
	if innerW < 40 {
		innerW = 40
	}

	// 1. Header Line
	elapsed := time.Since(m.startTime).Round(time.Second)
	targetDisplay := fmt.Sprintf("%s:%d", m.target, m.port)
	headerLeft := styleHeader.Render("NETPING DASHBOARD")
	headerMid := fmt.Sprintf("%s %s   %s %s",
		styleDim.Render("Target:"), styleCyan.Render(targetDisplay),
		styleDim.Render("Proto:"), styleTeal.Render(m.protocol),
	)
	headerRight := fmt.Sprintf("%s %s", styleDim.Render("Elapsed:"), styleDim.Render(elapsed.String()))
	headerContent := lipgloss.JoinHorizontal(lipgloss.Top,
		headerLeft,
		lipgloss.NewStyle().PaddingLeft(2).Render(headerMid),
		lipgloss.NewStyle().PaddingLeft(3).Render(headerRight),
	)

	// 2. Metrics Rows
	total := m.stats.TotalSuccessfulProbes + m.stats.TotalUnsuccessfulProbes
	succ := m.stats.TotalSuccessfulProbes
	fail := m.stats.TotalUnsuccessfulProbes
	lossRatio := float64(0)
	if total > 0 {
		lossRatio = float64(fail) / float64(total) * 100.0
	}
	res := calcMinAvgMaxRttTime(m.stats.RTT)

	lossStyle := styleGreen
	if fail > 0 {
		lossStyle = styleRed
	}

	colW := (innerW - 8) / 5
	if colW < 8 {
		colW = 8
	}

	cardStyle := lipgloss.NewStyle().Width(colW).Align(lipgloss.Left)

	// Row 1 Cards
	cProbes := cardStyle.Render(fmt.Sprintf("%s %s", styleDim.Render("Probes:"), styleValue.Render(fmt.Sprintf("%d", total))))
	cSucc := cardStyle.Render(fmt.Sprintf("%s %s", styleDim.Render("Success:"), styleGreen.Render(fmt.Sprintf("%d", succ))))
	cFail := cardStyle.Render(fmt.Sprintf("%s %s", styleDim.Render("Failed:"), styleRed.Render(fmt.Sprintf("%d", fail))))
	cLoss := cardStyle.Render(fmt.Sprintf("%s %s", styleDim.Render("Loss:"), lossStyle.Render(fmt.Sprintf("%.1f%%", lossRatio))))
	cJit := cardStyle.Render(fmt.Sprintf("%s %s", styleDim.Render("Jit:"), styleValue.Render(fmt.Sprintf("%.2fms", res.Jitter))))

	sep := lipgloss.NewStyle().Foreground(colorDivider).Render("│")
	row1 := lipgloss.JoinHorizontal(lipgloss.Top, cProbes, " "+sep+" ", cSucc, " "+sep+" ", cFail, " "+sep+" ", cLoss, " "+sep+" ", cJit)

	// Row 2 Cards
	cMin := cardStyle.Render(fmt.Sprintf("%s %s", styleDim.Render("Min:"), styleValue.Render(fmt.Sprintf("%.2fms", res.Min))))
	cAvg := cardStyle.Render(fmt.Sprintf("%s %s", styleDim.Render("Avg:"), styleValue.Render(fmt.Sprintf("%.2fms", res.Average))))
	cMax := cardStyle.Render(fmt.Sprintf("%s %s", styleDim.Render("Max:"), styleValue.Render(fmt.Sprintf("%.2fms", res.Max))))
	cP95 := cardStyle.Render(fmt.Sprintf("%s %s", styleDim.Render("P95:"), styleAmber.Render(fmt.Sprintf("%.2fms", res.P95))))
	cP99 := cardStyle.Render(fmt.Sprintf("%s %s", styleDim.Render("P99:"), styleAmber.Render(fmt.Sprintf("%.2fms", res.P99))))

	row2 := lipgloss.JoinHorizontal(lipgloss.Top, cMin, " "+sep+" ", cAvg, " "+sep+" ", cMax, " "+sep+" ", cP95, " "+sep+" ", cP99)

	// 3. Diagnostics row (optional)
	var diagBlock string
	if m.stats.WithDiags && m.stats.LatestDiagnostics != "" {
		diagText := fmt.Sprintf("%s %s", styleDim.Render("DIAGNOSTICS:"), styleCyan.Render(m.stats.LatestDiagnostics))
		diagBlock = ansi.Truncate(diagText, innerW, "…")
	}

	// 4. Bar Chart
	chartW := innerW - 10
	if chartW < 20 {
		chartW = 20
	}
	chartH := 5

	var graphStr string
	if len(m.recentRTTs) > 0 {
		graphStr = renderMultiLineBarChart(m.recentRTTs, chartW, chartH)
	} else {
		graphStr = styleDim.Render("  Awaiting probe samples...")
	}
	graphTitle := fmt.Sprintf("%s %s", styleHeader.Render("REAL-TIME LATENCY BARS (ms)"), styleDim.Render(fmt.Sprintf("(Last %d probes)", chartW)))

	// 5. Recent Event Log
	logTitle := styleHeader.Render("RECENT PROBE EVENT LOG")

	dividerLine := lipgloss.NewStyle().Foreground(colorDivider).Render(strings.Repeat("─", innerW))

	// Assemble blocks
	blocks := []string{
		ansi.Truncate(headerContent, innerW, ""),
		dividerLine,
		row1,
		row2,
	}

	if diagBlock != "" {
		blocks = append(blocks, dividerLine, diagBlock)
	}

	blocks = append(blocks,
		dividerLine,
		graphTitle,
		graphStr,
		dividerLine,
		logTitle,
	)

	// Calculate remaining lines for event log
	usedLines := lipgloss.Height(strings.Join(blocks, "\n")) + 4 // +4 for outer border and footer
	availLogLines := h - usedLines
	if availLogLines < 3 {
		availLogLines = 3
	}

	logSlice := m.recentProbes
	if len(logSlice) > availLogLines {
		logSlice = logSlice[len(logSlice)-availLogLines:]
	}

	if m.modalState != modalNone {
		blocks = append(blocks, renderExportModal(m.modalState, m.selectedFormat, m.inputPath, boxW))
	} else {
		for i := 0; i < availLogLines; i++ {
			if i < len(logSlice) {
				blocks = append(blocks, ansi.Truncate(logSlice[i], innerW, "…"))
			} else {
				blocks = append(blocks, "")
			}
		}
	}

	innerBody := strings.Join(blocks, "\n")

	outerBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorBorder).
		Padding(0, 1).
		Width(boxW).
		MaxHeight(h - 2).
		Render(innerBody)

	footerHelp := fmt.Sprintf("%s  %s  %s", styleDim.Render("Press s to save/export data"), styleDim.Render("│"), styleDim.Render("Press Ctrl+C or q to stop probing and view final report."))
	if m.flashMsg != "" && time.Since(m.flashTime) < 4*time.Second {
		footerHelp = fmt.Sprintf("%s   %s", m.flashMsg, footerHelp)
	}
	return lipgloss.JoinVertical(lipgloss.Left, outerBox, footerHelp)
}

// ---------------------------------------------------------------------
// MULTI-TARGET FLEET DASHBOARD MODEL
// ---------------------------------------------------------------------

type multiDashboardModel struct {
	targets        []FleetTarget
	targetRTTs     map[string][]float64
	recentLogs     []string
	probeHistory   []SingleProbeExportRecord
	badgeWidth     int
	startTime      time.Time
	width          int
	height         int
	quitting       bool
	modalState     modalState
	selectedFormat int
	inputPath      string
	flashMsg       string
	flashTime      time.Time
}

func newMultiDashboardModel(targets []FleetTarget) *multiDashboardModel {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		w, h = 80, 24
	}

	maxBadgeW := 36
	for _, t := range targets {
		proto := strings.ToUpper(t.Protocol)
		if proto == "" {
			proto = "TCP"
		}
		ipStr := ""
		if t.Stats != nil && t.Stats.IP.IsValid() {
			ipStr = t.Stats.IP.String()
		}
		raw := fmt.Sprintf("[%s %s, %s]", t.Target, ipStr, proto)
		if len(raw) > maxBadgeW {
			maxBadgeW = len(raw)
		}
	}

	return &multiDashboardModel{
		targets:      targets,
		targetRTTs:   make(map[string][]float64),
		recentLogs:   make([]string, 0, 100),
		probeHistory: make([]SingleProbeExportRecord, 0, 500),
		badgeWidth:   maxBadgeW + 2,
		startTime:    time.Now(),
		width:        w,
		height:       h,
	}
}

func (m *multiDashboardModel) Init() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *multiDashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		if m.modalState == modalSelectFormat {
			switch msg.Type {
			case tea.KeyEsc, tea.KeyCtrlC:
				m.modalState = modalNone
				return m, nil
			case tea.KeyUp:
				m.selectedFormat = (m.selectedFormat + len(FormatNames) - 1) % len(FormatNames)
				return m, nil
			case tea.KeyDown:
				m.selectedFormat = (m.selectedFormat + 1) % len(FormatNames)
				return m, nil
			case tea.KeyEnter:
				m.modalState = modalInputPath
				m.inputPath = GenerateDefaultExportPath(true, ExportFormat(m.selectedFormat))
				return m, nil
			default:
				s := msg.String()
				switch s {
				case "k", "K":
					m.selectedFormat = (m.selectedFormat + len(FormatNames) - 1) % len(FormatNames)
					return m, nil
				case "j", "J":
					m.selectedFormat = (m.selectedFormat + 1) % len(FormatNames)
					return m, nil
				case "1", "2", "3", "4", "5", "6":
					idx := int(s[0] - '1')
					m.selectedFormat = idx
					m.modalState = modalInputPath
					m.inputPath = GenerateDefaultExportPath(true, ExportFormat(m.selectedFormat))
					return m, nil
				case "q", "Q", "esc":
					m.modalState = modalNone
					return m, nil
				}
			}
			return m, nil
		}

		if m.modalState == modalInputPath {
			switch msg.Type {
			case tea.KeyEsc, tea.KeyCtrlC:
				m.modalState = modalNone
				return m, nil
			case tea.KeyEnter:
				targetsCopy := make([]FleetTarget, len(m.targets))
				copy(targetsCopy, m.targets)
				historyCopy := slices.Clone(m.probeHistory)
				startTime := m.startTime
				fmtIdx := ExportFormat(m.selectedFormat)
				destPath := m.inputPath
				m.modalState = modalNone
				m.flashMsg = styleDim.Render("Saving export...")
				m.flashTime = time.Now()
				return m, func() tea.Msg {
					err := ExportMultiTarget(targetsCopy, startTime, historyCopy, fmtIdx, destPath)
					return exportResultMsg{err: err, path: destPath}
				}
			case tea.KeyBackspace:
				if len(m.inputPath) > 0 {
					m.inputPath = m.inputPath[:len(m.inputPath)-1]
				}
				return m, nil
			default:
				if len(msg.Runes) > 0 {
					m.inputPath += string(msg.Runes)
				}
				return m, nil
			}
		}

		if msg.Type == tea.KeyCtrlC || msg.Type == tea.KeyEsc {
			m.quitting = true
			return m, tea.Quit
		}
		switch msg.String() {
		case "ctrl+c", "q", "Q", "esc":
			m.quitting = true
			return m, tea.Quit
		case "s", "S":
			m.modalState = modalSelectFormat
			m.selectedFormat = 0
			m.inputPath = GenerateDefaultExportPath(true, ExportFormat(0))
			return m, nil
		}

	case exportResultMsg:
		if msg.err != nil {
			m.flashMsg = styleRed.Render(fmt.Sprintf("✖ Export failed: %s", msg.err.Error()))
		} else {
			m.flashMsg = styleGreen.Render(fmt.Sprintf("✔ Saved to %s", msg.path))
		}
		m.flashTime = time.Now()
		return m, nil

	case tickMsg:
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})

	case multiProbeMsg:
		target := msg.target
		protoDisplay := strings.ToUpper(msg.protocol)
		if protoDisplay == "" {
			protoDisplay = "TCP"
		}

		h, p, err := net.SplitHostPort(target)
		if err != nil {
			h = target
			p = ""
		}
		portFormatted := ""
		if p != "" {
			portFormatted = ":" + p
		}

		// 1. Icon
		var icon string
		if msg.err == nil {
			icon = styleGreen.Render("●")
		} else {
			icon = styleRed.Render("×")
		}

		// 2. Timestamp
		ts := styleDim.Render(fmt.Sprintf("[%s]", msg.timestamp.Format("15:04:05")))

		// 3. Seq
		seq := styleDim.Render(fmt.Sprintf("Seq=%-4d", msg.seq))

		// 4. Target Host:Port Cell with exact Lip Gloss width
		maxTargetW := 22
		for _, t := range m.targets {
			if len(t.Target) > maxTargetW {
				maxTargetW = len(t.Target)
			}
		}
		targetText := fmt.Sprintf("%s%s", h, styleCyan.Render(portFormatted))
		targetCell := lipgloss.NewStyle().Width(maxTargetW + 2).Render(targetText)

		// 5. Dedicated Protocol Cell in teal without parentheses
		protoCell := lipgloss.NewStyle().Width(7).Render(styleTeal.Render(protoDisplay))

		// 6. Vertical Divider
		divider := styleDim.Render("│")

		// 7. RTT / Error Cell with compact width 13
		var valueCell string
		rttValMs := float64(0)
		isSucc := msg.err == nil
		errReason := ""
		if msg.err == nil {
			rttValMs = float64(msg.rtt.Seconds() * 1000)
			m.targetRTTs[target] = append(m.targetRTTs[target], rttValMs)
			rttContent := fmt.Sprintf("%s%s", styleDim.Render("RTT="), styleValue.Render(fmt.Sprintf("%.2f ms", rttValMs)))
			valueCell = lipgloss.NewStyle().Width(13).Render(rttContent)
		} else {
			m.targetRTTs[target] = append(m.targetRTTs[target], 0)
			errMsg := msg.err.Error()
			errReason = errMsg
			if idx := strings.LastIndex(errMsg, ": "); idx != -1 {
				errMsg = errMsg[idx+2:]
			}
			valueCell = lipgloss.NewStyle().Width(13).Render(styleRed.Render(errMsg))
		}

		// Record structured probe object for clean export
		m.probeHistory = append(m.probeHistory, SingleProbeExportRecord{
			Timestamp:   msg.timestamp,
			Seq:         msg.seq,
			Target:      msg.target,
			Protocol:    protoDisplay,
			IP:          msg.ip,
			IsSuccess:   isSucc,
			RTTMs:       rttValMs,
			Diagnostics: msg.diagnostics,
			Error:       errReason,
		})

		// 8. IP Cell (compact 2 spaces)
		var ipSection string
		if msg.ip != "" && msg.ip != "-" {
			ipSection = fmt.Sprintf("  %s%s", styleDim.Render("IP="), styleDim.Render(msg.ip))
		}

		// 9. Diagnostics
		var diagSection string
		if msg.diagnostics != "" {
			diagSection = fmt.Sprintf("  %s %s", styleDim.Render("│"), styleCyan.Render(msg.diagnostics))
		}

		logLine := fmt.Sprintf("%s %s %s %s %s %s  %s%s%s", icon, ts, seq, targetCell, protoCell, divider, valueCell, ipSection, diagSection)

		if len(m.targetRTTs[target]) > 100 {
			m.targetRTTs[target] = m.targetRTTs[target][1:]
		}

		m.recentLogs = append(m.recentLogs, logLine)
		if len(m.recentLogs) > 100 {
			m.recentLogs = m.recentLogs[1:]
		}
		return m, nil
	}

	return m, nil
}

func (m *multiDashboardModel) View() string {
	if m.quitting {
		return ""
	}

	w := m.width
	h := m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}

	minH := 16
	if len(m.targets) > 2 {
		minH = 14 + len(m.targets)*2
	}
	if w < 70 || h < minH {
		warnStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorRed).
			Padding(0, 1).
			Width(min(w-2, 60))
		content := fmt.Sprintf("%s\n%s",
			styleRed.Render(fmt.Sprintf("⚠ Window too small (%dx%d)", w, h)),
			styleDim.Render(fmt.Sprintf("Resize terminal to >= 70x%d", minH)),
		)
		return warnStyle.Render(content)
	}

	boxW := w - 2
	innerW := boxW - 2
	if innerW < 50 {
		innerW = 50
	}

	elapsed := time.Since(m.startTime).Round(time.Second)

	// Header
	headerLeft := styleHeader.Render("NETPING FLEET DASHBOARD")
	headerMid := fmt.Sprintf("%s %s", styleDim.Render("Targets:"), styleCyan.Render(fmt.Sprintf("%d", len(m.targets))))
	headerRight := fmt.Sprintf("%s %s", styleDim.Render("Elapsed:"), styleDim.Render(elapsed.String()))
	headerContent := lipgloss.JoinHorizontal(lipgloss.Top,
		headerLeft,
		lipgloss.NewStyle().PaddingLeft(3).Render(headerMid),
		lipgloss.NewStyle().PaddingLeft(4).Render(headerRight),
	)

	dividerLine := lipgloss.NewStyle().Foreground(colorDivider).Render(strings.Repeat("─", innerW))

	// Fleet Table Column Sizing
	maxTargetLen := 20
	for _, t := range m.targets {
		if len(t.Target) > maxTargetLen {
			maxTargetLen = len(t.Target)
		}
	}
	targetColW := maxTargetLen + 2
	if targetColW < 22 {
		targetColW = 22
	}
	if targetColW > 36 {
		targetColW = 36
	}

	fixedMetricsW := 5 + 8 + 5 + 5 + 1 + 5 + 1 + 6 + 5 + 8 + 1 + 8 + 1 + 8 + 5 // 4 separators with padding + PROTO, SENT, RECV, LOSS, LAST, AVG, MAX
	sparkColW := innerW - targetColW - fixedMetricsW
	if sparkColW < 10 {
		sparkColW = 10
		targetColW = innerW - fixedMetricsW - sparkColW
		if targetColW < 18 {
			targetColW = 18
		}
	}

	sep := styleDim.Render("  │  ")
	tableHdr := fmt.Sprintf("%-*s%s%-8s%s%5s %5s %6s%s%8s %8s %8s%s%-*s",
		targetColW, "TARGET",
		sep,
		"PROTOCOL",
		sep,
		"SENT", "RECV", "LOSS%",
		sep,
		"LAST ms", "AVG ms", "MAX ms",
		sep,
		sparkColW, "SPARKLINE (RECENT)")
	styledTableHdr := styleHeader.Render(tableHdr)

	var tableRows []string
	tableRows = append(tableRows, styledTableHdr, dividerLine)

	for _, t := range m.targets {
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

		lossColor := styleGreen
		if loss > 0 {
			lossColor = styleRed
		}

		targetName := t.Target
		if len(targetName) > targetColW {
			targetName = targetName[:targetColW-3] + "..."
		}

		spark := renderSparklineTrend(m.targetRTTs[t.Target], sparkColW)

		rowStr := fmt.Sprintf("%-*s%s%-8s%s%5d %s %s%s%s %8.2f %8.2f%s%s",
			targetColW, targetName,
			sep,
			styleTeal.Render(fmt.Sprintf("%-8s", protoDisplay)),
			sep,
			total,
			styleGreen.Render(fmt.Sprintf("%5d", succ)),
			lossColor.Render(fmt.Sprintf("%5.1f%%", loss)),
			sep,
			styleValue.Render(fmt.Sprintf("%8.2f", latest)),
			rttRes.Average,
			rttRes.Max,
			sep,
			spark,
		)
		tableRows = append(tableRows, rowStr)
	}

	blocks := []string{
		headerContent,
		dividerLine,
		strings.Join(tableRows, "\n"),
	}

	// Waveforms if terminal height allows
	showWaveform := h >= 24
	if showWaveform {
		blocks = append(blocks, dividerLine)
		chartPlotW := innerW - (targetColW + 12)
		if chartPlotW < 20 {
			chartPlotW = 20
		}
		blocks = append(blocks, fmt.Sprintf("%s %s", styleHeader.Render("REAL-TIME FLEET LATENCY BARS (ms)"), styleDim.Render(fmt.Sprintf("(Last %d probes)", chartPlotW))))
		for _, t := range m.targets {
			rtts := m.targetRTTs[t.Target]
			spark := renderLatencyBars(rtts, chartPlotW)
			protoDisplay := strings.ToUpper(t.Protocol)
			if protoDisplay == "" {
				protoDisplay = "TCP"
			}
			targetName := t.Target
			if len(targetName) > targetColW {
				targetName = targetName[:targetColW-3] + "..."
			}
			targetLabel := fmt.Sprintf("%s %s", styleCyan.Render(fmt.Sprintf("%-*s", targetColW, targetName)), styleTeal.Render(fmt.Sprintf("%-8s", protoDisplay)))
			blocks = append(blocks, fmt.Sprintf("%s %s", targetLabel, spark))
		}
	}

	blocks = append(blocks, dividerLine, styleHeader.Render("RECENT PROBE EVENT STREAM"))

	usedLines := lipgloss.Height(strings.Join(blocks, "\n")) + 4
	availLogs := h - usedLines
	if availLogs < 3 {
		availLogs = 3
	}

	logSlice := m.recentLogs
	if len(logSlice) > availLogs {
		logSlice = logSlice[len(logSlice)-availLogs:]
	}

	if m.modalState != modalNone {
		blocks = append(blocks, renderExportModal(m.modalState, m.selectedFormat, m.inputPath, boxW))
	} else {
		for i := 0; i < availLogs; i++ {
			if i < len(logSlice) {
				blocks = append(blocks, ansi.Truncate(logSlice[i], innerW, "…"))
			} else {
				blocks = append(blocks, "")
			}
		}
	}

	innerBody := strings.Join(blocks, "\n")
	outerBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorBorder).
		Padding(0, 1).
		Width(boxW).
		MaxHeight(h - 2).
		Render(innerBody)

	footerHelp := fmt.Sprintf("%s  %s  %s", styleDim.Render("Press s to save/export data"), styleDim.Render("│"), styleDim.Render("Press Ctrl+C or q to stop probing and view comparative fleet summary."))
	if m.flashMsg != "" && time.Since(m.flashTime) < 4*time.Second {
		footerHelp = fmt.Sprintf("%s   %s", m.flashMsg, footerHelp)
	}
	return lipgloss.JoinVertical(lipgloss.Left, outerBox, footerHelp)
}

// ---------------------------------------------------------------------
// PUBLIC EXPORTED DASHBOARD PRINTER WRAPPERS
// ---------------------------------------------------------------------

// DashboardPrinter renders a high-performance, real-time terminal UI dashboard.
type DashboardPrinter struct {
	mu         sync.Mutex
	target     string
	port       uint16
	protocol   string
	stats      *stats.Statistics
	underlying Printer
	prog       *tea.Program
	cancel     context.CancelFunc
	closed     bool
}

// SetCancel configures the cancellation callback triggered when user exits TUI.
func (d *DashboardPrinter) SetCancel(cancel context.CancelFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cancel = cancel
}

// NewDashboardPrinter constructs a new live terminal dashboard using Bubble Tea.
func NewDashboardPrinter(target string, port uint16, protocol string, stat *stats.Statistics, underlying ...Printer) *DashboardPrinter {
	var und Printer
	if len(underlying) > 0 {
		und = underlying[0]
	}

	model := newSingleDashboardModel(target, port, protocol, stat)
	p := tea.NewProgram(model, tea.WithAltScreen())

	dp := &DashboardPrinter{
		target:     target,
		port:       port,
		protocol:   protocol,
		stats:      stat,
		underlying: und,
		prog:       p,
	}

	go func() {
		if _, err := p.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
		}
		dp.mu.Lock()
		c := dp.cancel
		dp.mu.Unlock()
		if c != nil {
			c()
		}
	}()

	return dp
}

// Close restores the normal terminal screen buffer.
func (d *DashboardPrinter) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		if d.prog != nil {
			d.prog.Quit()
		}
	}
}

// PrintStart displays initial startup info if needed.
func (d *DashboardPrinter) PrintStart(s *stats.Statistics) {}

// PrintProbeSuccess records a probe success and updates the dashboard.
func (d *DashboardPrinter) PrintProbeSuccess(s *stats.Statistics) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.prog == nil {
		return
	}

	s.Mu.RLock()
	statCopy := *s
	s.Mu.RUnlock()

	diagStr := ""
	if statCopy.WithDiags {
		diagStr = statCopy.LatestDiagnostics
	}

	d.prog.Send(singleProbeMsg{
		stat:        statCopy,
		isSuccess:   true,
		timestamp:   time.Now(),
		seq:         statCopy.OngoingSuccessfulProbes + statCopy.OngoingUnsuccessfulProbes,
		rtt:         statCopy.LatestRTT,
		ip:          statCopy.IP.String(),
		diagnostics: diagStr,
	})
}

// PrintProbeFailure records a probe failure and updates the dashboard.
func (d *DashboardPrinter) PrintProbeFailure(s *stats.Statistics) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.prog == nil {
		return
	}

	s.Mu.RLock()
	statCopy := *s
	s.Mu.RUnlock()

	diagStr := ""
	if statCopy.WithDiags {
		diagStr = statCopy.LatestDiagnostics
	}

	d.prog.Send(singleProbeMsg{
		stat:        statCopy,
		isSuccess:   false,
		failReason:  statCopy.LastFailureReason,
		timestamp:   time.Now(),
		seq:         statCopy.OngoingSuccessfulProbes + statCopy.OngoingUnsuccessfulProbes,
		rtt:         0,
		ip:          statCopy.IP.String(),
		diagnostics: diagStr,
	})
}

// PrintRetryingToResolve stub for interface compliance.
func (d *DashboardPrinter) PrintRetryingToResolve(hostname string) {}

// PrintTotalDownTime stub for interface compliance.
func (d *DashboardPrinter) PrintTotalDownTime(s *stats.Statistics) {}

// PrintStatistics stub for interface compliance.
func (d *DashboardPrinter) PrintStatistics(s *stats.Statistics) {}

// PrintError stub for interface compliance.
func (d *DashboardPrinter) PrintError(format string, args ...any) {}

// Shutdown gracefully ends the TUI dashboard session and prints final statistics.
func (d *DashboardPrinter) Shutdown(s *stats.Statistics) {
	d.Close()
	time.Sleep(50 * time.Millisecond) // Ensure alt screen buffer is restored
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
	underlying  Printer
	prog        *tea.Program
	cancel      context.CancelFunc
	closed      bool
}

// SetCancel configures the cancellation callback triggered when user exits TUI.
func (d *MultiDashboardPrinter) SetCancel(cancel context.CancelFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cancel = cancel
}

// NewMultiDashboardPrinter constructs a new MultiDashboardPrinter using Bubble Tea.
func NewMultiDashboardPrinter(targets []FleetTarget, underlying ...Printer) *MultiDashboardPrinter {
	var und Printer
	if len(underlying) > 0 {
		und = underlying[0]
	}

	model := newMultiDashboardModel(targets)
	p := tea.NewProgram(model, tea.WithAltScreen())

	mdp := &MultiDashboardPrinter{
		targets:    targets,
		underlying: und,
		prog:       p,
	}

	go func() {
		if _, err := p.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Multi-Dashboard error: %v\n", err)
		}
		mdp.mu.Lock()
		c := mdp.cancel
		mdp.mu.Unlock()
		if c != nil {
			c()
		}
	}()

	return mdp
}

// Close restores the normal terminal screen buffer.
func (d *MultiDashboardPrinter) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		if d.prog != nil {
			d.prog.Quit()
		}
	}
}

// OnProbe records a live probe event from any concurrent worker and refreshes the fleet dashboard.
func (d *MultiDashboardPrinter) OnProbe(target string, proto string, rtt time.Duration, diags string, err error, seq uint, ip ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.prog == nil {
		return
	}

	ipStr := ""
	if len(ip) > 0 && ip[0] != "" {
		ipStr = ip[0]
	} else {
		for _, t := range d.targets {
			if t.Target == target && t.Stats != nil && t.Stats.IP.IsValid() {
				ipStr = t.Stats.IP.String()
				break
			}
		}
	}

	d.prog.Send(multiProbeMsg{
		target:      target,
		protocol:    proto,
		ip:          ipStr,
		rtt:         rtt,
		diagnostics: diags,
		err:         err,
		seq:         seq,
		timestamp:   time.Now(),
	})
}

// ---------------------------------------------------------------------
// SPARKLINE & STATISTICAL HELPERS
// ---------------------------------------------------------------------

var (
	modernSparkBlocks = []rune{'\u2581', '\u2582', '\u2583', '\u2584', '\u2585', '\u2586', '\u2587', '\u2588'}
	legacySparkBlocks = []rune{'_', '\u2584', '\u2588'}
)

// isLegacyWindowsConsole returns true if running on Windows inside legacy conhost (e.g. cmd.exe)
// without native DirectWrite / Cascadia font fractional block character support.
func isLegacyWindowsConsole() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	if os.Getenv("NETPING_COMPAT_GLYPHS") == "1" || os.Getenv("NETPING_LEGACY_CONSOLE") == "1" {
		return true
	}
	if os.Getenv("NETPING_COMPAT_GLYPHS") == "0" || os.Getenv("NETPING_LEGACY_CONSOLE") == "0" {
		return false
	}
	if os.Getenv("WT_SESSION") != "" ||
		os.Getenv("WT_PROFILE_ID") != "" ||
		os.Getenv("TERM_PROGRAM") != "" ||
		os.Getenv("TERMINAL_EMULATOR") != "" ||
		os.Getenv("ConEmuPID") != "" ||
		os.Getenv("WEZTERM_PANE") != "" ||
		os.Getenv("ALACRITTY_LOG") != "" ||
		os.Getenv("MSYSTEM") != "" {
		return false
	}
	term := os.Getenv("TERM")
	if term != "" && (strings.Contains(term, "xterm") || strings.Contains(term, "256color") || strings.Contains(term, "alacritty")) {
		return false
	}
	return true
}

func getSparkBlocks() []rune {
	if isLegacyWindowsConsole() {
		return legacySparkBlocks
	}
	return modernSparkBlocks
}

func renderLatencyBars(rtts []float64, width int) string {
	if width <= 0 {
		return ""
	}
	dataLen := len(rtts)
	slice := rtts
	if dataLen > width {
		slice = rtts[dataLen-width:]
	}

	maxVal := float64(10.0)
	for _, v := range slice {
		if v > maxVal {
			maxVal = v
		}
	}

	blocks := getSparkBlocks()
	var b strings.Builder
	pad := width - len(slice)
	for i := 0; i < pad; i++ {
		b.WriteRune(' ')
	}

	for _, v := range slice {
		if v <= 0 {
			b.WriteString(styleRed.Render("."))
			continue
		}
		idx := int((v / maxVal) * float64(len(blocks)-1))
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}
		if idx < 0 {
			idx = 0
		}
		st := styleCyan
		if v >= 150 {
			st = styleRed
		} else if v >= 50 {
			st = styleAmber
		}
		b.WriteString(st.Render(string(blocks[idx])))
	}

	return b.String()
}

func renderSparklineTrend(rtts []float64, width int) string {
	if width <= 0 {
		return ""
	}
	dataLen := len(rtts)
	slice := rtts
	if dataLen > width {
		slice = rtts[dataLen-width:]
	}

	var minVal, maxVal float64
	hasValid := false
	for _, v := range slice {
		if v > 0 {
			if !hasValid {
				minVal = v
				maxVal = v
				hasValid = true
			} else {
				if v < minVal {
					minVal = v
				}
				if v > maxVal {
					maxVal = v
				}
			}
		}
	}

	rangeVal := maxVal - minVal
	if rangeVal == 0 {
		rangeVal = 1.0
	}

	blocks := getSparkBlocks()
	var b strings.Builder
	pad := width - len(slice)
	for i := 0; i < pad; i++ {
		b.WriteRune(' ')
	}

	for _, v := range slice {
		if v <= 0 {
			b.WriteString(styleRed.Render("."))
			continue
		}
		var idx int
		if maxVal == minVal {
			idx = len(blocks) / 2
		} else {
			idx = int(((v - minVal) / rangeVal) * float64(len(blocks)-1))
		}
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}
		if idx < 0 {
			idx = 0
		}
		st := styleCyan
		if v >= 150 {
			st = styleRed
		} else if v >= 50 {
			st = styleAmber
		}
		b.WriteString(st.Render(string(blocks[idx])))
	}

	return b.String()
}

func renderSparklineFromFloat64(rtts []float64, width int) string {
	return renderLatencyBars(rtts, width)
}

func renderMultiLineBarChart(rtts []float64, plotWidth int, height int) string {
	if height < 3 {
		height = 5
	}

	maxVal := float64(10.0)
	for _, v := range rtts {
		if v > maxVal {
			maxVal = v
		}
	}
	maxVal = maxVal * 1.15

	dataLen := len(rtts)
	samples := make([]float64, plotWidth)
	offset := plotWidth - dataLen
	for i := 0; i < plotWidth; i++ {
		srcIdx := i - offset
		if srcIdx >= 0 && srcIdx < dataLen {
			samples[i] = rtts[srcIdx]
		} else {
			samples[i] = -1 // No data
		}
	}

	isLegacy := isLegacyWindowsConsole()
	lowChar := "\u2581"
	if isLegacy {
		lowChar = "_"
	}

	var lines []string
	for row := height - 1; row >= 0; row-- {
		rowVal := (float64(row+1) / float64(height)) * maxVal
		var line strings.Builder
		line.WriteString(styleDim.Render(fmt.Sprintf("%6.1fms ", rowVal)) + lipgloss.NewStyle().Foreground(colorDivider).Render("┤"))

		for col := 0; col < plotWidth; col++ {
			val := samples[col]
			if val < 0 {
				line.WriteString(" ")
				continue
			}
			if val == 0 {
				if row == 0 {
					line.WriteString(styleRed.Render("."))
				} else {
					line.WriteString(" ")
				}
				continue
			}

			norm := (val / maxVal) * float64(height)
			colorStyle := styleCyan
			if val >= 150 {
				colorStyle = styleRed
			} else if val >= 50 {
				colorStyle = styleAmber
			}

			if norm >= float64(row+1) {
				line.WriteString(colorStyle.Render("█"))
			} else if norm >= float64(row)+0.5 {
				line.WriteString(colorStyle.Render("▄"))
			} else if norm >= float64(row)+0.15 {
				line.WriteString(colorStyle.Render(lowChar))
			} else {
				line.WriteString(" ")
			}
		}
		lines = append(lines, line.String())
	}

	axisLine := styleDim.Render("   0.0ms ") + lipgloss.NewStyle().Foreground(colorDivider).Render("┴"+strings.Repeat("─", plotWidth))
	lines = append(lines, axisLine)
	return strings.Join(lines, "\n")
}
