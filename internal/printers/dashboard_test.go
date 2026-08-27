package printers

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
)

func TestSingleDashboardModel(t *testing.T) {
	st := &stats.Statistics{}
	m := newSingleDashboardModel("1.1.1.1", 443, "HTTPS", st)
	assert.NotNil(t, m)

	// Window resize
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	assert.Equal(t, 100, m.width)
	assert.Equal(t, 30, m.height)

	// Success probe
	m.Update(singleProbeMsg{
		stat:        cloneStats(st),
		isSuccess:   true,
		timestamp:   time.Now(),
		seq:         1,
		rtt:         15.5,
		ip:          "1.1.1.1",
		diagnostics: "TLS Handshake 12ms",
	})
	assert.Equal(t, 1, len(m.recentRTTs))
	assert.Equal(t, 1, len(m.recentProbes))

	// Failure probe
	m.Update(singleProbeMsg{
		stat:       cloneStats(st),
		isSuccess:  false,
		failReason: "Connection refused",
		timestamp:  time.Now(),
		seq:        2,
		rtt:        0,
		ip:         "1.1.1.1",
	})
	assert.Equal(t, 2, len(m.recentRTTs))
	assert.Equal(t, 2, len(m.recentProbes))

	// Render view
	view := m.View()
	assert.NotEmpty(t, view)
	assert.Contains(t, view, "NETPING DASHBOARD")
	assert.Contains(t, view, "1.1.1.1:443")
}

func TestMultiDashboardModel(t *testing.T) {
	targets := []FleetTarget{
		{
			Target:   "google.com:443",
			Host:     "google.com",
			Port:     443,
			Protocol: "HTTPS",
			Stats:    &stats.Statistics{IP: netip.MustParseAddr("142.250.190.46")},
		},
	}
	m := newMultiDashboardModel(targets)
	assert.NotNil(t, m)

	m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	assert.Equal(t, 120, m.width)

	m.Update(multiProbeMsg{
		target:      "google.com:443",
		protocol:    "HTTPS",
		rtt:         12 * time.Millisecond,
		diagnostics: "HTTP/2 200 OK",
		seq:         1,
		timestamp:   time.Now(),
	})
	assert.Equal(t, 1, len(m.targetRTTs["google.com:443"]))
	assert.Equal(t, 1, len(m.recentLogs))

	// Render view
	view := m.View()
	assert.NotEmpty(t, view)
	assert.Contains(t, view, "NETPING FLEET DASHBOARD")
	assert.Contains(t, view, "google.com:443")
}

func TestDashboardPrinterLifecycle(t *testing.T) {
	st := &stats.Statistics{IP: netip.MustParseAddr("1.1.1.1")}
	plain := NewPlainPrinter()
	dash := NewDashboardPrinter("1.1.1.1", 443, "HTTPS", st, plain)
	assert.NotNil(t, dash)

	dash.PrintStart(st)

	st.LatestRTT = 15.5
	st.OngoingSuccessfulProbes = 1
	st.RTT = []float32{15.5, 20.0, 10.2}
	dash.PrintProbeSuccess(st)

	st.LastFailureReason = "timeout"
	st.OngoingUnsuccessfulProbes = 1
	dash.PrintProbeFailure(st)

	dash.PrintRetryingToResolve("1.1.1.1")
	dash.PrintTotalDownTime(st)
	dash.PrintError("test error: %s", "details")
	dash.PrintStatistics(st)

	dash.Close()
}

func TestMultiDashboardPrinterLifecycle(t *testing.T) {
	targets := []FleetTarget{
		{
			Target:   "1.1.1.1:53",
			Host:     "1.1.1.1",
			Port:     53,
			Protocol: "DNS",
			Stats:    &stats.Statistics{IP: netip.MustParseAddr("1.1.1.1")},
		},
	}
	mdp := NewMultiDashboardPrinter(targets)
	assert.NotNil(t, mdp)

	mdp.OnProbe("1.1.1.1:53", "DNS", 5*time.Millisecond, "NOERROR", nil, 1)
	mdp.OnProbe("1.1.1.1:53", "DNS", 0, "", errors.New("timeout"), 2)

	mdp.Close()
}

func TestSparklineRenderingModes(t *testing.T) {
	t.Setenv("NETPING_LEGACY_CONSOLE", "1")
	assert.True(t, shouldUseCompatGlyphs())
	blocksLegacy := getSparkBlocks()
	assert.Equal(t, legacySparkBlocks, blocksLegacy)

	rtts := []float64{5.0, 15.0, 50.0, 120.0, 200.0}
	barsLegacy := renderLatencyBars(rtts, 10)
	assert.NotEmpty(t, barsLegacy)

	sparkLegacy := renderSparklineTrend(rtts, 10)
	assert.NotEmpty(t, sparkLegacy)

	chartLegacy := renderMultiLineBarChart(rtts, 20, 5)
	assert.NotEmpty(t, chartLegacy)

	t.Setenv("NETPING_LEGACY_CONSOLE", "0")
	assert.False(t, shouldUseCompatGlyphs())
	blocksModern := getSparkBlocks()
	assert.Equal(t, modernSparkBlocks, blocksModern)

	barsModern := renderLatencyBars(rtts, 10)
	assert.NotEmpty(t, barsModern)
}

func TestDashboard_FailureMessagesNeverCauseScroll(t *testing.T) {
	st := &stats.Statistics{
		WithDiags: true,
	}

	testSizes := []struct {
		W int
		H int
	}{
		{W: 80, H: 24},
		{W: 80, H: 20},
		{W: 100, H: 25},
		{W: 120, H: 30},
		{W: 150, H: 40},
	}

	for _, size := range testSizes {
		m := newSingleDashboardModel("gfusw-qecm300-gdwxy.gcp.mongodb.net", 27017, "MONGODBS", st)
		m.Update(tea.WindowSizeMsg{Width: size.W, Height: size.H})

		failureReasons := []string{
			"connection timeout after 5000ms",
			"dial tcp: lookup _mongodb._tcp.gfusw-qecm300-gdwxy.gcp.mongodb.net:\nno such host",
			"tls: handshake failure: remote error: tls: handshake failure",
			"read tcp 192.168.1.50:52134->142.250.190.46:443: wsarecv: An existing connection was forcibly closed by the remote host.",
			"connection refused",
		}

		for seq := 1; seq <= 30; seq++ {
			failReason := failureReasons[seq%len(failureReasons)]
			diag := "DNS: OK │ TLS: Failed │ Status: Error"

			m.Update(singleProbeMsg{
				stat:        cloneStats(st),
				isSuccess:   false,
				failReason:  failReason,
				timestamp:   time.Now(),
				seq:         uint(seq),
				rtt:         0,
				ip:          "142.250.190.46",
				diagnostics: diag,
			})

			view := m.View()
			lines := strings.Split(view, "\n")

			// Total lines MUST NOT exceed H - 1
			assert.LessOrEqual(t, len(lines), size.H-1, "Single Dashboard Frame %d at size %dx%d exceeded height limit", seq, size.W, size.H)
			// Line 0 MUST be top border
			assert.True(t, strings.HasPrefix(strings.TrimSpace(lines[0]), "╭") || strings.HasPrefix(strings.TrimSpace(lines[0]), "┌"),
				"Single Dashboard Frame %d: Line 0 is not top border: %q", seq, lines[0])
			// Line 1 MUST contain header title
			assert.Contains(t, lines[1], "NETPING DASHBOARD", "Single Dashboard Frame %d: Top header is missing from Line 1", seq)
			// Bottom border MUST be present at len-2
			bottomIdx := len(lines) - 2
			assert.True(t, strings.HasPrefix(strings.TrimSpace(lines[bottomIdx]), "╰") || strings.HasPrefix(strings.TrimSpace(lines[bottomIdx]), "└"),
				"Single Dashboard Frame %d: Bottom border is missing at line %d: %q", seq, bottomIdx, lines[bottomIdx])
		}

		// Multi-target fleet with 3 MongoDB cluster replica nodes
		multiTargets := []FleetTarget{
			{Target: "gfusw-qecm300-gdwxy-00-00.gcp.mongodb.net:27017", Protocol: "MONGODBS", Stats: &stats.Statistics{}},
			{Target: "gfusw-qecm300-gdwxy-00-01.gcp.mongodb.net:27017", Protocol: "MONGODBS", Stats: &stats.Statistics{}},
			{Target: "gfusw-qecm300-gdwxy-00-02.gcp.mongodb.net:27017", Protocol: "MONGODBS", Stats: &stats.Statistics{}},
		}
		mm := newMultiDashboardModel(multiTargets)
		mm.Update(tea.WindowSizeMsg{Width: size.W, Height: size.H})

		for seq := 1; seq <= 30; seq++ {
			tIdx := seq % len(multiTargets)
			failReason := failureReasons[seq%len(failureReasons)]
			mm.Update(multiProbeMsg{
				target:      multiTargets[tIdx].Target,
				protocol:    "MONGODBS",
				rtt:         0,
				seq:         uint(seq),
				timestamp:   time.Now(),
				diagnostics: "TLS: Failed",
				err:         errors.New(failReason),
			})

			view := mm.View()
			lines := strings.Split(view, "\n")

			minHMulti := 16
			if len(multiTargets) > 2 {
				minHMulti = 14 + len(multiTargets)*2
			}

			if size.H < minHMulti {
				assert.LessOrEqual(t, len(lines), size.H-1)
				continue
			}

			assert.LessOrEqual(t, len(lines), size.H-1, "Multi Dashboard Frame %d at size %dx%d exceeded height limit", seq, size.W, size.H)
			assert.True(t, strings.HasPrefix(strings.TrimSpace(lines[0]), "╭") || strings.HasPrefix(strings.TrimSpace(lines[0]), "┌"),
				"Multi Dashboard Frame %d: Line 0 is not top border: %q", seq, lines[0])
			assert.Contains(t, lines[1], "NETPING FLEET DASHBOARD", "Multi Dashboard Frame %d: Top header is missing from Line 1", seq)

			bottomIdx := len(lines) - 2
			assert.True(t, strings.HasPrefix(strings.TrimSpace(lines[bottomIdx]), "╰") || strings.HasPrefix(strings.TrimSpace(lines[bottomIdx]), "└"),
				"Multi Dashboard Frame %d: Bottom border is missing at line %d: %q", seq, bottomIdx, lines[bottomIdx])
		}

		// Verify export modal open state never overflows height
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
		modalViewSingle := m.View()
		modalLinesSingle := strings.Split(modalViewSingle, "\n")
		assert.LessOrEqual(t, len(modalLinesSingle), size.H-1, "Single modal at size %dx%d exceeded height limit", size.W, size.H)

		mm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
		modalViewMulti := mm.View()
		modalLinesMulti := strings.Split(modalViewMulti, "\n")
		assert.LessOrEqual(t, len(modalLinesMulti), size.H-1, "Multi modal at size %dx%d exceeded height limit", size.W, size.H)
	}
}
