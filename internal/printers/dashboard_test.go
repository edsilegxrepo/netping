package printers

import (
	"errors"
	"net/netip"
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
		stat:        *st,
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
		stat:       *st,
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
	t.Setenv("NETPING_COMPAT_GLYPHS", "1")
	assert.True(t, isLegacyWindowsConsole())
	blocksLegacy := getSparkBlocks()
	assert.Equal(t, legacySparkBlocks, blocksLegacy)

	rtts := []float64{5.0, 15.0, 50.0, 120.0, 200.0}
	barsLegacy := renderLatencyBars(rtts, 10)
	assert.NotEmpty(t, barsLegacy)

	sparkLegacy := renderSparklineTrend(rtts, 10)
	assert.NotEmpty(t, sparkLegacy)

	chartLegacy := renderMultiLineBarChart(rtts, 20, 5)
	assert.NotEmpty(t, chartLegacy)

	t.Setenv("NETPING_COMPAT_GLYPHS", "0")
	assert.False(t, isLegacyWindowsConsole())
	blocksModern := getSparkBlocks()
	assert.Equal(t, modernSparkBlocks, blocksModern)

	barsModern := renderLatencyBars(rtts, 10)
	assert.NotEmpty(t, barsModern)
}

