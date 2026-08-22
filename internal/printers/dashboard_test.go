package printers

import (
	"testing"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
)

func TestDashboardPrinter(t *testing.T) {
	st := &stats.Statistics{}
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

	assert.Equal(t, 2, len(dash.recentRTTs))
	assert.Equal(t, 2, len(dash.recentProbes))

	dash.Close()
	dash.PrintStatistics(st)
}
