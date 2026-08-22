package metrics

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
)

func TestPrometheusExporter(t *testing.T) {
	s := &stats.Statistics{
		Hostname:                "example.com",
		IP:                      netip.MustParseAddr("93.184.216.34"),
		Port:                    80,
		TotalSuccessfulProbes:   5,
		TotalUnsuccessfulProbes: 1,
		LatestRTT:               15.2,
		RTTResults: stats.RTTResult{
			Jitter: 1.5,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := StartMetricsServer(ctx, "127.0.0.1:19183", s)
	defer srv.Close()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:19183/metrics")
	assert.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	content := string(body)
	assert.True(t, strings.Contains(content, "tcping_up"))
	assert.True(t, strings.Contains(content, "tcping_probe_duration_seconds"))
	assert.True(t, strings.Contains(content, "tcping_probes_total"))
}
