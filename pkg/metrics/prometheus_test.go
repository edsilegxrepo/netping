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

func TestMultiPrometheusExporter(t *testing.T) {
	s1 := &stats.Statistics{
		Hostname:                "target1.com",
		IP:                      netip.MustParseAddr("1.1.1.1"),
		Port:                    443,
		TotalSuccessfulProbes:   10,
		TotalUnsuccessfulProbes: 0,
		LatestRTT:               12.5,
	}
	s2 := &stats.Statistics{
		Hostname:                "target2.com",
		IP:                      netip.MustParseAddr("8.8.8.8"),
		Port:                    53,
		TotalSuccessfulProbes:   8,
		TotalUnsuccessfulProbes: 2,
		LatestRTT:               19.8,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := StartMultiMetricsServer(ctx, "127.0.0.1:19184", []*stats.Statistics{s1, s2})
	defer srv.Close()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:19184/metrics")
	assert.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	content := string(body)
	assert.Contains(t, content, "netping_up")
	assert.Contains(t, content, "target1.com")
	assert.Contains(t, content, "target2.com")
	assert.Contains(t, content, "netping_probe_duration_seconds")
	assert.Contains(t, content, "netping_probes_total")
}
