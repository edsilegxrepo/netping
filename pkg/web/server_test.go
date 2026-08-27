// Test Strategy (pkg/web):
//  1. Dashboard & Static Content: Verify embedded HTML/JS delivery and valid HTTP headers (200 OK, text/html).
//  2. SSE Streaming: Validate real-time event delivery and non-blocking subscriber disconnection.
//  3. REST Endpoints: Test /api/v1/metrics, /api/v1/targets, /api/v1/probes, and /api/v1/openapi.json responses.
//  4. History Retention: Validate limit configuration changes, ring-buffer capacity pruning, and reset endpoints.
//  5. Data Exporting: Test server-side formatting into CSV, JSON, and plain-text formats.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/edsilegx/netping/internal/printers"
	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebServer(t *testing.T) {
	st := stats.NewStatistics(stats.Options{
		Hostname: "example.com",
		IP:       netip.MustParseAddr("93.184.216.34"),
		Port:     443,
	})

	broadcaster := NewBroadcaster()
	server := NewServer("127.0.0.1:0", st, broadcaster)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.Start(ctx)
	assert.NoError(t, err)

	// Test GET /
	req, _ := http.NewRequest(http.MethodGet, "http://"+server.httpServer.Addr+"/", nil)
	w := &mockResponseWriter{header: make(http.Header)}
	server.handleIndex(w, req)
	assert.Equal(t, http.StatusOK, w.statusCode)
	assert.Contains(t, string(w.body), "netping Enterprise Dashboard")

	// Test GET /api/stats
	wStats := &mockResponseWriter{header: make(http.Header)}
	server.handleStats(wStats, req)
	assert.Equal(t, http.StatusOK, wStats.statusCode)

	// Test Default Address
	sDefault := NewServer("", st, broadcaster)
	assert.Equal(t, "127.0.0.1:3000", sDefault.addr)
}

func TestBroadcaster_SubscribeBroadcastUnsubscribe(t *testing.T) {
	broadcaster := NewBroadcaster()
	ch1 := broadcaster.Subscribe()
	ch2 := broadcaster.Subscribe()

	event := ProbeEvent{
		Sequence: 1,
		Success:  true,
		RTT:      12.34,
	}

	broadcaster.Broadcast(event)

	select {
	case e1 := <-ch1:
		assert.Equal(t, uint(1), e1.Sequence)
		assert.NotEmpty(t, e1.Timestamp)
	case <-time.After(time.Second):
		t.Fatal("ch1 timed out")
	}

	select {
	case e2 := <-ch2:
		assert.Equal(t, uint(1), e2.Sequence)
	case <-time.After(time.Second):
		t.Fatal("ch2 timed out")
	}

	broadcaster.Unsubscribe(ch1)
	broadcaster.Unsubscribe(ch2)

	// Verify channels are closed
	_, ok1 := <-ch1
	assert.False(t, ok1)
	_, ok2 := <-ch2
	assert.False(t, ok2)
}

func TestBroadcaster_Concurrent(t *testing.T) {
	b := NewBroadcaster()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ch := b.Subscribe()
			defer b.Unsubscribe(ch)

			b.Broadcast(ProbeEvent{
				Sequence: uint(idx),
				Success:  true,
				RTT:      float64(idx),
			})
		}(i)
	}

	wg.Wait()
}

func TestHandleStream_ContextCancel(t *testing.T) {
	st := stats.NewStatistics(stats.Options{
		Hostname: "example.com",
		IP:       netip.MustParseAddr("93.184.216.34"),
		Port:     443,
	})
	broadcaster := NewBroadcaster()
	server := NewServer("127.0.0.1:0", st, broadcaster)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/stream", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	go func() {
		time.Sleep(50 * time.Millisecond)
		broadcaster.Broadcast(ProbeEvent{
			Sequence: 42,
			Success:  true,
			RTT:      5.5,
		})
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	server.handleStream(w, req)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/event-stream")
}

type mockResponseWriter struct {
	header     http.Header
	statusCode int
	body       []byte
}

func (m *mockResponseWriter) Header() http.Header {
	return m.header
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	m.body = append(m.body, b...)
	return len(b), nil
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}

func TestWebServer_REST_Endpoints(t *testing.T) {
	st := stats.NewStatistics(stats.Options{
		Hostname: "example.com",
		IP:       netip.MustParseAddr("93.184.216.34"),
		Port:     443,
	})
	st.RecordSuccess(15.5, time.Now())
	st.RecordSuccess(25.5, time.Now())

	broadcaster := NewBroadcaster()
	broadcaster.Broadcast(ProbeEvent{
		Sequence: 1,
		Success:  true,
		RTT:      15.5,
		Target:   "example.com:443",
	})
	broadcaster.Broadcast(ProbeEvent{
		Sequence: 2,
		Success:  true,
		RTT:      25.5,
		Target:   "example.com:443",
	})

	server := NewServer("127.0.0.1:0", st, broadcaster)

	// Test GET /api/v1/health
	reqHealth := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	wHealth := httptest.NewRecorder()
	server.handleHealth(wHealth, reqHealth)
	assert.Equal(t, http.StatusOK, wHealth.Code)
	assert.Contains(t, wHealth.Body.String(), "healthy")

	// Test GET /api/v1/metrics
	reqMetrics := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	wMetrics := httptest.NewRecorder()
	server.handleMetrics(wMetrics, reqMetrics)
	assert.Equal(t, http.StatusOK, wMetrics.Code)
	assert.Contains(t, wMetrics.Body.String(), "example.com")

	// Test GET /api/v1/targets
	reqTargets := httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
	wTargets := httptest.NewRecorder()
	server.handleTargets(wTargets, reqTargets)
	assert.Equal(t, http.StatusOK, wTargets.Code)
	assert.Contains(t, wTargets.Body.String(), "example.com")

	// Test GET /api/v1/probes
	reqProbes := httptest.NewRequest(http.MethodGet, "/api/v1/probes?limit=10", nil)
	wProbes := httptest.NewRecorder()
	server.handleProbes(wProbes, reqProbes)
	assert.Equal(t, http.StatusOK, wProbes.Code)
	assert.Contains(t, wProbes.Body.String(), `"total":2`)

	// Test GET /api/v1/export (JSON format streaming)
	reqExport := httptest.NewRequest(http.MethodGet, "/api/v1/export?format=json", nil)
	wExport := httptest.NewRecorder()
	server.handleExport(wExport, reqExport)
	assert.Equal(t, http.StatusOK, wExport.Code)
	assert.Equal(t, "application/json", wExport.Header().Get("Content-Type"))
	assert.Contains(t, wExport.Body.String(), `"target":"example.com:443"`)

	// Test GET /api (Swagger UI HTML)
	reqDocs := httptest.NewRequest(http.MethodGet, "/api", nil)
	wDocs := httptest.NewRecorder()
	server.handleAPIDocs(wDocs, reqDocs)
	assert.Equal(t, http.StatusOK, wDocs.Code)
	assert.Contains(t, wDocs.Body.String(), "SwaggerUIBundle")

	// Test GET /api/ (Swagger UI HTML with trailing slash)
	reqDocsSlash := httptest.NewRequest(http.MethodGet, "/api/", nil)
	wDocsSlash := httptest.NewRecorder()
	server.handleAPIDocs(wDocsSlash, reqDocsSlash)
	assert.Equal(t, http.StatusOK, wDocsSlash.Code)
	assert.Contains(t, wDocsSlash.Body.String(), "SwaggerUIBundle")

	// Test GET /api/openapi.json (OpenAPI 3.0 JSON spec)
	reqSpec := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	wSpec := httptest.NewRecorder()
	server.handleOpenAPISpec(wSpec, reqSpec)
	assert.Equal(t, http.StatusOK, wSpec.Code)
	assert.Contains(t, wSpec.Body.String(), `"openapi":"3.0.3"`)
	assert.Contains(t, wSpec.Body.String(), `"/api/v1/metrics"`)

	// Test GET /api/v1/config/history
	reqHistGet := httptest.NewRequest(http.MethodGet, "/api/v1/config/history", nil)
	wHistGet := httptest.NewRecorder()
	server.handleHistoryConfig(wHistGet, reqHistGet)
	assert.Equal(t, http.StatusOK, wHistGet.Code)
	assert.Contains(t, wHistGet.Body.String(), `"history_limit"`)

	// Test POST /api/v1/config/history
	reqHistPost := httptest.NewRequest(http.MethodPost, "/api/v1/config/history", strings.NewReader(`{"limit": 5000}`))
	wHistPost := httptest.NewRecorder()
	server.handleHistoryConfig(wHistPost, reqHistPost)
	assert.Equal(t, http.StatusOK, wHistPost.Code)
	assert.Contains(t, wHistPost.Body.String(), `"history_limit":5000`)
	assert.Equal(t, 5000, broadcaster.GetMaxHistory())

	// Test POST /api/v1/config/history validation bounds (min 100, max 5,000,000)
	reqHistClampLow := httptest.NewRequest(http.MethodPost, "/api/v1/config/history", strings.NewReader(`{"limit": 10}`))
	wHistClampLow := httptest.NewRecorder()
	server.handleHistoryConfig(wHistClampLow, reqHistClampLow)
	assert.Equal(t, http.StatusBadRequest, wHistClampLow.Code)
	assert.Contains(t, wHistClampLow.Body.String(), "at least 100")

	reqHistClampHigh := httptest.NewRequest(http.MethodPost, "/api/v1/config/history", strings.NewReader(`{"limit": 99999999}`))
	wHistClampHigh := httptest.NewRecorder()
	server.handleHistoryConfig(wHistClampHigh, reqHistClampHigh)
	assert.Equal(t, http.StatusBadRequest, wHistClampHigh.Code)
	assert.Contains(t, wHistClampHigh.Body.String(), "cannot exceed 5,000,000")

	// Test GET /docs and /docs/
	reqDocsAlias := httptest.NewRequest(http.MethodGet, "/docs", nil)
	wDocsAlias := httptest.NewRecorder()
	server.handleAPIDocs(wDocsAlias, reqDocsAlias)
	assert.Equal(t, http.StatusOK, wDocsAlias.Code)
	assert.Contains(t, wDocsAlias.Body.String(), "SwaggerUIBundle")
}

func TestBroadcaster_SetMaxHistory_Trimming(t *testing.T) {
	b := NewBroadcaster()
	b.SetMaxHistory(5)

	for i := 1; i <= 10; i++ {
		b.Broadcast(ProbeEvent{
			Sequence: uint(i),
			Success:  true,
			RTT:      float64(i),
		})
	}

	hist := b.GetHistory()
	assert.Equal(t, 5, len(hist))
	assert.Equal(t, uint(6), hist[0].Sequence)
	assert.Equal(t, uint(10), hist[4].Sequence)

	// Dynamically shrink buffer to 2 and verify automatic head trimming
	b.SetMaxHistory(2)
	histShrunk := b.GetHistory()
	assert.Equal(t, 2, len(histShrunk))
	assert.Equal(t, uint(9), histShrunk[0].Sequence)
	assert.Equal(t, uint(10), histShrunk[1].Sequence)
}

func TestWebServer_Export_HostSave_AllFormats(t *testing.T) {
	st := stats.NewStatistics(stats.Options{
		Hostname: "test-export.com",
		IP:       netip.MustParseAddr("1.1.1.1"),
		Port:     443,
	})
	st.RecordSuccess(12.5, time.Now())
	st.RecordSuccess(18.5, time.Now())

	broadcaster := NewBroadcaster()
	broadcaster.Broadcast(ProbeEvent{
		Sequence:   1,
		Success:    true,
		RTT:        12.5,
		DNSTime:    1.5,
		TCPTime:    2.0,
		TLSTime:    4.5,
		TTFB:       4.5,
		HTTPStatus: 200,
		Target:     "test-export.com:443",
	})
	broadcaster.Broadcast(ProbeEvent{
		Sequence:   2,
		Success:    true,
		RTT:        18.5,
		DNSTime:    1.2,
		TCPTime:    2.1,
		TLSTime:    5.0,
		TTFB:       5.0,
		HTTPStatus: 200,
		Target:     "test-export.com:443",
	})

	server := NewServer("127.0.0.1:0", st, broadcaster)
	tmpDir := t.TempDir()

	// Verify streaming GET export delivers TTFB fields
	t.Run("streaming_export_csv_json", func(t *testing.T) {
		reqCSV := httptest.NewRequest(http.MethodGet, "/api/v1/export?format=csv", nil)
		wCSV := httptest.NewRecorder()
		server.handleExport(wCSV, reqCSV)
		assert.Equal(t, http.StatusOK, wCSV.Code)
		assert.Contains(t, wCSV.Body.String(), "TTFB_ms")
		assert.Contains(t, wCSV.Body.String(), "4.50")

		reqJSON := httptest.NewRequest(http.MethodGet, "/api/v1/export?format=json", nil)
		wJSON := httptest.NewRecorder()
		server.handleExport(wJSON, reqJSON)
		assert.Equal(t, http.StatusOK, wJSON.Code)
		assert.Contains(t, wJSON.Body.String(), `"ttfbMs":4.5`)
	})

	formats := []string{"json", "pretty_json", "csv", "tsv", "sqlite"}
	for _, fmtKey := range formats {
		t.Run(fmtKey, func(t *testing.T) {
			ext := "." + fmtKey
			if fmtKey == "pretty_json" {
				ext = ".json"
			}
			outPath := filepath.Join(tmpDir, fmt.Sprintf("export_%s%s", fmtKey, ext))

			reqBody := fmt.Sprintf(`{"format":"%s","path":%q}`, fmtKey, outPath)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/export", strings.NewReader(reqBody))
			w := httptest.NewRecorder()

			server.handleExport(w, req)
			assert.Equal(t, http.StatusOK, w.Code)

			var res struct {
				Success bool   `json:"success"`
				Path    string `json:"path"`
			}
			err := json.Unmarshal(w.Body.Bytes(), &res)
			require.NoError(t, err)
			assert.True(t, res.Success)
			assert.Equal(t, outPath, res.Path)

			// Verify async background writer completes file creation within 2 seconds
			assert.Eventually(t, func() bool {
				info, err := os.Stat(outPath)
				return err == nil && info.Size() > 0
			}, 2*time.Second, 50*time.Millisecond, "expected output file %s to be created by async worker", outPath)
		})
	}
}

func TestWebServer_Reset_Endpoint(t *testing.T) {
	st := stats.NewStatistics(stats.Options{
		Hostname: "reset-target.com",
		IP:       netip.MustParseAddr("8.8.8.8"),
		Port:     53,
	})
	st.RecordSuccess(10.0, time.Now())

	broadcaster := NewBroadcaster()
	broadcaster.Broadcast(ProbeEvent{
		Sequence: 1,
		Success:  true,
		RTT:      10.0,
		Target:   "reset-target.com:53",
	})
	assert.Equal(t, 1, broadcaster.GetHistoryCount())

	server := NewServer("127.0.0.1:0", st, broadcaster)

	// POST /api/v1/reset
	reqReset := httptest.NewRequest(http.MethodPost, "/api/v1/reset", nil)
	wReset := httptest.NewRecorder()
	server.handleReset(wReset, reqReset)

	assert.Equal(t, http.StatusOK, wReset.Code)
	assert.Contains(t, wReset.Body.String(), `"status":"reset"`)
	assert.Equal(t, 0, broadcaster.GetHistoryCount())
	assert.Equal(t, uint(0), st.Snapshot().TotalSent)
}

func TestWebServer_FleetTargets_DetailedAPI(t *testing.T) {
	st1 := stats.NewStatistics(stats.Options{Hostname: "target1.com", Port: 80})
	st1.RecordSuccess(15.0, time.Now())
	st2 := stats.NewStatistics(stats.Options{Hostname: "target2.com", Port: 443})
	st2.RecordSuccess(25.0, time.Now())

	server := NewServer("127.0.0.1:0", st1, NewBroadcaster())
	server.SetTargetsSupplier(func() []printers.FleetTarget {
		return []printers.FleetTarget{
			{Target: "target1.com:80", Host: "target1.com", Port: 80, Protocol: "HTTP", Stats: st1},
			{Target: "target2.com:443", Host: "target2.com", Port: 443, Protocol: "HTTPS", Stats: st2},
		}
	})

	// GET /api/v1/targets
	reqTargets := httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
	wTargets := httptest.NewRecorder()
	server.handleTargets(wTargets, reqTargets)

	assert.Equal(t, http.StatusOK, wTargets.Code)
	assert.Contains(t, wTargets.Body.String(), "target1.com")
	assert.Contains(t, wTargets.Body.String(), "target2.com")

	// GET /api/v1/targets/target1.com:80
	reqTarget1 := httptest.NewRequest(http.MethodGet, "/api/v1/targets/target1.com:80", nil)
	wTarget1 := httptest.NewRecorder()
	server.handleTargetDetail(wTarget1, reqTarget1)
	assert.Equal(t, http.StatusOK, wTarget1.Code)
	assert.Contains(t, wTarget1.Body.String(), "target1.com")
}

func TestWebServer_Concurrent_SSE_Clients(t *testing.T) {
	broadcaster := NewBroadcaster()
	st := stats.NewStatistics(stats.Options{Hostname: "stream.com", Port: 443})
	server := NewServer("127.0.0.1:0", st, broadcaster)

	const clientCount = 20
	var wg sync.WaitGroup

	for i := 0; i < clientCount; i++ {
		wg.Add(1)
		go func(clientId int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			req := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(ctx)
			w := httptest.NewRecorder()
			server.handleStream(w, req)
		}(i)
	}

	// Broadcast bursts of events during active connections
	for seq := 1; seq <= 10; seq++ {
		time.Sleep(10 * time.Millisecond)
		broadcaster.Broadcast(ProbeEvent{
			Sequence: uint(seq),
			Success:  true,
			RTT:      float64(seq) * 2.5,
			Target:   "stream.com:443",
		})
	}

	wg.Wait()
}

type mockValidator struct {
	validKey string
}

func (m *mockValidator) ValidateKey(rawKey string) bool {
	return rawKey == m.validKey
}

type mockExecutor struct{}

func (m *mockExecutor) Execute(ctx context.Context, req TriggerRequest) (*TriggerResponse, error) {
	return &TriggerResponse{
		Success:   true,
		Target:    req.Target,
		Protocol:  "TCP",
		RTTMs:     12.34,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func TestWebServer_TriggerAPI(t *testing.T) {
	broadcaster := NewBroadcaster()
	server := NewServer("127.0.0.1:0", nil, broadcaster)
	validator := &mockValidator{validKey: "np_live_secretkey123"}
	server.SetKeyValidator(validator)
	server.SetDynamicExecutor(&mockExecutor{})

	// 1. Unauthenticated -> 401
	req := httptest.NewRequest(http.MethodPost, "/api/v1/trigger", strings.NewReader(`{"target":"example.com:80"}`))
	w := httptest.NewRecorder()
	server.handleTrigger(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), `"unauthorized"`)

	// 2. Preflight OPTIONS -> 204
	reqOpt := httptest.NewRequest(http.MethodOptions, "/api/v1/trigger", nil)
	wOpt := httptest.NewRecorder()
	server.handleTrigger(wOpt, reqOpt)
	assert.Equal(t, http.StatusNoContent, wOpt.Code)
	assert.Equal(t, "*", wOpt.Header().Get("Access-Control-Allow-Origin"))

	// 3. Authenticated X-API-Key -> 200
	reqAuth := httptest.NewRequest(http.MethodPost, "/api/v1/trigger", strings.NewReader(`{"target":"example.com:80"}`))
	reqAuth.Header.Set("X-API-Key", "np_live_secretkey123")
	wAuth := httptest.NewRecorder()
	server.handleTrigger(wAuth, reqAuth)
	assert.Equal(t, http.StatusOK, wAuth.Code)
	assert.Contains(t, wAuth.Body.String(), `"example.com:80"`)

	// 4. Trigger Status -> 200
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/v1/trigger/status", nil)
	reqStatus.Header.Set("Authorization", "Bearer np_live_secretkey123")
	wStatus := httptest.NewRecorder()
	server.handleTriggerStatus(wStatus, reqStatus)
	assert.Equal(t, http.StatusOK, wStatus.Code)
	assert.Contains(t, wStatus.Body.String(), `"mode":"trigger"`)
}

func TestWebServer_URLPrefixAndSubpathRouting(t *testing.T) {
	// 1. NormalizeURLPrefix tests
	assert.Equal(t, "", NormalizeURLPrefix(""))
	assert.Equal(t, "", NormalizeURLPrefix("/"))
	assert.Equal(t, "/probe", NormalizeURLPrefix("probe"))
	assert.Equal(t, "/probe", NormalizeURLPrefix("/probe"))
	assert.Equal(t, "/probe", NormalizeURLPrefix("/probe/"))
	assert.Equal(t, "/tools/netping", NormalizeURLPrefix("tools/netping/"))

	// 2. Server with URL prefix
	broadcaster := NewBroadcaster()
	server := NewServer("127.0.0.1:0", nil, broadcaster)
	server.SetURLPrefix("/probe")
	assert.Equal(t, "/probe", server.URLPrefix())

	// 2a. Request to exact prefix without slash -> 301 Redirect to /probe/
	reqRedirect := httptest.NewRequest(http.MethodGet, "/probe", nil)
	wRedirect := httptest.NewRecorder()
	server.ServeHTTP(wRedirect, reqRedirect)
	assert.Equal(t, http.StatusMovedPermanently, wRedirect.Code)
	assert.Equal(t, "/probe/", wRedirect.Header().Get("Location"))

	// 2b. Request to /probe/ -> 200 OK dashboard
	reqIndex := httptest.NewRequest(http.MethodGet, "/probe/", nil)
	wIndex := httptest.NewRecorder()
	server.ServeHTTP(wIndex, reqIndex)
	assert.Equal(t, http.StatusOK, wIndex.Code)
	assert.Contains(t, wIndex.Header().Get("Content-Type"), "text/html")

	// 2c. Request to /probe/api/v1/health -> 200 OK health JSON
	reqHealth := httptest.NewRequest(http.MethodGet, "/probe/api/v1/health", nil)
	wHealth := httptest.NewRecorder()
	server.ServeHTTP(wHealth, reqHealth)
	assert.Equal(t, http.StatusOK, wHealth.Code)
	assert.Contains(t, wHealth.Body.String(), `"status":"healthy"`)

	// 2d. Request to unmapped path -> 404
	req404 := httptest.NewRequest(http.MethodGet, "/other/path", nil)
	w404 := httptest.NewRecorder()
	server.ServeHTTP(w404, req404)
	assert.Equal(t, http.StatusNotFound, w404.Code)
}

func TestLatencyComparison_BreakdownDeliveryAndDashboard(t *testing.T) {
	// 1. Verify ProbeEvent JSON serialization contains all latency breakdown keys
	event := ProbeEvent{
		RawTime:      time.Now(),
		Sequence:     42,
		Success:      true,
		RTT:          156.78,
		Target:       "example.com:443",
		Protocol:     "HTTPS",
		DNSTime:      2.34,
		TCPTime:      14.56,
		TLSTime:      35.89,
		TTFB:         150.12,
		HTTPStatus:   200,
		TotalSent:    42,
		TotalSuccess: 42,
	}

	data, err := json.Marshal(event)
	require.NoError(t, err)
	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"dns_time":2.34`)
	assert.Contains(t, jsonStr, `"tcp_time":14.56`)
	assert.Contains(t, jsonStr, `"tls_time":35.89`)
	assert.Contains(t, jsonStr, `"ttfb":150.12`)
	assert.Contains(t, jsonStr, `"http_status":200`)

	// 2. Verify Broadcaster delivers the breakdown to subscribers and saves history
	broadcaster := NewBroadcaster()
	ch := broadcaster.Subscribe()
	defer broadcaster.Unsubscribe(ch)

	broadcaster.Broadcast(event)

	select {
	case received := <-ch:
		assert.Equal(t, 2.34, received.DNSTime)
		assert.Equal(t, 14.56, received.TCPTime)
		assert.Equal(t, 35.89, received.TLSTime)
		assert.Equal(t, 150.12, received.TTFB)
		assert.Equal(t, 200, received.HTTPStatus)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for broadcast event")
	}

	// 3. Verify /api/v1/probes returns history containing breakdown fields
	server := NewServer("127.0.0.1:0", nil, broadcaster)
	reqProbes := httptest.NewRequest(http.MethodGet, "/api/v1/probes", nil)
	wProbes := httptest.NewRecorder()
	server.handleProbes(wProbes, reqProbes)
	assert.Equal(t, http.StatusOK, wProbes.Code)
	assert.Contains(t, wProbes.Body.String(), `"dns_time":2.34`)
	assert.Contains(t, wProbes.Body.String(), `"tcp_time":14.56`)
	assert.Contains(t, wProbes.Body.String(), `"tls_time":35.89`)
	assert.Contains(t, wProbes.Body.String(), `"ttfb":150.12`)

	// 4. Verify Dashboard HTML contains Latency Comparison components & modes
	reqIndex := httptest.NewRequest(http.MethodGet, "/", nil)
	wIndex := httptest.NewRecorder()
	server.handleIndex(wIndex, reqIndex)
	assert.Equal(t, http.StatusOK, wIndex.Code)
	html := wIndex.Body.String()

	// UI Controls & Toggles
	assert.Contains(t, html, "btnToggleLatencyComp")
	assert.Contains(t, html, "latencyModeSelector")
	assert.Contains(t, html, "btnLatModeCurves")
	assert.Contains(t, html, "btnLatModeBars")
	assert.Contains(t, html, "btnLatModeStacked")
	assert.Contains(t, html, "menuItemLatencyComp")

	// Chart Engine Functions & Logic
	assert.Contains(t, html, "toggleLatencyComparison")
	assert.Contains(t, html, "setLatencyCompMode")
	assert.Contains(t, html, "getPhaseBreakdown")
	assert.Contains(t, html, "formatTooltipDiags")
	assert.Contains(t, html, "phaseColors")

	// 5. Verify fleet mode restrictions in HTML script
	assert.Contains(t, html, "if (isFleetMode) return;")
	assert.Contains(t, html, "itemLatencyComp.disabled = isChartHidden || isFleetMode;")
}
