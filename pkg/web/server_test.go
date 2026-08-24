package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
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
}
