// Test Strategy (cmd/netping - End-to-End & Integration):
//  1. Full Lifecycle Integration: Validate key generation, idle daemon initialization, authenticated REST triggering,
//     real-time SSE streaming, standing metrics computation, and Web UI target inventory registration.
//  2. Protocol Factory Coverage: Validate BuildPinger construction across all 49 supported L3-L7 protocols.
//  3. Security & Boundary Hardening: Test oversized HTTP body rejection (MaxBytesReader), malformed JSON payloads,
//     tampered keystores, invalid auth headers, and high-concurrency trigger bursts.
//  4. Diagnostic Exit Codes: Validate deterministic process termination status mappings.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/edsilegx/netping/internal/config"
	"github.com/edsilegx/netping/pkg/auth"
	"github.com/edsilegx/netping/pkg/consts"
	"github.com/edsilegx/netping/pkg/engine"
	"github.com/edsilegx/netping/pkg/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildPinger_AllProtocols(t *testing.T) {
	protocols := []consts.Protocol{
		consts.HTTP,
		consts.HTTPS,
		consts.UDP,
		consts.ICMP,
		consts.GRPC,
		consts.GRPCS,
		consts.WS,
		consts.WSS,
		consts.DNS,
		consts.DOH,
		consts.DOT,
		consts.REDIS,
		consts.REDISS,
		consts.SSH,
		consts.POSTGRES,
		consts.MYSQL,
		consts.MSSQL,
		consts.ORACLE,
		consts.MONGODB,
		consts.MONGODBS,
		consts.CASSANDRA,
		consts.CASSANDRAS,
		consts.SAPHANA,
		consts.MEMCACHED,
		consts.MEMCACHEDS,
		consts.SMTP,
		consts.SMTPS,
		consts.IMAP,
		consts.IMAPS,
		consts.POP3,
		consts.POP3S,
		consts.TLS,
		consts.LDAP,
		consts.LDAPS,
		consts.O365,
		consts.S3,
		consts.AZUREBLOB,
		consts.GCS,
		consts.KAFKA,
		consts.KAFKAS,
		consts.RABBITMQ,
		consts.AMQP,
		consts.AMQPS,
		consts.SMB,
		consts.RSYNC,
		consts.FTP,
		consts.FTPS,
		consts.TCP,
	}

	for _, proto := range protocols {
		t.Run(string(proto), func(t *testing.T) {
			tCfg := config.TargetConfig{
				Protocol: proto,
				Host:     "127.0.0.1",
				IP:       netip.MustParseAddr("127.0.0.1"),
				Port:     8080,
			}
			cfg := &config.Config{
				Protocol: proto,
				Hostname: "127.0.0.1",
				IP:       netip.MustParseAddr("127.0.0.1"),
				Port:     8080,
				Timeout:  1 * time.Second,
			}
			p := buildPingerForTarget(tCfg, *cfg, nil)
			assert.NotNil(t, p, "Pinger for protocol %s should not be nil", proto)
		})
	}
}

func startTestTCPTarget(t *testing.T) (net.Listener, uint16) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Echo server for send/expect data testing
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	return ln, port
}

func setupTriggerEnvironment(t *testing.T) (*httptest.Server, *auth.Keystore, string, *engine.DynamicTargetRegistry, *web.Broadcaster) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "keys", "netping_keystore.json")

	rawKey, hashStr, err := auth.GenerateAPIKey()
	require.NoError(t, err)

	err = auth.SaveKeyToStorePath(storePath, rawKey, hashStr)
	require.NoError(t, err)

	keystore, err := auth.NewKeystore(storePath)
	require.NoError(t, err)

	broadcaster := web.NewBroadcaster()
	registry := engine.NewDynamicTargetRegistry()
	dynamicEng := engine.NewDynamicEngine(broadcaster, registry, 50)

	server := web.NewServer("127.0.0.1:0", nil, broadcaster)
	server.SetTargetsSupplier(registry.GetFleetTargets)
	server.SetKeyValidator(keystore)
	server.SetDynamicExecutor(dynamicEng)
	server.SetDynamicFleetManager(registry)

	ts := httptest.NewServer(server.Handler())
	return ts, keystore, rawKey, registry, broadcaster
}

func TestEndToEnd_KeygenAndKeystoreHotReload(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "keystore.json")

	// 1. Initial key generation
	key1, hash1, err := auth.GenerateAPIKey()
	require.NoError(t, err)
	err = auth.SaveKeyToStorePath(storePath, key1, hash1)
	require.NoError(t, err)

	ks, err := auth.NewKeystore(storePath)
	require.NoError(t, err)
	assert.Equal(t, 1, ks.KeyCount())
	assert.True(t, ks.ValidateKey(key1))

	// 2. Generate and add a second key
	key2, hash2, err := auth.GenerateAPIKey()
	require.NoError(t, err)
	err = auth.SaveKeyToStorePath(storePath, key2, hash2)
	require.NoError(t, err)

	// Verify hot-reload recognizes key2 without restarting
	time.Sleep(10 * time.Millisecond)
	assert.True(t, ks.ValidateKey(key2))
	assert.True(t, ks.ValidateKey(key1))
	assert.False(t, ks.ValidateKey("np_live_nonexistent"))
}

func TestEndToEnd_TriggerMode_CORS_And_Auth(t *testing.T) {
	ts, _, rawKey, _, _ := setupTriggerEnvironment(t)
	defer ts.Close()

	// 1. CORS preflight OPTIONS request
	optReq, err := http.NewRequest(http.MethodOptions, ts.URL+"/api/v1/trigger", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(optReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "POST")
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Headers"), "X-API-Key")

	// 2. Unauthenticated POST -> 401
	payload := `{"target":"127.0.0.1:80","protocol":"tcp"}`
	unauthReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", strings.NewReader(payload))
	require.NoError(t, err)
	respUnauth, err := http.DefaultClient.Do(unauthReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, respUnauth.StatusCode)

	var errResp map[string]interface{}
	_ = json.NewDecoder(respUnauth.Body).Decode(&errResp)
	assert.Equal(t, "unauthorized", errResp["error"])

	// 3. Invalid API Key -> 401
	badKeyReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", strings.NewReader(payload))
	require.NoError(t, err)
	badKeyReq.Header.Set("X-API-Key", "np_live_wrongkey99999")
	respBadKey, err := http.DefaultClient.Do(badKeyReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, respBadKey.StatusCode)

	// 4. Valid Authorization: Bearer Header -> 200
	bearerReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", strings.NewReader(payload))
	require.NoError(t, err)
	bearerReq.Header.Set("Authorization", "Bearer "+rawKey)
	respBearer, err := http.DefaultClient.Do(bearerReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respBearer.StatusCode)
}

func TestEndToEnd_TriggerMode_AllPayloadsAndFeatures(t *testing.T) {
	ts, _, rawKey, registry, _ := setupTriggerEnvironment(t)
	defer ts.Close()

	targetLn, targetPort := startTestTCPTarget(t)
	defer targetLn.Close()

	sendTrigger := func(req web.TriggerRequest) (*web.TriggerResponse, int, error) {
		body, _ := json.Marshal(req)
		httpReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", bytes.NewReader(body))
		if err != nil {
			return nil, 0, err
		}
		httpReq.Header.Set("X-API-Key", rawKey)
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()

		var result web.TriggerResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		return &result, resp.StatusCode, err
	}

	// 1. Single Probe Execution (Default)
	res1, code, err := sendTrigger(web.TriggerRequest{
		Host:      "127.0.0.1",
		Port:      targetPort,
		Protocol:  "tcp",
		Timeout:   "1s",
		ShowDiags: true,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, res1.Success)
	assert.Equal(t, "TCP", res1.Protocol)
	assert.Equal(t, targetPort, res1.Port)
	assert.Equal(t, "127.0.0.1", res1.IP)
	assert.GreaterOrEqual(t, res1.RTTMs, float64(0))
	assert.NotEmpty(t, res1.Diagnostics)
	assert.NotEmpty(t, res1.Timestamp)

	// 2. Multi-Count Probe Execution
	resMulti, code, err := sendTrigger(web.TriggerRequest{
		Host:     "127.0.0.1",
		Port:     targetPort,
		Protocol: "tcp",
		Count:    3,
		Interval: "10ms",
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, resMulti.Success)
	assert.Len(t, resMulti.Probes, 3)
	assert.Equal(t, uint(1), resMulti.Probes[0].Sequence)
	assert.Equal(t, uint(3), resMulti.Probes[2].Sequence)

	// 3. Custom Payload (Send & Expect) & FastClose
	resPayload, code, err := sendTrigger(web.TriggerRequest{
		Host:       "127.0.0.1",
		Port:       targetPort,
		Protocol:   "tcp",
		SendData:   "PING_ECHO_TEST",
		ExpectData: "PING_ECHO_TEST",
		FastClose:  true,
		ShowDiags:  true,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, resPayload.Success)
	assert.Contains(t, resPayload.Diagnostics, "Payload Matched")

	// 4. Max Latency SLA Threshold Breach (using delayed HTTP target to guarantee deterministic SLA breach)
	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer httpTarget.Close()
	u, _ := url.Parse(httpTarget.URL)
	h, p, _ := net.SplitHostPort(u.Host)
	portVal, _ := strconv.Atoi(p)

	resSLA, code, err := sendTrigger(web.TriggerRequest{
		Host:         h,
		Port:         uint16(portVal),
		Protocol:     "http",
		MaxLatencyMS: 1.0, // 1ms SLA threshold breached by 5ms delay
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.False(t, resSLA.Success)
	assert.Contains(t, resSLA.Error, "latency breached SLA threshold")

	// 5. Retries with Backoff
	resRetry, code, err := sendTrigger(web.TriggerRequest{
		Host:         "127.0.0.1",
		Port:         targetPort,
		Protocol:     "tcp",
		Retries:      2,
		RetryBackoff: "5ms",
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, resRetry.Success)

	// 6. Unreachable Target Failure Handling
	resFail, code, err := sendTrigger(web.TriggerRequest{
		Host:     "127.0.0.1",
		Port:     1, // Unused/closed port
		Protocol: "tcp",
		Timeout:  "500ms",
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.False(t, resFail.Success)
	assert.NotEmpty(t, resFail.Error)
	assert.NotEmpty(t, resFail.ErrorCode)

	// 7. Layer-4 Traceroute Mode
	resTrace, code, err := sendTrigger(web.TriggerRequest{
		Host:       "127.0.0.1",
		Port:       targetPort,
		Protocol:   "tcp",
		Traceroute: true,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.NotNil(t, resTrace.Hops)

	// 8. HTTP Probe Method Dispatching (HEAD default, POST with send_data, GET with expect_data)
	httpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			if string(b) == `{"action":"ping"}` {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"pong","code":200}`))
				return
			}
			w.WriteHeader(http.StatusBadRequest)
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok-service-ready"))
		case http.MethodHead:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer httpBackend.Close()
	httpU, _ := url.Parse(httpBackend.URL)
	httpH, httpPStr, _ := net.SplitHostPort(httpU.Host)
	httpPortNum, _ := strconv.Atoi(httpPStr)

	// 8a. Default HEAD probe
	resHTTPHead, code, err := sendTrigger(web.TriggerRequest{
		Host:      httpH,
		Port:      uint16(httpPortNum),
		Protocol:  "http",
		ShowDiags: true,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, resHTTPHead.Success)
	assert.Equal(t, 200, resHTTPHead.HTTPStatus)

	// 8b. POST probe with send_data and expect_data
	resHTTPPost, code, err := sendTrigger(web.TriggerRequest{
		Host:       httpH,
		Port:       uint16(httpPortNum),
		Protocol:   "http",
		SendData:   `{"action":"ping"}`,
		ExpectData: `"status":"pong"`,
		ShowDiags:  true,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, resHTTPPost.Success)
	assert.Contains(t, resHTTPPost.Diagnostics, "Sent: 17B")
	assert.Contains(t, resHTTPPost.Diagnostics, `Matched: "\"status\":\"pong\""`)

	// 8c. GET probe with expect_data
	resHTTPGet, code, err := sendTrigger(web.TriggerRequest{
		Host:       httpH,
		Port:       uint16(httpPortNum),
		Protocol:   "http",
		ExpectData: "service-ready",
		ShowDiags:  true,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, resHTTPGet.Success)
	assert.Contains(t, resHTTPGet.Diagnostics, `Matched: "service-ready"`)

	// Verify target registry tracked active targets
	fleet := registry.GetFleetTargets()
	assert.GreaterOrEqual(t, len(fleet), 1)
}

func TestEndToEnd_TriggerMode_StatusAndReset(t *testing.T) {
	ts, _, rawKey, _, _ := setupTriggerEnvironment(t)
	defer ts.Close()

	// 1. GET /api/v1/trigger/status with API key
	statusReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/trigger/status", nil)
	require.NoError(t, err)
	statusReq.Header.Set("X-API-Key", rawKey)

	statusResp, err := http.DefaultClient.Do(statusReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusResp.StatusCode)

	var statusData map[string]interface{}
	_ = json.NewDecoder(statusResp.Body).Decode(&statusData)
	assert.Equal(t, "ready", statusData["status"])
	assert.Equal(t, "trigger", statusData["mode"])
	assert.Equal(t, true, statusData["auth_enabled"])
	assert.NotEmpty(t, statusData["uptime"])

	// 2. POST /api/v1/reset with API key
	resetReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/reset", nil)
	require.NoError(t, err)
	resetReq.Header.Set("X-API-Key", rawKey)

	resetResp, err := http.DefaultClient.Do(resetReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resetResp.StatusCode)

	var resetData map[string]interface{}
	_ = json.NewDecoder(resetResp.Body).Decode(&resetData)
	assert.Equal(t, "reset", resetData["status"])
}

func TestEndToEnd_TriggerMode_RealTime_SSE_Subscription(t *testing.T) {
	ts, _, rawKey, _, _ := setupTriggerEnvironment(t)
	defer ts.Close()

	targetLn, targetPort := startTestTCPTarget(t)
	defer targetLn.Close()

	// 1. Client connects to public unauthenticated SSE stream
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/stream", nil)
	require.NoError(t, err)

	sseResp, err := http.DefaultClient.Do(sseReq)
	require.NoError(t, err)
	defer sseResp.Body.Close()
	assert.Equal(t, http.StatusOK, sseResp.StatusCode)
	assert.Contains(t, sseResp.Header.Get("Content-Type"), "text/event-stream")

	eventsChan := make(chan string, 10)
	go func() {
		scanner := bufio.NewScanner(sseResp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				eventsChan <- strings.TrimPrefix(line, "data: ")
			}
		}
	}()

	// Allow SSE subscription loop to register
	time.Sleep(50 * time.Millisecond)

	// 2. Trigger probe with broadcast: true
	triggerReq := web.TriggerRequest{
		Host:      "127.0.0.1",
		Port:      targetPort,
		Protocol:  "tcp",
		Timeout:   "1s",
		ShowDiags: true,
	}
	body, _ := json.Marshal(triggerReq)
	postReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", bytes.NewReader(body))
	require.NoError(t, err)
	postReq.Header.Set("X-API-Key", rawKey)
	postReq.Header.Set("Content-Type", "application/json")

	postResp, err := http.DefaultClient.Do(postReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, postResp.StatusCode)

	// 3. Verify event is delivered in real time over SSE connection
	select {
	case eventJSON := <-eventsChan:
		var ev web.ProbeEvent
		err := json.Unmarshal([]byte(eventJSON), &ev)
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("127.0.0.1:%d", targetPort), ev.Target)
		assert.Equal(t, "TCP", ev.Protocol)
		assert.True(t, ev.Success)
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("timed out waiting for real-time SSE probe event")
	}

	// 4. Verify public /api/v1/metrics dynamically lists triggered target
	metricsResp, err := http.Get(ts.URL + "/api/v1/metrics")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, metricsResp.StatusCode)

	var metricsData map[string]interface{}
	_ = json.NewDecoder(metricsResp.Body).Decode(&metricsData)
	assert.GreaterOrEqual(t, metricsData["target_count"], float64(1))
}

func TestEndToEnd_CompleteTriggerLifecycle(t *testing.T) {
	// =========================================================================
	// STAGE 1: KEY GENERATION & KEYSTORE STORAGE
	// =========================================================================
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "secure_keystore.json")

	rawAPIKey, argonHash, err := auth.GenerateAPIKey()
	require.NoError(t, err)
	require.NotEmpty(t, rawAPIKey)
	require.NotEmpty(t, argonHash)

	err = auth.SaveKeyToStorePath(storePath, rawAPIKey, argonHash)
	require.NoError(t, err)

	// =========================================================================
	// STAGE 2: LISTENER STARTING IN TRIGGER MODE (ZERO INITIAL TARGETS)
	// =========================================================================
	keystore, err := auth.NewKeystore(storePath)
	require.NoError(t, err)

	broadcaster := web.NewBroadcaster()
	registry := engine.NewDynamicTargetRegistry()
	dynamicEng := engine.NewDynamicEngine(broadcaster, registry, 100)

	server := web.NewServer("127.0.0.1:0", nil, broadcaster)
	server.SetTargetsSupplier(registry.GetFleetTargets)
	server.SetKeyValidator(keystore)
	server.SetDynamicExecutor(dynamicEng)
	server.SetDynamicFleetManager(registry)

	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	// =========================================================================
	// STAGE 3: PUBLIC WEB DASHBOARD ACCESS & VISUALIZATION ASSETS
	// =========================================================================
	dashResp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	defer dashResp.Body.Close()
	assert.Equal(t, http.StatusOK, dashResp.StatusCode)
	assert.Contains(t, dashResp.Header.Get("Content-Type"), "text/html")

	// =========================================================================
	// STAGE 4: CLIENT SUBSCRIBES TO REAL-TIME SSE TELEMETRY STREAM
	// =========================================================================
	sseCtx, sseCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer sseCancel()

	sseReq, err := http.NewRequestWithContext(sseCtx, http.MethodGet, ts.URL+"/api/v1/stream", nil)
	require.NoError(t, err)

	sseResp, err := http.DefaultClient.Do(sseReq)
	require.NoError(t, err)
	defer sseResp.Body.Close()
	assert.Equal(t, http.StatusOK, sseResp.StatusCode)
	assert.Contains(t, sseResp.Header.Get("Content-Type"), "text/event-stream")

	liveEvents := make(chan web.ProbeEvent, 5)
	go func() {
		scanner := bufio.NewScanner(sseResp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				var ev web.ProbeEvent
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err == nil {
					liveEvents <- ev
				}
			}
		}
	}()

	time.Sleep(50 * time.Millisecond) // Allow SSE subscription loop to register

	// =========================================================================
	// STAGE 5: REST CLIENT AUTH & PROBE TRIGGERING (TCP ECHO SERVICE)
	// =========================================================================
	targetLn, targetPort := startTestTCPTarget(t)
	defer targetLn.Close()

	triggerPayload := web.TriggerRequest{
		Host:      "127.0.0.1",
		Port:      targetPort,
		Protocol:  "tcp",
		Timeout:   "1s",
		ShowDiags: true,
		Broadcast: func(b bool) *bool { return &b }(true),
	}
	bodyBytes, err := json.Marshal(triggerPayload)
	require.NoError(t, err)

	triggerReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", bytes.NewReader(bodyBytes))
	require.NoError(t, err)
	triggerReq.Header.Set("X-API-Key", rawAPIKey)
	triggerReq.Header.Set("Content-Type", "application/json")

	triggerResp, err := http.DefaultClient.Do(triggerReq)
	require.NoError(t, err)
	defer triggerResp.Body.Close()

	// =========================================================================
	// STAGE 6: SYNCHRONOUS PROBE RESPONSE VERIFICATION
	// =========================================================================
	assert.Equal(t, http.StatusOK, triggerResp.StatusCode)
	var trigResult web.TriggerResponse
	err = json.NewDecoder(triggerResp.Body).Decode(&trigResult)
	require.NoError(t, err)

	assert.True(t, trigResult.Success)
	assert.Equal(t, "TCP", trigResult.Protocol)
	assert.Equal(t, targetPort, trigResult.Port)
	assert.GreaterOrEqual(t, trigResult.RTTMs, float64(0))
	assert.NotEmpty(t, trigResult.Diagnostics)
	assert.NotEmpty(t, trigResult.Timestamp)

	// =========================================================================
	// STAGE 7: REAL-TIME SSE SUBSCRIBER DATA RECEIPT
	// =========================================================================
	select {
	case receivedEvent := <-liveEvents:
		assert.Equal(t, fmt.Sprintf("127.0.0.1:%d", targetPort), receivedEvent.Target)
		assert.Equal(t, "TCP", receivedEvent.Protocol)
		assert.True(t, receivedEvent.Success)
		assert.GreaterOrEqual(t, receivedEvent.RTT, float64(0))
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for live SSE event in full lifecycle test")
	}

	// =========================================================================
	// STAGE 8: WEB DASHBOARD VISUALIZATION TELEMETRY VERIFICATION
	// =========================================================================
	// 1. Check /api/v1/targets
	targetsResp, err := http.Get(ts.URL + "/api/v1/targets")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, targetsResp.StatusCode)
	var targetsData map[string]interface{}
	_ = json.NewDecoder(targetsResp.Body).Decode(&targetsData)
	assert.GreaterOrEqual(t, targetsData["total"], float64(1))

	// 2. Check /api/v1/metrics
	metricsResp, err := http.Get(ts.URL + "/api/v1/metrics")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, metricsResp.StatusCode)
	var metricsData map[string]interface{}
	_ = json.NewDecoder(metricsResp.Body).Decode(&metricsData)
	assert.GreaterOrEqual(t, metricsData["target_count"], float64(1))
	assert.GreaterOrEqual(t, metricsData["total_sent"], float64(1))

	// 3. Check /api/v1/probes history queryable by Web UI
	probesResp, err := http.Get(ts.URL + "/api/v1/probes?limit=10")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, probesResp.StatusCode)
	var probesData map[string]interface{}
	_ = json.NewDecoder(probesResp.Body).Decode(&probesData)
	assert.GreaterOrEqual(t, probesData["total"], float64(1))
}

func TestEndToEnd_TriggerMode_EdgeCases_And_SecurityBoundaries(t *testing.T) {
	ts, keystore, rawKey, _, _ := setupTriggerEnvironment(t)
	defer ts.Close()

	targetLn, targetPort := startTestTCPTarget(t)
	defer targetLn.Close()

	// 1. Malformed JSON payload -> 400 Bad Request
	malformedReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", strings.NewReader(`{malformed_json:`))
	require.NoError(t, err)
	malformedReq.Header.Set("X-API-Key", rawKey)
	resp, err := http.DefaultClient.Do(malformedReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// 2. Missing target/host/uri -> 400 Bad Request
	emptyTargetReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", strings.NewReader(`{"timeout":"1s"}`))
	require.NoError(t, err)
	emptyTargetReq.Header.Set("X-API-Key", rawKey)
	respEmpty, err := http.DefaultClient.Do(emptyTargetReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, respEmpty.StatusCode)

	// 3. URI scheme parsing in payload (e.g. postgres://db.corp:5432)
	uriPayload := fmt.Sprintf(`{"uri":"tcp://127.0.0.1:%d","timeout":"1s"}`, targetPort)
	uriReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", strings.NewReader(uriPayload))
	require.NoError(t, err)
	uriReq.Header.Set("X-API-Key", rawKey)
	respURI, err := http.DefaultClient.Do(uriReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respURI.StatusCode)
	var uriResult web.TriggerResponse
	_ = json.NewDecoder(respURI.Body).Decode(&uriResult)
	assert.True(t, uriResult.Success)

	// 4. Selective broadcasting (broadcast: false)
	sseCtx, sseCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sseCancel()

	sseReq, _ := http.NewRequestWithContext(sseCtx, http.MethodGet, ts.URL+"/api/v1/stream", nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	require.NoError(t, err)
	defer sseResp.Body.Close()

	noBroadcastReceived := make(chan struct{}, 1)
	go func() {
		scanner := bufio.NewScanner(sseResp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") && strings.Contains(line, "SECRET_NO_BROADCAST") {
				noBroadcastReceived <- struct{}{}
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)

	noBcastPayload := fmt.Sprintf(`{"target":"127.0.0.1:%d","protocol":"tcp","broadcast":false,"send_data":"SECRET_NO_BROADCAST"}`, targetPort)
	noBcastReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", strings.NewReader(noBcastPayload))
	noBcastReq.Header.Set("X-API-Key", rawKey)
	respNoBcast, err := http.DefaultClient.Do(noBcastReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respNoBcast.StatusCode)

	select {
	case <-noBroadcastReceived:
		t.Fatal("event with broadcast: false should not be received over SSE stream")
	case <-time.After(300 * time.Millisecond):
		// Expected: event was not broadcast
	}

	// 5. Alternate header formats: lower-case x-api-key, Authorization: apikey <key>
	caseReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", strings.NewReader(fmt.Sprintf(`{"target":"127.0.0.1:%d"}`, targetPort)))
	caseReq.Header.Set("x-api-key", rawKey)
	respCase, err := http.DefaultClient.Do(caseReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respCase.StatusCode)

	apikeyPrefixReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", strings.NewReader(fmt.Sprintf(`{"target":"127.0.0.1:%d"}`, targetPort)))
	apikeyPrefixReq.Header.Set("Authorization", "apikey "+rawKey)
	respApikey, err := http.DefaultClient.Do(apikeyPrefixReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respApikey.StatusCode)

	// 6. Corrupted / Tampered Keystore Hash Resilience
	tamperedResult := keystore.ValidateKey("np_live_tampered")
	assert.False(t, tamperedResult)
	tamperedHashCheck := auth.VerifyKey(rawKey, "$argon2id$v=19$m=65536,t=3,p=4$corrupted_salt$corrupted_hash")
	assert.False(t, tamperedHashCheck)
	assert.False(t, auth.VerifyKey("", ""))

	// 7. Concurrent Trigger Bursts (Stress Test)
	concurrencyCount := 10
	errChan := make(chan error, concurrencyCount)
	for i := 0; i < concurrencyCount; i++ {
		go func(seq int) {
			p := fmt.Sprintf(`{"target":"127.0.0.1:%d","protocol":"tcp","timeout":"1s"}`, targetPort)
			cReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", strings.NewReader(p))
			if err != nil {
				errChan <- err
				return
			}
			cReq.Header.Set("X-API-Key", rawKey)
			cResp, err := http.DefaultClient.Do(cReq)
			if err != nil {
				errChan <- err
				return
			}
			defer cResp.Body.Close()
			if cResp.StatusCode != http.StatusOK {
				errChan <- fmt.Errorf("expected 200 OK, got %d", cResp.StatusCode)
				return
			}
			errChan <- nil
		}(i)
	}

	for i := 0; i < concurrencyCount; i++ {
		assert.NoError(t, <-errChan)
	}

	// 8. Security Test: Oversized Payload Protection (MaxBytesReader)
	oversizedBody := strings.Repeat("a", 2<<20) // 2MB payload (exceeds 1MB limit)
	overReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/trigger", strings.NewReader(oversizedBody))
	overReq.Header.Set("X-API-Key", rawKey)
	overReq.Header.Set("Content-Type", "application/json")
	overResp, err := http.DefaultClient.Do(overReq)
	require.NoError(t, err)
	defer overResp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, overResp.StatusCode, "oversized payload should be rejected with 400 Bad Request")
}

func TestDiagnosticExitCodes(t *testing.T) {
	assert.Equal(t, 0, consts.ExitSuccess)
	assert.Equal(t, 1, consts.ExitGeneralError)
	assert.Equal(t, 2, consts.ExitUsageError)
	assert.Equal(t, 3, consts.ExitDNSResolutionFailed)
	assert.Equal(t, 4, consts.ExitNetworkInterfaceError)
	assert.Equal(t, 5, consts.ExitTargetUnreachable)
	assert.Equal(t, 6, consts.ExitPartialPacketLoss)
	assert.Equal(t, 7, consts.ExitStorageError)
	assert.Equal(t, 130, consts.ExitInterrupted)
}
