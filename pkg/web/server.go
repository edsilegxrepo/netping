// Package web provides the embedded real-time HTTP server, Server-Sent Events (SSE) broadcaster,
// HTML5 Canvas 2D dashboard, REST telemetry APIs, OpenAPI 3.0 specifications, and trigger endpoints for netping.
//
// Objectives:
//   - Serve zero-dependency interactive HTML5/Canvas visualization dashboard.
//   - Stream live probe events to connected browser clients via Server-Sent Events (SSE).
//   - Provide REST APIs for target metrics, telemetry history, report exports, and dynamic probe triggering.
//   - Enforce Argon2id authentication and request body bounds on protected endpoints.
//
// Core Components:
//   - Server: Embedded HTTP server multiplexing web dashboard, REST endpoints, and SSE streams.
//   - Broadcaster: High-throughput non-blocking SSE event distributor with ring-buffer retention.
//   - Trigger API: Authenticated POST /api/v1/trigger endpoint executing dynamic on-demand probes.
//
// Data Flow:
//
//	Prober Event -> Broadcaster.Broadcast() -> Active SSE Channels -> Browser EventSource / Canvas Stream
//	REST Client -> POST /api/v1/trigger -> Auth Validation -> Engine Execution -> Broadcaster -> JSON Response.
package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/edsilegx/netping/internal/printers"
	"github.com/edsilegx/netping/pkg/stats"
)

//go:embed dashboard.html
var dashboardHTML []byte

type Server struct {
	addr            string
	stats           *stats.Statistics
	broadcaster     *Broadcaster
	httpServer      *http.Server
	startTime       time.Time
	targetsSupplier func() []printers.FleetTarget
	validator       KeyValidator
	dynamicExecutor DynamicExecutor
	fleetManager    DynamicFleetManager
}

// NewServer constructs a new web dashboard server.
func NewServer(addr string, st *stats.Statistics, broadcaster *Broadcaster) *Server {
	if addr == "" {
		addr = "127.0.0.1:3000"
	}

	s := &Server{
		addr:        addr,
		stats:       st,
		broadcaster: broadcaster,
		startTime:   time.Now(),
	}

	mux := http.NewServeMux()

	// Static SPA Dashboard
	mux.HandleFunc("/", s.handleIndex)

	// REST API v1
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/health/", s.handleHealth)
	mux.HandleFunc("/api/v1/metrics", s.handleMetrics)
	mux.HandleFunc("/api/v1/metrics/", s.handleMetrics)
	mux.HandleFunc("/api/v1/targets", s.handleTargets)
	mux.HandleFunc("/api/v1/targets/", s.handleTargetDetail)
	mux.HandleFunc("/api/v1/probes", s.handleProbes)
	mux.HandleFunc("/api/v1/probes/", s.handleProbes)
	mux.HandleFunc("/api/v1/stream", s.handleStream)
	mux.HandleFunc("/api/v1/stream/", s.handleStream)
	mux.HandleFunc("/api/v1/export", s.handleExport)
	mux.HandleFunc("/api/v1/export/", s.handleExport)
	mux.HandleFunc("/api/v1/reset", s.handleReset)
	mux.HandleFunc("/api/v1/reset/", s.handleReset)
	mux.HandleFunc("/api/v1/config/history", s.handleHistoryConfig)
	mux.HandleFunc("/api/v1/config/history/", s.handleHistoryConfig)

	// Trigger API v1 (Protected via Argon2id)
	mux.HandleFunc("/api/v1/trigger", s.handleTrigger)
	mux.HandleFunc("/api/v1/trigger/", s.handleTrigger)
	mux.HandleFunc("/api/v1/trigger/status", s.handleTriggerStatus)
	mux.HandleFunc("/api/v1/trigger/status/", s.handleTriggerStatus)

	// Swagger UI / OpenAPI 3.0 Documentation
	mux.HandleFunc("/api", s.handleAPIDocs)
	mux.HandleFunc("/api/", s.handleAPIDocs)
	mux.HandleFunc("/api/docs", s.handleAPIDocs)
	mux.HandleFunc("/api/docs/", s.handleAPIDocs)
	mux.HandleFunc("/swagger", s.handleAPIDocs)
	mux.HandleFunc("/swagger/", s.handleAPIDocs)
	mux.HandleFunc("/docs", s.handleAPIDocs)
	mux.HandleFunc("/docs/", s.handleAPIDocs)
	mux.HandleFunc("/api/openapi.json", s.handleOpenAPISpec)
	mux.HandleFunc("/api/v1/openapi.json", s.handleOpenAPISpec)
	mux.HandleFunc("/swagger.json", s.handleOpenAPISpec)

	// Legacy / Backward Compatible Endpoints
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/stats/", s.handleStats)
	mux.HandleFunc("/api/stream", s.handleStream)
	mux.HandleFunc("/api/export", s.handleExport)

	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return s
}

// Handler returns the underlying http.Handler for testing and embedding.
func (s *Server) Handler() http.Handler {
	if s.httpServer != nil {
		return s.httpServer.Handler
	}
	return nil
}

// SetTargetsSupplier registers a fleet supplier callback to query active probers in O(1) time.
func (s *Server) SetTargetsSupplier(fn func() []printers.FleetTarget) {
	s.targetsSupplier = fn
}

// SetKeyValidator registers an API key validator for protected endpoints.
func (s *Server) SetKeyValidator(v KeyValidator) {
	s.validator = v
}

// SetDynamicExecutor registers the dynamic on-demand probe runner.
func (s *Server) SetDynamicExecutor(e DynamicExecutor) {
	s.dynamicExecutor = e
}

// SetDynamicFleetManager registers the dynamic target fleet manager.
func (s *Server) SetDynamicFleetManager(m DynamicFleetManager) {
	s.fleetManager = m
}

// Start launches the web server asynchronously and shuts down gracefully on context cancellation.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to bind web dashboard to %s: %w", s.addr, err)
	}

	fmt.Printf("\n\033[1;32m●\033[0m \033[1mWeb Dashboard & REST API live at:\033[0m \033[1;36mhttp://%s\033[0m\n\n", s.addr)

	// #nosec G118 -- background shutdown listener watching application lifecycle context
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Printf("web dashboard error: %v\n", err)
		}
	}()

	return nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- static compile-time embedded dashboard HTML
	_, _ = w.Write(dashboardHTML)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	targetCount := 1
	if s.targetsSupplier != nil {
		targetCount = len(s.targetsSupplier())
	}
	historyCount := 0
	historyLimit := 1000000
	if s.broadcaster != nil {
		historyCount = s.broadcaster.GetHistoryCount()
		historyLimit = s.broadcaster.GetMaxHistory()
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":               "healthy",
		"uptime":               time.Since(s.startTime).Round(time.Second).String(),
		"start_time":           s.startTime.Format(time.RFC3339),
		"target_count":         targetCount,
		"history_count":        historyCount,
		"history_limit":        historyLimit,
		"history_max_capacity": 5000000,
		"version":              "v1.0.0",
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.targetsSupplier != nil {
		targets := s.targetsSupplier()
		var totalSent, totalSuccess, totalFailed uint
		var sumRTT float64
		var countRTT uint
		var minRTT, maxRTT float32
		minRTT = -1

		targetSnapshots := make([]stats.Snapshot, len(targets))
		for i, t := range targets {
			snap := t.Stats.Snapshot()
			targetSnapshots[i] = snap
			totalSent += snap.TotalSent
			totalSuccess += snap.TotalSuccess
			totalFailed += snap.TotalFailed
			if snap.TotalSuccess > 0 {
				sumRTT += float64(snap.AvgRTT)
				countRTT++
				if minRTT < 0 || snap.MinRTT < minRTT {
					minRTT = snap.MinRTT
				}
				if snap.MaxRTT > maxRTT {
					maxRTT = snap.MaxRTT
				}
			}
		}

		loss := float64(0)
		if totalSent > 0 {
			loss = float64(totalFailed) / float64(totalSent) * 100.0
		}
		avg := float32(0)
		if countRTT > 0 {
			avg = float32(sumRTT / float64(countRTT))
		}
		if minRTT < 0 {
			minRTT = 0
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"uptime":        time.Since(s.startTime).Round(time.Second).String(),
			"start_time":    s.startTime.Format(time.RFC3339),
			"target_count":  len(targets),
			"total_sent":    totalSent,
			"total_success": totalSuccess,
			"total_failed":  totalFailed,
			"packet_loss":   loss,
			"avg_rtt":       avg,
			"min_rtt":       minRTT,
			"max_rtt":       maxRTT,
			"targets":       targetSnapshots,
		})
		return
	}

	if s.stats != nil {
		snap := s.stats.Snapshot()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"uptime":        snap.UptimeDuration,
			"start_time":    s.startTime.Format(time.RFC3339),
			"target_count":  1,
			"total_sent":    snap.TotalSent,
			"total_success": snap.TotalSuccess,
			"total_failed":  snap.TotalFailed,
			"packet_loss":   snap.PacketLoss,
			"latest_rtt":    snap.LatestRTT,
			"avg_rtt":       snap.AvgRTT,
			"min_rtt":       snap.MinRTT,
			"max_rtt":       snap.MaxRTT,
			"jitter":        snap.Jitter,
			"targets":       []stats.Snapshot{snap},
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"uptime":       time.Since(s.startTime).Round(time.Second).String(),
		"start_time":   s.startTime.Format(time.RFC3339),
		"target_count": 0,
	})
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	if s.targetsSupplier != nil {
		targets := s.targetsSupplier()
		snapshots := make([]stats.Snapshot, len(targets))
		for i, t := range targets {
			snapshots[i] = t.Stats.Snapshot()
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"total": len(snapshots),
			"data":  snapshots,
		})
		return
	}

	if s.stats != nil {
		snap := s.stats.Snapshot()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"total": 1,
			"data":  []stats.Snapshot{snap},
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total": 0,
		"data":  []stats.Snapshot{},
	})
}

func (s *Server) handleTargetDetail(w http.ResponseWriter, r *http.Request) {
	targetID := strings.TrimPrefix(r.URL.Path, "/api/v1/targets/")
	if targetID == "" {
		s.handleTargets(w, r)
		return
	}

	if s.targetsSupplier != nil {
		for _, t := range s.targetsSupplier() {
			if t.Target == targetID || t.Host == targetID || (t.Stats != nil && t.Stats.IP.String() == targetID) {
				writeJSON(w, http.StatusOK, t.Stats.Snapshot())
				return
			}
		}
	}

	if s.stats != nil {
		snap := s.stats.Snapshot()
		if s.stats.Hostname == targetID || s.stats.IP.String() == targetID || fmt.Sprintf("%s:%d", s.stats.Hostname, s.stats.Port) == targetID {
			writeJSON(w, http.StatusOK, snap)
			return
		}
	}

	http.Error(w, fmt.Sprintf("Target not found: %s", targetID), http.StatusNotFound)
}

func (s *Server) handleProbes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := q.Get("target")
	status := q.Get("status")
	limit := 50
	if l := q.Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}
	offset := 0
	if o := q.Get("offset"); o != "" {
		if val, err := strconv.Atoi(o); err == nil && val >= 0 {
			offset = val
		}
	}

	events, total := s.broadcaster.GetProbes(target, status, limit, offset)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":  total,
		"limit":  limit,
		"offset": offset,
		"data":   events,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if s.stats != nil {
		s.stats.Mu.RLock()
		defer s.stats.Mu.RUnlock()
		writeJSON(w, http.StatusOK, s.stats)
		return
	}
	s.handleMetrics(w, r)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush()

	ch := s.broadcaster.Subscribe()
	defer s.broadcaster.Unsubscribe(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			// nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter -- text/event-stream SSE payload
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func parseExportFormat(fmtStr string) printers.ExportFormat {
	switch strings.ToLower(strings.TrimSpace(fmtStr)) {
	case "0", "1", "json":
		return printers.FormatJSON
	case "2", "pretty_json", "prettyjson":
		return printers.FormatPrettyJSON
	case "3", "csv":
		return printers.FormatCSV
	case "4", "tsv":
		return printers.FormatTSV
	case "5", "sqlite", "sqlite3", "db":
		return printers.FormatSQLite3
	case "6", "txt", "text", "plain":
		return printers.FormatPlainText
	default:
		return printers.FormatJSON
	}
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, X-API-Key, Content-Type, Accept")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return false
	}

	if s.validator == nil {
		return true // Auth not configured (e.g. standard subscriber mode)
	}

	key := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if key == "" {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			key = strings.TrimSpace(authHeader[7:])
		} else if strings.HasPrefix(strings.ToLower(authHeader), "apikey ") {
			key = strings.TrimSpace(authHeader[7:])
		} else {
			key = authHeader
		}
	}

	if key == "" || !s.validator.ValidateKey(key) {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"error":   "unauthorized",
			"message": "Invalid or missing API key. Provide via 'X-API-Key' or 'Authorization: Bearer <key>' header.",
		})
		return false
	}

	return true
}

func (s *Server) handleTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, X-API-Key, Content-Type, Accept")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if !s.authenticate(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Use POST to trigger probes.", http.StatusMethodNotAllowed)
		return
	}

	if s.dynamicExecutor == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error":   "unavailable",
			"message": "Trigger engine is not initialized",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB payload limit
	var req TriggerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "bad_request",
			"message": fmt.Sprintf("invalid JSON payload: %v", err),
		})
		return
	}

	resp, err := s.dynamicExecutor.Execute(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "probe_execution_failed",
			"message": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTriggerStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}

	targetCount := 0
	if s.targetsSupplier != nil {
		targetCount = len(s.targetsSupplier())
	}
	historyCount := 0
	historyLimit := 1000000
	if s.broadcaster != nil {
		historyCount = s.broadcaster.GetHistoryCount()
		historyLimit = s.broadcaster.GetMaxHistory()
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":          "ready",
		"mode":            "trigger",
		"auth_enabled":    s.validator != nil,
		"uptime":          time.Since(s.startTime).Round(time.Second).String(),
		"start_time_utc":  s.startTime.Format(time.RFC3339),
		"active_targets":  targetCount,
		"history_events":  historyCount,
		"history_limit":   historyLimit,
		"server_time_utc": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}

	if s.broadcaster != nil {
		s.broadcaster.ClearHistory()
	}
	if s.stats != nil {
		s.stats.Reset()
	}
	if s.targetsSupplier != nil {
		for _, t := range s.targetsSupplier() {
			if t.Stats != nil {
				t.Stats.Reset()
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "reset",
		"message": "Telemetry, chart, and probe history reset successfully",
	})
}

func (s *Server) handleHistoryConfig(w http.ResponseWriter, r *http.Request) {
	if s.broadcaster == nil {
		http.Error(w, "Broadcaster unavailable", http.StatusServiceUnavailable)
		return
	}

	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"history_limit":        s.broadcaster.GetMaxHistory(),
			"history_count":        s.broadcaster.GetHistoryCount(),
			"history_max_capacity": 5000000,
		})
		return
	}

	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64KB limit
		var req struct {
			Limit int `json:"limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Limit < 100 {
			http.Error(w, "history limit must be at least 100", http.StatusBadRequest)
			return
		}
		if req.Limit > 5000000 {
			http.Error(w, "history limit cannot exceed 5,000,000", http.StatusBadRequest)
			return
		}

		s.broadcaster.SetMaxHistory(req.Limit)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":              true,
			"history_limit":        s.broadcaster.GetMaxHistory(),
			"history_count":        s.broadcaster.GetHistoryCount(),
			"history_max_capacity": 5000000,
			"message":              fmt.Sprintf("History retention limit updated to %d events", s.broadcaster.GetMaxHistory()),
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	rawEvents := s.broadcaster.GetHistory()
	history := make([]printers.SingleProbeExportRecord, len(rawEvents))

	var fleetTargets []printers.FleetTarget
	if s.targetsSupplier != nil {
		fleetTargets = s.targetsSupplier()
	}

	defaultTarget := ""
	defaultPort := uint16(0)
	defaultProtocol := ""

	for i, ev := range rawEvents {
		t := ev.RawTime
		if t.IsZero() {
			t = time.Now()
		}

		tgt := ev.Target
		if tgt == "" && ev.IP != "" {
			tgt = ev.IP
			if ev.Port != 0 {
				tgt = fmt.Sprintf("%s:%d", ev.IP, ev.Port)
			}
		}
		if defaultTarget == "" && tgt != "" {
			defaultTarget = tgt
		}
		if defaultPort == 0 && ev.Port != 0 {
			defaultPort = ev.Port
		}
		if defaultProtocol == "" && ev.Protocol != "" {
			defaultProtocol = ev.Protocol
		}

		history[i] = printers.SingleProbeExportRecord{
			Timestamp:   t,
			Seq:         ev.Sequence,
			Target:      tgt,
			Protocol:    ev.Protocol,
			IP:          ev.IP,
			IsSuccess:   ev.Success,
			RTTMs:       ev.RTT,
			Diagnostics: ev.Diagnostics,
			Error:       ev.Error,
		}
	}

	if s.stats != nil {
		snap := s.stats.Snapshot()
		if defaultTarget == "" {
			defaultTarget = snap.Hostname
		}
		if defaultPort == 0 {
			defaultPort = snap.Port
		}
		if defaultProtocol == "" {
			defaultProtocol = snap.Protocol
		}
	}

	isFleet := len(fleetTargets) > 1

	if r.Method == http.MethodPost {
		var req struct {
			Format string `json:"format"`
			Path   string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		format := parseExportFormat(req.Format)
		savePath := req.Path
		if savePath == "" {
			savePath = printers.GenerateDefaultExportPath(isFleet, format)
		}

		go func() {
			if isFleet {
				_ = printers.ExportMultiTarget(fleetTargets, s.startTime, history, format, savePath)
			} else {
				_ = printers.ExportSingleTarget(defaultTarget, defaultPort, defaultProtocol, s.stats, history, format, savePath)
			}
		}()

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"path":    savePath,
			"format":  printers.FormatNames[format],
			"message": fmt.Sprintf("Successfully exported to %s", savePath),
		})
		return
	}

	// GET: browser direct download
	formatStr := r.URL.Query().Get("format")
	format := parseExportFormat(formatStr)
	defaultFileName := filepath.Base(printers.GenerateDefaultExportPath(isFleet, format))

	contentType := "application/octet-stream"
	switch format {
	case printers.FormatJSON, printers.FormatPrettyJSON:
		contentType = "application/json"
	case printers.FormatCSV:
		contentType = "text/csv"
	case printers.FormatTSV:
		contentType = "text/tab-separated-values"
	case printers.FormatPlainText:
		contentType = "text/plain; charset=utf-8"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", defaultFileName))

	if format == printers.FormatSQLite3 {
		tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("netping_%d.db", time.Now().UnixNano()))
		defer func() { _ = os.Remove(tmpFile) }()
		var exportErr error
		if isFleet {
			exportErr = printers.ExportMultiTarget(fleetTargets, s.startTime, history, format, tmpFile)
		} else {
			exportErr = printers.ExportSingleTarget(defaultTarget, defaultPort, defaultProtocol, s.stats, history, format, tmpFile)
		}
		if exportErr != nil {
			http.Error(w, fmt.Sprintf("Export failed: %v", exportErr), http.StatusInternalServerError)
			return
		}
		// #nosec G304 -- opens temporary export file created by internal export routine
		f, err := os.Open(filepath.Clean(tmpFile))
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read export: %v", err), http.StatusInternalServerError)
			return
		}
		defer func() { _ = f.Close() }()
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
		return
	}

	w.WriteHeader(http.StatusOK)
	if isFleet {
		_ = printers.ExportMultiTargetToWriter(w, fleetTargets, s.startTime, history, format)
	} else {
		_ = printers.ExportSingleTargetToWriter(w, defaultTarget, defaultPort, defaultProtocol, s.stats, history, format)
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, X-API-Key, Content-Type, Accept")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") || r.URL.Query().Get("format") == "json" {
		s.handleOpenAPISpec(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Netping REST API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  <style>
    body { margin: 0; padding: 0; background: #0B0F19; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .swagger-ui .topbar { display: none; }
    .swagger-ui { filter: invert(88%) hue-rotate(180deg); }
    .swagger-ui .wrapper { max-width: 1200px; padding: 20px; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: "/api/openapi.json",
        dom_id: '#swagger-ui',
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout",
        deepLinking: true,
        showExtensions: true,
        showCommonExtensions: true
      });
    };
  </script>
</body>
</html>`))
}

func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	spec := map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":       "Netping REST API",
			"description": "High-performance enterprise network probing, health checking, and telemetry API.",
			"version":     "1.0.0",
		},
		"paths": map[string]interface{}{
			"/api/v1/health": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Service Health",
					"description": "Returns current daemon health, uptime, and target count.",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Health status",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"status":       map[string]interface{}{"type": "string", "example": "healthy"},
											"uptime":       map[string]interface{}{"type": "string", "example": "5m32s"},
											"start_time":   map[string]interface{}{"type": "string", "format": "date-time"},
											"target_count": map[string]interface{}{"type": "integer", "example": 3},
											"version":      map[string]interface{}{"type": "string", "example": "v1.0.0"},
										},
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/metrics": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Aggregate Metrics",
					"description": "Returns point-in-time fleet summary and per-target metrics in O(1) time.",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Aggregate fleet metrics",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/FleetMetrics"},
								},
							},
						},
					},
				},
			},
			"/api/v1/targets": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List Monitored Targets",
					"description": "Retrieves all monitored targets and their latest health statistics.",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "List of targets",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"total": map[string]interface{}{"type": "integer"},
											"data":  map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/components/schemas/TargetSnapshot"}},
										},
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/targets/{id}": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "Target Details",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"schema":      map[string]interface{}{"type": "string"},
							"description": "Target name, hostname, or IP address",
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Target statistics snapshot",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/TargetSnapshot"},
								},
							},
						},
						"404": map[string]interface{}{"description": "Target not found"},
					},
				},
			},
			"/api/v1/probes": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Query Probe History",
					"description": "Retrieves paginated and filtered historical probe events.",
					"parameters": []map[string]interface{}{
						{"name": "target", "in": "query", "schema": map[string]interface{}{"type": "string"}, "description": "Filter by target name/IP"},
						{"name": "status", "in": "query", "schema": map[string]interface{}{"type": "string", "enum": []string{"success", "failed"}}, "description": "Filter by probe status"},
						{"name": "limit", "in": "query", "schema": map[string]interface{}{"type": "integer", "default": 50}, "description": "Max records to return (1-500)"},
						{"name": "offset", "in": "query", "schema": map[string]interface{}{"type": "integer", "default": 0}, "description": "Pagination offset"},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Paginated probe records",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"total":  map[string]interface{}{"type": "integer"},
											"limit":  map[string]interface{}{"type": "integer"},
											"offset": map[string]interface{}{"type": "integer"},
											"data":   map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/components/schemas/ProbeEvent"}},
										},
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/stream": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Real-time Event Stream (SSE)",
					"description": "Server-Sent Events stream yielding live probe results.",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Text event stream",
							"content": map[string]interface{}{
								"text/event-stream": map[string]interface{}{
									"schema": map[string]interface{}{"type": "string"},
								},
							},
						},
					},
				},
			},
			"/api/v1/export": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Stream Export File",
					"description": "Downloads probe metrics and history in the requested format without disk temp files.",
					"parameters": []map[string]interface{}{
						{
							"name":        "format",
							"in":          "query",
							"schema":      map[string]interface{}{"type": "string", "enum": []string{"json", "pretty_json", "csv", "tsv", "txt", "db"}, "default": "json"},
							"description": "Export format",
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Export file stream"},
					},
				},
				"post": map[string]interface{}{
					"summary":     "Save Export to Host",
					"description": "Generates and saves the export file to a specific destination path on the host filesystem.",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"format": map[string]interface{}{"type": "string", "enum": []string{"json", "pretty_json", "csv", "tsv", "txt", "db"}},
										"path":   map[string]interface{}{"type": "string", "description": "Destination file path"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Export saved successfully"},
					},
				},
			},
			"/api/v1/trigger": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Execute Dynamic Probe",
					"description": "Triggers an on-demand synchronous network probe across any supported protocol.",
					"security": []map[string]interface{}{
						{"ApiKeyAuth": []string{}},
						{"BearerAuth": []string{}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"target"},
									"properties": map[string]interface{}{
										"target":     map[string]interface{}{"type": "string", "example": "db.internal.net"},
										"port":       map[string]interface{}{"type": "integer", "example": 5432},
										"protocol":   map[string]interface{}{"type": "string", "example": "postgres"},
										"timeout":    map[string]interface{}{"type": "string", "example": "2s"},
										"count":      map[string]interface{}{"type": "integer", "example": 1},
										"show_diags": map[string]interface{}{"type": "boolean", "example": true},
										"broadcast":  map[string]interface{}{"type": "boolean", "example": true},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Probe execution result",
						},
						"401": map[string]interface{}{"description": "Unauthorized - Missing or invalid API key"},
					},
				},
			},
		},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"ApiKeyAuth": map[string]interface{}{
					"type":        "apiKey",
					"in":          "header",
					"name":        "X-API-Key",
					"description": "Argon2id API Key authentication token",
				},
				"BearerAuth": map[string]interface{}{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "APIKey",
					"description":  "Argon2id API Key bearer token",
				},
			},
			"schemas": map[string]interface{}{
				"TargetSnapshot": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"hostname":        map[string]interface{}{"type": "string"},
						"ip":              map[string]interface{}{"type": "string"},
						"port":            map[string]interface{}{"type": "integer"},
						"protocol":        map[string]interface{}{"type": "string"},
						"total_sent":      map[string]interface{}{"type": "integer"},
						"total_success":   map[string]interface{}{"type": "integer"},
						"total_failed":    map[string]interface{}{"type": "integer"},
						"packet_loss":     map[string]interface{}{"type": "number"},
						"latest_rtt":      map[string]interface{}{"type": "number"},
						"min_rtt":         map[string]interface{}{"type": "number"},
						"avg_rtt":         map[string]interface{}{"type": "number"},
						"max_rtt":         map[string]interface{}{"type": "number"},
						"jitter":          map[string]interface{}{"type": "number"},
						"uptime_duration": map[string]interface{}{"type": "string"},
					},
				},
				"FleetMetrics": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"uptime":        map[string]interface{}{"type": "string"},
						"start_time":    map[string]interface{}{"type": "string"},
						"target_count":  map[string]interface{}{"type": "integer"},
						"total_sent":    map[string]interface{}{"type": "integer"},
						"total_success": map[string]interface{}{"type": "integer"},
						"total_failed":  map[string]interface{}{"type": "integer"},
						"packet_loss":   map[string]interface{}{"type": "number"},
						"avg_rtt":       map[string]interface{}{"type": "number"},
						"min_rtt":       map[string]interface{}{"type": "number"},
						"max_rtt":       map[string]interface{}{"type": "number"},
						"targets":       map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/components/schemas/TargetSnapshot"}},
					},
				},
				"ProbeEvent": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"timestamp":   map[string]interface{}{"type": "string"},
						"sequence":    map[string]interface{}{"type": "integer"},
						"success":     map[string]interface{}{"type": "boolean"},
						"rtt":         map[string]interface{}{"type": "number"},
						"target":      map[string]interface{}{"type": "string"},
						"hostname":    map[string]interface{}{"type": "string"},
						"ip":          map[string]interface{}{"type": "string"},
						"port":        map[string]interface{}{"type": "integer"},
						"protocol":    map[string]interface{}{"type": "string"},
						"diagnostics": map[string]interface{}{"type": "string"},
						"error":       map[string]interface{}{"type": "string"},
					},
				},
			},
		},
	}
	writeJSON(w, http.StatusOK, spec)
}
