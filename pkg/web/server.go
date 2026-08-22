package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/edsilegx/netping/internal/printers"
	"github.com/edsilegx/netping/pkg/stats"
)

//go:embed dashboard.html
var dashboardHTML []byte

type Server struct {
	addr        string
	stats       *stats.Statistics
	broadcaster *Broadcaster
	httpServer  *http.Server
	startTime   time.Time
}

// NewServer constructs a new web dashboard server.
func NewServer(addr string, stats *stats.Statistics, broadcaster *Broadcaster) *Server {
	if addr == "" {
		addr = "127.0.0.1:3000"
	}

	mux := http.NewServeMux()
	s := &Server{
		addr:        addr,
		stats:       stats,
		broadcaster: broadcaster,
		startTime:   time.Now(),
	}

	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/stream", s.handleStream)
	mux.HandleFunc("/api/export", s.handleExport)

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return s
}

// Start launches the web server asynchronously and shuts down gracefully on context cancellation.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to bind web dashboard to %s: %w", s.addr, err)
	}

	fmt.Printf("\n\033[1;32m●\033[0m \033[1mWeb Dashboard live at:\033[0m \033[1;36mhttp://%s\033[0m\n\n", s.addr)

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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dashboardHTML)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.stats.Mu.RLock()
	defer s.stats.Mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.stats)
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

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	rawEvents := s.broadcaster.GetHistory()
	history := make([]printers.SingleProbeExportRecord, len(rawEvents))

	uniqueTargets := make(map[string]*stats.Statistics)
	targetOrder := make([]string, 0)
	targetProtocols := make(map[string]string)
	defaultTarget := ""
	defaultPort := uint16(0)
	defaultProtocol := ""

	for i, ev := range rawEvents {
		t, err := time.Parse("15:04:05.000", ev.Timestamp)
		if err != nil {
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

		if tgt != "" {
			if _, ok := uniqueTargets[tgt]; !ok {
				uniqueTargets[tgt] = &stats.Statistics{
					Hostname: ev.Hostname,
					Port:     ev.Port,
					RTT:      make([]float32, 0),
				}
				if ipAddr, err := netip.ParseAddr(ev.IP); err == nil {
					uniqueTargets[tgt].IP = ipAddr
				}
				targetOrder = append(targetOrder, tgt)
				targetProtocols[tgt] = ev.Protocol
			}
			st := uniqueTargets[tgt]
			if ev.Success {
				st.TotalSuccessfulProbes++
				st.LatestRTT = float32(ev.RTT)
				st.RTT = append(st.RTT, float32(ev.RTT))
			} else {
				st.TotalUnsuccessfulProbes++
			}
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
		s.stats.Mu.RLock()
		if defaultTarget == "" {
			defaultTarget = s.stats.Hostname
		}
		if defaultPort == 0 {
			defaultPort = s.stats.Port
		}
		if defaultProtocol == "" {
			defaultProtocol = string(s.stats.Protocol)
		}
		s.stats.Mu.RUnlock()
	}

	isFleet := len(uniqueTargets) > 1

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

		var exportErr error
		if isFleet {
			fleetTargets := make([]printers.FleetTarget, len(targetOrder))
			for idx, tgt := range targetOrder {
				fleetTargets[idx] = printers.FleetTarget{
					Target:   tgt,
					Protocol: targetProtocols[tgt],
					Stats:    uniqueTargets[tgt],
				}
			}
			exportErr = printers.ExportMultiTarget(fleetTargets, s.startTime, history, format, savePath)
		} else {
			exportErr = printers.ExportSingleTarget(defaultTarget, defaultPort, defaultProtocol, s.stats, history, format, savePath)
		}

		if exportErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   exportErr.Error(),
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
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

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("netping_%d%s", time.Now().UnixNano(), printers.FormatExtensions[format]))
	defer os.Remove(tmpFile)

	var exportErr error
	if isFleet {
		fleetTargets := make([]printers.FleetTarget, len(targetOrder))
		for idx, tgt := range targetOrder {
			fleetTargets[idx] = printers.FleetTarget{
				Target:   tgt,
				Protocol: targetProtocols[tgt],
				Stats:    uniqueTargets[tgt],
			}
		}
		exportErr = printers.ExportMultiTarget(fleetTargets, s.startTime, history, format, tmpFile)
	} else {
		exportErr = printers.ExportSingleTarget(defaultTarget, defaultPort, defaultProtocol, s.stats, history, format, tmpFile)
	}

	if exportErr != nil {
		http.Error(w, fmt.Sprintf("Export failed: %v", exportErr), http.StatusInternalServerError)
		return
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read export: %v", err), http.StatusInternalServerError)
		return
	}

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
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
