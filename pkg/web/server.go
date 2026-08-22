package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
)

//go:embed dashboard.html
var dashboardHTML []byte

type Server struct {
	addr        string
	stats       *stats.Statistics
	broadcaster *Broadcaster
	httpServer  *http.Server
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
	}

	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/stream", s.handleStream)

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
