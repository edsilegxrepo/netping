// Package metrics implements an embedded lightweight Prometheus exposition endpoint
// exporting real-time network telemetry, SLA status, and latency histograms.
//
// Objectives:
//   - Expose OpenMetrics / Prometheus scrape endpoints without heavy external SDKs.
//   - Report target reachability, RTT (min/avg/max/latest), packet loss, and RFC 3550 jitter.
//
// Core Components:
//   - StartMetricsServer: HTTP listener serving the standard GET /metrics endpoint.
//
// Data Flow:
//
//	Prometheus Scraper -> GET /metrics -> Statistics.Snapshot() -> OpenMetrics Text Format -> HTTP 200.
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
)

// StartMetricsServer starts an embedded lightweight Prometheus metrics exporter.
func StartMetricsServer(ctx context.Context, addr string, s *stats.Statistics) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		s.Mu.RLock()
		defer s.Mu.RUnlock()

		target := s.Hostname
		ip := s.IPStr()
		port := s.Port

		up := 0
		if !s.DestWasDown && s.TotalSuccessfulProbes > 0 {
			up = 1
		}

		total := s.TotalSuccessfulProbes + s.TotalUnsuccessfulProbes
		var lossRatio float32
		if total > 0 {
			lossRatio = float32(s.TotalUnsuccessfulProbes) / float32(total)
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		fmt.Fprintf(w, "# HELP tcping_up Target reachability (1 = up, 0 = down)\n")
		fmt.Fprintf(w, "# TYPE tcping_up gauge\n")
		fmt.Fprintf(w, "tcping_up{target=%q,ip=%q,port=\"%d\"} %d\n\n", target, ip, port, up)

		fmt.Fprintf(w, "# HELP tcping_probe_duration_seconds Latest round-trip latency in seconds\n")
		fmt.Fprintf(w, "# TYPE tcping_probe_duration_seconds gauge\n")
		fmt.Fprintf(w, "tcping_probe_duration_seconds{target=%q,ip=%q,port=\"%d\"} %f\n\n", target, ip, port, float64(s.LatestRTT)/1000.0)

		fmt.Fprintf(w, "# HELP tcping_jitter_seconds Packet jitter in seconds\n")
		fmt.Fprintf(w, "# TYPE tcping_jitter_seconds gauge\n")
		fmt.Fprintf(w, "tcping_jitter_seconds{target=%q,ip=%q,port=\"%d\"} %f\n\n", target, ip, port, float64(s.RTTResults.Jitter)/1000.0)

		fmt.Fprintf(w, "# HELP tcping_packet_loss_ratio Packet loss ratio between 0 and 1\n")
		fmt.Fprintf(w, "# TYPE tcping_packet_loss_ratio gauge\n")
		fmt.Fprintf(w, "tcping_packet_loss_ratio{target=%q,ip=%q,port=\"%d\"} %f\n\n", target, ip, port, lossRatio)

		fmt.Fprintf(w, "# HELP tcping_probes_total Total number of probes sent\n")
		fmt.Fprintf(w, "# TYPE tcping_probes_total counter\n")
		fmt.Fprintf(w, "tcping_probes_total{target=%q,ip=%q,port=\"%d\",status=\"success\"} %d\n", target, ip, port, s.TotalSuccessfulProbes)
		fmt.Fprintf(w, "tcping_probes_total{target=%q,ip=%q,port=\"%d\",status=\"failure\"} %d\n\n", target, ip, port, s.TotalUnsuccessfulProbes)

		fmt.Fprintf(w, "# HELP tcping_uptime_seconds Total accumulated uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE tcping_uptime_seconds counter\n")
		fmt.Fprintf(w, "tcping_uptime_seconds{target=%q,ip=%q,port=\"%d\"} %f\n\n", target, ip, port, s.TotalUptime.Seconds())

		fmt.Fprintf(w, "# HELP tcping_downtime_seconds Total accumulated downtime in seconds\n")
		fmt.Fprintf(w, "# TYPE tcping_downtime_seconds counter\n")
		fmt.Fprintf(w, "tcping_downtime_seconds{target=%q,ip=%q,port=\"%d\"} %f\n", target, ip, port, s.TotalDowntime.Seconds())
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		_ = srv.ListenAndServe()
	}()

	// #nosec G118 -- graceful shutdown listener watching application lifecycle context
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	return srv
}

// StartMultiMetricsServer starts an embedded Prometheus metrics exporter for multiple target statistics.
func StartMultiMetricsServer(ctx context.Context, addr string, statsList []*stats.Statistics) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		fmt.Fprintf(w, "# HELP netping_up Target reachability (1 = up, 0 = down)\n")
		fmt.Fprintf(w, "# TYPE netping_up gauge\n")
		for _, s := range statsList {
			s.Mu.RLock()
			target := s.Hostname
			ip := s.IPStr()
			port := s.Port
			up := 0
			if !s.DestWasDown && s.TotalSuccessfulProbes > 0 {
				up = 1
			}
			s.Mu.RUnlock()
			fmt.Fprintf(w, "netping_up{target=%q,ip=%q,port=\"%d\"} %d\n", target, ip, port, up)
		}
		fmt.Fprintln(w)

		fmt.Fprintf(w, "# HELP netping_probe_duration_seconds Latest round-trip latency in seconds\n")
		fmt.Fprintf(w, "# TYPE netping_probe_duration_seconds gauge\n")
		for _, s := range statsList {
			s.Mu.RLock()
			target := s.Hostname
			ip := s.IPStr()
			port := s.Port
			lat := float64(s.LatestRTT) / 1000.0
			s.Mu.RUnlock()
			fmt.Fprintf(w, "netping_probe_duration_seconds{target=%q,ip=%q,port=\"%d\"} %f\n", target, ip, port, lat)
		}
		fmt.Fprintln(w)

		fmt.Fprintf(w, "# HELP netping_packet_loss_ratio Packet loss ratio between 0 and 1\n")
		fmt.Fprintf(w, "# TYPE netping_packet_loss_ratio gauge\n")
		for _, s := range statsList {
			s.Mu.RLock()
			target := s.Hostname
			ip := s.IPStr()
			port := s.Port
			total := s.TotalSuccessfulProbes + s.TotalUnsuccessfulProbes
			var lossRatio float32
			if total > 0 {
				lossRatio = float32(s.TotalUnsuccessfulProbes) / float32(total)
			}
			s.Mu.RUnlock()
			fmt.Fprintf(w, "netping_packet_loss_ratio{target=%q,ip=%q,port=\"%d\"} %f\n", target, ip, port, lossRatio)
		}
		fmt.Fprintln(w)

		fmt.Fprintf(w, "# HELP netping_probes_total Total number of probes sent\n")
		fmt.Fprintf(w, "# TYPE netping_probes_total counter\n")
		for _, s := range statsList {
			s.Mu.RLock()
			target := s.Hostname
			ip := s.IPStr()
			port := s.Port
			succ := s.TotalSuccessfulProbes
			fail := s.TotalUnsuccessfulProbes
			s.Mu.RUnlock()
			fmt.Fprintf(w, "netping_probes_total{target=%q,ip=%q,port=\"%d\",status=\"success\"} %d\n", target, ip, port, succ)
			fmt.Fprintf(w, "netping_probes_total{target=%q,ip=%q,port=\"%d\",status=\"failure\"} %d\n", target, ip, port, fail)
		}
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		_ = srv.ListenAndServe()
	}()

	// #nosec G118 -- graceful shutdown listener watching application lifecycle context
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	return srv
}
