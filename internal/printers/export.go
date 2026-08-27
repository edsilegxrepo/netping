package printers

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/edsilegx/netping/pkg/stats"
	_ "modernc.org/sqlite"
)

var (
	ansiRegex      = regexp.MustCompile(`[\x1b\x9b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><~]`)
	escapeReplacer = strings.NewReplacer(
		"│", " | ",
		"─", "-",
		"┌", "+",
		"┐", "+",
		"└", "+",
		"┘", "+",
		"├", "+",
		"┤", "+",
		"┬", "+",
		"┴", "+",
		"┼", "+",
		"●", "*",
		"×", "x",
		"▶", ">",
		"…", "...",
		"\t", " ",
		"\r", " ",
		"\n", " ",
	)
)

func sanitizeExportField(str string) string {
	if str == "" {
		return ""
	}
	// Fast-path bypass for clean strings (avoids regex and replacer allocations)
	if !strings.ContainsAny(str, "\x1b\u009b│─┌┐└┘├┤┬┴┼●×▶…\t\r\n") {
		return str
	}
	cleaned := ansi.Strip(str)
	cleaned = ansiRegex.ReplaceAllString(cleaned, "")
	cleaned = escapeReplacer.Replace(cleaned)
	return strings.TrimSpace(cleaned)
}

type ExportFormat int

const (
	FormatJSON ExportFormat = iota
	FormatPrettyJSON
	FormatCSV
	FormatTSV
	FormatSQLite3
	FormatPlainText
)

var FormatNames = []string{
	"JSON (.json)",
	"Pretty JSON (.json)",
	"CSV (.csv)",
	"TSV (.tsv)",
	"SQLite3 Database (.db)",
	"Plain Text Report (.txt)",
}

var FormatExtensions = []string{
	".json",
	".json",
	".csv",
	".tsv",
	".db",
	".txt",
}

// SingleProbeExportRecord captures an individual probe event as a clean, structured object.
type SingleProbeExportRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	Seq         uint      `json:"seq"`
	Target      string    `json:"target"`
	Port        uint16    `json:"port,omitempty"`
	Protocol    string    `json:"protocol"`
	IP          string    `json:"ip"`
	IsSuccess   bool      `json:"isSuccess"`
	RTTMs       float64   `json:"rttMs"`
	DNSTimeMs   float64   `json:"dnsTimeMs"`
	TCPTimeMs   float64   `json:"tcpTimeMs"`
	TLSTimeMs   float64   `json:"tlsTimeMs"`
	TTFBMs      float64   `json:"ttfbMs"`
	HTTPStatus  int       `json:"httpStatus,omitempty"`
	Diagnostics string    `json:"diagnostics,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// SingleTargetExportData captures the complete state of a single-target probe run.
type SingleTargetExportData struct {
	ExportTimestamp time.Time                 `json:"exportTimestamp"`
	Target          string                    `json:"target"`
	Port            uint16                    `json:"port"`
	Protocol        string                    `json:"protocol"`
	IP              string                    `json:"ip"`
	Duration        string                    `json:"duration"`
	TotalProbes     uint                      `json:"totalProbes"`
	Successful      uint                      `json:"successfulProbes"`
	Failed          uint                      `json:"failedProbes"`
	LossPercent     float64                   `json:"lossPercent"`
	MinRTTMs        float32                   `json:"minRttMs"`
	AvgRTTMs        float32                   `json:"avgRttMs"`
	MaxRTTMs        float32                   `json:"maxRttMs"`
	Probes          []SingleProbeExportRecord `json:"probes"`
}

// FleetTargetExportSummary captures summary metrics for one fleet target.
type FleetTargetExportSummary struct {
	Target      string  `json:"target"`
	Protocol    string  `json:"protocol"`
	IP          string  `json:"ip"`
	Sent        uint    `json:"sent"`
	Recv        uint    `json:"recv"`
	LossPercent float64 `json:"lossPercent"`
	LastRTTMs   float64 `json:"lastRttMs"`
	AvgRTTMs    float32 `json:"avgRttMs"`
	MaxRTTMs    float32 `json:"maxRttMs"`
}

// FleetExportData captures the complete state of a multi-target probe run with decomposed probe objects.
type FleetExportData struct {
	ExportTimestamp time.Time                  `json:"exportTimestamp"`
	Duration        string                     `json:"duration"`
	TargetCount     int                        `json:"targetCount"`
	Targets         []FleetTargetExportSummary `json:"targets"`
	Probes          []SingleProbeExportRecord  `json:"probes"`
}

// GenerateDefaultExportPath produces a timestamped file path for a selected format.
func GenerateDefaultExportPath(isFleet bool, format ExportFormat) string {
	ts := time.Now().Format("20060102_150405")
	ext := FormatExtensions[format]
	prefix := "netping_single_"
	if isFleet {
		prefix = "netping_fleet_"
	}
	return fmt.Sprintf("./%s%s%s", prefix, ts, ext)
}

// SaveFileAsync saves data to disk asynchronously in an isolated background process on Windows.
func SaveFileAsync(filePath string, data []byte) error {
	cleanPath := filepath.Clean(filePath)
	exe, err := os.Executable()
	if err != nil || strings.HasSuffix(exe, ".test") || strings.HasSuffix(exe, ".test.exe") {
		dir := filepath.Dir(cleanPath)
		if dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0o750)
		}
		return os.WriteFile(cleanPath, data, 0o600)
	}

	// #nosec G204 -- invokes self-executable for isolated background disk write
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- self-executable path from os.Executable() used for background save
	cmd := exec.Command(exe, "--internal-async-save", cleanPath)
	cmd.Stdin = bytes.NewReader(data)
	setDetachedProcess(cmd)
	return cmd.Start()
}

// ExportSingleTarget exports single-target probe metrics and history to file, sanitizing all ANSI and box-drawing characters.
func ExportSingleTarget(target string, port uint16, protocol string, st *stats.Statistics, history []SingleProbeExportRecord, format ExportFormat, filePath string) error {
	if format == FormatSQLite3 {
		return exportSingleTargetSQLite(target, port, protocol, st, history, filePath)
	}

	var buf bytes.Buffer
	if err := ExportSingleTargetToWriter(&buf, target, port, protocol, st, history, format); err != nil {
		return err
	}
	return SaveFileAsync(filePath, buf.Bytes())
}

func exportSingleTargetSQLite(target string, port uint16, protocol string, st *stats.Statistics, history []SingleProbeExportRecord, filePath string) error {
	cleanTarget := sanitizeExportField(target)
	cleanProtocol := sanitizeExportField(protocol)

	var total, succ, fail uint
	var loss float64
	var rttRes stats.RTTResult
	var duration, ipStr string

	if st != nil {
		snap := st.Snapshot()
		total = snap.TotalSent
		succ = snap.TotalSuccess
		fail = snap.TotalFailed
		loss = snap.PacketLoss
		rttRes = stats.RTTResult{
			Min:     snap.MinRTT,
			Average: snap.AvgRTT,
			Max:     snap.MaxRTT,
			Jitter:  snap.Jitter,
		}
		duration = snap.UptimeDuration
		ipStr = sanitizeExportField(snap.IP)
	}

	_ = os.Remove(filePath)
	db, err := sql.Open("sqlite", filePath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	_, _ = db.Exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")

	createTable := `
	CREATE TABLE summary (
		target TEXT,
		port INTEGER,
		protocol TEXT,
		ip TEXT,
		total_probes INTEGER,
		successful_probes INTEGER,
		failed_probes INTEGER,
		loss_percent REAL,
		min_rtt_ms REAL,
		avg_rtt_ms REAL,
		max_rtt_ms REAL,
		duration TEXT,
		exported_at TEXT
	);
	CREATE TABLE probes (
		timestamp TEXT,
		seq INTEGER,
		target TEXT,
		port INTEGER,
		protocol TEXT,
		ip TEXT,
		is_success INTEGER,
		rtt_ms REAL,
		dns_ms REAL,
		tcp_ms REAL,
		tls_ms REAL,
		ttfb_ms REAL,
		http_status INTEGER,
		diagnostics TEXT,
		error TEXT
	);`
	if _, err := db.Exec(createTable); err != nil {
		return err
	}

	_, _ = db.Exec(`INSERT INTO summary VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cleanTarget, port, cleanProtocol, ipStr, total, succ, fail, loss, rttRes.Min, rttRes.Average, rttRes.Max, duration, time.Now().Format(time.RFC3339))

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT INTO probes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, p := range history {
		isSucc := 0
		if p.IsSuccess {
			isSucc = 1
		}
		_, _ = stmt.Exec(p.Timestamp.Format(time.RFC3339), p.Seq, cleanTarget, port, cleanProtocol, p.IP, isSucc, p.RTTMs, p.DNSTimeMs, p.TCPTimeMs, p.TLSTimeMs, p.TTFBMs, p.HTTPStatus, sanitizeExportField(p.Diagnostics), sanitizeExportField(p.Error))
	}
	return tx.Commit()
}

// ExportSingleTargetToWriter streams single-target probe metrics and history directly to an io.Writer.
func ExportSingleTargetToWriter(w io.Writer, target string, port uint16, protocol string, st *stats.Statistics, history []SingleProbeExportRecord, format ExportFormat) error {
	cleanTarget := sanitizeExportField(target)
	cleanProtocol := sanitizeExportField(protocol)

	var total, succ, fail uint
	var loss float64
	var rttRes stats.RTTResult
	var duration, ipStr string

	if st != nil {
		snap := st.Snapshot()
		total = snap.TotalSent
		succ = snap.TotalSuccess
		fail = snap.TotalFailed
		loss = snap.PacketLoss
		rttRes = stats.RTTResult{
			Min:     snap.MinRTT,
			Average: snap.AvgRTT,
			Max:     snap.MaxRTT,
			Jitter:  snap.Jitter,
		}
		duration = snap.UptimeDuration
		ipStr = sanitizeExportField(snap.IP)
	}

	data := SingleTargetExportData{
		ExportTimestamp: time.Now(),
		Target:          cleanTarget,
		Port:            port,
		Protocol:        cleanProtocol,
		IP:              ipStr,
		Duration:        duration,
		TotalProbes:     total,
		Successful:      succ,
		Failed:          fail,
		LossPercent:     loss,
		MinRTTMs:        rttRes.Min,
		AvgRTTMs:        rttRes.Average,
		MaxRTTMs:        rttRes.Max,
		Probes:          history,
	}

	switch format {
	case FormatJSON:
		return json.NewEncoder(w).Encode(data)

	case FormatPrettyJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(data)

	case FormatCSV, FormatTSV:
		delimiter := ','
		if format == FormatTSV {
			delimiter = '\t'
		}
		cw := csv.NewWriter(w)
		cw.Comma = delimiter
		defer cw.Flush()

		_ = cw.Write([]string{"Timestamp", "Seq", "Target", "Port", "Protocol", "IP", "Status", "RTT_ms", "DNS_ms", "TCP_ms", "TLS_ms", "TTFB_ms", "HTTP_Status", "Diagnostics", "Error"})
		for _, p := range history {
			status := "SUCCESS"
			if !p.IsSuccess {
				status = "FAILED"
			}
			_ = cw.Write([]string{
				p.Timestamp.Format(time.RFC3339),
				fmt.Sprintf("%d", p.Seq),
				cleanTarget,
				fmt.Sprintf("%d", port),
				cleanProtocol,
				p.IP,
				status,
				fmt.Sprintf("%.2f", p.RTTMs),
				fmt.Sprintf("%.2f", p.DNSTimeMs),
				fmt.Sprintf("%.2f", p.TCPTimeMs),
				fmt.Sprintf("%.2f", p.TLSTimeMs),
				fmt.Sprintf("%.2f", p.TTFBMs),
				fmt.Sprintf("%d", p.HTTPStatus),
				p.Diagnostics,
				p.Error,
			})
		}
		cw.Flush()
		return cw.Error()

	case FormatPlainText:
		bw := bufio.NewWriter(w)
		defer func() { _ = bw.Flush() }()
		_, _ = bw.WriteString("================================================================================\n")
		_, _ = bw.WriteString("                           NETPING PROBE REPORT                                 \n")
		_, _ = bw.WriteString("================================================================================\n\n")
		_, _ = fmt.Fprintf(bw, "Target:         %s:%d\n", cleanTarget, port)
		_, _ = fmt.Fprintf(bw, "Protocol:       %s\n", cleanProtocol)
		_, _ = fmt.Fprintf(bw, "IP:             %s\n", ipStr)
		_, _ = fmt.Fprintf(bw, "Exported At:    %s\n", time.Now().Format(time.RFC1123))
		_, _ = fmt.Fprintf(bw, "Total Duration: %s\n\n", duration)

		_, _ = bw.WriteString("SUMMARY STATISTICS:\n")
		_, _ = fmt.Fprintf(bw, "  Probes Sent:     %d\n", total)
		_, _ = fmt.Fprintf(bw, "  Probes Recv:     %d\n", succ)
		_, _ = fmt.Fprintf(bw, "  Probes Failed:   %d\n", fail)
		_, _ = fmt.Fprintf(bw, "  Packet Loss:     %.1f%%\n", loss)
		_, _ = fmt.Fprintf(bw, "  Min Latency:     %.2f ms\n", rttRes.Min)
		_, _ = fmt.Fprintf(bw, "  Avg Latency:     %.2f ms\n", rttRes.Average)
		_, _ = fmt.Fprintf(bw, "  Max Latency:     %.2f ms\n\n", rttRes.Max)

		_, _ = bw.WriteString("PROBE EVENT HISTORY:\n")
		_, _ = fmt.Fprintf(bw, "%-20s %-6s %-10s %-10s %-10s %-16s %s\n", "TIMESTAMP", "SEQ", "STATUS", "RTT(ms)", "TTFB(ms)", "IP", "DETAILS")
		_, _ = bw.WriteString(strings.Repeat("-", 95) + "\n")
		for _, p := range history {
			status := "SUCCESS"
			if !p.IsSuccess {
				status = "FAILED"
			}
			details := p.Diagnostics
			if p.Error != "" {
				details = "Error: " + p.Error
			}
			_, _ = fmt.Fprintf(bw, "%-20s %-6d %-10s %-10.2f %-10.2f %-16s %s\n",
				p.Timestamp.Format("2006-01-02 15:04:05"),
				p.Seq,
				status,
				p.RTTMs,
				p.TTFBMs,
				p.IP,
				details,
			)
		}
		return bw.Flush()
	}
	return nil
}

// ExportMultiTarget exports multi-target fleet metrics and structured probe events to file, sanitizing all ANSI and box-drawing characters.
func ExportMultiTarget(targets []FleetTarget, startTime time.Time, history []SingleProbeExportRecord, format ExportFormat, filePath string) error {
	if format == FormatSQLite3 {
		return exportMultiTargetSQLite(targets, startTime, history, filePath)
	}

	var buf bytes.Buffer
	if err := ExportMultiTargetToWriter(&buf, targets, startTime, history, format); err != nil {
		return err
	}
	return SaveFileAsync(filePath, buf.Bytes())
}

func exportMultiTargetSQLite(targets []FleetTarget, startTime time.Time, history []SingleProbeExportRecord, filePath string) error {
	var summaries []FleetTargetExportSummary
	for _, t := range targets {
		var total, succ uint
		var loss float64
		var latest float32
		var rttRes stats.RTTResult
		var ipStr string

		if t.Stats != nil {
			snap := t.Stats.Snapshot()
			total = snap.TotalSent
			succ = snap.TotalSuccess
			loss = snap.PacketLoss
			latest = snap.LatestRTT
			rttRes = stats.RTTResult{
				Min:     snap.MinRTT,
				Average: snap.AvgRTT,
				Max:     snap.MaxRTT,
				Jitter:  snap.Jitter,
			}
			ipStr = sanitizeExportField(snap.IP)
		}

		protoDisplay := strings.ToUpper(t.Protocol)
		if protoDisplay == "" {
			protoDisplay = "TCP"
		}

		summaries = append(summaries, FleetTargetExportSummary{
			Target:      sanitizeExportField(t.Target),
			Protocol:    sanitizeExportField(protoDisplay),
			IP:          ipStr,
			Sent:        total,
			Recv:        succ,
			LossPercent: loss,
			LastRTTMs:   float64(latest),
			AvgRTTMs:    rttRes.Average,
			MaxRTTMs:    rttRes.Max,
		})
	}

	_ = os.Remove(filePath)
	db, err := sql.Open("sqlite", filePath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	_, _ = db.Exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")

	createTable := `
	CREATE TABLE fleet_summary (
		target TEXT,
		protocol TEXT,
		ip TEXT,
		sent INTEGER,
		recv INTEGER,
		loss_percent REAL,
		last_rtt_ms REAL,
		avg_rtt_ms REAL,
		max_rtt_ms REAL,
		duration TEXT,
		exported_at TEXT
	);
	CREATE TABLE probes (
		timestamp TEXT,
		seq INTEGER,
		target TEXT,
		protocol TEXT,
		ip TEXT,
		is_success INTEGER,
		rtt_ms REAL,
		dns_ms REAL,
		tcp_ms REAL,
		tls_ms REAL,
		ttfb_ms REAL,
		http_status INTEGER,
		diagnostics TEXT,
		error TEXT
	);`
	if _, err := db.Exec(createTable); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT INTO fleet_summary VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	elapsed := time.Since(startTime).Round(time.Second).String()
	for _, s := range summaries {
		_, _ = stmt.Exec(s.Target, s.Protocol, s.IP, s.Sent, s.Recv, s.LossPercent, s.LastRTTMs, s.AvgRTTMs, s.MaxRTTMs, elapsed, time.Now().Format(time.RFC3339))
	}

	probeStmt, err := tx.Prepare(`INSERT INTO probes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err == nil {
		defer func() { _ = probeStmt.Close() }()
		for _, p := range history {
			isSucc := 0
			if p.IsSuccess {
				isSucc = 1
			}
			_, _ = probeStmt.Exec(p.Timestamp.Format(time.RFC3339), p.Seq, sanitizeExportField(p.Target), sanitizeExportField(p.Protocol), sanitizeExportField(p.IP), isSucc, p.RTTMs, p.DNSTimeMs, p.TCPTimeMs, p.TLSTimeMs, p.TTFBMs, p.HTTPStatus, sanitizeExportField(p.Diagnostics), sanitizeExportField(p.Error))
		}
	}
	return tx.Commit()
}

// ExportMultiTargetToWriter streams multi-target fleet metrics and structured probe events directly to an io.Writer.
func ExportMultiTargetToWriter(w io.Writer, targets []FleetTarget, startTime time.Time, history []SingleProbeExportRecord, format ExportFormat) error {
	var summaries []FleetTargetExportSummary
	for _, t := range targets {
		var total, succ uint
		var loss float64
		var latest float32
		var rttRes stats.RTTResult
		var ipStr string

		if t.Stats != nil {
			snap := t.Stats.Snapshot()
			total = snap.TotalSent
			succ = snap.TotalSuccess
			loss = snap.PacketLoss
			latest = snap.LatestRTT
			rttRes = stats.RTTResult{
				Min:     snap.MinRTT,
				Average: snap.AvgRTT,
				Max:     snap.MaxRTT,
				Jitter:  snap.Jitter,
			}
			ipStr = sanitizeExportField(snap.IP)
		}

		protoDisplay := strings.ToUpper(t.Protocol)
		if protoDisplay == "" {
			protoDisplay = "TCP"
		}

		summaries = append(summaries, FleetTargetExportSummary{
			Target:      sanitizeExportField(t.Target),
			Protocol:    sanitizeExportField(protoDisplay),
			IP:          ipStr,
			Sent:        total,
			Recv:        succ,
			LossPercent: loss,
			LastRTTMs:   float64(latest),
			AvgRTTMs:    rttRes.Average,
			MaxRTTMs:    rttRes.Max,
		})
	}

	elapsed := time.Since(startTime).Round(time.Second).String()
	data := FleetExportData{
		ExportTimestamp: time.Now(),
		Duration:        elapsed,
		TargetCount:     len(targets),
		Targets:         summaries,
		Probes:          history,
	}

	switch format {
	case FormatJSON:
		return json.NewEncoder(w).Encode(data)

	case FormatPrettyJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(data)

	case FormatCSV, FormatTSV:
		delimiter := ','
		if format == FormatTSV {
			delimiter = '\t'
		}
		cw := csv.NewWriter(w)
		cw.Comma = delimiter
		defer cw.Flush()

		_ = cw.Write([]string{"# FLEET TARGET SUMMARY"})
		_ = cw.Write([]string{"Target", "Protocol", "IP", "Sent", "Recv", "LossPercent", "LastRTTMs", "AvgRTTMs", "MaxRTTMs"})
		for _, s := range summaries {
			_ = cw.Write([]string{
				s.Target,
				s.Protocol,
				s.IP,
				fmt.Sprintf("%d", s.Sent),
				fmt.Sprintf("%d", s.Recv),
				fmt.Sprintf("%.1f", s.LossPercent),
				fmt.Sprintf("%.2f", s.LastRTTMs),
				fmt.Sprintf("%.2f", s.AvgRTTMs),
				fmt.Sprintf("%.2f", s.MaxRTTMs),
			})
		}

		if len(history) > 0 {
			_ = cw.Write([]string{})
			_ = cw.Write([]string{"# PROBE EVENTS"})
			_ = cw.Write([]string{"Timestamp", "Seq", "Target", "Protocol", "IP", "Status", "RTT_ms", "DNS_ms", "TCP_ms", "TLS_ms", "TTFB_ms", "HTTP_Status", "Diagnostics", "Error"})
			for _, p := range history {
				status := "SUCCESS"
				if !p.IsSuccess {
					status = "FAILED"
				}
				_ = cw.Write([]string{
					p.Timestamp.Format(time.RFC3339),
					fmt.Sprintf("%d", p.Seq),
					p.Target,
					p.Protocol,
					p.IP,
					status,
					fmt.Sprintf("%.2f", p.RTTMs),
					fmt.Sprintf("%.2f", p.DNSTimeMs),
					fmt.Sprintf("%.2f", p.TCPTimeMs),
					fmt.Sprintf("%.2f", p.TLSTimeMs),
					fmt.Sprintf("%.2f", p.TTFBMs),
					fmt.Sprintf("%d", p.HTTPStatus),
					p.Diagnostics,
					p.Error,
				})
			}
		}
		cw.Flush()
		return cw.Error()

	case FormatPlainText:
		bw := bufio.NewWriter(w)
		defer func() { _ = bw.Flush() }()
		_, _ = bw.WriteString("================================================================================\n")
		_, _ = bw.WriteString("                        NETPING FLEET PROBE REPORT                              \n")
		_, _ = bw.WriteString("================================================================================\n\n")
		_, _ = fmt.Fprintf(bw, "Exported At:    %s\n", time.Now().Format(time.RFC1123))
		_, _ = fmt.Fprintf(bw, "Total Duration: %s\n", elapsed)
		_, _ = fmt.Fprintf(bw, "Total Targets:  %d\n\n", len(targets))

		_, _ = bw.WriteString("FLEET TARGET SUMMARY:\n")
		_, _ = fmt.Fprintf(bw, "%-28s %-10s %-16s %-6s %-6s %-8s %-10s %-10s %-10s\n",
			"TARGET", "PROTOCOL", "IP", "SENT", "RECV", "LOSS%", "LAST(ms)", "AVG(ms)", "MAX(ms)")
		_, _ = bw.WriteString(strings.Repeat("-", 110) + "\n")
		for _, s := range summaries {
			_, _ = fmt.Fprintf(bw, "%-28s %-10s %-16s %-6d %-6d %-8s %-10.2f %-10.2f %-10.2f\n",
				s.Target, s.Protocol, s.IP, s.Sent, s.Recv, fmt.Sprintf("%.1f%%", s.LossPercent), s.LastRTTMs, s.AvgRTTMs, s.MaxRTTMs)
		}

		if len(history) > 0 {
			_, _ = bw.WriteString("\nPROBE EVENT HISTORY:\n")
			_, _ = fmt.Fprintf(bw, "%-20s %-6s %-24s %-8s %-16s %-10s %-10s %-10s %s\n",
				"TIMESTAMP", "SEQ", "TARGET", "PROTO", "IP", "STATUS", "RTT(ms)", "TTFB(ms)", "DETAILS")
			_, _ = bw.WriteString(strings.Repeat("-", 125) + "\n")
			for _, p := range history {
				status := "SUCCESS"
				if !p.IsSuccess {
					status = "FAILED"
				}
				details := p.Diagnostics
				if p.Error != "" {
					details = "Error: " + p.Error
				}
				_, _ = fmt.Fprintf(bw, "%-20s %-6d %-24s %-8s %-16s %-10s %-10.2f %-10.2f %s\n",
					p.Timestamp.Format("2006-01-02 15:04:05"),
					p.Seq,
					p.Target,
					p.Protocol,
					p.IP,
					status,
					p.RTTMs,
					p.TTFBMs,
					details,
				)
			}
		}
		return bw.Flush()
	}
	return nil
}
