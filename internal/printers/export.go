package printers

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
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
	Protocol    string    `json:"protocol"`
	IP          string    `json:"ip"`
	IsSuccess   bool      `json:"isSuccess"`
	RTTMs       float64   `json:"rttMs"`
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

// ExportSingleTarget exports single-target probe metrics and history to file, sanitizing all ANSI and box-drawing characters.
func ExportSingleTarget(target string, port uint16, protocol string, st *stats.Statistics, history []SingleProbeExportRecord, format ExportFormat, filePath string) error {
	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	cleanTarget := sanitizeExportField(target)
	cleanProtocol := sanitizeExportField(protocol)

	st.Mu.RLock()
	total := st.TotalSuccessfulProbes + st.TotalUnsuccessfulProbes
	succ := st.TotalSuccessfulProbes
	fail := st.TotalUnsuccessfulProbes
	loss := float64(0)
	if total > 0 {
		loss = float64(fail) / float64(total) * 100.0
	}
	rttRes := calcMinAvgMaxRttTime(st.RTT)
	duration := ""
	if !st.StartTime.IsZero() {
		duration = time.Since(st.StartTime).Round(time.Second).String()
	}
	ipStr := sanitizeExportField(st.IP.String())
	st.Mu.RUnlock()

	cleanHistory := make([]SingleProbeExportRecord, len(history))
	for i, p := range history {
		cleanHistory[i] = SingleProbeExportRecord{
			Timestamp:   p.Timestamp,
			Seq:         p.Seq,
			Target:      sanitizeExportField(p.Target),
			Protocol:    sanitizeExportField(p.Protocol),
			IP:          sanitizeExportField(p.IP),
			IsSuccess:   p.IsSuccess,
			RTTMs:       p.RTTMs,
			Diagnostics: sanitizeExportField(p.Diagnostics),
			Error:       sanitizeExportField(p.Error),
		}
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
		Probes:          cleanHistory,
	}

	switch format {
	case FormatJSON:
		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		return os.WriteFile(filePath, b, 0644)

	case FormatPrettyJSON:
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filePath, b, 0644)

	case FormatCSV, FormatTSV:
		delimiter := ','
		if format == FormatTSV {
			delimiter = '\t'
		}
		f, err := os.Create(filePath)
		if err != nil {
			return err
		}
		defer f.Close()

		w := csv.NewWriter(f)
		w.Comma = delimiter
		defer w.Flush()

		_ = w.Write([]string{"Timestamp", "Seq", "Target", "Port", "Protocol", "IP", "Status", "RTT_ms", "Diagnostics", "Error"})
		for _, p := range cleanHistory {
			status := "SUCCESS"
			if !p.IsSuccess {
				status = "FAILED"
			}
			_ = w.Write([]string{
				p.Timestamp.Format(time.RFC3339),
				fmt.Sprintf("%d", p.Seq),
				cleanTarget,
				fmt.Sprintf("%d", port),
				cleanProtocol,
				p.IP,
				status,
				fmt.Sprintf("%.2f", p.RTTMs),
				p.Diagnostics,
				p.Error,
			})
		}
		w.Flush()
		return nil

	case FormatSQLite3:
		_ = os.Remove(filePath)
		db, err := sql.Open("sqlite", filePath)
		if err != nil {
			return err
		}
		defer db.Close()

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
		stmt, err := tx.Prepare(`INSERT INTO probes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, p := range cleanHistory {
			isSucc := 0
			if p.IsSuccess {
				isSucc = 1
			}
			_, _ = stmt.Exec(p.Timestamp.Format(time.RFC3339), p.Seq, cleanTarget, port, cleanProtocol, p.IP, isSucc, p.RTTMs, p.Diagnostics, p.Error)
		}
		return tx.Commit()

	case FormatPlainText:
		var sb strings.Builder
		sb.WriteString("================================================================================\n")
		sb.WriteString("                           NETPING PROBE REPORT                                 \n")
		sb.WriteString("================================================================================\n\n")
		sb.WriteString(fmt.Sprintf("Target:         %s:%d\n", cleanTarget, port))
		sb.WriteString(fmt.Sprintf("Protocol:       %s\n", cleanProtocol))
		sb.WriteString(fmt.Sprintf("IP:             %s\n", ipStr))
		sb.WriteString(fmt.Sprintf("Exported At:    %s\n", time.Now().Format(time.RFC1123)))
		sb.WriteString(fmt.Sprintf("Total Duration: %s\n\n", duration))

		sb.WriteString("SUMMARY STATISTICS:\n")
		sb.WriteString(fmt.Sprintf("  Probes Sent:     %d\n", total))
		sb.WriteString(fmt.Sprintf("  Probes Recv:     %d\n", succ))
		sb.WriteString(fmt.Sprintf("  Probes Failed:   %d\n", fail))
		sb.WriteString(fmt.Sprintf("  Packet Loss:     %.1f%%\n", loss))
		sb.WriteString(fmt.Sprintf("  Min Latency:     %.2f ms\n", rttRes.Min))
		sb.WriteString(fmt.Sprintf("  Avg Latency:     %.2f ms\n", rttRes.Average))
		sb.WriteString(fmt.Sprintf("  Max Latency:     %.2f ms\n\n", rttRes.Max))

		sb.WriteString("PROBE EVENT HISTORY:\n")
		sb.WriteString(fmt.Sprintf("%-20s %-6s %-10s %-12s %-16s %s\n", "TIMESTAMP", "SEQ", "STATUS", "RTT (ms)", "IP", "DETAILS"))
		sb.WriteString(strings.Repeat("-", 80) + "\n")
		for _, p := range cleanHistory {
			status := "SUCCESS"
			if !p.IsSuccess {
				status = "FAILED"
			}
			details := p.Diagnostics
			if p.Error != "" {
				details = "Error: " + p.Error
			}
			sb.WriteString(fmt.Sprintf("%-20s %-6d %-10s %-12.2f %-16s %s\n",
				p.Timestamp.Format("2006-01-02 15:04:05"),
				p.Seq,
				status,
				p.RTTMs,
				p.IP,
				details,
			))
		}
		return os.WriteFile(filePath, []byte(sb.String()), 0644)
	}

	return nil
}

// ExportMultiTarget exports multi-target fleet metrics and structured probe events to file, sanitizing all ANSI and box-drawing characters.
func ExportMultiTarget(targets []FleetTarget, startTime time.Time, history []SingleProbeExportRecord, format ExportFormat, filePath string) error {
	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	var summaries []FleetTargetExportSummary
	for _, t := range targets {
		t.Stats.Mu.RLock()
		total := t.Stats.TotalSuccessfulProbes + t.Stats.TotalUnsuccessfulProbes
		succ := t.Stats.TotalSuccessfulProbes
		loss := float64(0)
		if total > 0 {
			loss = float64(t.Stats.TotalUnsuccessfulProbes) / float64(total) * 100.0
		}
		latest := t.Stats.LatestRTT
		rttRes := calcMinAvgMaxRttTime(t.Stats.RTT)
		ipStr := sanitizeExportField(t.Stats.IP.String())
		t.Stats.Mu.RUnlock()

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

	cleanHistory := make([]SingleProbeExportRecord, len(history))
	for i, p := range history {
		cleanHistory[i] = SingleProbeExportRecord{
			Timestamp:   p.Timestamp,
			Seq:         p.Seq,
			Target:      sanitizeExportField(p.Target),
			Protocol:    sanitizeExportField(p.Protocol),
			IP:          sanitizeExportField(p.IP),
			IsSuccess:   p.IsSuccess,
			RTTMs:       p.RTTMs,
			Diagnostics: sanitizeExportField(p.Diagnostics),
			Error:       sanitizeExportField(p.Error),
		}
	}

	elapsed := time.Since(startTime).Round(time.Second).String()
	data := FleetExportData{
		ExportTimestamp: time.Now(),
		Duration:        elapsed,
		TargetCount:     len(targets),
		Targets:         summaries,
		Probes:          cleanHistory,
	}

	switch format {
	case FormatJSON:
		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		return os.WriteFile(filePath, b, 0644)

	case FormatPrettyJSON:
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filePath, b, 0644)

	case FormatCSV, FormatTSV:
		delimiter := ','
		if format == FormatTSV {
			delimiter = '\t'
		}
		f, err := os.Create(filePath)
		if err != nil {
			return err
		}
		defer f.Close()

		w := csv.NewWriter(f)
		w.Comma = delimiter
		defer w.Flush()

		// Write Section 1: Fleet Targets Summary
		_ = w.Write([]string{"# FLEET TARGET SUMMARY"})
		_ = w.Write([]string{"Target", "Protocol", "IP", "Sent", "Recv", "LossPercent", "LastRTTMs", "AvgRTTMs", "MaxRTTMs"})
		for _, s := range summaries {
			_ = w.Write([]string{
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

		// Write Section 2: Probes History
		if len(cleanHistory) > 0 {
			_ = w.Write([]string{})
			_ = w.Write([]string{"# PROBE EVENTS"})
			_ = w.Write([]string{"Timestamp", "Seq", "Target", "Protocol", "IP", "Status", "RTT_ms", "Diagnostics", "Error"})
			for _, p := range cleanHistory {
				status := "SUCCESS"
				if !p.IsSuccess {
					status = "FAILED"
				}
				_ = w.Write([]string{
					p.Timestamp.Format(time.RFC3339),
					fmt.Sprintf("%d", p.Seq),
					p.Target,
					p.Protocol,
					p.IP,
					status,
					fmt.Sprintf("%.2f", p.RTTMs),
					p.Diagnostics,
					p.Error,
				})
			}
		}
		w.Flush()
		return nil

	case FormatSQLite3:
		_ = os.Remove(filePath)
		db, err := sql.Open("sqlite", filePath)
		if err != nil {
			return err
		}
		defer db.Close()

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
		stmt, err := tx.Prepare(`INSERT INTO fleet_summary VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, s := range summaries {
			_, _ = stmt.Exec(s.Target, s.Protocol, s.IP, s.Sent, s.Recv, s.LossPercent, s.LastRTTMs, s.AvgRTTMs, s.MaxRTTMs, elapsed, time.Now().Format(time.RFC3339))
		}

		probeStmt, err := tx.Prepare(`INSERT INTO probes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err == nil {
			defer probeStmt.Close()
			for _, p := range cleanHistory {
				isSucc := 0
				if p.IsSuccess {
					isSucc = 1
				}
				_, _ = probeStmt.Exec(p.Timestamp.Format(time.RFC3339), p.Seq, p.Target, p.Protocol, p.IP, isSucc, p.RTTMs, p.Diagnostics, p.Error)
			}
		}
		return tx.Commit()

	case FormatPlainText:
		var sb strings.Builder
		sb.WriteString("================================================================================\n")
		sb.WriteString("                        NETPING FLEET PROBE REPORT                              \n")
		sb.WriteString("================================================================================\n\n")
		sb.WriteString(fmt.Sprintf("Exported At:    %s\n", time.Now().Format(time.RFC1123)))
		sb.WriteString(fmt.Sprintf("Total Duration: %s\n", elapsed))
		sb.WriteString(fmt.Sprintf("Total Targets:  %d\n\n", len(targets)))

		sb.WriteString("FLEET TARGET SUMMARY:\n")
		sb.WriteString(fmt.Sprintf("%-28s %-10s %-16s %-6s %-6s %-8s %-10s %-10s %-10s\n",
			"TARGET", "PROTOCOL", "IP", "SENT", "RECV", "LOSS%", "LAST(ms)", "AVG(ms)", "MAX(ms)"))
		sb.WriteString(strings.Repeat("-", 110) + "\n")
		for _, s := range summaries {
			sb.WriteString(fmt.Sprintf("%-28s %-10s %-16s %-6d %-6d %-7.1f%% %-10.2f %-10.2f %-10.2f\n",
				s.Target, s.Protocol, s.IP, s.Sent, s.Recv, s.LossPercent, s.LastRTTMs, s.AvgRTTMs, s.MaxRTTMs))
		}

		if len(cleanHistory) > 0 {
			sb.WriteString("\nPROBE EVENT HISTORY:\n")
			sb.WriteString(fmt.Sprintf("%-20s %-6s %-24s %-8s %-16s %-10s %-10s %s\n",
				"TIMESTAMP", "SEQ", "TARGET", "PROTO", "IP", "STATUS", "RTT(ms)", "DETAILS"))
			sb.WriteString(strings.Repeat("-", 110) + "\n")
			for _, p := range cleanHistory {
				status := "SUCCESS"
				if !p.IsSuccess {
					status = "FAILED"
				}
				details := p.Diagnostics
				if p.Error != "" {
					details = "Error: " + p.Error
				}
				sb.WriteString(fmt.Sprintf("%-20s %-6d %-24s %-8s %-16s %-10s %-10.2f %s\n",
					p.Timestamp.Format("2006-01-02 15:04:05"),
					p.Seq,
					p.Target,
					p.Protocol,
					p.IP,
					status,
					p.RTTMs,
					details,
				))
			}
		}
		return os.WriteFile(filePath, []byte(sb.String()), 0644)
	}

	return nil
}
