package printers

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func TestSanitizeExportField(t *testing.T) {
	// Clean strings (fast path)
	assert.Equal(t, "clean_string_123", sanitizeExportField("clean_string_123"))
	assert.Equal(t, "", sanitizeExportField(""))

	// ANSI color codes stripped
	assert.Equal(t, "Colored Text", sanitizeExportField("\033[1;32mColored Text\033[0m"))

	// Box drawing and special glyphs replaced
	assert.Equal(t, "* test", sanitizeExportField("● test"))
	assert.Equal(t, "x fail", sanitizeExportField("× fail"))
	assert.Equal(t, "a | b", sanitizeExportField("a│b"))
}

func BenchmarkSanitizeExportField_Clean(b *testing.B) {
	str := "www.criticalsys.net:443"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizeExportField(str)
	}
}

func BenchmarkSanitizeExportField_Dirty(b *testing.B) {
	str := "\033[1;32m●\033[0m www.criticalsys.net:443 │ RTT=14.5ms"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizeExportField(str)
	}
}

func TestExportMultiTarget_TableAlignment(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.txt")

	targets := []FleetTarget{
		{
			Target:   "www.example.com:443",
			Host:     "www.example.com",
			Port:     443,
			Protocol: "HTTPS",
			Stats: &stats.Statistics{
				TotalSuccessfulProbes:   10,
				TotalUnsuccessfulProbes: 0,
				RTT:                     []float32{15.0, 16.0},
			},
		},
	}

	history := []SingleProbeExportRecord{
		{
			Timestamp: time.Date(2026, 8, 23, 16, 0, 0, 0, time.UTC),
			Seq:       1,
			Target:    "www.example.com:443",
			Protocol:  "HTTPS",
			IP:        "93.184.216.34",
			IsSuccess: true,
			RTTMs:     15.2,
		},
	}

	err := ExportMultiTarget(targets, time.Now().Add(-10*time.Second), history, FormatPlainText, outPath)
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	text := string(content)

	// Verify Loss percentage formatting aligns properly (e.g. "0.0%    " without space before %)
	assert.Contains(t, text, "0.0%    ")
	assert.NotContains(t, text, "0.0    %")
	assert.Contains(t, text, "2026-08-23 16:00:00")
	assert.NotContains(t, text, "0000-01-01")
}

func TestExportFormats_Single_And_Multi(t *testing.T) {
	tmpDir := t.TempDir()
	st := &stats.Statistics{
		Hostname:                "example.com",
		Port:                    443,
		TotalSuccessfulProbes:   5,
		TotalUnsuccessfulProbes: 0,
		RTT:                     []float32{12.5, 14.5},
	}

	targets := []FleetTarget{
		{
			Target:   "example.com:443",
			Host:     "example.com",
			Port:     443,
			Protocol: "HTTPS",
			Stats:    st,
		},
	}

	history := []SingleProbeExportRecord{
		{
			Timestamp:   time.Now(),
			Seq:         1,
			Target:      "example.com:443",
			Port:        443,
			Protocol:    "HTTPS",
			IP:          "93.184.216.34",
			IsSuccess:   true,
			RTTMs:       12.5,
			DNSTimeMs:   1.2,
			TCPTimeMs:   2.3,
			TLSTimeMs:   4.5,
			TTFBMs:      4.5,
			HTTPStatus:  200,
			Diagnostics: "TLS 1.3 | HTTP/2",
		},
	}

	formats := []ExportFormat{
		FormatJSON,
		FormatPrettyJSON,
		FormatCSV,
		FormatTSV,
		FormatSQLite3,
		FormatPlainText,
	}

	for _, fmtKey := range formats {
		t.Run(fmt.Sprintf("format_%d", fmtKey), func(t *testing.T) {
			singlePath := filepath.Join(tmpDir, fmt.Sprintf("single_%d", fmtKey))
			err := ExportSingleTarget("example.com", 443, "HTTPS", st, history, fmtKey, singlePath)
			require.NoError(t, err)
			_, err = os.Stat(singlePath)
			assert.NoError(t, err)

			multiPath := filepath.Join(tmpDir, fmt.Sprintf("multi_%d", fmtKey))
			err = ExportMultiTarget(targets, time.Now().Add(-5*time.Second), history, fmtKey, multiPath)
			require.NoError(t, err)
			_, err = os.Stat(multiPath)
			assert.NoError(t, err)
		})
	}
}

func TestExportFormats_TTFBVerification(t *testing.T) {
	tmpDir := t.TempDir()
	st := &stats.Statistics{
		Hostname: "api.example.com",
		Port:     443,
	}
	history := []SingleProbeExportRecord{
		{
			Timestamp:   time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC),
			Seq:         1,
			Target:      "api.example.com:443",
			Port:        443,
			Protocol:    "HTTPS",
			IP:          "1.2.3.4",
			IsSuccess:   true,
			RTTMs:       15.50,
			DNSTimeMs:   2.10,
			TCPTimeMs:   3.20,
			TLSTimeMs:   5.10,
			TTFBMs:      5.10,
			HTTPStatus:  200,
			Diagnostics: "HTTP/2 200 OK",
		},
	}

	// 1. CSV Verification
	csvPath := filepath.Join(tmpDir, "test.csv")
	err := ExportSingleTarget("api.example.com", 443, "HTTPS", st, history, FormatCSV, csvPath)
	require.NoError(t, err)
	csvData, err := os.ReadFile(csvPath)
	require.NoError(t, err)
	assert.Contains(t, string(csvData), "TTFB_ms")
	assert.Contains(t, string(csvData), "5.10")

	// 2. TSV Verification
	tsvPath := filepath.Join(tmpDir, "test.tsv")
	err = ExportSingleTarget("api.example.com", 443, "HTTPS", st, history, FormatTSV, tsvPath)
	require.NoError(t, err)
	tsvData, err := os.ReadFile(tsvPath)
	require.NoError(t, err)
	assert.Contains(t, string(tsvData), "TTFB_ms")
	assert.Contains(t, string(tsvData), "5.10")

	// 3. JSON Verification
	jsonPath := filepath.Join(tmpDir, "test.json")
	err = ExportSingleTarget("api.example.com", 443, "HTTPS", st, history, FormatJSON, jsonPath)
	require.NoError(t, err)
	jsonData, err := os.ReadFile(jsonPath)
	require.NoError(t, err)
	assert.Contains(t, string(jsonData), `"ttfbMs":5.1`)

	// 4. Plain Text Verification
	txtPath := filepath.Join(tmpDir, "test.txt")
	err = ExportSingleTarget("api.example.com", 443, "HTTPS", st, history, FormatPlainText, txtPath)
	require.NoError(t, err)
	txtData, err := os.ReadFile(txtPath)
	require.NoError(t, err)
	assert.Contains(t, string(txtData), "TTFB(ms)")
	assert.Contains(t, string(txtData), "5.10")

	// 5. SQLite3 Verification (Single Target)
	dbPath := filepath.Join(tmpDir, "test.db")
	err = ExportSingleTarget("api.example.com", 443, "HTTPS", st, history, FormatSQLite3, dbPath)
	require.NoError(t, err)
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	var ttfbVal float64
	var dnsVal, tcpVal, tlsVal float64
	var statusVal int
	row := db.QueryRow("SELECT dns_ms, tcp_ms, tls_ms, ttfb_ms, http_status FROM probes WHERE seq = 1")
	err = row.Scan(&dnsVal, &tcpVal, &tlsVal, &ttfbVal, &statusVal)
	require.NoError(t, err)
	assert.InDelta(t, 2.10, dnsVal, 0.01)
	assert.InDelta(t, 3.20, tcpVal, 0.01)
	assert.InDelta(t, 5.10, tlsVal, 0.01)
	assert.InDelta(t, 5.10, ttfbVal, 0.01)
	assert.Equal(t, 200, statusVal)

	// 6. Fleet CSV & SQLite Verification
	fleetTargets := []FleetTarget{
		{Target: "api.example.com:443", Host: "api.example.com", Port: 443, Protocol: "HTTPS", Stats: st},
	}
	fleetCSVPath := filepath.Join(tmpDir, "fleet.csv")
	err = ExportMultiTarget(fleetTargets, time.Now().Add(-5*time.Second), history, FormatCSV, fleetCSVPath)
	require.NoError(t, err)
	fleetCSVData, err := os.ReadFile(fleetCSVPath)
	require.NoError(t, err)
	assert.Contains(t, string(fleetCSVData), "TTFB_ms")
	assert.Contains(t, string(fleetCSVData), "5.10")

	fleetDBPath := filepath.Join(tmpDir, "fleet.db")
	err = ExportMultiTarget(fleetTargets, time.Now().Add(-5*time.Second), history, FormatSQLite3, fleetDBPath)
	require.NoError(t, err)
	dbFleet, err := sql.Open("sqlite", fleetDBPath)
	require.NoError(t, err)
	defer func() { _ = dbFleet.Close() }()

	var fleetTTFB float64
	rowFleet := dbFleet.QueryRow("SELECT ttfb_ms FROM probes WHERE seq = 1")
	err = rowFleet.Scan(&fleetTTFB)
	require.NoError(t, err)
	assert.InDelta(t, 5.10, fleetTTFB, 0.01)
}
