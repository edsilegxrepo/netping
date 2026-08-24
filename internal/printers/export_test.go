package printers

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			Timestamp: time.Now(),
			Seq:       1,
			Target:    "example.com:443",
			Protocol:  "HTTPS",
			IP:        "93.184.216.34",
			IsSuccess: true,
			RTTMs:     12.5,
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
