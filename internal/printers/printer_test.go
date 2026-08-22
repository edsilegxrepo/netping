package printers

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
)

func TestNewPrinter(t *testing.T) {
	tempCSV := filepath.Join(t.TempDir(), "test_new_printer.csv")

	tests := []struct {
		name        string
		cfg         PrinterConfig
		wantErr     bool
		expectedTyp string
	}{
		{
			name:        "JSON Printer",
			cfg:         PrinterConfig{OutputJSON: true},
			wantErr:     false,
			expectedTyp: "*printers.JSONPrinter",
		},
		{
			name:        "Pretty without JSON errors",
			cfg:         PrinterConfig{PrettyJSON: true, OutputJSON: false},
			wantErr:     true,
			expectedTyp: "",
		},
		{
			name:        "Plain Printer",
			cfg:         PrinterConfig{NoColor: true},
			wantErr:     false,
			expectedTyp: "*printers.PlainPrinter",
		},
		{
			name:        "Color Printer (Default)",
			cfg:         PrinterConfig{},
			wantErr:     false,
			expectedTyp: "*printers.ColorPrinter",
		},
		{
			name:        "CSV Printer",
			cfg:         PrinterConfig{OutputCSVPath: tempCSV},
			wantErr:     false,
			expectedTyp: "*printers.CSVPrinter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewPrinter(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, p)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, p)
			}
			if cp, ok := p.(*CSVPrinter); ok {
				cp.Done()
			}
		})
	}
}

func TestCalcMinAvgMaxRttTime(t *testing.T) {
	t.Run("empty array", func(t *testing.T) {
		res := calcMinAvgMaxRttTime(nil)
		assert.False(t, res.HasResults)
		assert.Equal(t, float32(0), res.Min)
		assert.Equal(t, float32(0), res.Average)
		assert.Equal(t, float32(0), res.Max)
	})

	t.Run("single element", func(t *testing.T) {
		res := calcMinAvgMaxRttTime([]float32{12.345})
		assert.True(t, res.HasResults)
		assert.Equal(t, float32(12.345), res.Min)
		assert.Equal(t, float32(12.345), res.Average)
		assert.Equal(t, float32(12.345), res.Max)
	})

	t.Run("multiple elements", func(t *testing.T) {
		res := calcMinAvgMaxRttTime([]float32{10.0, 20.0, 30.0})
		assert.True(t, res.HasResults)
		assert.Equal(t, float32(10.0), res.Min)
		assert.Equal(t, float32(20.0), res.Average)
		assert.Equal(t, float32(30.0), res.Max)
	})
}

func TestJSONPrinterOutput(t *testing.T) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	jp := &JSONPrinter{encoder: encoder}

	s := &stats.Statistics{
		Hostname:                "example.com",
		IP:                      netip.MustParseAddr("93.184.216.34"),
		Port:                    443,
		StartTime:               time.Now(),
		OngoingSuccessfulProbes: 1,
		LatestRTT:               15.2,
		RTT:                     []float32{15.2},
	}

	jp.PrintStart(s)
	jp.PrintProbeSuccess(s)
	jp.PrintProbeFailure(s)
	jp.PrintRetryingToResolve("example.com")
	jp.PrintTotalDownTime(s)
	jp.PrintStatistics(s)

	output := buf.String()
	assert.NotEmpty(t, output)

	// Verify it contains valid JSON objects line by line
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	for _, line := range lines {
		var data map[string]any
		err := json.Unmarshal(line, &data)
		assert.NoError(t, err, "JSON line must be valid JSON: %s", string(line))
	}
}

func TestPlainAndColorPrinterMethods(t *testing.T) {
	plain := NewPlainPrinter()
	colorP := NewColorPrinter()

	s := &stats.Statistics{
		Hostname:                "example.com",
		IP:                      netip.MustParseAddr("93.184.216.34"),
		Port:                    443,
		StartTime:               time.Now(),
		OngoingSuccessfulProbes: 1,
		LatestRTT:               12.345,
		RTT:                     []float32{12.345, 15.678, 10.111},
		WithTimestamp:           true,
		WithSourceAddress:       true,
		WithDiags:               true,
		LatestDiagnostics:       "Upgrade: 101 Switching Protocols",
	}

	// Ensure calling methods does not panic
	assert.NotPanics(t, func() {
		plain.PrintStart(s)
		plain.PrintProbeSuccess(s)
		plain.PrintProbeFailure(s)
		plain.PrintRetryingToResolve("example.com")
		plain.PrintTotalDownTime(s)
		plain.PrintStatistics(s)

		colorP.PrintStart(s)
		colorP.PrintProbeSuccess(s)
		colorP.PrintProbeFailure(s)
		colorP.PrintRetryingToResolve("example.com")
		colorP.PrintTotalDownTime(s)
		colorP.PrintStatistics(s)
	})
}
