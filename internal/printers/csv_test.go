package printers

import (
	"encoding/csv"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
)

func TestNewCSVPrinter(t *testing.T) {
	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "test_data")
	probeFilename := basePath + ".csv"
	statsFilename := basePath + "_stats.csv"

	cp, err := NewCSVPrinter(basePath)
	assert.NoError(t, err)
	assert.NotNil(t, cp)
	assert.Equal(t, probeFilename, cp.ProbeFile.Name())
	assert.Equal(t, statsFilename, cp.StatsFile.Name())

	cp.Done()
}

func TestWriteRecord(t *testing.T) {
	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "test_record")
	probeFilename := basePath + ".csv"

	cp, err := NewCSVPrinter(basePath)
	assert.NoError(t, err)
	assert.NotNil(t, cp)

	s := &stats.Statistics{
		IP:                      netip.MustParseAddr("127.0.0.1"),
		Hostname:                "localhost",
		Port:                    80,
		StartTime:               time.Now(),
		OngoingSuccessfulProbes: 1,
		LatestRTT:               10.123,
	}

	cp.PrintStart(s)
	cp.PrintProbeSuccess(s)
	cp.Done()

	file, err := os.Open(probeFilename)
	assert.NoError(t, err)
	defer file.Close()

	reader := csv.NewReader(file)
	headers, err := reader.Read()
	assert.NoError(t, err)
	assert.Equal(t, []string{"Status", "Hostname", "IP", "Port", "Connection", "Latency(ms)"}, headers)

	readRecord, err := reader.Read()
	assert.NoError(t, err)

	record := []string{"Reply", "localhost", "127.0.0.1", "80", "1", "10.123"}
	assert.Equal(t, record, readRecord)
}

func TestWriteStatistics(t *testing.T) {
	tempDir := t.TempDir()
	probeFilename := filepath.Join(tempDir, "test_stats_data.csv")
	statsFilename := filepath.Join(tempDir, "test_stats_data_stats.csv")

	cp, err := NewCSVPrinter(probeFilename)
	assert.NoError(t, err)
	assert.NotNil(t, cp)

	s := &stats.Statistics{
		Hostname:                "localhost",
		IP:                      netip.MustParseAddr("127.0.0.1"),
		Port:                    1234,
		TotalSuccessfulProbes:   1,
		TotalUnsuccessfulProbes: 0,
		LastSuccessfulProbe:     time.Now(),
		StartTime:               time.Now(),
		RTT:                     []float32{15.0},
	}

	PrintStats(cp, s)
	cp.Done()

	statsFile, err := os.Open(statsFilename)
	assert.NoError(t, err)
	defer statsFile.Close()

	reader := csv.NewReader(statsFile)

	recordCount := 0
	for {
		_, err := reader.Read()
		if err != nil {
			break
		}
		recordCount++
	}

	assert.Equal(t, 25, recordCount)
}

func TestTSVPrinter(t *testing.T) {
	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "test_tsv")
	probeFilename := basePath + ".tsv"

	tp, err := NewTSVPrinter(basePath)
	assert.NoError(t, err)
	assert.NotNil(t, tp)

	s := &stats.Statistics{
		IP:                      netip.MustParseAddr("127.0.0.1"),
		Hostname:                "localhost",
		Port:                    80,
		StartTime:               time.Now(),
		OngoingSuccessfulProbes: 1,
		LatestRTT:               10.123,
	}

	tp.PrintStart(s)
	tp.PrintProbeSuccess(s)
	tp.PrintProbeFailure(s)
	PrintStats(tp, s)
	tp.Done()

	data, err := os.ReadFile(probeFilename)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "Status\tHostname\tIP\tPort")
}
