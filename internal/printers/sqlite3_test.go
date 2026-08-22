package printers

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const (
	probeDataQuery = `SELECT
		type,
		success,
		timestamp,
		ip_address,
		hostname,
		port,
		source_address,
		destination_is_ip,
		time,
		ongoing_successful_probes,
		ongoing_unsuccessful_probes
		FROM %s WHERE type = ?`

	statsDataQuery = `SELECT
		type,
		timestamp,
		ip_address,
		hostname,
		port,
		total_duration,
		total_uptime,
		total_downtime,
		total_packets,
		total_successful_packets,
		total_unsuccessful_packets,
		total_packet_loss_percent,
		longest_uptime,
		longest_downtime,
		hostname_resolve_retries,
		hostname_changes,
		last_successful_probe,
		last_unsuccessful_probe,
		longest_consecutive_uptime_start,
		longest_consecutive_uptime_end,
		longest_consecutive_downtime_start,
		longest_consecutive_downtime_end,
		latency_min,
		latency_avg,
		latency_max,
		start_time,
		end_time
		FROM %s WHERE type = ?`
)

func TestNewDatabasePrinter(t *testing.T) {
	tempDB := filepath.Join(t.TempDir(), "test_db")

	tests := []struct {
		name    string
		target  string
		port    string
		dbPath  string
		wantErr bool
	}{
		{
			name:    "memory database",
			target:  "localhost",
			port:    "8001",
			dbPath:  ":memory:",
			wantErr: false,
		},
		{
			name:    "file database",
			target:  "example.com",
			port:    "80",
			dbPath:  tempDB,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDatabasePrinter(tt.target, tt.port, tt.dbPath)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, db)
			defer db.Done()

			// Verify tables were created
			query := "SELECT name FROM sqlite_master WHERE type='table';"
			var foundProbe, foundStats bool
			err = sqlitex.Execute(db.Conn, query, &sqlitex.ExecOptions{
				ResultFunc: func(stmt *sqlite.Stmt) error {
					tableName := stmt.ColumnText(0)
					if tableName == db.probeTableName {
						foundProbe = true
					}
					if tableName == db.statsTableName {
						foundStats = true
					}
					return nil
				},
			})
			assert.NoError(t, err)
			assert.True(t, foundProbe, "probe table not created")
			assert.True(t, foundStats, "stats table not created")
		})
	}
}

func TestDatabasePrinter_PrintProbeSuccess(t *testing.T) {
	db, err := NewDatabasePrinter("example.com", "443", ":memory:")
	assert.NoError(t, err)
	defer db.Done()

	s := &stats.Statistics{
		Hostname:                "example.com",
		IP:                      netip.MustParseAddr("93.184.216.34"),
		Port:                    443,
		StartTime:               time.Now(),
		OngoingSuccessfulProbes: 1,
		LatestRTT:               15.5,
	}

	db.PrintProbeSuccess(s)

	query := fmt.Sprintf(probeDataQuery, db.probeTableName)
	var records int
	err = sqlitex.Execute(db.Conn, query, &sqlitex.ExecOptions{
		Args: []interface{}{string(ProbeEvent)},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			assert.Equal(t, "true", stmt.ColumnText(1))
			assert.Equal(t, "93.184.216.34", stmt.ColumnText(3))
			assert.Equal(t, int64(443), stmt.ColumnInt64(5))
			assert.Equal(t, int64(1), stmt.ColumnInt64(9))
			records++
			return nil
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, records)
}

func TestDatabasePrinter_PrintProbeFailure(t *testing.T) {
	db, err := NewDatabasePrinter("example.com", "443", ":memory:")
	assert.NoError(t, err)
	defer db.Done()

	s := &stats.Statistics{
		Hostname:                  "example.com",
		IP:                        netip.MustParseAddr("93.184.216.34"),
		Port:                      443,
		StartTime:                 time.Now(),
		OngoingUnsuccessfulProbes: 3,
	}

	db.PrintProbeFailure(s)

	query := fmt.Sprintf(probeDataQuery, db.probeTableName)
	var records int
	err = sqlitex.Execute(db.Conn, query, &sqlitex.ExecOptions{
		Args: []interface{}{string(ProbeEvent)},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			assert.Equal(t, "false", stmt.ColumnText(1))
			assert.Equal(t, "93.184.216.34", stmt.ColumnText(3))
			assert.Equal(t, int64(443), stmt.ColumnInt64(5))
			assert.Equal(t, int64(3), stmt.ColumnInt64(10))
			records++
			return nil
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, records)
}

func TestDatabasePrinter_PrintStatistics(t *testing.T) {
	db, err := NewDatabasePrinter("example.com", "443", ":memory:")
	assert.NoError(t, err)
	defer db.Done()

	s := &stats.Statistics{
		Hostname:                "example.com",
		IP:                      netip.MustParseAddr("93.184.216.34"),
		Port:                    443,
		StartTime:               time.Now(),
		EndTime:                 time.Now().Add(10 * time.Second),
		TotalSuccessfulProbes:   10,
		TotalUnsuccessfulProbes: 2,
		RTTResults: stats.RTTResult{
			Min:        10.0,
			Average:    15.0,
			Max:        20.0,
			HasResults: true,
		},
	}

	db.PrintStatistics(s)

	query := fmt.Sprintf(statsDataQuery, db.statsTableName)
	var records int
	err = sqlitex.Execute(db.Conn, query, &sqlitex.ExecOptions{
		Args: []interface{}{string(StatisticsEvent)},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			assert.Equal(t, "93.184.216.34", stmt.ColumnText(2))
			assert.Equal(t, "example.com", stmt.ColumnText(3))
			assert.Equal(t, int64(443), stmt.ColumnInt64(4))
			assert.Equal(t, int64(10), stmt.ColumnInt64(9))
			assert.Equal(t, int64(2), stmt.ColumnInt64(10))
			records++
			return nil
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, records)
}

func TestSanitizeTableName(t *testing.T) {
	now := time.Now().Format(time.DateTime)
	now = strings.ReplaceAll(now, " ", "_")
	now = strings.ReplaceAll(now, "-", "_")
	now = strings.ReplaceAll(now, ":", "_")

	tests := []struct {
		name     string
		hostname string
		port     string
		want     string
	}{
		{
			name:     "basic hostname",
			hostname: "example.com",
			port:     "80",
			want:     fmt.Sprintf("example_com_80__%s", now),
		},
		{
			name:     "IP address",
			hostname: "192.168.1.1",
			port:     "443",
			want:     fmt.Sprintf("_192_168_1_1_443__%s", now),
		},
		{
			name:     "hostname with hyphens",
			hostname: "test-server-1",
			port:     "8080",
			want:     fmt.Sprintf("test_server_1_8080__%s", now),
		},
		{
			name:     "numeric hostname",
			hostname: "123server",
			port:     "22",
			want:     fmt.Sprintf("_123server_22__%s", now),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTableName(tt.hostname, tt.port)
			if !strings.HasPrefix(got, tt.want[:len(tt.want)-4]) {
				t.Errorf("sanitizeTableName() = %v, want prefix %v", got, tt.want)
			}
		})
	}
}
