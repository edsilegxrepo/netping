package printers

import (
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/edsilegx/netping/pkg/utils"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// EventType is a special type for each method
// in the printer interface so that automatic tools
// can understand what kind of an event they've received.
type EventType string

const (
	ProbeEvent          EventType = "probe"
	StatisticsEvent     EventType = "statistics"
	HostnameChangeEvent EventType = "hostname change"
)

const (
	dataTableSchema = `CREATE TABLE IF NOT EXISTS %s (
		type TEXT NOT NULL,
		success TEXT,
		timestamp DATETIME,
		ip_address TEXT,
		hostname TEXT,
		port INTEGER,
		source_address TEXT,
		destination_is_ip TEXT,
		time TEXT,
		ongoing_successful_probes INTEGER,
		ongoing_unsuccessful_probes INTEGER
	);`

	dataTableInsertSchema = `INSERT INTO %s (
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
		)
		VALUES (?,?,?,?,?,?,?,?,?,?,?);`
)

const (
	statsTableSchema = `CREATE TABLE IF NOT EXISTS %s (
		type TEXT NOT NULL,
		timestamp DATETIME,
		ip_address TEXT,
		hostname TEXT,
		port INTEGER,
		total_duration TEXT,
		total_uptime TEXT,
		total_downtime TEXT,
		total_packets INTEGER,
		total_successful_packets INTEGER,
		total_unsuccessful_packets INTEGER,
		total_packet_loss_percent TEXT,
		longest_uptime TEXT,
		longest_downtime TEXT,
		hostname_resolve_retries INTEGER,
		hostname_changes BLOB,
		last_successful_probe TEXT,
		last_unsuccessful_probe TEXT,
		longest_consecutive_uptime_start TEXT,
		longest_consecutive_uptime_end TEXT,
		longest_consecutive_downtime_start TEXT,
		longest_consecutive_downtime_end TEXT,
		latency_min TEXT,
		latency_avg TEXT,
		latency_max TEXT,
		start_time TEXT,
		end_time TEXT
	);`

	statsTableInsertSchema = `INSERT INTO %s (
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
		)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);`
)

type probeData struct {
	kind                      EventType
	success                   string
	timestamp                 string
	ip                        string
	hostname                  string
	port                      uint16
	sourceAddress             string
	destIsIP                  string
	time                      string
	ongoingSuccessfulProbes   uint
	ongoingUnsuccessfulProbes uint
}

func (d *probeData) toArgs() []interface{} {
	return []interface{}{
		string(d.kind),
		d.success,
		d.timestamp,
		d.ip,
		d.hostname,
		int64(d.port),
		d.sourceAddress,
		d.destIsIP,
		d.time,
		// #nosec G115 -- probe counts safely converted for SQLite int64 column
		int64(d.ongoingSuccessfulProbes),
		// #nosec G115 -- probe counts safely converted for SQLite int64 column
		int64(d.ongoingUnsuccessfulProbes),
	}
}

type statsData struct {
	kind                            EventType
	timestamp                       string
	ip                              string
	hostname                        string
	port                            uint16
	totalDuration                   string
	totalUptime                     string
	totalDowntime                   string
	totalPackets                    uint
	totalSuccessfulPackets          uint
	totalUnsuccessfulPackets        uint
	totalPacketLossPercent          string
	longestUptime                   string
	longestDowntime                 string
	hostnameResolveRetries          uint
	hostnameChanges                 string
	lastSuccessfulProbe             string
	lastUnsuccessfulProbe           string
	longestConsecutiveUptimeStart   string
	longestConsecutiveUptimeEnd     string
	longestConsecutiveDowntimeStart string
	longestConsecutiveDowntimeEnd   string
	latencyMin                      string
	latencyAvg                      string
	latencyMax                      string
	startTimestamp                  string
	endTimestamp                    string
}

func (d *statsData) toArgs() []interface{} {
	return []interface{}{
		string(d.kind),
		d.timestamp,
		d.ip,
		d.hostname,
		int64(d.port),
		d.totalDuration,
		d.totalUptime,
		d.totalDowntime,
		// #nosec G115 -- probe counts safely converted for SQLite int64 column
		int64(d.totalPackets),
		// #nosec G115 -- probe counts safely converted for SQLite int64 column
		int64(d.totalSuccessfulPackets),
		// #nosec G115 -- probe counts safely converted for SQLite int64 column
		int64(d.totalUnsuccessfulPackets),
		d.totalPacketLossPercent,
		d.longestUptime,
		d.longestDowntime,
		// #nosec G115 -- retry count safely converted for SQLite int64 column
		int64(d.hostnameResolveRetries),
		d.hostnameChanges,
		d.lastSuccessfulProbe,
		d.lastUnsuccessfulProbe,
		d.longestConsecutiveUptimeStart,
		d.longestConsecutiveUptimeEnd,
		d.longestConsecutiveDowntimeStart,
		d.longestConsecutiveDowntimeEnd,
		d.latencyMin,
		d.latencyAvg,
		d.latencyMax,
		d.startTimestamp,
		d.endTimestamp,
	}
}

// DatabasePrinter represents a SQLite database connection for storing TCPing results.
type DatabasePrinter struct {
	mu             sync.Mutex
	Conn           *sqlite.Conn
	probeTableName string
	statsTableName string
	FilePath       string
}

// NewDatabasePrinter initializes a new sqlite3 Database instance, creates the data table, and returns a pointer to it.
func NewDatabasePrinter(target, port, filePath string) (*DatabasePrinter, error) {
	probeTableName := sanitizeTableName(target, port)
	statsTableName := probeTableName + "_stats"

	filePath = addDbExtension(filePath)

	conn, err := sqlite.OpenConn(filePath, sqlite.OpenCreate, sqlite.OpenReadWrite)
	if err != nil {
		return nil, fmt.Errorf("error creating the database %q: %w", filePath, err)
	}

	tableSchema := fmt.Sprintf(dataTableSchema, probeTableName)
	if err = sqlitex.Execute(conn, tableSchema, &sqlitex.ExecOptions{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("error creating the data table: %w", err)
	}

	statsTableSchema := fmt.Sprintf(statsTableSchema, statsTableName)
	if err = sqlitex.Execute(conn, statsTableSchema, &sqlitex.ExecOptions{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("error creating the statistics table: %w", err)
	}

	return &DatabasePrinter{
		Conn:           conn,
		probeTableName: probeTableName,
		statsTableName: statsTableName,
		FilePath:       filePath,
	}, nil
}

func addDbExtension(filename string) string {
	if filename == ":memory:" || strings.HasSuffix(filename, ".db") {
		return filename
	}

	return filename + ".db"
}

func sanitizeTableName(hostname, port string) string {
	var sb strings.Builder
	for _, r := range hostname {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	sanitizedHost := sb.String()

	var sbPort strings.Builder
	for _, r := range port {
		if r >= '0' && r <= '9' {
			sbPort.WriteRune(r)
		}
	}
	sanitizedPort := sbPort.String()

	sanitizedTime := strings.ReplaceAll(time.Now().Format(time.DateTime), "-", "_")
	sanitizedTime = strings.ReplaceAll(sanitizedTime, ":", "_")
	sanitizedTime = strings.ReplaceAll(sanitizedTime, " ", "_")

	tableName := fmt.Sprintf("%s_%s__%s",
		sanitizedHost,
		sanitizedPort,
		sanitizedTime,
	)

	if len(tableName) > 0 && unicode.IsNumber(rune(tableName[0])) {
		tableName = "_" + tableName
	}

	return tableName
}

// Done closes the connection to the database
func (p *DatabasePrinter) Done() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Conn != nil {
		_ = p.Conn.Close()
		p.Conn = nil
	}
}

// Shutdown sets the end time, prints statistics, and calls Done().
func (p *DatabasePrinter) Shutdown(s *stats.Statistics) {
	s.EndTime = time.Now()
	PrintStats(p, s)
	p.Done()
}

// PrintStart prints a message indicating that TCPing has started for the given hostname and port.
func (p *DatabasePrinter) PrintStart(s *stats.Statistics) {
	fmt.Printf("TCPinging %s on port %d - saving the results to: %s\n", s.Hostname, s.Port, p.FilePath)
}

// PrintProbeSuccess logs a successful probe to the SQLite database.
func (p *DatabasePrinter) PrintProbeSuccess(s *stats.Statistics) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Conn == nil {
		return
	}

	timestamp := ""
	if s.WithTimestamp {
		timestamp = time.Now().Format(time.DateTime)
	}

	sourceAddress := ""
	if s.WithSourceAddress {
		sourceAddress = s.SourceAddr()
	}

	destIsIP := "true"
	if !s.DestIsIP {
		destIsIP = "false"
	}

	data := probeData{
		kind:                    ProbeEvent,
		success:                 "true",
		timestamp:               timestamp,
		ip:                      s.IPStr(),
		hostname:                s.Hostname,
		port:                    s.Port,
		sourceAddress:           sourceAddress,
		destIsIP:                destIsIP,
		time:                    s.RTTStr(),
		ongoingSuccessfulProbes: s.OngoingSuccessfulProbes,
	}

	if err := sqlitex.Execute(
		p.Conn,
		fmt.Sprintf(dataTableInsertSchema, p.probeTableName),
		&sqlitex.ExecOptions{Args: data.toArgs()},
	); err != nil {
		p.PrintError("Failed writing probe data to database: %s\n", err)
	}
}

// PrintProbeFailure logs a failed probe attempt to the SQLite database.
func (p *DatabasePrinter) PrintProbeFailure(s *stats.Statistics) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Conn == nil {
		return
	}

	timestamp := ""
	if s.WithTimestamp {
		timestamp = time.Now().Format(time.DateTime)
	}

	sourceAddress := ""
	if s.WithSourceAddress {
		sourceAddress = s.SourceAddr()
	}

	destIsIP := "true"
	if !s.DestIsIP {
		destIsIP = "false"
	}

	data := probeData{
		kind:                      ProbeEvent,
		success:                   "false",
		timestamp:                 timestamp,
		ip:                        s.IPStr(),
		hostname:                  s.Hostname,
		port:                      s.Port,
		sourceAddress:             sourceAddress,
		destIsIP:                  destIsIP,
		time:                      "0",
		ongoingUnsuccessfulProbes: s.OngoingUnsuccessfulProbes,
	}

	if err := sqlitex.Execute(
		p.Conn,
		fmt.Sprintf(dataTableInsertSchema, p.probeTableName),
		&sqlitex.ExecOptions{Args: data.toArgs()},
	); err != nil {
		p.PrintError("Failed writing probe data to database: %s\n", err)
	}
}

// PrintError prints error messages to stderr.
func (p *DatabasePrinter) PrintError(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Database Error: "+format+"\n", args...)
}

// PrintRetryingToResolve prints a message indicating that the program is retrying to resolve a hostname.
func (p *DatabasePrinter) PrintRetryingToResolve(hostname string) {
	fmt.Printf("Retrying to resolve %s\n", hostname)
}

// PrintStatistics logs TCPing statistics to the SQLite database.
func (p *DatabasePrinter) PrintStatistics(s *stats.Statistics) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Conn == nil {
		return
	}

	totalPackets := s.TotalSuccessfulProbes + s.TotalUnsuccessfulProbes

	data := statsData{
		kind:                            StatisticsEvent,
		timestamp:                       time.Now().Format(time.DateTime),
		ip:                              s.IPStr(),
		hostname:                        s.Hostname,
		port:                            s.Port,
		totalPackets:                    totalPackets,
		totalSuccessfulPackets:          s.TotalSuccessfulProbes,
		totalUnsuccessfulPackets:        s.TotalUnsuccessfulProbes,
		longestUptime:                   "Never",
		longestDowntime:                 "Never",
		longestConsecutiveUptimeStart:   "Never",
		longestConsecutiveUptimeEnd:     "Never",
		longestConsecutiveDowntimeStart: "Never",
		longestConsecutiveDowntimeEnd:   "Never",
		latencyMin:                      "N/A",
		latencyAvg:                      "N/A",
		latencyMax:                      "N/A",
		startTimestamp:                  s.StartTime.Format(time.DateTime),
		endTimestamp:                    "In progress",
	}

	packetLoss := (float32(s.TotalUnsuccessfulProbes) / float32(totalPackets)) * 100
	if math.IsNaN(float64(packetLoss)) {
		packetLoss = 0
	}

	data.totalPacketLossPercent = fmt.Sprintf("%.2f", packetLoss)

	if !s.LastSuccessfulProbe.IsZero() {
		data.lastSuccessfulProbe = s.LastSuccessfulProbe.Format(time.DateTime)
	}

	if !s.LastUnsuccessfulProbe.IsZero() {
		data.lastUnsuccessfulProbe = s.LastUnsuccessfulProbe.Format(time.DateTime)
	}

	if s.LongestUp.Duration != 0 {
		data.longestUptime = fmt.Sprintf("%.0f", s.LongestUp.Duration.Seconds())
		data.longestConsecutiveUptimeStart = s.LongestUp.Start.Format(time.DateTime)
		data.longestConsecutiveUptimeEnd = s.LongestUp.End.Format(time.DateTime)
	}

	if s.LongestDown.Duration != 0 {
		data.longestDowntime = fmt.Sprintf("%.0f", s.LongestDown.Duration.Seconds())
		data.longestConsecutiveDowntimeStart = s.LongestDown.Start.Format(time.DateTime)
		data.longestConsecutiveDowntimeEnd = s.LongestDown.End.Format(time.DateTime)
	}

	if !s.DestIsIP {
		data.hostnameResolveRetries = s.RetriedHostnameLookups
	}

	if s.RTTResults.HasResults {
		data.latencyMin = fmt.Sprintf("%.3f", s.RTTResults.Min)
		data.latencyAvg = fmt.Sprintf("%.3f", s.RTTResults.Average)
		data.latencyMax = fmt.Sprintf("%.3f", s.RTTResults.Max)
	}

	if !s.EndTime.IsZero() {
		data.endTimestamp = s.EndTime.Format(time.DateTime)
	}

	totalDuration := s.TotalDowntime + s.TotalUptime
	data.totalDuration = fmt.Sprintf("%.0f", totalDuration.Seconds())
	data.totalUptime = utils.DurationToString(s.TotalUptime)
	data.totalDowntime = utils.DurationToString(s.TotalDowntime)

	if err := sqlitex.Execute(
		p.Conn,
		fmt.Sprintf(statsTableInsertSchema, p.statsTableName),
		&sqlitex.ExecOptions{Args: data.toArgs()},
	); err != nil {
		p.PrintError("Failed writing statistics to database: %s", err)
	}

	fmt.Printf("\nProbe and statistics data for %q have been saved to the table %q and %q, respectively\n",
		s.Hostname,
		p.probeTableName,
		p.statsTableName,
	)
}

// PrintTotalDownTime satisfies the "printer" interface but does nothing in this implementation
func (p *DatabasePrinter) PrintTotalDownTime(_ *stats.Statistics) {}
