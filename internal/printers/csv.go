// csv.go outputs data in CSV format
package printers

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/edsilegx/netping/pkg/utils"
)

const (
	colTimestamp     string = "Timestamp"
	colStatus        string = "Status"
	colHostname      string = "Hostname"
	colIP            string = "IP"
	colPort          string = "Port"
	colConnection    string = "Connection"
	colLatency       string = "Latency(ms)"
	colSourceAddress string = "Source Address"
)

const (
	filePermission os.FileMode = 0644
	fileFlag       int         = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
)

// CSVPrinter is responsible for writing probe results and statistics to CSV files.
type CSVPrinter struct {
	mu            sync.Mutex
	headerWritten bool
	ProbeWriter   *csv.Writer
	StatsWriter   *csv.Writer
	ProbeFile     *os.File
	StatsFile     *os.File
}

// NewCSVPrinter initializes a CSVPrinter instance with the given filename and settings.
func NewCSVPrinter(filePath string) (*CSVPrinter, error) {
	probeFilename := addExtension(filePath, ".csv", false)

	probeFile, err := os.OpenFile(probeFilename, fileFlag, filePermission)
	if err != nil {
		return nil, fmt.Errorf("error creating the probe CSV file %s: %w", probeFilename, err)
	}

	statsFilename := addExtension(filePath, ".csv", true)

	statsFile, err := os.OpenFile(statsFilename, fileFlag, filePermission)
	if err != nil {
		probeFile.Close()
		return nil, fmt.Errorf("error creating the stats CSV file %s: %w", statsFilename, err)
	}

	p := &CSVPrinter{
		ProbeWriter: csv.NewWriter(probeFile),
		StatsWriter: csv.NewWriter(statsFile),
		ProbeFile:   probeFile,
		StatsFile:   statsFile,
	}

	return p, nil
}

// NewTSVPrinter initializes a TSV (Tab-Separated Values) printer instance.
func NewTSVPrinter(filePath string) (*CSVPrinter, error) {
	probeFilename := addExtension(filePath, ".tsv", false)

	probeFile, err := os.OpenFile(probeFilename, fileFlag, filePermission)
	if err != nil {
		return nil, fmt.Errorf("error creating the probe TSV file %s: %w", probeFilename, err)
	}

	statsFilename := addExtension(filePath, ".tsv", true)

	statsFile, err := os.OpenFile(statsFilename, fileFlag, filePermission)
	if err != nil {
		probeFile.Close()
		return nil, fmt.Errorf("error creating the stats TSV file %s: %w", statsFilename, err)
	}

	pw := csv.NewWriter(probeFile)
	pw.Comma = '\t'
	sw := csv.NewWriter(statsFile)
	sw.Comma = '\t'

	p := &CSVPrinter{
		ProbeWriter: pw,
		StatsWriter: sw,
		ProbeFile:   probeFile,
		StatsFile:   statsFile,
	}

	return p, nil
}

func addExtension(filename string, ext string, withStatsExt bool) string {
	base := filename
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ext) {
		base = base[:len(base)-len(ext)]
	} else if strings.HasSuffix(lower, ".csv") || strings.HasSuffix(lower, ".tsv") {
		idx := strings.LastIndex(lower, ".")
		if idx != -1 {
			base = base[:idx]
		}
	}

	if withStatsExt {
		return base + "_stats" + ext
	}

	return base + ext
}

func addCSVExtension(filename string, withStatsExt bool) string {
	return addExtension(filename, ".csv", withStatsExt)
}

// Done flushes the buffer of writers and closes the probe and stats file
func (p *CSVPrinter) Done() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ProbeWriter != nil {
		p.ProbeWriter.Flush()
	}

	if p.ProbeFile != nil {
		p.ProbeFile.Close()
		p.ProbeFile = nil
	}

	if p.StatsWriter != nil {
		p.StatsWriter.Flush()
	}

	if p.StatsFile != nil {
		p.StatsFile.Close()
		p.StatsFile = nil
	}
}

// Shutdown sets the end time, prints statistics, and calls Done().
func (p *CSVPrinter) Shutdown(s *stats.Statistics) {
	s.EndTime = time.Now()
	PrintStats(p, s)
	p.Done()
}

func (p *CSVPrinter) writeProbeHeader(s *stats.Statistics) error {
	headers := []string{}

	if s.WithTimestamp {
		headers = append(headers, colTimestamp)
	}

	headers = append(headers, colStatus, colHostname, colIP, colPort)

	if s.WithSourceAddress {
		headers = append(headers, colSourceAddress)
	}

	headers = append(headers, colConnection, colLatency)

	if err := p.ProbeWriter.Write(headers); err != nil {
		return fmt.Errorf("failed to write headers: %w", err)
	}

	p.ProbeWriter.Flush()

	return p.ProbeWriter.Error()
}

func (p *CSVPrinter) writeStatsHeader() error {
	headers := []string{
		"Metric",
		"Value",
	}

	if err := p.StatsWriter.Write(headers); err != nil {
		return fmt.Errorf("failed to write statistics headers: %w", err)
	}

	p.StatsWriter.Flush()

	return p.StatsWriter.Error()
}

// PrintStart logs the beginning of a TCPing session.
func (p *CSVPrinter) PrintStart(s *stats.Statistics) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.headerWritten {
		p.writeProbeHeader(s)
		p.writeStatsHeader()
		p.headerWritten = true
		fmt.Printf("TCPinging %s on port %d - saving the results to: %s\n", s.Hostname, s.Port, p.ProbeFile.Name())
	}
}

// PrintProbeSuccess logs a successful probe to the CSV file.
func (p *CSVPrinter) PrintProbeSuccess(s *stats.Statistics) {
	p.mu.Lock()
	defer p.mu.Unlock()

	record := []string{}

	if s.WithTimestamp {
		record = append(record, time.Now().Format(time.DateTime))
	}

	record = append(
		record,
		"Reply",
		s.Hostname,
		s.IP.String(),
		fmt.Sprint(s.Port),
	)

	if s.WithSourceAddress {
		record = append(record, s.SourceAddr())
	}

	record = append(record, fmt.Sprint(s.OngoingSuccessfulProbes), s.RTTStr())

	if err := p.ProbeWriter.Write(record); err != nil {
		p.PrintError("Failed to write success record: %v", err)
	}

	p.ProbeWriter.Flush()
}

// PrintProbeFailure logs a failed probe attempt to the CSV file.
func (p *CSVPrinter) PrintProbeFailure(s *stats.Statistics) {
	p.mu.Lock()
	defer p.mu.Unlock()

	record := []string{}

	if s.WithTimestamp {
		record = append(record, time.Now().Format(time.DateTime))
	}

	record = append(
		record,
		"No Reply",
		s.Hostname,
		s.IP.String(),
		fmt.Sprint(s.Port),
	)

	if s.WithSourceAddress {
		record = append(record, s.SourceAddr())
	}

	record = append(record, fmt.Sprint(s.OngoingUnsuccessfulProbes), "0")

	if err := p.ProbeWriter.Write(record); err != nil {
		p.PrintError("Failed to write failure record: %v", err)
	}

	p.ProbeWriter.Flush()
}

// PrintError logs an error message to stderr.
func (p *CSVPrinter) PrintError(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "CSV Error: "+format+"\n", args...)
}

// PrintRetryingToResolve logs an attempt to resolve a hostname.
func (p *CSVPrinter) PrintRetryingToResolve(hostname string) {
	fmt.Printf("Retrying to resolve %s\n", hostname)
}

// PrintStatistics logs TCPing statistics to a CSV file.
func (p *CSVPrinter) PrintStatistics(s *stats.Statistics) {
	p.mu.Lock()
	defer p.mu.Unlock()

	timestamp := time.Now().Format(time.DateTime)

	statistics := [][]string{
		{"Timestamp", timestamp},
		{"IP Address", s.IPStr()},
	}

	if s.IPStr() != s.Hostname {
		statistics = append(statistics, []string{"Hostname", s.Hostname})
	}

	statistics = append(statistics, []string{"Port", fmt.Sprintf("%d", s.Port)})

	totalDuration := s.TotalDowntime + s.TotalUptime
	statistics = append(statistics, []string{"Total Duration",
		fmt.Sprintf("%.0f", totalDuration.Seconds())},
	)

	statistics = append(statistics, []string{"Total Uptime",
		utils.DurationToString(s.TotalUptime)},
	)
	statistics = append(statistics, []string{"Total Downtime",
		utils.DurationToString(s.TotalDowntime)},
	)

	totalPackets := s.TotalSuccessfulProbes + s.TotalUnsuccessfulProbes
	packetLoss := (float32(s.TotalUnsuccessfulProbes) / float32(totalPackets)) * 100

	if math.IsNaN(float64(packetLoss)) {
		packetLoss = 0
	}

	statistics = append(statistics, []string{"Total Packets", fmt.Sprintf("%d", totalPackets)})
	statistics = append(statistics, []string{"Total Successful Packets", fmt.Sprintf("%d", s.TotalSuccessfulProbes)})
	statistics = append(statistics, []string{"Total Unsuccessful Packets", fmt.Sprintf("%d", s.TotalUnsuccessfulProbes)})
	statistics = append(statistics, []string{"Total Packet Loss Percentage", fmt.Sprintf("%.2f", packetLoss)})

	if s.LongestUp.Duration != 0 {
		longestUptime := fmt.Sprintf("%.0f", s.LongestUp.Duration.Seconds())
		longestConsecutiveUptimeStart := s.LongestUp.Start.Format(time.DateTime)
		longestConsecutiveUptimeEnd := s.LongestUp.End.Format(time.DateTime)

		statistics = append(statistics, []string{"Longest Uptime", longestUptime})
		statistics = append(statistics, []string{"Longest Consecutive Uptime Start", longestConsecutiveUptimeStart})
		statistics = append(statistics, []string{"Longest Consecutive Uptime End", longestConsecutiveUptimeEnd})
	} else {
		statistics = append(statistics, []string{"Longest Uptime", "Never"})
		statistics = append(statistics, []string{"Longest Consecutive Uptime Start", "Never"})
		statistics = append(statistics, []string{"Longest Consecutive Uptime End", "Never"})
	}

	if s.LongestDown.Duration != 0 {
		longestDowntime := fmt.Sprintf("%.0f", s.LongestDown.Duration.Seconds())
		longestConsecutiveDowntimeStart := s.LongestDown.Start.Format(time.DateTime)
		longestConsecutiveDowntimeEnd := s.LongestDown.End.Format(time.DateTime)

		statistics = append(statistics, []string{"Longest Downtime", longestDowntime})
		statistics = append(statistics, []string{"Longest Consecutive Downtime Start", longestConsecutiveDowntimeStart})
		statistics = append(statistics, []string{"Longest Consecutive Downtime End", longestConsecutiveDowntimeEnd})
	} else {
		statistics = append(statistics, []string{"Longest Downtime", "Never"})
		statistics = append(statistics, []string{"Longest Consecutive Downtime Start", "Never"})
		statistics = append(statistics, []string{"Longest Consecutive Downtime End", "Never"})
	}

	if s.RetriedHostnameLookups > 0 {
		statistics = append(statistics, []string{"Hostname Resolve Retries", fmt.Sprintf("%d", s.RetriedHostnameLookups)})
	}

	if len(s.HostnameChanges) > 1 {
		var changes []string
		for i := 0; i < len(s.HostnameChanges)-1; i++ {
			if s.HostnameChanges[i].Addr.String() == "" {
				continue
			}

			changes = append(changes, fmt.Sprintf("from %s to %s at %v",
				s.HostnameChanges[i].Addr.String(),
				s.HostnameChanges[i+1].Addr.String(),
				s.HostnameChanges[i+1].When.Format(time.DateTime),
			))
		}
		statistics = append(statistics, []string{"Hostname Changes", strings.Join(changes, " | ")})
	} else {
		statistics = append(statistics, []string{"Hostname Changes", "Never changed"})
	}

	if s.LastSuccessfulProbe.IsZero() {
		statistics = append(statistics, []string{"Last Successful Probe", "Never succeeded"})
	} else {
		statistics = append(statistics, []string{"Last Successful Probe", s.LastSuccessfulProbe.Format(time.DateTime)})
	}

	if s.LastUnsuccessfulProbe.IsZero() {
		statistics = append(statistics, []string{"Last Unsuccessful Probe", "Never failed"})
	} else {
		statistics = append(statistics, []string{"Last Unsuccessful Probe", s.LastUnsuccessfulProbe.Format(time.DateTime)})
	}

	if s.RTTResults.HasResults {
		statistics = append(statistics, []string{"Latency Min", fmt.Sprintf("%.3f", s.RTTResults.Min)})
		statistics = append(statistics, []string{"Latency Avg", fmt.Sprintf("%.3f", s.RTTResults.Average)})
		statistics = append(statistics, []string{"Latency Max", fmt.Sprintf("%.3f", s.RTTResults.Max)})
	} else {
		statistics = append(statistics, []string{"Latency Min", "N/A"})
		statistics = append(statistics, []string{"Latency Avg", "N/A"})
		statistics = append(statistics, []string{"Latency Max", "N/A"})
	}

	statistics = append(statistics, []string{"Start Timestamp", s.StartTime.Format(time.DateTime)})

	if !s.EndTime.IsZero() {
		statistics = append(statistics, []string{"End Timestamp", s.EndTime.Format(time.DateTime)})
	} else {
		statistics = append(statistics, []string{"End Timestamp", "In progress"})
	}

	for _, record := range statistics {
		if err := p.StatsWriter.Write(record); err != nil {
			p.PrintError("Failed to write statistics record: %v", err)
			return
		}
	}

	fmt.Printf("\nStatistics have been saved to: %s\n", p.StatsFile.Name())
}

// PrintTotalDownTime is a no-op implementation to satisfy the Printer interface.
func (p *CSVPrinter) PrintTotalDownTime(_ *stats.Statistics) {}
