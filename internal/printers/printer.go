// Package printers provides terminal formatters, interactive Bubble Tea TUIs,
// structured serialization (JSON, NDJSON, JSONL, CSV, TSV), and SQLite3 persistence for netping.
//
// Objectives:
//   - Render colorized terminal output with ANSI/VT escape sequences and UTF-8 box characters.
//   - Provide an interactive 120-column TUI dashboard with real-time waveform charts.
//   - Stream structured JSON, CSV, and TSV records to stdout or files.
//   - Persist historical probe records and summary statistics into SQLite databases.
//
// Core Components:
//   - Printer: Core interface defining Print(msg), PrintTotalStats(), and Done().
//   - PlainPrinter: Streamlined human-readable plain text output.
//   - JSONPrinter: JSON, Pretty-printed JSON, and NDJSON/JSONL serialization.
//   - CSVPrinter: RFC 4180 compliant CSV and TSV streaming printer.
//   - DatabasePrinter: CGo-free SQLite persistence using sqlitex prepared statement caching.
//   - DashboardModel: Bubble Tea TUI rendering real-time KPI cards and waveform graphs.
//
// Data Flow:
//
//	Prober Event -> Printer.Print() -> Formatter (Plain/JSON/CSV/DB) -> Output Destination (stdout/Disk).
package printers

import (
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/edsilegx/netping/pkg/utils"
)

// PrinterConfig holds all configuration options for Printer creation
type PrinterConfig struct {
	OutputFormat      string
	OutputFile        string
	OutputJSON        bool
	PrettyJSON        bool
	NoColor           bool
	WithTimestamp     bool
	WithSourceAddress bool
	WithDiags         bool
	OutputDBPath      string
	OutputCSVPath     string
	OutputTSVPath     string
	Target            string
	Port              uint16
}

func (p PrinterConfig) GetWithTimestamp() bool {
	return p.WithTimestamp
}

func (p PrinterConfig) GetWithSourceAddress() bool {
	return p.WithSourceAddress
}

func (p PrinterConfig) GetWithDiags() bool {
	return p.WithDiags
}

// Printer defines a set of methods that any printer implementation must provide.
// Printers are responsible for outputting information, but should not modify data or perform calculations.
type Printer interface {
	// PrintStart prints the first message to indicate the target's address and port.
	// This message is printed only once, at the very beginning.
	PrintStart(s *stats.Statistics)

	// PrintProbeSuccess should print a message after each successful probe.
	// hostname could be empty, meaning it's pinging an address.
	// streak is the number of successful consecuti`ve probes.
	PrintProbeSuccess(s *stats.Statistics)

	// PrintProbeFailure should print a message after each failed probe.
	// hostname could be empty, meaning it's pinging an address.
	// streak is the number of successful consecutive probes.
	PrintProbeFailure(s *stats.Statistics)

	// PrintRetryingToResolve should print a message with the hostname
	// it is trying to resolve an IP for.
	//
	// This is only being printed when the -r flag is applied.
	PrintRetryingToResolve(hostname string)

	// PrintTotalDownTime should print a downtime duration.
	//
	// This is being called when host was unavailable for some time
	// but the latest probe was successful (became available).
	PrintTotalDownTime(s *stats.Statistics)

	// PrintStatistics should print a message with
	// helpful statistics information.
	//
	// This is being called on exit and when user hits "Enter".
	PrintStatistics(s *stats.Statistics)

	// PrintError should print an error message.
	// Printer should also apply \n to the given string, if needed.
	PrintError(format string, args ...any)

	// Shutdown sets the EndTime, calls PrintStatistics() and Done() then exits the program.
	Shutdown(s *stats.Statistics)
}

// NewPrinter creates and returns an appropriate printer based on configuration
func NewPrinter(cfg PrinterConfig) (Printer, error) {
	if cfg.PrettyJSON && !cfg.OutputJSON {
		return nil, fmt.Errorf("--pretty has no effect without the -j flag")
	}

	switch {
	case cfg.OutputJSON:
		return NewJSONPrinter(cfg.PrettyJSON), nil

	case cfg.OutputDBPath != "":
		return NewDatabasePrinter(cfg.Target, strconv.Itoa(int(cfg.Port)), cfg.OutputDBPath)

	case cfg.OutputCSVPath != "":
		return NewCSVPrinter(cfg.OutputCSVPath)

	case cfg.OutputTSVPath != "":
		return NewTSVPrinter(cfg.OutputTSVPath)

	case cfg.NoColor:
		return NewPlainPrinter(), nil

	default:
		if !EnableVirtualTerminalProcessing() {
			return NewPlainPrinter(), nil
		}
		return NewColorPrinter(), nil
	}
}

// PrintStats is a helper method for PrintStatistics of the current printer.
// This should be used instead of directly calling the PrintStatistics
// as it makes the common calculations beforehand.
func PrintStats(p Printer, s *stats.Statistics) {
	if s.DestWasDown {
		utils.SetLongestDuration(s.StartOfDowntime, time.Since(s.StartOfDowntime), &s.LongestDowntime)
	} else {
		utils.SetLongestDuration(s.StartOfUptime, time.Since(s.StartOfUptime), &s.LongestUptime)
	}

	s.RTTResults = CalcMinAvgMaxRttTime(s.RTT)

	p.PrintStatistics(s)
}

// calcMinAvgMaxRttTime is an internal alias for CalcMinAvgMaxRttTime.
func calcMinAvgMaxRttTime(timeArr []float32) stats.RTTResult {
	return CalcMinAvgMaxRttTime(timeArr)
}

// CalcMinAvgMaxRttTime calculates min, avg, max, jitter, p95, and p99 RTT values
func CalcMinAvgMaxRttTime(timeArr []float32) stats.RTTResult {
	var result stats.RTTResult

	arrLen := len(timeArr)
	if arrLen == 0 {
		return result
	}

	var sum float32
	for _, t := range timeArr {
		sum += t
	}

	sorted := slices.Clone(timeArr)
	slices.Sort(sorted)

	result.Min = sorted[0]
	result.Max = sorted[arrLen-1]
	result.Average = sum / float32(arrLen)
	result.Jitter = utils.CalculateJitter(timeArr)

	pcts := utils.CalculatePercentilesSorted(sorted, 95, 99)
	result.P95 = pcts[0]
	result.P99 = pcts[1]
	result.HasResults = true

	return result
}
