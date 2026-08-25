package printers

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/edsilegx/netping/pkg/utils"
)

// JSONEventType is a special type for each method
// in the printer interface so that automatic tools
// can understand what kind of an event they've received.
type JSONEventType string

const (
	startEvent        JSONEventType = "start"        // Event type for `PrintStart` method.
	probeEvent        JSONEventType = "probe"        // Event type for both `PrintProbeSuccess` and `PrintProbeFail`.
	retryEvent        JSONEventType = "retry"        // Event type for `PrintRetryingToResolve` method.
	retrySuccessEvent JSONEventType = "retrySuccess" // Event type for `PrintTotalDowntime` method.
	statisticsEvent   JSONEventType = "statistics"   // Event type for `PrintStatistics` method.
	infoEvent         JSONEventType = "info"         // Event type for `PrintInfo` method.
	errorEvent        JSONEventType = "error"        // Event type for `PrintError` method.
)

// JSONData contains all possible fields for JSON output.
type JSONData struct {
	Type                            JSONEventType          `json:"type"`
	Success                         *bool                  `json:"success,omitempty"`
	Timestamp                       string                 `json:"timestamp,omitempty"`
	Message                         string                 `json:"message"`
	IPAddr                          string                 `json:"ipAddress,omitempty"`
	Hostname                        string                 `json:"hostname,omitempty"`
	Port                            uint16                 `json:"port,omitempty"`
	TotalDuration                   string                 `json:"totalDuration,omitempty"`
	TotalUptime                     string                 `json:"totalUptime,omitempty"`
	TotalDowntime                   string                 `json:"totalDowntime,omitempty"`
	TotalPackets                    uint                   `json:"totalPackets,omitempty"`
	TotalSuccessfulPackets          uint                   `json:"totalSuccessfulPackets,omitempty"`
	TotalUnsuccessfulPackets        uint                   `json:"totalUnsuccessfulPackets,omitempty"`
	TotalPacketLossPercent          string                 `json:"totalPacketLossPercent,omitempty"`
	LongestUp                       string                 `json:"longestUp,omitempty"`
	LongestDown                     string                 `json:"longestDowntime,omitempty"`
	SourceAddr                      string                 `json:"sourceAddress,omitempty"`
	HostnameResolveRetries          uint                   `json:"hostnameResolveRetries,omitempty"`
	HostnameChanges                 []stats.HostnameChange `json:"hostnameChanges,omitempty"`
	DestIsIP                        *bool                  `json:"destinationIsIP,omitempty"`
	Time                            string                 `json:"time,omitempty"`
	LastSuccessfulProbe             string                 `json:"lastSuccessfulProbe,omitempty"`
	LastUnsuccessfulProbe           string                 `json:"lastUnsuccessfulProbe,omitempty"`
	LongestConsecutiveUptimeStart   string                 `json:"longestConsecutiveUptimeStart,omitempty"`
	LongestConsecutiveUptimeEnd     string                 `json:"longestConsecutiveUptimeEnd,omitempty"`
	LongestConsecutiveDowntimeStart string                 `json:"longestConsecutiveDowntimeStart,omitempty"`
	LongestConsecutiveDowntimeEnd   string                 `json:"longestConsecutiveDowntimeEnd,omitempty"`
	Latency                         float32                `json:"latency,omitempty"`
	LatencyMin                      string                 `json:"latencyMin,omitempty"`
	LatencyAvg                      string                 `json:"latencyAvg,omitempty"`
	LatencyMax                      string                 `json:"latencyMax,omitempty"`
	OngoingSuccessfulProbes         uint                   `json:"ongoingSuccessfulProbes,omitempty"`
	OngoingUnsuccessfulProbes       uint                   `json:"ongoingUnsuccessfulProbes,omitempty"`
	StartTimestamp                  string                 `json:"startTime,omitempty"`
	EndTimestamp                    string                 `json:"endTime,omitempty"`
}

// JSONPrinter is a struct that holds a JSON encoder to print structured JSON output.
type JSONPrinter struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

// NewJSONPrinter creates a new JSONPrinter instance writing to os.Stdout.
func NewJSONPrinter(pretty bool) *JSONPrinter {
	return NewJSONWriterPrinter(os.Stdout, pretty)
}

// NewJSONWriterPrinter creates a new JSONPrinter instance writing to any custom io.Writer.
func NewJSONWriterPrinter(w io.Writer, pretty bool) *JSONPrinter {
	encoder := json.NewEncoder(w)

	if pretty {
		encoder.SetIndent("", "\t")
	}

	return &JSONPrinter{encoder: encoder}
}

// Shutdown sets the end time and prints statistics.
func (p *JSONPrinter) Shutdown(s *stats.Statistics) {
	s.EndTime = time.Now()
	PrintStats(p, s)
}

// PrintStart prints the initial message before doing probes.
func (p *JSONPrinter) PrintStart(s *stats.Statistics) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.encoder.Encode(JSONData{
		Type:     startEvent,
		Message:  fmt.Sprintf("TCPinging %s on port %d", s.Hostname, s.Port),
		Hostname: s.Hostname,
		Port:     s.Port,
	})
}

// PrintProbeSuccess prints successful TCP probe replies in JSON format.
func (p *JSONPrinter) PrintProbeSuccess(s *stats.Statistics) {
	f := false
	t := true

	data := JSONData{
		Type:                    probeEvent,
		Hostname:                s.Hostname,
		IPAddr:                  s.IPStr(),
		Port:                    s.Port,
		Time:                    s.RTTStr(),
		DestIsIP:                &t,
		Success:                 &t,
		OngoingSuccessfulProbes: s.OngoingSuccessfulProbes,
	}

	timestamp := ""
	if s.WithTimestamp {
		timestamp = time.Now().Format(time.DateTime)
	}

	if s.Hostname == s.IPStr() {
		data.Hostname = ""

		if timestamp == "" {
			if s.WithSourceAddress {
				data.Message = fmt.Sprintf("Reply from %s on port %d using %s TCP_conn=%d time=%s ms",
					s.IP.String(),
					s.Port,
					s.SourceAddr(),
					s.OngoingSuccessfulProbes,
					s.RTTStr())
			} else {
				data.Message = fmt.Sprintf("Reply from %s on port %d TCP_conn=%d time=%s ms",
					s.IP.String(),
					s.Port,
					s.OngoingSuccessfulProbes,
					s.RTTStr())
			}
		} else {
			data.Timestamp = timestamp
			if s.WithSourceAddress {
				data.Message = fmt.Sprintf("%s Reply from %s on port %d using %s TCP_conn=%d time=%s ms",
					timestamp,
					s.IP.String(),
					s.Port,
					s.SourceAddr(),
					s.OngoingSuccessfulProbes,
					s.RTTStr())
			} else {
				data.Message = fmt.Sprintf("%s Reply from %s on port %d TCP_conn=%d time=%s ms",
					timestamp,
					s.IP.String(),
					s.Port,
					s.OngoingSuccessfulProbes,
					s.RTTStr())
			}
		}
	} else {
		data.DestIsIP = &f

		if timestamp == "" {
			if s.WithSourceAddress {
				data.Message = fmt.Sprintf("Reply from %s (%s) on port %d using %s TCP_conn=%d time=%s ms",
					s.Hostname,
					s.IP.String(),
					s.Port,
					s.SourceAddr(),
					s.OngoingSuccessfulProbes,
					s.RTTStr())
			} else {
				data.Message = fmt.Sprintf("Reply from %s (%s) on port %d TCP_conn=%d time=%s ms",
					s.Hostname,
					s.IP.String(),
					s.Port,
					s.OngoingSuccessfulProbes,
					s.RTTStr())
			}
		} else {
			data.Timestamp = timestamp
			if s.WithSourceAddress {
				data.Message = fmt.Sprintf("%s Reply from %s (%s) on port %d using %s TCP_conn=%d time=%s ms",
					timestamp,
					s.Hostname,
					s.IP.String(),
					s.Port,
					s.SourceAddr(),
					s.OngoingSuccessfulProbes,
					s.RTTStr())
			} else {
				data.Message = fmt.Sprintf("%s Reply from %s (%s) on port %d TCP_conn=%d time=%s ms",
					timestamp,
					s.Hostname,
					s.IP.String(),
					s.Port,
					s.OngoingSuccessfulProbes,
					s.RTTStr())
			}
		}
	}

	if s.WithSourceAddress {
		data.SourceAddr = s.SourceAddr()
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.encoder.Encode(data)
}

// PrintProbeFailure prints failed probe attempts in JSON format.
func (p *JSONPrinter) PrintProbeFailure(s *stats.Statistics) {
	f := false
	t := true

	data := JSONData{
		Type:                      probeEvent,
		Hostname:                  s.Hostname,
		IPAddr:                    s.IPStr(),
		Port:                      s.Port,
		DestIsIP:                  &t,
		Success:                   &f,
		OngoingUnsuccessfulProbes: s.OngoingUnsuccessfulProbes,
	}

	timestamp := ""
	if s.WithTimestamp {
		timestamp = time.Now().Format(time.DateTime)
	}

	if s.Hostname == s.IPStr() {
		data.Hostname = ""

		if timestamp == "" {
			data.Message = fmt.Sprintf("No reply from %s on port %d TCP_conn=%d",
				s.IP.String(),
				s.Port,
				s.OngoingUnsuccessfulProbes)
		} else {
			data.Timestamp = timestamp
			data.Message = fmt.Sprintf("%s No reply from %s on port %d TCP_conn=%d",
				timestamp,
				s.IP.String(),
				s.Port,
				s.OngoingUnsuccessfulProbes)
		}
	} else {
		data.DestIsIP = &f

		if timestamp == "" {
			data.Message = fmt.Sprintf("No reply from %s (%s) on port %d TCP_conn=%d",
				s.Hostname,
				s.IP.String(),
				s.Port,
				s.OngoingUnsuccessfulProbes)
		} else {
			data.Timestamp = timestamp
			data.Message = fmt.Sprintf("%s No reply from %s (%s) on port %d TCP_conn=%d",
				timestamp,
				s.Hostname,
				s.IP.String(),
				s.Port,
				s.OngoingUnsuccessfulProbes)
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.encoder.Encode(data)
}

// PrintRetryingToResolve prints a message indicating retry attempt to resolve hostname.
func (p *JSONPrinter) PrintRetryingToResolve(hostname string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.encoder.Encode(JSONData{
		Type:     retryEvent,
		Message:  fmt.Sprintf("Retrying to resolve %s", hostname),
		Hostname: hostname,
	})
}

// PrintTotalDownTime prints the total duration of downtime when no response was received.
func (p *JSONPrinter) PrintTotalDownTime(s *stats.Statistics) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.encoder.Encode(JSONData{
		Type:          retrySuccessEvent,
		Message:       fmt.Sprintf("No response received for %s", utils.DurationToString(s.DownTime)),
		TotalDowntime: utils.DurationToString(s.DownTime),
	})
}

// PrintError prints error messages.
func (p *JSONPrinter) PrintError(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.encoder.Encode(JSONData{
		Type:    errorEvent,
		Message: fmt.Sprintf(format, args...),
	})
}

// PrintStatistics prints detailed statistics about the TCPing session.
func (p *JSONPrinter) PrintStatistics(s *stats.Statistics) {
	f := false
	t := true

	totalPackets := s.TotalSuccessfulProbes + s.TotalUnsuccessfulProbes
	packetLoss := (float32(s.TotalUnsuccessfulProbes) / float32(totalPackets)) * 100

	if math.IsNaN(float64(packetLoss)) {
		packetLoss = 0
	}

	data := JSONData{
		Type:                     statisticsEvent,
		Message:                  fmt.Sprintf("--- %s TCPing statistics ---", s.Hostname),
		Hostname:                 s.Hostname,
		IPAddr:                   s.IPStr(),
		Port:                     s.Port,
		DestIsIP:                 &t,
		TotalDuration:            time.Time{}.Add(s.TotalDowntime + s.TotalUptime).Format(time.TimeOnly),
		TotalUptime:              utils.DurationToString(s.TotalUptime),
		TotalDowntime:            utils.DurationToString(s.TotalDowntime),
		TotalPackets:             totalPackets,
		TotalSuccessfulPackets:   s.TotalSuccessfulProbes,
		TotalUnsuccessfulPackets: s.TotalUnsuccessfulProbes,
		TotalPacketLossPercent:   fmt.Sprintf("%.2f%%", packetLoss),
		StartTimestamp:           s.StartTimeFormatted(),
	}

	if s.Hostname != s.IPStr() {
		data.DestIsIP = &f
		data.Message = fmt.Sprintf("--- %s (%s) TCPing statistics ---", s.Hostname, s.IPStr())
		data.HostnameResolveRetries = s.RetriedHostnameLookups
		data.HostnameChanges = s.HostnameChanges
	}

	if !s.EndTime.IsZero() {
		data.EndTimestamp = s.EndTimeFormatted()
	}

	if s.LastSuccessfulProbe.IsZero() {
		data.LastSuccessfulProbe = "Never succeeded"
	} else {
		data.LastSuccessfulProbe = s.LastSuccessfulProbe.Format(time.DateTime)
	}

	if s.LastUnsuccessfulProbe.IsZero() {
		data.LastUnsuccessfulProbe = "Never failed"
	} else {
		data.LastUnsuccessfulProbe = s.LastUnsuccessfulProbe.Format(time.DateTime)
	}

	if s.LongestUp.Duration != 0 {
		data.LongestUp = utils.DurationToString(s.LongestUp.Duration)
		data.LongestConsecutiveUptimeStart = s.LongestUp.Start.Format(time.DateTime)
		data.LongestConsecutiveUptimeEnd = s.LongestUp.End.Format(time.DateTime)
	}

	if s.LongestDown.Duration != 0 {
		data.LongestDown = utils.DurationToString(s.LongestDown.Duration)
		data.LongestConsecutiveDowntimeStart = s.LongestDown.Start.Format(time.DateTime)
		data.LongestConsecutiveDowntimeEnd = s.LongestDown.End.Format(time.DateTime)
	}

	if s.RTTResults.HasResults {
		data.LatencyMin = fmt.Sprintf("%.3f", s.RTTResults.Min)
		data.LatencyAvg = fmt.Sprintf("%.3f", s.RTTResults.Average)
		data.LatencyMax = fmt.Sprintf("%.3f", s.RTTResults.Max)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.encoder.Encode(data)
}
