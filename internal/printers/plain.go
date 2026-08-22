package printers

import (
	"fmt"
	"math"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/edsilegx/netping/pkg/utils"
)

// PlainPrinter is a printer that prints messages without color.
type PlainPrinter struct{}

// NewPlainPrinter creates and returns a new instance of PlainPrinter.
func NewPlainPrinter() *PlainPrinter {
	return &PlainPrinter{}
}

// Shutdown sets the end time and prints statistics.
func (p *PlainPrinter) Shutdown(s *stats.Statistics) {
	s.EndTime = time.Now()
	PrintStats(p, s)
}

// PrintStart prints the start message for a TCPing session.
func (p *PlainPrinter) PrintStart(s *stats.Statistics) {
	if s.Port == 0 {
		fmt.Printf("Probing %s via ICMP\n", s.Hostname)
		return
	}
	fmt.Printf("TCPinging %s on port %d\n", s.Hostname, s.Port)
}

// PrintProbeSuccess prints a message when a probe is successful.
func (p *PlainPrinter) PrintProbeSuccess(s *stats.Statistics) {
	msg := "Reply from "

	if s.WithTimestamp {
		timestamp := time.Now().Format(time.DateTime)
		msg = fmt.Sprintf("%v %v", timestamp, msg)
	}

	hostnameAndIP := s.IPStr()
	if s.Hostname != hostnameAndIP {
		hostnameAndIP = fmt.Sprintf("%s (%s)", s.Hostname, s.IPStr())
	}

	if s.Port == 0 {
		msg += hostnameAndIP
	} else {
		msg += fmt.Sprintf("%s on port %s", hostnameAndIP, s.PortStr())
	}

	if s.WithSourceAddress {
		msg += fmt.Sprintf(" using %s", s.SourceAddr())
	}

	if s.Port == 0 {
		msg += fmt.Sprintf(" seq=%d time=%s ms\n", s.OngoingSuccessfulProbes, s.RTTStr())
	} else {
		msg += fmt.Sprintf(" TCP_conn=%d time=%s ms\n", s.OngoingSuccessfulProbes, s.RTTStr())
	}

	if s.WithDiags && s.LatestDiagnostics != "" {
		msg += fmt.Sprintf("  └─ [DIAG] %s\n", s.LatestDiagnostics)
	}

	fmt.Print(msg)
}

// PrintProbeFailure prints a message when a probe fails.
func (p *PlainPrinter) PrintProbeFailure(s *stats.Statistics) {
	msg := "No reply from "

	if s.WithTimestamp {
		timestamp := time.Now().Format(time.DateTime)
		msg = fmt.Sprintf("%v %v", timestamp, msg)
	}

	hostnameAndIP := s.IPStr()
	if s.Hostname != hostnameAndIP {
		hostnameAndIP = fmt.Sprintf("%s (%s)", s.Hostname, s.IPStr())
	}

	failureSuffix := ""
	if s.LastFailureReason != "" {
		failureSuffix = fmt.Sprintf(" (%s)", s.LastFailureReason)
	}

	if s.Port == 0 {
		msg += fmt.Sprintf("%s seq=%d%s\n", hostnameAndIP, s.OngoingUnsuccessfulProbes, failureSuffix)
	} else {
		msg += fmt.Sprintf("%s on port %s TCP_conn=%d%s\n", hostnameAndIP, s.PortStr(), s.OngoingUnsuccessfulProbes, failureSuffix)
	}

	fmt.Print(msg)
}

// PrintTotalDownTime prints the total downtime when no response is received.
func (p *PlainPrinter) PrintTotalDownTime(s *stats.Statistics) {
	fmt.Printf("No response received for %s\n", utils.DurationToString(s.DownTime))
}

// PrintRetryingToResolve prints a message indicating that the program is retrying to resolve the hostname.
func (p *PlainPrinter) PrintRetryingToResolve(hostname string) {
	fmt.Printf("Retrying to resolve %s\n", hostname)
}

// PrintError prints error messages.
func (p *PlainPrinter) PrintError(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

// PrintStatistics prints detailed statistics about the TCPing session.
func (p *PlainPrinter) PrintStatistics(s *stats.Statistics) {
	msg := fmt.Sprintf("\n--- %s TCPing statistics ---\n", s.Hostname)

	if !s.DestIsIP {
		msg = fmt.Sprintf("\n--- %s (%s) TCPing statistics ---\n",
			s.Hostname,
			s.IP)
	}

	totalPackets := s.TotalSuccessfulProbes + s.TotalUnsuccessfulProbes

	portMsg := fmt.Sprintf("on port %d", s.Port)
	if s.Port == 0 {
		portMsg = "via ICMP"
	}

	msg += fmt.Sprintf("%d probes transmitted %s | %d received, ",
		totalPackets,
		portMsg,
		s.TotalSuccessfulProbes)

	packetLoss := (float32(s.TotalUnsuccessfulProbes) / float32(totalPackets)) * 100

	if math.IsNaN(float64(packetLoss)) {
		packetLoss = 0
	}

	msg += fmt.Sprintf("%.2f%% packet loss\n", packetLoss)

	msg += fmt.Sprintf("successful probes:   %d\n", s.TotalSuccessfulProbes)
	msg += fmt.Sprintf("unsuccessful probes: %d\n", s.TotalUnsuccessfulProbes)

	if s.LastSuccessfulProbe.IsZero() {
		msg += "last successful probe:   Never succeeded\n"
	} else {
		msg += fmt.Sprintf("last successful probe:   %v\n", s.LastSuccessfulProbe.Format(time.DateTime))
	}

	if s.LastUnsuccessfulProbe.IsZero() {
		msg += "last unsuccessful probe: Never failed\n"
	} else {
		msg += fmt.Sprintf("last unsuccessful probe: %v\n", s.LastUnsuccessfulProbe.Format(time.DateTime))
	}

	msg += fmt.Sprintf("total uptime:   %s\n", utils.DurationToString(s.TotalUptime))
	msg += fmt.Sprintf("total downtime: %s\n", utils.DurationToString(s.TotalDowntime))

	if s.LongestUp.Duration != 0 {
		uptime := utils.DurationToString(s.LongestUp.Duration)
		msg += fmt.Sprintf("longest consecutive uptime:   %s from %v to %v\n",
			uptime,
			s.LongestUp.Start.Format(time.DateTime),
			s.LongestUp.End.Format(time.DateTime))
	}

	if s.LongestDown.Duration != 0 {
		downtime := utils.DurationToString(s.LongestDown.Duration)
		msg += fmt.Sprintf("longest consecutive downtime: %s from %v to %v\n",
			downtime,
			s.LongestDown.Start.Format(time.DateTime),
			s.LongestDown.End.Format(time.DateTime))
	}

	if !s.DestIsIP {
		timeNoun := "time"
		if s.RetriedHostnameLookups > 1 {
			timeNoun = "times"
		}
		msg += fmt.Sprintf("retried to resolve hostname %d %s\n", s.RetriedHostnameLookups, timeNoun)

		if len(s.HostnameChanges) > 1 {
			msg += "IP address changes:\n"
			for i := 0; i < len(s.HostnameChanges)-1; i++ {
				msg += fmt.Sprintf("  from %s to %s at %v\n",
					s.HostnameChanges[i].Addr.String(),
					s.HostnameChanges[i+1].Addr.String(),
					s.HostnameChanges[i+1].When.Format(time.DateTime))
			}
		}
	}

	if s.RTTResults.HasResults {
		rttLine := fmt.Sprintf("rtt min/avg/max: %.3f/%.3f/%.3f ms",
			s.RTTResults.Min,
			s.RTTResults.Average,
			s.RTTResults.Max)
		if s.RTTResults.Jitter > 0 {
			rttLine += fmt.Sprintf(" | jitter: %.3f ms", s.RTTResults.Jitter)
		}
		if s.RTTResults.P95 > 0 {
			rttLine += fmt.Sprintf(" | p95: %.3f ms", s.RTTResults.P95)
		}
		msg += rttLine + "\n"
	}

	msg += "--------------------------------------\n"
	msg += fmt.Sprintf("TCPing started at: %v\n", s.StartTimeFormatted())

	/* If the program was not terminated, no need to show the end time */
	if !s.EndTime.IsZero() {
		msg += fmt.Sprintf("TCPing ended at:   %v\n", s.EndTimeFormatted())
	}

	durationTime := time.Time{}.Add(s.TotalDowntime + s.TotalUptime)
	msg += fmt.Sprintf("duration (HH:MM:SS): %v\n\n", durationTime.Format(time.TimeOnly))

	fmt.Print(msg)
}
