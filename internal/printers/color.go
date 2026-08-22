package printers

import (
	"fmt"
	"math"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/edsilegx/netping/pkg/utils"
)

// ColorPrinter provides functionality for printing messages with color support.
type ColorPrinter struct{}

// NewColorPrinter creates a new ColorPrinter instance.
func NewColorPrinter() *ColorPrinter {
	return &ColorPrinter{}
}

// Shutdown sets the end time and prints statistics.
func (p *ColorPrinter) Shutdown(s *stats.Statistics) {
	s.EndTime = time.Now()
	PrintStats(p, s)
}

// PrintStart prints a message indicating the start of a TCP ping attempt.
func (p *ColorPrinter) PrintStart(s *stats.Statistics) {
	if s.Port == 0 {
		fmt.Printf("\033[38;5;244mProbing\033[0m \033[1;38;5;75m%s\033[0m \033[38;5;244mvia ICMP\033[0m\n", s.Hostname)
		return
	}
	fmt.Printf("\033[38;5;244mProbing\033[0m \033[1;38;5;75m%s\033[0m \033[38;5;244mon port\033[0m \033[1;38;5;75m%d\033[0m\n", s.Hostname, s.Port)
}

// PrintProbeSuccess prints a message indicating a successful probe response.
func (p *ColorPrinter) PrintProbeSuccess(s *stats.Statistics) {
	timestamp := ""
	if s.WithTimestamp {
		timestamp = fmt.Sprintf("\033[38;5;244m[%s]\033[0m ", time.Now().Format(time.DateTime))
	}

	hostnameAndIP := s.IPStr()
	if s.Hostname != hostnameAndIP {
		hostnameAndIP = fmt.Sprintf("%s (%s)", s.Hostname, s.IPStr())
	}

	src := ""
	if s.WithSourceAddress {
		src = fmt.Sprintf(" \033[38;5;244mvia\033[0m %s", s.SourceAddr())
	}

	portInfo := fmt.Sprintf(" on port \033[38;5;75m%d\033[0m", s.Port)
	connLabel := fmt.Sprintf("TCP_conn=\033[38;5;248m%d\033[0m", s.OngoingSuccessfulProbes)
	if s.Port == 0 {
		portInfo = ""
		connLabel = fmt.Sprintf("seq=\033[38;5;248m%d\033[0m", s.OngoingSuccessfulProbes)
	}

	fmt.Printf("%s\033[38;5;71m●\033[0m Reply from \033[1;37m%s\033[0m%s%s: %s time=\033[1;37m%s ms\033[0m\n",
		timestamp, hostnameAndIP, portInfo, src, connLabel, s.RTTStr())

	if s.WithDiags && s.LatestDiagnostics != "" {
		fmt.Printf("  \033[38;5;240m└─\033[0m \033[38;5;244m[DIAG]\033[0m \033[38;5;75m%s\033[0m\n", s.LatestDiagnostics)
	}
}

// PrintProbeFailure prints a message indicating a failed probe attempt.
func (p *ColorPrinter) PrintProbeFailure(s *stats.Statistics) {
	timestamp := ""
	if s.WithTimestamp {
		timestamp = fmt.Sprintf("\033[38;5;244m[%s]\033[0m ", time.Now().Format(time.DateTime))
	}

	hostnameAndIP := s.IPStr()
	if s.Hostname != hostnameAndIP {
		hostnameAndIP = fmt.Sprintf("%s (%s)", s.Hostname, s.IPStr())
	}

	failureSuffix := ""
	if s.LastFailureReason != "" {
		failureSuffix = fmt.Sprintf(" (\033[38;5;167m%s\033[0m)", s.LastFailureReason)
	}

	portInfo := fmt.Sprintf(" on port \033[38;5;75m%d\033[0m", s.Port)
	connLabel := fmt.Sprintf("TCP_conn=\033[38;5;248m%d\033[0m", s.OngoingUnsuccessfulProbes)
	if s.Port == 0 {
		portInfo = ""
		connLabel = fmt.Sprintf("seq=\033[38;5;248m%d\033[0m", s.OngoingUnsuccessfulProbes)
	}

	fmt.Printf("%s\033[38;5;167m✖\033[0m No reply from \033[1;37m%s\033[0m%s: %s%s\n",
		timestamp, hostnameAndIP, portInfo, connLabel, failureSuffix)
}

// PrintTotalDownTime prints the total duration of downtime when no response was received.
func (p *ColorPrinter) PrintTotalDownTime(s *stats.Statistics) {
	fmt.Printf("\033[38;5;244mNo response received for\033[0m \033[38;5;167m%s\033[0m\n", utils.DurationToString(s.DownTime))
}

// PrintRetryingToResolve prints a message indicating that the program is retrying to resolve a hostname.
func (p *ColorPrinter) PrintRetryingToResolve(hostname string) {
	fmt.Printf("\033[38;5;244mRetrying to resolve\033[0m \033[1;38;5;75m%s\033[0m\n", hostname)
}

// PrintError prints an error message in red.
func (p *ColorPrinter) PrintError(format string, args ...any) {
	fmt.Printf("\033[38;5;167mError: "+format+"\033[0m\n", args...)
}

// PrintStatistics prints a summary of TCP ping statistics.
func (p *ColorPrinter) PrintStatistics(s *stats.Statistics) {
	if !s.DestIsIP {
		fmt.Printf("\n\033[1;37m--- \033[1;38;5;75m%s (%s)\033[1;37m TCPing statistics ---\033[0m\n",
			s.Hostname,
			s.IPStr())
	} else {
		fmt.Printf("\n\033[1;37m--- \033[1;38;5;75m%s\033[1;37m TCPing statistics ---\033[0m\n", s.Hostname)
	}

	totalPackets := s.TotalSuccessfulProbes + s.TotalUnsuccessfulProbes

	lossStr := "\033[38;5;71m0.00%\033[0m"
	packetLoss := float32(0)
	if totalPackets > 0 {
		packetLoss = (float32(s.TotalUnsuccessfulProbes) / float32(totalPackets)) * 100
		if math.IsNaN(float64(packetLoss)) {
			packetLoss = 0
		}
	}
	if packetLoss > 0 && packetLoss <= 30 {
		lossStr = fmt.Sprintf("\033[38;5;221m%.2f%%\033[0m", packetLoss)
	} else if packetLoss > 30 {
		lossStr = fmt.Sprintf("\033[38;5;167m%.2f%%\033[0m", packetLoss)
	}

	portMsg := fmt.Sprintf("\033[38;5;244mon port\033[0m \033[38;5;75m%d\033[0m", s.Port)
	if s.Port == 0 {
		portMsg = "\033[38;5;244mvia ICMP\033[0m"
	}

	fmt.Printf("\033[1;37m%d\033[0m \033[38;5;244mprobes transmitted\033[0m %s \033[38;5;240m│\033[0m \033[1;37m%d\033[0m \033[38;5;244mreceived,\033[0m %s \033[38;5;244mpacket loss\033[0m\n",
		totalPackets, portMsg, s.TotalSuccessfulProbes, lossStr)

	fmt.Printf("\033[38;5;244msuccessful probes:\033[0m   \033[38;5;71m%d\033[0m\n", s.TotalSuccessfulProbes)
	fmt.Printf("\033[38;5;244munsuccessful probes:\033[0m \033[38;5;167m%d\033[0m\n", s.TotalUnsuccessfulProbes)

	if s.LastSuccessfulProbe.IsZero() {
		fmt.Printf("\033[38;5;244mlast successful probe:\033[0m   \033[38;5;244mNever succeeded\033[0m\n")
	} else {
		fmt.Printf("\033[38;5;244mlast successful probe:\033[0m   \033[38;5;250m%v\033[0m\n", s.LastSuccessfulProbe.Format(time.DateTime))
	}

	if s.LastUnsuccessfulProbe.IsZero() {
		fmt.Printf("\033[38;5;244mlast unsuccessful probe:\033[0m \033[38;5;244mNever failed\033[0m\n")
	} else {
		fmt.Printf("\033[38;5;244mlast unsuccessful probe:\033[0m \033[38;5;167m%v\033[0m\n", s.LastUnsuccessfulProbe.Format(time.DateTime))
	}

	fmt.Printf("\033[38;5;244mtotal uptime:\033[0m   \033[38;5;71m%s\033[0m\n", utils.DurationToString(s.TotalUptime))
	fmt.Printf("\033[38;5;244mtotal downtime:\033[0m \033[38;5;167m%s\033[0m\n", utils.DurationToString(s.TotalDowntime))

	if s.LongestUp.Duration != 0 {
		uptime := utils.DurationToString(s.LongestUp.Duration)
		fmt.Printf("\033[38;5;244mlongest consecutive uptime:\033[0m   \033[38;5;71m%v\033[0m \033[38;5;244mfrom\033[0m \033[38;5;250m%v\033[0m \033[38;5;244mto\033[0m \033[38;5;250m%v\033[0m\n",
			uptime, s.LongestUp.Start.Format(time.DateTime), s.LongestUp.End.Format(time.DateTime))
	}

	if s.LongestDown.Duration != 0 {
		downtime := utils.DurationToString(s.LongestDown.Duration)
		fmt.Printf("\033[38;5;244mlongest consecutive downtime:\033[0m \033[38;5;167m%v\033[0m \033[38;5;244mfrom\033[0m \033[38;5;250m%v\033[0m \033[38;5;244mto\033[0m \033[38;5;250m%v\033[0m\n",
			downtime, s.LongestDown.Start.Format(time.DateTime), s.LongestDown.End.Format(time.DateTime))
	}

	if !s.DestIsIP {
		timeNoun := "time"
		if s.RetriedHostnameLookups > 1 {
			timeNoun = "times"
		}
		fmt.Printf("\033[38;5;244mretried to resolve hostname:\033[0m  \033[1;37m%d\033[0m \033[38;5;244m%s\033[0m\n", s.RetriedHostnameLookups, timeNoun)

		if len(s.HostnameChanges) > 1 {
			fmt.Printf("\033[38;5;244mIP address changes:\033[0m\n")
			for i := 0; i < len(s.HostnameChanges)-1; i++ {
				fmt.Printf("  \033[38;5;244mfrom\033[0m \033[38;5;167m%s\033[0m \033[38;5;244mto\033[0m \033[38;5;71m%s\033[0m \033[38;5;244mat\033[0m \033[38;5;250m%v\033[0m\n",
					s.HostnameChanges[i].Addr.String(), s.HostnameChanges[i+1].Addr.String(), s.HostnameChanges[i+1].When.Format(time.DateTime))
			}
		}
	}

	if s.RTTResults.HasResults {
		fmt.Printf("\033[38;5;244mrtt min/avg/max:\033[0m \033[1;37m%.3f\033[0m/\033[1;37m%.3f\033[0m/\033[1;37m%.3f\033[0m \033[38;5;244mms\033[0m",
			s.RTTResults.Min, s.RTTResults.Average, s.RTTResults.Max)
		if s.RTTResults.Jitter > 0 {
			fmt.Printf(" \033[38;5;240m│\033[0m \033[38;5;244mjitter:\033[0m \033[1;37m%.3f ms\033[0m", s.RTTResults.Jitter)
		}
		if s.RTTResults.P95 > 0 {
			fmt.Printf(" \033[38;5;240m│\033[0m \033[38;5;244mp95:\033[0m \033[38;5;221m%.3f ms\033[0m", s.RTTResults.P95)
		}
		fmt.Print("\n")
	}

	fmt.Printf("\033[38;5;240m--------------------------------------\033[0m\n")
	fmt.Printf("\033[38;5;244mTCPing started at:\033[0m   \033[38;5;250m%v\033[0m\n", s.StartTimeFormatted())

	if !s.EndTime.IsZero() {
		fmt.Printf("\033[38;5;244mTCPing ended at:\033[0m     \033[38;5;250m%v\033[0m\n", s.EndTimeFormatted())
	}

	durationTime := time.Time{}.Add(s.TotalDowntime + s.TotalUptime)
	fmt.Printf("\033[38;5;244mduration (HH:MM:SS):\033[0m \033[1;37m%v\033[0m\n\n", durationTime.Format(time.TimeOnly))
}
