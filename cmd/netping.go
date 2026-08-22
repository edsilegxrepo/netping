// netping.go - Multi-protocol network latency and diagnostics prober.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/edsilegx/netping/internal/app"
	"github.com/edsilegx/netping/internal/config"
	"github.com/edsilegx/netping/internal/printers"
	"github.com/edsilegx/netping/pkg/consts"
	"github.com/edsilegx/netping/pkg/metrics"
	"github.com/edsilegx/netping/pkg/probers"
	"github.com/edsilegx/netping/pkg/stats"
	"github.com/edsilegx/netping/pkg/utils"
	"github.com/edsilegx/netping/pkg/web"
)

// monitorSummaryRequest checks stdin to see whether the 'Enter' key was pressed
// if so, it prints the statistics
func monitorSummaryRequest(ctx context.Context, p printers.Printer, s *stats.Statistics) {
	reader := bufio.NewReader(os.Stdin)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		input, err := reader.ReadString('\n')
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		if strings.TrimSpace(input) == "" {
			printers.PrintStats(p, s)
		}
	}
}

func buildPingerForTarget(tCfg config.TargetConfig, cfg config.Config, dialer *net.Dialer) probers.Pinger {
	svc := tCfg.ServiceName
	if svc == "" {
		svc = cfg.ServiceName
	}
	switch tCfg.Protocol {
	case consts.HTTP, consts.HTTPS:
		return probers.NewHTTPing(probers.HTTPOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Protocol: tCfg.Protocol,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.UDP:
		return probers.NewUDPing(probers.UDPOptions{
			IP:         tCfg.IP,
			Port:       tCfg.Port,
			Timeout:    cfg.Timeout,
			Dialer:     dialer,
			SendData:   cfg.SendData,
			ExpectData: cfg.ExpectData,
		})
	case consts.ICMP:
		return probers.NewICMPing(probers.ICMPOptions{
			IP:      tCfg.IP,
			Timeout: cfg.Timeout,
			UseIPv6: cfg.UseIPv6,
		})
	case consts.GRPC:
		return probers.NewGRPCing(probers.GRPCOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.WS:
		return probers.NewWSing(probers.WSOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   false,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.WSS:
		return probers.NewWSing(probers.WSOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.DNS:
		return probers.NewDNSQueryProber(probers.DNSQueryOptions{
			Nameserver: tCfg.Host,
			IP:         tCfg.IP,
			Port:       tCfg.Port,
			Domains:    cfg.DNSHosts,
			Domain:     tCfg.Host,
			IsDoH:      false,
			Timeout:    cfg.Timeout,
			Dialer:     dialer,
		})
	case consts.DOH:
		return probers.NewDNSQueryProber(probers.DNSQueryOptions{
			Nameserver: tCfg.Host,
			IP:         tCfg.IP,
			Port:       tCfg.Port,
			Domains:    cfg.DNSHosts,
			Domain:     tCfg.Host,
			IsDoH:      true,
			Timeout:    cfg.Timeout,
			Dialer:     dialer,
		})
	case consts.REDIS:
		return probers.NewRedising(probers.RedisOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.SSH:
		return probers.NewSSHing(probers.SSHOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.POSTGRES:
		return probers.NewDBing(probers.DBOptions{
			Type:     probers.PostgreSQL,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.MYSQL:
		return probers.NewDBing(probers.DBOptions{
			Type:     probers.MySQL,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.MSSQL:
		return probers.NewDBing(probers.DBOptions{
			Type:     probers.MSSQL,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.ORACLE:
		return probers.NewDBing(probers.DBOptions{
			Type:        probers.Oracle,
			Hostname:    tCfg.Host,
			IP:          tCfg.IP,
			Port:        tCfg.Port,
			ServiceName: svc,
			Timeout:     cfg.Timeout,
			Dialer:      dialer,
		})
	case consts.MONGODB:
		return probers.NewDBing(probers.DBOptions{
			Type:     probers.MongoDB,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.MONGODBS:
		return probers.NewDBing(probers.DBOptions{
			Type:     probers.MongoDB,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.CASSANDRA:
		return probers.NewDBing(probers.DBOptions{
			Type:     probers.Cassandra,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.CASSANDRAS:
		return probers.NewDBing(probers.DBOptions{
			Type:     probers.Cassandra,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.SAPHANA:
		return probers.NewDBing(probers.DBOptions{
			Type:     probers.SAPHANA,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.MEMCACHED:
		return probers.NewMemcacheding(probers.MemcachedOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.SMTP:
		return probers.NewMailing(probers.MailOptions{
			Protocol: probers.MailSMTP,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   false,
			StartTLS: cfg.StartTLS,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.SMTPS:
		return probers.NewMailing(probers.MailOptions{
			Protocol: probers.MailSMTP,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			StartTLS: false,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.IMAP:
		return probers.NewMailing(probers.MailOptions{
			Protocol: probers.MailIMAP,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   false,
			StartTLS: cfg.StartTLS,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.IMAPS:
		return probers.NewMailing(probers.MailOptions{
			Protocol: probers.MailIMAP,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			StartTLS: false,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.TLS:
		return probers.NewTLSing(probers.TLSOptions{
			Hostname:  tCfg.Host,
			IP:        tCfg.IP,
			Port:      tCfg.Port,
			Timeout:   cfg.Timeout,
			Dialer:    dialer,
			FastClose: cfg.FastClose,
		})
	case consts.GRPCS:
		return probers.NewGRPCing(probers.GRPCOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.DOT:
		return probers.NewDNSQueryProber(probers.DNSQueryOptions{
			Nameserver: tCfg.Host,
			IP:         tCfg.IP,
			Port:       tCfg.Port,
			Domains:    cfg.DNSHosts,
			Domain:     tCfg.Host,
			IsDoT:      true,
			Timeout:    cfg.Timeout,
			Dialer:     dialer,
		})
	case consts.REDISS:
		return probers.NewRedising(probers.RedisOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.MEMCACHEDS:
		return probers.NewMemcacheding(probers.MemcachedOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.POP3:
		return probers.NewMailing(probers.MailOptions{
			Protocol: probers.MailPOP3,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   false,
			StartTLS: cfg.StartTLS,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.POP3S:
		return probers.NewMailing(probers.MailOptions{
			Protocol: probers.MailPOP3,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			StartTLS: false,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.LDAP:
		return probers.NewLDAPing(probers.LDAPOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   false,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.LDAPS:
		return probers.NewLDAPing(probers.LDAPOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.O365:
		return probers.NewO365ing(probers.O365Options{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.S3:
		return probers.NewStorageing(probers.StorageOptions{
			Type:     probers.StorageS3,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.AZUREBLOB:
		return probers.NewStorageing(probers.StorageOptions{
			Type:     probers.StorageAzureBlob,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.GCS:
		return probers.NewStorageing(probers.StorageOptions{
			Type:     probers.StorageGCS,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.KAFKA:
		return probers.NewQueueing(probers.QueueOptions{
			Protocol: probers.QueueKafka,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   false,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.KAFKAS:
		return probers.NewQueueing(probers.QueueOptions{
			Protocol: probers.QueueKafka,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.RABBITMQ, consts.AMQP:
		return probers.NewQueueing(probers.QueueOptions{
			Protocol: probers.QueueRabbitMQ,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   false,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.AMQPS:
		return probers.NewQueueing(probers.QueueOptions{
			Protocol: probers.QueueRabbitMQ,
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.SMB:
		return probers.NewSMBing(probers.SMBOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.RSYNC:
		return probers.NewRsyncing(probers.RsyncOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.FTP:
		return probers.NewFTPing(probers.FTPOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   false,
			StartTLS: cfg.StartTLS,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.FTPS:
		return probers.NewFTPing(probers.FTPOptions{
			Hostname: tCfg.Host,
			IP:       tCfg.IP,
			Port:     tCfg.Port,
			UseTLS:   true,
			StartTLS: false,
			Timeout:  cfg.Timeout,
			Dialer:   dialer,
		})
	case consts.TCP:
		fallthrough
	default:
		return probers.NewTcping(probers.TCPOptions{
			Hostname:   tCfg.Host,
			IP:         tCfg.IP,
			Port:       tCfg.Port,
			Timeout:    cfg.Timeout,
			Dialer:     dialer,
			SendData:   cfg.SendData,
			ExpectData: cfg.ExpectData,
			FastClose:  cfg.FastClose,
		})
	}
}

func main() {
	cfg := config.ProcessUserInput()

	printer, err := printers.NewPrinter(cfg.PrinterConfig)
	if err != nil {
		fmt.Printf("Failed to create printer: %s\n", err)
		os.Exit(1)
	}
	defer func() {
		if c, ok := printer.(interface{ Done() }); ok {
			c.Done()
		}
	}()

	probeCtx, cancel := app.SetupSignalHandler(context.Background())
	defer cancel()

	if cfg.TracerouteMode {
		for i, tCfg := range cfg.TargetConfigs {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("traceroute to %s:%d (%s), 30 hops max, %s probe\n", tCfg.Host, tCfg.Port, tCfg.IP, tCfg.Protocol)
			_, err := probers.RunTraceroute(probeCtx, probers.TracerouteOptions{
				Target:   tCfg.Host,
				IP:       tCfg.IP,
				Port:     tCfg.Port,
				Protocol: tCfg.Protocol,
				MaxHops:  30,
				Probes:   3,
				Timeout:  cfg.Timeout,
			}, func(hop probers.TraceHop) {
				if hop.Timeout && len(hop.RTTs) == 0 {
					fmt.Printf("%2d  * * *\n", hop.Hop)
				} else {
					addrStr := "*"
					if hop.Addr != nil {
						addrStr = hop.Addr.String()
					}
					if hop.Hostname != "" {
						addrStr = fmt.Sprintf("%s (%s)", hop.Hostname, addrStr)
					}
					rttStr := ""
					for _, r := range hop.RTTs {
						rttStr += fmt.Sprintf("  %6.2f ms", r.Seconds()*1000)
					}
					fmt.Printf("%2d  %-35s%s\n", hop.Hop, addrStr, rttStr)
				}
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				fmt.Printf("traceroute error: %v\n", err)
			}
		}
		return
	}

	var dialer *net.Dialer
	if cfg.NetworkInterface.Use {
		dialer = &cfg.NetworkInterface.Dialer
	}

	var localAddr net.Addr
	if cfg.NetworkInterface.Use && cfg.NetworkInterface.Dialer.LocalAddr != nil {
		localAddr = cfg.NetworkInterface.Dialer.LocalAddr
	}

	if len(cfg.TargetConfigs) > 1 {
		workers := make([]probers.TargetWorker, 0, len(cfg.TargetConfigs))
		for _, tCfg := range cfg.TargetConfigs {
			workerPinger := buildPingerForTarget(tCfg, cfg, dialer)
			workerStats := stats.NewStatistics(stats.Options{
				Hostname:          tCfg.Host,
				IP:                tCfg.IP,
				Port:              tCfg.Port,
				Protocol:          tCfg.Protocol,
				TargetIsIP:        tCfg.TargetIsIP,
				LocalAddr:         localAddr,
				WithTimestamp:     cfg.PrinterConfig.WithTimestamp,
				WithSourceAddress: cfg.PrinterConfig.WithSourceAddress,
				WithDiags:         cfg.PrinterConfig.WithDiags,
			})
			workers = append(workers, probers.TargetWorker{
				Target:      fmt.Sprintf("%s:%d", tCfg.Host, tCfg.Port),
				Host:        tCfg.Host,
				IP:          tCfg.IP,
				Port:        tCfg.Port,
				Protocol:    tCfg.Protocol,
				ServiceName: tCfg.ServiceName,
				Pinger:      workerPinger,
				Stats:       workerStats,
			})
		}

		var broadcaster *web.Broadcaster
		if cfg.EnableWeb {
			webAddr := cfg.WebAddr
			if webAddr == "" {
				webAddr = "127.0.0.1:3000"
			}
			broadcaster = web.NewBroadcaster()
			webServer := web.NewServer(webAddr, workers[0].Stats, broadcaster)
			_ = webServer.Start(probeCtx)
		}

		var multiDash *printers.MultiDashboardPrinter
		if cfg.ShowDashboard {
			if !printers.EnableVirtualTerminalProcessing() {
				fmt.Fprintln(os.Stderr, "Warning: Terminal does not support Virtual Terminal processing. Disabling dashboard mode.")
			} else {
				fleetTargets := make([]printers.FleetTarget, 0, len(workers))
				for _, w := range workers {
					fleetTargets = append(fleetTargets, printers.FleetTarget{
						Target:      w.Target,
						Host:        w.Host,
						Port:        w.Port,
						Protocol:    string(w.Protocol),
						ServiceName: w.ServiceName,
						Stats:       w.Stats,
					})
				}
				multiDash = printers.NewMultiDashboardPrinter(fleetTargets, printer)
				multiDash.SetCancel(cancel)
				defer multiDash.Close()
			}
		}

		onMultiProbe := func(res probers.ProbeResult, w probers.TargetWorker, seq uint) {
			if multiDash != nil {
				diagStr := ""
				if cfg.ShowDiags {
					diagStr = res.Diagnostics
				}
				ipStr := ""
				if w.Stats != nil && w.Stats.IP.IsValid() {
					ipStr = w.Stats.IP.String()
				}
				multiDash.OnProbe(w.Target, string(w.Protocol), res.RTT, diagStr, res.Err, seq, ipStr)
			}

			if cfg.PrinterConfig.OutputCSVPath != "" || cfg.PrinterConfig.OutputTSVPath != "" || cfg.PrinterConfig.OutputDBPath != "" {
				if res.Err == nil {
					printer.PrintProbeSuccess(w.Stats)
				} else {
					printer.PrintProbeFailure(w.Stats)
				}
			}

			if cfg.EnableWeb && broadcaster != nil {
				w.Stats.Mu.RLock()
				total := w.Stats.TotalSuccessfulProbes + w.Stats.TotalUnsuccessfulProbes
				loss := float64(0)
				if total > 0 {
					loss = float64(w.Stats.TotalUnsuccessfulProbes) / float64(total) * 100.0
				}
				rttRes := printers.CalcMinAvgMaxRttTime(w.Stats.RTT)
				ipStr := w.Stats.IP.String()
				hostname := w.Stats.Hostname
				port := w.Stats.Port
				w.Stats.Mu.RUnlock()

				proto := strings.ToUpper(string(w.Protocol))
				if proto == "" {
					proto = "TCP"
				}

				targetDisplay := fmt.Sprintf("%s:%d", hostname, port)
				if hostname == "" || hostname == ipStr {
					targetDisplay = fmt.Sprintf("%s:%d", ipStr, port)
				}

				diagStr := ""
				if cfg.ShowDiags {
					diagStr = res.Diagnostics
				}

				broadcaster.Broadcast(web.ProbeEvent{
					Sequence:     total,
					Success:      res.Err == nil,
					RTT:          res.RTT.Seconds() * 1000,
					Target:       targetDisplay,
					Hostname:     hostname,
					IP:           ipStr,
					Port:         port,
					Protocol:     proto,
					Diagnostics:  diagStr,
					Error:        utils.ClassifyError(res.Err),
					TotalSent:    total,
					TotalSuccess: w.Stats.TotalSuccessfulProbes,
					TotalFailed:  w.Stats.TotalUnsuccessfulProbes,
					PacketLoss:   loss,
					AvgRTT:       float64(rttRes.Average),
					MinRTT:       float64(rttRes.Min),
					MaxRTT:       float64(rttRes.Max),
					P95RTT:       float64(rttRes.P95),
					P99RTT:       float64(rttRes.P99),
				})
			}
		}

		if cfg.MetricsAddr != "" {
			statsList := make([]*stats.Statistics, 0, len(workers))
			for _, w := range workers {
				statsList = append(statsList, w.Stats)
			}
			metrics.StartMultiMetricsServer(probeCtx, cfg.MetricsAddr, statsList)
		}

		multiProber := probers.NewMultiProber(workers, probers.MultiProberOptions{
			ProbeCount:          cfg.ProbesBeforeQuit,
			Interval:            cfg.IntervalBetweenProbes,
			Timeout:             cfg.Timeout,
			Concurrency:         cfg.Concurrency,
			ShowDiags:           cfg.ShowDiags,
			NoColor:             cfg.PrinterConfig.NoColor,
			QuietMode:           cfg.QuietMode,
			WithTimestamp:       cfg.PrinterConfig.WithTimestamp,
			ShowSourceAddress:   cfg.PrinterConfig.WithSourceAddress,
			ShowFailuresOnly:    cfg.ShowFailuresOnly,
			MaxLatency:          cfg.MaxLatency,
			MaxConsecutiveFails: cfg.MaxConsecutiveFails,
			Retries:             cfg.Retries,
			InitialRetryBackoff: cfg.InitialRetryBackoff,
			MaxRetryBackoff:     cfg.MaxRetryBackoff,
			RetryJitter:         cfg.RetryJitter,
			HideLiveLogs:        multiDash != nil,
			OnProbeEvent:        onMultiProbe,
		})

		multiProber.Run(probeCtx)

		if multiDash != nil {
			multiDash.Close()
			multiProber.PrintSummaryTable()
		}

		if cfg.PrinterConfig.OutputCSVPath != "" || cfg.PrinterConfig.OutputTSVPath != "" || cfg.PrinterConfig.OutputDBPath != "" {
			for _, w := range workers {
				printer.PrintStatistics(w.Stats)
			}
		}

		if probeCtx.Err() == context.Canceled {
			os.Exit(consts.ExitInterrupted)
		}
		var totalSucc, totalFail uint
		for _, w := range workers {
			w.Stats.Mu.RLock()
			totalSucc += w.Stats.TotalSuccessfulProbes
			totalFail += w.Stats.TotalUnsuccessfulProbes
			w.Stats.Mu.RUnlock()
		}
		if totalSucc == 0 && totalFail > 0 {
			os.Exit(consts.ExitTargetUnreachable)
		} else if totalFail > 0 {
			os.Exit(consts.ExitPartialPacketLoss)
		}
		return
	}

	pinger := buildPingerForTarget(cfg.TargetConfigs[0], cfg, dialer)

	stat := stats.NewStatistics(stats.Options{
		Hostname:          cfg.Hostname,
		IP:                cfg.IP,
		Port:              cfg.Port,
		Protocol:          cfg.Protocol,
		TargetIsIP:        cfg.TargetIsIP,
		LocalAddr:         localAddr,
		WithTimestamp:     cfg.PrinterConfig.WithTimestamp,
		WithSourceAddress: cfg.PrinterConfig.WithSourceAddress,
		WithDiags:         cfg.PrinterConfig.WithDiags,
	})

	var dashPrinter *printers.DashboardPrinter
	if cfg.ShowDashboard {
		if !printers.EnableVirtualTerminalProcessing() {
			fmt.Fprintln(os.Stderr, "Warning: Terminal does not support Virtual Terminal processing. Disabling dashboard mode.")
		} else {
			dashPrinter = printers.NewDashboardPrinter(cfg.Hostname, cfg.Port, string(cfg.Protocol), stat, printer)
			dashPrinter.SetCancel(cancel)
			defer dashPrinter.Close()
			printer = dashPrinter
		}
	}

	var onProbe func(res probers.ProbeResult, s *stats.Statistics)
	if cfg.EnableWeb {
		webAddr := cfg.WebAddr
		if webAddr == "" {
			webAddr = "127.0.0.1:3000"
		}
		broadcaster := web.NewBroadcaster()
		webServer := web.NewServer(webAddr, stat, broadcaster)
		_ = webServer.Start(probeCtx)

		onProbe = func(res probers.ProbeResult, s *stats.Statistics) {
			s.Mu.RLock()
			total := s.TotalSuccessfulProbes + s.TotalUnsuccessfulProbes
			loss := float64(0)
			if total > 0 {
				loss = float64(s.TotalUnsuccessfulProbes) / float64(total) * 100.0
			}
			rttRes := printers.CalcMinAvgMaxRttTime(s.RTT)
			ipStr := s.IP.String()
			hostname := s.Hostname
			port := s.Port
			s.Mu.RUnlock()

			proto := strings.ToUpper(string(cfg.Protocol))
			if proto == "" {
				proto = "TCP"
			}

			targetDisplay := fmt.Sprintf("%s:%d", hostname, port)
			if hostname == "" || hostname == ipStr {
				targetDisplay = fmt.Sprintf("%s:%d", ipStr, port)
			}

			diagStr := ""
			if cfg.ShowDiags {
				diagStr = res.Diagnostics
			}

			broadcaster.Broadcast(web.ProbeEvent{
				Sequence:     total,
				Success:      res.Err == nil,
				RTT:          res.RTT.Seconds() * 1000,
				Target:       targetDisplay,
				Hostname:     hostname,
				IP:           ipStr,
				Port:         port,
				Protocol:     proto,
				Diagnostics:  diagStr,
				Error:        utils.ClassifyError(res.Err),
				TotalSent:    total,
				TotalSuccess: s.TotalSuccessfulProbes,
				TotalFailed:  s.TotalUnsuccessfulProbes,
				PacketLoss:   loss,
				AvgRTT:       float64(rttRes.Average),
				MinRTT:       float64(rttRes.Min),
				MaxRTT:       float64(rttRes.Max),
				P95RTT:       float64(rttRes.P95),
				P99RTT:       float64(rttRes.P99),
				Jitter:       float64(rttRes.Jitter),
			})
		}
	}

	prober := probers.NewProber(pinger, printer, stat, probers.Options{
		Timeout:                    cfg.Timeout,
		IntervalBetweenProbes:      cfg.IntervalBetweenProbes,
		ProbesBeforeQuit:           cfg.ProbesBeforeQuit,
		ShouldRetryResolve:         cfg.ShouldRetryResolve,
		RetryResolveAfterNFailures: cfg.RetryResolveAfterNFailures,
		ResolveEveryProbe:          cfg.ResolveEveryProbe,
		MaxConsecutiveFails:        cfg.MaxConsecutiveFails,
		MaxLatency:                 cfg.MaxLatency,
		QuietMode:                  cfg.QuietMode,
		Retries:                    cfg.Retries,
		InitialRetryBackoff:        cfg.InitialRetryBackoff,
		MaxRetryBackoff:            cfg.MaxRetryBackoff,
		RetryJitter:                cfg.RetryJitter,
		OnProbeResult:              onProbe,
		Resolver:                   cfg.Resolver,
	})

	if cfg.MetricsAddr != "" {
		metrics.StartMetricsServer(probeCtx, cfg.MetricsAddr, prober.Statistics)
	}

	if isForegroundTerminal() && !cfg.ShowDashboard {
		go monitorSummaryRequest(probeCtx, printer, prober.Statistics)
	}

	resStats, err := prober.Probe(probeCtx)
	if err != nil && !errors.Is(err, context.Canceled) {
		printer.PrintError("%v", err)
	}
	if dashPrinter != nil {
		dashPrinter.Shutdown(resStats)
	} else {
		printers.PrintStats(printer, resStats)
	}

	if probeCtx.Err() == context.Canceled {
		os.Exit(consts.ExitInterrupted)
	} else if resStats.TotalSuccessfulProbes == 0 && resStats.TotalUnsuccessfulProbes > 0 {
		os.Exit(consts.ExitTargetUnreachable)
	} else if resStats.TotalUnsuccessfulProbes > 0 {
		os.Exit(consts.ExitPartialPacketLoss)
	}
}
