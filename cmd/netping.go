// Package main is the entry point for netping — a high-performance, multi-protocol network
// latency prober, protocol diagnostics engine, TUI dashboard, and REST trigger listener daemon.
//
// Objectives:
//   - Parse CLI arguments and dispatch execution across operational modes.
//   - Manage process lifecycles, signal trapping (SIGINT/SIGTERM), and diagnostic exit codes.
//   - Coordinate concurrent multi-target probing loops, TUI event loops, and web servers.
//
// Core Components:
//   - main: Process entry point and operational mode dispatcher.
//   - runSingleTargetProbing / runMultiTargetProbing: Main probe execution engines.
//   - buildPingerForTarget: Factory wrapper constructing protocol pingers.
//
// Data Flow:
//
//	CLI Flags -> config.ProcessUserInput() -> Mode Dispatch (Subscriber/Trigger/CLI/TUI)
//	-> Probing Loop -> Stats & Broadcaster -> Output Rendering -> Process Exit.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/edsilegx/netping/internal/app"
	"github.com/edsilegx/netping/internal/config"
	"github.com/edsilegx/netping/internal/printers"
	"github.com/edsilegx/netping/pkg/auth"
	"github.com/edsilegx/netping/pkg/consts"
	"github.com/edsilegx/netping/pkg/engine"
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

// buildPingerForTarget constructs an initialized Pinger instance for a single target
// configuration using the centralized probers.BuildPinger factory with all user options applied.
func buildPingerForTarget(tCfg config.TargetConfig, cfg config.Config, dialer *net.Dialer) probers.Pinger {
	svc := tCfg.ServiceName
	if svc == "" {
		svc = cfg.ServiceName
	}
	method := tCfg.HTTPMethod
	if method == "" {
		method = cfg.HTTPMethod
	}
	ua := tCfg.UserAgent
	if ua == "" {
		ua = cfg.UserAgent
	}
	waf := tCfg.WAFMode || cfg.WAFMode

	return probers.BuildPinger(probers.FactoryOptions{
		Protocol:    tCfg.Protocol,
		Hostname:    tCfg.Host,
		IP:          tCfg.IP,
		Port:        tCfg.Port,
		Timeout:     cfg.Timeout,
		Dialer:      dialer,
		UseIPv4:     cfg.UseIPv4,
		UseIPv6:     cfg.UseIPv6,
		SendData:    cfg.SendData,
		ExpectData:  cfg.ExpectData,
		ServiceName: svc,
		DNSHosts:    cfg.DNSHosts,
		StartTLS:    cfg.StartTLS,
		FastClose:   cfg.FastClose,
		URI:         tCfg.URI,
		HTTPMethod:  method,
		UserAgent:   ua,
		WAFMode:     waf,
	})
}

func main() {
	// Mode 1: Detached internal asynchronous exporter process (avoids GC/disk I/O pauses in parent)
	if len(os.Args) >= 3 && os.Args[1] == "--internal-async-save" {
		filePath := filepath.Clean(os.Args[2])
		dir := filepath.Dir(filePath)
		if dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0o750)
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			os.Exit(consts.ExitStorageError)
		}
		if err := os.WriteFile(filePath, data, 0o600); err != nil {
			os.Exit(consts.ExitStorageError)
		}
		os.Exit(consts.ExitSuccess)
	}

	// Parse command line flags, environment variables, and target endpoints
	cfg := config.ProcessUserInput()

	// Mode 2: API Key Generation (--generate-api-key <storePath>)
	if cfg.GenerateAPIKeyPath != "" {
		rawKey, hashStr, err := auth.GenerateAPIKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating API key: %v\n", err)
			os.Exit(consts.ExitGeneralError)
		}
		if err := auth.SaveKeyToStorePath(cfg.GenerateAPIKeyPath, rawKey, hashStr); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving API key to %q: %v\n", cfg.GenerateAPIKeyPath, err)
			os.Exit(consts.ExitStorageError)
		}
		fmt.Printf("\n\033[1;32m✓\033[0m \033[1mAPI Key generated successfully!\033[0m\n\n")
		fmt.Printf("  \033[1;33mAPI Key (Save now - cannot be recovered):\033[0m\n")
		fmt.Printf("  \033[1;36m%s\033[0m\n\n", rawKey)
		fmt.Printf("  \033[1;30mArgon2id Hash saved to:\033[0m %s\n\n", cfg.GenerateAPIKeyPath)
		os.Exit(consts.ExitSuccess)
	}

	// Mode 3: Trigger Listener Daemon (--trigger-mode with zero initial targets)
	if cfg.TriggerMode && len(cfg.TargetConfigs) == 0 {
		var validator auth.KeyValidator
		if cfg.APIKeyStore != "" || cfg.APIKeyHash != "" {
			ks, err := auth.NewKeystore(cfg.APIKeyStore, cfg.APIKeyHash)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing keystore: %v\n", err)
				os.Exit(consts.ExitUsageError)
			}
			validator = ks
		}

		broadcaster := web.NewBroadcaster()
		if cfg.HistoryLimit > 0 {
			broadcaster.SetMaxHistory(int(cfg.HistoryLimit))
		}

		registry := engine.NewDynamicTargetRegistry()
		dynamicEng := engine.NewDynamicEngine(broadcaster, registry, cfg.TriggerConcurrency)

		webAddr := cfg.WebAddr
		if webAddr == "" {
			webAddr = ":3000"
		}

		webServer := web.NewServer(webAddr, nil, broadcaster)
		if cfg.URLPrefix != "" {
			webServer.SetURLPrefix(cfg.URLPrefix)
		}
		webServer.SetTargetsSupplier(registry.GetFleetTargets)
		if validator != nil {
			webServer.SetKeyValidator(validator)
		}
		webServer.SetDynamicExecutor(dynamicEng)
		webServer.SetDynamicFleetManager(registry)

		probeCtx, cancel := app.SetupSignalHandler(context.Background())
		defer cancel()

		if err := webServer.Start(probeCtx); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting trigger listener: %v\n", err)
			os.Exit(consts.ExitGeneralError)
		}

		authStatus := "Argon2id Key Required"
		if validator == nil {
			authStatus = "Public (No Key Set)"
		}

		fmt.Printf("╔════════════════════════════════════════════════════════════════╗\n")
		fmt.Printf("║  \033[1;36mNETPING TRIGGER MODE LISTENER\033[0m                                 ║\n")
		fmt.Printf("╠════════════════════════════════════════════════════════════════╣\n")
		fmt.Printf("║  \033[1mWeb Dashboard / Stream:\033[0m http://%-36s ║\n", webAddr)
		fmt.Printf("║  \033[1mTrigger REST Endpoint:\033[0m  POST /api/v1/trigger                  ║\n")
		fmt.Printf("║  \033[1mAuthentication:\033[0m         %-36s ║\n", authStatus)
		fmt.Printf("║  \033[1mMax Concurrency:\033[0m        %-36s ║\n", fmt.Sprintf("%d workers", cfg.TriggerConcurrency))
		fmt.Printf("╚════════════════════════════════════════════════════════════════╝\n")
		fmt.Printf("Waiting for dynamic probe triggers (Press Ctrl+C to stop)...\n")

		<-probeCtx.Done()
		fmt.Println("\nTrigger listener gracefully shut down.")
		os.Exit(consts.ExitSuccess)
	}

	printer, err := printers.NewPrinter(cfg.PrinterConfig)
	if err != nil {
		fmt.Printf("Failed to create printer: %s\n", err)
		os.Exit(consts.ExitStorageError)
	}
	defer func() {
		if c, ok := printer.(interface{ Done() }); ok {
			c.Done()
		}
	}()

	probeCtx, cancel := app.SetupSignalHandler(context.Background())
	defer cancel()

	// Mode 4: Layer-4 Hop-by-Hop Traceroute Discovery (--traceroute)
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

	// Mode 5: Multi-Target Fleet Probing (multiple targets specified)
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
			if cfg.HistoryLimit > 0 {
				broadcaster.SetMaxHistory(int(cfg.HistoryLimit))
			}
			fleetSupplier := func() []printers.FleetTarget {
				fleet := make([]printers.FleetTarget, len(workers))
				for i, w := range workers {
					fleet[i] = printers.FleetTarget{
						Target:      w.Target,
						Host:        w.Host,
						Port:        w.Port,
						Protocol:    string(w.Protocol),
						ServiceName: w.ServiceName,
						Stats:       w.Stats,
					}
				}
				return fleet
			}
			webServer := web.NewServer(webAddr, nil, broadcaster)
			if cfg.URLPrefix != "" {
				webServer.SetURLPrefix(cfg.URLPrefix)
			}
			webServer.SetTargetsSupplier(fleetSupplier)
			if cfg.APIKeyStore != "" || cfg.APIKeyHash != "" {
				if ks, err := auth.NewKeystore(cfg.APIKeyStore, cfg.APIKeyHash); err == nil {
					webServer.SetKeyValidator(ks)
				}
			}
			dynReg := engine.NewDynamicTargetRegistry()
			dynamicEng := engine.NewDynamicEngine(broadcaster, dynReg, cfg.TriggerConcurrency)
			webServer.SetDynamicExecutor(dynamicEng)
			webServer.SetDynamicFleetManager(dynReg)

			if err := webServer.Start(probeCtx); err != nil {
				fmt.Fprintf(os.Stderr, "Error starting web server: %v\n", err)
			}
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
				snap := w.Stats.Snapshot()
				proto := strings.ToUpper(string(w.Protocol))
				if proto == "" {
					proto = "TCP"
				}

				targetDisplay := fmt.Sprintf("%s:%d", snap.Hostname, snap.Port)
				if snap.Hostname == "" || snap.Hostname == snap.IP {
					targetDisplay = fmt.Sprintf("%s:%d", snap.IP, snap.Port)
				}

				diagStr := ""
				if cfg.ShowDiags {
					diagStr = res.Diagnostics
				}

				broadcaster.Broadcast(web.ProbeEvent{
					RawTime:      time.Now(),
					Sequence:     snap.TotalSent,
					Success:      res.Err == nil,
					RTT:          res.RTT.Seconds() * 1000,
					Target:       targetDisplay,
					Hostname:     snap.Hostname,
					IP:           snap.IP,
					Port:         snap.Port,
					Protocol:     proto,
					Diagnostics:  diagStr,
					Error:        utils.ClassifyError(res.Err),
					DNSTime:      res.DNSTime.Seconds() * 1000,
					TCPTime:      res.TCPTime.Seconds() * 1000,
					TLSTime:      res.TLSTime.Seconds() * 1000,
					TTFB:         res.TTFB.Seconds() * 1000,
					HTTPStatus:   res.HTTPStatus,
					TotalSent:    snap.TotalSent,
					TotalSuccess: snap.TotalSuccess,
					TotalFailed:  snap.TotalFailed,
					PacketLoss:   snap.PacketLoss,
					AvgRTT:       float64(snap.AvgRTT),
					MinRTT:       float64(snap.MinRTT),
					MaxRTT:       float64(snap.MaxRTT),
					Jitter:       float64(snap.Jitter),
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

	// Mode 6: Single-Target Probing (standard mode)
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
		if cfg.HistoryLimit > 0 {
			broadcaster.SetMaxHistory(int(cfg.HistoryLimit))
		}
		webServer := web.NewServer(webAddr, stat, broadcaster)
		if cfg.URLPrefix != "" {
			webServer.SetURLPrefix(cfg.URLPrefix)
		}
		if cfg.APIKeyStore != "" || cfg.APIKeyHash != "" {
			if ks, err := auth.NewKeystore(cfg.APIKeyStore, cfg.APIKeyHash); err == nil {
				webServer.SetKeyValidator(ks)
			}
		}
		dynReg := engine.NewDynamicTargetRegistry()
		dynamicEng := engine.NewDynamicEngine(broadcaster, dynReg, cfg.TriggerConcurrency)
		webServer.SetDynamicExecutor(dynamicEng)
		webServer.SetDynamicFleetManager(dynReg)

		if err := webServer.Start(probeCtx); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting web server: %v\n", err)
		}

		onProbe = func(res probers.ProbeResult, s *stats.Statistics) {
			snap := s.Snapshot()
			proto := strings.ToUpper(string(cfg.Protocol))
			if proto == "" {
				proto = "TCP"
			}

			targetDisplay := fmt.Sprintf("%s:%d", snap.Hostname, snap.Port)
			if snap.Hostname == "" || snap.Hostname == snap.IP {
				targetDisplay = fmt.Sprintf("%s:%d", snap.IP, snap.Port)
			}

			diagStr := ""
			if cfg.ShowDiags {
				diagStr = res.Diagnostics
			}

			broadcaster.Broadcast(web.ProbeEvent{
				RawTime:      time.Now(),
				Sequence:     snap.TotalSent,
				Success:      res.Err == nil,
				RTT:          res.RTT.Seconds() * 1000,
				Target:       targetDisplay,
				Hostname:     snap.Hostname,
				IP:           snap.IP,
				Port:         snap.Port,
				Protocol:     proto,
				Diagnostics:  diagStr,
				Error:        utils.ClassifyError(res.Err),
				DNSTime:      res.DNSTime.Seconds() * 1000,
				TCPTime:      res.TCPTime.Seconds() * 1000,
				TLSTime:      res.TLSTime.Seconds() * 1000,
				TTFB:         res.TTFB.Seconds() * 1000,
				HTTPStatus:   res.HTTPStatus,
				TotalSent:    snap.TotalSent,
				TotalSuccess: snap.TotalSuccess,
				TotalFailed:  snap.TotalFailed,
				PacketLoss:   snap.PacketLoss,
				AvgRTT:       float64(snap.AvgRTT),
				MinRTT:       float64(snap.MinRTT),
				MaxRTT:       float64(snap.MaxRTT),
				Jitter:       float64(snap.Jitter),
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
