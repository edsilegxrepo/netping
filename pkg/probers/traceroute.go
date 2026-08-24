package probers

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
)

type TraceHop struct {
	Hop      int
	Addr     net.Addr
	Hostname string
	RTTs     []time.Duration
	Reached  bool
	Timeout  bool
}

type TracerouteOptions struct {
	Target   string
	IP       netip.Addr
	Port     uint16
	Protocol consts.Protocol
	MaxHops  int
	Probes   int
	Timeout  time.Duration
}

// Traceroute executes a hop-by-hop Layer-4 route discovery to the target.
func RunTraceroute(ctx context.Context, opts TracerouteOptions, onHop func(hop TraceHop)) ([]TraceHop, error) {
	maxHops := opts.MaxHops
	if maxHops <= 0 {
		maxHops = 30
	}
	numProbes := opts.Probes
	if numProbes <= 0 {
		numProbes = 3
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	targetHost := opts.Target
	if targetHost == "" {
		targetHost = opts.IP.String()
	}
	portStr := strconv.Itoa(int(opts.Port))
	if opts.Port == 0 {
		portStr = "80"
	}
	destAddr := net.JoinHostPort(targetHost, portStr)

	hops := make([]TraceHop, 0, maxHops)

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			return hops, ctx.Err()
		default:
		}

		hop := TraceHop{
			Hop:  ttl,
			RTTs: make([]time.Duration, 0, numProbes),
		}

		for p := 0; p < numProbes; p++ {
			rtt, responderAddr, reached, err := probeTTL(ctx, destAddr, ttl, timeout)
			if err != nil || rtt == 0 {
				hop.Timeout = true
			} else {
				hop.RTTs = append(hop.RTTs, rtt)
				if responderAddr != nil && hop.Addr == nil {
					hop.Addr = responderAddr
				}
				if reached {
					hop.Reached = true
				}
			}
		}

		if hop.Addr != nil {
			names, _ := net.LookupAddr(hop.Addr.String())
			if len(names) > 0 {
				hop.Hostname = names[0]
			}
		}

		hops = append(hops, hop)
		if onHop != nil {
			onHop(hop)
		}

		if hop.Reached {
			break
		}
	}

	return hops, nil
}

// probeTTL sends a TCP connect probe with a specific IP TTL set on the socket.
func probeTTL(ctx context.Context, targetAddr string, ttl int, timeout time.Duration) (time.Duration, net.Addr, bool, error) {
	start := time.Now()

	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				controlErr = setSocketTTL(fd, ttl)
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	rtt := time.Since(start)

	if err == nil {
		remoteAddr := conn.RemoteAddr()
		conn.Close()
		return rtt, remoteAddr, true, nil
	}

	// If timeout occurred, return empty
	if os.IsTimeout(err) {
		return 0, nil, false, err
	}

	// On TCP RST / Connection Refused from destination, destination host is reached
	return rtt, nil, true, nil
}
