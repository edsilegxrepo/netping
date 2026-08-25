package probers

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const tcp = "tcp"

type TCPOptions struct {
	Hostname   string
	IP         netip.Addr
	Port       uint16
	Timeout    time.Duration
	Dialer     *net.Dialer
	SendData   string
	ExpectData string
	FastClose  bool
}

type Tcping struct {
	dialer     *net.Dialer
	hostname   string
	ip         netip.Addr
	port       uint16
	timeout    time.Duration
	sendData   string
	expectData string
	fastClose  bool
}

func NewTcping(opts TCPOptions) Tcping {
	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return Tcping{
		dialer:     d,
		hostname:   opts.Hostname,
		ip:         opts.IP,
		port:       opts.Port,
		timeout:    opts.Timeout,
		sendData:   opts.SendData,
		expectData: opts.ExpectData,
		fastClose:  opts.FastClose,
	}
}

func (t *Tcping) address() string {
	if t.ip.IsValid() {
		return net.JoinHostPort(t.ip.String(), strconv.Itoa(int(t.port)))
	}
	if t.hostname != "" {
		return net.JoinHostPort(t.hostname, strconv.Itoa(int(t.port)))
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(t.port)))
}

func (t Tcping) Ping(ctx context.Context) ProbeResult {
	start := time.Now()
	conn, err := t.dialer.DialContext(ctx, tcp, t.address())
	rtt := time.Since(start)
	if err != nil {
		return ProbeResult{
			RTT: rtt,
			Err: err,
		}
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok && t.fastClose {
		_ = tcpConn.SetLinger(0)
	}

	defer func() { _ = conn.Close() }()

	if t.sendData != "" {
		_ = conn.SetDeadline(time.Now().Add(t.timeout))
		if _, err := conn.Write([]byte(t.sendData)); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("send payload failed: %w", err),
			}
		}

		if t.expectData != "" {
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				return ProbeResult{
					LocalAddr: conn.LocalAddr(),
					RTT:       time.Since(start),
					Err:       fmt.Errorf("read expect payload failed: %w", err),
				}
			}
			if !strings.Contains(string(buf[:n]), t.expectData) {
				return ProbeResult{
					LocalAddr: conn.LocalAddr(),
					RTT:       time.Since(start),
					Err:       fmt.Errorf("expected %q, received %q", t.expectData, string(buf[:n])),
				}
			}
		}
	}

	diag := fmt.Sprintf("Local: %s (SYN-ACK established)", conn.LocalAddr().String())
	if t.sendData != "" {
		diag += " │ Payload Matched"
	}

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: diag,
		Err:         nil,
	}
}
