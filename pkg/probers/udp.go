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

const udp = "udp"

type UDPOptions struct {
	IP         netip.Addr
	Port       uint16
	Timeout    time.Duration
	Dialer     *net.Dialer
	SendData   string
	ExpectData string
}

// UDPing implements Pinger for UDP protocol.
type UDPing struct {
	dialer     *net.Dialer
	ip         netip.Addr
	port       uint16
	timeout    time.Duration
	sendData   string
	expectData string
}

// NewUDPing constructs a new UDP prober.
func NewUDPing(opts UDPOptions) UDPing {
	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return UDPing{
		dialer:     d,
		ip:         opts.IP,
		port:       opts.Port,
		timeout:    opts.Timeout,
		sendData:   opts.SendData,
		expectData: opts.ExpectData,
	}
}

func (u *UDPing) address() string {
	return net.JoinHostPort(u.ip.String(), strconv.Itoa(int(u.port)))
}

// Ping sends a UDP probe packet and measures RTT.
func (u UDPing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()
	conn, err := u.dialer.DialContext(ctx, udp, u.address())
	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer conn.Close()

	payload := []byte(u.sendData)
	if len(payload) == 0 {
		if u.port == 53 {
			// Standard minimal DNS query header for "." root NS query
			payload = []byte{
				0x12, 0x34, // ID
				0x01, 0x00, // Flags: Standard query
				0x00, 0x01, // Questions: 1
				0x00, 0x00, // Answer RRs: 0
				0x00, 0x00, // Authority RRs: 0
				0x00, 0x00, // Additional RRs: 0
				0x00,       // Root label
				0x00, 0x01, // Type: A
				0x00, 0x01, // Class: IN
			}
		} else {
			payload = []byte("tcping UDP probe packet\x00\x00\x00\x00\x00\x00\x00\x00")
		}
	}

	_ = conn.SetDeadline(time.Now().Add(u.timeout))

	if _, err := conn.Write(payload); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("udp write failed: %w", err),
		}
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	rtt := time.Since(start)

	if err != nil {
		if u.expectData != "" || u.port == 53 {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       rtt,
				Err:       err,
			}
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       rtt,
				Err:       nil,
			}
		}
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       rtt,
			Err:       err,
		}
	}

	if u.expectData != "" && !strings.Contains(string(buf[:n]), u.expectData) {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       rtt,
			Err:       fmt.Errorf("expected %q, received %q", u.expectData, string(buf[:n])),
		}
	}

	return ProbeResult{
		LocalAddr: conn.LocalAddr(),
		RTT:       rtt,
		Err:       nil,
	}
}
