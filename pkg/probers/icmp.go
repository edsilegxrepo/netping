package probers

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var icmpSeq uint32

type ICMPOptions struct {
	IP      netip.Addr
	Timeout time.Duration
	UseIPv6 bool
}

// ICMPing implements Pinger for Layer-3 ICMP Echo probing.
type ICMPing struct {
	ip      netip.Addr
	timeout time.Duration
	useIPv6 bool
}

// NewICMPing creates a new ICMP prober.
func NewICMPing(opts ICMPOptions) ICMPing {
	return ICMPing{
		ip:      opts.IP,
		timeout: opts.Timeout,
		useIPv6: opts.UseIPv6 || opts.IP.Is6(),
	}
}

// Ping sends an ICMP Echo Request and awaits an Echo Reply.
func (i ICMPing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	network := "ip4:icmp"
	if i.useIPv6 {
		network = "ip6:ipv6-icmp"
	}

	conn, err := net.DialTimeout(network, i.ip.String(), i.timeout)
	if err != nil {
		network = "udp4"
		if i.useIPv6 {
			network = "udp6"
		}
		conn, err = net.DialTimeout(network, i.ip.String(), i.timeout)
		if err != nil {
			return ProbeResult{
				RTT: time.Since(start),
				Err: fmt.Errorf("icmp socket dial failed: %w", err),
			}
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(i.timeout))

	seq := atomic.AddUint32(&icmpSeq, 1) & 0xffff
	pid := uint32(os.Getpid()) & 0xffff

	icmpType := byte(8)
	if i.useIPv6 {
		icmpType = byte(128)
	}

	packet := make([]byte, 40)
	packet[0] = icmpType
	packet[1] = 0
	packet[2] = 0
	packet[3] = 0
	packet[4] = byte(pid >> 8)
	packet[5] = byte(pid & 0xff)
	packet[6] = byte(seq >> 8)
	packet[7] = byte(seq & 0xff)
	copy(packet[8:], []byte("tcping ICMP echo probe payload"))

	if !i.useIPv6 {
		csum := computeChecksum(packet)
		packet[2] = byte(csum >> 8)
		packet[3] = byte(csum & 0xff)
	}

	if _, err := conn.Write(packet); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("icmp send failed: %w", err),
		}
	}

	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	rtt := time.Since(start)
	if err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       rtt,
			Err:       err,
		}
	}

	var diagParts []string
	diagParts = append(diagParts, fmt.Sprintf("Seq: %d", seq))
	diagParts = append(diagParts, fmt.Sprintf("Bytes: %d", n))
	if n >= 9 && reply[0] == 0x45 {
		ttl := reply[8]
		diagParts = append(diagParts, fmt.Sprintf("TTL: %d", ttl))
	}

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: strings.Join(diagParts, ", "),
		Err:         nil,
	}
}

func computeChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
