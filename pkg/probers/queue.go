package probers

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type QueueProtocol string

const (
	QueueKafka    QueueProtocol = "kafka"
	QueueRabbitMQ QueueProtocol = "rabbitmq"
)

type QueueOptions struct {
	Protocol   QueueProtocol
	Hostname   string
	IP         netip.Addr
	Port       uint16
	UseTLS     bool
	SkipVerify bool
	Timeout    time.Duration
	Dialer     *net.Dialer
}

// Queueing implements Pinger for message brokers (Apache Kafka and RabbitMQ / AMQP 0-9-1).
type Queueing struct {
	protocol   QueueProtocol
	hostname   string
	ip         netip.Addr
	port       uint16
	useTLS     bool
	skipVerify bool
	timeout    time.Duration
	dialer     *net.Dialer
}

// NewQueueing constructs a new message broker prober.
func NewQueueing(opts QueueOptions) *Queueing {
	port := opts.Port
	if port == 0 {
		if opts.Protocol == QueueKafka {
			if opts.UseTLS {
				port = 9093
			} else {
				port = 9092
			}
		} else { // RabbitMQ / AMQP
			if opts.UseTLS {
				port = 5671
			} else {
				port = 5672
			}
		}
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return &Queueing{
		protocol:   opts.Protocol,
		hostname:   opts.Hostname,
		ip:         opts.IP,
		port:       port,
		useTLS:     opts.UseTLS,
		skipVerify: opts.SkipVerify,
		timeout:    opts.Timeout,
		dialer:     d,
	}
}

// Ping connects to the broker, executes protocol handshake, and measures round-trip time.
func (q *Queueing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	targetHost := q.hostname
	if targetHost == "" {
		targetHost = q.ip.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(q.port)))

	var conn net.Conn
	var err error

	if q.useTLS {
		tlsConfig := &tls.Config{
			ServerName: targetHost,
			// #nosec G402 -- user-configurable TLS verification flag for message queue probing
			InsecureSkipVerify: q.skipVerify,
		}
		tlsDialer := &tls.Dialer{
			NetDialer: q.dialer,
			Config:    tlsConfig,
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = q.dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(q.timeout))

	var diags []string

	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		diags = append(diags, fmt.Sprintf("TLS: %s (%s)", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite)))
	}

	if q.protocol == QueueKafka {
		// Kafka ApiVersions Request v0 (API Key 18, 19 bytes)
		// Format: [4 bytes size][2 bytes api_key=18][2 bytes api_version=0][4 bytes correlation_id=1][2 bytes client_id_len=7][client_id="netping"]
		kafkaReq := []byte{
			0x00, 0x00, 0x00, 0x13, // Size: 19 bytes
			0x00, 0x12, // API Key: 18 (ApiVersions)
			0x00, 0x00, // API Version: 0
			0x00, 0x00, 0x00, 0x01, // Correlation ID: 1
			0x00, 0x07, // Client ID length: 7
			'n', 'e', 't', 'p', 'i', 'n', 'g', // "netping"
		}

		if _, err := conn.Write(kafkaReq); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("kafka apiversions request write failed: %w", err),
			}
		}

		header := make([]byte, 8)
		if _, err := io.ReadFull(conn, header); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("kafka response header read failed: %w", err),
			}
		}

		// Validate correlation ID (bytes 4-7 must match correlation ID 1)
		if header[4] != 0x00 || header[5] != 0x00 || header[6] != 0x00 || header[7] != 0x01 {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("unexpected kafka correlation id in response: 0x%x", header[4:8]),
			}
		}

		respLen := binary.BigEndian.Uint32(header[0:4])
		if respLen > 4 && respLen < 65536 {
			payload := make([]byte, respLen-4)
			if _, err := io.ReadFull(conn, payload); err == nil && len(payload) >= 2 {
				errorCode := binary.BigEndian.Uint16(payload[0:2])
				if errorCode == 0 && len(payload) >= 6 {
					numAPIs := int(binary.BigEndian.Uint32(payload[2:6]))
					diags = append(diags, fmt.Sprintf("Kafka: ApiVersions OK (APIs: %d)", numAPIs))
				} else {
					diags = append(diags, fmt.Sprintf("Kafka: ApiVersions OK (Error: %d)", errorCode))
				}
			} else {
				diags = append(diags, "Kafka: ApiVersions (v0) OK")
			}
		} else {
			diags = append(diags, "Kafka: ApiVersions (v0) OK")
		}

	} else if q.protocol == QueueRabbitMQ {
		// AMQP 0-9-1 Protocol Header (8 bytes): "AMQP\x00\x00\x09\x01"
		amqpHeader := []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}

		if _, err := conn.Write(amqpHeader); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("amqp protocol header write failed: %w", err),
			}
		}

		resp := make([]byte, 8)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("amqp server response read failed: %w", err),
			}
		}

		// RabbitMQ responds with either Connection.Start frame (starts with 0x01) or protocol header
		if resp[0] != 0x01 && (resp[0] != 'A' || resp[1] != 'M' || resp[2] != 'Q' || resp[3] != 'P') {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("unexpected amqp response frame header: 0x%x", resp[0]),
			}
		}

		// Read remainder of Connection.Start frame to extract server properties & auth mechanisms
		frameBuf := make([]byte, 4096)
		copy(frameBuf[:8], resp)
		n, _ := conn.Read(frameBuf[8:])
		fullPayload := string(frameBuf[:8+n])

		var product, ver, clusterName string
		var authMechs []string

		if strings.Contains(fullPayload, "RabbitMQ") {
			product = "RabbitMQ"
		} else if strings.Contains(fullPayload, "product") {
			product = "AMQP Broker"
		}

		if idx := strings.Index(fullPayload, "version"); idx >= 0 && idx+20 < len(fullPayload) {
			sub := fullPayload[idx+7 : idx+25]
			for _, part := range strings.FieldsFunc(sub, func(r rune) bool {
				return r < 0x20 || r > 0x7E
			}) {
				if len(part) >= 3 && strings.Contains(part, ".") {
					ver = part
					break
				}
			}
		}

		if idx := strings.Index(fullPayload, "cluster_name"); idx >= 0 && idx+30 < len(fullPayload) {
			sub := fullPayload[idx+12 : idx+40]
			for _, part := range strings.FieldsFunc(sub, func(r rune) bool {
				return r < 0x20 || r > 0x7E
			}) {
				if len(part) >= 2 {
					clusterName = part
					break
				}
			}
		}

		for _, mech := range []string{"PLAIN", "AMQPLAIN", "EXTERNAL", "OAUTHBEARER"} {
			if strings.Contains(fullPayload, mech) {
				authMechs = append(authMechs, mech)
			}
		}

		if product != "" {
			if ver != "" {
				diags = append(diags, fmt.Sprintf("Broker: %s %s", product, ver))
			} else {
				diags = append(diags, fmt.Sprintf("Broker: %s", product))
			}
		}
		if clusterName != "" {
			diags = append(diags, fmt.Sprintf("Cluster: %s", clusterName))
		}
		if len(authMechs) > 0 {
			diags = append(diags, fmt.Sprintf("Auth: %s", strings.Join(authMechs, "|")))
		}
		diags = append(diags, "Protocol: AMQP 0-9-1")
	}

	rtt := time.Since(start)

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: strings.Join(diags, ", "),
		Err:         nil,
	}
}
