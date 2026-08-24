package probers

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// SMBOptions holds configuration for the SMB prober.
type SMBOptions struct {
	Hostname string
	IP       netip.Addr
	Port     uint16
	Timeout  time.Duration
	Dialer   *net.Dialer
}

// SMBing probes SMB/CIFS servers on port 445 using native SMB2/SMB3 protocol negotiation.
type SMBing struct {
	hostname string
	ip       netip.Addr
	port     uint16
	timeout  time.Duration
	dialer   *net.Dialer
}

// NewSMBing creates a new SMB prober.
func NewSMBing(opts SMBOptions) *SMBing {
	port := opts.Port
	if port == 0 {
		port = 445
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return &SMBing{
		hostname: opts.Hostname,
		ip:       opts.IP,
		port:     port,
		timeout:  opts.Timeout,
		dialer:   d,
	}
}

// buildSMB311NegotiatePacket constructs a full RFC-compliant SMB 3.1.1 Negotiate Request
// with 8-byte aligned Pre-Authentication Integrity (SHA-512) and Encryption (AES-GCM/CCM) contexts.
func buildSMB311NegotiatePacket() []byte {
	// SMB2 Header (64 bytes)
	header := []byte{
		0xfe, 'S', 'M', 'B', // ProtocolId (4)
		0x40, 0x00, // StructureSize = 64 (2)
		0x00, 0x00, // CreditCharge = 0 (2)
		0x00, 0x00, 0x00, 0x00, // Status (4)
		0x00, 0x00, // Command = SMB2_NEGOTIATE (0x0000) (2)
		0x24, 0x00, // CreditsRequested = 36 (2)
		0x00, 0x00, 0x00, 0x00, // Flags (4)
		0x00, 0x00, 0x00, 0x00, // NextCommand (4)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId = 0 (8)
		0x00, 0x00, 0x00, 0x00, // ProcessId (4)
		0x00, 0x00, 0x00, 0x00, // TreeId (4)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId (8)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (16)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// SMB2 Negotiate Request Body (36 bytes)
	body := []byte{
		0x24, 0x00, // StructureSize = 36 (2)
		0x05, 0x00, // DialectCount = 5 (2)
		0x01, 0x00, // SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED (2)
		0x00, 0x00, // Reserved (2)
		0x7f, 0x00, 0x00, 0x00, // Capabilities: DFS|Leasing|LargeMTU|MultiChannel|Encryption (4)
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // ClientGuid (16)
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
		0x70, 0x00, 0x00, 0x00, // NegotiateContextOffset = 112 (0x00000070) (4)
		0x02, 0x00, // NegotiateContextCount = 2 (2)
		0x00, 0x00, // Reserved2 (2)
		// Dialects (10 bytes):
		0x02, 0x02, // SMB 2.0.2 (0x0202)
		0x10, 0x02, // SMB 2.1 (0x0210)
		0x00, 0x03, // SMB 3.0 (0x0300)
		0x02, 0x03, // SMB 3.0.2 (0x0302)
		0x11, 0x03, // SMB 3.1.1 (0x0311)
		0x00, 0x00, // 2 bytes padding to 8-byte boundary (reaches offset 112 from header)
	}

	// Context 1: Pre-Authentication Integrity (Type 0x0001)
	ctx1 := []byte{
		0x01, 0x00, // ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES (2)
		0x26, 0x00, // DataLength = 38 bytes (2)
		0x00, 0x00, 0x00, 0x00, // Reserved (4)
		0x01, 0x00, // HashAlgorithmCount = 1 (2)
		0x20, 0x00, // SaltLength = 32 bytes (2)
		0x01, 0x00, // HashAlgorithm = SHA-512 (0x0001) (2)
		// Salt (32 bytes):
		0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
		0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
		0x00, 0x00, // 2 bytes padding to 8-byte boundary
	}

	// Context 2: Encryption Capabilities (Type 0x0002)
	ctx2 := []byte{
		0x02, 0x00, // ContextType = SMB2_ENCRYPTION_CAPABILITIES (2)
		0x06, 0x00, // DataLength = 6 bytes (2)
		0x00, 0x00, 0x00, 0x00, // Reserved (4)
		0x02, 0x00, // CipherCount = 2 (2)
		0x02, 0x00, // Cipher = AES-128-GCM (0x0002) (2)
		0x04, 0x00, // Cipher = AES-256-GCM (0x0004) (2)
	}

	payloadLen := len(header) + len(body) + len(ctx1) + len(ctx2)
	tcpHeader := []byte{0x00, byte((payloadLen >> 16) & 0xff), byte((payloadLen >> 8) & 0xff), byte(payloadLen & 0xff)}

	packet := make([]byte, 0, 4+payloadLen)
	packet = append(packet, tcpHeader...)
	packet = append(packet, header...)
	packet = append(packet, body...)
	packet = append(packet, ctx1...)
	packet = append(packet, ctx2...)
	return packet
}

// BuildMultiProtocolNegotiatePacket constructs a universal multi-protocol negotiate packet for legacy servers.
func BuildMultiProtocolNegotiatePacket() []byte {
	dialects := []string{
		"PC NETWORK PROGRAM 1.0",
		"LANMAN1.0",
		"Windows for Workgroups 3.1a",
		"LM1.2X002",
		"LANMAN2.1",
		"NT LM 0.12",
		"SMB 2.002",
		"SMB 2.???",
	}

	var dialectBuf []byte
	for _, d := range dialects {
		dialectBuf = append(dialectBuf, 0x02)
		dialectBuf = append(dialectBuf, []byte(d)...)
		dialectBuf = append(dialectBuf, 0x00)
	}

	byteCount := len(dialectBuf)

	smb1Header := []byte{
		0xff, 'S', 'M', 'B',
		0x72,
		0x00, 0x00, 0x00, 0x00,
		0x18,
		0x53, 0xc8,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}

	body := []byte{0x00, byte(byteCount & 0xff), byte((byteCount >> 8) & 0xff)}
	body = append(body, dialectBuf...)

	payloadLen := len(smb1Header) + len(body)
	tcpHeader := []byte{0x00, byte((payloadLen >> 16) & 0xff), byte((payloadLen >> 8) & 0xff), byte(payloadLen & 0xff)}

	packet := make([]byte, 0, 4+payloadLen)
	packet = append(packet, tcpHeader...)
	packet = append(packet, smb1Header...)
	packet = append(packet, body...)
	return packet
}

// parseSMBNegotiateResponse parses the server response and extracts diagnostic metadata.
func parseSMBNegotiateResponse(resp []byte) (string, error) {
	if len(resp) < 4 {
		return "", fmt.Errorf("response too short (%d bytes)", len(resp))
	}

	// First 4 bytes: Direct TCP transport header
	payload := resp[4:]
	if len(payload) < 4 {
		return "", fmt.Errorf("empty SMB payload")
	}

	// Check Protocol Magic
	if payload[0] == 0xff && payload[1] == 'S' && payload[2] == 'M' && payload[3] == 'B' {
		return "Protocol: SMBv1 (Legacy CIFS), Server replied with SMB1 Negotiate Response", nil
	}

	if payload[0] != 0xfe || payload[1] != 'S' || payload[2] != 'M' || payload[3] != 'B' {
		return "", fmt.Errorf("invalid SMB magic: 0x%02x%02x%02x%02x", payload[0], payload[1], payload[2], payload[3])
	}

	if len(payload) < 64 {
		return "Protocol: SMB2/3 Header received", nil
	}

	status := binary.LittleEndian.Uint32(payload[8:12])
	if status != 0 {
		return fmt.Sprintf("Protocol: SMB2/3, NT Status: 0x%08X", status), nil
	}

	// Parse SMB2 Negotiate Response Body (offset 64)
	if len(payload) < 64+8 {
		return "Protocol: SMB2/3, Negotiated OK", nil
	}

	secMode := binary.LittleEndian.Uint16(payload[66:68])
	dialect := binary.LittleEndian.Uint16(payload[68:70])

	dialectName := fmt.Sprintf("SMB 0x%04X", dialect)
	switch dialect {
	case 0x0200:
		dialectName = "SMB 2.0.0"
	case 0x0202:
		dialectName = "SMB 2.0.2"
	case 0x0210:
		dialectName = "SMB 2.1"
	case 0x02ff:
		dialectName = "SMB 2.x/3.x"
	case 0x0300:
		dialectName = "SMB 3.0"
	case 0x0302:
		dialectName = "SMB 3.0.2"
	case 0x0311:
		dialectName = "SMB 3.1.1"
	}

	signing := "Enabled"
	if secMode&0x02 != 0 {
		signing = "Required"
	} else if secMode == 0 {
		signing = "Disabled"
	}

	var caps []string
	if len(payload) >= 64+28 {
		capBits := binary.LittleEndian.Uint32(payload[88:92])
		if capBits&0x01 != 0 {
			caps = append(caps, "DFS")
		}
		if capBits&0x02 != 0 {
			caps = append(caps, "Leasing")
		}
		if capBits&0x04 != 0 {
			caps = append(caps, "LargeMTU")
		}
		if capBits&0x08 != 0 {
			caps = append(caps, "MultiChannel")
		}
		if capBits&0x40 != 0 {
			caps = append(caps, "Encryption")
		}
	}

	capsStr := "None"
	if len(caps) > 0 {
		capsStr = strings.Join(caps, "|")
	}

	var parts []string
	parts = append(parts, fmt.Sprintf("Dialect: %s (0x%04X)", dialectName, dialect))
	parts = append(parts, fmt.Sprintf("Signing: %s", signing))

	// Extract Negotiated Encryption Cipher if SMB 3.1.1 context present
	if dialect == 0x0311 && len(payload) >= 64+68 {
		ctxOffset := binary.LittleEndian.Uint32(payload[64+64 : 64+68])
		ctxCount := binary.LittleEndian.Uint16(payload[70:72])
		if ctxOffset > 0 && int(ctxOffset) < len(payload) {
			currOffset := int(ctxOffset)
			for i := 0; i < int(ctxCount) && currOffset+8 <= len(payload); i++ {
				cType := binary.LittleEndian.Uint16(payload[currOffset : currOffset+2])
				cLen := binary.LittleEndian.Uint16(payload[currOffset+2 : currOffset+4])
				dataStart := currOffset + 8
				if cType == 0x0002 && dataStart+4 <= len(payload) { // SMB2_ENCRYPTION_CAPABILITIES
					cipherID := binary.LittleEndian.Uint16(payload[dataStart+2 : dataStart+4])
					cipherName := fmt.Sprintf("0x%04X", cipherID)
					switch cipherID {
					case 0x0001:
						cipherName = "AES-128-CCM"
					case 0x0002:
						cipherName = "AES-128-GCM"
					case 0x0003:
						cipherName = "AES-256-CCM"
					case 0x0004:
						cipherName = "AES-256-GCM"
					}
					parts = append(parts, fmt.Sprintf("Cipher: %s", cipherName))
					break
				}
				// Advance to next 8-byte aligned context
				nextOffset := currOffset + 8 + int(cLen)
				if nextOffset%8 != 0 {
					nextOffset += 8 - (nextOffset % 8)
				}
				currOffset = nextOffset
			}
		}
	}

	parts = append(parts, fmt.Sprintf("Caps: %s", capsStr))

	// Extract Server SystemTime and calculate Clock Skew (Windows FILETIME at offset 104)
	if len(payload) >= 64+48 {
		ft := binary.LittleEndian.Uint64(payload[104:112])
		const filetimeEpochDiff = 116444736000000000 // 100ns units between 1601 and 1970
		if ft > filetimeEpochDiff {
			diff := ft - filetimeEpochDiff
			if diff < uint64(math.MaxInt64/100) {
				// #nosec G115 -- diff checked against MaxInt64/100
				unixNanos := int64(diff * 100)
				serverTime := time.Unix(0, unixNanos)
				skew := time.Until(serverTime)
				skewMs := skew.Milliseconds()
				if math.Abs(float64(skewMs)) < 60000 {
					parts = append(parts, fmt.Sprintf("ClockSkew: %+dms", skewMs))
				} else {
					parts = append(parts, fmt.Sprintf("ClockSkew: %+ds", int64(skew.Seconds())))
				}
			}
		}
	}

	// Extract Server GUID if present
	if len(payload) >= 64+24 {
		guid := payload[72:88]
		guidStr := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			binary.LittleEndian.Uint32(guid[0:4]),
			binary.LittleEndian.Uint16(guid[4:6]),
			binary.LittleEndian.Uint16(guid[6:8]),
			binary.BigEndian.Uint16(guid[8:10]),
			guid[10:16])
		parts = append(parts, fmt.Sprintf("ServerGUID: %s", guidStr))
	}

	return strings.Join(parts, ", "), nil
}

// Ping connects to the target SMB server, negotiates SMB 3.1.1 (falling back to multi-protocol if needed), and parses the response.
func (s *SMBing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	targetHost := s.hostname
	if targetHost == "" {
		targetHost = s.ip.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(s.port)))

	conn, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.timeout))

	// Send SMB 3.1.1 Negotiate Request
	reqPacket := buildSMB311NegotiatePacket()
	if _, err := conn.Write(reqPacket); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("smb write failed: %w", err),
		}
	}

	// Read response (at least Direct TCP 4-byte header)
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("smb header read failed: %w", err),
		}
	}

	payloadLen := int(respHeader[1])<<16 | int(respHeader[2])<<8 | int(respHeader[3])
	if payloadLen <= 0 || payloadLen > 65536 {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("invalid smb packet length: %d", payloadLen),
		}
	}

	respBody := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, respBody); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("smb body read failed: %w", err),
		}
	}

	rtt := time.Since(start)
	fullResp := append(respHeader, respBody...)
	diags, err := parseSMBNegotiateResponse(fullResp)
	if err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       rtt,
			Err:       fmt.Errorf("smb negotiation failed: %w", err),
		}
	}

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: diags,
		Err:         nil,
	}
}
