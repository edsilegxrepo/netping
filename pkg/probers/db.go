package probers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type DBType string

const (
	PostgreSQL DBType = "postgres"
	MySQL      DBType = "mysql"
	MSSQL      DBType = "mssql"
	Oracle     DBType = "oracle"
	MongoDB    DBType = "mongodb"
	Cassandra  DBType = "cassandra"
	SAPHANA    DBType = "saphana"
)

type DBOptions struct {
	Type        DBType
	Hostname    string
	IP          netip.Addr
	Port        uint16
	ServiceName string
	UseTLS      bool
	Timeout     time.Duration
	Dialer      *net.Dialer
}

// DBing implements Pinger for database protocol handshakes (PostgreSQL, MySQL, MSSQL, Oracle, MongoDB, Cassandra, SAP HANA).
type DBing struct {
	DBOptions
}

// defaultDBPort returns the canonical IANA port for a given database type.
func defaultDBPort(dbType DBType, useTLS bool) uint16 {
	switch dbType {
	case MySQL:
		return 3306
	case MSSQL:
		return 1433
	case Oracle:
		if useTLS {
			return 2484
		}
		return 1521
	case MongoDB:
		return 27017
	case Cassandra:
		return 9042
	case SAPHANA:
		return 30015
	case PostgreSQL:
		fallthrough
	default:
		return 5432
	}
}

// NewDBing constructs a new Database handshake prober.
func NewDBing(opts DBOptions) *DBing {
	if opts.Port == 0 {
		opts.Port = defaultDBPort(opts.Type, opts.UseTLS)
	}

	if opts.Dialer == nil {
		opts.Dialer = &net.Dialer{Timeout: opts.Timeout}
	}

	return &DBing{DBOptions: opts}
}

// dial establishes the initial TCP or TLS connection.
func (d *DBing) dial(ctx context.Context) (net.Conn, string, string, error) {
	targetHost := d.Hostname
	if targetHost == "" {
		targetHost = d.IP.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(d.Port)))

	var conn net.Conn
	var err error
	var tlsDetails string

	if d.UseTLS && d.Type != PostgreSQL && d.Type != MySQL { // PostgreSQL & MySQL do in-band SSL negotiation
		// #nosec G402 -- diagnostic database TLS prober measuring latency
		// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification -- diagnostic prober measuring latency
		tlsConfig := &tls.Config{
			ServerName:         targetHost,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
		tlsDialer := &tls.Dialer{NetDialer: d.Dialer, Config: tlsConfig}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			if tc, ok := conn.(*tls.Conn); ok {
				state := tc.ConnectionState()
				tlsDetails = fmt.Sprintf("TLS: %s (%s)", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))
			}
		}
	} else {
		conn, err = d.Dialer.DialContext(ctx, "tcp", addr)
	}

	return conn, targetHost, tlsDetails, err
}

// Ping connects to the database listener and executes the native protocol handshake with rich diagnostics.
func (d *DBing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	conn, targetHost, tlsDetails, err := d.dial(ctx)
	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(d.Timeout))

	var diagParts []string
	if tlsDetails != "" {
		diagParts = append(diagParts, tlsDetails)
	}

	var probeDiags []string
	var probeErr error

	switch d.Type {
	case PostgreSQL:
		probeDiags, probeErr = d.probePostgres(ctx, conn, targetHost)
	case MySQL:
		probeDiags, probeErr = d.probeMySQL(conn)
	case MSSQL:
		probeDiags, probeErr = d.probeMSSQL(conn)
	case Oracle:
		probeDiags, probeErr = d.probeOracle(conn)
	case MongoDB:
		probeDiags, probeErr = d.probeMongoDB(conn)
	case Cassandra:
		probeDiags, probeErr = d.probeCassandra(conn)
	case SAPHANA:
		probeDiags, probeErr = d.probeSAPHANA(conn)
	}

	if probeErr != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       probeErr,
		}
	}

	diagParts = append(diagParts, probeDiags...)

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         time.Since(start),
		Diagnostics: strings.Join(diagParts, ", "),
		Err:         nil,
	}
}

// probePostgres executes PostgreSQL SSLRequest and Frontend StartupMessage handshakes.
func (d *DBing) probePostgres(ctx context.Context, conn net.Conn, targetHost string) ([]string, error) {
	var diags []string

	// PostgreSQL SSLRequest packet (8 bytes: length=8, code=80877103)
	sslRequest := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := conn.Write(sslRequest); err != nil {
		return nil, fmt.Errorf("postgres sslrequest write failed: %w", err)
	}

	reply := make([]byte, 1)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, fmt.Errorf("postgres response read failed: %w", err)
	}

	activeConn := conn
	switch reply[0] {
	case 'S':
		// SSL Supported: perform TLS handshake to extract TLS version and cipher suite
		// #nosec G402 -- diagnostic Postgres SSL prober measuring handshake latency
		// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification -- diagnostic prober measuring latency
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         targetHost,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err == nil {
			state := tlsConn.ConnectionState()
			diags = append(diags, fmt.Sprintf("SSL: Supported (%s / %s)", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite)))
			activeConn = tlsConn
		} else {
			diags = append(diags, "SSL: Supported")
		}
	case 'N':
		diags = append(diags, "SSL: Not Supported")
	default:
		return nil, fmt.Errorf("unexpected postgres handshake response: 0x%x (%q)", reply[0], reply[0])
	}

	// Send PostgreSQL 3.0 StartupMessage (user=netping, database=postgres)
	var sm bytes.Buffer
	sm.Write([]byte{0x00, 0x03, 0x00, 0x00}) // Protocol 3.0
	sm.WriteString("user\x00netping\x00")
	sm.WriteString("database\x00postgres\x00")
	sm.WriteString("client_encoding\x00UTF8\x00")
	sm.WriteByte(0x00) // Terminator

	smBytes := sm.Bytes()
	// #nosec G115 -- Postgres startup message length bounded
	pktLen := uint32(len(smBytes) + 4)
	// #nosec G115 -- byte masking for 32-bit big-endian length prefix
	fullSM := append([]byte{byte(pktLen >> 24), byte(pktLen >> 16), byte(pktLen >> 8), byte(pktLen)}, smBytes...)

	if _, err := activeConn.Write(fullSM); err == nil {
		buf := make([]byte, 4096)
		_ = activeConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err := activeConn.Read(buf); err == nil && n >= 5 {
			data := buf[:n]
			offset := 0
			var pgVersion, pgAuth, pgStatus string
			for offset+5 <= len(data) {
				respType := data[offset]
				msgLen := int(binary.BigEndian.Uint32(data[offset+1 : offset+5]))
				if msgLen < 4 || offset+1+msgLen > len(data) {
					break
				}
				payload := data[offset+5 : offset+1+msgLen]
				offset += 1 + msgLen

				switch respType {
				case 'S': // ParameterStatus (e.g. server_version)
					nullIdx := bytes.IndexByte(payload, 0x00)
					if nullIdx > 0 && nullIdx+1 < len(payload) {
						pName := string(payload[:nullIdx])
						pVal := strings.Trim(string(payload[nullIdx+1:]), "\x00")
						if pName == "server_version" {
							pgVersion = pVal
						}
					}
				case 'R': // Authentication request
					if len(payload) >= 4 {
						authCode := binary.BigEndian.Uint32(payload[0:4])
						switch authCode {
						case 0:
							pgAuth = "Trust (No Password)"
						case 2:
							pgAuth = "Kerberos V5"
						case 3:
							pgAuth = "Cleartext Password"
						case 5:
							pgAuth = "MD5 Password"
						case 7:
							pgAuth = "GSS"
						case 9:
							pgAuth = "SSPI"
						case 10:
							rawMechs := strings.Trim(string(payload[4:]), "\x00")
							mechs := strings.Split(rawMechs, "\x00")
							var validMechs []string
							for _, m := range mechs {
								if m != "" {
									validMechs = append(validMechs, m)
								}
							}
							if len(validMechs) > 0 {
								pgAuth = fmt.Sprintf("SASL (%s)", strings.Join(validMechs, "|"))
							} else {
								pgAuth = "SASL (SCRAM-SHA-256)"
							}
						default:
							pgAuth = fmt.Sprintf("Code %d", authCode)
						}
					}
				case 'E': // ErrorResponse
					fields := make(map[byte]string)
					idx := 0
					for idx < len(payload) && payload[idx] != 0 {
						c := payload[idx]
						idx++
						nullIdx := bytes.IndexByte(payload[idx:], 0x00)
						if nullIdx < 0 {
							break
						}
						fields[c] = string(payload[idx : idx+nullIdx])
						idx += nullIdx + 1
					}
					sqlCode := fields['C']
					msg := fields['M']
					if sqlCode == "28P01" {
						pgStatus = "Password Required (28P01)"
					} else if sqlCode == "28000" {
						pgStatus = "Role Authentication (28000)"
					} else if msg != "" {
						pgStatus = msg
					}
				}
			}

			if pgVersion != "" {
				diags = append(diags, fmt.Sprintf("Version: PostgreSQL %s", pgVersion))
			}
			if pgAuth != "" {
				diags = append(diags, fmt.Sprintf("Auth: %s", pgAuth))
			}
			if pgStatus != "" && pgAuth == "" {
				diags = append(diags, fmt.Sprintf("Status: %s", pgStatus))
			}
		}
	}

	diags = append(diags, "Protocol: PostgreSQL 3.0")
	return diags, nil
}

// probeMySQL parses the MySQL HandshakeV10 initial greeting packet.
func (d *DBing) probeMySQL(conn net.Conn) ([]string, error) {
	var diags []string

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("mysql initial handshake packet header read failed: %w", err)
	}

	pktLen := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if pktLen < 1 || pktLen > 16384 {
		return nil, fmt.Errorf("invalid mysql handshake packet length: %d", pktLen)
	}

	payload := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("mysql payload read failed: %w", err)
	}

	protoVersion := payload[0]
	if protoVersion == 0xff {
		errCode := uint16(0)
		if len(payload) >= 3 {
			errCode = binary.LittleEndian.Uint16(payload[1:3])
		}
		errMsg := string(payload[3:])
		diags = append(diags, fmt.Sprintf("Error: #%d (%s)", errCode, strings.TrimSpace(errMsg)))
		return diags, nil
	}

	if protoVersion != 0x0a {
		return nil, fmt.Errorf("unexpected mysql protocol version byte: 0x%x", protoVersion)
	}

	// HandshakeV10: extract server version string (null-terminated)
	nullIdx := bytes.IndexByte(payload[1:], 0x00)
	var srvVer string
	var restOffset int
	if nullIdx >= 0 {
		srvVer = string(payload[1 : 1+nullIdx])
		restOffset = 1 + nullIdx + 1
	} else {
		srvVer = "Unknown"
		restOffset = 1
	}
	diags = append(diags, fmt.Sprintf("Version: %s", srvVer))

	if len(payload) >= restOffset+4 {
		threadID := binary.LittleEndian.Uint32(payload[restOffset : restOffset+4])
		diags = append(diags, fmt.Sprintf("ThreadID: %d", threadID))
		restOffset += 4
	}

	// Skip auth_plugin_data_part_1 (8 bytes) + filter (1 byte)
	restOffset += 9
	if len(payload) >= restOffset+2 {
		capsLow := binary.LittleEndian.Uint16(payload[restOffset : restOffset+2])
		restOffset += 2
		// Skip charset (1) + status_flags (2)
		restOffset += 3
		var capsHigh uint16
		if len(payload) >= restOffset+2 {
			capsHigh = binary.LittleEndian.Uint16(payload[restOffset : restOffset+2])
			restOffset += 2
		}
		caps := uint32(capsLow) | uint32(capsHigh)<<16
		if (caps & 0x0800) != 0 { // CLIENT_SSL (0x00000800)
			diags = append(diags, "SSL: Supported")
		} else {
			diags = append(diags, "SSL: Disabled")
		}

		var authDataLen int
		if len(payload) > restOffset {
			authDataLen = int(payload[restOffset])
			restOffset++
		}

		// Skip reserved (10 bytes)
		restOffset += 10

		// Skip auth_plugin_data_part_2 (length: max(13, authDataLen - 8))
		if (caps & 0x8000) != 0 { // CLIENT_SECURE_CONNECTION
			salt2Len := authDataLen - 8
			if salt2Len < 13 {
				salt2Len = 13
			}
			restOffset += salt2Len
		}

		// Extract auth plugin name if CLIENT_PLUGIN_AUTH (0x00080000) is set
		if (caps&0x00080000) != 0 && restOffset < len(payload) {
			authPart := payload[restOffset:]
			nullAuth := bytes.IndexByte(authPart, 0x00)
			if nullAuth > 0 {
				authPlugin := strings.TrimSpace(string(authPart[:nullAuth]))
				// Sanity check: valid auth plugin names are ASCII alphanumeric
				isClean := len(authPlugin) > 0
				for _, r := range authPlugin {
					if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
						isClean = false
						break
					}
				}
				if isClean {
					diags = append(diags, fmt.Sprintf("Auth: %s", authPlugin))
				}
			}
		}
	}

	return diags, nil
}

// probeMSSQL sends a TDS PRELOGIN packet and decodes the server version and encryption requirements.
func (d *DBing) probeMSSQL(conn net.Conn) ([]string, error) {
	var diags []string

	// TDS 7.x/8.0 PRELOGIN Packet (32 bytes)
	tdsPrelogin := []byte{
		0x12, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, // Header: Type 0x12 PRELOGIN, status 1 (EOM), length 32
		0x00, 0x00, 0x10, 0x00, 0x06, // Option 0: VERSION offset 16, len 6
		0x01, 0x00, 0x16, 0x00, 0x01, // Option 1: ENCRYPTION offset 22, len 1
		0x02, 0x00, 0x17, 0x00, 0x01, // Option 2: MARS offset 23, len 1
		0xff,                               // Terminator
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // Version payload (6 bytes: client version 9.0)
		0x00, // Encryption: ENCRYPT_OFF (1 byte)
		0x00, // MARS: Off (1 byte)
	}

	if _, err := conn.Write(tdsPrelogin); err != nil {
		return nil, fmt.Errorf("mssql tds prelogin write failed: %w", err)
	}

	respHeader := make([]byte, 8)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return nil, fmt.Errorf("mssql tds response header read failed: %w", err)
	}

	if respHeader[0] != 0x04 && respHeader[0] != 0x12 {
		return nil, fmt.Errorf("unexpected mssql tds response type 0x%x", respHeader[0])
	}

	respLen := int(binary.BigEndian.Uint16(respHeader[2:4])) - 8
	if respLen > 0 && respLen < 4096 {
		respBody := make([]byte, respLen)
		if _, err := io.ReadFull(conn, respBody); err == nil {
			// Parse TDS PRELOGIN response tokens
			idx := 0
			var verMajor, verMinor, verBuild uint16
			var encMode byte = 0xff
			for idx < len(respBody) && respBody[idx] != 0xff {
				token := respBody[idx]
				if idx+4 >= len(respBody) {
					break
				}
				offset := int(binary.BigEndian.Uint16(respBody[idx+1 : idx+3]))
				length := int(binary.BigEndian.Uint16(respBody[idx+3 : idx+5]))
				idx += 5

				if offset >= 0 && offset+length <= len(respBody) {
					if token == 0x00 && length >= 4 { // VERSION
						verMajor = uint16(respBody[offset])
						verMinor = uint16(respBody[offset+1])
						verBuild = binary.BigEndian.Uint16(respBody[offset+2 : offset+4])
					} else if token == 0x01 && length >= 1 { // ENCRYPTION
						encMode = respBody[offset]
					}
				}
			}

			if verMajor > 0 {
				releaseName := mssqlReleaseName(verMajor)
				diags = append(diags, fmt.Sprintf("Version: %s (%d.%d.%d)", releaseName, verMajor, verMinor, verBuild))
			}

			switch encMode {
			case 0x00:
				diags = append(diags, "Encryption: Off")
			case 0x01:
				diags = append(diags, "Encryption: On")
			case 0x02:
				diags = append(diags, "Encryption: Not Supported")
			case 0x03:
				diags = append(diags, "Encryption: Required")
			}
		}
	}

	if len(diags) == 0 {
		diags = append(diags, "TDS: Prelogin OK")
	}

	return diags, nil
}

// mssqlReleaseName maps SQL Server major version numbers to commercial release names.
func mssqlReleaseName(major uint16) string {
	switch major {
	case 16:
		return "SQL Server 2022"
	case 15:
		return "SQL Server 2019"
	case 14:
		return "SQL Server 2017"
	case 13:
		return "SQL Server 2016"
	case 12:
		return "SQL Server 2014"
	case 11:
		return "SQL Server 2012"
	case 10:
		return "SQL Server 2008"
	default:
		return fmt.Sprintf("SQL Server v%d", major)
	}
}

// probeOracle executes the Oracle TNS Connect handshake and parses ACCEPT / REFUSE / REDIRECT packets.
func (d *DBing) probeOracle(conn net.Conn) ([]string, error) {
	var diags []string

	svc := d.ServiceName
	if svc == "" {
		svc = "XE"
	}
	connectStr := fmt.Sprintf("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=%s)(CID=(PROGRAM=netping)(HOST=localhost)(USER=netping))))", svc)
	// #nosec G115 -- bounded Oracle connect packet length
	cDataLen := uint16(len(connectStr))
	cDataOffset := uint16(58)
	// #nosec G115 -- bounded Oracle connect packet length
	totalPktLen := uint16(58 + len(connectStr))

	tnsConnect := make([]byte, totalPktLen)
	binary.BigEndian.PutUint16(tnsConnect[0:2], totalPktLen)
	tnsConnect[4] = 0x01                                  // Type 1 (CONNECT)
	binary.BigEndian.PutUint16(tnsConnect[8:10], 0x013c)  // Version 316
	binary.BigEndian.PutUint16(tnsConnect[10:12], 0x012c) // Compatible 300
	binary.BigEndian.PutUint16(tnsConnect[14:16], 0x2000) // SDU 8192
	binary.BigEndian.PutUint16(tnsConnect[16:18], 0x7fff) // TDU 32767
	binary.BigEndian.PutUint16(tnsConnect[18:20], 0x7f08) // Protocol characteristics
	binary.BigEndian.PutUint16(tnsConnect[22:24], 0x0100) // HW byte order
	binary.BigEndian.PutUint16(tnsConnect[24:26], cDataLen)
	binary.BigEndian.PutUint16(tnsConnect[26:28], cDataOffset)
	binary.BigEndian.PutUint16(tnsConnect[34:36], 0x2000) // Large SDU
	copy(tnsConnect[58:], []byte(connectStr))

	if _, err := conn.Write(tnsConnect); err != nil {
		return nil, fmt.Errorf("oracle tns connect packet write failed: %w", err)
	}

	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("oracle tns response read failed: %w", err)
	}

	pktType := resp[4]
	restLen := int(binary.BigEndian.Uint16(resp[0:2])) - 8
	var restData []byte
	if restLen > 0 && restLen < 4096 {
		restData = make([]byte, restLen)
		_, _ = io.ReadFull(conn, restData)
	}

	if pktType == 0x0b { // TNS RESEND
		if _, err := conn.Write(tnsConnect); err == nil {
			resp2 := make([]byte, 8)
			if _, err := io.ReadFull(conn, resp2); err == nil {
				pktType = resp2[4]
				restLen2 := int(binary.BigEndian.Uint16(resp2[0:2])) - 8
				if restLen2 > 0 && restLen2 < 4096 {
					restData = make([]byte, restLen2)
					_, _ = io.ReadFull(conn, restData)
				}
			}
		}
	}

	switch pktType {
	case 0x02: // TNS ACCEPT
		if len(restData) >= 2 {
			tnsVer := binary.BigEndian.Uint16(restData[0:2])
			rel := tnsProtocolRelease(tnsVer)
			diags = append(diags, fmt.Sprintf("Version: %s (TNS v%d)", rel, tnsVer))
			if len(restData) >= 6 {
				sdu := binary.BigEndian.Uint16(restData[4:6])
				diags = append(diags, fmt.Sprintf("TNS: ACCEPT (Service: %s OK, SDU: %d)", svc, sdu))
			} else {
				diags = append(diags, fmt.Sprintf("TNS: ACCEPT (Service: %s OK)", svc))
			}
		} else {
			diags = append(diags, fmt.Sprintf("TNS: ACCEPT (Service: %s OK)", svc))
		}
	case 0x04: // TNS REFUSE
		refuseStr := string(restData)
		if vsnNum := extractTNSParam(refuseStr, "VSN="); vsnNum != "" {
			if v := decodeOracleVSN(vsnNum); v != "" {
				diags = append(diags, fmt.Sprintf("Version: %s", v))
			}
		}
		errCode := extractTNSParam(refuseStr, "ERR=")
		if errCode == "" {
			errCode = extractTNSParam(refuseStr, "CODE=")
		}

		switch errCode {
		case "1189":
			diags = append(diags, "TNS: REFUSE (TNS-01189: Listener Command Refused)")
		case "12514":
			diags = append(diags, fmt.Sprintf("TNS: REFUSE (TNS-12514: Service '%s' Unknown)", svc))
		case "12505":
			diags = append(diags, fmt.Sprintf("TNS: REFUSE (TNS-12505: SID '%s' Unknown)", svc))
		case "12541":
			diags = append(diags, "TNS: REFUSE (TNS-12541: No Listener)")
		case "12560":
			diags = append(diags, "TNS: REFUSE (TNS-12560: Protocol Adapter Error)")
		case "":
			diags = append(diags, "TNS: REFUSE (Service/SID rejected)")
		default:
			diags = append(diags, fmt.Sprintf("TNS: REFUSE (TNS-%s)", errCode))
		}
	case 0x05: // TNS REDIRECT
		diags = append(diags, fmt.Sprintf("TNS: REDIRECT (Service: %s -> Dispatcher Active)", svc))
	case 0x0b: // TNS RESEND
		diags = append(diags, "TNS: RESEND (Parameter Negotiation)")
	default:
		return nil, fmt.Errorf("unexpected oracle tns packet type: 0x%x", pktType)
	}

	return diags, nil
}

// extractTNSParam extracts a key=value parameter from an Oracle TNS connect descriptor string.
func extractTNSParam(str, key string) string {
	upperStr := strings.ToUpper(str)
	upperKey := strings.ToUpper(key)
	idx := strings.Index(upperStr, upperKey)
	if idx < 0 {
		return ""
	}
	valPart := str[idx+len(key):]
	end := strings.IndexAny(valPart, " )")
	if end > 0 {
		return strings.TrimSpace(valPart[:end])
	}
	return strings.TrimSpace(valPart)
}

// probeMongoDB sends an OP_MSG hello query to MongoDB and parses BSON metadata.
func (d *DBing) probeMongoDB(conn net.Conn) ([]string, error) {
	var diags []string

	// MongoDB Wire Protocol: OP_MSG (OpCode 2013) hello command (52 bytes)
	mongoHello := []byte{
		0x34, 0x00, 0x00, 0x00, // Length (52 bytes)
		0x01, 0x00, 0x00, 0x00, // RequestID (1)
		0x00, 0x00, 0x00, 0x00, // ResponseTo (0)
		0xdd, 0x07, 0x00, 0x00, // OpCode: OP_MSG (2013)
		0x00, 0x00, 0x00, 0x00, // FlagBits (0)
		0x00,                   // Section Kind: 0 (Body)
		0x1f, 0x00, 0x00, 0x00, // Document Length (31 bytes)
		0x10, 'h', 'e', 'l', 'l', 'o', 0x00, 0x01, 0x00, 0x00, 0x00, // int32 "hello": 1
		0x02, '$', 'd', 'b', 0x00, 0x06, 0x00, 0x00, 0x00, 'a', 'd', 'm', 'i', 'n', 0x00, // string "$db": "admin"
		0x00, // Document null terminator
	}

	if _, err := conn.Write(mongoHello); err != nil {
		return nil, fmt.Errorf("mongodb hello query write failed: %w", err)
	}

	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("mongodb response header read failed: %w", err)
	}

	respLen := int(binary.LittleEndian.Uint32(header[0:4])) - 16
	if respLen > 0 && respLen < 65536 {
		body := make([]byte, respLen)
		if _, err := io.ReadFull(conn, body); err == nil {
			ver := extractBSONString(body, "version")
			if ver != "" {
				diags = append(diags, fmt.Sprintf("Version: %s", ver))
			} else {
				maxWire := extractBSONInt32(body, "maxWireVersion")
				switch {
				case maxWire >= 25:
					diags = append(diags, fmt.Sprintf("Version: MongoDB 8.0 (Wire %d)", maxWire))
				case maxWire >= 21:
					diags = append(diags, fmt.Sprintf("Version: MongoDB 7.0 (Wire %d)", maxWire))
				case maxWire >= 17:
					diags = append(diags, fmt.Sprintf("Version: MongoDB 6.0 (Wire %d)", maxWire))
				case maxWire >= 13:
					diags = append(diags, fmt.Sprintf("Version: MongoDB 5.0 (Wire %d)", maxWire))
				case maxWire >= 9:
					diags = append(diags, fmt.Sprintf("Version: MongoDB 4.4 (Wire %d)", maxWire))
				case maxWire > 0:
					diags = append(diags, fmt.Sprintf("WireVersion: %d", maxWire))
				}
			}

			setName := extractBSONString(body, "setName")
			msg := extractBSONString(body, "msg")
			bodyStr := string(body)

			if msg == "isdbgrid" {
				diags = append(diags, "Role: Mongos Router")
			} else if setName != "" {
				if strings.Contains(bodyStr, "isWritablePrimary") || strings.Contains(bodyStr, "ismaster") {
					diags = append(diags, fmt.Sprintf("Role: Primary (ReplSet: %s)", setName))
				} else {
					diags = append(diags, fmt.Sprintf("Role: Secondary (ReplSet: %s)", setName))
				}
			} else if strings.Contains(bodyStr, "isWritablePrimary") || strings.Contains(bodyStr, "ismaster") {
				diags = append(diags, "Role: Primary/Standalone")
			}

			if nodeAddr := extractBSONString(body, "me"); nodeAddr != "" {
				diags = append(diags, fmt.Sprintf("Node: %s", nodeAddr))
			}

			connID := extractBSONInt32(body, "connectionId")
			if connID < 0 {
				// #nosec G115 -- MongoDB connectionId fits in standard integer range
				connID = int32(extractBSONInt64(body, "connectionId"))
			}
			if connID > 0 {
				diags = append(diags, fmt.Sprintf("ConnID: %d", connID))
			}

			if maxBson := extractBSONInt32(body, "maxBsonObjectSize"); maxBson > 0 {
				diags = append(diags, fmt.Sprintf("MaxBSON: %s", formatBytes(int64(maxBson))))
			}

			if sessionTimeout := extractBSONInt32(body, "logicalSessionTimeoutMinutes"); sessionTimeout > 0 {
				diags = append(diags, fmt.Sprintf("SessionTimeout: %dm", sessionTimeout))
			}

			if extractBSONBool(body, "readOnly") {
				diags = append(diags, "ReadOnly: true")
			}

			diags = append(diags, "Protocol: OP_MSG (2013)")
		}
	}

	if len(diags) == 0 {
		diags = append(diags, "MongoDB Wire Protocol: OK")
	}

	return diags, nil
}

// probeCassandra sends a CQL STARTUP frame and decodes READY or AUTHENTICATE responses.
func (d *DBing) probeCassandra(conn net.Conn) ([]string, error) {
	var diags []string

	// CQL Native Protocol v4 STARTUP frame (22 bytes)
	cqlStartup := []byte{
		0x04,       // Version 4 (Request)
		0x00,       // Flags
		0x00, 0x01, // Stream ID 1
		0x01,                   // Opcode 1 (STARTUP)
		0x00, 0x00, 0x00, 0x16, // Length 22
		0x00, 0x01, // Map size: 1 key-value
		0x00, 0x0b, 0x43, 0x51, 0x4c, 0x5f, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4f, 0x4e, // "CQL_VERSION"
		0x00, 0x05, 0x33, 0x2e, 0x30, 0x2e, 0x30, // "3.0.0"
	}

	if _, err := conn.Write(cqlStartup); err != nil {
		return nil, fmt.Errorf("cql startup frame write failed: %w", err)
	}

	header := make([]byte, 9)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("cql response header read failed: %w", err)
	}

	// Response version should be 0x84 (v4 Response), 0x83, or 0x85 (v5)
	if header[0] != 0x84 && header[0] != 0x83 && header[0] != 0x85 {
		return nil, fmt.Errorf("unexpected cql response header version 0x%x", header[0])
	}

	opcode := header[4]
	switch opcode {
	case 0x02: // READY
		diags = append(diags, "CQL: v4/v5 (READY)")
	case 0x03: // AUTHENTICATE
		bodyLen := int(binary.BigEndian.Uint32(header[5:9]))
		if bodyLen > 2 && bodyLen < 512 {
			authBody := make([]byte, bodyLen)
			if _, err := io.ReadFull(conn, authBody); err == nil {
				authClass := string(authBody[2:])
				if idx := strings.LastIndex(authClass, "."); idx >= 0 {
					authClass = authClass[idx+1:]
				}
				diags = append(diags, fmt.Sprintf("CQL: v4, Auth: %s", authClass))
			}
		} else {
			diags = append(diags, "CQL: v4, Auth: Required")
		}
	default:
		diags = append(diags, fmt.Sprintf("CQL: v4 (Opcode 0x%x)", opcode))
	}

	return diags, nil
}

// probeSAPHANA sends the SAP HANA initial handshake frame and authentication initiation request.
func (d *DBing) probeSAPHANA(conn net.Conn) ([]string, error) {
	var diags []string

	// Official SAP HANA 14-byte initialization handshake (Magic 0xFFFFFFFF, Proto 4.20, Option Count 4)
	hanaInit := []byte{0xff, 0xff, 0xff, 0xff, 0x04, 0x14, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01}
	if _, err := conn.Write(hanaInit); err != nil {
		return nil, fmt.Errorf("sap hana init write failed: %w", err)
	}

	buf := make([]byte, 4096)
	_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return nil, fmt.Errorf("sap hana init response read failed: %w", err)
	}

	initData := buf[:n]
	var majorProto, minorProto int
	if len(initData) >= 3 && (initData[0] == 4 || initData[0] == 1) {
		majorProto = int(initData[0])
		minorProto = int(binary.LittleEndian.Uint16(initData[1:3]))
	} else if len(initData) >= 8 && (initData[4] == 4 || initData[4] == 1) {
		majorProto = int(initData[4])
		minorProto = int(binary.LittleEndian.Uint16(initData[5:7]))
	}

	var protoVerStr string
	switch majorProto {
	case 4:
		if minorProto > 0 {
			protoVerStr = fmt.Sprintf("SAP HANA 2.0 (Protocol v4.%d)", minorProto)
		} else {
			protoVerStr = "SAP HANA 2.0"
		}
	case 1:
		if minorProto > 0 {
			protoVerStr = fmt.Sprintf("SAP HANA 1.0 (Protocol v1.%d)", minorProto)
		} else {
			protoVerStr = "SAP HANA 1.0"
		}
	default:
		if majorProto > 0 {
			protoVerStr = fmt.Sprintf("SAP HANA (Protocol v%d.%d)", majorProto, minorProto)
		} else {
			protoVerStr = "SAP HANA 2.0"
		}
	}

	// Instance and topology deduction from SAP standard port schema 3<NN><XX>
	port := d.Port
	var instanceInfo string
	if port >= 30000 && port <= 39999 {
		instNum := (port - 30000) / 100
		subPort := port % 100
		switch subPort {
		case 13:
			instanceInfo = fmt.Sprintf("Instance: %02d (SystemDB SQL)", instNum)
		case 15:
			instanceInfo = fmt.Sprintf("Instance: %02d (Tenant SQL)", instNum)
		case 17:
			instanceInfo = fmt.Sprintf("Instance: %02d (Tenant SQL)", instNum)
		case 0o1:
			instanceInfo = fmt.Sprintf("Instance: %02d (Nameserver)", instNum)
		default:
			instanceInfo = fmt.Sprintf("Instance: %02d", instNum)
		}
	}

	// Send Authenticate / Initial Connect segment to discover supported auth & DB details
	userBytes := []byte("SYSTEM")
	var pData bytes.Buffer
	_ = binary.Write(&pData, binary.LittleEndian, uint16(1)) // Field count: 1
	// #nosec G115 -- static 6-byte user buffer
	pData.WriteByte(byte(len(userBytes))) // Field size: 6
	pData.Write(userBytes)                // Field data: "SYSTEM"

	payloadBytes := pData.Bytes()
	padLen := (8 - (len(payloadBytes) % 8)) % 8
	for i := 0; i < padLen; i++ {
		payloadBytes = append(payloadBytes, 0x00)
	}

	partHeader := make([]byte, 16)
	partHeader[0] = 33                                // Part Kind 33 (AUTHENTICATION)
	binary.LittleEndian.PutUint16(partHeader[2:4], 1) // Argument count 1
	// #nosec G115 -- static authentication packet payload length
	binary.LittleEndian.PutUint32(partHeader[8:12], uint32(len(payloadBytes))) // Payload size
	// #nosec G115 -- static authentication packet payload length
	binary.LittleEndian.PutUint32(partHeader[12:16], uint32(len(payloadBytes)))

	partFull := append(partHeader, payloadBytes...)

	segmentHeader := make([]byte, 24)
	// #nosec G115 -- bounded SAP HANA segment length
	segLen := uint32(24 + len(partFull))
	binary.LittleEndian.PutUint32(segmentHeader[0:4], segLen)
	binary.LittleEndian.PutUint16(segmentHeader[8:10], 1)  // Part count 1
	binary.LittleEndian.PutUint16(segmentHeader[10:12], 1) // Segment number 1
	segmentHeader[12] = 1                                  // Segment kind: 1 (Request)
	segmentHeader[13] = 65                                 // Message type: 65 (Connect / Authenticate)

	segmentFull := append(segmentHeader, partFull...)

	msgHeader := make([]byte, 32)
	for i := 0; i < 8; i++ {
		msgHeader[i] = 0xff // Session ID: -1
	}
	// #nosec G115 -- bounded SAP HANA message length
	binary.LittleEndian.PutUint32(msgHeader[12:16], uint32(len(segmentFull)))
	// #nosec G115 -- bounded SAP HANA message length
	binary.LittleEndian.PutUint32(msgHeader[16:20], uint32(len(segmentFull)))
	binary.LittleEndian.PutUint16(msgHeader[20:22], 1)

	fullReq := append(msgHeader, segmentFull...)

	var srvVer, dbName string
	var authMethods []string

	if _, err := conn.Write(fullReq); err == nil {
		respBuf := make([]byte, 4096)
		_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
		if rn, err := conn.Read(respBuf); err == nil && rn > 16 {
			respStr := string(respBuf[:rn])

			for _, match := range findHanaVersions(respStr) {
				if match != "" {
					srvVer = decodeHanaVersion(match)
					break
				}
			}

			for _, mech := range []string{"SCRAMSHA256", "SCRAMPBKDF2SHA256", "PASSWORD", "SAML", "JWT", "GSS", "X509"} {
				if strings.Contains(respStr, mech) {
					authMethods = append(authMethods, mech)
				}
			}

			if strings.Contains(respStr, "SYSTEMDB") {
				dbName = "SYSTEMDB"
			} else if idx := strings.Index(respStr, "databaseName"); idx >= 0 && idx+20 < len(respStr) {
				sub := respStr[idx+12 : idx+30]
				nullIdx := strings.IndexByte(sub, 0x00)
				if nullIdx > 0 {
					dbName = strings.TrimSpace(sub[:nullIdx])
				}
			}
		}
	}

	if srvVer != "" {
		diags = append(diags, fmt.Sprintf("Version: %s", srvVer))
	} else if protoVerStr != "" {
		diags = append(diags, fmt.Sprintf("Version: %s", protoVerStr))
	}

	if dbName != "" {
		diags = append(diags, fmt.Sprintf("Database: %s", dbName))
	}

	if instanceInfo != "" {
		diags = append(diags, instanceInfo)
	}

	if len(authMethods) > 0 {
		diags = append(diags, fmt.Sprintf("Auth: %s", strings.Join(authMethods, "|")))
	}

	diags = append(diags, "Protocol: SAP HANA SQL")
	return diags, nil
}

var hanaVerRegex = regexp.MustCompile(`[12]\.00\.\d{3}\.\d{2}(?:\.\d+)?`)

func findHanaVersions(s string) []string {
	return hanaVerRegex.FindAllString(s, -1)
}

func decodeHanaVersion(rawVer string) string {
	parts := strings.Split(rawVer, ".")
	if len(parts) < 3 {
		return fmt.Sprintf("SAP HANA %s", rawVer)
	}
	major := parts[0]
	spsNum, err := strconv.Atoi(parts[2])
	if err != nil {
		return fmt.Sprintf("SAP HANA %s", rawVer)
	}
	sps := spsNum / 10
	patch := spsNum % 10
	if patch > 0 {
		return fmt.Sprintf("SAP HANA %s.0 SPS%02d Patch %d (%s)", major, sps, patch, rawVer)
	}
	return fmt.Sprintf("SAP HANA %s.0 SPS%02d (%s)", major, sps, rawVer)
}

// findBSONElement locates a key with a specific BSON type byte prefix in binary data.
func findBSONElement(data []byte, typeByte byte, key string) []byte {
	prefix := append([]byte{typeByte}, []byte(key+"\x00")...)
	idx := bytes.Index(data, prefix)
	if idx < 0 {
		return nil
	}
	return data[idx+len(prefix):]
}

func extractBSONString(data []byte, key string) string {
	payload := findBSONElement(data, 0x02, key)
	if len(payload) < 4 {
		return ""
	}
	strLen := int(binary.LittleEndian.Uint32(payload[0:4]))
	if strLen <= 1 || 4+strLen > len(payload) {
		return ""
	}
	return strings.TrimRight(string(payload[4:4+strLen-1]), "\x00")
}

func extractBSONInt32(data []byte, key string) int32 {
	payload := findBSONElement(data, 0x10, key)
	if len(payload) < 4 {
		return -1
	}
	// #nosec G115 -- BSON 32-bit integer binary extraction
	return int32(binary.LittleEndian.Uint32(payload[0:4]))
}

func extractBSONInt64(data []byte, key string) int64 {
	payload := findBSONElement(data, 0x12, key)
	if len(payload) < 8 {
		return -1
	}
	// #nosec G115 -- BSON 64-bit integer binary extraction
	return int64(binary.LittleEndian.Uint64(payload[0:8]))
}

func extractBSONBool(data []byte, key string) bool {
	payload := findBSONElement(data, 0x08, key)
	if len(payload) < 1 {
		return false
	}
	return payload[0] == 1
}

// decodeOracleVSN translates an Oracle VSN integer code into a human-readable version string.
func decodeOracleVSN(vsnStr string) string {
	vsn, err := strconv.ParseUint(vsnStr, 10, 32)
	if err != nil {
		return ""
	}
	major := (vsn >> 24) & 0xff
	minor := (vsn >> 20) & 0x0f
	update := (vsn >> 12) & 0xff
	patch := (vsn >> 8) & 0x0f
	portPatch := vsn & 0xff

	var releaseName string
	switch major {
	case 23:
		releaseName = "Oracle 23c"
	case 21:
		releaseName = "Oracle 21c"
	case 19:
		releaseName = "Oracle 19c"
	case 18:
		releaseName = "Oracle 18c"
	case 12:
		releaseName = "Oracle 12c"
	case 11:
		releaseName = "Oracle 11g"
	default:
		releaseName = fmt.Sprintf("Oracle v%d", major)
	}
	return fmt.Sprintf("%s (%d.%d.%d.%d.%d)", releaseName, major, minor, update, patch, portPatch)
}

// tnsProtocolRelease maps the 16-bit TNS protocol version from ACCEPT frames to Oracle releases.
func tnsProtocolRelease(tnsVer uint16) string {
	switch tnsVer {
	case 316:
		return "Oracle 19c/21c/23c"
	case 315:
		return "Oracle 18c"
	case 314:
		return "Oracle 12c R2"
	case 313:
		return "Oracle 12c R1"
	case 312:
		return "Oracle 11g R2"
	case 311:
		return "Oracle 11g R1"
	case 310:
		return "Oracle 10g"
	default:
		return fmt.Sprintf("Oracle TNS v%d", tnsVer)
	}
}
