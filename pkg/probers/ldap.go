package probers

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type LDAPOptions struct {
	Hostname string
	IP       netip.Addr
	Port     uint16
	UseTLS   bool
	Timeout  time.Duration
	Dialer   *net.Dialer
}

// LDAPing implements Pinger for LDAP (RFC 4511) and LDAPS directory services.
type LDAPing struct {
	hostname string
	ip       netip.Addr
	port     uint16
	useTLS   bool
	timeout  time.Duration
	dialer   *net.Dialer
}

// NewLDAPing constructs a new LDAP / LDAPS prober.
func NewLDAPing(opts LDAPOptions) *LDAPing {
	port := opts.Port
	if port == 0 {
		if opts.UseTLS {
			port = 636
		} else {
			port = 389
		}
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	return &LDAPing{
		hostname: opts.Hostname,
		ip:       opts.IP,
		port:     port,
		useTLS:   opts.UseTLS,
		timeout:  opts.Timeout,
		dialer:   d,
	}
}

// Ping connects to the LDAP daemon, transmits an RFC 4511 Anonymous Simple Bind Request, and validates the BindResponse.
func (l *LDAPing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	targetHost := l.hostname
	if targetHost == "" {
		targetHost = l.ip.String()
	}
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(l.port)))

	var conn net.Conn
	var err error

	if l.useTLS {
		tlsConfig := &tls.Config{
			ServerName: targetHost,
			MinVersion: tls.VersionTLS12,
		}
		tlsDialer := &tls.Dialer{
			NetDialer: l.dialer,
			Config:    tlsConfig,
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = l.dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(l.timeout))

	// RFC 4511 LDAP Message: BindRequest (Anonymous simple bind)
	// Sequence (12 bytes):
	//   MessageID: 1 (INTEGER 1)
	//   BindRequest (Tag 0x60, 7 bytes):
	//     Version: 3 (INTEGER 3)
	//     Name: "" (OCTET STRING 0)
	//     Authentication: simple "" (Context Tag 0x80, 0 bytes)
	bindRequest := []byte{
		0x30, 0x0c, // SEQUENCE, len 12
		0x02, 0x01, 0x01, // Message ID: 1
		0x60, 0x07, // [APPLICATION 0] BindRequest, len 7
		0x02, 0x01, 0x03, // LDAP Version: 3
		0x04, 0x00, // Name: ""
		0x80, 0x00, // Simple Authentication: ""
	}

	if _, err := conn.Write(bindRequest); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("ldap bind request write failed: %w", err),
		}
	}

	respBuf := make([]byte, 512)
	n, err := conn.Read(respBuf)
	if err != nil || n < 7 {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("ldap bind response read failed: %w", err),
		}
	}
	if respBuf[0] != 0x30 {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("unexpected ldap response sequence tag: 0x%x", respBuf[0]),
		}
	}
	fullResp := respBuf[:n]

	var diags []string
	var resultCode byte
	hasResultCode := false

	// Locate ResultCode in BindResponse: Tag 0x0A (ENUMERATED)
	for i := 0; i < len(fullResp)-2; i++ {
		if fullResp[i] == 0x0a && fullResp[i+1] == 0x01 {
			resultCode = fullResp[i+2]
			hasResultCode = true
			break
		}
	}

	if hasResultCode {
		diags = append(diags, fmt.Sprintf("Bind: %s (Code %d)", ldapResultCodeName(resultCode), resultCode))
	} else {
		diags = append(diags, "LDAPv3 Anonymous Bind OK")
	}

	var namingContext, dnsHostName string

	// If Bind succeeded, query RootDSE (RFC 4512) for Default Naming Context (DC/Domain) and Server Info
	if !hasResultCode || resultCode == 0 {
		attrs := []string{"defaultNamingContext", "namingContexts", "dnsHostName", "rootDomainNamingContext"}
		var attrBuf bytes.Buffer
		for _, a := range attrs {
			attrBuf.WriteByte(0x04) // OCTET STRING
			// #nosec G115 -- static LDAP attribute name length
			attrBuf.WriteByte(byte(len(a)))
			attrBuf.WriteString(a)
		}

		filter := []byte{0x87, 0x0b, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's'} // present: objectClass

		var searchReqBody bytes.Buffer
		searchReqBody.Write([]byte{0x04, 0x00})       // BaseDN: ""
		searchReqBody.Write([]byte{0x0a, 0x01, 0x00}) // Scope: baseObject (0)
		searchReqBody.Write([]byte{0x0a, 0x01, 0x00}) // Deref: neverDerefAliases (0)
		searchReqBody.Write([]byte{0x02, 0x01, 0x00}) // SizeLimit: 0
		searchReqBody.Write([]byte{0x02, 0x01, 0x05}) // TimeLimit: 5
		searchReqBody.Write([]byte{0x01, 0x01, 0x00}) // TypesOnly: false
		searchReqBody.Write(filter)                   // Filter: (objectClass=*)
		searchReqBody.WriteByte(0x30)                 // SEQUENCE of attributes
		// #nosec G115 -- bounded attribute buffer length
		searchReqBody.WriteByte(byte(attrBuf.Len()))
		searchReqBody.Write(attrBuf.Bytes())

		var searchMsg bytes.Buffer
		searchMsg.Write([]byte{0x02, 0x01, 0x02}) // MessageID: 2
		searchMsg.WriteByte(0x63)                 // [APPLICATION 3] SearchRequest
		// #nosec G115 -- bounded search request length
		searchMsg.WriteByte(byte(searchReqBody.Len()))
		searchMsg.Write(searchReqBody.Bytes())

		var rootDSEReq bytes.Buffer
		rootDSEReq.WriteByte(0x30) // SEQUENCE
		// #nosec G115 -- bounded root DSE message length
		rootDSEReq.WriteByte(byte(searchMsg.Len()))
		rootDSEReq.Write(searchMsg.Bytes())

		if _, err := conn.Write(rootDSEReq.Bytes()); err == nil {
			dseBuf := make([]byte, 4096)
			_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			if dn, err := conn.Read(dseBuf); err == nil && dn > 10 {
				// Extract defaultNamingContext or namingContexts (e.g. DC=corp,DC=example,DC=com)
				for _, marker := range []string{"defaultNamingContext", "rootDomainNamingContext", "namingContexts"} {
					if val := extractLDAPStringAttr(dseBuf[:dn], marker); val != "" {
						namingContext = val
						break
					}
				}

				// Extract dnsHostName (e.g. dc01.corp.example.com)
				if val := extractLDAPStringAttr(dseBuf[:dn], "dnsHostName"); val != "" {
					dnsHostName = val
				}
			}
		}
	}

	if namingContext != "" {
		diags = append(diags, fmt.Sprintf("BaseDN: %s", namingContext))
	}

	if dnsHostName != "" {
		diags = append(diags, fmt.Sprintf("DC: %s", dnsHostName))
	}

	if l.useTLS {
		if tlsConn, ok := conn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()
			diags = append(diags, fmt.Sprintf("TLS: %s (%s)", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite)))
		}
	}

	diags = append(diags, "Protocol: LDAPv3")
	rtt := time.Since(start)

	var probeErr error
	if hasResultCode && resultCode != 0 && resultCode != 7 && resultCode != 49 && resultCode != 53 {
		probeErr = fmt.Errorf("ldap bind returned error code %d (%s)", resultCode, ldapResultCodeName(resultCode))
	}

	return ProbeResult{
		LocalAddr:   conn.LocalAddr(),
		RTT:         rtt,
		Diagnostics: strings.Join(diags, ", "),
		Err:         probeErr,
	}
}

func ldapResultCodeName(code byte) string {
	switch code {
	case 0:
		return "SUCCESS"
	case 1:
		return "OPERATIONS_ERROR"
	case 2:
		return "PROTOCOL_ERROR"
	case 7:
		return "AUTH_METHOD_NOT_SUPPORTED"
	case 8:
		return "STRONGER_AUTH_REQUIRED"
	case 14:
		return "SASL_BIND_IN_PROGRESS"
	case 32:
		return "NO_SUCH_OBJECT"
	case 34:
		return "INVALID_DN_SYNTAX"
	case 48:
		return "INAPPROPRIATE_AUTH"
	case 49:
		return "INVALID_CREDENTIALS"
	case 50:
		return "INSUFFICIENT_ACCESS_RIGHTS"
	case 51:
		return "BUSY"
	case 52:
		return "UNAVAILABLE"
	case 53:
		return "UNWILLING_TO_PERFORM"
	default:
		return "RESULT"
	}
}

// extractLDAPStringAttr finds an attribute key and extracts its ASN.1 OCTET STRING value.
func extractLDAPStringAttr(data []byte, marker string) string {
	idx := bytes.Index(data, []byte(marker))
	if idx < 0 {
		return ""
	}
	offset := idx + len(marker)
	for i := offset; i < len(data)-2 && i < offset+30; i++ {
		if data[i] == 0x04 { // OCTET STRING tag
			strLen := int(data[i+1])
			if strLen > 0 && i+2+strLen <= len(data) {
				val := string(data[i+2 : i+2+strLen])
				if len(val) > 0 {
					return val
				}
			}
		}
	}
	return ""
}
