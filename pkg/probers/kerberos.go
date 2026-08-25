package probers

import (
	"bytes"
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

// KerberosOptions defines the configuration parameters for probing a Kerberos KDC.
type KerberosOptions struct {
	Hostname string
	IP       netip.Addr
	Port     uint16
	IsUDP    bool
	Realm    string
	Timeout  time.Duration
	Dialer   *net.Dialer
}

// Kerberosing implements Pinger for Kerberos v5 (RFC 4120) across TCP and UDP.
type Kerberosing struct {
	hostname string
	ip       netip.Addr
	port     uint16
	isUDP    bool
	realm    string
	timeout  time.Duration
	dialer   *net.Dialer
}

// NewKerberosing constructs a new Kerberos prober.
func NewKerberosing(opts KerberosOptions) *Kerberosing {
	port := opts.Port
	if port == 0 {
		port = 88
	}

	d := opts.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: opts.Timeout}
	}

	realm := strings.TrimSpace(opts.Realm)
	if realm == "" {
		if opts.Hostname != "" && !opts.IP.IsValid() {
			realm = strings.ToUpper(opts.Hostname)
		} else {
			realm = "EXAMPLE.COM"
		}
	}

	return &Kerberosing{
		hostname: opts.Hostname,
		ip:       opts.IP,
		port:     port,
		isUDP:    opts.IsUDP,
		realm:    realm,
		timeout:  opts.Timeout,
		dialer:   d,
	}
}

// Ping probes the Kerberos Key Distribution Center (KDC) over TCP or UDP.
func (k *Kerberosing) Ping(ctx context.Context) ProbeResult {
	start := time.Now()

	target := k.hostname
	if target == "" {
		target = k.ip.String()
	}
	addr := net.JoinHostPort(target, strconv.Itoa(int(k.port)))

	network := "tcp"
	if k.isUDP {
		network = "udp"
	}

	conn, err := k.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return ProbeResult{
			RTT: time.Since(start),
			Err: err,
		}
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(k.timeout))

	asReq := buildKerberosASREQ(k.realm, "netping")

	if k.isUDP {
		// RFC 4120 §7.2.1: UDP transmits raw ASN.1 DER payload
		if _, err := conn.Write(asReq); err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       time.Since(start),
				Err:       fmt.Errorf("kerberos udp write failed: %w", err),
			}
		}

		respBuf := make([]byte, 4096)
		n, err := conn.Read(respBuf)
		rtt := time.Since(start)
		if err != nil {
			return ProbeResult{
				LocalAddr: conn.LocalAddr(),
				RTT:       rtt,
				Err:       fmt.Errorf("kerberos udp read failed: %w", err),
			}
		}

		return k.processResponse(conn.LocalAddr(), respBuf[:n], rtt, start)
	}

	// RFC 4120 §7.2.2: TCP uses 4-byte big-endian stream length prefix
	lenBuf := make([]byte, 4)
	// #nosec G115 -- AS-REQ payload size strictly bounded
	binary.BigEndian.PutUint32(lenBuf, uint32(len(asReq)))

	if _, err := conn.Write(append(lenBuf, asReq...)); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("kerberos tcp write failed: %w", err),
		}
	}

	respLenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, respLenBuf); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("kerberos length read failed: %w", err),
		}
	}

	respLen := binary.BigEndian.Uint32(respLenBuf)
	if respLen == 0 || respLen > 65536 {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("invalid kerberos response length: %d", respLen),
		}
	}

	respBody := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBody); err != nil {
		return ProbeResult{
			LocalAddr: conn.LocalAddr(),
			RTT:       time.Since(start),
			Err:       fmt.Errorf("kerberos body read failed: %w", err),
		}
	}
	rtt := time.Since(start)

	return k.processResponse(conn.LocalAddr(), respBody, rtt, start)
}

// processResponse parses and analyzes the ASN.1 Kerberos response.
func (k *Kerberosing) processResponse(localAddr net.Addr, data []byte, rtt time.Duration, probeStartTime time.Time) ProbeResult {
	if len(data) < 4 {
		return ProbeResult{
			LocalAddr: localAddr,
			RTT:       rtt,
			Err:       fmt.Errorf("kerberos response payload too short (%d bytes)", len(data)),
		}
	}

	appTag := data[0]
	transportStr := "TCP"
	if k.isUDP {
		transportStr = "UDP"
	}

	var diags []string
	diags = append(diags, "Protocol: Kerberos v5 (RFC 4120)", "Transport: "+transportStr)

	// Check response message tag
	switch appTag {
	case 0x7e: // [APPLICATION 30] KRB-ERROR
		diags = append(diags, "Msg: KRB-ERROR (30)")
		parsed := dissectKRBError(data)

		if parsed.HasErrorCode {
			diags = append(diags, fmt.Sprintf("Status: %s (%d)", krbErrorCodeName(parsed.ErrorCode), parsed.ErrorCode))
		}
		if parsed.Realm != "" {
			diags = append(diags, "Realm: "+parsed.Realm)
		}
		if parsed.SName != "" {
			diags = append(diags, "SPN: "+parsed.SName)
		}
		if !parsed.ServerTime.IsZero() {
			diags = append(diags, "ServerTime: "+parsed.ServerTime.UTC().Format("2006-01-02 15:04:05")+" UTC")

			// Clock Skew Analysis
			skew := parsed.ServerTime.Sub(probeStartTime.UTC())
			skewSec := skew.Seconds()
			sign := "+"
			if skewSec < 0 {
				sign = "-"
				skewSec = math.Abs(skewSec)
			}
			skewStr := fmt.Sprintf("ClockSkew: %s%.2fs", sign, skewSec)
			if math.Abs(skew.Seconds()) >= 300 {
				skewStr += " [CRITICAL: SKEW >= 300s]"
			}
			diags = append(diags, skewStr)
		}

		if len(parsed.SupportedETypes) > 0 {
			diags = append(diags, fmt.Sprintf("ETypes: [%s]", strings.Join(parsed.SupportedETypes, ", ")))
		}
		if len(parsed.PreAuthMethods) > 0 {
			diags = append(diags, fmt.Sprintf("PreAuth: [%s]", strings.Join(parsed.PreAuthMethods, ", ")))
		}
		if parsed.EText != "" {
			diags = append(diags, "E-Text: "+parsed.EText)
		}

		// RFC 4120 standard expected error codes indicating healthy responsive KDC
		// Codes 6 (C_PRINCIPAL_UNKNOWN), 7 (S_PRINCIPAL_UNKNOWN), 15 (NAME_EXP), 24 (PREAUTH_FAILED),
		// 25 (PREAUTH_REQUIRED), 37 (SKEW), 68 (WRONG_REALM)
		var probeErr error
		if parsed.HasErrorCode && parsed.ErrorCode != 0 &&
			parsed.ErrorCode != 6 && parsed.ErrorCode != 7 &&
			parsed.ErrorCode != 15 && parsed.ErrorCode != 24 &&
			parsed.ErrorCode != 25 && parsed.ErrorCode != 37 &&
			parsed.ErrorCode != 68 {
			probeErr = fmt.Errorf("kdc returned error %d (%s)", parsed.ErrorCode, krbErrorCodeName(parsed.ErrorCode))
		}

		return ProbeResult{
			LocalAddr:   localAddr,
			RTT:         rtt,
			Diagnostics: strings.Join(diags, " │ "),
			Err:         probeErr,
		}

	case 0x6b: // [APPLICATION 11] AS-REP
		diags = append(diags, "Msg: AS-REP (11)", "Status: OK (Ticket Issued)")
		if realm := extractASN1GeneralString(data); realm != "" {
			diags = append(diags, "Realm: "+realm)
		}
		return ProbeResult{
			LocalAddr:   localAddr,
			RTT:         rtt,
			Diagnostics: strings.Join(diags, " │ "),
			Err:         nil,
		}

	default:
		return ProbeResult{
			LocalAddr: localAddr,
			RTT:       rtt,
			Err:       fmt.Errorf("unexpected kerberos response tag 0x%02x", appTag),
		}
	}
}

// parsedKRBError holds extracted diagnostic telemetry from a KRB-ERROR packet.
type parsedKRBError struct {
	HasErrorCode    bool
	ErrorCode       int
	Realm           string
	SName           string
	CName           string
	ServerTime      time.Time
	SupportedETypes []string
	PreAuthMethods  []string
	EText           string
}

// dissectKRBError parses the ASN.1 structure of KRB-ERROR.
func dissectKRBError(data []byte) parsedKRBError {
	var res parsedKRBError

	// Walk top-level context tags in KRB-ERROR
	// [APPLICATION 30] SEQUENCE -> Context tags [0] through [12]
	offset := 0
	if offset < len(data) && data[offset] == 0x7e {
		offset++
		_, newOffset := readASN1Length(data, offset)
		offset = newOffset
	}
	if offset < len(data) && data[offset] == 0x30 {
		offset++
		_, newOffset := readASN1Length(data, offset)
		offset = newOffset
	}

	for offset < len(data) {
		if (data[offset] & 0xc0) != 0x80 && (data[offset] & 0xc0) != 0xa0 {
			break
		}
		tagNum := int(data[offset] & 0x1f)
		offset++
		tagLen, newOffset := readASN1Length(data, offset)
		if newOffset+tagLen > len(data) {
			break
		}
		tagContent := data[newOffset : newOffset+tagLen]
		offset = newOffset + tagLen

		switch tagNum {
		case 4: // stime: KerberosTime [GeneralizedTime 0x18]
			if t, err := parseASN1GeneralizedTime(tagContent); err == nil {
				res.ServerTime = t
			}
		case 6: // error-code: INTEGER [0x02]
			if val, ok := parseASN1Integer(tagContent); ok {
				res.ErrorCode = val
				res.HasErrorCode = true
			}
		case 7: // crealm: Realm [GeneralString 0x1b]
			if str := parseASN1String(tagContent); str != "" {
				res.Realm = str
			}
		case 9: // realm: Realm [GeneralString 0x1b]
			if str := parseASN1String(tagContent); str != "" {
				res.Realm = str
			}
		case 10: // sname: PrincipalName
			if sname := parsePrincipalName(tagContent); sname != "" {
				res.SName = sname
			}
		case 11: // e-text: GeneralString
			if str := parseASN1String(tagContent); str != "" {
				res.EText = str
			}
		case 12: // e-data: OCTET STRING / PA-DATA sequence
			etypes, preauth := parseEDataPAData(tagContent)
			if len(etypes) > 0 {
				res.SupportedETypes = etypes
			}
			if len(preauth) > 0 {
				res.PreAuthMethods = preauth
			}
		}
	}

	return res
}

// buildKerberosASREQ constructs a standard RFC 4120 DER-encoded AS-REQ packet.
func buildKerberosASREQ(realm, principal string) []byte {
	now := time.Now().UTC()
	tillTime := now.Add(24 * time.Hour)
	tillStr := tillTime.Format("20060102150405Z")

	// PrincipalName (cname): name-type 1 (NT-PRINCIPAL), name-string { principal }
	var cnameBuf bytes.Buffer
	cnameBuf.Write([]byte{0xa0, 0x03, 0x02, 0x01, 0x01}) // [0] INTEGER 1
	var cnameStrSeq bytes.Buffer
	cnameStrSeq.WriteByte(0x1b) // GeneralString
	// #nosec G115 -- principal name bounded
	cnameStrSeq.WriteByte(byte(len(principal)))
	cnameStrSeq.WriteString(principal)
	cnameBuf.Write([]byte{0xa1, byte(cnameStrSeq.Len() + 2), 0x30, byte(cnameStrSeq.Len())})
	cnameBuf.Write(cnameStrSeq.Bytes())

	cnameSeq := wrapASN1(0x30, cnameBuf.Bytes())
	cnameWrapped := wrapASN1(0xa1, cnameSeq) // [1] PrincipalName

	// Realm [2] GeneralString
	realmBytes := wrapASN1(0x1b, []byte(realm))
	realmWrapped := wrapASN1(0xa2, realmBytes) // [2] Realm

	// sname [3] PrincipalName: krbtgt / realm
	var snameBuf bytes.Buffer
	snameBuf.Write([]byte{0xa0, 0x03, 0x02, 0x01, 0x02}) // [0] INTEGER 2 (NT-SRV-INST)
	var snameStrSeq bytes.Buffer
	snameStrSeq.WriteByte(0x1b)
	snameStrSeq.WriteByte(6)
	snameStrSeq.WriteString("krbtgt")
	snameStrSeq.WriteByte(0x1b)
	// #nosec G115 -- realm length bounded
	snameStrSeq.WriteByte(byte(len(realm)))
	snameStrSeq.WriteString(realm)
	snameBuf.Write([]byte{0xa1, byte(snameStrSeq.Len() + 2), 0x30, byte(snameStrSeq.Len())})
	snameBuf.Write(snameStrSeq.Bytes())

	snameSeq := wrapASN1(0x30, snameBuf.Bytes())
	snameWrapped := wrapASN1(0xa3, snameSeq) // [3] PrincipalName

	// till [5] KerberosTime (GeneralizedTime)
	tillBytes := wrapASN1(0x18, []byte(tillStr))
	tillWrapped := wrapASN1(0xa5, tillBytes)

	// nonce [7] UInt32 (INTEGER 12345678)
	nonceBytes := []byte{0x02, 0x04, 0x00, 0xbc, 0x61, 0x4e}
	nonceWrapped := wrapASN1(0xa7, nonceBytes)

	// etype [8] SEQUENCE OF Int32:
	// 18 (aes256-cts-hmac-sha1-96), 17 (aes128-cts-hmac-sha1-96), 23 (rc4-hmac)
	etypeList := []byte{
		0x02, 0x01, 0x12, // 18
		0x02, 0x01, 0x11, // 17
		0x02, 0x01, 0x17, // 23
	}
	etypeSeq := wrapASN1(0x30, etypeList)
	etypeWrapped := wrapASN1(0xa8, etypeSeq)

	// KDC-REQ-BODY Sequence
	var bodyBuf bytes.Buffer
	// kdc-options [0] KDCOptions: BIT STRING (forwardable, proxiable, renewable_ok)
	bodyBuf.Write([]byte{0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10})
	bodyBuf.Write(cnameWrapped)
	bodyBuf.Write(realmWrapped)
	bodyBuf.Write(snameWrapped)
	bodyBuf.Write(tillWrapped)
	bodyBuf.Write(nonceWrapped)
	bodyBuf.Write(etypeWrapped)

	reqBody := wrapASN1(0x30, bodyBuf.Bytes())
	reqBodyWrapped := wrapASN1(0xa4, reqBody) // [4] req-body

	// KDC-REQ Sequence:
	// pvno [1] INTEGER 5
	// msg-type [2] INTEGER 10 (krb-as-req)
	// req-body [4]
	var kdcReqBuf bytes.Buffer
	kdcReqBuf.Write([]byte{0xa1, 0x03, 0x02, 0x01, 0x05}) // pvno: 5
	kdcReqBuf.Write([]byte{0xa2, 0x03, 0x02, 0x01, 0x0a}) // msg-type: 10
	kdcReqBuf.Write(reqBodyWrapped)

	kdcReqSeq := wrapASN1(0x30, kdcReqBuf.Bytes())
	return wrapASN1(0x6a, kdcReqSeq) // [APPLICATION 10]
}

// wrapASN1 prepends an ASN.1 identifier and length header.
func wrapASN1(tag byte, content []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(tag)
	l := len(content)
	if l < 128 {
		// #nosec G115 -- bounded ASN.1 length
		buf.WriteByte(byte(l))
	} else if l < 256 {
		// #nosec G115 -- bounded ASN.1 length
		buf.Write([]byte{0x81, byte(l)})
	} else {
		// #nosec G115 -- bounded ASN.1 length
		buf.Write([]byte{0x82, byte(l >> 8), byte(l & 0xff)})
	}
	buf.Write(content)
	return buf.Bytes()
}

// readASN1Length decodes DER length and returns length and new offset.
func readASN1Length(data []byte, offset int) (int, int) {
	if offset >= len(data) {
		return 0, offset
	}
	b := data[offset]
	offset++
	if (b & 0x80) == 0 {
		return int(b), offset
	}
	numBytes := int(b & 0x7f)
	if offset+numBytes > len(data) || numBytes > 4 {
		return 0, offset
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[offset])
		offset++
	}
	return length, offset
}

// parseASN1Integer parses an ASN.1 INTEGER value.
func parseASN1Integer(data []byte) (int, bool) {
	offset := 0
	if offset < len(data) && (data[offset]&0xc0) != 0 {
		offset++
		_, offset = readASN1Length(data, offset)
	}
	if offset >= len(data) || data[offset] != 0x02 {
		return 0, false
	}
	offset++
	length, offset := readASN1Length(data, offset)
	if offset+length > len(data) || length == 0 || length > 4 {
		return 0, false
	}
	val := 0
	for i := 0; i < length; i++ {
		val = (val << 8) | int(data[offset+i])
	}
	return val, true
}

// parseASN1String extracts a string from GeneralString (0x1b), UTF8String (0x0c), or PrintableString (0x13).
func parseASN1String(data []byte) string {
	offset := 0
	if offset < len(data) && (data[offset]&0xc0) != 0 {
		offset++
		_, offset = readASN1Length(data, offset)
	}
	if offset >= len(data) {
		return ""
	}
	tag := data[offset]
	if tag != 0x1b && tag != 0x0c && tag != 0x13 && tag != 0x16 && tag != 0x04 {
		return ""
	}
	offset++
	length, offset := readASN1Length(data, offset)
	if offset+length > len(data) {
		return ""
	}
	return string(data[offset : offset+length])
}

// parseASN1GeneralizedTime decodes KerberosTime (e.g. 20260825214023Z).
func parseASN1GeneralizedTime(data []byte) (time.Time, error) {
	offset := 0
	if offset < len(data) && (data[offset]&0xc0) != 0 {
		offset++
		_, offset = readASN1Length(data, offset)
	}
	if offset >= len(data) || data[offset] != 0x18 {
		return time.Time{}, fmt.Errorf("not generalized time")
	}
	offset++
	length, offset := readASN1Length(data, offset)
	if offset+length > len(data) {
		return time.Time{}, fmt.Errorf("out of bounds")
	}
	str := string(data[offset : offset+length])
	return time.Parse("20060102150405Z", str)
}

// parsePrincipalName parses a Kerberos PrincipalName sequence.
func parsePrincipalName(data []byte) string {
	var parts []string
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 0x1b || data[i] == 0x0c || data[i] == 0x13 { // string tag
			length := int(data[i+1])
			if length > 0 && i+2+length <= len(data) {
				val := string(data[i+2 : i+2+length])
				if len(val) > 0 {
					parts = append(parts, val)
				}
				i += 1 + length
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "/")
}

// parseEDataPAData extracts supported encryption types and pre-auth methods from e-data.
func parseEDataPAData(data []byte) ([]string, []string) {
	var etypes []string
	var preauth []string
	seenEtypes := make(map[string]bool)
	seenPreauth := make(map[string]bool)

	// Scan through sequence for PA-DATA entries
	for i := 0; i <= len(data)-3; i++ {
		// Look for INTEGER tags representing PA-DATA types or E-Types
		if data[i] == 0x02 && data[i+1] == 0x01 {
			val := int(data[i+2])
			switch val {
			case 2:
				if !seenPreauth["PA-ENC-TIMESTAMP(2)"] {
					seenPreauth["PA-ENC-TIMESTAMP(2)"] = true
					preauth = append(preauth, "PA-ENC-TIMESTAMP(2)")
				}
			case 11:
				if !seenPreauth["PA-ETYPE-INFO(11)"] {
					seenPreauth["PA-ETYPE-INFO(11)"] = true
					preauth = append(preauth, "PA-ETYPE-INFO(11)")
				}
			case 16:
				if !seenPreauth["PA-PK-AS-REQ(16)"] {
					seenPreauth["PA-PK-AS-REQ(16)"] = true
					preauth = append(preauth, "PA-PK-AS-REQ(16)")
				}
			case 19:
				if !seenPreauth["PA-ETYPE-INFO2(19)"] {
					seenPreauth["PA-ETYPE-INFO2(19)"] = true
					preauth = append(preauth, "PA-ETYPE-INFO2(19)")
				}
			case 136:
				if !seenPreauth["PA-FX-FAST(136)"] {
					seenPreauth["PA-FX-FAST(136)"] = true
					preauth = append(preauth, "PA-FX-FAST(136)")
				}
			}

			// E-Types
			if name := krbETypeName(val); name != "" {
				if !seenEtypes[name] {
					seenEtypes[name] = true
					etypes = append(etypes, name)
				}
			}
		}
	}

	return etypes, preauth
}

// extractASN1GeneralString searches for the first GeneralString or UTF8String in data.
func extractASN1GeneralString(data []byte) string {
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 0x1b || data[i] == 0x0c {
			length := int(data[i+1])
			if length > 0 && i+2+length <= len(data) {
				return string(data[i+2 : i+2+length])
			}
		}
	}
	return ""
}

// krbETypeName resolves Kerberos Encryption Type identifiers to human-readable names.
func krbETypeName(etype int) string {
	switch etype {
	case 1:
		return "DES-CBC-CRC(1)"
	case 3:
		return "DES-CBC-MD5(3)"
	case 16:
		return "DES3-CBC-SHA1(16)"
	case 17:
		return "AES128-CTS-SHA1(17)"
	case 18:
		return "AES256-CTS-SHA1(18)"
	case 19:
		return "AES128-CTS-SHA2(19)"
	case 20:
		return "AES256-CTS-SHA2(20)"
	case 23:
		return "RC4-HMAC(23)"
	case 24:
		return "RC4-HMAC-EXP(24)"
	case 25:
		return "Camellia128-CTS-CMAC(25)"
	case 26:
		return "Camellia256-CTS-CMAC(26)"
	default:
		return ""
	}
}

// krbErrorCodeName returns the RFC 4120 symbolic name for Kerberos error codes.
func krbErrorCodeName(code int) string {
	switch code {
	case 0:
		return "KDC_ERR_NONE"
	case 1:
		return "KDC_ERR_NAME_EXP"
	case 2:
		return "KDC_ERR_SERVICE_EXP"
	case 3:
		return "KDC_ERR_BAD_PVNO"
	case 4:
		return "KDC_ERR_C_OLD_MAST_KVNO"
	case 5:
		return "KDC_ERR_S_OLD_MAST_KVNO"
	case 6:
		return "KDC_ERR_C_PRINCIPAL_UNKNOWN"
	case 7:
		return "KDC_ERR_S_PRINCIPAL_UNKNOWN"
	case 8:
		return "KDC_ERR_PRINCIPAL_NOT_UNIQUE"
	case 9:
		return "KDC_ERR_NULL_KEY"
	case 10:
		return "KDC_ERR_CANNOT_POSTDATE"
	case 11:
		return "KDC_ERR_NEVER_VALID"
	case 12:
		return "KDC_ERR_POLICY"
	case 13:
		return "KDC_ERR_BADOPTION"
	case 14:
		return "KDC_ERR_ETYPE_NOSUPP"
	case 15:
		return "KDC_ERR_SUMTYPE_NOSUPP"
	case 16:
		return "KDC_ERR_PADATA_TYPE_NOSUPP"
	case 17:
		return "KDC_ERR_TRTYPE_NOSUPP"
	case 18:
		return "KDC_ERR_CLIENT_REVOKED"
	case 19:
		return "KDC_ERR_SERVICE_REVOKED"
	case 20:
		return "KDC_ERR_TGT_REVOKED"
	case 21:
		return "KDC_ERR_CLIENT_NOTYET"
	case 22:
		return "KDC_ERR_SERVICE_NOTYET"
	case 23:
		return "KDC_ERR_KEY_EXPIRED"
	case 24:
		return "KDC_ERR_PREAUTH_FAILED"
	case 25:
		return "KDC_ERR_PREAUTH_REQUIRED"
	case 26:
		return "KDC_ERR_SERVER_NOMASTER"
	case 27:
		return "KDC_ERR_MUST_USE_USER2USER"
	case 28:
		return "KDC_ERR_PATH_NOT_ACCEPTED"
	case 29:
		return "KDC_ERR_SVC_UNAVAILABLE"
	case 31:
		return "KRB_AP_ERR_BAD_INTEGRITY"
	case 32:
		return "KRB_AP_ERR_TKT_EXPIRED"
	case 33:
		return "KRB_AP_ERR_TKT_NYV"
	case 34:
		return "KRB_AP_ERR_REPEAT"
	case 35:
		return "KRB_AP_ERR_NOT_US"
	case 36:
		return "KRB_AP_ERR_BADMATCH"
	case 37:
		return "KRB_AP_ERR_SKEW"
	case 38:
		return "KRB_AP_ERR_BADADDR"
	case 39:
		return "KRB_AP_ERR_BADVERSION"
	case 40:
		return "KRB_AP_ERR_MSG_TYPE"
	case 41:
		return "KRB_AP_ERR_MODIFIED"
	case 42:
		return "KRB_AP_ERR_BADORDER"
	case 44:
		return "KRB_AP_ERR_BADKEYVER"
	case 45:
		return "KRB_AP_ERR_NOKEY"
	case 46:
		return "KRB_AP_ERR_MUT_FAIL"
	case 47:
		return "KRB_AP_ERR_BADDIRECTION"
	case 48:
		return "KRB_AP_ERR_METHOD"
	case 49:
		return "KRB_AP_ERR_BADSEQ"
	case 50:
		return "KRB_AP_ERR_INAPP_CKSUM"
	case 51:
		return "KRB_AP_PATH_NOT_ACCEPTED"
	case 52:
		return "KRB_ERR_RESPONSE_TOO_BIG"
	case 60:
		return "KRB_ERR_GENERIC"
	case 61:
		return "KRB_ERR_FIELD_TOOLONG"
	case 62:
		return "KDC_ERROR_CLIENT_NOT_TRUSTED"
	case 63:
		return "KDC_ERROR_KDC_NOT_TRUSTED"
	case 64:
		return "KDC_ERROR_INVALID_SIG"
	case 65:
		return "KDC_ERR_KEY_TOO_WEAK"
	case 66:
		return "KDC_ERR_CERTIFICATE_MISMATCH"
	case 67:
		return "KRB_AP_ERR_NO_TGT"
	case 68:
		return "KDC_ERR_WRONG_REALM"
	case 69:
		return "KRB_AP_ERR_USER_TO_USER_REQUIRED"
	case 70:
		return "KDC_ERR_CANT_VERIFY_CERTIFICATE"
	case 71:
		return "KDC_ERR_INVALID_CERTIFICATE"
	case 72:
		return "KDC_ERR_REVOKED_CERTIFICATE"
	case 73:
		return "KDC_ERR_REVOCATION_STATUS_UNKNOWN"
	case 74:
		return "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE"
	case 75:
		return "KDC_ERR_CLIENT_NAME_MISMATCH"
	case 76:
		return "KDC_ERR_KDC_NAME_MISMATCH"
	default:
		return "KDC_ERR"
	}
}
