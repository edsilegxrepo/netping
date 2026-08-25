package probers

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildKerberosASREQ(t *testing.T) {
	req := buildKerberosASREQ("CORP.EXAMPLE.COM", "netping")
	require.NotEmpty(t, req)

	// RFC 4120 AS-REQ tag is [APPLICATION 10] (0x6a)
	assert.Equal(t, byte(0x6a), req[0])
	assert.Contains(t, string(req), "CORP.EXAMPLE.COM")
	assert.Contains(t, string(req), "netping")
	assert.Contains(t, string(req), "krbtgt")
}

func TestKerberos_ErrorCodeNames(t *testing.T) {
	testCases := []struct {
		code int
		name string
	}{
		{0, "KDC_ERR_NONE"},
		{1, "KDC_ERR_NAME_EXP"},
		{2, "KDC_ERR_SERVICE_EXP"},
		{3, "KDC_ERR_BAD_PVNO"},
		{4, "KDC_ERR_C_OLD_MAST_KVNO"},
		{5, "KDC_ERR_S_OLD_MAST_KVNO"},
		{6, "KDC_ERR_C_PRINCIPAL_UNKNOWN"},
		{7, "KDC_ERR_S_PRINCIPAL_UNKNOWN"},
		{8, "KDC_ERR_PRINCIPAL_NOT_UNIQUE"},
		{9, "KDC_ERR_NULL_KEY"},
		{10, "KDC_ERR_CANNOT_POSTDATE"},
		{11, "KDC_ERR_NEVER_VALID"},
		{12, "KDC_ERR_POLICY"},
		{13, "KDC_ERR_BADOPTION"},
		{14, "KDC_ERR_ETYPE_NOSUPP"},
		{15, "KDC_ERR_SUMTYPE_NOSUPP"},
		{16, "KDC_ERR_PADATA_TYPE_NOSUPP"},
		{17, "KDC_ERR_TRTYPE_NOSUPP"},
		{18, "KDC_ERR_CLIENT_REVOKED"},
		{19, "KDC_ERR_SERVICE_REVOKED"},
		{20, "KDC_ERR_TGT_REVOKED"},
		{21, "KDC_ERR_CLIENT_NOTYET"},
		{22, "KDC_ERR_SERVICE_NOTYET"},
		{23, "KDC_ERR_KEY_EXPIRED"},
		{24, "KDC_ERR_PREAUTH_FAILED"},
		{25, "KDC_ERR_PREAUTH_REQUIRED"},
		{26, "KDC_ERR_SERVER_NOMASTER"},
		{27, "KDC_ERR_MUST_USE_USER2USER"},
		{28, "KDC_ERR_PATH_NOT_ACCEPTED"},
		{29, "KDC_ERR_SVC_UNAVAILABLE"},
		{31, "KRB_AP_ERR_BAD_INTEGRITY"},
		{32, "KRB_AP_ERR_TKT_EXPIRED"},
		{33, "KRB_AP_ERR_TKT_NYV"},
		{34, "KRB_AP_ERR_REPEAT"},
		{35, "KRB_AP_ERR_NOT_US"},
		{36, "KRB_AP_ERR_BADMATCH"},
		{37, "KRB_AP_ERR_SKEW"},
		{38, "KRB_AP_ERR_BADADDR"},
		{39, "KRB_AP_ERR_BADVERSION"},
		{40, "KRB_AP_ERR_MSG_TYPE"},
		{41, "KRB_AP_ERR_MODIFIED"},
		{42, "KRB_AP_ERR_BADORDER"},
		{44, "KRB_AP_ERR_BADKEYVER"},
		{45, "KRB_AP_ERR_NOKEY"},
		{46, "KRB_AP_ERR_MUT_FAIL"},
		{47, "KRB_AP_ERR_BADDIRECTION"},
		{48, "KRB_AP_ERR_METHOD"},
		{49, "KRB_AP_ERR_BADSEQ"},
		{50, "KRB_AP_ERR_INAPP_CKSUM"},
		{51, "KRB_AP_PATH_NOT_ACCEPTED"},
		{52, "KRB_ERR_RESPONSE_TOO_BIG"},
		{60, "KRB_ERR_GENERIC"},
		{61, "KRB_ERR_FIELD_TOOLONG"},
		{62, "KDC_ERROR_CLIENT_NOT_TRUSTED"},
		{63, "KDC_ERROR_KDC_NOT_TRUSTED"},
		{64, "KDC_ERROR_INVALID_SIG"},
		{65, "KDC_ERR_KEY_TOO_WEAK"},
		{66, "KDC_ERR_CERTIFICATE_MISMATCH"},
		{67, "KRB_AP_ERR_NO_TGT"},
		{68, "KDC_ERR_WRONG_REALM"},
		{69, "KRB_AP_ERR_USER_TO_USER_REQUIRED"},
		{70, "KDC_ERR_CANT_VERIFY_CERTIFICATE"},
		{71, "KDC_ERR_INVALID_CERTIFICATE"},
		{72, "KDC_ERR_REVOKED_CERTIFICATE"},
		{73, "KDC_ERR_REVOCATION_STATUS_UNKNOWN"},
		{74, "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE"},
		{75, "KDC_ERR_CLIENT_NAME_MISMATCH"},
		{76, "KDC_ERR_KDC_NAME_MISMATCH"},
		{999, "KDC_ERR"},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.name, krbErrorCodeName(tc.code))
	}
}

func TestKerberos_ETypeNames(t *testing.T) {
	testCases := []struct {
		etype int
		name  string
	}{
		{1, "DES-CBC-CRC(1)"},
		{3, "DES-CBC-MD5(3)"},
		{16, "DES3-CBC-SHA1(16)"},
		{17, "AES128-CTS-SHA1(17)"},
		{18, "AES256-CTS-SHA1(18)"},
		{19, "AES128-CTS-SHA2(19)"},
		{20, "AES256-CTS-SHA2(20)"},
		{23, "RC4-HMAC(23)"},
		{24, "RC4-HMAC-EXP(24)"},
		{25, "Camellia128-CTS-CMAC(25)"},
		{26, "Camellia256-CTS-CMAC(26)"},
		{999, ""},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.name, krbETypeName(tc.etype))
	}
}

func TestKerberos_DefaultOptions(t *testing.T) {
	p := NewKerberosing(KerberosOptions{
		Hostname: "kdc.test.local",
	})
	assert.Equal(t, uint16(88), p.port)
	assert.Equal(t, "KDC.TEST.LOCAL", p.realm)
	assert.False(t, p.isUDP)

	pUDP := NewKerberosing(KerberosOptions{
		IP:    netip.MustParseAddr("127.0.0.1"),
		IsUDP: true,
	})
	assert.Equal(t, uint16(88), pUDP.port)
	assert.Equal(t, "EXAMPLE.COM", pUDP.realm)
	assert.True(t, pUDP.isUDP)

	pCustom := NewKerberosing(KerberosOptions{
		Hostname: "192.168.1.1",
		Port:     8888,
		Realm:    "MY.REALM",
	})
	assert.Equal(t, uint16(8888), pCustom.port)
	assert.Equal(t, "MY.REALM", pCustom.realm)
}

func buildMockKRBError(errorCode int, realm, sname string, serverTime time.Time) []byte {
	var seqBuf bytes.Buffer

	// pvno [0] INTEGER 5
	seqBuf.Write([]byte{0xa0, 0x03, 0x02, 0x01, 0x05})
	// msg-type [1] INTEGER 30 (krb-error)
	seqBuf.Write([]byte{0xa1, 0x03, 0x02, 0x01, 0x1e})

	// stime [4] KerberosTime (GeneralizedTime)
	timeStr := serverTime.UTC().Format("20060102150405Z")
	tBytes := wrapASN1(0x18, []byte(timeStr))
	seqBuf.Write(wrapASN1(0xa4, tBytes))

	// error-code [6] INTEGER
	codeBytes := wrapASN1(0x02, []byte{byte(errorCode)})
	seqBuf.Write(wrapASN1(0xa6, codeBytes))

	// realm [9] GeneralString
	realmBytes := wrapASN1(0x1b, []byte(realm))
	seqBuf.Write(wrapASN1(0xa9, realmBytes))

	// sname [10] PrincipalName
	var snameBuf bytes.Buffer
	snameBuf.Write([]byte{0xa0, 0x03, 0x02, 0x01, 0x02}) // NT-SRV-INST
	var snameStrings bytes.Buffer
	for _, part := range strings.Split(sname, "/") {
		snameStrings.Write(wrapASN1(0x1b, []byte(part)))
	}
	snameBuf.Write(wrapASN1(0xa1, wrapASN1(0x30, snameStrings.Bytes())))
	seqBuf.Write(wrapASN1(0xaa, wrapASN1(0x30, snameBuf.Bytes())))

	// e-text [11] GeneralString
	eTextBytes := wrapASN1(0x1b, []byte("Pre-authentication required"))
	seqBuf.Write(wrapASN1(0xab, eTextBytes))

	// e-data [12] PA-DATA sequence with PA-ETYPE-INFO2 (19), PA-ENC-TIMESTAMP (2), and E-Types 18, 17
	var paDataBuf bytes.Buffer
	paDataBuf.Write([]byte{0x02, 0x01, 0x02}) // 2 (PA-ENC-TIMESTAMP)
	paDataBuf.Write([]byte{0x02, 0x01, 0x13}) // 19 (PA-ETYPE-INFO2)
	paDataBuf.Write([]byte{0x02, 0x01, 0x12}) // 18 (AES256)
	paDataBuf.Write([]byte{0x02, 0x01, 0x11}) // 17 (AES128)
	seqBuf.Write(wrapASN1(0xac, wrapASN1(0x30, paDataBuf.Bytes())))

	return wrapASN1(0x7e, wrapASN1(0x30, seqBuf.Bytes())) // [APPLICATION 30]
}

func TestKerberos_DissectKRBError(t *testing.T) {
	fixedTime := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	mockPacket := buildMockKRBError(25, "CORP.CONTOSO.COM", "krbtgt/CORP.CONTOSO.COM", fixedTime)

	parsed := dissectKRBError(mockPacket)
	assert.True(t, parsed.HasErrorCode)
	assert.Equal(t, 25, parsed.ErrorCode)
	assert.Equal(t, "CORP.CONTOSO.COM", parsed.Realm)
	assert.Equal(t, "krbtgt/CORP.CONTOSO.COM", parsed.SName)
	assert.Equal(t, fixedTime, parsed.ServerTime)
	assert.Contains(t, parsed.SupportedETypes, "AES256-CTS-SHA1(18)")
	assert.Contains(t, parsed.SupportedETypes, "AES128-CTS-SHA1(17)")
	assert.Contains(t, parsed.PreAuthMethods, "PA-ETYPE-INFO2(19)")
	assert.Contains(t, parsed.PreAuthMethods, "PA-ENC-TIMESTAMP(2)")
	assert.Equal(t, "Pre-authentication required", parsed.EText)
}

func TestKerberos_ASN1Helpers_WrapAndLength(t *testing.T) {
	// Short length (<128)
	shortData := []byte("hello")
	wrappedShort := wrapASN1(0x1b, shortData)
	assert.Equal(t, byte(0x1b), wrappedShort[0])
	assert.Equal(t, byte(5), wrappedShort[1])
	l, off := readASN1Length(wrappedShort, 1)
	assert.Equal(t, 5, l)
	assert.Equal(t, 2, off)

	// Medium length (128 - 255)
	medData := make([]byte, 150)
	wrappedMed := wrapASN1(0x30, medData)
	assert.Equal(t, byte(0x30), wrappedMed[0])
	assert.Equal(t, byte(0x81), wrappedMed[1])
	assert.Equal(t, byte(150), wrappedMed[2])
	lMed, offMed := readASN1Length(wrappedMed, 1)
	assert.Equal(t, 150, lMed)
	assert.Equal(t, 3, offMed)

	// Long length (> 255)
	longData := make([]byte, 300)
	wrappedLong := wrapASN1(0x30, longData)
	assert.Equal(t, byte(0x30), wrappedLong[0])
	assert.Equal(t, byte(0x82), wrappedLong[1])
	lLong, offLong := readASN1Length(wrappedLong, 1)
	assert.Equal(t, 300, lLong)
	assert.Equal(t, 4, offLong)

	// Length boundary checks
	lZero, _ := readASN1Length([]byte{}, 0)
	assert.Equal(t, 0, lZero)
	lOverflow, _ := readASN1Length([]byte{0x85, 0x01}, 0)
	assert.Equal(t, 0, lOverflow)
}

func TestKerberos_ASN1Helpers_Parsers(t *testing.T) {
	// parseASN1Integer
	intData := []byte{0x02, 0x02, 0x01, 0x23}
	val, ok := parseASN1Integer(intData)
	assert.True(t, ok)
	assert.Equal(t, 0x0123, val)

	// Context-wrapped INTEGER [6] INTEGER
	wrappedInt := wrapASN1(0xa6, intData)
	valWrapped, okWrapped := parseASN1Integer(wrappedInt)
	assert.True(t, okWrapped)
	assert.Equal(t, 0x0123, valWrapped)

	valInvalid, okInvalid := parseASN1Integer([]byte{0x1b, 0x01, 0x01})
	assert.False(t, okInvalid)
	assert.Equal(t, 0, valInvalid)

	// parseASN1String
	strData := []byte{0x1b, 0x04, 'T', 'E', 'S', 'T'}
	assert.Equal(t, "TEST", parseASN1String(strData))
	// Context-wrapped string [9] GeneralString
	wrappedStr := wrapASN1(0xa9, strData)
	assert.Equal(t, "TEST", parseASN1String(wrappedStr))

	utf8Data := []byte{0x0c, 0x04, 'U', 'T', 'F', '8'}
	assert.Equal(t, "UTF8", parseASN1String(utf8Data))
	printableData := []byte{0x13, 0x03, 'A', 'B', 'C'}
	assert.Equal(t, "ABC", parseASN1String(printableData))
	ia5Data := []byte{0x16, 0x03, 'X', 'Y', 'Z'}
	assert.Equal(t, "XYZ", parseASN1String(ia5Data))
	octetData := []byte{0x04, 0x02, 0x11, 0x22}
	assert.Equal(t, "\x11\x22", parseASN1String(octetData))
	assert.Equal(t, "", parseASN1String([]byte{0x99, 0x01, 0x01}))

	// parseASN1GeneralizedTime
	timeData := []byte{0x18, 0x0f, '2', '0', '2', '6', '0', '8', '2', '5', '1', '2', '0', '0', '0', '0', 'Z'}
	tVal, err := parseASN1GeneralizedTime(timeData)
	assert.NoError(t, err)
	assert.Equal(t, 2026, tVal.Year())
	assert.Equal(t, time.Month(8), tVal.Month())

	// Context-wrapped GeneralizedTime [4] GeneralizedTime
	wrappedTime := wrapASN1(0xa4, timeData)
	tValWrapped, errWrapped := parseASN1GeneralizedTime(wrappedTime)
	assert.NoError(t, errWrapped)
	assert.Equal(t, 2026, tValWrapped.Year())

	_, errInvalidTime := parseASN1GeneralizedTime([]byte{0x02, 0x01, 0x01})
	assert.Error(t, errInvalidTime)

	// parsePrincipalName
	snameData := []byte{
		0x1b, 0x06, 'k', 'r', 'b', 't', 'g', 't',
		0x1b, 0x04, 'C', 'O', 'R', 'P',
	}
	assert.Equal(t, "krbtgt/CORP", parsePrincipalName(snameData))
	assert.Equal(t, "", parsePrincipalName([]byte{}))

	// extractASN1GeneralString
	assert.Equal(t, "REALM", extractASN1GeneralString([]byte{0x1b, 0x05, 'R', 'E', 'A', 'L', 'M'}))
	assert.Equal(t, "UTFREALM", extractASN1GeneralString([]byte{0x0c, 0x08, 'U', 'T', 'F', 'R', 'E', 'A', 'L', 'M'}))
	assert.Equal(t, "", extractASN1GeneralString([]byte{0x02, 0x01, 0x01}))
}

func TestKerberos_ParseEDataPAData_AllTypes(t *testing.T) {
	paDataBytes := []byte{
		0x02, 0x01, 0x02, // PA-ENC-TIMESTAMP(2)
		0x02, 0x01, 0x0b, // PA-ETYPE-INFO(11)
		0x02, 0x01, 0x10, // PA-PK-AS-REQ(16)
		0x02, 0x01, 0x13, // PA-ETYPE-INFO2(19)
		0x02, 0x01, 0x88, // PA-FX-FAST(136 = 0x88)
		0x02, 0x01, 0x17, // RC4-HMAC(23)
		0x02, 0x01, 0x19, // Camellia128(25)
		0x02, 0x01, 0x1a, // Camellia256(26)
	}

	etypes, preauth := parseEDataPAData(paDataBytes)
	assert.Contains(t, preauth, "PA-ENC-TIMESTAMP(2)")
	assert.Contains(t, preauth, "PA-ETYPE-INFO(11)")
	assert.Contains(t, preauth, "PA-PK-AS-REQ(16)")
	assert.Contains(t, preauth, "PA-ETYPE-INFO2(19)")
	assert.Contains(t, preauth, "PA-FX-FAST(136)")
	assert.Contains(t, etypes, "RC4-HMAC(23)")
	assert.Contains(t, etypes, "Camellia128-CTS-CMAC(25)")
	assert.Contains(t, etypes, "Camellia256-CTS-CMAC(26)")
}

func TestKerberos_ClockSkewCriticalAlert(t *testing.T) {
	p := NewKerberosing(KerberosOptions{})

	// Clock skew > 300s ahead (+400s)
	skewAheadTime := time.Now().UTC().Add(400 * time.Second)
	mockPacketAhead := buildMockKRBError(25, "REALM.COM", "krbtgt/REALM.COM", skewAheadTime)
	resAhead := p.processResponse(nil, mockPacketAhead, 5*time.Millisecond, time.Now())
	assert.Contains(t, resAhead.Diagnostics, "CRITICAL: SKEW >= 300s")
	assert.Contains(t, resAhead.Diagnostics, "ClockSkew: +")

	// Clock skew > 300s behind (-400s)
	skewBehindTime := time.Now().UTC().Add(-400 * time.Second)
	mockPacketBehind := buildMockKRBError(25, "REALM.COM", "krbtgt/REALM.COM", skewBehindTime)
	resBehind := p.processResponse(nil, mockPacketBehind, 5*time.Millisecond, time.Now())
	assert.Contains(t, resBehind.Diagnostics, "CRITICAL: SKEW >= 300s")
	assert.Contains(t, resBehind.Diagnostics, "ClockSkew: -")
}

func TestKerberos_UnexpectedResponses(t *testing.T) {
	p := NewKerberosing(KerberosOptions{})

	// Payload too short (< 4 bytes)
	resShort := p.processResponse(nil, []byte{0x7e, 0x01}, 5*time.Millisecond, time.Now())
	assert.Error(t, resShort.Err)
	assert.Contains(t, resShort.Err.Error(), "too short")

	// Unexpected application tag
	resBadTag := p.processResponse(nil, []byte{0x7f, 0x04, 0x00, 0x00}, 5*time.Millisecond, time.Now())
	assert.Error(t, resBadTag.Err)
	assert.Contains(t, resBadTag.Err.Error(), "unexpected kerberos response tag 0x7f")

	// Unexpected KDC error code (e.g. 12 = KDC_ERR_POLICY)
	badErrPacket := buildMockKRBError(12, "REALM.COM", "krbtgt/REALM.COM", time.Now().UTC())
	resBadCode := p.processResponse(nil, badErrPacket, 5*time.Millisecond, time.Now())
	assert.Error(t, resBadCode.Err)
	assert.Contains(t, resBadCode.Err.Error(), "KDC_ERR_POLICY")
}

func TestKerberos_TCP_MockServer_KRBError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	parts := strings.Split(ln.Addr().String(), ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	require.NoError(t, err)

	now := time.Now().UTC()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		lenBuf := make([]byte, 4)
		_, _ = io.ReadFull(conn, lenBuf)
		reqLen := binary.BigEndian.Uint32(lenBuf)
		reqBuf := make([]byte, reqLen)
		_, _ = io.ReadFull(conn, reqBuf)

		respPayload := buildMockKRBError(25, "TEST.REALM", "krbtgt/TEST.REALM", now)
		respLenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(respLenBuf, uint32(len(respPayload)))
		_, _ = conn.Write(append(respLenBuf, respPayload...))
	}()

	p := NewKerberosing(KerberosOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(port),
		IsUDP:   false,
		Timeout: 2 * time.Second,
	})

	res := p.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.True(t, res.RTT >= 0)
	assert.Contains(t, res.Diagnostics, "Kerberos v5 (RFC 4120)")
	assert.Contains(t, res.Diagnostics, "Transport: TCP")
	assert.Contains(t, res.Diagnostics, "KDC_ERR_PREAUTH_REQUIRED (25)")
	assert.Contains(t, res.Diagnostics, "Realm: TEST.REALM")
	assert.Contains(t, res.Diagnostics, "ClockSkew:")
	assert.Contains(t, res.Diagnostics, "AES256-CTS-SHA1(18)")
}

func TestKerberos_TCP_MockServer_ASRep(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	parts := strings.Split(ln.Addr().String(), ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	require.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		lenBuf := make([]byte, 4)
		_, _ = io.ReadFull(conn, lenBuf)
		reqLen := binary.BigEndian.Uint32(lenBuf)
		reqBuf := make([]byte, reqLen)
		_, _ = io.ReadFull(conn, reqBuf)

		// [APPLICATION 11] AS-REP
		asRepPayload := wrapASN1(0x6b, wrapASN1(0x30, []byte{0x1b, 0x0a, 'T', 'E', 'S', 'T', '.', 'R', 'E', 'A', 'L', 'M'}))
		respLenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(respLenBuf, uint32(len(asRepPayload)))
		_, _ = conn.Write(append(respLenBuf, asRepPayload...))
	}()

	p := NewKerberosing(KerberosOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(port),
		IsUDP:   false,
		Timeout: 2 * time.Second,
	})

	res := p.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Msg: AS-REP (11)")
	assert.Contains(t, res.Diagnostics, "Status: OK (Ticket Issued)")
	assert.Contains(t, res.Diagnostics, "Realm: TEST.REALM")
}

func TestKerberos_TCP_InvalidLengthHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	parts := strings.Split(ln.Addr().String(), ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	require.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		lenBuf := make([]byte, 4)
		_, _ = io.ReadFull(conn, lenBuf)
		reqLen := binary.BigEndian.Uint32(lenBuf)
		reqBuf := make([]byte, reqLen)
		_, _ = io.ReadFull(conn, reqBuf)

		// Send length prefix > 65536
		hugeLenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(hugeLenBuf, 999999)
		_, _ = conn.Write(hugeLenBuf)
	}()

	p := NewKerberosing(KerberosOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(port),
		IsUDP:   false,
		Timeout: 2 * time.Second,
	})

	res := p.Ping(context.Background())
	assert.Error(t, res.Err)
	assert.Contains(t, res.Err.Error(), "invalid kerberos response length")
}

func TestKerberos_UDP_MockServer_KRBError(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	parts := strings.Split(conn.LocalAddr().String(), ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	require.NoError(t, err)

	now := time.Now().UTC()
	go func() {
		buf := make([]byte, 2048)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}

		resp := buildMockKRBError(6, "UDP.EXAMPLE.COM", "krbtgt/UDP.EXAMPLE.COM", now)
		_, _ = conn.WriteTo(resp, addr)
	}()

	p := NewKerberosing(KerberosOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(port),
		IsUDP:   true,
		Timeout: 2 * time.Second,
	})

	res := p.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.True(t, res.RTT >= 0)
	assert.Contains(t, res.Diagnostics, "Transport: UDP")
	assert.Contains(t, res.Diagnostics, "KDC_ERR_C_PRINCIPAL_UNKNOWN (6)")
	assert.Contains(t, res.Diagnostics, "Realm: UDP.EXAMPLE.COM")
}

func TestKerberos_Timeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	parts := strings.Split(ln.Addr().String(), ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	require.NoError(t, err)

	p := NewKerberosing(KerberosOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(port),
		IsUDP:   false,
		Timeout: 100 * time.Millisecond,
	})

	res := p.Ping(context.Background())
	assert.Error(t, res.Err)
}
