package probers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const mockWSManIdentifyResponse = `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Header/>
  <s:Body>
    <wsmid:IdentifyResponse>
      <wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>
      <wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>
      <wsmid:ProductVersion>OS: 10.0.22631 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>
      <wsmid:SecurityProfiles>
        <wsmid:SecurityProfileName>HTTP_Basic</wsmid:SecurityProfileName>
        <wsmid:SecurityProfileName>HTTP_Negotiate</wsmid:SecurityProfileName>
        <wsmid:SecurityProfileName>HTTP_Kerberos</wsmid:SecurityProfileName>
      </wsmid:SecurityProfiles>
    </wsmid:IdentifyResponse>
  </s:Body>
</s:Envelope>`

func TestWinRM_PingSuccessIdentifyXML(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/wsman", r.URL.Path)
		assert.Contains(t, r.Header.Get("Content-Type"), "application/soap+xml")

		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockWSManIdentifyResponse))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := BuildPinger(FactoryOptions{
		Protocol: consts.WINRM,
		Hostname: u.Hostname(),
		Port:     uint16(port),
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "Vendor: Microsoft Corporation")
	assert.Contains(t, res.Diagnostics, "OS: 10.0.22631")
	assert.Contains(t, res.Diagnostics, "HTTP_Negotiate")
	assert.Contains(t, res.Diagnostics, "Microsoft-HTTPAPI/2.0")
}

func TestWinRM_PingSuccessAuthChallenge401(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		w.Header().Add("WWW-Authenticate", "Negotiate")
		w.Header().Add("WWW-Authenticate", "Kerberos")
		w.Header().Add("WWW-Authenticate", "NTLM")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := BuildPinger(FactoryOptions{
		Protocol: consts.WINRM,
		Hostname: u.Hostname(),
		Port:     uint16(port),
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusUnauthorized, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "AuthSchemes: Negotiate, Kerberos, NTLM")
	assert.Contains(t, res.Diagnostics, "Server: Microsoft-HTTPAPI/2.0")
}

func TestWinRM_PingTLSSuccess(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockWSManIdentifyResponse))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := BuildPinger(FactoryOptions{
		Protocol:  consts.WINRMS,
		Hostname:  u.Hostname(),
		Port:      uint16(port),
		Timeout:   2 * time.Second,
		TLSConfig: ts.Client().Transport.(*http.Transport).TLSClientConfig,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "TLSVersion:")
	assert.Contains(t, res.Diagnostics, "Vendor: Microsoft Corporation")
}

func TestWinRM_PingServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := BuildPinger(FactoryOptions{
		Protocol: consts.WINRM,
		Hostname: u.Hostname(),
		Port:     uint16(port),
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.Error(t, res.Err)
	assert.True(t, strings.Contains(res.Err.Error(), "500"))
}

func TestWinRM_BuildTargetURL_Variations(t *testing.T) {
	// 1. Missing target
	p1 := NewWinRMing(WinRMOptions{})
	res1 := p1.Ping(context.Background())
	assert.Error(t, res1.Err)
	assert.Contains(t, res1.Err.Error(), "no target host or uri specified")

	// 2. Target URI with scheme and custom path
	p2 := NewWinRMing(WinRMOptions{
		URI:      "https://custom-winrm.corp.net:5986/wsman/custom",
		Hostname: "custom-winrm.corp.net",
		Port:     5986,
		UseTLS:   true,
	})
	url2, err2 := p2.buildTargetURL()
	assert.NoError(t, err2)
	assert.Equal(t, "https://custom-winrm.corp.net:5986/wsman/custom", url2.String())

	// 3. Target URI without scheme
	p3 := NewWinRMing(WinRMOptions{
		URI: "winrm.corp.net:5985",
	})
	url3, err3 := p3.buildTargetURL()
	assert.NoError(t, err3)
	assert.Equal(t, "http://winrm.corp.net:5985/wsman", url3.String())

	// 4. IP target
	p4 := NewWinRMing(WinRMOptions{
		Hostname: "192.168.1.100",
		Port:     5985,
	})
	url4, err4 := p4.buildTargetURL()
	assert.NoError(t, err4)
	assert.Equal(t, "http://192.168.1.100:5985/wsman", url4.String())
}

func TestWinRM_Diagnostics_EdgeCases(t *testing.T) {
	p := NewWinRMing(WinRMOptions{})

	// 1. Empty body with WWW-Authenticate CredSSP
	resp1 := &http.Response{
		StatusCode: 401,
		Header:     http.Header{},
	}
	resp1.Header.Set("WWW-Authenticate", "CredSSP")
	resp1.Header.Set("Server", "Microsoft-HTTPAPI/2.0")
	diag1 := p.parseDiagnostics(resp1, nil, nil)
	assert.Contains(t, diag1, "AuthSchemes: CredSSP")
	assert.Contains(t, diag1, "Server: Microsoft-HTTPAPI/2.0")

	// 2. Malformed XML body with 200
	malformedXML := []byte("<not-valid-xml")
	diag2 := p.parseDiagnostics(resp1, malformedXML, nil)
	assert.Contains(t, diag2, "AuthSchemes: CredSSP")

	// 3. XML with SecurityProfiles containing Basic & Digest
	customXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Body>
    <wsmid:IdentifyResponse>
      <wsmid:ProductVendor>Custom Vendor</wsmid:ProductVendor>
      <wsmid:SecurityProfiles>
        <wsmid:SecurityProfileName>HTTP_Basic</wsmid:SecurityProfileName>
        <wsmid:SecurityProfileName>HTTP_Digest</wsmid:SecurityProfileName>
      </wsmid:SecurityProfiles>
    </wsmid:IdentifyResponse>
  </s:Body>
</s:Envelope>`)
	resp2 := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}
	diag3 := p.parseDiagnostics(resp2, customXML, nil)
	assert.Contains(t, diag3, "Vendor: Custom Vendor")
	assert.Contains(t, diag3, "HTTP_Basic, HTTP_Digest")
}

func TestWinRM_NetworkDialError(t *testing.T) {
	p := NewWinRMing(WinRMOptions{
		Hostname: "127.0.0.1",
		Port:     1, // Unbound port
		Timeout:  100 * time.Millisecond,
	})
	res := p.Ping(context.Background())
	assert.Error(t, res.Err)
}
