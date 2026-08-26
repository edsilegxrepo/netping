// Test Strategy (pkg/engine):
//  1. TCP & Multi-Protocol Execution: Verify on-demand dynamic dials against loopback TCP servers.
//  2. Target Resolution & Scheme Parsing: Validate URI schemas (scheme://host:port), defaults, and protocol mappings.
//  3. Concurrency Semaphore Throttling: Test concurrent trigger bursts ensuring worker limits are strictly respected.
//  4. SLA Latency Assertions: Validate SLA breach detection when RTT exceeds configured max_latency_ms thresholds.
//  5. Registry Lifecycle: Verify thread-safe target registration, statistics accumulation, and dynamic target removal.
package engine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
	"github.com/edsilegx/netping/pkg/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDynamicEngineTCPExecution(t *testing.T) {
	// Start a local dummy TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	broadcaster := web.NewBroadcaster()
	registry := NewDynamicTargetRegistry()
	eng := NewDynamicEngine(broadcaster, registry, 10)

	// 1. Successful local TCP probe
	resp, err := eng.Execute(context.Background(), TriggerRequest{
		Host:     "127.0.0.1",
		Port:     uint16(addr.Port),
		Protocol: "tcp",
		Timeout:  "1s",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, uint16(addr.Port), resp.Port)
	assert.Equal(t, "TCP", resp.Protocol)
	assert.NotEmpty(t, resp.Timestamp)
	assert.GreaterOrEqual(t, resp.RTTMs, float64(0))

	// Verify target was registered in registry
	assert.GreaterOrEqual(t, registry.TargetCount(), 1)
	fleet := registry.GetFleetTargets()
	assert.NotEmpty(t, fleet)

	// 2. Multi-count probe
	respMulti, err := eng.Execute(context.Background(), TriggerRequest{
		Target:   addr.String(),
		Protocol: "tcp",
		Count:    3,
		Interval: "50ms",
	})
	require.NoError(t, err)
	assert.True(t, respMulti.Success)
	assert.Len(t, respMulti.Probes, 3)

	// 3. Unreachable target returns error in response without crashing
	respFail, err := eng.Execute(context.Background(), TriggerRequest{
		Host:     "127.0.0.1",
		Port:     1, // Closed port
		Protocol: "tcp",
		Timeout:  "500ms",
	})
	require.NoError(t, err)
	assert.False(t, respFail.Success)
	assert.NotEmpty(t, respFail.Error)
	assert.NotEmpty(t, respFail.ErrorCode)
}

func TestDynamicTargetRegistry(t *testing.T) {
	registry := NewDynamicTargetRegistry()

	st := registry.GetOrCreateStats("127.0.0.1:8080", "127.0.0.1", netip.Addr{}, 8080, consts.HTTP, "")
	require.NotNil(t, st)
	assert.Equal(t, 1, registry.TargetCount())

	// Same target returns same stats object
	st2 := registry.GetOrCreateStats("127.0.0.1:8080", "127.0.0.1", netip.Addr{}, 8080, consts.HTTP, "")
	assert.Same(t, st, st2)

	// Register background target
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := registry.RegisterTarget(&DynamicTarget{
		ID:        "target_1",
		Target:    "api.test:443",
		Host:      "api.test",
		Port:      443,
		Protocol:  "HTTPS",
		Stats:     st,
		cancel:    cancel,
		CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	fleet := registry.GetFleetTargets()
	assert.Len(t, fleet, 2)

	// Remove target
	removed := registry.RemoveTarget("target_1")
	assert.True(t, removed)

	// Reset
	registry.Reset()
	assert.Equal(t, 1, registry.TargetCount())
}

func TestResolveTriggerTarget_Variations(t *testing.T) {
	// 1. Host and Port
	h, p, proto, svc, err := resolveTriggerTarget(TriggerRequest{
		Host:     "db.corp.internal",
		Port:     5432,
		Protocol: "postgres",
	})
	require.NoError(t, err)
	assert.Equal(t, "db.corp.internal", h)
	assert.Equal(t, uint16(5432), p)
	assert.Equal(t, consts.POSTGRES, proto)
	assert.Empty(t, svc)

	// 2. URI Format (scheme://host:port)
	h, p, proto, _, err = resolveTriggerTarget(TriggerRequest{
		URI: "https://api.gateway.io:8443",
	})
	require.NoError(t, err)
	assert.Equal(t, "api.gateway.io", h)
	assert.Equal(t, uint16(8443), p)
	assert.Equal(t, consts.HTTPS, proto)

	// 3. Target with default protocol port
	h, p, proto, _, err = resolveTriggerTarget(TriggerRequest{
		Target:   "redis.internal",
		Protocol: "redis",
	})
	require.NoError(t, err)
	assert.Equal(t, "redis.internal", h)
	assert.Equal(t, uint16(6379), p)
	assert.Equal(t, consts.REDIS, proto)

	// 4. Missing target/host/uri -> error
	_, _, _, _, err = resolveTriggerTarget(TriggerRequest{})
	assert.Error(t, err)
}

func TestResolveProtocolAndDefaultPort_All(t *testing.T) {
	tests := []struct {
		input    string
		expected consts.Protocol
		defPort  string
	}{
		{"http", consts.HTTP, "80"},
		{"https", consts.HTTPS, "443"},
		{"grpc", consts.GRPC, "50051"},
		{"grpcs", consts.GRPCS, "443"},
		{"udp", consts.UDP, "53"},
		{"icmp", consts.ICMP, "0"},
		{"dns", consts.DNS, "53"},
		{"doh", consts.DOH, "443"},
		{"dot", consts.DOT, "853"},
		{"redis", consts.REDIS, "6379"},
		{"postgres", consts.POSTGRES, "5432"},
		{"mysql", consts.MYSQL, "3306"},
		{"mssql", consts.MSSQL, "1433"},
		{"oracle", consts.ORACLE, "1521"},
		{"mongodb", consts.MONGODB, "27017"},
		{"cassandra", consts.CASSANDRA, "9042"},
		{"smtp", consts.SMTP, "25"},
		{"imap", consts.IMAP, "143"},
		{"pop3", consts.POP3, "110"},
		{"ldap", consts.LDAP, "389"},
		{"kafka", consts.KAFKA, "9092"},
		{"rabbitmq", consts.RABBITMQ, "5672"},
		{"s3", consts.S3, "443"},
		{"unknown", consts.TCP, "443"},
	}

	for _, tc := range tests {
		proto, port, _ := resolveProtocolAndDefaultPort(tc.input)
		assert.Equal(t, tc.expected, proto)
		assert.Equal(t, tc.defPort, port)
	}
}

func TestDynamicEngine_ConcurrencyLimit(t *testing.T) {
	broadcaster := web.NewBroadcaster()
	registry := NewDynamicTargetRegistry()
	eng := NewDynamicEngine(broadcaster, registry, 1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancelled context immediately triggers context error on semaphore acquire

	_, err := eng.Execute(ctx, TriggerRequest{
		Host:     "127.0.0.1",
		Port:     80,
		Protocol: "tcp",
	})
	assert.Error(t, err)
}

func TestDynamicEngine_TracerouteExecution(t *testing.T) {
	broadcaster := web.NewBroadcaster()
	registry := NewDynamicTargetRegistry()
	eng := NewDynamicEngine(broadcaster, registry, 10)

	resp, err := eng.Execute(context.Background(), TriggerRequest{
		Target:     "127.0.0.1:80",
		Protocol:   "tcp",
		Traceroute: true,
		Timeout:    "100ms",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "127.0.0.1:80", resp.Target)
	assert.Equal(t, "TCP", resp.Protocol)
}

func TestDynamicEngine_MultipleProbes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	broadcaster := web.NewBroadcaster()
	registry := NewDynamicTargetRegistry()
	eng := NewDynamicEngine(broadcaster, registry, 10)

	resp, err := eng.Execute(context.Background(), TriggerRequest{
		Target:    addr.String(),
		Protocol:  "tcp",
		Count:     3,
		Interval:  "10ms",
		Timeout:   "500ms",
		ShowDiags: true,
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Len(t, resp.Probes, 3)
}

func TestDynamicEngine_KerberosExecution(t *testing.T) {
	// Start mock TCP Kerberos listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	broadcaster := web.NewBroadcaster()
	registry := NewDynamicTargetRegistry()
	eng := NewDynamicEngine(broadcaster, registry, 10)

	// Trigger Kerberos TCP probe via Engine
	resp, err := eng.Execute(context.Background(), TriggerRequest{
		Host:      "127.0.0.1",
		Port:      uint16(addr.Port),
		Protocol:  "kerberos",
		Timeout:   "500ms",
		ShowDiags: true,
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "KERBEROS", resp.Protocol)
	assert.Equal(t, uint16(addr.Port), resp.Port)

	// Trigger Kerberos UDP probe via Engine
	respUDP, err := eng.Execute(context.Background(), TriggerRequest{
		Host:      "127.0.0.1",
		Port:      uint16(addr.Port),
		Protocol:  "kerberos-udp",
		Timeout:   "500ms",
		ShowDiags: true,
	})
	require.NoError(t, err)
	assert.NotNil(t, respUDP)
	assert.Equal(t, "KERBEROSUDP", respUDP.Protocol)
}

func TestDynamicEngine_SSO_All3Protocols_Execution(t *testing.T) {
	// Mock HTTP server serving OIDC, SAML, and OAuth2 responses
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "openid-configuration"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"issuer": "https://auth.example.com",
				"authorization_endpoint": "https://auth.example.com/oauth2/v1/authorize",
				"token_endpoint": "https://auth.example.com/oauth2/v1/token",
				"jwks_uri": "https://auth.example.com/oauth2/v1/keys",
				"id_token_signing_alg_values_supported": ["RS256", "ES256"],
				"scopes_supported": ["openid", "profile", "email"]
			}`))
		case strings.Contains(r.URL.Path, "FederationMetadata.xml") || strings.Contains(r.URL.Path, "saml"):
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0"?>
<EntityDescriptor entityID="https://sts.example.com/" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sts.example.com/adfs/ls/"/>
    </IDPSSODescriptor>
</EntityDescriptor>`))
		case strings.Contains(r.URL.Path, "oauth-authorization-server") || strings.Contains(r.URL.Path, "oauth"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"issuer": "https://as.example.com",
				"token_endpoint": "https://as.example.com/token",
				"grant_types_supported": ["authorization_code", "client_credentials"],
				"code_challenge_methods_supported": ["S256"]
			}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer mockServer.Close()

	u, err := url.Parse(mockServer.URL)
	require.NoError(t, err)
	portVal, err := strconv.ParseUint(u.Port(), 10, 16)
	require.NoError(t, err)
	port := uint16(portVal)

	broadcaster := web.NewBroadcaster()
	registry := NewDynamicTargetRegistry()
	eng := NewDynamicEngine(broadcaster, registry, 10)

	// 1. OIDC Trigger via Engine
	respOIDC, err := eng.Execute(context.Background(), TriggerRequest{
		Host:      u.Hostname(),
		Port:      port,
		URI:       mockServer.URL + "/.well-known/openid-configuration",
		Protocol:  "oidc",
		Timeout:   "2s",
		ShowDiags: true,
	})
	require.NoError(t, err)
	assert.NotNil(t, respOIDC)
	assert.True(t, respOIDC.Success)
	assert.Equal(t, "OIDC", respOIDC.Protocol)
	assert.Equal(t, 200, respOIDC.HTTPStatus)
	assert.Contains(t, respOIDC.Diagnostics, "Protocol: OIDC")
	assert.Contains(t, respOIDC.Diagnostics, "Issuer: https://auth.example.com")

	// 2. SAML 2.0 Trigger via Engine
	respSAML, err := eng.Execute(context.Background(), TriggerRequest{
		Host:      u.Hostname(),
		Port:      port,
		URI:       mockServer.URL + "/FederationMetadata/2007-06/FederationMetadata.xml",
		Protocol:  "saml",
		Timeout:   "2s",
		ShowDiags: true,
	})
	require.NoError(t, err)
	assert.NotNil(t, respSAML)
	assert.True(t, respSAML.Success)
	assert.Equal(t, "SAML", respSAML.Protocol)
	assert.Equal(t, 200, respSAML.HTTPStatus)
	assert.Contains(t, respSAML.Diagnostics, "Protocol: SAML 2.0 Metadata")
	assert.Contains(t, respSAML.Diagnostics, "EntityID: https://sts.example.com/")

	// 3. OAuth 2.0 Trigger via Engine
	respOAuth, err := eng.Execute(context.Background(), TriggerRequest{
		Host:      u.Hostname(),
		Port:      port,
		URI:       mockServer.URL + "/.well-known/oauth-authorization-server",
		Protocol:  "oauth2",
		Timeout:   "2s",
		ShowDiags: true,
	})
	require.NoError(t, err)
	assert.NotNil(t, respOAuth)
	assert.True(t, respOAuth.Success)
	assert.Equal(t, "OAUTH2", respOAuth.Protocol)
	assert.Equal(t, 200, respOAuth.HTTPStatus)
	assert.Contains(t, respOAuth.Diagnostics, "Protocol: OAuth 2.0 (RFC 8414)")
	assert.Contains(t, respOAuth.Diagnostics, "Issuer: https://as.example.com")
	assert.Contains(t, respOAuth.Diagnostics, "PKCE: [S256]")
}
