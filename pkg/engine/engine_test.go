package engine

import (
	"context"
	"net"
	"net/netip"
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
	defer ln.Close()

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
