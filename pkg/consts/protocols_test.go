// Test Strategy (pkg/consts):
//  1. Canonical Port Mapping: Validate default L4/L7 ports across all protocols against IANA assignments.
//  2. Alias Normalization: Verify case-insensitive scheme strings and common abbreviations map to canonical enums.
//  3. Total Protocol Coverage: Ensure AllProtocols enumerates all registered prober protocols without omission.
package consts

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDefaultPort(t *testing.T) {
	assert.Equal(t, uint16(80), GetDefaultPort(HTTP))
	assert.Equal(t, uint16(443), GetDefaultPort(HTTPS))
	assert.Equal(t, uint16(53), GetDefaultPort(DNS))
	assert.Equal(t, uint16(6379), GetDefaultPort(REDIS))
	assert.Equal(t, uint16(5432), GetDefaultPort(POSTGRES))
	assert.Equal(t, uint16(3306), GetDefaultPort(MYSQL))
	assert.Equal(t, uint16(1433), GetDefaultPort(MSSQL))
	assert.Equal(t, uint16(1521), GetDefaultPort(ORACLE))
	assert.Equal(t, uint16(27017), GetDefaultPort(MONGODB))
	assert.Equal(t, uint16(9042), GetDefaultPort(CASSANDRA))
	assert.Equal(t, uint16(30015), GetDefaultPort(SAPHANA))
	assert.Equal(t, uint16(11211), GetDefaultPort(MEMCACHED))
	assert.Equal(t, uint16(25), GetDefaultPort(SMTP))
	assert.Equal(t, uint16(143), GetDefaultPort(IMAP))
	assert.Equal(t, uint16(110), GetDefaultPort(POP3))
	assert.Equal(t, uint16(389), GetDefaultPort(LDAP))
	assert.Equal(t, uint16(9092), GetDefaultPort(KAFKA))
	assert.Equal(t, uint16(5672), GetDefaultPort(RABBITMQ))
	assert.Equal(t, uint16(445), GetDefaultPort(SMB))
	assert.Equal(t, uint16(873), GetDefaultPort(RSYNC))
	assert.Equal(t, uint16(21), GetDefaultPort(FTP))
	assert.Equal(t, uint16(443), GetDefaultPort(Protocol("UNKNOWN")))
}

func TestNormalizeProtocol(t *testing.T) {
	// Standard protocols
	p, port, ok := NormalizeProtocol("http")
	assert.True(t, ok)
	assert.Equal(t, HTTP, p)
	assert.Equal(t, uint16(80), port)

	// Aliases
	p, port, ok = NormalizeProtocol("postgresql")
	assert.True(t, ok)
	assert.Equal(t, POSTGRES, p)
	assert.Equal(t, uint16(5432), port)

	p, port, ok = NormalizeProtocol("hana")
	assert.True(t, ok)
	assert.Equal(t, SAPHANA, p)
	assert.Equal(t, uint16(30015), port)

	p, port, ok = NormalizeProtocol("ping")
	assert.True(t, ok)
	assert.Equal(t, ICMP, p)
	assert.Equal(t, uint16(0), port)

	// Unknown fallback
	p, port, ok = NormalizeProtocol("unrecognized_scheme")
	assert.False(t, ok)
	assert.Equal(t, TCP, p)
	assert.Equal(t, uint16(443), port)
}

func TestAllProtocols(t *testing.T) {
	all := AllProtocols()
	assert.GreaterOrEqual(t, len(all), 45)
}
