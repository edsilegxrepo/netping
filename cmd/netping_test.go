package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/edsilegx/netping/internal/config"
	"github.com/edsilegx/netping/pkg/consts"
	"github.com/stretchr/testify/assert"
)

func TestBuildPinger_AllProtocols(t *testing.T) {
	protocols := []consts.Protocol{
		consts.HTTP,
		consts.HTTPS,
		consts.UDP,
		consts.ICMP,
		consts.GRPC,
		consts.GRPCS,
		consts.WS,
		consts.WSS,
		consts.DNS,
		consts.DOH,
		consts.DOT,
		consts.REDIS,
		consts.REDISS,
		consts.SSH,
		consts.POSTGRES,
		consts.MYSQL,
		consts.MSSQL,
		consts.ORACLE,
		consts.MONGODB,
		consts.MONGODBS,
		consts.CASSANDRA,
		consts.CASSANDRAS,
		consts.SAPHANA,
		consts.MEMCACHED,
		consts.MEMCACHEDS,
		consts.SMTP,
		consts.SMTPS,
		consts.IMAP,
		consts.IMAPS,
		consts.POP3,
		consts.POP3S,
		consts.TLS,
		consts.LDAP,
		consts.LDAPS,
		consts.O365,
		consts.S3,
		consts.AZUREBLOB,
		consts.GCS,
		consts.KAFKA,
		consts.KAFKAS,
		consts.RABBITMQ,
		consts.AMQP,
		consts.AMQPS,
		consts.SMB,
		consts.RSYNC,
		consts.FTP,
		consts.FTPS,
		consts.TCP,
	}

	for _, proto := range protocols {
		t.Run(string(proto), func(t *testing.T) {
			tCfg := config.TargetConfig{
				Protocol: proto,
				Host:     "127.0.0.1",
				IP:       netip.MustParseAddr("127.0.0.1"),
				Port:     8080,
			}
			cfg := &config.Config{
				Protocol: proto,
				Hostname: "127.0.0.1",
				IP:       netip.MustParseAddr("127.0.0.1"),
				Port:     8080,
				Timeout:  1 * time.Second,
			}
			p := buildPingerForTarget(tCfg, *cfg, nil)
			assert.NotNil(t, p, "Pinger for protocol %s should not be nil", proto)
		})
	}
}
