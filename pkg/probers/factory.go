package probers

import (
	"crypto/tls"
	"net"
	"net/netip"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
)

// FactoryOptions defines all parameters necessary to construct any of the 51 protocol pingers.
type FactoryOptions struct {
	Protocol    consts.Protocol
	Hostname    string
	IP          netip.Addr
	Port        uint16
	Timeout     time.Duration
	Dialer      *net.Dialer
	UseIPv4     bool
	UseIPv6     bool
	SendData    string
	ExpectData  string
	ServiceName string
	DNSHosts    []string
	StartTLS    bool
	FastClose   bool
	URI         string
	TLSConfig   *tls.Config
}

// BuildPinger constructs a Pinger for the specified protocol and options.
func BuildPinger(opts FactoryOptions) Pinger {
	dialer := opts.Dialer
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	switch opts.Protocol {
	case consts.HTTP, consts.HTTPS:
		return NewHTTPing(HTTPOptions{
			Hostname:   opts.Hostname,
			IP:         opts.IP,
			Port:       opts.Port,
			Protocol:   opts.Protocol,
			Timeout:    timeout,
			Dialer:     dialer,
			SendData:   opts.SendData,
			ExpectData: opts.ExpectData,
		})
	case consts.UDP:
		return NewUDPing(UDPOptions{
			IP:         opts.IP,
			Port:       opts.Port,
			Timeout:    timeout,
			Dialer:     dialer,
			SendData:   opts.SendData,
			ExpectData: opts.ExpectData,
		})
	case consts.ICMP:
		return NewICMPing(ICMPOptions{
			IP:      opts.IP,
			Timeout: timeout,
			UseIPv6: opts.UseIPv6,
		})
	case consts.GRPC:
		return NewGRPCing(GRPCOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.GRPCS:
		return NewGRPCing(GRPCOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.WS:
		return NewWSing(WSOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   false,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.WSS:
		return NewWSing(WSOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.DNS:
		return NewDNSQueryProber(DNSQueryOptions{
			Nameserver: opts.Hostname,
			IP:         opts.IP,
			Port:       opts.Port,
			Domains:    opts.DNSHosts,
			Domain:     opts.Hostname,
			IsDoH:      false,
			Timeout:    timeout,
			Dialer:     dialer,
		})
	case consts.DOH:
		return NewDNSQueryProber(DNSQueryOptions{
			Nameserver: opts.Hostname,
			IP:         opts.IP,
			Port:       opts.Port,
			Domains:    opts.DNSHosts,
			Domain:     opts.Hostname,
			IsDoH:      true,
			Timeout:    timeout,
			Dialer:     dialer,
		})
	case consts.DOT:
		return NewDNSQueryProber(DNSQueryOptions{
			Nameserver: opts.Hostname,
			IP:         opts.IP,
			Port:       opts.Port,
			Domains:    opts.DNSHosts,
			Domain:     opts.Hostname,
			IsDoT:      true,
			Timeout:    timeout,
			Dialer:     dialer,
		})
	case consts.REDIS:
		return NewRedising(RedisOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.REDISS:
		return NewRedising(RedisOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.SSH:
		return NewSSHing(SSHOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.POSTGRES:
		return NewDBing(DBOptions{
			Type:     PostgreSQL,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.MYSQL:
		return NewDBing(DBOptions{
			Type:     MySQL,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.MSSQL:
		return NewDBing(DBOptions{
			Type:     MSSQL,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.ORACLE:
		return NewDBing(DBOptions{
			Type:        Oracle,
			Hostname:    opts.Hostname,
			IP:          opts.IP,
			Port:        opts.Port,
			ServiceName: opts.ServiceName,
			Timeout:     timeout,
			Dialer:      dialer,
		})
	case consts.MONGODB:
		return NewDBing(DBOptions{
			Type:     MongoDB,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.MONGODBS:
		return NewDBing(DBOptions{
			Type:     MongoDB,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.CASSANDRA:
		return NewDBing(DBOptions{
			Type:     Cassandra,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.CASSANDRAS:
		return NewDBing(DBOptions{
			Type:     Cassandra,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.SAPHANA:
		return NewDBing(DBOptions{
			Type:     SAPHANA,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.MEMCACHED:
		return NewMemcacheding(MemcachedOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.MEMCACHEDS:
		return NewMemcacheding(MemcachedOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.SMTP:
		return NewMailing(MailOptions{
			Protocol: MailSMTP,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   false,
			StartTLS: opts.StartTLS,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.SMTPS:
		return NewMailing(MailOptions{
			Protocol: MailSMTP,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			StartTLS: false,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.IMAP:
		return NewMailing(MailOptions{
			Protocol: MailIMAP,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   false,
			StartTLS: opts.StartTLS,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.IMAPS:
		return NewMailing(MailOptions{
			Protocol: MailIMAP,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			StartTLS: false,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.POP3:
		return NewMailing(MailOptions{
			Protocol: MailPOP3,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   false,
			StartTLS: opts.StartTLS,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.POP3S:
		return NewMailing(MailOptions{
			Protocol: MailPOP3,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			StartTLS: false,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.TLS:
		return NewTLSing(TLSOptions{
			Hostname:  opts.Hostname,
			IP:        opts.IP,
			Port:      opts.Port,
			Timeout:   timeout,
			Dialer:    dialer,
			FastClose: opts.FastClose,
		})
	case consts.LDAP:
		return NewLDAPing(LDAPOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   false,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.LDAPS:
		return NewLDAPing(LDAPOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.O365:
		return NewO365ing(O365Options{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.S3:
		return NewStorageing(StorageOptions{
			Type:     StorageS3,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.AZUREBLOB:
		return NewStorageing(StorageOptions{
			Type:     StorageAzureBlob,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.GCS:
		return NewStorageing(StorageOptions{
			Type:     StorageGCS,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.KAFKA:
		return NewQueueing(QueueOptions{
			Protocol: QueueKafka,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   false,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.KAFKAS:
		return NewQueueing(QueueOptions{
			Protocol: QueueKafka,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.RABBITMQ, consts.AMQP:
		return NewQueueing(QueueOptions{
			Protocol: QueueRabbitMQ,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   false,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.AMQPS:
		return NewQueueing(QueueOptions{
			Protocol: QueueRabbitMQ,
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.SMB:
		return NewSMBing(SMBOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.RSYNC:
		return NewRsyncing(RsyncOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.FTP:
		return NewFTPing(FTPOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   false,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.FTPS:
		return NewFTPing(FTPOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			UseTLS:   true,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.KERBEROS:
		return NewKerberosing(KerberosOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			IsUDP:    false,
			Realm:    opts.ServiceName,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.KERBEROSUDP:
		return NewKerberosing(KerberosOptions{
			Hostname: opts.Hostname,
			IP:       opts.IP,
			Port:     opts.Port,
			IsUDP:    true,
			Realm:    opts.ServiceName,
			Timeout:  timeout,
			Dialer:   dialer,
		})
	case consts.OIDC:
		return NewSSOing(SSOOptions{
			Type:      SSOTypeOIDC,
			Hostname:  opts.Hostname,
			IP:        opts.IP,
			Port:      opts.Port,
			URI:       opts.URI,
			Timeout:   timeout,
			TLSConfig: opts.TLSConfig,
			Dialer:    dialer,
			UseIPv4:   opts.UseIPv4,
			UseIPv6:   opts.UseIPv6,
		})
	case consts.SAML:
		return NewSSOing(SSOOptions{
			Type:      SSOTypeSAML,
			Hostname:  opts.Hostname,
			IP:        opts.IP,
			Port:      opts.Port,
			URI:       opts.URI,
			Timeout:   timeout,
			TLSConfig: opts.TLSConfig,
			Dialer:    dialer,
			UseIPv4:   opts.UseIPv4,
			UseIPv6:   opts.UseIPv6,
		})
	case consts.OAUTH2:
		return NewSSOing(SSOOptions{
			Type:      SSOTypeOAuth2,
			Hostname:  opts.Hostname,
			IP:        opts.IP,
			Port:      opts.Port,
			URI:       opts.URI,
			Timeout:   timeout,
			TLSConfig: opts.TLSConfig,
			Dialer:    dialer,
			UseIPv4:   opts.UseIPv4,
			UseIPv6:   opts.UseIPv6,
		})
	case consts.SSO:
		return NewSSOing(SSOOptions{
			Type:      SSOTypeAuto,
			Hostname:  opts.Hostname,
			IP:        opts.IP,
			Port:      opts.Port,
			URI:       opts.URI,
			Timeout:   timeout,
			TLSConfig: opts.TLSConfig,
			Dialer:    dialer,
			UseIPv4:   opts.UseIPv4,
			UseIPv6:   opts.UseIPv6,
		})
	default:
		return NewTcping(TCPOptions{
			Hostname:   opts.Hostname,
			IP:         opts.IP,
			Port:       opts.Port,
			Timeout:    timeout,
			FastClose:  opts.FastClose,
			Dialer:     dialer,
			SendData:   opts.SendData,
			ExpectData: opts.ExpectData,
		})
	}
}
