// Package consts provides protocol constants and exit codes.
package consts

type Protocol string

const (
	TCP        Protocol = "TCP"
	TLS        Protocol = "TLS"
	UDP        Protocol = "UDP"
	HTTP       Protocol = "HTTP"
	HTTPS      Protocol = "HTTPS"
	ICMP       Protocol = "ICMP"
	GRPC       Protocol = "GRPC"
	GRPCS      Protocol = "GRPCS"
	WS         Protocol = "WS"
	WSS        Protocol = "WSS"
	DNS        Protocol = "DNS"
	DOT        Protocol = "DOT"
	DOH        Protocol = "DOH"
	REDIS      Protocol = "REDIS"
	REDISS     Protocol = "REDISS"
	SSH        Protocol = "SSH"
	POSTGRES   Protocol = "POSTGRES"
	MYSQL      Protocol = "MYSQL"
	MSSQL      Protocol = "MSSQL"
	ORACLE     Protocol = "ORACLE"
	MONGODB    Protocol = "MONGODB"
	MONGODBS   Protocol = "MONGODBS"
	CASSANDRA  Protocol = "CASSANDRA"
	CASSANDRAS Protocol = "CASSANDRAS"
	SAPHANA    Protocol = "SAPHANA"
	MEMCACHED  Protocol = "MEMCACHED"
	MEMCACHEDS Protocol = "MEMCACHEDS"
	SMTP       Protocol = "SMTP"
	SMTPS      Protocol = "SMTPS"
	IMAP       Protocol = "IMAP"
	IMAPS      Protocol = "IMAPS"
	POP3       Protocol = "POP3"
	POP3S      Protocol = "POP3S"
	LDAP       Protocol = "LDAP"
	LDAPS      Protocol = "LDAPS"
	O365       Protocol = "O365"
	S3         Protocol = "S3"
	AZUREBLOB  Protocol = "AZUREBLOB"
	GCS        Protocol = "GCS"
	KAFKA      Protocol = "KAFKA"
	KAFKAS     Protocol = "KAFKAS"
	RABBITMQ   Protocol = "RABBITMQ"
	AMQP       Protocol = "AMQP"
	AMQPS      Protocol = "AMQPS"
	SMB        Protocol = "SMB"
	RSYNC      Protocol = "RSYNC"
	FTP        Protocol = "FTP"
	FTPS       Protocol = "FTPS"
)

// Diagnostic Exit Codes
const (
	ExitSuccess               = 0   // Probing finished with 0% packet loss
	ExitGeneralError          = 1   // Unhandled error or runtime failure
	ExitUsageError            = 2   // Invalid CLI arguments or conflicting flags
	ExitDNSResolutionFailed   = 3   // Failed to resolve hostname or DNS server unreachable
	ExitNetworkInterfaceError = 4   // Network interface not found or routing failure
	ExitTargetUnreachable     = 5   // 100% packet loss (target did not respond to any probe)
	ExitPartialPacketLoss     = 6   // Completed with partial packet loss (>0% and <100%)
	ExitStorageError          = 7   // Failed to open, write, or flush CSV or SQLite database
	ExitInterrupted           = 130 // Terminated by user via SIGINT (Ctrl+C) / SIGTERM
)
